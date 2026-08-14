import Crypto
import Foundation
import SwanCore
import SwanSpaces

public enum BlobNamespace: Sendable, Hashable {
    case `public`
    case space(SpaceURI)
    /// Where an authenticated `com.atproto.repo.uploadBlob` lands.
    ///
    /// The upload wire format carries no namespace intent, so a blob destined
    /// for a permissioned space arrives on exactly the same route as an avatar
    /// destined for the public repository. Landing every upload in `.public`
    /// therefore published private-intended bytes to any anonymous caller who
    /// knew the CID — before the record commit, forever after a failed or
    /// abandoned commit, and again on every same-CID re-upload.
    ///
    /// A staged edge is never served by `com.atproto.sync.getBlob`. It is
    /// consumed by whichever commit claims it: a validated public record
    /// promotes it to `.public`, a permissioned record promotes it to
    /// `.space`, and an unclaimed edge expires.
    case staged
}

public struct BlobReference: Sendable, Hashable {
    public let cid: String
    public let namespace: BlobNamespace
    public init(cid: String, namespace: BlobNamespace) {
        self.cid = cid
        self.namespace = namespace
    }
}

/// Durable per-account bounds for the immutable blob CAS and its namespace
/// references. Bytes count each logical CID payload once even when several
/// namespaces reference it; references count each distinct namespace edge.
public struct AccountBlobQuota: Sendable, Equatable {
    public static let conservative = AccountBlobQuota(
        maximumUniqueBytes: 1 * 1_024 * 1_024 * 1_024,
        maximumReferences: 10_000
    )

    public let maximumUniqueBytes: Int
    public let maximumReferences: Int

    public init(maximumUniqueBytes: Int, maximumReferences: Int) {
        precondition(maximumUniqueBytes > 0)
        precondition(maximumReferences > 0)
        self.maximumUniqueBytes = maximumUniqueBytes
        self.maximumReferences = maximumReferences
    }
}

/// A typed admission failure so protocol adapters can distinguish an account
/// storage ceiling from malformed content or transient storage failure.
public enum BlobQuotaError: Error, Sendable, Equatable {
    case uniqueBytesExceeded(limit: Int)
    case referenceCountExceeded(limit: Int)
}

public protocol BlobStore: Sendable {
    func put(_ data: Data, namespace: BlobNamespace) async throws -> BlobReference
    func data(for reference: BlobReference) async throws -> Data
    func publicData(cid: String) async throws -> Data?
    func remove(_ reference: BlobReference) async throws
}

/// A bounded-memory body backed by an already verified immutable payload.
/// Implementations must close and release their underlying resource on every
/// terminal path, including cancellation and writer failure.
public protocol StreamingBlobBody: Sendable {
    var contentLength: Int { get }

    func streamBody(
        maximumChunkBytes: Int,
        consume: (Data) async throws -> Void
    ) async throws
}

/// The public namespace projection returned to an HTTP adapter. It contains
/// only sanitized metadata and a one-shot body; it never exposes a path,
/// descriptor, database, or namespace reference.
public struct PublicBlob: Sendable {
    public let mimeType: String?
    public let body: any StreamingBlobBody

    public init(mimeType: String?, body: any StreamingBlobBody) {
        self.mimeType = mimeType
        self.body = body
    }
}

/// Metadata for a reachable public blob.  This projection deliberately does
/// not expose a body or a storage handle, so record validation can compare a
/// typed blob reference without opening or materializing the payload.
public struct PublicBlobMetadata: Sendable, Equatable {
    public let mimeType: String?
    public let size: Int

    public init(mimeType: String?, size: Int) {
        self.mimeType = mimeType
        self.size = size
    }
}

/// The only blob capability the unauthenticated public read surface is ever
/// handed.
///
/// ``StreamingBlobStore`` and ``BlobStore`` can also write, adopt, and delete.
/// Passing one of those to an anonymous route and relying on the route to call
/// only the read method is the conditional-trust shape that has already
/// produced two production bugs in this codebase. This is the allow-list
/// instead: one method, read-only, public namespace only, no path, descriptor,
/// database, or namespace reference reachable through it.
public protocol PublicRepositoryReadBlobStore: Sendable {
    /// The sanitized public-namespace projection for a content-addressed blob,
    /// or nil when this account has no reachable public blob at that CID.
    func publicBlob(cid: String) async throws -> PublicBlob?

    /// The sanitized metadata for a reachable public blob — its true length
    /// and MIME type — without opening or materializing its body.
    ///
    /// Part of the read-only allow-list because the anonymous read route must
    /// reserve the blob's *actual* length from the shared transfer budget.
    /// Without a metadata-only accessor the route can only reserve the
    /// 256 MiB worst case for a 5 KiB avatar, which caps the whole service at
    /// two concurrent image reads per account and four in total, and starves
    /// `com.atproto.sync.getRepo` out of the same budget. This exposes no
    /// body, path, descriptor, database, or namespace reference, so it does
    /// not widen what the anonymous surface can reach.
    func publicBlobMetadata(cid: String) async throws -> PublicBlobMetadata?
}

/// Optional streaming extension for durable blob stores. The source closure
/// is called once and must feed serial chunks to the supplied sink. The store
/// owns staging, hashing, content-addressed adoption, and cleanup; callers
/// only choose the byte limit and namespace.
public protocol StreamingBlobStore: BlobStore, PublicRepositoryReadBlobStore {
    func putStreaming(
        namespace: BlobNamespace,
        mimeType: String?,
        maximumBytes: Int,
        source: @escaping @Sendable (
            @escaping (Data) async throws -> Void
        ) async throws -> Void
    ) async throws -> BlobReference

    // `publicBlob(cid:)` and `publicBlobMetadata(cid:)` are inherited from
    // `PublicRepositoryReadBlobStore`, which is the projection the anonymous
    // read surface is handed.

    /// Metadata-only reachability check for public record references. This
    /// must not open or materialize the blob body.
    func publicBlobExists(cid: String) async throws -> Bool

    /// Metadata for a blob this account has uploaded but not yet committed to
    /// a record, or has already published publicly.
    ///
    /// The authenticated mutation surface needs this to compare a record's
    /// declared `size`/`mimeType` against the stored payload *before* signing
    /// the commit that promotes it. It is deliberately absent from
    /// ``PublicRepositoryReadBlobStore``: the anonymous read surface must
    /// still see only the public namespace, so widening its allow-list would
    /// reintroduce exactly the staged-blob disclosure this namespace exists
    /// to prevent.
    func uploadedBlobMetadata(cid: String) async throws -> PublicBlobMetadata?
}

/// Local immutable content-addressed blobs. File contents are shared, while
/// their public and permissioned reachability is tracked separately.
public actor FileBlobStore: BlobStore {
    private let root: URL
    private var references: [String: Set<BlobNamespace>] = [:]

    public init(root: URL) throws {
        self.root = root
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    public func put(_ data: Data, namespace: BlobNamespace) throws -> BlobReference {
        let cid = "sha256:\(Hex.encode(SHA256.hash(data: data)))"
        let file = fileURL(for: cid)
        if !FileManager.default.fileExists(atPath: file.path) {
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: file, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        }
        references[cid, default: []].insert(namespace)
        return BlobReference(cid: cid, namespace: namespace)
    }

    public func data(for reference: BlobReference) throws -> Data {
        guard references[reference.cid, default: []].contains(reference.namespace) else {
            throw SwanError.unauthorized("blob reference is not reachable in this namespace")
        }
        return try Data(contentsOf: fileURL(for: reference.cid))
    }

    public func publicData(cid: String) throws -> Data? {
        guard references[cid, default: []].contains(.public) else { return nil }
        return try Data(contentsOf: fileURL(for: cid))
    }

    public func remove(_ reference: BlobReference) throws {
        guard var namespaces = references[reference.cid] else { return }
        namespaces.remove(reference.namespace)
        if namespaces.isEmpty {
            references.removeValue(forKey: reference.cid)
            try? FileManager.default.removeItem(at: fileURL(for: reference.cid))
        } else {
            references[reference.cid] = namespaces
        }
    }

    private func fileURL(for cid: String) -> URL {
        let digest = String(cid.dropFirst("sha256:".count))
        return root.appending(path: String(digest.prefix(2))).appending(path: digest)
    }
}

public struct OutboxEvent: Sendable, Equatable, Identifiable {
    public let id: UUID
    public let space: SpaceURI
    public let revision: UInt64
    public let payload: Data
    public let createdAt: Date
    public var attempts: Int

    public init(id: UUID = UUID(), space: SpaceURI, revision: UInt64, payload: Data, createdAt: Date = Date(), attempts: Int = 0) {
        self.id = id
        self.space = space
        self.revision = revision
        self.payload = payload
        self.createdAt = createdAt
        self.attempts = attempts
    }
}

public actor TransactionalOutbox {
    private var pending: [UUID: OutboxEvent] = [:]

    public init() {}

    public func enqueue(_ event: OutboxEvent) {
        pending[event.id] = event
    }

    public func next(limit: Int = 100) -> [OutboxEvent] {
        pending.values.sorted { $0.createdAt < $1.createdAt }.prefix(limit).map { $0 }
    }

    public func markDelivered(_ id: UUID) { pending.removeValue(forKey: id) }

    public func markAttempt(_ id: UUID) {
        guard var event = pending[id] else { return }
        event.attempts += 1
        pending[id] = event
    }
}

/// This protocol is intentionally expressed in repository domain terms instead
/// of as a generic key/value API. SQLite is the first implementation and a
/// FoundationDB adapter may implement the same transaction boundary later.
public protocol AccountRepositoryStore: Sendable {
    func repository(for space: SpaceURI, author: String) async throws -> SpaceRepository
}

public actor InMemoryAccountRepositoryStore: AccountRepositoryStore {
    private struct RepositoryKey: Hashable {
        let space: SpaceURI
        let author: String
    }

    private var repositories: [RepositoryKey: SpaceRepository] = [:]
    private let retention: Int

    public init(retention: Int = 10_000) { self.retention = retention }

    public func repository(for space: SpaceURI, author: String) throws -> SpaceRepository {
        let key = RepositoryKey(space: space, author: author)
        if let repository = repositories[key] { return repository }
        let repository = try SpaceRepository(space: space, author: author, retention: retention)
        repositories[key] = repository
        return repository
    }
}

/// Coordinates in-process work only. Durable conflict detection belongs to
/// the storage transaction, so callers must continue to pass expected CIDs or
/// revisions when a concrete database backend is introduced.
public actor AccountCoordinator {
    private let store: any AccountRepositoryStore
    public init(store: any AccountRepositoryStore) { self.store = store }

    public func repository(for space: SpaceURI, author: String) async throws -> SpaceRepository {
        try await store.repository(for: space, author: author)
    }
}

// MARK: - OAuth control plane

/// The deliberately narrow failure vocabulary for durable OAuth state.  None
/// of these cases include a bearer token, authorization code, proof body, or
/// client assertion, so an adapter can surface a safe OAuth error without
/// accidentally logging a credential.
public enum OAuthControlStoreError: Error, Sendable, Equatable {
    case notFound
    case expired
    case bindingMismatch
    case alreadyConsumed
    case replayDetected
    case invalidInput
    case malformedRecord
}

/// The complete public-key identity verified for a confidential OAuth client.
/// A key ID alone is not a cryptographic binding: the durable record carries
/// the JOSE algorithm and RFC 7638 thumbprint as well, so a reused `kid` with
/// new key material cannot silently inherit an existing token family.
public struct OAuthConfidentialClientKeyBinding: Sendable, Equatable {
    public let keyID: String
    public let algorithm: String
    public let keyThumbprint: String

    public init(keyID: String, algorithm: String, keyThumbprint: String) {
        self.keyID = keyID
        self.algorithm = algorithm
        self.keyThumbprint = keyThumbprint
    }
}

/// Which scope parameters a client *physically wrote*, recorded per effective
/// scope string.
///
/// This is durable state, not parser metadata (spec §9-D23). Two Swan fences —
/// `isExactReadOnlyDelegationGrant` (§5.6.3) and `allowsSpaceListing` (§6.1) —
/// require a parameter to have been literally stated by the client rather than
/// defaulted into place by the grammar, and a serialised scope string cannot
/// answer that question in either direction:
///
///   * resolving `authority=self` at mint writes a concrete DID where the
///     client wrote nothing, so a re-parse reports `authority` as *stated* and
///     the delegation fence flips open;
///   * canonical serialisation deletes any value equal to its default, so a
///     literally-written `skey=*` disappears and the listing fence can never
///     fire again.
///
/// Both directions are demonstrated against upstream's own serialiser in
/// `Tests/SwanOAuthTests/Fixtures/pinned-typescript-oauth-scopes.json`.
/// Provenance is therefore carried forward from the parse that produced it and
/// persisted beside the effective grant — never reconstructed.
///
/// Keys are the **effective** (post-resolution) scope strings, i.e. exactly the
/// members of `OAuthClientBinding.scopes`, so a reader holding a scope set can
/// look provenance up without re-deriving anything.
public struct OAuthScopeProvenance: Sendable, Equatable, Hashable {
    /// Effective scope string → the parameter keys the client wrote.
    private var storage: [String: Set<String>]

    public init(_ statedParameterKeys: [String: Set<String>] = [:]) {
        storage = statedParameterKeys
    }

    public var isEmpty: Bool { storage.isEmpty }

    /// Effective scope string → stated parameter keys, for persistence and for
    /// readers that reconstruct a permissions value from durable state.
    public var statedParameterKeys: [String: Set<String>] { storage }

    /// The keys the client physically wrote in `scope`. An unrecorded scope
    /// answers "nothing was stated", which is the fail-closed direction for
    /// both fences.
    public func statedKeys(for scope: String) -> Set<String> {
        storage[scope] ?? []
    }

    public func wasStated(_ key: String, in scope: String) -> Bool {
        storage[scope]?.contains(key) ?? false
    }

    public mutating func record(_ statedKeys: Set<String>, for scope: String) {
        storage[scope] = statedKeys
    }

    /// Re-keys provenance onto a rewritten scope string. Mint resolves
    /// `authority=self` into a concrete DID, which changes the *value* and must
    /// never change the *statedness* (§9-D23).
    public func rekeyed(from old: String, to new: String) -> OAuthScopeProvenance {
        guard old != new, let slot = storage[old] else { return self }
        var copy = storage
        copy.removeValue(forKey: old)
        copy[new] = slot
        return OAuthScopeProvenance(copy)
    }

    /// Drops records for scopes that are not in `scopes`. Called before a write
    /// so a rewritten grant cannot carry provenance for a scope it no longer
    /// holds.
    public func restricted(to scopes: Set<String>) -> OAuthScopeProvenance {
        OAuthScopeProvenance(storage.filter { scopes.contains($0.key) })
    }
}

/// Values which bind an OAuth request, authorization code, and token family.
/// Keeping these values together makes it hard for a later HTTP adapter to
/// accidentally turn a PAR or code for one client/redirect URI into a token
/// for another.
public struct OAuthClientBinding: Sendable, Equatable {
    public let issuer: String
    public let clientID: String
    public let redirectURI: String
    /// The **effective** grant. For a token family this is post-`self`
    /// resolution (§9-D8); for a PAR row it is necessarily the as-requested set,
    /// because a PAR has no subject to resolve against.
    public let scopes: Set<String>
    /// RFC 7638 S256 JWK thumbprint binding. This is public key metadata, not
    /// a DPoP proof body.
    public let dpopJKT: String?
    /// The complete verified key identity for a `private_key_jwt` client.
    /// It is intentionally absent for public clients; an identifier-only
    /// confidential-client binding is not representable.
    public let confidentialClientKey: OAuthConfidentialClientKeyBinding?
    /// This is frozen from client metadata at PAR. A later metadata expansion
    /// cannot turn a code originally authorized without refresh permission
    /// into a refresh-token grant.
    public let refreshTokenAllowed: Bool
    /// The exact bytes the client requested, when they differ from `scopes`.
    ///
    /// `nil` means "requested == scopes" — **not** "unknown" (§6.7). Rows
    /// written before `self` resolution existed genuinely stored what was
    /// requested, which is what makes `requestedScopes` a total function and
    /// keeps a pre-migration family refreshing exactly as it does today. Never
    /// persist an empty set to mean "same": empty and absent would then be
    /// indistinguishable from "requested nothing".
    ///
    /// This is **never** read by the matcher (§9-D8). It has exactly two
    /// readers: consent/audit, and the refresh binding baseline (§9-D20).
    public let scopesRequested: Set<String>?
    /// Which parameters the client stated, keyed by effective scope string.
    /// `nil` for rows written before the column existed.
    public let scopeProvenance: OAuthScopeProvenance?
    /// The same bits keyed by the **requested** scope strings — the exact
    /// counterpart of `scopesRequested`, and stored under exactly the same rule:
    /// present iff the requested set is.
    ///
    /// It exists because re-deriving the grant on refresh (§5.7.5's second call
    /// site) has to start from the requested bytes, and the transformations
    /// carry provenance forward by re-keying it. `scopeProvenance` is keyed by
    /// the *effective* strings, so it cannot serve as that input: the entry for
    /// a rewritten scope sits under a key the requested set does not contain.
    ///
    /// Persisted rather than recovered by re-parsing `scopesRequested`, because
    /// §9-D23's rule is mechanical: provenance is durable state, carried forward
    /// from the parse that produced it, and never reconstructed from a
    /// serialised scope string. A reader cannot tell locally whether a given
    /// string is the client's or Swan's, which is the whole reason the rule has
    /// no exceptions.
    ///
    /// `nil` alongside a non-`nil` `scopesRequested` therefore means one thing
    /// only: a row written before this column existed. Refresh treats that as
    /// "cannot re-derive" and leaves the grant frozen — see
    /// ``requestedBaseline()``.
    public let scopeProvenanceRequested: OAuthScopeProvenance?

    public init(
        issuer: String,
        clientID: String,
        redirectURI: String,
        scopes: Set<String>,
        dpopJKT: String? = nil,
        confidentialClientKey: OAuthConfidentialClientKeyBinding? = nil,
        refreshTokenAllowed: Bool = true,
        scopesRequested: Set<String>? = nil,
        scopeProvenance: OAuthScopeProvenance? = nil,
        scopeProvenanceRequested: OAuthScopeProvenance? = nil
    ) {
        self.issuer = issuer
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.scopes = scopes
        self.dpopJKT = dpopJKT
        self.confidentialClientKey = confidentialClientKey
        self.refreshTokenAllowed = refreshTokenAllowed
        // Storing the requested set when it is identical to the effective one
        // would make `scopes_requested` ambiguous on reload; collapse it here,
        // once, so no caller has to remember the rule.
        self.scopesRequested = scopesRequested == scopes ? nil : scopesRequested
        self.scopeProvenance = scopeProvenance
        // Collapsed by the same rule and in the same place: when the requested
        // set is not stored, its provenance has nothing to be keyed by, and
        // `scopeProvenance` is already keyed by those very strings.
        self.scopeProvenanceRequested = self.scopesRequested == nil
            ? nil
            : scopeProvenanceRequested
    }

    /// The baseline a refreshing client is compared against (§9-D20). The `??`
    /// is §6.7's NULL rule, which makes this total: it is the *correct* answer
    /// for a pre-migration row, not a defensive shrug.
    ///
    /// Never compare a re-presented `scope` against `scopes`: under §9-D8 that
    /// column holds the post-resolution grant the client has never seen, and
    /// `authority=self` is the grammar's default, so the comparison would fail
    /// for essentially every grant Swan issues.
    public var requestedScopes: Set<String> { scopesRequested ?? scopes }

    /// This binding as it stood **before** any mint-time transformation: the
    /// requested scopes with the provenance that parse produced, and nothing
    /// derived from either.
    ///
    /// It is the input a refresh re-derives from (§5.7.5's "token mint /
    /// refresh"), which upstream spells `buildTokenScope(parameters.scope!, …)`
    /// on every rotation (`token-manager.ts:260`). The operand is the same one
    /// §9-D20 fixed for the refresh binding comparison, and for the same reason:
    /// `scopes` holds the post-`self`-resolution grant (§9-D8), so re-deriving
    /// from it would re-resolve an already-resolved value and drift.
    ///
    /// `nil` means the requested-side provenance is unavailable — a row written
    /// before `scope_provenance_requested` existed. It is deliberately not
    /// substituted with an empty map: an empty map is a *claim* that the client
    /// stated nothing, which would silently close both §9-D23 fences on a live
    /// grant that legitimately stated something. A caller that cannot get a
    /// baseline must leave the grant alone rather than narrow it.
    public func requestedBaseline() -> OAuthClientBinding? {
        let provenance: OAuthScopeProvenance?
        if let scopeProvenanceRequested {
            provenance = scopeProvenanceRequested
        } else if scopesRequested == nil {
            // Requested == effective, so `scopeProvenance` is already keyed by
            // the requested strings. Total for every pre-migration row, by the
            // same NULL rule as `requestedScopes` (§6.7).
            provenance = scopeProvenance ?? OAuthScopeProvenance()
        } else {
            return nil
        }
        return OAuthClientBinding(
            issuer: issuer,
            clientID: clientID,
            redirectURI: redirectURI,
            scopes: requestedScopes,
            dpopJKT: dpopJKT,
            confidentialClientKey: confidentialClientKey,
            refreshTokenAllowed: refreshTokenAllowed,
            scopeProvenance: provenance
        )
    }

    /// Everything a durable comparison treats as the binding's identity.
    ///
    /// `scopesRequested` and `scopeProvenance` are deliberately excluded: both
    /// are *derived from* the scope set that is compared, so including them can
    /// only manufacture a false mismatch — e.g. a PAR consumed with a binding
    /// rebuilt from a fresh session rather than round-tripped through storage.
    /// They carry no authority a matching `scopes` does not already carry.
    public func matchesIdentity(of other: OAuthClientBinding) -> Bool {
        issuer == other.issuer && clientID == other.clientID
            && redirectURI == other.redirectURI && scopes == other.scopes
            && dpopJKT == other.dpopJKT
            && confidentialClientKey == other.confidentialClientKey
            && refreshTokenAllowed == other.refreshTokenAllowed
    }

    /// Returns a copy whose effective grant is `scopes`, preserving the
    /// requested bytes and re-keyed provenance. Used by the mint-time `self`
    /// rewrite (§6.4), which changes values and must not change statedness.
    ///
    /// The requested-side provenance is frozen here, at the one point where the
    /// two sides part company: whatever this binding held before the rewrite is
    /// what the requested strings were parsed with, so it is preserved verbatim
    /// rather than re-derived later from either serialised set (§9-D23).
    public func withEffectiveScopes(
        _ scopes: Set<String>,
        provenance: OAuthScopeProvenance?
    ) -> OAuthClientBinding {
        OAuthClientBinding(
            issuer: issuer,
            clientID: clientID,
            redirectURI: redirectURI,
            scopes: scopes,
            dpopJKT: dpopJKT,
            confidentialClientKey: confidentialClientKey,
            refreshTokenAllowed: refreshTokenAllowed,
            scopesRequested: requestedScopes,
            scopeProvenance: (provenance ?? scopeProvenance)?.restricted(to: scopes),
            scopeProvenanceRequested: scopeProvenanceRequested
                ?? scopeProvenance
                ?? OAuthScopeProvenance()
        )
    }
}

/// A validated client metadata document cached until `expiresAt`. The
/// document is public metadata; secret client credentials do not belong here.
public struct OAuthCachedClientMetadata: Sendable, Equatable {
    public let clientID: String
    public let document: Data
    public let expiresAt: Date

    public init(clientID: String, document: Data, expiresAt: Date) {
        self.clientID = clientID
        self.document = document
        self.expiresAt = expiresAt
    }
}

/// A durable, per-client ordering token issued before remote metadata or JWKS
/// retrieval begins. The generation is monotonically increasing in the
/// control database and deliberately survives cache-entry eviction, so a
/// delayed older fetch cannot republish stale key material after a newer
/// revalidation has completed.
public struct OAuthClientMetadataFetchTicket: Sendable, Equatable {
    public let clientID: String
    public let generation: Int64

    public init(clientID: String, generation: Int64) {
        self.clientID = clientID
        self.generation = generation
    }
}

/// Swan supports only RFC 7636's SHA-256 proof-key transform. The method is
/// durable alongside the challenge so a future endpoint cannot silently fall
/// back to `plain` PKCE when interpreting an old PAR or code.
public enum OAuthCodeChallengeMethod: String, Sendable, Equatable {
    case s256 = "S256"
}

/// A pushed authorization request keyed only by a digest of its opaque
/// request URI. The raw request URI is intentionally never stored.
public struct OAuthPushedAuthorizationRequest: Sendable, Equatable {
    public let requestDigest: Data
    public let binding: OAuthClientBinding
    /// Exact opaque client state returned with a future authorization code.
    /// It is bounded/untrusted client input, not a bearer credential.
    public let state: String
    /// A keyed digest which prevents state reuse through PAR expiry without
    /// indexing a raw state value.
    public let stateDigest: Data
    public let codeChallengeMethod: OAuthCodeChallengeMethod
    public let codeChallengeS256: String
    public let expiresAt: Date

    public init(
        requestDigest: Data,
        binding: OAuthClientBinding,
        state: String,
        stateDigest: Data,
        codeChallengeMethod: OAuthCodeChallengeMethod = .s256,
        codeChallengeS256: String,
        expiresAt: Date
    ) {
        self.requestDigest = requestDigest
        self.binding = binding
        self.state = state
        self.stateDigest = stateDigest
        self.codeChallengeMethod = codeChallengeMethod
        self.codeChallengeS256 = codeChallengeS256
        self.expiresAt = expiresAt
    }
}

/// A pending authorization code. `codeDigest` is a keyed digest; raw codes
/// never cross the storage boundary. A consumed code remains as a replay
/// sentinel until the associated token family can no longer be valid.
public struct OAuthAuthorizationCode: Sendable, Equatable {
    public let codeDigest: Data
    public let familyID: UUID
    public let subject: String
    public let binding: OAuthClientBinding
    public let codeChallengeMethod: OAuthCodeChallengeMethod
    public let codeChallengeS256: String
    public let expiresAt: Date
    public let familyExpiresAt: Date
    public let consumedAt: Date?

    public init(
        codeDigest: Data,
        familyID: UUID,
        subject: String,
        binding: OAuthClientBinding,
        codeChallengeMethod: OAuthCodeChallengeMethod = .s256,
        codeChallengeS256: String,
        expiresAt: Date,
        familyExpiresAt: Date,
        consumedAt: Date? = nil
    ) {
        self.codeDigest = codeDigest
        self.familyID = familyID
        self.subject = subject
        self.binding = binding
        self.codeChallengeMethod = codeChallengeMethod
        self.codeChallengeS256 = codeChallengeS256
        self.expiresAt = expiresAt
        self.familyExpiresAt = familyExpiresAt
        self.consumedAt = consumedAt
    }
}

/// Durable status and binding facts for an OAuth token family. A family is
/// created before a code is redeemed so that a later code replay can revoke
/// every token the original redemption produced.
public struct OAuthTokenFamily: Sendable, Equatable {
    public let familyID: UUID
    public let subject: String
    public let binding: OAuthClientBinding
    public let expiresAt: Date
    public let revokedAt: Date?

    public init(
        familyID: UUID,
        subject: String,
        binding: OAuthClientBinding,
        expiresAt: Date,
        revokedAt: Date? = nil
    ) {
        self.familyID = familyID
        self.subject = subject
        self.binding = binding
        self.expiresAt = expiresAt
        self.revokedAt = revokedAt
    }
}

/// A pair of *keyed HMAC digests* for opaque access and refresh tokens. The
/// raw bearer strings are generated and retained only by the OAuth layer.
public struct OAuthIssuedTokenDigests: Sendable, Equatable {
    public let familyID: UUID
    public let accessTokenDigest: Data
    /// A code issued to a client which did not declare `refresh_token` has no
    /// refresh credential at all.  Keeping this optional is materially
    /// different from minting an undisclosed refresh token: no durable bearer
    /// capability then exists to be discovered or accidentally enabled later.
    public let refreshTokenDigest: Data?
    public let accessExpiresAt: Date
    public let refreshExpiresAt: Date?

    public init(
        familyID: UUID,
        accessTokenDigest: Data,
        refreshTokenDigest: Data? = nil,
        accessExpiresAt: Date,
        refreshExpiresAt: Date? = nil
    ) {
        self.familyID = familyID
        self.accessTokenDigest = accessTokenDigest
        self.refreshTokenDigest = refreshTokenDigest
        self.accessExpiresAt = accessExpiresAt
        self.refreshExpiresAt = refreshExpiresAt
    }
}

/// A grant re-derived at refresh, written into its family row by the same
/// durable transaction that rotates the token digests (§5.7.5's second call
/// site; upstream passes `scope` into `store.rotateToken`, `token-manager.ts:266-274`).
///
/// It carries the effective side only. The requested side — `scopes_requested`
/// and `scope_provenance_requested` — is the client's own frozen input and the
/// baseline every later refresh re-derives from (§9-D20); a rotation that
/// rewrote it would move the baseline under itself, and the second refresh
/// would compare against bytes the client never sent.
///
/// Rotation and scope rewrite are one transaction rather than two on purpose: a
/// write that rotated the digests without the scopes would mint a token whose
/// stored grant is the one the re-derivation just rejected, and the reverse
/// would narrow a live family without issuing the token that narrowing was for.
public struct OAuthRefreshedGrant: Sendable, Equatable {
    /// The effective, post-transformation grant.
    public let scopes: Set<String>
    /// Provenance keyed by those effective strings (§9-D23).
    public let scopeProvenance: OAuthScopeProvenance

    public init(scopes: Set<String>, scopeProvenance: OAuthScopeProvenance) {
        self.scopes = scopes
        self.scopeProvenance = scopeProvenance
    }
}

/// The two opaque token tables which may identify a durable OAuth family for
/// RFC 7009 revocation. Keeping this typed prevents an adapter from probing
/// arbitrary control-plane tables using a client-presented string.
public enum OAuthOpaqueTokenKind: Sendable, Equatable {
    case accessToken
    case refreshToken
}

/// Domain-specific durable OAuth state. This is intentionally not a generic
/// key/value API: every operation names the protocol fact and transaction
/// boundary it needs to preserve.
public protocol OAuthControlStore: Sendable {
    func cacheClientMetadata(_ metadata: OAuthCachedClientMetadata, now: Date) async throws
    func cachedClientMetadata(clientID: String, now: Date) async throws -> OAuthCachedClientMetadata?
    /// Advances the durable freshness watermark for `clientID`. Fetchers must
    /// obtain this ticket before performing any remote I/O.
    func beginClientMetadataFetch(
        clientID: String,
        now: Date
    ) async throws -> OAuthClientMetadataFetchTicket
    /// Publishes only if `ticket` is still the latest generation issued for
    /// its client. A `false` result means a newer fetch won the race; the
    /// caller must not use or return its stale response for authorization.
    func publishClientMetadata(
        _ metadata: OAuthCachedClientMetadata,
        using ticket: OAuthClientMetadataFetchTicket,
        now: Date
    ) async throws -> Bool
    /// Releases a ticket whose fetch will never publish. Without it a failed
    /// or rejected remote document leaves a durable freshness row behind, and
    /// an anonymous caller can fill that bounded table with client IDs it
    /// merely named. The store deletes only while `ticket` is still the sole
    /// outstanding generation for its client and no cached document depends on
    /// the watermark, so a concurrent successful flight is a no-op rather than
    /// a lost row. Abandoning a ticket that no longer qualifies is not an
    /// error: the caller cannot know which race it lost.
    func abandonClientMetadataFetch(
        ticket: OAuthClientMetadataFetchTicket,
        now: Date
    ) async throws
    /// True when the account currently holds a live, unrevoked token family
    /// naming this client. It is the one client-identity fact available before
    /// any remote document is fetched that an anonymous caller cannot
    /// manufacture: creating it requires completing an authorization against
    /// the account's own credentials.
    func clientHoldsLiveAuthorization(
        clientID: String,
        now: Date
    ) async throws -> Bool

    func storePushedAuthorizationRequest(_ request: OAuthPushedAuthorizationRequest, now: Date) async throws
    /// Returns an unexpired, unconsumed PAR selected by the keyed digest of
    /// its opaque request URI. The raw URI and any browser-session material
    /// never enter durable storage.
    func activePushedAuthorizationRequest(
        requestDigest: Data,
        now: Date
    ) async throws -> OAuthPushedAuthorizationRequest?
    func consumePushedAuthorizationRequest(
        requestDigest: Data,
        binding: OAuthClientBinding,
        now: Date
    ) async throws -> OAuthPushedAuthorizationRequest

    func storeAuthorizationCode(_ code: OAuthAuthorizationCode, now: Date) async throws
    /// Atomically stores the code and its token family only while the subject
    /// remains active at the exact account revision authenticated into the
    /// browser cookie. This is the consent/password-recovery linearization
    /// point; the revision is SQLite's microsecond `accounts.updated_at`.
    func storeAuthorizationCode(
        _ code: OAuthAuthorizationCode,
        requiringActiveSubjectRevisionMicroseconds revision: Int64,
        now: Date
    ) async throws
    /// Returns a code's immutable PKCE/binding facts. A consumed code is
    /// returned as a replay sentinel; only the redemption transaction decides
    /// whether it can issue tokens.
    func authorizationCode(codeDigest: Data, now: Date) async throws -> OAuthAuthorizationCode?
    func redeemAuthorizationCode(
        codeDigest: Data,
        binding: OAuthClientBinding,
        issuedTokens: OAuthIssuedTokenDigests,
        requireActiveSubject: Bool,
        now: Date
    ) async throws

    func issueTokenPair(
        family: OAuthTokenFamily,
        tokens: OAuthIssuedTokenDigests,
        now: Date
    ) async throws
    func validatedAccessToken(
        accessTokenDigest: Data,
        requireActiveSubject: Bool,
        now: Date
    ) async throws -> OAuthTokenFamily
    func refreshTokenFamily(refreshTokenDigest: Data, now: Date) async throws -> OAuthTokenFamily
    /// Returns an active, unrevoked family selected by one typed opaque-token
    /// digest. This is used only to validate sender constraints immediately
    /// before revocation; callers receive no raw token material.
    func tokenFamily(
        tokenDigest: Data,
        kind: OAuthOpaqueTokenKind,
        now: Date
    ) async throws -> OAuthTokenFamily?
    /// Rotates a refresh token and, when `rewrittenGrant` is present, writes the
    /// re-derived grant into the same family row **inside the same
    /// transaction**. `nil` leaves the stored grant untouched, which is both the
    /// no-change case and the "cannot re-derive" case (see
    /// ``OAuthClientBinding/requestedBaseline()``).
    func redeemRefreshToken(
        refreshTokenDigest: Data,
        replacement: OAuthIssuedTokenDigests,
        rewrittenGrant: OAuthRefreshedGrant?,
        requireActiveSubject: Bool,
        now: Date
    ) async throws
    /// Revokes the complete family identified by a refresh-token digest. The
    /// return value is false only when the digest was not known.
    func revokeTokenFamily(refreshTokenDigest: Data, now: Date) async throws -> Bool
    /// Revokes a family selected from already-validated durable state. This is
    /// used when fresh confidential-client metadata shows the persisted key has
    /// been removed or rekeyed, and must be a single durable transaction.
    func revokeTokenFamily(familyID: UUID, now: Date) async throws

    /// Atomically reserves a DPoP `jti` digest through its proof validity.
    /// The store receives no DPoP proof body or raw `jti`.
    func claimDPoPReplay(digest: Data, expiresAt: Date, now: Date) async throws -> Bool
    /// Client assertion `jti` values have a separate durable replay namespace
    /// and are likewise represented by a keyed digest only.
    func claimClientAssertion(
        digest: Data,
        clientID: String,
        expiresAt: Date,
        now: Date
    ) async throws -> Bool

    func purgeExpiredOAuthControlState(now: Date) async throws
}

/// One durable, expiry-bounded reservation for a verified permissioned-data
/// delegation. The caller supplies an authority-scoped HMAC digest, never the
/// raw JWT or its `jti`, so this remains a separate replay namespace from
/// OAuth DPoP and client-assertion identifiers.
///
/// The reservation is deliberately made before authority policy evaluation or
/// credential signing. A `false` result means a previously verified
/// delegation has already been consumed and must not produce another
/// credential.
public protocol SpaceDelegationReplayStore: Sendable {
    func claimSpaceDelegation(
        digest: Data,
        expiresAt: Date,
        now: Date
    ) async throws -> Bool
}

/// Durable single-use reservation for a cryptographically verified
/// proposal-0016 client attestation. The storage boundary accepts only a
/// keyed 32-byte digest and expiry; raw JWT, JTI, client identity, signature,
/// delegation, credential, and private-key material are not representable.
public protocol SpaceClientAttestationReplayStore: Sendable {
    func claimSpaceClientAttestation(
        digest: Data,
        expiresAt: Date,
        now: Date
    ) async throws -> Bool
}
