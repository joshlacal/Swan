import Crypto
import Foundation
import SwanCore
import SwanSpaces

public enum BlobNamespace: Sendable, Hashable {
    case `public`
    case space(SpaceURI)
}

public struct BlobReference: Sendable, Hashable {
    public let cid: String
    public let namespace: BlobNamespace
    public init(cid: String, namespace: BlobNamespace) {
        self.cid = cid
        self.namespace = namespace
    }
}

public protocol BlobStore: Sendable {
    func put(_ data: Data, namespace: BlobNamespace) async throws -> BlobReference
    func data(for reference: BlobReference) async throws -> Data
    func publicData(cid: String) async throws -> Data?
    func remove(_ reference: BlobReference) async throws
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

/// Values which bind an OAuth request, authorization code, and token family.
/// Keeping these values together makes it hard for a later HTTP adapter to
/// accidentally turn a PAR or code for one client/redirect URI into a token
/// for another.
public struct OAuthClientBinding: Sendable, Equatable {
    public let issuer: String
    public let clientID: String
    public let redirectURI: String
    public let scopes: Set<String>
    /// RFC 7638 S256 JWK thumbprint binding. This is public key metadata, not
    /// a DPoP proof body.
    public let dpopJKT: String?
    /// The complete verified key identity for a `private_key_jwt` client.
    /// It is intentionally absent for public clients; an identifier-only
    /// confidential-client binding is not representable.
    public let confidentialClientKey: OAuthConfidentialClientKeyBinding?

    public init(
        issuer: String,
        clientID: String,
        redirectURI: String,
        scopes: Set<String>,
        dpopJKT: String? = nil,
        confidentialClientKey: OAuthConfidentialClientKeyBinding? = nil
    ) {
        self.issuer = issuer
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.scopes = scopes
        self.dpopJKT = dpopJKT
        self.confidentialClientKey = confidentialClientKey
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
    public let refreshTokenDigest: Data
    public let accessExpiresAt: Date
    public let refreshExpiresAt: Date

    public init(
        familyID: UUID,
        accessTokenDigest: Data,
        refreshTokenDigest: Data,
        accessExpiresAt: Date,
        refreshExpiresAt: Date
    ) {
        self.familyID = familyID
        self.accessTokenDigest = accessTokenDigest
        self.refreshTokenDigest = refreshTokenDigest
        self.accessExpiresAt = accessExpiresAt
        self.refreshExpiresAt = refreshExpiresAt
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
    /// Returns a code's immutable PKCE/binding facts. A consumed code is
    /// returned as a replay sentinel; only the redemption transaction decides
    /// whether it can issue tokens.
    func authorizationCode(codeDigest: Data, now: Date) async throws -> OAuthAuthorizationCode?
    func redeemAuthorizationCode(
        codeDigest: Data,
        binding: OAuthClientBinding,
        issuedTokens: OAuthIssuedTokenDigests,
        now: Date
    ) async throws

    func issueTokenPair(
        family: OAuthTokenFamily,
        tokens: OAuthIssuedTokenDigests,
        now: Date
    ) async throws
    func validatedAccessToken(accessTokenDigest: Data, now: Date) async throws -> OAuthTokenFamily
    func refreshTokenFamily(refreshTokenDigest: Data, now: Date) async throws -> OAuthTokenFamily
    /// Returns an active, unrevoked family selected by one typed opaque-token
    /// digest. This is used only to validate sender constraints immediately
    /// before revocation; callers receive no raw token material.
    func tokenFamily(
        tokenDigest: Data,
        kind: OAuthOpaqueTokenKind,
        now: Date
    ) async throws -> OAuthTokenFamily?
    func redeemRefreshToken(
        refreshTokenDigest: Data,
        replacement: OAuthIssuedTokenDigests,
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
