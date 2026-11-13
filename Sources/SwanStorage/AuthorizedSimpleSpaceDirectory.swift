import Crypto
import Foundation
import Petrel
import SwanCore
import SwanSpaces
/// A caller-selected record mutation.  Unlike ``SpaceWrite``, this retains
/// the XRPC operation's requested create/update semantics until the durable
/// transaction has checked them against the authoritative SQLite state.
/// Keeping `put` distinct is important: it is the only endpoint permitted to
/// choose create versus update from that state.
public enum AuthorizedSpaceRepositoryWrite: Sendable, Equatable {
    case create(uri: SpaceRecordURI, value: Data)
    case put(uri: SpaceRecordURI, value: Data)
    case update(uri: SpaceRecordURI, value: Data)
    case delete(uri: SpaceRecordURI)

    public var uri: SpaceRecordURI {
        switch self {
        case let .create(uri, _): return uri
        case let .put(uri, _): return uri
        case let .update(uri, _): return uri
        case let .delete(uri): return uri
        }
    }

    public var valueByteCount: Int {
        switch self {
        case let .create(_, value), let .put(_, value), let .update(_, value):
            value.count
        case .delete:
            0
        }
    }
}

/// The privacy-safe subset of a committed mutation required to render the
/// generated write outputs. It deliberately omits the opaque outbox payload,
/// LT-hash material, and any other repository state.
public struct AuthorizedSpaceRepositoryWriteResult: Sendable, Equatable {
    public enum Action: Sendable, Equatable {
        case create
        case update
        case delete
    }

    public let action: Action
    public let uri: SpaceRecordURI
    public let cid: String?

    public init(action: Action, uri: SpaceRecordURI, cid: String?) {
        self.action = action
        self.uri = uri
        self.cid = cid
    }
}

/// The current durable facts needed to create a reader-specific permissioned
/// commit.  The value deliberately contains the LtHash *commitment*, never
/// the serialized LtHash state, an account key reference, or a database
/// handle.  A `nil` wire revision means the repository has not committed a
/// permissioned write, matching the reference PDS's absent signed commit.
public struct AuthorizedSpaceRepositoryCommitState: Sendable, Equatable {
    public let space: SpaceURI
    public let author: String
    public let wireRevision: String?
    public let commitment: Data

    public init(
        space: SpaceURI,
        author: String,
        wireRevision: String?,
        commitment: Data
    ) {
        self.space = space
        self.author = author
        self.wireRevision = wireRevision
        self.commitment = commitment
    }
}

/// A validated, immutable permissioned-repository snapshot prepared for
/// full-CAR recovery. The private spool contains only the index and record
/// blocks. Its reader-specific signed commit is created later by the narrow
/// account-key signer and is never written to SQLite or a spool.
public struct AuthorizedSpaceRepositoryCARSnapshot: Sendable {
    public let state: AuthorizedSpaceRepositoryCommitState
    public let spool: SpaceCARBodySpool

    public init(
        state: AuthorizedSpaceRepositoryCommitState,
        spool: SpaceCARBodySpool
    ) {
        self.state = state
        self.spool = spool
    }
}

/// One privacy-safe permissioned oplog row for the incremental-sync XRPC
/// surface.  `value` is present only when the current live record still has
/// this row's CID; historic values and SQLite implementation details never
/// cross this boundary.
public struct AuthorizedSpaceRepositoryOplogEntry: Sendable, Equatable {
    public let wireRevision: String
    public let collection: String
    public let rkey: String
    public let cid: String?
    public let previousCID: String?
    public let value: Data?

    public init(
        wireRevision: String,
        collection: String,
        rkey: String,
        cid: String?,
        previousCID: String?,
        value: Data?
    ) {
        self.wireRevision = wireRevision
        self.collection = collection
        self.rkey = rkey
        self.cid = cid
        self.previousCID = previousCID
        self.value = value
    }
}

/// The only two incremental-read outcomes visible to the HTTP adapter.  A
/// retention gap carries no historic records or recovery CAR; callers must
/// use the separate, later `getRepo` full-recovery endpoint.
public enum AuthorizedSpaceRepositoryOplogRead: Sendable, Equatable {
    case incremental(
        state: AuthorizedSpaceRepositoryCommitState,
        entries: [AuthorizedSpaceRepositoryOplogEntry]
    )
    case fullRecoveryRequired
}

/// The deliberately narrow result available to an authenticated authority
/// lookup. It is a projection made only after the durable simple-space state
/// has been fully decoded and validated; owner, members, revision, deletion
/// state, and managing-app decisions are intentionally not representable.
public struct AuthenticatedSimpleSpaceDescription: Sendable, Equatable {
    public let space: SpaceURI
    public let configuration: SimpleSpaceConfiguration

    public init(space: SpaceURI, configuration: SimpleSpaceConfiguration) {
        self.space = space
        self.configuration = configuration
    }
}

/// Startup-preopened authority directory for the authenticated
/// space lifecycle and memberspace surface (formerly `com.atproto.simplespace`).
///
/// Implementations must never treat a request authority as permission to
/// create, migrate, or open an account database. They preopen an explicitly
/// enumerated active-account set during service startup and return only the
/// safe description projection above.
public protocol AuthorizedSimpleSpaceDirectory: Sendable {
    func space(
        _ space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws -> AuthenticatedSimpleSpaceDescription?

    func close() async throws
}

/// A proof that an account database was selected from the startup inventory
/// and remains usable without a request-time open or migration.  It exposes
/// no repository or authority state: user-PDS delegation minting needs only
/// this lifecycle/preopen gate before asking its separately configured key
/// signer to create a short-lived token.
public protocol AuthorizedPreopenedAccountDirectory: Sendable {
    func requireActivePreopenedAccount(_ did: String) async throws
}

/// The authenticated account's current view of one hosted space.
public struct AuthorizedHostedSpace: Sendable, Equatable {
    public let space: SpaceURI
    public let repoRev: String?
    public let data: Data?
    public let spaceRev: String?

    public init(space: SpaceURI, repoRev: String?, data: Data?, spaceRev: String?) {
        self.space = space
        self.repoRev = repoRev
        self.data = data
        self.spaceRev = spaceRev
    }
}

/// Typed and already-validated request dimensions for a local hosted-space
/// projection. A nil dimension means the caller requested the aggregate
/// wildcard; cursor is a canonical `SpaceURI`, never an opaque SQL cursor.
public struct AuthorizedHostedSpaceListQuery: Sendable, Equatable {
    public let subject: String
    public let spaceType: String?
    public let authority: String?
    public let cursor: SpaceURI?
    public let limit: Int

    public init(
        subject: String,
        spaceType: String?,
        authority: String?,
        cursor: SpaceURI?,
        limit: Int
    ) {
        self.subject = subject
        self.spaceType = spaceType
        self.authority = authority
        self.cursor = cursor
        self.limit = limit
    }
}

public struct AuthorizedHostedSpacePage: Sendable, Equatable {
    public let spaces: [AuthorizedHostedSpace]
    public let cursor: SpaceURI?

    public init(spaces: [AuthorizedHostedSpace], cursor: SpaceURI?) {
        self.spaces = spaces
        self.cursor = cursor
    }
}

/// The local hosted-space view. Implementations must select only the
/// authenticated subject's startup-preopened active account database; this
/// API deliberately cannot select an arbitrary account or enumerate members.
public protocol AuthorizedHostedSpaceDirectory: Sendable {
    func hostedSpaces(
        _ query: AuthorizedHostedSpaceListQuery,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedHostedSpacePage
}

/// An opaque, already-verified permissioned blob body.  The storage adapter
/// owns the underlying descriptor and never exposes a path or a `Data` value,
/// so an HTTP route cannot accidentally buffer a private blob or retarget a
/// file after authorization has completed.
public protocol AuthorizedSpaceBlobBody: StreamingBlobBody {
    /// File metadata was validated against the descriptor before this body was
    /// returned.  It is therefore safe for the HTTP adapter to emit it as a
    /// content length without looking the path up again.
    var contentLength: Int { get }

    /// Delivers at most `maximumChunkBytes` on each call.  Implementations
    /// must close and clean up their descriptor on normal completion, writer
    /// failure, or task cancellation.
    func streamBody(
        maximumChunkBytes: Int,
        consume: (Data) async throws -> Void
    ) async throws
}

/// The narrow durable projection required by `com.atproto.space.getBlob`.
/// It deliberately has no public-blob fallback and no path, database, or
/// mutable reference exposure.  Implementations select only startup-preopened
/// account databases and apply aggregate repository-read authorization before
/// opening the private content-addressed payload.
public struct AuthorizedSpaceBlob: Sendable {
    public let mimeType: String?
    public let body: any AuthorizedSpaceBlobBody

    public init(mimeType: String?, body: any AuthorizedSpaceBlobBody) {
        self.mimeType = mimeType
        self.body = body
    }
}

/// The declared length of an authorized space blob, read without opening a
/// body or materializing a payload.
///
/// This exists so the transfer budget can be reserved for the bytes a
/// response will actually stream. Reserving a fixed ceiling instead makes a
/// 5 KiB avatar cost a quarter of one author's allowance for as long as its
/// reader takes, so a handful of stalled tiny reads exhaust the pool that the
/// public CAR, public blob, and blob-upload streams share. It carries only the
/// size: the MIME type a response emits is the one the opened body declares.
public struct AuthorizedSpaceBlobMetadata: Sendable, Equatable {
    public let size: Int

    public init(size: Int) {
        self.size = size
    }
}

public protocol AuthorizedSpaceBlobDirectory: Sendable {
    /// The blob's declared length under the same authorization, lifecycle, and
    /// namespace checks `spaceBlob` applies. It must never be reachable on a
    /// request that `spaceBlob` would refuse, or it becomes an existence and
    /// size oracle for private content.
    func spaceBlobMetadata(
        space: SpaceURI,
        author: String,
        cid: String,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceBlobMetadata?

    func spaceBlob(
        space: SpaceURI,
        author: String,
        cid: String,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceBlob?
}

// MARK: - Writer discovery and notification routing

/// The small, non-content-bearing synchronisation hint maintained by a space
/// authority. A writer entry never grants access: membership and credentials
/// remain separate authority policy. `commitment` is the SHA-256 LtHash
/// commitment reported by the writer PDS, not a CAR, record CID, or value.
public struct AuthorizedSpaceWriter: Sendable, Equatable {
    public let space: SpaceURI
    public let repository: String
    public let wireRevision: String
    public let commitment: Data
    /// The space revision (a TID allocated by the space host) at which this
    /// writer state was last accepted. `nil` only for values that never came
    /// from the authority's writer set, such as a repo host's outbound
    /// announcement, which carries no space revision.
    public let spaceRevision: String?
    /// A removed writer remains in the sequenced set until a later write
    /// re-adds it. Its previous repo revision and commitment are retained only
    /// as durable high-water state and are not emitted on the wire.
    public let isRemoved: Bool

    public init(
        space: SpaceURI,
        repository: String,
        wireRevision: String,
        commitment: Data,
        spaceRevision: String? = nil,
        isRemoved: Bool = false
    ) {
        self.space = space
        self.repository = repository
        self.wireRevision = wireRevision
        self.commitment = commitment
        self.spaceRevision = spaceRevision
        self.isRemoved = isRemoved
    }
}


/// A notification registration created while authorizing a space sync. The
/// opaque token is supplied by the endpoint and is never an authorization
/// credential for Swan.
public struct AuthorizedSpaceSyncRegistration: Sendable, Equatable {
    public let space: SpaceURI
    public let endpoint: String
    public let token: String
    public let expiresAt: Date
    public let expiryNotified: Bool

    public init(
        space: SpaceURI,
        endpoint: String,
        token: String,
        expiresAt: Date,
        expiryNotified: Bool = false
    ) {
        self.space = space
        self.endpoint = endpoint
        self.token = token
        self.expiresAt = expiresAt
        self.expiryNotified = expiryNotified
    }
}

/// Durable registration state owned by the space authority. Selection is
/// always through a startup-preopened authority database.
public protocol AuthorizedSpaceSyncRegistrationDirectory: Sendable {
    /// Requires an active space and returns its latest revision, or `nil`
    /// before the first sequenced update.
    func activeSpaceRevision(_ space: SpaceURI) async throws -> String?
    func spaceSyncRegistration(
        space: SpaceURI,
        endpoint: String,
        token: String
    ) async throws -> AuthorizedSpaceSyncRegistration?
    func putSpaceSyncRegistration(
        _ registration: AuthorizedSpaceSyncRegistration
    ) async throws
    func removeSpaceSyncRegistration(
        space: SpaceURI,
        endpoint: String,
        token: String
    ) async throws
}

/// A signed service announcement after its HTTP/JWT boundary has completed.
/// `eventID` is the opaque service-JWT JTI, recorded transactionally by the
/// authority. Senders mint a fresh one per attempt, so a repeat is recognized
/// by its revision, not its JTI. It is never an authorization credential.
public struct AuthorizedSpaceWriteNotification: Sendable, Equatable {
    public let eventID: String
    public let space: SpaceURI
    public let repository: String
    public let wireRevision: String
    public let commitment: Data
    public let issuer: String
    public let audience: String
    public let requestBodyDigest: String

    public init(
        eventID: String,
        space: SpaceURI,
        repository: String,
        wireRevision: String,
        commitment: Data,
        issuer: String,
        audience: String,
        requestBodyDigest: String
    ) {
        self.eventID = eventID
        self.space = space
        self.repository = repository
        self.wireRevision = wireRevision
        self.commitment = commitment
        self.issuer = issuer
        self.audience = audience
        self.requestBodyDigest = requestBodyDigest
    }
}

/// A startup-preopened authority projection for the writer-set and recipient
/// registry. It intentionally does not expose a SQLite handle or any record
/// material. Every method operates on the authority account selected by the
/// parsed `SpaceURI`; request-selected accounts are never opened or migrated.
public protocol AuthorizedSpaceNotificationDirectory: Sendable {
    func listSpaceWriters(
        space: SpaceURI,
        limit: Int,
        cursor: String?,
        authorization: AuthorizationContext
    ) async throws -> [AuthorizedSpaceWriter]


    /// Records a direct writer-to-authority service-authenticated announcement.
    /// In one transaction it advances the writer's state, allocates the next
    /// space revision (strictly increasing across all writers in the space),
    /// and queues authority-signed forwards to registered services carrying
    /// that `spaceRev` and the preceding one. Duplicate or older/reordered
    /// events are idempotent no-ops that allocate and forward nothing. An
    /// unknown or deleted space throws ``AuthorizedSimpleSpaceLifecycleError``;
    /// a revision too far in the future throws
    /// ``AuthorizedSpaceWriteNotificationError/futureRevision``.
    func receiveSpaceWriteNotification(
        _ notification: AuthorizedSpaceWriteNotification
    ) async throws
}


/// A deliberately narrow lifecycle/membership projection for a simple-space
/// authority account that was opened at service startup.  It names domain
/// operations rather than exposing a SQLite handle or mutable authority
/// object, so request handlers cannot create, migrate, or select an arbitrary
/// account database.
public protocol AuthorizedSimpleSpaceLifecycleDirectory: Sendable {
    func createSimpleSpace(
        _ space: SpaceURI,
        configuration: SimpleSpaceConfiguration,
        authorization: AuthorizationContext
    ) async throws

    /// Replaces the policy wholesale (October 29 `updateSpace`). A policy of
    /// a different `$type` discards the previous policy's state, such as a
    /// memberspace member list.
    func updateSimpleSpace(
        _ space: SpaceURI,
        configuration: SimpleSpaceConfiguration,
        authorization: AuthorizationContext
    ) async throws

    func deleteSimpleSpace(
        _ space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws

    func putSimpleSpaceMembers(
        _ members: [AuthorizedSimpleSpaceMemberPage.Member],
        in space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws

    func removeSimpleSpaceMembers(
        _ members: [String],
        from space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws

    func simpleSpaceMembers(
        _ space: SpaceURI,
        limit: Int,
        cursor: String?,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSimpleSpaceMemberPage

    /// `com.atproto.space.removeWriter`: drops one account from the space's
    /// writer set. Idempotent; the account is tracked again after its next
    /// authorized write.
    func removeSpaceWriter(
        _ writer: String,
        from space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws

    func exportSpaceMeta(
        _ space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws -> SpaceMetaArchive

    func importSpaceMeta(
        _ archive: SpaceMetaArchive,
        authorization: AuthorizationContext
    ) async throws
}

public extension AuthorizedSimpleSpaceLifecycleDirectory {
    func removeSpaceWriter(
        _: String,
        from _: SpaceURI,
        authorization _: AuthorizationContext
    ) async throws {
        throw SwanError.unavailable("space writer removal is unavailable")
    }

    /// `com.atproto.space.exportSpaceMeta`: the authority's state for one
    /// live space, for the owner's OAuth with `read_self`.
    func exportSpaceMeta(
        _: SpaceURI,
        authorization _: AuthorizationContext
    ) async throws -> SpaceMetaArchive {
        throw SwanError.unavailable("space meta export is unavailable")
    }

    /// `com.atproto.space.importSpaceMeta`: creates or replaces the
    /// authority's space from its previous host's archive. Requires
    /// `manage=create` and `manage=update`; publishes nothing.
    func importSpaceMeta(
        _: SpaceMetaArchive,
        authorization _: AuthorizationContext
    ) async throws {
        throw SwanError.unavailable("space meta import is unavailable")
    }
}

/// The two decisions returned by `com.atproto.managedspace.checkAccess`.
public struct ManagedSpaceAccess: Sendable, Equatable {
    public let read: Bool
    public let write: Bool

    public init(read: Bool, write: Bool) {
        self.read = read
        self.write = write
    }
}

/// A managing app that cannot be reached or does not answer correctly is an
/// upstream failure, not an access denial.
public enum ManagedSpaceAccessError: Error, Sendable, Equatable {
    case upstreamFailure
}

/// Asks a managedspace's managing app for both access decisions in one
/// `com.atproto.managedspace.checkAccess` request. `repo` is absent when the
/// credential request carries no delegation token.
public protocol ManagedSpaceAccessChecking: Sendable {
    func checkAccess(
        space: SpaceURI,
        repo: String?,
        clientID: String?,
        managingApp: String
    ) async throws -> ManagedSpaceAccess
}

/// The checker used when no managing-app client is configured.
public struct UnavailableManagedSpaceAccessChecker: ManagedSpaceAccessChecking {
    public init() {}

    public func checkAccess(
        space _: SpaceURI,
        repo _: String?,
        clientID _: String?,
        managingApp _: String
    ) async throws -> ManagedSpaceAccess {
        throw ManagedSpaceAccessError.upstreamFailure
    }
}

/// Startup-preopened authority policy projection used only while an
/// authority credential is being minted. It deliberately returns no space
/// state, members, keys, or credential material: after the durable policy
/// transaction succeeds, the caller may ask its separate key resolver to
/// sign a transient JWT.
///
/// Implementations must not perform network I/O inside their policy
/// transaction. In particular, client-attestation/JWKS resolution belongs to
/// a caller-supplied policy component which has completed before this method
/// is invoked.
public protocol AuthorizedSimpleSpaceCredentialDirectory: Sendable {
    func authorizeSimpleSpaceCredentialRead(
        space: SpaceURI,
        user: String?,
        clientID: String?,
        authorization: AuthorizationContext
    ) async throws
}

/// Privacy-safe page returned only after the caller has passed the exact
/// authority account and lifecycle-scope checks.  Member identities are
/// intentionally unavailable from the generic `getSpace` projection.
public struct AuthorizedSimpleSpaceMemberPage: Sendable, Equatable {
    public struct Member: Sendable, Equatable {
        public let did: String
        public let read: Bool
        public let write: Bool

        public init(did: String, read: Bool, write: Bool) {
            self.did = did
            self.read = read
            self.write = write
        }
    }

    public let members: [Member]
    public let cursor: String?

    public init(members: [Member], cursor: String?) {
        self.members = members
        self.cursor = cursor
    }

    public init(dids: [String], cursor: String?) {
        self.members = dids.map { Member(did: $0, read: true, write: true) }
        self.cursor = cursor
    }
}

/// Stable, privacy-safe lifecycle error used across the SQLite adapter and
/// HTTP boundary. It intentionally carries no space, account, member, or
/// storage detail.
public enum AuthorizedSimpleSpaceLifecycleError: Error, Sendable, Equatable {
    case notFound
    /// Credential renewal distinguishes a durable tombstone from a missing
    /// space so a syncer can discard retained data after a missed notification.
    case deleted
}

/// Account states which the Spaces wire exposes distinctly while treating all
/// other unavailable authority states as an opaque denial.
public enum AuthorizedSpaceAuthorityStatusError: Error, Sendable, Equatable {
    case deactivated
    case takendown
}

/// Marker for a managing-app call that failed upstream. The XRPC boundary
/// exposes this as a retryable HTTP 502 `UpstreamFailure`.
public protocol AuthorizedSpaceUpstreamFailure: Error, Sendable {}

extension ManagedSpaceAccessError: AuthorizedSpaceUpstreamFailure {}

/// A write notification the space host refuses for a reason the lexicon
/// names. Unknown and deleted spaces use
/// ``AuthorizedSimpleSpaceLifecycleError`` (`SpaceNotFound`) instead.
public enum AuthorizedSpaceWriteNotificationError: Error, Sendable, Equatable {
    /// `repoRev` is more than ``maximumFutureSkew`` ahead of the receiver's
    /// clock (`FutureRev`).
    case futureRevision

    /// The reference receiver's allowance: five minutes.
    public static let maximumFutureSkew: TimeInterval = 5 * 60
}

/// Startup-preopened, authenticated projection of a permissioned repository.
///
/// This is intentionally separate from ``AuthorizedSimpleSpaceDirectory``:
/// an authority-description adapter must not accidentally become a record
/// reader merely by conforming to a broad store protocol. Implementations may
/// select only a database that was opened during startup, and must invoke the
/// domain repository with the supplied ``AuthorizationContext`` rather than
/// treating a successful HTTP authentication as a boolean capability.
public protocol AuthorizedSpaceRepositoryDirectory: Sendable {
    /// Returns a single durable permissioned record, or `nil` when the
    /// selected repository/record is absent. Callers are responsible for
    /// rendering that absence without disclosing whether the space exists.
    func record(
        _ uri: SpaceRecordURI,
        authorization: AuthorizationContext
    ) async throws -> SpaceRecord?

    /// The distinct blob CIDs referenced by one account's records within a
    /// space, ordered ascending (`com.atproto.space.listBlobs`). `since`
    /// filters by the referencing record's last-write wire TID; `cursor` is
    /// the last CID of the previous page.
    func repositoryBlobCIDs(
        space: SpaceURI,
        author: String,
        since: String?,
        limit: Int,
        cursor: String?,
        authorization: AuthorizationContext
    ) async throws -> [String]

    /// Returns a bounded, deterministic page from one durable permissioned
    /// repository. `cursor` is already syntactically bounded by the HTTP
    /// adapter; malformed cursor *semantics* are tolerated by the domain
    /// reader to match the pinned TypeScript implementation.
    func records(
        space: SpaceURI,
        author: String,
        collection: String?,
        limit: Int,
        cursor: String?,
        reverse: Bool,
        authorization: AuthorizationContext
    ) async throws -> [SpaceRecord]

    /// Returns the current durable commitment facts for one preopened
    /// permissioned repository.  The supplied authorization is evaluated at
    /// the domain boundary; this is not an account-key lookup.
    func repositoryCommitState(
        space: SpaceURI,
        author: String,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceRepositoryCommitState

    /// Returns only the current wire revision after rechecking the exact
    /// permissions needed by an ordered write batch. This is intentionally
    /// distinct from ``repositoryCommitState``: a writer need not also hold a
    /// repository-read grant merely to seed a monotonic request TID.
    func repositoryWriteWireRevision(
        space: SpaceURI,
        author: String,
        writes: [AuthorizedSpaceRepositoryWrite],
        authorization: AuthorizationContext
    ) async throws -> String?

    /// Returns an ordered, bounded page after the supplied wire TID cursor.
    /// A retention gap is intentionally distinct from an empty incremental
    /// page so HTTP cannot fabricate a convergent response from incomplete
    /// history.  `includeValues` requests only values that still match live
    /// records; it never permits historic value retrieval.
    func repositoryOplog(
        space: SpaceURI,
        author: String,
        since: String?,
        limit: Int,
        includeValues: Bool,
        maximumAggregateValueBytes: Int,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceRepositoryOplogRead

    /// Prepares a fully validated, consistent permissioned repository
    /// snapshot for the streaming full-CAR recovery endpoint. Implementations
    /// may return `nil` only when this account has no repository state; they
    /// must never open or migrate a database in response to this call.
    func repositorySTARSnapshot(
        space: SpaceURI,
        author: String,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceRepositorySTARSnapshot?

    func repositoryCARSnapshot(
        space: SpaceURI,
        author: String,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceRepositoryCARSnapshot?

    /// Applies an ordered, all-or-nothing mutation batch through an account
    /// database that was opened during startup. Implementations must retain
    /// the supplied operation kinds until their revision-CAS transaction, and
    /// must never use this request as authority to open or migrate SQLite.
    func apply(
        space: SpaceURI,
        author: String,
        writes: [AuthorizedSpaceRepositoryWrite],
        requestID: UUID,
        wireRevision: String,
        authorization: AuthorizationContext
    ) async throws -> [AuthorizedSpaceRepositoryWriteResult]

    func clearRepository(
        space: SpaceURI,
        author: String,
        authorization: AuthorizationContext
    ) async throws -> Bool

    func importRepository(
        space: SpaceURI,
        author: String,
        records: [SpaceRecord],
        ltHash: Data,
        authorization: AuthorizationContext
    ) async throws
}

public extension AuthorizedSpaceRepositoryDirectory {
    /// `com.atproto.space.clearRecords`: deletes the caller's records in the
    /// space (the authority keeps its published policy and member records),
    /// clears the operation log and advances the repo. Requires a `delete`
    /// grant for every collection it deletes from. Returns `false`, writing
    /// nothing, when there was nothing to delete.
    func clearRepository(
        space _: SpaceURI,
        author _: String,
        authorization _: AuthorizationContext
    ) async throws -> Bool {
        throw SwanError.unavailable("space repository clearing is unavailable")
    }

    /// `com.atproto.space.importRepo`: replaces the caller's repo in the
    /// space with verified archive records at a new rev. Requires a `create`
    /// grant for every collection in the archive.
    func importRepository(
        space _: SpaceURI,
        author _: String,
        records _: [SpaceRecord],
        ltHash _: Data,
        authorization _: AuthorizationContext
    ) async throws {
        throw SwanError.unavailable("space repository import is unavailable")
    }

    /// Test and alternate adapters that do not persist a durable wire
    /// revision may opt out of seeding. The authoritative apply transaction
    /// still enforces its own monotonicity check.
    func repositoryWriteWireRevision(
        space: SpaceURI,
        author: String,
        writes: [AuthorizedSpaceRepositoryWrite],
        authorization: AuthorizationContext
    ) async throws -> String? {
        nil
    }
}
public func serviceIssuerDID(_ value: String) -> String? {
    let parts = value.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)
    guard (1 ... 2).contains(parts.count),
          !parts[0].isEmpty,
          (parts.count == 1 || (!parts[1].isEmpty && parts[1].utf8.count <= 512)),
          let did = try? DID(didString: String(parts[0])) else {
        return nil
    }
    return did.didString()
}

public enum SpaceNotificationRequestDigest {
    public static func deletion(space: SpaceURI) -> String {
        SpaceServiceRequestDigest.deletion(space: space)
    }

    /// The `req` binding for `notifyCredentialRevoked`: the space and its
    /// revoked credential IDs, in body order.
    public static func credentialRevocation(space: SpaceURI, credentials: [String]) -> String {
        SpaceServiceRequestDigest.credentialRevocation(space: space, credentials: credentials)
    }

    public static func write(
        space: SpaceURI,
        repository: String,
        wireRevision: String,
        commitment: Data
    ) -> String {
        SpaceServiceRequestDigest.write(
            space: space,
            repository: repository,
            revision: wireRevision,
            commitment: commitment
        )
    }

    /// The `req` binding for a space-host -> syncer `notifyWrite`: the
    /// repo-host fields plus the space revisions the space host assigned.
    public static func forwardedWrite(
        space: SpaceURI,
        repository: String,
        wireRevision: String,
        commitment: Data,
        spaceRevision: String,
        previousSpaceRevision: String?
    ) -> String {
        SpaceServiceRequestDigest.forwardedWrite(
            space: space,
            repository: repository,
            revision: wireRevision,
            commitment: commitment,
            spaceRevision: spaceRevision,
            previousSpaceRevision: previousSpaceRevision
        )
    }

    public static func deletionBytes(space: SpaceURI) -> Data {
        SpaceServiceRequestDigest.deletionBytes(space: space)
    }

    public static func writeBytes(
        space: SpaceURI,
        repository: String,
        wireRevision: String,
        commitment: Data
    ) -> Data {
        SpaceServiceRequestDigest.writeBytes(
            space: space,
            repository: repository,
            revision: wireRevision,
            commitment: commitment
        )
    }
}

public enum SpaceServiceRequestDigest {
    public static func deletion(space: SpaceURI) -> String {
        base64URLEncode(deletionBytes(space: space))
    }

    public static func write(
        space: SpaceURI,
        repository: String,
        revision: String,
        commitment: Data
    ) -> String {
        base64URLEncode(writeBytes(space: space, repository: repository, revision: revision, commitment: commitment))
    }
    public static func deletionBytes(space: SpaceURI) -> Data {
        digestBytes(domain: "swan.space.notify-deleted.v1", parts: [
            Data(space.rawValue.utf8)
        ])
    }

    public static func credentialRevocation(space: SpaceURI, credentials: [String]) -> String {
        base64URLEncode(credentialRevocationBytes(space: space, credentials: credentials))
    }

    public static func credentialRevocationBytes(space: SpaceURI, credentials: [String]) -> Data {
        digestBytes(
            domain: "swan.space.notify-credential-revoked.v1",
            parts: [Data(space.rawValue.utf8)] + credentials.map { Data($0.utf8) }
        )
    }

    public static func writeBytes(
        space: SpaceURI,
        repository: String,
        revision: String,
        commitment: Data
    ) -> Data {
        digestBytes(
            domain: "swan.space.notify-write.v1",
            parts: [
                Data(space.rawValue.utf8),
                Data(repository.utf8),
                Data(revision.utf8),
                commitment
            ]
        )
    }

    public static func forwardedWrite(
        space: SpaceURI,
        repository: String,
        revision: String,
        commitment: Data,
        spaceRevision: String,
        previousSpaceRevision: String?
    ) -> String {
        base64URLEncode(forwardedWriteBytes(
            space: space,
            repository: repository,
            revision: revision,
            commitment: commitment,
            spaceRevision: spaceRevision,
            previousSpaceRevision: previousSpaceRevision
        ))
    }

    /// Parts are length-prefixed and a space revision is never empty, so the
    /// empty final part unambiguously encodes an omitted `prevSpaceRev`.
    public static func forwardedWriteBytes(
        space: SpaceURI,
        repository: String,
        revision: String,
        commitment: Data,
        spaceRevision: String,
        previousSpaceRevision: String?
    ) -> Data {
        digestBytes(
            domain: "swan.space.notify-write-forwarded.v1",
            parts: [
                Data(space.rawValue.utf8),
                Data(repository.utf8),
                Data(revision.utf8),
                commitment,
                Data(spaceRevision.utf8),
                Data((previousSpaceRevision ?? "").utf8),
            ]
        )
    }
    private static func digestBytes(domain: String, parts: [Data]) -> Data {
        var input = Data()
        for part in [Data(domain.utf8)] + parts {
            var length = UInt64(part.count).bigEndian
            withUnsafeBytes(of: &length) { input.append(contentsOf: $0) }
            input.append(part)
        }
        return Data(SHA256.hash(data: input))
    }

    private static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

public struct AuthorizedSpaceRepositorySTARSnapshot: Sendable {
    public let state: AuthorizedSpaceRepositoryCommitState
    public let spool: SpaceSTARBodySpool
    public init(state: AuthorizedSpaceRepositoryCommitState, spool: SpaceSTARBodySpool) {
        self.state = state
        self.spool = spool
    }
}

public extension AuthorizedSpaceRepositoryDirectory {
    func repositorySTARSnapshot(space: SpaceURI, author: String, authorization: AuthorizationContext)
        async throws -> AuthorizedSpaceRepositorySTARSnapshot? {
        throw SwanError.unavailable("STAR repository snapshot is unavailable")
    }
}
