import Foundation
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
/// `com.atproto.simplespace` surface.
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

/// An opaque, already-verified permissioned blob body.  The storage adapter
/// owns the underlying descriptor and never exposes a path or a `Data` value,
/// so an HTTP route cannot accidentally buffer a private blob or retarget a
/// file after authorization has completed.
public protocol AuthorizedSpaceBlobBody: Sendable {
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

public protocol AuthorizedSpaceBlobDirectory: Sendable {
    func spaceBlob(
        space: SpaceURI,
        author: String,
        cid: String,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceBlob?
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

    func updateSimpleSpace(
        _ space: SpaceURI,
        patch: SimpleSpaceConfigurationPatch,
        authorization: AuthorizationContext
    ) async throws

    func deleteSimpleSpace(
        _ space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws

    func addSimpleSpaceMember(
        _ member: String,
        to space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws

    func removeSimpleSpaceMember(
        _ member: String,
        from space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws

    func simpleSpaceMembers(
        _ space: SpaceURI,
        limit: Int,
        cursor: String?,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSimpleSpaceMemberPage
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
        user: String,
        clientID: String?,
        authorization: AuthorizationContext
    ) async throws
}

/// Privacy-safe page returned only after the caller has passed the exact
/// authority account and lifecycle-scope checks.  Member identities are
/// intentionally unavailable from the generic `getSpace` projection.
public struct AuthorizedSimpleSpaceMemberPage: Sendable, Equatable {
    public let members: [String]
    public let cursor: String?

    public init(members: [String], cursor: String?) {
        self.members = members
        self.cursor = cursor
    }
}

/// Stable, privacy-safe lifecycle error used across the SQLite adapter and
/// HTTP boundary. It intentionally carries no space, account, member, or
/// storage detail.
public enum AuthorizedSimpleSpaceLifecycleError: Error, Sendable, Equatable {
    case notFound
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
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceRepositoryOplogRead

    /// Prepares a fully validated, consistent permissioned repository
    /// snapshot for the streaming full-CAR recovery endpoint. Implementations
    /// may return `nil` only when this account has no repository state; they
    /// must never open or migrate a database in response to this call.
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
}
