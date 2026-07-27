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
