import SwanCore
import SwanSpaces

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
}
