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
