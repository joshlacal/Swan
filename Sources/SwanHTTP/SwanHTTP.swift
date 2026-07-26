import Foundation
import Hummingbird
import Logging
import ServiceLifecycle
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage

public struct SwanHTTPConfiguration: Sendable, Equatable {
    public let host: String
    public let port: Int
    public let publicURL: URL

    public init(host: String = "127.0.0.1", port: Int = 3000, publicURL: URL = URL(string: "http://127.0.0.1:3000")!) {
        self.host = host
        self.port = port
        self.publicURL = publicURL
    }
}

public struct SwanHTTPServer: Sendable {
    public let profile: ProtocolProfile
    public let configuration: SwanHTTPConfiguration
    public let repositories: any AccountRepositoryStore
    /// The durable OAuth control-plane runtime. The server deliberately has no
    /// `OAuthTokenVault` fallback: an incomplete or missing durable runtime is
    /// a startup failure, not a switch back to process-local bearer state.
    public let oauthRuntime: SwanOAuthRuntime

    public init(
        profile: ProtocolProfile,
        configuration: SwanHTTPConfiguration = .init(),
        repositories: any AccountRepositoryStore = InMemoryAccountRepositoryStore(),
        oauthRuntime: SwanOAuthRuntime
    ) {
        self.profile = profile
        self.configuration = configuration
        self.repositories = repositories
        self.oauthRuntime = oauthRuntime
    }

    /// All routes are registered before Application construction. Hummingbird
    /// ignores routes appended after app initialization, so this is the only
    /// supported server assembly boundary.
    public func buildRouter() -> Router<BasicRequestContext> {
        let router = Router(context: BasicRequestContext.self)
        router.get("/health") { _, _ in "OK" }

        let publicURL = configuration.publicURL
        let profile = profile
        router.get("/.well-known/oauth-protected-resource") { _, _ -> Response in
            oauthUnavailable()
        }
        router.get("/.well-known/oauth-authorization-server") { _, _ -> Response in
            oauthUnavailable()
        }

        router.get("/oauth/authorize") { _, _ -> Response in
            oauthUnavailable()
        }

        router.get("/xrpc/com.atproto.server.describeServer") { _, _ -> Response in
            jsonResponse(ServerDescription(
                did: "did:web:\(publicURL.host ?? "localhost")",
                availableUserDomains: [],
                inviteCodeRequired: true,
                swanProfile: profile.id
            ))
        }

        // Permissioned methods never fall through to public handlers. OAuth
        // metadata and token routes are not live yet, so there is no served
        // bearer-token validation path to accidentally back with memory state.
        router.get("/xrpc/com.atproto.space.getRecord") { _, _ -> Response in
            oauthUnavailable()
        }
        router.post("/xrpc/com.atproto.space.applyWrites") { _, _ -> Response in
            oauthUnavailable()
        }

        return router
    }

    public func buildApplication(logger: Logger) -> some ApplicationProtocol {
        Application(
            router: buildRouter(),
            configuration: .init(address: .hostname(configuration.host, port: configuration.port), serverName: "swan"),
            logger: logger
        )
    }
}

private struct ServerDescription: Encodable {
    let did: String
    let availableUserDomains: [String]
    let inviteCodeRequired: Bool
    let swanProfile: String

    enum CodingKeys: String, CodingKey {
        case did
        case availableUserDomains
        case inviteCodeRequired
        case swanProfile
    }
}

private func jsonResponse(_ body: some Encodable) -> Response {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = (try? encoder.encode(body)) ?? Data("{}".utf8)
    return Response(status: .ok, headers: [.contentType: "application/json", .cacheControl: "no-store"], body: .init(byteBuffer: ByteBuffer(data: data)))
}

private func oauthUnavailable() -> Response {
    // Do not publish OAuth discovery metadata until PAR, authorization,
    // token, revocation, consent, and proof validation are all registered.
    jsonResponseWithStatus(.serviceUnavailable, body: ["error": "oauth_flow_pending"])
}

private func jsonResponseWithStatus(_ status: HTTPResponse.Status, body: some Encodable) -> Response {
    let encoder = JSONEncoder()
    let data = (try? encoder.encode(body)) ?? Data("{}".utf8)
    return Response(status: status, headers: [.contentType: "application/json", .cacheControl: "no-store"], body: .init(byteBuffer: ByteBuffer(data: data)))
}
