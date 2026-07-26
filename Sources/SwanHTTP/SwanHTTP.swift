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
    public let tokenVault: OAuthTokenVault

    public init(
        profile: ProtocolProfile,
        configuration: SwanHTTPConfiguration = .init(),
        repositories: any AccountRepositoryStore = InMemoryAccountRepositoryStore(),
        tokenVault: OAuthTokenVault = OAuthTokenVault()
    ) {
        self.profile = profile
        self.configuration = configuration
        self.repositories = repositories
        self.tokenVault = tokenVault
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
            jsonResponse(ProtectedResourceMetadata(
                resource: publicURL.absoluteString,
                authorizationServers: [publicURL.absoluteString]
            ))
        }
        router.get("/.well-known/oauth-authorization-server") { _, _ -> Response in
            jsonResponse(AuthorizationServerMetadata(
                issuer: publicURL.absoluteString,
                authorizationEndpoint: publicURL.appending(path: "oauth/authorize").absoluteString,
                tokenEndpoint: publicURL.appending(path: "oauth/token").absoluteString,
                pushedAuthorizationRequestEndpoint: publicURL.appending(path: "oauth/par").absoluteString,
                revocationEndpoint: publicURL.appending(path: "oauth/revoke").absoluteString,
                dpopSigningAlgValuesSupported: ["ES256"]
            ))
        }

        router.get("/oauth/authorize") { _, _ -> Response in
            Response(
                status: .ok,
                headers: [.contentType: "text/html; charset=utf-8", .cacheControl: "no-store"],
                body: .init(byteBuffer: ByteBuffer(string: "<html><body><h1>Swan authorization</h1><p>Login and consent routes are enabled only after an Argon2id password backend is configured.</p></body></html>"))
            )
        }

        router.get("/xrpc/com.atproto.server.describeServer") { _, _ -> Response in
            jsonResponse(ServerDescription(
                did: "did:web:\(publicURL.host ?? "localhost")",
                availableUserDomains: [],
                inviteCodeRequired: true,
                swanProfile: profile.id
            ))
        }

        // Permissioned methods never fall through to public handlers. Until a
        // fully validated OAuth/space grant is supplied they return a generic
        // error without revealing space or record existence.
        router.get("/xrpc/com.atproto.space.getRecord") { request, _ -> Response in
            guard request.headers[.authorization] != nil else {
                return oauthError(status: .unauthorized, error: "invalid_token")
            }
            return oauthError(status: .notImplemented, error: "profile_endpoint_pending")
        }
        router.post("/xrpc/com.atproto.space.applyWrites") { request, _ -> Response in
            guard request.headers[.authorization] != nil else {
                return oauthError(status: .unauthorized, error: "invalid_token")
            }
            return oauthError(status: .notImplemented, error: "profile_endpoint_pending")
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

private struct ProtectedResourceMetadata: Encodable {
    let resource: String
    let authorizationServers: [String]

    enum CodingKeys: String, CodingKey {
        case resource
        case authorizationServers = "authorization_servers"
    }
}

private struct AuthorizationServerMetadata: Encodable {
    let issuer: String
    let authorizationEndpoint: String
    let tokenEndpoint: String
    let pushedAuthorizationRequestEndpoint: String
    let revocationEndpoint: String
    let dpopSigningAlgValuesSupported: [String]

    enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case pushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint"
        case revocationEndpoint = "revocation_endpoint"
        case dpopSigningAlgValuesSupported = "dpop_signing_alg_values_supported"
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

private func oauthError(status: HTTPResponse.Status, error: String) -> Response {
    jsonResponseWithStatus(status, body: ["error": error])
}

private func jsonResponseWithStatus(_ status: HTTPResponse.Status, body: some Encodable) -> Response {
    let encoder = JSONEncoder()
    let data = (try? encoder.encode(body)) ?? Data("{}".utf8)
    return Response(status: status, headers: [.contentType: "application/json", .cacheControl: "no-store"], body: .init(byteBuffer: ByteBuffer(data: data)))
}
