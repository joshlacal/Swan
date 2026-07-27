import Foundation
import Hummingbird
import Logging
import ServiceLifecycle
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanSpacesWire
import SwanStorage

/// An explicit publication boundary for OAuth discovery. The only public
/// construction is `.unavailable`; a future complete HTTP assembly inside
/// `SwanHTTP` must supply validated metadata before discovery can return 200.
/// This prevents a caller from accidentally advertising incomplete PAR,
/// authorization, token, or revocation routes.
public struct OAuthPublicationGate: Sendable {
    private let publication: OAuthMetadataPublication?

    public static let unavailable = OAuthPublicationGate(publication: nil)

    init(completePublication: OAuthMetadataPublication) {
        publication = completePublication
    }

    private init(publication: OAuthMetadataPublication?) {
        self.publication = publication
    }

    func protectedResourceMetadata() -> OAuthProtectedResourceMetadata? {
        publication?.protectedResource
    }

    func authorizationServerMetadata() -> OAuthAuthorizationServerMetadata? {
        publication?.authorizationServer
    }
}

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

/// An explicit development-only opt-in for Swan's first live OAuth endpoint.
///
/// The value can be constructed only from an HTTPS issuer that passes the
/// same URL policy as the eventual authorization-server metadata. It does not
/// publish discovery metadata or make authorization, token, or revocation
/// routes available.
public struct SwanLocalhostPARConfiguration: Sendable, Equatable {
    public let issuer: URL

    public init(issuer: URL) throws {
        self.issuer = try OAuthAuthorizationServerMetadata(issuer: issuer).issuer
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
    /// Discovery is unavailable unless a later complete OAuth HTTP assembly
    /// explicitly supplies a ready gate. Durable OAuth primitives alone are
    /// not sufficient authorization-server behavior.
    public let oauthPublicationGate: OAuthPublicationGate
    /// The sole live OAuth alpha route. This never enables discovery or any
    /// other authorization-server endpoint.
    public let localhostPARConfiguration: SwanLocalhostPARConfiguration?
    /// The one authenticated authority `getSpace` query. It is unavailable by
    /// default and only constructed from this server's runtime and canonical
    /// public URL after account databases have been preopened at startup.
    public let authenticatedGetSpace: SwanAuthenticatedGetSpaceCapability?

    public init(
        profile: ProtocolProfile,
        configuration: SwanHTTPConfiguration = .init(),
        repositories: any AccountRepositoryStore = InMemoryAccountRepositoryStore(),
        oauthRuntime: SwanOAuthRuntime,
        oauthPublicationGate: OAuthPublicationGate = .unavailable,
        localhostPARConfiguration: SwanLocalhostPARConfiguration? = nil,
        authenticatedGetSpaceDirectory: (any AuthorizedSimpleSpaceDirectory)? = nil,
        accountControlStore: (any AccountControlStore)? = nil
    ) {
        self.profile = profile
        self.configuration = configuration
        self.repositories = repositories
        self.oauthRuntime = oauthRuntime
        self.oauthPublicationGate = oauthPublicationGate
        // A mismatched issuer would produce a DPoP target different from the
        // process's public identity. There is no best-effort normalization:
        // retain the default 404 closure instead.
        if let localhostPARConfiguration,
           localhostPARConfiguration.issuer.absoluteString == configuration.publicURL.absoluteString {
            self.localhostPARConfiguration = localhostPARConfiguration
        } else {
            self.localhostPARConfiguration = nil
        }
        // Never accept a caller-supplied authorizer here: it might bind DPoP
        // to another public URL or runtime. Failure to form the exact local
        // binding is a safe closed route, not a best-effort fallback.
        if let authenticatedGetSpaceDirectory,
           let accountControlStore,
           Self.permitsResourceAuthorization(on: configuration),
           let authorizer = try? SwanOAuthResourceAuthorizer(
               publicURL: configuration.publicURL,
               runtime: oauthRuntime,
               accountControlStore: accountControlStore
           ) {
            authenticatedGetSpace = SwanAuthenticatedGetSpaceCapability(
                authorizer: authorizer,
                directory: authenticatedGetSpaceDirectory
            )
        } else {
            authenticatedGetSpace = nil
        }
    }

    /// HTTPS resource identities may be reverse-proxied in the normal way.
    /// A cleartext identity is only a local lab escape hatch, so require the
    /// actual listener to be a literal loopback address on the same port.
    /// This prevents `http://127.0.0.1` from being advertised while Hummingbird
    /// is really accepting DPoP credentials on `0.0.0.0`.
    private static func permitsResourceAuthorization(
        on configuration: SwanHTTPConfiguration
    ) -> Bool {
        guard configuration.publicURL.scheme?.lowercased() == "http" else {
            return true
        }
        guard (configuration.publicURL.port ?? 80) == configuration.port else {
            return false
        }
        return switch configuration.host.lowercased() {
        case "127.0.0.1", "::1": true
        default: false
        }
    }

    /// All routes are registered before Application construction. Hummingbird
    /// ignores routes appended after app initialization, so this is the only
    /// supported server assembly boundary.
    public func buildRouter() -> Router<BasicRequestContext> {
        let router = Router(context: BasicRequestContext.self)
        router.get("/health") { _, _ in "OK" }

        let publicURL = configuration.publicURL
        let profile = profile
        let oauthPublicationGate = oauthPublicationGate
        router.get("/.well-known/oauth-protected-resource") { _, _ -> Response in
            guard let metadata = oauthPublicationGate.protectedResourceMetadata() else {
                return oauthUnavailable()
            }
            return jsonResponse(metadata)
        }
        router.get("/.well-known/oauth-authorization-server") { _, _ -> Response in
            guard let metadata = oauthPublicationGate.authorizationServerMetadata() else {
                return oauthUnavailable()
            }
            return jsonResponse(metadata)
        }

        router.get("/oauth/authorize") { _, _ -> Response in
            oauthUnavailable()
        }

        // This narrow development bridge stores a durable PAR only. It does
        // not publish discovery and cannot lead to login, consent, codes, or
        // tokens until a complete OAuth HTTP assembly is separately enabled.
        if let localhostPARConfiguration {
            registerLocalhostPAREndpoint(
                on: router,
                configuration: localhostPARConfiguration,
                runtime: oauthRuntime
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

        // Do not route permissioned traffic to the in-memory repository store
        // while durable OAuth and account control have no HTTP entry points.
        // The checked-in wire registry is the sole source for this coverage:
        // every profile method gets an explicit, method-correct closed handler
        // until its authenticated implementation is ready.
        for descriptor in PermissionedData0016.methods {
            if descriptor.nsid == ComAtprotoSpaceGetSpace.typeIdentifier,
               let authenticatedGetSpace {
                registerAuthenticatedGetSpaceEndpoint(on: router, capability: authenticatedGetSpace)
            } else {
                registerUnavailablePermissionedEndpoint(descriptor, on: router)
            }
        }

        // Reject future/unknown permissioned methods explicitly instead of
        // allowing a later generic XRPC route to become an accidental public
        // fallback. Exact profile routes above have higher router precedence,
        // so a wrong method on a known endpoint remains unavailable (404),
        // rather than being mistaken for its method-correct 503 gate.
        registerUnknownPermissionedEndpointGuards(on: router)

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

private func registerUnavailablePermissionedEndpoint(
    _ descriptor: XRPCMethodDescriptor,
    on router: Router<BasicRequestContext>
) {
    let path = RouterPath("/xrpc/\(descriptor.nsid)")
    switch descriptor.kind {
    case .query, .subscription:
        router.get(path) { _, _ -> Response in
            permissionedDataUnavailable()
        }
    case .procedure:
        router.post(path) { _, _ -> Response in
            permissionedDataUnavailable()
        }
    }
}

private func registerUnknownPermissionedEndpointGuards(
    on router: Router<BasicRequestContext>
) {
    let methods: [HTTPRequest.Method] = [
        .get, .head, .post, .put, .patch, .delete, .options, .connect, .trace,
    ]
    let paths: [RouterPath] = [
        "/xrpc/com.atproto.space.*",
        "/xrpc/com.atproto.simplespace.*",
    ]

    for path in paths {
        for method in methods {
            router.on(path, method: method) { _, _ -> Response in
                permissionedEndpointUnavailable()
            }
        }
    }
}

private func permissionedEndpointUnavailable() -> Response {
    jsonResponseWithStatus(.notFound, body: ["error": "permissioned_endpoint_unavailable"])
}

private func permissionedDataUnavailable() -> Response {
    jsonResponseWithStatus(.serviceUnavailable, body: ["error": "permissioned_data_pending"])
}

private func jsonResponseWithStatus(_ status: HTTPResponse.Status, body: some Encodable) -> Response {
    let encoder = JSONEncoder()
    let data = (try? encoder.encode(body)) ?? Data("{}".utf8)
    return Response(status: status, headers: [.contentType: "application/json", .cacheControl: "no-store"], body: .init(byteBuffer: ByteBuffer(data: data)))
}
