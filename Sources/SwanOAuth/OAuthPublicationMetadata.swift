import Foundation
import SwanCore

/// A standards-shaped protected-resource metadata document. Constructing this
/// value validates only URL and schema facts; it deliberately does not claim
/// that the corresponding authorization server is reachable or complete.
public struct OAuthProtectedResourceMetadata: Codable, Sendable, Equatable {
    public let resource: URL
    public let authorizationServers: [URL]
    public let bearerMethodsSupported: [String]
    public let scopesSupported: [String]

    public init(
        resource: URL,
        authorizationServer: URL,
        scopesSupported: [String] = ["atproto"]
    ) throws {
        self.resource = try OAuthPublishedURL.validate(resource, role: "resource")
        authorizationServers = [try OAuthPublishedURL.validate(authorizationServer, role: "issuer")]
        bearerMethodsSupported = ["header"]
        self.scopesSupported = try OAuthPublishedURL.validateScopes(scopesSupported)
    }

    private enum CodingKeys: String, CodingKey {
        case resource
        case authorizationServers = "authorization_servers"
        case bearerMethodsSupported = "bearer_methods_supported"
        case scopesSupported = "scopes_supported"
    }
}

/// A standards-shaped authorization-server metadata document for Swan's
/// declared authorization-code, PKCE, DPoP, PAR, and revocation profile.
/// Publishing this document is separately gated by `SwanHTTP`; this data type
/// is intentionally useful for review and future complete assembly only.
public struct OAuthAuthorizationServerMetadata: Codable, Sendable, Equatable {
    public let issuer: URL
    public let authorizationEndpoint: URL
    public let tokenEndpoint: URL
    public let pushedAuthorizationRequestEndpoint: URL
    public let revocationEndpoint: URL
    public let responseTypesSupported: [String]
    public let grantTypesSupported: [String]
    public let codeChallengeMethodsSupported: [String]
    public let tokenEndpointAuthMethodsSupported: [String]
    public let tokenEndpointAuthSigningAlgValuesSupported: [String]
    public let dpopSigningAlgValuesSupported: [String]
    public let authorizationResponseIssuerParameterSupported: Bool
    public let requirePushedAuthorizationRequests: Bool
    public let clientIDMetadataDocumentSupported: Bool

    public init(issuer: URL) throws {
        self.issuer = try OAuthPublishedURL.validate(issuer, role: "issuer")
        authorizationEndpoint = try OAuthPublishedURL.endpoint(issuer: self.issuer, path: "oauth/authorize")
        tokenEndpoint = try OAuthPublishedURL.endpoint(issuer: self.issuer, path: "oauth/token")
        pushedAuthorizationRequestEndpoint = try OAuthPublishedURL.endpoint(issuer: self.issuer, path: "oauth/par")
        revocationEndpoint = try OAuthPublishedURL.endpoint(issuer: self.issuer, path: "oauth/revoke")
        responseTypesSupported = ["code"]
        grantTypesSupported = ["authorization_code", "refresh_token"]
        codeChallengeMethodsSupported = ["S256"]
        tokenEndpointAuthMethodsSupported = ["none", "private_key_jwt"]
        tokenEndpointAuthSigningAlgValuesSupported = ["ES256"]
        dpopSigningAlgValuesSupported = ["ES256"]
        authorizationResponseIssuerParameterSupported = true
        requirePushedAuthorizationRequests = true
        clientIDMetadataDocumentSupported = true
    }

    private enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case pushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint"
        case revocationEndpoint = "revocation_endpoint"
        case responseTypesSupported = "response_types_supported"
        case grantTypesSupported = "grant_types_supported"
        case codeChallengeMethodsSupported = "code_challenge_methods_supported"
        case tokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported"
        case tokenEndpointAuthSigningAlgValuesSupported = "token_endpoint_auth_signing_alg_values_supported"
        case dpopSigningAlgValuesSupported = "dpop_signing_alg_values_supported"
        case authorizationResponseIssuerParameterSupported = "authorization_response_iss_parameter_supported"
        case requirePushedAuthorizationRequests = "require_pushed_authorization_requests"
        case clientIDMetadataDocumentSupported = "client_id_metadata_document_supported"
    }
}

/// The two documents that a complete future OAuth HTTP assembly will pass to
/// its publication gate. Keeping the pair together prevents an accidental
/// resource metadata success response without its matching server metadata.
public struct OAuthMetadataPublication: Sendable, Equatable {
    public let protectedResource: OAuthProtectedResourceMetadata
    public let authorizationServer: OAuthAuthorizationServerMetadata

    public init(resource: URL, issuer: URL, scopesSupported: [String] = ["atproto"]) throws {
        let authorizationServer = try OAuthAuthorizationServerMetadata(issuer: issuer)
        protectedResource = try OAuthProtectedResourceMetadata(
            resource: resource,
            authorizationServer: authorizationServer.issuer,
            scopesSupported: scopesSupported
        )
        self.authorizationServer = authorizationServer
    }
}

/// Stable JSON rendering for metadata fixtures and future HTTP publication.
public enum OAuthMetadataRenderer {
    public static func render(_ metadata: some Encodable) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(metadata)
    }
}

private enum OAuthPublishedURL {
    static func validate(_ url: URL, role: String) throws -> URL {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https",
              let host = components.host,
              !host.isEmpty,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              url.absoluteString.utf8.count <= 2_048 else {
            throw SwanError.malformed("OAuth \(role) URL is invalid")
        }
        return url
    }

    static func endpoint(issuer: URL, path: String) throws -> URL {
        guard !path.isEmpty else {
            throw SwanError.malformed("OAuth endpoint URL is invalid")
        }
        let endpoint = issuer.appending(path: path)
        return try validate(endpoint, role: "endpoint")
    }

    static func validateScopes(_ scopes: [String]) throws -> [String] {
        guard !scopes.isEmpty, scopes.count <= 64,
              Set(scopes).count == scopes.count,
              scopes.allSatisfy({ scope in
                  !scope.isEmpty && scope.utf8.count <= 256
                      && scope.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7E }
              }) else {
            throw SwanError.malformed("OAuth metadata scopes are invalid")
        }
        return scopes.sorted()
    }
}
