import Foundation
import SwanCore

/// The two application environments the AT Protocol OAuth profile permits.
public enum OAuthClientApplicationType: String, Codable, Sendable, Equatable {
    case web
    case native
}

/// Swan deliberately supports only AT Protocol's public and confidential
/// client modes. In particular, shared secrets and arbitrary OAuth client
/// authentication methods cannot reach a future endpoint implementation.
public enum OAuthTokenEndpointAuthenticationMethod: String, Codable, Sendable, Equatable {
    case none
    case privateKeyJWT = "private_key_jwt"
}

/// A validated AT Protocol client metadata document. Constructing or decoding
/// this value applies the profile invariants; callers must additionally bind a
/// fetched document to its requested response URL with
/// `validateResponseIdentity(_:)`.
public struct OAuthClientMetadata: Codable, Sendable, Equatable {
    public let clientID: URL
    public let applicationType: OAuthClientApplicationType
    public let redirectURIs: [URL]
    public let grantTypes: Set<String>
    public let responseTypes: Set<String>
    public let scopes: Set<String>
    public let tokenEndpointAuthMethod: OAuthTokenEndpointAuthenticationMethod
    public let tokenEndpointAuthSigningAlgorithm: String?
    public let dpopBoundAccessTokens: Bool
    public let jwks: OAuthJSONWebKeySet?
    public let jwksURI: URL?
    public let clientName: String?
    public let clientURI: URL?
    public let logoURI: URL?
    public let termsOfServiceURI: URL?
    public let policyURI: URL?

    /// True only for the specified `http://localhost` development virtual
    /// metadata document. This is never accepted from a fetched JSON body.
    public let isLocalhostDevelopmentClient: Bool

    /// Compatibility initializer for existing in-process callers. It creates
    /// a public, DPoP-bound AT Protocol client rather than the old underspecified
    /// three-field metadata value.
    public init(
        clientID: URL,
        redirectURIs: [URL],
        tokenEndpointAuthMethod: String = "none"
    ) throws {
        guard let method = OAuthTokenEndpointAuthenticationMethod(rawValue: tokenEndpointAuthMethod) else {
            throw SwanError.malformed("unsupported OAuth client authentication method")
        }
        try self.init(
            clientID: clientID,
            applicationType: .web,
            redirectURIs: redirectURIs,
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: ["atproto"],
            tokenEndpointAuthMethod: method,
            tokenEndpointAuthSigningAlgorithm: nil,
            dpopBoundAccessTokens: true,
            jwks: nil,
            jwksURI: nil,
            clientName: nil,
            clientURI: nil,
            logoURI: nil,
            termsOfServiceURI: nil,
            policyURI: nil,
            isLocalhostDevelopmentClient: false
        )
    }

    public init(
        clientID: URL,
        applicationType: OAuthClientApplicationType = .web,
        redirectURIs: [URL],
        grantTypes: Set<String>,
        responseTypes: Set<String>,
        scopes: Set<String>,
        tokenEndpointAuthMethod: OAuthTokenEndpointAuthenticationMethod = .none,
        tokenEndpointAuthSigningAlgorithm: String? = nil,
        dpopBoundAccessTokens: Bool,
        jwks: OAuthJSONWebKeySet? = nil,
        jwksURI: URL? = nil,
        clientName: String? = nil,
        clientURI: URL? = nil,
        logoURI: URL? = nil,
        termsOfServiceURI: URL? = nil,
        policyURI: URL? = nil
    ) throws {
        try self.init(
            clientID: clientID,
            applicationType: applicationType,
            redirectURIs: redirectURIs,
            grantTypes: grantTypes,
            responseTypes: responseTypes,
            scopes: scopes,
            tokenEndpointAuthMethod: tokenEndpointAuthMethod,
            tokenEndpointAuthSigningAlgorithm: tokenEndpointAuthSigningAlgorithm,
            dpopBoundAccessTokens: dpopBoundAccessTokens,
            jwks: jwks,
            jwksURI: jwksURI,
            clientName: clientName,
            clientURI: clientURI,
            logoURI: logoURI,
            termsOfServiceURI: termsOfServiceURI,
            policyURI: policyURI,
            isLocalhostDevelopmentClient: false
        )
    }

    private init(
        clientID: URL,
        applicationType: OAuthClientApplicationType,
        redirectURIs: [URL],
        grantTypes: Set<String>,
        responseTypes: Set<String>,
        scopes: Set<String>,
        tokenEndpointAuthMethod: OAuthTokenEndpointAuthenticationMethod,
        tokenEndpointAuthSigningAlgorithm: String?,
        dpopBoundAccessTokens: Bool,
        jwks: OAuthJSONWebKeySet?,
        jwksURI: URL?,
        clientName: String?,
        clientURI: URL?,
        logoURI: URL?,
        termsOfServiceURI: URL?,
        policyURI: URL?,
        isLocalhostDevelopmentClient: Bool
    ) throws {
        self.clientID = clientID
        self.applicationType = applicationType
        self.redirectURIs = redirectURIs
        self.grantTypes = grantTypes
        self.responseTypes = responseTypes
        self.scopes = scopes
        self.tokenEndpointAuthMethod = tokenEndpointAuthMethod
        self.tokenEndpointAuthSigningAlgorithm = tokenEndpointAuthSigningAlgorithm
        self.dpopBoundAccessTokens = dpopBoundAccessTokens
        self.jwks = jwks
        self.jwksURI = jwksURI
        self.clientName = clientName
        self.clientURI = clientURI
        self.logoURI = logoURI
        self.termsOfServiceURI = termsOfServiceURI
        self.policyURI = policyURI
        self.isLocalhostDevelopmentClient = isLocalhostDevelopmentClient
        try validate()
    }

    private enum CodingKeys: String, CodingKey {
        case clientID = "client_id"
        case applicationType = "application_type"
        case redirectURIs = "redirect_uris"
        case grantTypes = "grant_types"
        case responseTypes = "response_types"
        case scope
        case tokenEndpointAuthMethod = "token_endpoint_auth_method"
        case tokenEndpointAuthSigningAlgorithm = "token_endpoint_auth_signing_alg"
        case dpopBoundAccessTokens = "dpop_bound_access_tokens"
        case jwks
        case jwksURI = "jwks_uri"
        case clientName = "client_name"
        case clientURI = "client_uri"
        case logoURI = "logo_uri"
        case termsOfServiceURI = "tos_uri"
        case policyURI = "policy_uri"
    }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let clientID = try values.decode(URL.self, forKey: .clientID)
        let applicationType = try values.decodeIfPresent(OAuthClientApplicationType.self, forKey: .applicationType) ?? .web
        let redirectURIs = try values.decode([URL].self, forKey: .redirectURIs)
        let decodedGrantTypes = try values.decode([String].self, forKey: .grantTypes)
        let decodedResponseTypes = try values.decode([String].self, forKey: .responseTypes)
        guard decodedGrantTypes.count == Set(decodedGrantTypes).count,
              decodedResponseTypes.count == Set(decodedResponseTypes).count else {
            throw SwanError.malformed("OAuth client metadata contains duplicate type declarations")
        }
        let grantTypes = Set(decodedGrantTypes)
        let responseTypes = Set(decodedResponseTypes)
        let scopes = try Self.parseScopes(values.decode(String.self, forKey: .scope))
        let method = try values.decodeIfPresent(OAuthTokenEndpointAuthenticationMethod.self, forKey: .tokenEndpointAuthMethod) ?? .none
        try self.init(
            clientID: clientID,
            applicationType: applicationType,
            redirectURIs: redirectURIs,
            grantTypes: grantTypes,
            responseTypes: responseTypes,
            scopes: scopes,
            tokenEndpointAuthMethod: method,
            tokenEndpointAuthSigningAlgorithm: try values.decodeIfPresent(String.self, forKey: .tokenEndpointAuthSigningAlgorithm),
            dpopBoundAccessTokens: try values.decode(Bool.self, forKey: .dpopBoundAccessTokens),
            jwks: try values.decodeIfPresent(OAuthJSONWebKeySet.self, forKey: .jwks),
            jwksURI: try values.decodeIfPresent(URL.self, forKey: .jwksURI),
            clientName: try values.decodeIfPresent(String.self, forKey: .clientName),
            clientURI: try values.decodeIfPresent(URL.self, forKey: .clientURI),
            logoURI: try values.decodeIfPresent(URL.self, forKey: .logoURI),
            termsOfServiceURI: try values.decodeIfPresent(URL.self, forKey: .termsOfServiceURI),
            policyURI: try values.decodeIfPresent(URL.self, forKey: .policyURI),
            isLocalhostDevelopmentClient: false
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(clientID, forKey: .clientID)
        try values.encode(applicationType, forKey: .applicationType)
        try values.encode(redirectURIs, forKey: .redirectURIs)
        try values.encode(grantTypes.sorted(), forKey: .grantTypes)
        try values.encode(responseTypes.sorted(), forKey: .responseTypes)
        try values.encode(scopes.sorted().joined(separator: " "), forKey: .scope)
        try values.encode(tokenEndpointAuthMethod, forKey: .tokenEndpointAuthMethod)
        try values.encodeIfPresent(tokenEndpointAuthSigningAlgorithm, forKey: .tokenEndpointAuthSigningAlgorithm)
        try values.encode(dpopBoundAccessTokens, forKey: .dpopBoundAccessTokens)
        try values.encodeIfPresent(jwks, forKey: .jwks)
        try values.encodeIfPresent(jwksURI, forKey: .jwksURI)
        try values.encodeIfPresent(clientName, forKey: .clientName)
        try values.encodeIfPresent(clientURI, forKey: .clientURI)
        try values.encodeIfPresent(logoURI, forKey: .logoURI)
        try values.encodeIfPresent(termsOfServiceURI, forKey: .termsOfServiceURI)
        try values.encodeIfPresent(policyURI, forKey: .policyURI)
    }

    /// Decodes a fetched document after rejecting duplicate JSON member names.
    /// `responseURL` must be the final response URL; redirects are not an
    /// accepted way to satisfy the `client_id` identity relation.
    public static func decodeValidated(_ data: Data, responseURL: URL) throws -> Self {
        let metadata = try StrictJSON.decode(Self.self, from: data)
        try metadata.validateResponseIdentity(responseURL)
        return metadata
    }

    /// The response URL comparison is byte-for-byte at the URL string level,
    /// not Foundation URL equivalence. This avoids normalizing away an identity
    /// difference that an HTTP client might otherwise conceal.
    public func validateResponseIdentity(_ responseURL: URL) throws {
        guard !isLocalhostDevelopmentClient,
              clientID.absoluteString == responseURL.absoluteString else {
            throw SwanError.unauthorized("OAuth client metadata response URL does not match client_id")
        }
    }

    /// Checks a requested authorization redirect against the registered
    /// redirect set. The localhost virtual client has the profile's special
    /// port-insensitive loopback matching; all other registrations are exact.
    public func matchesRedirectURI(_ requested: URL) -> Bool {
        if isLocalhostDevelopmentClient {
            return redirectURIs.contains { Self.matchesVirtualLocalhostRedirect($0, requested) }
        }
        return redirectURIs.contains { $0.absoluteString == requested.absoluteString }
    }

    /// Generates the exact virtual public-client metadata defined by the AT
    /// Protocol localhost development exception. It performs no HTTP request.
    public static func localhostDevelopmentMetadata(clientID: URL) throws -> Self {
        guard isExactLocalhostDevelopmentClientID(clientID) else {
            throw SwanError.malformed("invalid localhost development client_id")
        }
        let components = URLComponents(url: clientID, resolvingAgainstBaseURL: false)
        let items = components?.queryItems ?? []
        let permitted = Set(["redirect_uri", "scope"])
        guard items.allSatisfy({ permitted.contains($0.name) }),
              items.filter({ $0.name == "scope" }).count <= 1 else {
            throw SwanError.malformed("invalid localhost development client_id query")
        }
        let redirectItems = items.filter { $0.name == "redirect_uri" }
        guard redirectItems.allSatisfy({ $0.value != nil }) else {
            throw SwanError.malformed("invalid localhost development redirect_uri")
        }
        let redirectValues = redirectItems.compactMap(\.value)
        let redirects: [URL]
        if redirectValues.isEmpty {
            redirects = [
                URL(string: "http://127.0.0.1/")!,
                URL(string: "http://[::1]/")!,
            ]
        } else {
            redirects = try redirectValues.map {
                guard let url = URL(string: $0), isVirtualLocalhostRedirect(url) else {
                    throw SwanError.malformed("invalid localhost development redirect_uri")
                }
                return url
            }
        }
        let scope = try parseScopes(items.first(where: { $0.name == "scope" })?.value ?? "atproto")
        return try Self(
            clientID: clientID,
            applicationType: .native,
            redirectURIs: redirects,
            grantTypes: ["authorization_code", "refresh_token"],
            responseTypes: ["code"],
            scopes: scope,
            tokenEndpointAuthMethod: .none,
            tokenEndpointAuthSigningAlgorithm: nil,
            dpopBoundAccessTokens: true,
            jwks: nil,
            jwksURI: nil,
            clientName: "Development client",
            clientURI: nil,
            logoURI: nil,
            termsOfServiceURI: nil,
            policyURI: nil,
            isLocalhostDevelopmentClient: true
        )
    }

    public static func isExactLocalhostDevelopmentClientID(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme == "http", components.host == "localhost",
              components.port == nil, components.user == nil, components.password == nil,
              components.fragment == nil,
              components.path.isEmpty || components.path == "/" else {
            return false
        }
        return true
    }

    /// Validates the non-development `client_id` URL form before any remote
    /// fetch is attempted. Response identity still has to be validated after
    /// a successful exact-200 document fetch.
    public static func validateStandardClientID(_ url: URL) throws {
        try validateHTTPSClientID(url)
    }

    private func validate() throws {
        if isLocalhostDevelopmentClient {
            guard Self.isExactLocalhostDevelopmentClientID(clientID) else {
                throw SwanError.malformed("invalid localhost development client_id")
            }
        } else {
            try Self.validateHTTPSClientID(clientID)
        }
        guard !redirectURIs.isEmpty,
              grantTypes.contains("authorization_code"),
              responseTypes.contains("code"),
              scopes.contains("atproto"),
              dpopBoundAccessTokens else {
            throw SwanError.malformed("OAuth client metadata misses a required AT Protocol field")
        }
        guard redirectURIs.count == Set(redirectURIs.map(\.absoluteString)).count else {
            throw SwanError.malformed("OAuth client metadata contains duplicate redirect URIs")
        }
        try redirectURIs.forEach { try validateRedirectURI($0) }
        guard jwks == nil || jwksURI == nil else {
            throw SwanError.malformed("OAuth client metadata cannot contain both jwks and jwks_uri")
        }
        switch tokenEndpointAuthMethod {
        case .none:
            guard tokenEndpointAuthSigningAlgorithm == nil, jwks == nil, jwksURI == nil else {
                throw SwanError.malformed("public OAuth clients cannot declare client authentication keys")
            }
        case .privateKeyJWT:
            guard tokenEndpointAuthSigningAlgorithm == "ES256", jwks != nil || jwksURI != nil else {
                throw SwanError.malformed("confidential OAuth clients require ES256 and exactly one JWKS source")
            }
            if let jwksURI {
                try Self.validateHTTPSURL(jwksURI, message: "jwks_uri must be an HTTPS URL")
            }
        }
        if let clientURI {
            try Self.validateHTTPSURL(clientURI, message: "client_uri must be an HTTPS URL")
            guard clientURI.host?.lowercased() == clientID.host?.lowercased() else {
                throw SwanError.malformed("client_uri hostname must match client_id")
            }
        }
        for uri in [logoURI, termsOfServiceURI, policyURI].compactMap({ $0 }) {
            try Self.validateHTTPSURL(uri, message: "display metadata URI must be an HTTPS URL")
        }
    }

    private func validateRedirectURI(_ redirect: URL) throws {
        guard let components = URLComponents(url: redirect, resolvingAgainstBaseURL: false),
              components.user == nil, components.password == nil, components.fragment == nil else {
            throw SwanError.malformed("OAuth redirect URI is malformed")
        }
        if isLocalhostDevelopmentClient {
            guard Self.isVirtualLocalhostRedirect(redirect) else {
                throw SwanError.malformed("localhost development redirect URI is invalid")
            }
            return
        }
        switch applicationType {
        case .web:
            guard components.scheme?.lowercased() == "https", components.host != nil,
                  components.port != 443 else {
                throw SwanError.malformed("web OAuth redirect URI must be HTTPS without default port")
            }
        case .native:
            if components.scheme?.lowercased() == "https" {
                guard components.host?.lowercased() == clientID.host?.lowercased(),
                      components.port == nil else {
                    throw SwanError.malformed("native HTTPS redirect URI must share client_id origin")
                }
            } else {
                guard let scheme = components.scheme?.lowercased(),
                      scheme != "http", scheme != "https",
                      components.host == nil,
                      !components.path.isEmpty, components.path != "/",
                      redirect.absoluteString.hasPrefix("\(scheme):/"),
                      !redirect.absoluteString.hasPrefix("\(scheme)://"),
                      let clientHost = clientID.host?.lowercased(),
                      scheme == clientHost.split(separator: ".").reversed().joined(separator: ".") else {
                    throw SwanError.malformed("native OAuth redirect URI does not match client_id")
                }
            }
        }
    }

    private static func validateHTTPSClientID(_ url: URL) throws {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https", components.host != nil,
              components.port == nil, components.user == nil, components.password == nil,
              components.fragment == nil else {
            throw SwanError.malformed("OAuth client_id must be an HTTPS URL without an explicit port")
        }
    }

    private static func validateHTTPSURL(_ url: URL, message: String) throws {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https", components.host != nil,
              components.user == nil, components.password == nil, components.fragment == nil else {
            throw SwanError.malformed(message)
        }
    }

    private static func parseScopes(_ raw: String) throws -> Set<String> {
        let values = raw.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard !values.isEmpty, values.count == Set(values).count,
              values.allSatisfy({ value in
                  !value.isEmpty && value.utf8.allSatisfy { $0 > 0x20 && $0 < 0x7F }
              }) else {
            throw SwanError.malformed("OAuth scope declaration is invalid")
        }
        return Set(values)
    }

    private static func isVirtualLocalhostRedirect(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme == "http", components.user == nil, components.password == nil,
              components.fragment == nil, !components.path.isEmpty,
              ["127.0.0.1", "::1"].contains(
                  components.host?.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
              ) else {
            return false
        }
        return true
    }

    private static func matchesVirtualLocalhostRedirect(_ registered: URL, _ requested: URL) -> Bool {
        guard isVirtualLocalhostRedirect(registered), isVirtualLocalhostRedirect(requested),
              let left = URLComponents(url: registered, resolvingAgainstBaseURL: false),
              let right = URLComponents(url: requested, resolvingAgainstBaseURL: false) else {
            return false
        }
        return left.scheme == right.scheme &&
            left.host?.trimmingCharacters(in: CharacterSet(charactersIn: "[]")) ==
                right.host?.trimmingCharacters(in: CharacterSet(charactersIn: "[]")) &&
            left.percentEncodedPath == right.percentEncodedPath &&
            left.percentEncodedQuery == right.percentEncodedQuery
    }
}
