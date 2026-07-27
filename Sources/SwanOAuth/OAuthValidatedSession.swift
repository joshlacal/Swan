import Foundation
import SwanCore
import SwanStorage

/// A request context whose client metadata, redirect URI, requested scopes,
/// DPoP proof, and (when required) client assertion have all been verified.
/// OAuth issuance APIs accept this value instead of caller-provided JKT, `kid`,
/// or raw binding strings.
public struct OAuthValidatedSession: Sendable, Equatable {
    public let issuer: String
    public let client: OAuthResolvedClientMetadata
    public let redirectURI: URL
    public let scopes: Set<String>
    public let dpopProof: OAuthValidatedDPoPProof
    public let clientAssertion: OAuthValidatedClientAssertion?

    public init(
        issuer: String,
        client: OAuthResolvedClientMetadata,
        redirectURI: URL,
        scopes: Set<String>,
        dpopProof: OAuthValidatedDPoPProof,
        clientAssertion: OAuthValidatedClientAssertion? = nil,
        now: Date = Date()
    ) throws {
        guard !issuer.isEmpty, issuer.utf8.count <= 4_096, !issuer.utf8.contains(0),
              client.metadata.matchesRedirectURI(redirectURI),
              Self.hasATProtocolResourceScope(scopes),
              scopes.isSubset(of: client.metadata.scopes),
              Self.validThumbprint(dpopProof.keyThumbprint) else {
            throw SwanError.unauthorized("OAuth session binding is invalid")
        }

        switch client.metadata.tokenEndpointAuthMethod {
        case .none:
            guard clientAssertion == nil else {
                throw SwanError.unauthorized("public OAuth client supplied a client assertion")
            }
        case .privateKeyJWT:
            guard let clientAssertion, let keySet = client.keySet,
                  clientAssertion.clientID == client.metadata.clientID.absoluteString,
                  clientAssertion.algorithm == "ES256",
                  clientAssertion.expiresAt > now else {
                throw SwanError.unauthorized("confidential OAuth client assertion is invalid")
            }
            let key = try keySet.select(keyID: clientAssertion.selectedKeyID)
            guard key.thumbprint() == clientAssertion.keyThumbprint else {
                throw SwanError.unauthorized("confidential OAuth client key does not match metadata")
            }
        }

        self.issuer = issuer
        self.client = client
        self.redirectURI = redirectURI
        self.scopes = scopes
        self.dpopProof = dpopProof
        self.clientAssertion = clientAssertion
    }

    var durableBinding: OAuthClientBinding {
        OAuthClientBinding(
            issuer: issuer,
            clientID: client.metadata.clientID.absoluteString,
            redirectURI: redirectURI.absoluteString,
            scopes: scopes,
            dpopJKT: dpopProof.keyThumbprint,
            confidentialClientKey: clientAssertion.map {
                OAuthConfidentialClientKeyBinding(
                    keyID: $0.selectedKeyID,
                    algorithm: $0.algorithm,
                    keyThumbprint: $0.keyThumbprint
                )
            },
            refreshTokenAllowed: client.metadata.grantTypes.contains("refresh_token")
        )
    }

    private static func validThumbprint(_ value: String) -> Bool {
        value.utf8.count == 43 && value.utf8.allSatisfy { byte in
            (65 ... 90).contains(byte) || (97 ... 122).contains(byte) ||
                (48 ... 57).contains(byte) || byte == 45 || byte == 95
        }
    }

    /// A complete client metadata document must still advertise `atproto`,
    /// but an issued access token may carry only one profile-specific
    /// permissioned-space grant. The resource boundary and SwanSpaces parse
    /// its exact authority/skey/action/collection later; this layer admits
    /// only a qualified tuple, rather than accepting a bare type grant with
    /// no trusted authority or action binding.
    private static func hasATProtocolResourceScope(_ scopes: Set<String>) -> Bool {
        scopes.contains("atproto") || scopes.contains { scope in
            PermissionedSpaceScopeSyntax.isQualified(scope)
        }
    }
}
