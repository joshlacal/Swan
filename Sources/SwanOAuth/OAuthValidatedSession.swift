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
    /// Which parameters the client physically wrote, witnessed by the admission
    /// parse below and carried into the durable binding. It is never re-derived
    /// from a scope string afterwards (§9-D23).
    public let scopeProvenance: OAuthScopeProvenance
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
              Self.validThumbprint(dpopProof.keyThumbprint) else {
            throw SwanError.unauthorized("OAuth session binding is invalid")
        }
        // Stages B, C and E (§6.3). These replace the two predicates that stood
        // here — `hasATProtocolResourceScope` and a raw `isSubset` — with the
        // one admission policy, so the base-scope floor and the
        // requested-⊆-declared check cannot drift between call sites again.
        //
        // The subset check now canonicalises both sides (§9-D7): a client may
        // legitimately spell the same grant differently in its metadata and its
        // request, and after §9-D21 the registered set is "strings the client
        // typed", so comparing raw bytes would produce false negatives that
        // registration no longer catches.
        //
        // `OAuthScopeAdmissionError` is deliberately allowed to propagate rather
        // than being flattened into `SwanError.unauthorized`: the HTTP layer maps
        // it to `invalid_scope` for a malformed request and keeps
        // `invalid_request` for the subset failure, which would otherwise leak
        // the client's registration.
        let admission = try OAuthScopeAdmissionPolicy.admit(
            requested: scopes,
            declaredBy: client.metadata.scopes
        )
        scopeProvenance = admission.provenance

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
            refreshTokenAllowed: client.metadata.grantTypes.contains("refresh_token"),
            // A PAR binding is by definition the as-requested set — it has no
            // subject to resolve `self` against — so `scopesRequested` stays
            // absent here and is filled in at mint, by stage F, where the two
            // first diverge.
            scopeProvenance: scopeProvenance
        )
    }

    private static func validThumbprint(_ value: String) -> Bool {
        value.utf8.count == 43 && value.utf8.allSatisfy { byte in
            (65 ... 90).contains(byte) || (97 ... 122).contains(byte) ||
                (48 ... 57).contains(byte) || byte == 45 || byte == 95
        }
    }

}
