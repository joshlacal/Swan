import Crypto
import Foundation
import HTTPTypes
import SwanOAuth
import SwanSpaces

/// A fixed test-only holder key keeps credential construction independent of
/// account-signing keys. Presentations carry October 22 HTTP message
/// signatures: one signature covers a credential and its audience and may be
/// reused for every request with that pair.
enum SpaceCredentialSignatureTestSupport {
    static var key: P256.Signing.PrivateKey {
        get throws { try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x3C, count: 32)) }
    }

    /// The holder key's canonical P-256 `did:key`, the credential's `cnf.kid`.
    static var keyID: String {
        get throws { SpaceHTTPSignature.keyID(for: try key) }
    }

    /// `Authorization: Atproto-Space-Credential <token>` signed for `audience`: the repo
    /// owner's DID for repo reads, the authority's bare DID for space-host
    /// operations.
    static func headers(
        token: String,
        audience: String,
        key: P256.Signing.PrivateKey? = nil
    ) throws -> HTTPFields {
        let signed = try SpaceHTTPSignature.sign(
            authorization: "Atproto-Space-Credential \(token)",
            audience: audience,
            key: key ?? self.key
        )
        var headers = HTTPFields()
        headers[.authorization] = signed.authorization
        headers[HTTPField.Name(SpaceHTTPSignature.audienceFieldName)!] = audience
        headers[HTTPField.Name(SpaceHTTPSignature.signatureInputFieldName)!] = signed.signatureInput
        headers[HTTPField.Name(SpaceHTTPSignature.signatureFieldName)!] = signed.signature
        return headers
    }

    /// The reference client's audience rule for a request URI:
    /// `params.repo ?? spaceDid(params.space)`.
    static func headers(token: String, uri: String) throws -> HTTPFields {
        try headers(token: token, audience: audience(forURI: uri))
    }

    static func audience(forURI uri: String) throws -> String {
        let items = URLComponents(string: uri)?.queryItems ?? []
        if let repo = items.first(where: { $0.name == "repo" })?.value { return repo }
        guard let space = items.first(where: { $0.name == "space" })?.value else {
            throw SpaceCredentialSignatureTestSupportError.noAudience
        }
        return try SpaceURI(space).authority
    }

    /// October 22 exchanges carry credentialKey and optional delegationToken
    /// in JSON; exchange headers contain no bearer credential or signature.
    static func exchangeHeaders() -> HTTPFields {
        var headers = HTTPFields()
        headers[.contentType] = "application/json"
        return headers
    }

}

enum SpaceCredentialSignatureTestSupportError: Error {
    case noAudience
}
