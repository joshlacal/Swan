import Crypto
import Foundation
import HTTPTypes
import PetrelCrypto
import SwanOAuth

/// A fixed test-only holder key keeps credential construction independent of
/// account-signing keys. Every presentation signs a fresh, request-bound proof.
enum SpaceCredentialDPoPTestSupport {
    static var key: P256.Signing.PrivateKey {
        get throws { try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x3C, count: 32)) }
    }

    static var thumbprint: String {
        get throws { try OAuthJSONWebKey.from(key).thumbprint() }
    }

    static func proof(
        path: String,
        method: String,
        token: String? = nil,
        origin: String = "https://swan.example"
    ) throws -> String {
        struct Header: Encodable {
            let alg = "ES256"
            let typ = OAuthDPoPProofValidator.proofType
            let jwk: OAuthJSONWebKey
        }
        struct Claims: Encodable {
            let jti: String
            let iat: Int64
            let htm: String
            let htu: String
            let ath: String?
        }
        let signingKey = try key
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let header = try encoder.encode(Header(jwk: OAuthJSONWebKey.from(signingKey))).base64URLEncodedString()
        let target = path.split(separator: "?", maxSplits: 1).first.map(String.init) ?? path
        let claims = try encoder.encode(Claims(
            jti: UUID().uuidString,
            iat: Int64(Date().timeIntervalSince1970),
            htm: method,
            htu: origin + target,
            ath: token.map { Data(SHA256.hash(data: Data($0.utf8))).base64URLEncodedString() }
        )).base64URLEncodedString()
        let input = "\(header).\(claims)"
        let signature = try P256WireSignature.sign(Data(input.utf8), using: signingKey).base64URLEncodedString()
        return "\(input).\(signature)"
    }

    static func headers(
        token: String,
        path: String,
        method: String = "GET",
        origin: String = "https://swan.example"
    ) throws -> HTTPFields {
        var headers = HTTPFields()
        headers[.authorization] = "DPoP \(token)"
        headers[HTTPField.Name("DPoP")!] = try proof(path: path, method: method, token: token, origin: origin)
        return headers
    }

    static func exchangeHeaders(
        token: String,
        path: String = "/xrpc/com.atproto.space.getSpaceCredential",
        origin: String = "https://swan.example",
        authorizationScheme: String = "Bearer"
    ) throws -> HTTPFields {
        var headers = HTTPFields()
        headers[.authorization] = "\(authorizationScheme) \(token)"
        headers[.contentType] = "application/json"
        headers[HTTPField.Name("DPoP")!] = try proof(path: path, method: "POST", origin: origin)
        return headers
    }

    static func refreshed(_ headers: HTTPFields, path: String, method: String = "POST") throws -> HTTPFields {
        var refreshed = headers
        guard let authorization = headers[.authorization],
              let token = authorization.split(separator: " ", maxSplits: 1).last else { return headers }
        refreshed[HTTPField.Name("DPoP")!] = try proof(path: path, method: method, token: String(token))
        return refreshed
    }
}
