import Crypto
import Foundation
import SwanCore
import SwanSpaces

public enum PKCE {
    public static func verifyS256(verifier: String, challenge: String) -> Bool {
        let digest = Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString()
        return constantTimeEqual(Data(digest.utf8), Data(challenge.utf8))
    }
}

public struct OAuthTokenPair: Sendable, Equatable {
    public let accessToken: String
    public let refreshToken: String
    public let accessExpiresAt: Date
    public let refreshExpiresAt: Date
    public let familyID: UUID
}

private struct StoredToken: Sendable {
    let subject: String
    let scopes: Set<String>
    let accessDigest: Data
    let refreshDigest: Data
    let accessExpiresAt: Date
    let refreshExpiresAt: Date
    let familyID: UUID
    var refreshUsed: Bool
}

/// Stores only keyed token digests. Refresh rotation is atomic at the actor
/// boundary; a persistent implementation must preserve the same family-revoke
/// rule inside its SQLite transaction.
public actor OAuthTokenVault {
    private let macKey: SymmetricKey
    private var refreshTokens: [Data: StoredToken] = [:]
    private var accessTokens: [Data: StoredToken] = [:]
    private var revokedFamilies: Set<UUID> = []

    public init(secret: Data? = nil) {
        macKey = SymmetricKey(data: secret ?? Self.randomBytes(count: 32))
    }

    public func issue(
        subject: String,
        scopes: Set<String>,
        accessLifetime: TimeInterval = 300,
        refreshLifetime: TimeInterval = 14 * 24 * 60 * 60,
        familyID: UUID = UUID(),
        now: Date = Date()
    ) -> OAuthTokenPair {
        let pair = OAuthTokenPair(
            accessToken: Self.randomToken(),
            refreshToken: Self.randomToken(),
            accessExpiresAt: now.addingTimeInterval(accessLifetime),
            refreshExpiresAt: now.addingTimeInterval(refreshLifetime),
            familyID: familyID
        )
        let stored = StoredToken(
            subject: subject,
            scopes: scopes,
            accessDigest: digest(pair.accessToken),
            refreshDigest: digest(pair.refreshToken),
            accessExpiresAt: pair.accessExpiresAt,
            refreshExpiresAt: pair.refreshExpiresAt,
            familyID: familyID,
            refreshUsed: false
        )
        accessTokens[stored.accessDigest] = stored
        refreshTokens[stored.refreshDigest] = stored
        return pair
    }

    public func validateAccess(_ token: String, now: Date = Date()) throws -> (subject: String, scopes: Set<String>) {
        guard let stored = accessTokens[digest(token)], stored.accessExpiresAt > now,
              !revokedFamilies.contains(stored.familyID) else {
            throw SwanError.unauthorized("unknown, expired, or revoked access token")
        }
        return (stored.subject, stored.scopes)
    }

    public func redeemRefresh(_ token: String, now: Date = Date()) throws -> OAuthTokenPair {
        let tokenDigest = digest(token)
        guard var stored = refreshTokens[tokenDigest], stored.refreshExpiresAt > now,
              !revokedFamilies.contains(stored.familyID) else {
            throw SwanError.unauthorized("unknown, expired, or revoked refresh token")
        }
        if stored.refreshUsed {
            revokedFamilies.insert(stored.familyID)
            throw SwanError.unauthorized("refresh token reuse revoked its token family")
        }
        stored.refreshUsed = true
        refreshTokens[tokenDigest] = stored
        return issue(
            subject: stored.subject,
            scopes: stored.scopes,
            accessLifetime: 300,
            refreshLifetime: stored.refreshExpiresAt.timeIntervalSince(now),
            familyID: stored.familyID,
            now: now
        )
    }

    public func revokeFamily(for refreshToken: String) {
        if let stored = refreshTokens[digest(refreshToken)] { revokedFamilies.insert(stored.familyID) }
    }

    private func digest(_ token: String) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(token.utf8), using: macKey))
    }

    private static func randomToken() -> String { randomBytes(count: 32).base64URLEncodedString() }

    private static func randomBytes(count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }
}

public struct DPoPNonceService: Sendable {
    private let key: SymmetricKey
    private let lifetime: TimeInterval

    public init(secret: Data, lifetime: TimeInterval = 300) {
        key = SymmetricKey(data: secret)
        self.lifetime = lifetime
    }

    public func issue(now: Date = Date()) -> String {
        let timestamp = String(Int(now.timeIntervalSince1970))
        let signature = Data(HMAC<SHA256>.authenticationCode(for: Data(timestamp.utf8), using: key)).base64URLEncodedString()
        return "\(timestamp).\(signature)"
    }

    public func isValid(_ nonce: String, now: Date = Date()) -> Bool {
        let pieces = nonce.split(separator: ".", maxSplits: 1).map(String.init)
        guard pieces.count == 2, let timestamp = Int(pieces[0]),
              abs(now.timeIntervalSince1970 - TimeInterval(timestamp)) <= lifetime,
              let actual = Data(base64URLEncoded: pieces[1]) else { return false }
        let expected = Data(HMAC<SHA256>.authenticationCode(for: Data(pieces[0].utf8), using: key))
        return constantTimeEqual(expected, actual)
    }
}

public actor DPoPReplayStore {
    private var expiryByJTI: [String: Date] = [:]
    private let lifetime: TimeInterval

    public init(lifetime: TimeInterval = 600) { self.lifetime = lifetime }

    public func accept(jti: String, now: Date = Date()) -> Bool {
        expiryByJTI = expiryByJTI.filter { $0.value > now }
        guard expiryByJTI[jti] == nil else { return false }
        expiryByJTI[jti] = now.addingTimeInterval(lifetime)
        return true
    }
}

public enum PermissionedDataJWT {
    public static let delegationType = "atproto-space-delegation+jwt"
    public static let credentialType = "atproto-space-credential+jwt"
    public static let clientAttestationType = "atproto-client-attestation+jwt"

    public struct Header: Codable, Sendable, Equatable {
        public let alg: String
        public let typ: String
        public let kid: String?
    }

    public struct DelegationClaims: Codable, Sendable, Equatable {
        public let iss: String
        public let aud: String
        public let sub: String
        public let iat: Int64
        public let exp: Int64
        public let jti: String
    }

    public struct SpaceCredentialClaims: Codable, Sendable, Equatable {
        public let iss: String
        public let sub: String
        public let iat: Int64
        public let exp: Int64
        public let jti: String
    }

    public struct ClientAttestationClaims: Codable, Sendable, Equatable {
        public let iss: String
        public let sub: String
        public let aud: String
        public let iat: Int64
        public let exp: Int64
        public let jti: String
    }

    public static func createDelegationToken(
        issuer: String,
        audience: String,
        space: SpaceURI,
        key: P256.Signing.PrivateKey,
        now: Date = Date(),
        lifetime: TimeInterval = 60
    ) throws -> String {
        let issuedAt = Int64(now.timeIntervalSince1970)
        return try sign(
            type: delegationType,
            kid: "#atproto",
            claims: DelegationClaims(
                iss: issuer, aud: audience, sub: space.rawValue, iat: issuedAt,
                exp: issuedAt + Int64(lifetime), jti: UUID().uuidString
            ),
            key: key
        )
    }

    public static func verifyDelegationToken(
        _ token: String,
        publicKey: P256.Signing.PublicKey,
        audience: String,
        now: Date = Date(),
        clockSkew: TimeInterval = 60
    ) throws -> DelegationClaims {
        let parsed = try verify(token, expectedType: delegationType, publicKey: publicKey)
        let claims = try decode(DelegationClaims.self, from: parsed.payload)
        guard claims.aud == audience, (try? SpaceURI(claims.sub)) != nil else {
            throw SwanError.unauthorized("delegation token audience or space is invalid")
        }
        try validateTimes(iat: claims.iat, exp: claims.exp, now: now, clockSkew: clockSkew)
        return claims
    }

    public static func createSpaceCredential(
        issuer: String,
        space: SpaceURI,
        key: P256.Signing.PrivateKey,
        now: Date = Date(),
        lifetime: TimeInterval = 2 * 60 * 60,
        kid: String = "#atproto_space"
    ) throws -> String {
        let issuedAt = Int64(now.timeIntervalSince1970)
        return try sign(
            type: credentialType,
            kid: kid,
            claims: SpaceCredentialClaims(
                iss: issuer, sub: space.rawValue, iat: issuedAt,
                exp: issuedAt + Int64(lifetime), jti: UUID().uuidString
            ),
            key: key
        )
    }

    public static func verifySpaceCredential(
        _ token: String,
        publicKey: P256.Signing.PublicKey,
        now: Date = Date(),
        clockSkew: TimeInterval = 60
    ) throws -> SpaceCredentialClaims {
        let parsed = try verify(token, expectedType: credentialType, publicKey: publicKey)
        let claims = try decode(SpaceCredentialClaims.self, from: parsed.payload)
        guard let space = try? SpaceURI(claims.sub), space.authority == claims.iss else {
            throw SwanError.unauthorized("space credential issuer or subject is invalid")
        }
        try validateTimes(iat: claims.iat, exp: claims.exp, now: now, clockSkew: clockSkew)
        return claims
    }

    /// Parses structural attestation claims before the metadata/JWKS component
    /// resolves and verifies the app key. This intentionally does not assert
    /// attestation authenticity until that network-bound step succeeds.
    public static func parseClientAttestation(_ token: String, now: Date = Date(), clockSkew: TimeInterval = 60) throws -> ClientAttestationClaims {
        let parsed = try parse(token)
        guard parsed.header.typ == clientAttestationType else { throw SwanError.unauthorized("wrong client attestation type") }
        let claims = try decode(ClientAttestationClaims.self, from: parsed.payload)
        guard claims.iss == claims.sub, URL(string: claims.iss)?.scheme == "https", !claims.aud.isEmpty else {
            throw SwanError.malformed("invalid client attestation claims")
        }
        try validateTimes(iat: claims.iat, exp: claims.exp, now: now, clockSkew: clockSkew)
        return claims
    }

    private struct ParsedJWT: Sendable {
        let header: Header
        let payload: Data
        let signingInput: Data
        let signature: Data
    }

    private static func sign<Claims: Encodable>(type: String, kid: String?, claims: Claims, key: P256.Signing.PrivateKey) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let header = Header(alg: "ES256", typ: type, kid: kid)
        let headerPart = try encoder.encode(header).base64URLEncodedString()
        let payloadPart = try encoder.encode(claims).base64URLEncodedString()
        let signingInput = "\(headerPart).\(payloadPart)"
        let signature = try P256WireSignature.sign(Data(signingInput.utf8), using: key).base64URLEncodedString()
        return "\(signingInput).\(signature)"
    }

    private static func verify(_ token: String, expectedType: String, publicKey: P256.Signing.PublicKey) throws -> ParsedJWT {
        let parsed = try parse(token)
        guard parsed.header.typ == expectedType, parsed.header.alg == "ES256" else {
            throw SwanError.unauthorized("JWT type or algorithm is invalid")
        }
        let signature = try P256WireSignature.decodeCanonical(parsed.signature)
        guard publicKey.isValidSignature(signature, for: parsed.signingInput) else {
            throw SwanError.unauthorized("JWT signature is invalid")
        }
        return parsed
    }

    private static func parse(_ token: String) throws -> ParsedJWT {
        let pieces = token.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard pieces.count == 3,
              let headerData = Data(base64URLEncoded: pieces[0]),
              let payload = Data(base64URLEncoded: pieces[1]),
              let signature = Data(base64URLEncoded: pieces[2]) else {
            throw SwanError.malformed("malformed JWT")
        }
        let header = try decode(Header.self, from: headerData)
        return ParsedJWT(header: header, payload: payload, signingInput: Data("\(pieces[0]).\(pieces[1])".utf8), signature: signature)
    }

    private static func decode<Decoded: Decodable>(_ type: Decoded.Type, from data: Data) throws -> Decoded {
        do { return try JSONDecoder().decode(type, from: data) }
        catch { throw SwanError.malformed("malformed JWT JSON") }
    }

    private static func validateTimes(iat: Int64, exp: Int64, now: Date, clockSkew: TimeInterval) throws {
        let current = Int64(now.timeIntervalSince1970)
        guard exp >= iat, exp >= current - Int64(clockSkew), iat <= current + Int64(clockSkew) else {
            throw SwanError.expired
        }
    }
}

public extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    init?(base64URLEncoded value: String) {
        var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64.append(String(repeating: "=", count: (4 - base64.count % 4) % 4))
        self.init(base64Encoded: base64)
    }
}

private func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
    guard lhs.count == rhs.count else { return false }
    var difference: UInt8 = 0
    for (left, right) in zip(lhs, rhs) { difference |= left ^ right }
    return difference == 0
}
