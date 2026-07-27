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
    /// Proposal 0016 signs user-to-space-host delegations with the user's
    /// regular AT Protocol signing key. This is intentionally distinct from
    /// the authority-owned `#atproto_space` credential key below.
    public static let delegationKeyID = "#atproto"
    public static let delegationLifetime: TimeInterval = 60
    /// Proposal 0016 assigns a dedicated DID verification method to space
    /// credentials. Swan's authority boundary does not silently fall back to
    /// another account key: a future DID resolver can make that fallback an
    /// explicit, profile-reviewed decision instead.
    public static let spaceCredentialKeyID = "#atproto_space"
    public static let spaceCredentialLifetime: TimeInterval = 2 * 60 * 60
    public static let maximumCompactDelegationBytes = 8 * 1_024
    public static let maximumCompactSpaceCredentialBytes = 8 * 1_024
    private static let maximumDelegationComponentBytes = 4 * 1_024
    private static let maximumDelegationJSONBytes = 4 * 1_024
    private static let maximumSpaceCredentialComponentBytes = 4 * 1_024
    private static let maximumSpaceCredentialJSONBytes = 4 * 1_024

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

    /// The unsigned, bounded metadata needed to select a verification key.
    /// Callers must never treat this inspection result as authorization: the
    /// signature is checked by ``verifySpaceCredential(_:publicKey:expectedSpace:now:clockSkew:)``.
    public struct SpaceCredentialInspection: Sendable, Equatable {
        public let header: Header
        public let claims: SpaceCredentialClaims

        public init(header: Header, claims: SpaceCredentialClaims) {
            self.header = header
            self.claims = claims
        }
    }

    /// The unsigned, bounded metadata used to select a local or pinned user
    /// verification key for a delegation. Inspection is never authorization:
    /// callers must verify the ES256 signature before creating a requester
    /// context or minting a credential.
    public struct DelegationInspection: Sendable, Equatable {
        public let header: Header
        public let claims: DelegationClaims

        public init(header: Header, claims: DelegationClaims) {
            self.header = header
            self.claims = claims
        }
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
        guard isPermissionedDataDID(issuer),
              audience == "\(space.authority)#atproto_space_host",
              lifetime > 0,
              lifetime <= delegationLifetime,
              lifetime.rounded(.towardZero) == lifetime else {
            throw SwanError.malformed("invalid delegation issuer, audience, or lifetime")
        }
        let issuedAt = Int64(now.timeIntervalSince1970)
        return try sign(
            type: delegationType,
            kid: delegationKeyID,
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
        expectedSpace: SpaceURI? = nil,
        now: Date = Date(),
        clockSkew: TimeInterval = 60
    ) throws -> DelegationClaims {
        guard clockSkew >= 0, clockSkew <= 5 * 60 else {
            throw SwanError.malformed("invalid delegation clock skew")
        }
        let parsed = try verifyDelegationStructure(token, publicKey: publicKey)
        let claims = try decode(DelegationClaims.self, from: parsed.payload)
        guard claims.aud == audience,
              isPermissionedDataDID(claims.iss),
              let space = try? SpaceURI(claims.sub),
              claims.aud == "\(space.authority)#atproto_space_host",
              expectedSpace.map({ $0 == space }) ?? true,
              claims.jti.isCanonicalCredentialJTI else {
            throw SwanError.unauthorized("delegation token audience or space is invalid")
        }
        try validateTimes(
            iat: claims.iat,
            exp: claims.exp,
            now: now,
            clockSkew: clockSkew,
            maximumLifetime: Int64(delegationLifetime)
        )
        return claims
    }

    /// Inspects a compact delegation before selecting a verification key.
    /// Like space credentials, this applies byte, base64url, JSON, type,
    /// algorithm, key-ID, DID, space, and JTI constraints before callers can
    /// access an issuer value. It deliberately performs no network lookup.
    public static func inspectDelegationToken(
        _ token: String
    ) throws -> DelegationInspection {
        let parsed = try parseDelegationToken(token)
        guard parsed.header.typ == delegationType,
              parsed.header.alg == "ES256",
              parsed.header.kid == delegationKeyID else {
            throw SwanError.unauthorized("JWT type, algorithm, or key ID is invalid")
        }
        let claims = try decode(DelegationClaims.self, from: parsed.payload)
        guard isPermissionedDataDID(claims.iss),
              let space = try? SpaceURI(claims.sub),
              claims.aud == "\(space.authority)#atproto_space_host",
              claims.jti.isCanonicalCredentialJTI else {
            throw SwanError.unauthorized("delegation token issuer, audience, or subject is invalid")
        }
        return DelegationInspection(header: parsed.header, claims: claims)
    }

    public static func createSpaceCredential(
        issuer: String,
        space: SpaceURI,
        key: P256.Signing.PrivateKey,
        now: Date = Date(),
        lifetime: TimeInterval = spaceCredentialLifetime,
        kid: String = spaceCredentialKeyID
    ) throws -> String {
        guard issuer == space.authority,
              kid == spaceCredentialKeyID,
              lifetime > 0,
              lifetime <= spaceCredentialLifetime,
              lifetime.rounded(.towardZero) == lifetime else {
            throw SwanError.malformed("invalid space credential issuer, key ID, or lifetime")
        }
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
        expectedSpace: SpaceURI? = nil,
        now: Date = Date(),
        clockSkew: TimeInterval = 60
    ) throws -> SpaceCredentialClaims {
        guard clockSkew >= 0, clockSkew <= 5 * 60 else {
            throw SwanError.malformed("invalid space credential clock skew")
        }
        let parsed = try verifySpaceCredentialStructure(token, publicKey: publicKey)
        let claims = try decode(SpaceCredentialClaims.self, from: parsed.payload)
        guard let space = try? SpaceURI(claims.sub),
              space.authority == claims.iss,
              claims.jti.isCanonicalCredentialJTI,
              expectedSpace.map({ $0 == space }) ?? true else {
            throw SwanError.unauthorized("space credential issuer or subject is invalid")
        }
        try validateTimes(
            iat: claims.iat,
            exp: claims.exp,
            now: now,
            clockSkew: clockSkew,
            maximumLifetime: Int64(spaceCredentialLifetime)
        )
        return claims
    }

    /// Inspects a compact space credential before DID/public-key resolution.
    /// The hard byte and base64url grammar limits are applied before JSON
    /// decoding so an untrusted bearer value cannot turn key selection into a
    /// whole-body parser or an oversized allocation.
    public static func inspectSpaceCredential(
        _ token: String
    ) throws -> SpaceCredentialInspection {
        let parsed = try parseSpaceCredential(token)
        guard parsed.header.typ == credentialType,
              parsed.header.alg == "ES256",
              parsed.header.kid == spaceCredentialKeyID else {
            throw SwanError.unauthorized("JWT type, algorithm, or key ID is invalid")
        }
        let claims = try decode(SpaceCredentialClaims.self, from: parsed.payload)
        guard let space = try? SpaceURI(claims.sub),
              space.authority == claims.iss,
              claims.jti.isCanonicalCredentialJTI else {
            throw SwanError.unauthorized("space credential issuer or subject is invalid")
        }
        return SpaceCredentialInspection(header: parsed.header, claims: claims)
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

    private static func verifySpaceCredentialStructure(
        _ token: String,
        publicKey: P256.Signing.PublicKey
    ) throws -> ParsedJWT {
        let parsed = try parseSpaceCredential(token)
        guard parsed.header.typ == credentialType,
              parsed.header.alg == "ES256",
              parsed.header.kid == spaceCredentialKeyID else {
            throw SwanError.unauthorized("JWT type, algorithm, or key ID is invalid")
        }
        let signature = try P256WireSignature.decodeCanonical(parsed.signature)
        guard publicKey.isValidSignature(signature, for: parsed.signingInput) else {
            throw SwanError.unauthorized("JWT signature is invalid")
        }
        return parsed
    }

    private static func verifyDelegationStructure(
        _ token: String,
        publicKey: P256.Signing.PublicKey
    ) throws -> ParsedJWT {
        let parsed = try parseDelegationToken(token)
        guard parsed.header.typ == delegationType,
              parsed.header.alg == "ES256",
              parsed.header.kid == delegationKeyID else {
            throw SwanError.unauthorized("JWT type, algorithm, or key ID is invalid")
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

    private static func parseSpaceCredential(_ token: String) throws -> ParsedJWT {
        guard token.utf8.count <= maximumCompactSpaceCredentialBytes else {
            throw SwanError.malformed("space credential is too large")
        }
        let pieces = token.split(separator: ".", omittingEmptySubsequences: false)
        guard pieces.count == 3,
              pieces.allSatisfy({
                  !$0.isEmpty
                      && $0.utf8.count <= maximumSpaceCredentialComponentBytes
                      && $0.utf8.allSatisfy(isBase64URLByte)
              }),
              let headerData = Data(base64URLEncoded: String(pieces[0])),
              let payload = Data(base64URLEncoded: String(pieces[1])),
              let signature = Data(base64URLEncoded: String(pieces[2])),
              headerData.count <= maximumSpaceCredentialJSONBytes,
              payload.count <= maximumSpaceCredentialJSONBytes,
              signature.count == 64 else {
            throw SwanError.malformed("malformed space credential")
        }
        let header = try decode(Header.self, from: headerData)
        return ParsedJWT(
            header: header,
            payload: payload,
            signingInput: Data("\(pieces[0]).\(pieces[1])".utf8),
            signature: signature
        )
    }

    private static func parseDelegationToken(_ token: String) throws -> ParsedJWT {
        guard token.utf8.count <= maximumCompactDelegationBytes else {
            throw SwanError.malformed("delegation token is too large")
        }
        let pieces = token.split(separator: ".", omittingEmptySubsequences: false)
        guard pieces.count == 3,
              pieces.allSatisfy({
                  !$0.isEmpty
                      && $0.utf8.count <= maximumDelegationComponentBytes
                      && $0.utf8.allSatisfy(isBase64URLByte)
              }),
              let headerData = Data(base64URLEncoded: String(pieces[0])),
              let payload = Data(base64URLEncoded: String(pieces[1])),
              let signature = Data(base64URLEncoded: String(pieces[2])),
              headerData.count <= maximumDelegationJSONBytes,
              payload.count <= maximumDelegationJSONBytes,
              signature.count == 64 else {
            throw SwanError.malformed("malformed delegation token")
        }
        let header = try decode(Header.self, from: headerData)
        return ParsedJWT(
            header: header,
            payload: payload,
            signingInput: Data("\(pieces[0]).\(pieces[1])".utf8),
            signature: signature
        )
    }

    private static func decode<Decoded: Decodable>(_ type: Decoded.Type, from data: Data) throws -> Decoded {
        do { return try JSONDecoder().decode(type, from: data) }
        catch { throw SwanError.malformed("malformed JWT JSON") }
    }

    private static func validateTimes(
        iat: Int64,
        exp: Int64,
        now: Date,
        clockSkew: TimeInterval,
        maximumLifetime: Int64? = nil
    ) throws {
        guard let current = integerTimestamp(now),
              let allowedSkew = integerClockSkew(clockSkew),
              exp >= iat,
              maximumLifetime.map({ maximumLifetime in
                  guard maximumLifetime >= 0 else { return false }
                  let duration = exp.subtractingReportingOverflow(iat)
                  return !duration.overflow && duration.partialValue <= maximumLifetime
              }) ?? true,
              isNotTooFarInPast(exp, comparedTo: current, allowedSkew: allowedSkew),
              isNotTooFarInFuture(iat, comparedTo: current, allowedSkew: allowedSkew) else {
            throw SwanError.expired
        }
    }

    private static func integerTimestamp(_ date: Date) -> Int64? {
        let timestamp = date.timeIntervalSince1970
        // `Double(Int64.max)` rounds up to 2^63, which cannot safely convert
        // back to Int64. Keep the upper bound exclusive before conversion.
        guard timestamp.isFinite,
              timestamp >= Double(Int64.min),
              timestamp < Double(Int64.max) else {
            return nil
        }
        return Int64(timestamp)
    }

    /// The JWT primitive validates the protocol's generic DID grammar rather
    /// than a local account-registry policy. A concrete local resolver later
    /// requires a registered, active account; pinned interop fixtures may use
    /// another valid DID method or a deliberately minimal test DID.
    private static func isPermissionedDataDID(_ value: String) -> Bool {
        let parts = value.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count >= 3,
              parts[0] == "did",
              !parts[1].isEmpty,
              !parts.dropFirst(2).joined(separator: ":").isEmpty else {
            return false
        }
        return value.utf8.allSatisfy {
            $0 >= 33 && $0 <= 126 && $0 != 47 && $0 != 63 && $0 != 35
        }
    }

    private static func integerClockSkew(_ skew: TimeInterval) -> Int64? {
        guard skew.isFinite,
              skew >= 0,
              skew < Double(Int64.max) else {
            return nil
        }
        return Int64(skew)
    }

    private static func isNotTooFarInPast(
        _ value: Int64,
        comparedTo current: Int64,
        allowedSkew: Int64
    ) -> Bool {
        guard value < current else { return true }
        let elapsed = current.subtractingReportingOverflow(value)
        return !elapsed.overflow && elapsed.partialValue <= allowedSkew
    }

    private static func isNotTooFarInFuture(
        _ value: Int64,
        comparedTo current: Int64,
        allowedSkew: Int64
    ) -> Bool {
        guard value > current else { return true }
        let lead = value.subtractingReportingOverflow(current)
        return !lead.overflow && lead.partialValue <= allowedSkew
    }
}

private func isBase64URLByte(_ byte: UInt8) -> Bool {
    (48 ... 57).contains(byte)
        || (65 ... 90).contains(byte)
        || (97 ... 122).contains(byte)
        || byte == 45
        || byte == 95
}

private extension String {
    var isCanonicalCredentialJTI: Bool {
        UUID(uuidString: self)?.uuidString.lowercased() == lowercased()
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
