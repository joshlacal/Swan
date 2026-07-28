import Crypto
import Foundation
import secp256k1
import SwanCore
import SwanSpaces

/// A bounded public key selected from a local account projection or an
/// operator-pinned interop fixture. P-256 remains Swan's local issuance
/// format, while the pinned TypeScript PDS produces compact low-S secp256k1
/// JWT signatures (`ES256K`). Keeping only raw secp256k1 public bytes here
/// makes the key material `Sendable` and avoids a request path retaining a
/// mutable C crypto context.
public enum PermissionedDataJWTVerificationKey: Sendable {
    case p256(P256.Signing.PublicKey)
    case secp256k1PublicKey(Data)

    var deterministicIdentity: Data {
        switch self {
        case let .p256(publicKey):
            return Data([0x01]) + publicKey.x963Representation
        case let .secp256k1PublicKey(encoded):
            return Data([0x02]) + encoded
        }
    }

    /// Internal shared verifier for the bounded proposal JWT and service-JWT
    /// parsers. The key enum itself still exposes no signing material and the
    /// caller must select it from a local/pinned resolver before this method
    /// is reached.
    func verifies(
        signature: Data,
        signingInput: Data,
        algorithm: String
    ) throws -> Bool {
        switch self {
        case let .p256(publicKey):
            guard algorithm == "ES256" else {
                throw SwanError.unauthorized("JWT algorithm does not match verification key")
            }
            let canonical = try P256WireSignature.decodeCanonical(signature)
            return publicKey.isValidSignature(canonical, for: signingInput)
        case let .secp256k1PublicKey(encoded):
            guard algorithm == "ES256K",
                  Self.isCanonicalSecp256k1Signature(signature) else {
                throw SwanError.unauthorized("JWT algorithm or signature is invalid")
            }
            let format: secp256k1.Format
            switch (encoded.count, encoded.first) {
            case (33, 0x02), (33, 0x03):
                format = .compressed
            case (65, 0x04):
                format = .uncompressed
            default:
                throw SwanError.unauthorized("secp256k1 public key is invalid")
            }
            do {
                let publicKey = try secp256k1.Signing.PublicKey(
                    dataRepresentation: encoded,
                    format: format
                )
                let compact = try secp256k1.Signing.ECDSASignature(
                    compactRepresentation: signature
                )
                return publicKey.isValidSignature(compact, for: signingInput)
            } catch {
                throw SwanError.unauthorized("secp256k1 JWT verification failed")
            }
        }
    }

    static func validatesSecp256k1PublicKey(_ encoded: Data) -> Bool {
        do {
            let format: secp256k1.Format
            switch (encoded.count, encoded.first) {
            case (33, 0x02), (33, 0x03):
                format = .compressed
            case (65, 0x04):
                format = .uncompressed
            default:
                return false
            }
            _ = try secp256k1.Signing.PublicKey(
                dataRepresentation: encoded,
                format: format
            )
            return true
        } catch {
            return false
        }
    }

    /// Both the TypeScript `@noble/curves` implementation and Swan reject
    /// malleable high-S compact signatures. secp256k1's group-order half is
    /// encoded as a big-endian 32-byte integer for a constant-size lexical
    /// comparison of the S half of `r || s`.
    private static func isCanonicalSecp256k1Signature(_ signature: Data) -> Bool {
        let bytes = Array(signature)
        guard bytes.count == 64 else { return false }
        let halfOrder: [UInt8] = [
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
            0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
        ]
        let s = bytes[32...]
        guard s.contains(where: { $0 != 0 }) else { return false }
        for (value, maximum) in zip(s, halfOrder) {
            if value != maximum { return value < maximum }
        }
        return true
    }
}

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

/// Token endpoint output paired with the scopes stored in the durable
/// authorization binding. The HTTP layer never reconstructs scope from a
/// current client document or form input.
public struct OAuthTokenGrantResult: Sendable, Equatable {
    public let accessToken: String
    public let accessExpiresAt: Date
    public let scopes: Set<String>
    public let subject: String
    /// Omitted when the metadata that authorized this code did not declare
    /// the `refresh_token` grant. The durable token pair is intentionally not
    /// itself an HTTP response model.
    public let refreshToken: String?

    public init(
        accessToken: String,
        accessExpiresAt: Date,
        scopes: Set<String>,
        subject: String,
        refreshToken: String?
    ) {
        self.accessToken = accessToken
        self.accessExpiresAt = accessExpiresAt
        self.scopes = scopes
        self.subject = subject
        self.refreshToken = refreshToken
    }
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
        Data(HMAC<Crypto.SHA256>.authenticationCode(for: Data(token.utf8), using: macKey))
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
        let signature = Data(HMAC<Crypto.SHA256>.authenticationCode(for: Data(timestamp.utf8), using: key)).base64URLEncodedString()
        return "\(timestamp).\(signature)"
    }

    public func isValid(_ nonce: String, now: Date = Date()) -> Bool {
        let pieces = nonce.split(separator: ".", maxSplits: 1).map(String.init)
        guard pieces.count == 2, let timestamp = Int(pieces[0]),
              abs(now.timeIntervalSince1970 - TimeInterval(timestamp)) <= lifetime,
              let actual = Data(base64URLEncoded: pieces[1]) else { return false }
        let expected = Data(HMAC<Crypto.SHA256>.authenticationCode(for: Data(pieces[0].utf8), using: key))
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
    /// credentials. Local issuance defaults to that method; verification has
    /// a separately named, profile-reviewed ordinary-account-key fallback.
    public static let spaceCredentialKeyID = "#atproto_space"
    /// Proposal 0016 permits the authority's ordinary AT Protocol verification
    /// method when no dedicated `#atproto_space` method is published. The
    /// pinned TypeScript PDS currently exercises this fallback in practice.
    public static let spaceCredentialFallbackKeyID = "#atproto"
    public static let spaceCredentialLifetime: TimeInterval = 2 * 60 * 60
    public static let maximumCompactDelegationBytes = 8 * 1_024
    public static let maximumCompactSpaceCredentialBytes = 8 * 1_024
    /// `jti` is a bounded opaque nonce in proposal 0016, not a UUID grammar.
    /// UUIDs remain Swan's minting format, but TypeScript producers and future
    /// implementations may use another non-control nonce representation.
    public static let maximumOpaqueJTIBytes = 512
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

    /// Bounded JOSE and claim material discovered before signature
    /// verification. The deliberately explicit `Untrusted` name is a security
    /// boundary: this value is only a key-resolution hint and must never be
    /// accepted as an authorization result.
    public struct UntrustedClientAttestationInspection: Sendable, Equatable {
        public let clientID: URL
        public let keyID: String
        public let claims: ClientAttestationClaims
        public let replayExpiresAt: Date

        public init(
            clientID: URL,
            keyID: String,
            claims: ClientAttestationClaims,
            replayExpiresAt: Date
        ) {
            self.clientID = clientID
            self.keyID = keyID
            self.claims = claims
            self.replayExpiresAt = replayExpiresAt
        }
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
        try verifyDelegationToken(
            token,
            publicKey: .p256(publicKey),
            audience: audience,
            expectedSpace: expectedSpace,
            now: now,
            clockSkew: clockSkew
        )
    }

    /// Verifies either proposal-supported ES256/P-256 or ES256K/secp256k1
    /// delegation material. Resolver selection remains local/pinned and is
    /// performed only after bounded structural inspection.
    public static func verifyDelegationToken(
        _ token: String,
        publicKey: PermissionedDataJWTVerificationKey,
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
              claims.jti.isValidPermissionedDataJTI else {
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
              isSupportedJWTAlgorithm(parsed.header.alg),
              parsed.header.kid == delegationKeyID else {
            throw SwanError.unauthorized("JWT type, algorithm, or key ID is invalid")
        }
        let claims = try decode(DelegationClaims.self, from: parsed.payload)
        guard isPermissionedDataDID(claims.iss),
              let space = try? SpaceURI(claims.sub),
              claims.aud == "\(space.authority)#atproto_space_host",
              claims.jti.isValidPermissionedDataJTI else {
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
              isSpaceCredentialKeyID(kid),
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
        try verifySpaceCredential(
            token,
            publicKey: .p256(publicKey),
            expectedSpace: expectedSpace,
            now: now,
            clockSkew: clockSkew
        )
    }

    /// Verifies either proposal-supported ES256/P-256 or ES256K/secp256k1
    /// authority credential material.
    public static func verifySpaceCredential(
        _ token: String,
        publicKey: PermissionedDataJWTVerificationKey,
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
              claims.jti.isValidPermissionedDataJTI,
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
              isSupportedJWTAlgorithm(parsed.header.alg),
              parsed.header.kid.map(isSpaceCredentialKeyID) == true else {
            throw SwanError.unauthorized("JWT type, algorithm, or key ID is invalid")
        }
        let claims = try decode(SpaceCredentialClaims.self, from: parsed.payload)
        guard let space = try? SpaceURI(claims.sub),
              space.authority == claims.iss,
              claims.jti.isValidPermissionedDataJTI else {
            throw SwanError.unauthorized("space credential issuer or subject is invalid")
        }
        return SpaceCredentialInspection(header: parsed.header, claims: claims)
    }

    /// Performs strict, bounded, duplicate-free local discovery before a
    /// client metadata URL may become a fetch target. This does not verify the
    /// signature and therefore returns an explicitly untrusted type.
    public static func inspectUntrustedClientAttestation(
        _ token: String,
        authority: String,
        now: Date = Date(),
        maximumLifetime: TimeInterval = 300,
        clockSkew: TimeInterval = 60
    ) throws -> UntrustedClientAttestationInspection {
        guard token.utf8.count <= 8 * 1_024,
              maximumLifetime > 0,
              maximumLifetime <= 600,
              maximumLifetime.rounded(.towardZero) == maximumLifetime,
              clockSkew >= 0,
              clockSkew <= 120,
              clockSkew.rounded(.towardZero) == clockSkew else {
            throw SwanError.malformed("client attestation policy is invalid")
        }
        let pieces = token.split(separator: ".", omittingEmptySubsequences: false)
        guard pieces.count == 3 else {
            throw SwanError.malformed("client attestation must use compact serialization")
        }
        let headerData = try OAuthBase64URL.decode(String(pieces[0]), maxBytes: 4 * 1_024)
        let payload = try OAuthBase64URL.decode(String(pieces[1]), maxBytes: 4 * 1_024)
        let signature = try OAuthBase64URL.decode(String(pieces[2]), maxBytes: 64)
        guard signature.count == 64 else {
            throw SwanError.malformed("client attestation signature length is invalid")
        }
        let header = try StrictJSON.decode(OAuthJWTHeader.self, from: headerData)
        guard header.type == clientAttestationType,
              header.algorithm == "ES256",
              let keyID = header.keyID,
              !keyID.isEmpty,
              keyID.utf8.count <= 1_024,
              keyID.utf8.allSatisfy({ $0 >= 0x20 && $0 != 0x7f }),
              header.jwk == nil,
              header.criticalHeaders == nil,
              header.base64Payload == nil else {
            throw SwanError.unauthorized("client attestation JOSE header is invalid")
        }
        let claims = try StrictJSON.decode(ClientAttestationClaims.self, from: payload)
        let expectedAudience = "\(authority)#atproto_space_host"
        guard claims.iss == claims.sub,
              claims.aud == expectedAudience,
              claims.jti.isValidPermissionedDataJTI,
              let clientID = URL(string: claims.iss),
              clientID.absoluteString == claims.iss else {
            throw SwanError.unauthorized("client attestation claims are invalid")
        }
        try OAuthClientMetadata.validateStandardClientID(clientID)
        try validateTimes(
            iat: claims.iat,
            exp: claims.exp,
            now: now,
            clockSkew: clockSkew,
            maximumLifetime: Int64(maximumLifetime)
        )
        let replayTimestamp = Double(claims.exp) + clockSkew
        guard replayTimestamp.isFinite else {
            throw SwanError.malformed("client attestation expiry is invalid")
        }
        return UntrustedClientAttestationInspection(
            clientID: clientID,
            keyID: keyID,
            claims: claims,
            replayExpiresAt: Date(timeIntervalSince1970: replayTimestamp)
        )
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

    private static func verifySpaceCredentialStructure(
        _ token: String,
        publicKey: PermissionedDataJWTVerificationKey
    ) throws -> ParsedJWT {
        let parsed = try parseSpaceCredential(token)
        guard parsed.header.typ == credentialType,
              isSupportedJWTAlgorithm(parsed.header.alg),
              parsed.header.kid.map(isSpaceCredentialKeyID) == true else {
            throw SwanError.unauthorized("JWT type, algorithm, or key ID is invalid")
        }
        guard try publicKey.verifies(
            signature: parsed.signature,
            signingInput: parsed.signingInput,
            algorithm: parsed.header.alg
        ) else {
            throw SwanError.unauthorized("JWT signature is invalid")
        }
        return parsed
    }

    private static func verifyDelegationStructure(
        _ token: String,
        publicKey: PermissionedDataJWTVerificationKey
    ) throws -> ParsedJWT {
        let parsed = try parseDelegationToken(token)
        guard parsed.header.typ == delegationType,
              isSupportedJWTAlgorithm(parsed.header.alg),
              parsed.header.kid == delegationKeyID else {
            throw SwanError.unauthorized("JWT type, algorithm, or key ID is invalid")
        }
        guard try publicKey.verifies(
            signature: parsed.signature,
            signingInput: parsed.signingInput,
            algorithm: parsed.header.alg
        ) else {
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

    private static func isSupportedJWTAlgorithm(_ value: String) -> Bool {
        value == "ES256" || value == "ES256K"
    }

    private static func isSpaceCredentialKeyID(_ value: String) -> Bool {
        value == spaceCredentialKeyID || value == spaceCredentialFallbackKeyID
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
    /// Proposal 0016 calls `jti` a random nonce. Do not impose Swan's UUID
    /// minting format on a TypeScript producer; retain only a compact,
    /// control-character-free representation suitable for HMAC replay keys.
    var isValidPermissionedDataJTI: Bool {
        let bytes = utf8
        return !bytes.isEmpty
            && bytes.count <= PermissionedDataJWT.maximumOpaqueJTIBytes
            && bytes.allSatisfy { $0 >= 0x20 && $0 != 0x7f }
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
