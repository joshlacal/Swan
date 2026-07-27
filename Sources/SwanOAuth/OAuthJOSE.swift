import Crypto
import Foundation
import SwanCore

/// A public P-256 JWK accepted by Swan's AT Protocol OAuth implementation.
/// Only the EC/P-256 material necessary for ES256 verification is modeled;
/// private JWK material is rejected at this trust boundary.
public struct OAuthJSONWebKey: Codable, Sendable, Equatable {
    public let keyType: String
    public let curve: String
    public let x: String
    public let y: String
    public let keyID: String?
    public let algorithm: String?
    public let use: String?

    public init(
        keyType: String = "EC",
        curve: String = "P-256",
        x: String,
        y: String,
        keyID: String? = nil,
        algorithm: String? = "ES256",
        use: String? = "sig"
    ) throws {
        self.keyType = keyType
        self.curve = curve
        self.x = x
        self.y = y
        self.keyID = keyID
        self.algorithm = algorithm
        self.use = use
        try validate()
    }

    private enum CodingKeys: String, CodingKey {
        case keyType = "kty"
        case curve = "crv"
        case x, y
        case keyID = "kid"
        case algorithm = "alg"
        case use
        case privateScalar = "d"
    }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        guard !values.contains(.privateScalar) else {
            throw SwanError.malformed("private JWK material is not accepted")
        }
        try self.init(
            keyType: try values.decode(String.self, forKey: .keyType),
            curve: try values.decode(String.self, forKey: .curve),
            x: try values.decode(String.self, forKey: .x),
            y: try values.decode(String.self, forKey: .y),
            keyID: try values.decodeIfPresent(String.self, forKey: .keyID),
            algorithm: try values.decodeIfPresent(String.self, forKey: .algorithm),
            use: try values.decodeIfPresent(String.self, forKey: .use)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(keyType, forKey: .keyType)
        try values.encode(curve, forKey: .curve)
        try values.encode(x, forKey: .x)
        try values.encode(y, forKey: .y)
        try values.encodeIfPresent(keyID, forKey: .keyID)
        try values.encodeIfPresent(algorithm, forKey: .algorithm)
        try values.encodeIfPresent(use, forKey: .use)
    }

    /// RFC 7638's SHA-256 thumbprint over the required P-256 public members.
    public func thumbprint() -> String {
        let canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(x)\",\"y\":\"\(y)\"}"
        return Data(SHA256.hash(data: Data(canonical.utf8))).base64URLEncodedString()
    }

    public func publicKey() throws -> P256.Signing.PublicKey {
        let xBytes = try OAuthBase64URL.decodeCoordinate(x)
        let yBytes = try OAuthBase64URL.decodeCoordinate(y)
        var representation = Data([0x04])
        representation.append(xBytes)
        representation.append(yBytes)
        do {
            return try P256.Signing.PublicKey(x963Representation: representation)
        } catch {
            throw SwanError.malformed("JWK P-256 point is invalid")
        }
    }

    private func validate() throws {
        guard keyType == "EC", curve == "P-256",
              algorithm == nil || algorithm == "ES256",
              use == nil || use == "sig" else {
            throw SwanError.malformed("unsupported JWK parameters")
        }
        if let keyID {
            guard !keyID.isEmpty, keyID.utf8.count <= 1_024, !keyID.utf8.contains(0) else {
                throw SwanError.malformed("JWK kid is invalid")
            }
        }
        _ = try OAuthBase64URL.decodeCoordinate(x)
        _ = try OAuthBase64URL.decodeCoordinate(y)
        _ = try publicKey()
    }
}

/// A key set that cannot contain duplicate `kid` entries. Key selection is
/// intentionally fail-closed: an absent `kid` only works when exactly one key
/// exists, and never silently picks the first of several candidates.
public struct OAuthJSONWebKeySet: Codable, Sendable, Equatable {
    public let keys: [OAuthJSONWebKey]

    private enum CodingKeys: String, CodingKey {
        case keys
    }

    public init(keys: [OAuthJSONWebKey]) throws {
        guard !keys.isEmpty, keys.count <= 64 else {
            throw SwanError.malformed("JWKS key count is invalid")
        }
        let named = keys.compactMap(\.keyID)
        guard named.count == Set(named).count else {
            throw SwanError.malformed("JWKS contains duplicate kid values")
        }
        self.keys = keys
    }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(keys: values.decode([OAuthJSONWebKey].self, forKey: .keys))
    }

    public func encode(to encoder: any Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(keys, forKey: .keys)
    }

    public func select(keyID: String?) throws -> OAuthJSONWebKey {
        if let keyID {
            guard let key = keys.first(where: { $0.keyID == keyID }) else {
                throw SwanError.unauthorized("JWT kid is not present in JWKS")
            }
            return key
        }
        guard keys.count == 1, let key = keys.first else {
            throw SwanError.unauthorized("JWT key selection is ambiguous")
        }
        return key
    }

    /// Decodes a fetched JWKS after rejecting duplicate JSON member names.
    public static func decodeValidated(_ data: Data) throws -> Self {
        try StrictJSON.decode(Self.self, from: data)
    }
}

public enum OAuthBase64URL {
    /// Decodes only canonical unpadded base64url text. Accepting the more
    /// permissive Base64 variants here would make JWK identity and RFC 7638
    /// thumbprints ambiguous.
    public static func decode(_ value: String, maxBytes: Int = 16_384) throws -> Data {
        guard !value.isEmpty, !value.contains("="), value.utf8.allSatisfy({ byte in
            (65 ... 90).contains(byte) || (97 ... 122).contains(byte) ||
                (48 ... 57).contains(byte) || byte == 45 || byte == 95
        }), let decoded = Data(base64URLEncoded: value), decoded.count <= maxBytes,
           decoded.base64URLEncodedString() == value else {
            throw SwanError.malformed("invalid base64url value")
        }
        return decoded
    }

    fileprivate static func decodeCoordinate(_ value: String) throws -> Data {
        let decoded = try decode(value, maxBytes: 32)
        guard decoded.count == 32 else {
            throw SwanError.malformed("P-256 JWK coordinate must be exactly 32 bytes")
        }
        return decoded
    }
}

public struct OAuthJWTHeader: Codable, Sendable, Equatable {
    public let algorithm: String
    public let type: String?
    public let keyID: String?
    public let jwk: OAuthJSONWebKey?
    public let criticalHeaders: [String]?
    public let base64Payload: Bool?

    private enum CodingKeys: String, CodingKey {
        case algorithm = "alg"
        case type = "typ"
        case keyID = "kid"
        case jwk
        case criticalHeaders = "crit"
        case base64Payload = "b64"
    }
}

/// Standard JWT claims represented independently from any OAuth-specific
/// claims. `aud` follows JWT's permitted string-or-array encoding.
public struct OAuthJWTRegisteredClaims: Decodable, Sendable, Equatable {
    public let issuer: String?
    public let subject: String?
    public let audience: [String]?
    public let issuedAt: Int64?
    public let expiresAt: Int64?
    public let jwtID: String?

    private enum CodingKeys: String, CodingKey {
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case issuedAt = "iat"
        case expiresAt = "exp"
        case jwtID = "jti"
    }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        issuer = try values.decodeIfPresent(String.self, forKey: .issuer)
        subject = try values.decodeIfPresent(String.self, forKey: .subject)
        if let single = try values.decodeIfPresent(String.self, forKey: .audience) {
            audience = [single]
        } else {
            audience = try values.decodeIfPresent([String].self, forKey: .audience)
        }
        issuedAt = try values.decodeIfPresent(Int64.self, forKey: .issuedAt)
        expiresAt = try values.decodeIfPresent(Int64.self, forKey: .expiresAt)
        jwtID = try values.decodeIfPresent(String.self, forKey: .jwtID)
    }
}

/// Constraints applied after a compact JWT has been structurally parsed and
/// its ES256 signature has verified. The defaults require no registered claims
/// so the same strict verifier can serve DPoP, then callers can opt into the
/// claims appropriate to their profile.
public struct OAuthJWTVerificationConstraints: Sendable, Equatable {
    public var expectedIssuer: String?
    public var expectedAudience: String?
    public var now: Date
    public var clockSkew: TimeInterval
    public var requireIssuedAt: Bool
    public var requireExpiration: Bool
    public var maxLifetime: TimeInterval?
    public var maximumAge: TimeInterval?

    public init(
        expectedIssuer: String? = nil,
        expectedAudience: String? = nil,
        now: Date = Date(),
        clockSkew: TimeInterval = 60,
        requireIssuedAt: Bool = false,
        requireExpiration: Bool = false,
        maxLifetime: TimeInterval? = nil,
        maximumAge: TimeInterval? = nil
    ) {
        self.expectedIssuer = expectedIssuer
        self.expectedAudience = expectedAudience
        self.now = now
        self.clockSkew = clockSkew
        self.requireIssuedAt = requireIssuedAt
        self.requireExpiration = requireExpiration
        self.maxLifetime = maxLifetime
        self.maximumAge = maximumAge
    }
}

public struct OAuthVerifiedJWT: Sendable {
    public let header: OAuthJWTHeader
    public let payload: Data
    public let registeredClaims: OAuthJWTRegisteredClaims
}

/// Minimal, strict ES256 compact JWT verification. It never accepts `none`,
/// never infers an algorithm from a key, and scans header and payload JSON for
/// duplicate member names before decoding either document.
public enum OAuthCompactJWT {
    /// Reads a strict JOSE header only to locate the verification key. Callers
    /// must immediately verify the complete token before trusting any field.
    public static func unverifiedHeader(_ compact: String) throws -> OAuthJWTHeader {
        try parse(compact).header
    }

    public static func verify(
        _ compact: String,
        publicKey: P256.Signing.PublicKey,
        expectedType: String? = nil,
        constraints: OAuthJWTVerificationConstraints = .init()
    ) throws -> OAuthVerifiedJWT {
        let parsed = try parse(compact)
        guard parsed.header.algorithm == "ES256", parsed.header.type == expectedType || expectedType == nil else {
            throw SwanError.unauthorized("JWT type or algorithm is invalid")
        }
        let signature = try P256WireSignature.decodeCanonical(parsed.signature)
        guard publicKey.isValidSignature(signature, for: parsed.signingInput) else {
            throw SwanError.unauthorized("JWT signature is invalid")
        }
        let registered = try StrictJSON.decode(OAuthJWTRegisteredClaims.self, from: parsed.payload)
        try validate(registered, constraints: constraints)
        return OAuthVerifiedJWT(header: parsed.header, payload: parsed.payload, registeredClaims: registered)
    }

    public static func decodeClaims<Claims: Decodable>(_ type: Claims.Type, from token: OAuthVerifiedJWT) throws -> Claims {
        try StrictJSON.decode(type, from: token.payload)
    }

    private struct Parsed: Sendable {
        let header: OAuthJWTHeader
        let payload: Data
        let signingInput: Data
        let signature: Data
    }

    private static func parse(_ compact: String) throws -> Parsed {
        guard compact.utf8.count <= 32_768 else { throw SwanError.malformed("JWT is too large") }
        let parts = compact.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3 else { throw SwanError.malformed("JWT must be compact serialization") }
        let headerData = try OAuthBase64URL.decode(parts[0], maxBytes: 4_096)
        let payload = try OAuthBase64URL.decode(parts[1], maxBytes: 16_384)
        let signature = try OAuthBase64URL.decode(parts[2], maxBytes: 64)
        guard signature.count == 64 else { throw SwanError.malformed("JWT ES256 signature length is invalid") }
        let header = try StrictJSON.decode(OAuthJWTHeader.self, from: headerData)
        // Swan implements only ordinary compact JWS JSON payload processing.
        // There are no supported critical extensions, and accepting either a
        // `crit` list or an explicit `b64` flag would permit semantics that the
        // verifier does not model in its signing input.
        guard header.criticalHeaders == nil, header.base64Payload == nil else {
            throw SwanError.malformed("JWT uses unsupported critical JOSE header semantics")
        }
        return Parsed(
            header: header,
            payload: payload,
            signingInput: Data("\(parts[0]).\(parts[1])".utf8),
            signature: signature
        )
    }

    private static func validate(
        _ claims: OAuthJWTRegisteredClaims,
        constraints: OAuthJWTVerificationConstraints
    ) throws {
        guard constraints.clockSkew >= 0, constraints.clockSkew.isFinite else {
            throw SwanError.malformed("JWT clock skew policy is invalid")
        }
        if let expectedIssuer = constraints.expectedIssuer {
            guard claims.issuer == expectedIssuer else { throw SwanError.unauthorized("JWT issuer is invalid") }
        }
        if let expectedAudience = constraints.expectedAudience {
            guard claims.audience?.contains(expectedAudience) == true else {
                throw SwanError.unauthorized("JWT audience is invalid")
            }
        }
        let now = Int64(constraints.now.timeIntervalSince1970)
        let skew = Int64(constraints.clockSkew)
        if constraints.requireIssuedAt, claims.issuedAt == nil { throw SwanError.malformed("JWT iat is required") }
        if constraints.requireExpiration, claims.expiresAt == nil { throw SwanError.malformed("JWT exp is required") }
        if let issuedAt = claims.issuedAt {
            guard issuedAt <= now + skew else { throw SwanError.unauthorized("JWT iat is in the future") }
            if let maximumAge = constraints.maximumAge {
                guard maximumAge > 0, maximumAge.isFinite,
                      issuedAt >= now - Int64(maximumAge) - skew else {
                    throw SwanError.expired
                }
            }
        }
        if let expiresAt = claims.expiresAt {
            guard expiresAt >= now - skew else { throw SwanError.expired }
            if let issuedAt = claims.issuedAt {
                guard expiresAt >= issuedAt else { throw SwanError.malformed("JWT exp precedes iat") }
                if let maxLifetime = constraints.maxLifetime {
                    guard maxLifetime > 0, maxLifetime.isFinite,
                          expiresAt - issuedAt <= Int64(maxLifetime) else {
                        throw SwanError.unauthorized("JWT lifetime is too long")
                    }
                }
            }
        }
    }
}

/// A small complete JSON parser used only to reject duplicate object member
/// names before Foundation's Codable decoder sees an untrusted document.
/// Duplicate names are otherwise accepted by JSONDecoder with last-value-wins
/// behavior, which is unsuitable for signed JOSE headers and metadata.
enum StrictJSON {
    static func validate(_ data: Data) throws {
        var parser = Parser(bytes: Array(data))
        try parser.parseDocument()
    }

    static func decode<Value: Decodable>(_ type: Value.Type, from data: Data) throws -> Value {
        try validate(data)
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch let error as SwanError {
            throw error
        } catch {
            throw SwanError.malformed("invalid JSON")
        }
    }

    private struct Parser {
        let bytes: [UInt8]
        var index = 0

        mutating func parseDocument() throws {
            skipWhitespace()
            try parseValue()
            skipWhitespace()
            guard index == bytes.count else { throw SwanError.malformed("invalid JSON") }
        }

        mutating func parseValue() throws {
            skipWhitespace()
            guard let byte = bytes[safe: index] else { throw SwanError.malformed("invalid JSON") }
            switch byte {
            case 0x7B: try parseObject()
            case 0x5B: try parseArray()
            case 0x22: _ = try parseString()
            case 0x74: try consumeLiteral("true")
            case 0x66: try consumeLiteral("false")
            case 0x6E: try consumeLiteral("null")
            case 0x2D, 0x30 ... 0x39: try parseNumber()
            default: throw SwanError.malformed("invalid JSON")
            }
        }

        mutating func parseObject() throws {
            try consume(0x7B)
            skipWhitespace()
            if consumeIf(0x7D) { return }
            var keys = Set<String>()
            while true {
                skipWhitespace()
                let key = try parseString()
                guard keys.insert(key).inserted else { throw SwanError.malformed("duplicate JSON member") }
                skipWhitespace()
                try consume(0x3A)
                try parseValue()
                skipWhitespace()
                if consumeIf(0x7D) { return }
                try consume(0x2C)
            }
        }

        mutating func parseArray() throws {
            try consume(0x5B)
            skipWhitespace()
            if consumeIf(0x5D) { return }
            while true {
                try parseValue()
                skipWhitespace()
                if consumeIf(0x5D) { return }
                try consume(0x2C)
            }
        }

        mutating func parseString() throws -> String {
            try consume(0x22)
            var result = ""
            var chunkStart = index
            while let byte = bytes[safe: index] {
                if byte == 0x22 {
                    try appendUTF8Chunk(start: chunkStart, to: index, into: &result)
                    index += 1
                    return result
                }
                if byte == 0x5C {
                    try appendUTF8Chunk(start: chunkStart, to: index, into: &result)
                    index += 1
                    guard let escape = bytes[safe: index] else { throw SwanError.malformed("invalid JSON string") }
                    index += 1
                    switch escape {
                    case 0x22: result.append("\"")
                    case 0x5C: result.append("\\")
                    case 0x2F: result.append("/")
                    case 0x62: result.append("\u{08}")
                    case 0x66: result.append("\u{0C}")
                    case 0x6E: result.append("\n")
                    case 0x72: result.append("\r")
                    case 0x74: result.append("\t")
                    case 0x75: try appendUnicodeEscape(into: &result)
                    default: throw SwanError.malformed("invalid JSON string")
                    }
                    chunkStart = index
                } else {
                    guard byte >= 0x20 else { throw SwanError.malformed("invalid JSON string") }
                    index += 1
                }
            }
            throw SwanError.malformed("invalid JSON string")
        }

        mutating func appendUnicodeEscape(into output: inout String) throws {
            let first = try parseHex16()
            if (0xD800 ... 0xDBFF).contains(first) {
                guard consumeIf(0x5C), consumeIf(0x75) else { throw SwanError.malformed("invalid JSON surrogate") }
                let second = try parseHex16()
                guard (0xDC00 ... 0xDFFF).contains(second) else { throw SwanError.malformed("invalid JSON surrogate") }
                let scalar = 0x10000 + ((UInt32(first) - 0xD800) << 10) + (UInt32(second) - 0xDC00)
                guard let value = UnicodeScalar(scalar) else { throw SwanError.malformed("invalid JSON scalar") }
                output.unicodeScalars.append(value)
            } else {
                guard !(0xDC00 ... 0xDFFF).contains(first), let value = UnicodeScalar(UInt32(first)) else {
                    throw SwanError.malformed("invalid JSON surrogate")
                }
                output.unicodeScalars.append(value)
            }
        }

        mutating func parseHex16() throws -> UInt16 {
            guard index + 4 <= bytes.count else { throw SwanError.malformed("invalid JSON escape") }
            var result: UInt16 = 0
            for _ in 0 ..< 4 {
                guard let byte = bytes[safe: index] else { throw SwanError.malformed("invalid JSON escape") }
                let nibble: UInt16
                switch byte {
                case 0x30 ... 0x39: nibble = UInt16(byte - 0x30)
                case 0x41 ... 0x46: nibble = UInt16(byte - 0x41 + 10)
                case 0x61 ... 0x66: nibble = UInt16(byte - 0x61 + 10)
                default: throw SwanError.malformed("invalid JSON escape")
                }
                result = (result << 4) | nibble
                index += 1
            }
            return result
        }

        mutating func parseNumber() throws {
            _ = consumeIf(0x2D)
            guard let first = bytes[safe: index] else { throw SwanError.malformed("invalid JSON number") }
            if first == 0x30 {
                index += 1
            } else if (0x31 ... 0x39).contains(first) {
                index += 1
                while let digit = bytes[safe: index], (0x30 ... 0x39).contains(digit) { index += 1 }
            } else {
                throw SwanError.malformed("invalid JSON number")
            }
            if consumeIf(0x2E) {
                guard let digit = bytes[safe: index], (0x30 ... 0x39).contains(digit) else {
                    throw SwanError.malformed("invalid JSON number")
                }
                while let digit = bytes[safe: index], (0x30 ... 0x39).contains(digit) { index += 1 }
            }
            if let exponent = bytes[safe: index], exponent == 0x45 || exponent == 0x65 {
                index += 1
                _ = consumeIf(0x2B) || consumeIf(0x2D)
                guard let digit = bytes[safe: index], (0x30 ... 0x39).contains(digit) else {
                    throw SwanError.malformed("invalid JSON number")
                }
                while let digit = bytes[safe: index], (0x30 ... 0x39).contains(digit) { index += 1 }
            }
        }

        mutating func consumeLiteral(_ literal: String) throws {
            for byte in literal.utf8 { try consume(byte) }
        }

        mutating func skipWhitespace() {
            while let byte = bytes[safe: index], byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D {
                index += 1
            }
        }

        mutating func consume(_ expected: UInt8) throws {
            guard consumeIf(expected) else { throw SwanError.malformed("invalid JSON") }
        }

        mutating func consumeIf(_ expected: UInt8) -> Bool {
            guard bytes[safe: index] == expected else { return false }
            index += 1
            return true
        }

        func appendUTF8Chunk(start: Int, to end: Int, into output: inout String) throws {
            guard start <= end, let chunk = String(bytes: bytes[start ..< end], encoding: .utf8) else {
                throw SwanError.malformed("invalid JSON UTF-8")
            }
            output.append(chunk)
        }
    }
}

private extension Array where Element == UInt8 {
    subscript(safe index: Int) -> UInt8? {
        indices.contains(index) ? self[index] : nil
    }
}
