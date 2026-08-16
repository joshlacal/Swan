import Foundation

/// The only factors which can raise a password-authenticated account to MFA
/// strength.  Cryptographic enrollment and assertion verification live in the
/// factors lane; this value is the dependency-neutral storage/API contract.
public enum AuthenticationFactorKind: String, Codable, CaseIterable, Sendable {
    case passkey
    case totp
    case recoveryCode
}

public enum AuthenticationStrength: Codable, Sendable, Equatable {
    public enum Base: String, Codable, Sendable {
        case password
        case passwordPlusTOTP
        case passwordPlusPasskey
    }

    case none
    case password
    case passwordPlusTOTP
    case passwordPlusPasskey
    case emailRecovery
    case scopedAppPassword
    case stepUp(base: Base, factor: AuthenticationFactorKind?, verifiedAt: Date)

    public var isStepUp: Bool {
        if case .stepUp = self { return true }
        return false
    }
}

/// Opaque identifiers remain useful in in-memory authorization while storage
/// receives only the keyed 32-byte digest of the presented value.
public struct ManagementSessionID: Codable, Hashable, Sendable, Equatable {
    public let rawValue: String

    public init(rawValue: String) {
        precondition(Self.isValid(rawValue), "invalid management session identifier")
        self.rawValue = rawValue
    }

    public init(digest: Data) throws {
        guard digest.count == 32 else { throw SwanError.invalidIdentifier("management session digest") }
        self.rawValue = Hex.encode(digest)
    }

    public init(from decoder: any Decoder) throws {
        let value = try decoder.singleValueContainer().decode(String.self)
        guard Self.isValid(value) else {
            throw DecodingError.dataCorruptedError(
                in: try decoder.singleValueContainer(),
                debugDescription: "invalid management session identifier"
            )
        }
        self.rawValue = value
    }

    public func encode(to encoder: any Encoder) throws {
        guard Self.isValid(rawValue) else {
            throw EncodingError.invalidValue(
                rawValue,
                EncodingError.Context(codingPath: encoder.codingPath, debugDescription: "invalid management session identifier")
            )
        }
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    private static func isValid(_ value: String) -> Bool {
        (1 ... 512).contains(value.utf8.count)
            && value.utf8.allSatisfy { byte in
                (48 ... 57).contains(byte) || (65 ... 90).contains(byte)
                    || (97 ... 122).contains(byte) || byte == 45 || byte == 95
            }
    }
}

public struct LegacySessionID: Codable, Hashable, Sendable, Equatable {
    public let rawValue: String

    public init(rawValue: String) {
        precondition(Self.isValid(rawValue), "invalid legacy session identifier")
        self.rawValue = rawValue
    }

    public init(digest: Data) throws {
        guard digest.count == 32 else { throw SwanError.invalidIdentifier("legacy session digest") }
        self.rawValue = Hex.encode(digest)
    }

    public init(from decoder: any Decoder) throws {
        let value = try decoder.singleValueContainer().decode(String.self)
        guard Self.isValid(value) else {
            throw DecodingError.dataCorruptedError(
                in: try decoder.singleValueContainer(),
                debugDescription: "invalid legacy session identifier"
            )
        }
        self.rawValue = value
    }

    public func encode(to encoder: any Encoder) throws {
        guard Self.isValid(rawValue) else {
            throw EncodingError.invalidValue(
                rawValue,
                EncodingError.Context(codingPath: encoder.codingPath, debugDescription: "invalid legacy session identifier")
            )
        }
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    private static func isValid(_ value: String) -> Bool {
        (1 ... 512).contains(value.utf8.count)
            && value.utf8.allSatisfy { byte in
                (48 ... 57).contains(byte) || (65 ... 90).contains(byte)
                    || (97 ... 122).contains(byte) || byte == 45 || byte == 95
            }
    }
}
