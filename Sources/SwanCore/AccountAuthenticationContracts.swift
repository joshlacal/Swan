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

    public enum MFA: String, Codable, Sendable {
        case passwordPlusTOTP
        case passwordPlusPasskey
    }

    case none
    case password
    case passwordPlusTOTP
    case passwordPlusPasskey
    case emailRecovery
    case scopedAppPassword
    case stepUpPassword(verifiedAt: Date)
    case stepUpMFA(base: MFA, verifiedAt: Date)

    public static func stepUp(base: Base, factor: AuthenticationFactorKind?, verifiedAt: Date) throws -> Self {
        switch (base, factor) {
        case (.password, nil):
            return .stepUpPassword(verifiedAt: verifiedAt)
        case (.passwordPlusTOTP, .totp):
            return .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: verifiedAt)
        case (.passwordPlusPasskey, .passkey):
            return .stepUpMFA(base: .passwordPlusPasskey, verifiedAt: verifiedAt)
        default:
            throw SwanError.invalidIdentifier("invalid step-up strength")
        }
    }

    public var isStepUp: Bool {
        switch self {
        case .stepUpPassword, .stepUpMFA: return true
        default: return false
        }
    }

    private enum CodingKeys: String, CodingKey { case kind, base, verifiedAt }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try container.decode(String.self, forKey: .kind)
        switch kind {
        case "none": self = .none
        case "password": self = .password
        case "passwordPlusTOTP": self = .passwordPlusTOTP
        case "passwordPlusPasskey": self = .passwordPlusPasskey
        case "emailRecovery": self = .emailRecovery
        case "scopedAppPassword": self = .scopedAppPassword
        case "stepUpPassword": self = .stepUpPassword(verifiedAt: try container.decode(Date.self, forKey: .verifiedAt))
        case "stepUpMFA": self = .stepUpMFA(base: try container.decode(MFA.self, forKey: .base), verifiedAt: try container.decode(Date.self, forKey: .verifiedAt))
        default: throw DecodingError.dataCorruptedError(forKey: .kind, in: container, debugDescription: "unknown authentication strength")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .none: try container.encode("none", forKey: .kind)
        case .password: try container.encode("password", forKey: .kind)
        case .passwordPlusTOTP: try container.encode("passwordPlusTOTP", forKey: .kind)
        case .passwordPlusPasskey: try container.encode("passwordPlusPasskey", forKey: .kind)
        case .emailRecovery: try container.encode("emailRecovery", forKey: .kind)
        case .scopedAppPassword: try container.encode("scopedAppPassword", forKey: .kind)
        case let .stepUpPassword(verifiedAt):
            try container.encode("stepUpPassword", forKey: .kind)
            try container.encode(verifiedAt, forKey: .verifiedAt)
        case let .stepUpMFA(base, verifiedAt):
            try container.encode("stepUpMFA", forKey: .kind)
            try container.encode(base, forKey: .base)
            try container.encode(verifiedAt, forKey: .verifiedAt)
        }
    }
}

/// Opaque identifiers remain useful in in-memory authorization while storage
/// receives only the keyed 32-byte digest of the presented value.
public struct ManagementSessionID: Codable, Hashable, Sendable, Equatable {
    public let rawValue: String

    public init(rawValue: String) throws {
        guard Self.isValid(rawValue) else { throw SwanError.invalidIdentifier("management session identifier") }
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
        self = try Self(rawValue: value)
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

    public init(rawValue: String) throws {
        guard Self.isValid(rawValue) else { throw SwanError.invalidIdentifier("legacy session identifier") }
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
        self = try Self(rawValue: value)
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
