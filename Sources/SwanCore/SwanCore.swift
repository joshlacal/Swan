import Foundation
import Logging
import Crypto

public enum SwanError: Error, Sendable, Equatable, CustomStringConvertible {
    case invalidIdentifier(String)
    case invalidProfile(String)
    case unauthorized(String)
    case conflict(expected: UInt64, actual: UInt64)
    case expired
    case malformed(String)
    case unavailable(String)

    public var description: String {
        switch self {
        case let .invalidIdentifier(value): "invalid identifier: \(value)"
        case let .invalidProfile(value): "invalid protocol profile: \(value)"
        case let .unauthorized(value): "unauthorized: \(value)"
        case .conflict: "repository revision conflict"
        case .expired: "credential or token expired"
        case let .malformed(value): "malformed input: \(value)"
        case let .unavailable(value): "unavailable: \(value)"
        }
    }
}

public struct ProtocolProfile: Codable, Sendable, Equatable {
    public struct CryptoSuite: Codable, Sendable, Equatable {
        public let lthashBytes: Int
        public let lthashHash: String
        public let commitmentHash: String
        public let contentBinding: String
    }

    public let id: String
    public let proposalCommit: String
    public let referenceImplementationCommit: String
    /// The isolated Petrel generator revision which produced the checked-in
    /// wire source. This is intentionally distinct from `petrelCommit`, the
    /// runtime package revision used by normal Swan builds.
    public let petrelGeneratorCommit: String
    public let petrelCommit: String
    public let migrationCompatibility: String
    public let crypto: CryptoSuite
    public let permissionedDataIsEncrypted: Bool
    public let oplogRetention: Int
    public let endpoints: [String]
    public let referenceArchiveSHA256: String?
    public let lexiconManifest: String?
    public let lexiconManifestSHA256: String?

    public init(data: Data) throws {
        do {
            self = try JSONDecoder().decode(Self.self, from: data)
        } catch {
            throw SwanError.invalidProfile(error.localizedDescription)
        }
        guard id.hasPrefix("permissioned-data-"), crypto.lthashBytes == 2048,
              crypto.lthashHash == "BLAKE3-XOF", crypto.commitmentHash == "SHA-256",
              oplogRetention > 0 else {
            throw SwanError.invalidProfile("unsupported profile invariants")
        }
        for commit in [proposalCommit, referenceImplementationCommit, petrelGeneratorCommit, petrelCommit] {
            guard commit.count == 40, commit.utf8.allSatisfy({
                ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
            }) else {
                throw SwanError.invalidProfile("invalid immutable revision pin")
            }
        }
        for checksum in [referenceArchiveSHA256, lexiconManifestSHA256].compactMap({ $0 }) {
            guard checksum.count == 64, checksum.utf8.allSatisfy({
                ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 70) || ($0 >= 97 && $0 <= 102)
            }) else {
                throw SwanError.invalidProfile("invalid SHA-256 pin")
            }
        }
    }

    public static func load(from url: URL) throws -> Self {
        try Self(data: Data(contentsOf: url))
    }

    /// Verifies the checked-in manifest and every pinned permissioned-data
    /// lexicon under an explicitly supplied, ignored reference checkout. This
    /// is intentionally offline once the archive has been fetched.
    public static func verifyPinnedLexicons(profileURL: URL, referenceRoot: URL) throws {
        let profile = try load(from: profileURL)
        guard let manifestName = profile.lexiconManifest,
              let expectedManifestHash = profile.lexiconManifestSHA256 else {
            throw SwanError.invalidProfile("profile has no lexicon manifest pin")
        }
        let manifestURL = profileURL.deletingLastPathComponent().appending(path: manifestName)
        let manifest = try Data(contentsOf: manifestURL)
        guard Hex.encode(SHA256.hash(data: manifest)) == expectedManifestHash else {
            throw SwanError.invalidProfile("lexicon manifest checksum mismatch")
        }
        guard let text = String(data: manifest, encoding: .utf8) else {
            throw SwanError.invalidProfile("lexicon manifest is not UTF-8")
        }
        for line in text.split(whereSeparator: \.isNewline) {
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard fields.count == 2, fields[0].count == 64,
                  !fields[1].hasPrefix("/"), !fields[1].split(separator: "/").contains("..") else {
                throw SwanError.invalidProfile("malformed lexicon manifest entry")
            }
            let expected = String(fields[0])
            let source = referenceRoot.appending(path: "lexicons").appending(path: String(fields[1]))
            guard FileManager.default.fileExists(atPath: source.path),
                  Hex.encode(SHA256.hash(data: try Data(contentsOf: source))) == expected else {
                throw SwanError.invalidProfile("pinned lexicon checksum mismatch")
            }
        }
    }
}

public enum Hex {
    public static func encode(_ data: some Sequence<UInt8>) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

/// Structural validation for a permissioned-data OAuth grant.
///
/// This deliberately validates only the scope envelope shared by the OAuth
/// control/resource planes. The resource domain performs the authoritative
/// comparison of the type, authority, `skey`, action, and collection against
/// the requested operation. Keeping that comparison there means an OAuth
/// token cannot turn a syntactically valid scope for one space into access to
/// another one.
///
/// In particular, the proposal's shorthand `space:<type>` is not accepted at
/// this boundary. Swan has no trusted generic issuer-side context from which
/// to normalize it into an authority, `skey`, and action, so accepting it
/// would make the grant broader than the pinned TypeScript tuple check.
public enum PermissionedSpaceScopeSyntax {
    public static func isQualified(_ scope: String) -> Bool {
        let prefix = "space:"
        guard scope.hasPrefix(prefix),
              (7 ... 4_096).contains(scope.utf8.count),
              scope.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e })
        else {
            return false
        }

        let typeStart = scope.index(scope.startIndex, offsetBy: prefix.count)
        guard let queryStart = scope[typeStart...].firstIndex(of: "?"),
              queryStart > typeStart,
              queryStart < scope.index(before: scope.endIndex)
        else {
            return false
        }

        var keys = Set<String>()
        var requiredKeys = Set<String>()
        var hasAction = false
        var hasManage = false
        for component in scope[scope.index(after: queryStart)...].split(separator: "&", omittingEmptySubsequences: false) {
            let pair = component.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard pair.count == 2,
                  !pair[0].isEmpty,
                  !pair[1].isEmpty,
                  keys.insert(String(pair[0])).inserted
            else {
                return false
            }
            switch pair[0] {
            case "authority", "skey":
                requiredKeys.insert(String(pair[0]))
            case "action":
                hasAction = true
            case "manage":
                hasManage = true
            default:
                break
            }
        }
        // The pinned OAuth scopes distinguish record `action` grants from
        // simple-space lifecycle `manage` grants.  A qualified scope names
        // exactly one of them: accepting neither would make it ambient, and
        // accepting both would leave the resource operation ambiguous.
        return requiredKeys == ["authority", "skey"] && (hasAction != hasManage)
    }
}

/// Canonical raw P-256 signatures used by Swan wire protocols.
///
/// P-256 ECDSA admits a second, equally valid signature for every message:
/// `(r, n - s)`.  AT Protocol's ES256 and Swan's signed space context are
/// serialized as a fixed-width `r || s` value, so accepting both encodings
/// would make those wire values malleable.  This boundary emits only low-S
/// values and rejects high-S values *before* asking Swift Crypto to verify
/// them.
public enum P256WireSignature {
    public static let rawByteCount = 64

    /// Signs a message using Swift Crypto's P-256 implementation, normalizing
    /// the raw `r || s` representation even if the provider changes its
    /// default signature normalization behavior.
    public static func sign(_ message: Data, using key: P256.Signing.PrivateKey) throws -> Data {
        try canonicalize(try key.signature(for: message).rawRepresentation)
    }

    /// Normalizes a structurally valid raw P-256 signature to low-S form.
    /// This is appropriate only for locally produced signatures. Untrusted
    /// inputs must use ``decodeCanonical(_:)`` instead.
    public static func canonicalize(_ rawRepresentation: Data) throws -> Data {
        try validateScalars(rawRepresentation)
        _ = try decode(rawRepresentation)

        let s = Data(rawRepresentation.suffix(32))
        guard compare(s, halfOrder) == .orderedDescending else {
            return rawRepresentation
        }

        var normalized = rawRepresentation
        normalized.replaceSubrange(32 ..< 64, with: subtract(s, from: order))
        return normalized
    }

    /// Rejects non-canonical raw P-256 values before creating the signature
    /// object passed to the cryptographic verifier.
    public static func decodeCanonical(_ rawRepresentation: Data) throws -> P256.Signing.ECDSASignature {
        try validateScalars(rawRepresentation)
        guard compare(Data(rawRepresentation.suffix(32)), halfOrder) != .orderedDescending else {
            throw SwanError.malformed("P-256 signature is not canonical low-S")
        }
        return try decode(rawRepresentation)
    }

    public static func isCanonicalLowS(_ rawRepresentation: Data) -> Bool {
        (try? decodeCanonical(rawRepresentation)) != nil
    }

    private static let order = Data([
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ])

    private static let halfOrder = Data([
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
        0x79, 0xdc, 0xd6, 0x61, 0x7e, 0x31, 0x92, 0xa8,
    ])

    private static func validateScalars(_ rawRepresentation: Data) throws {
        guard rawRepresentation.count == rawByteCount else {
            throw SwanError.malformed("P-256 signature must be 64 bytes")
        }
        let r = Data(rawRepresentation.prefix(32))
        let s = Data(rawRepresentation.suffix(32))
        guard isValidScalar(r), isValidScalar(s) else {
            throw SwanError.malformed("P-256 signature scalar is invalid")
        }
    }

    private static func decode(_ rawRepresentation: Data) throws -> P256.Signing.ECDSASignature {
        do {
            return try P256.Signing.ECDSASignature(rawRepresentation: rawRepresentation)
        } catch {
            throw SwanError.malformed("P-256 signature is malformed")
        }
    }

    private static func isValidScalar(_ scalar: Data) -> Bool {
        scalar.count == 32 && scalar.contains(where: { $0 != 0 }) && compare(scalar, order) == .orderedAscending
    }

    private static func compare(_ lhs: Data, _ rhs: Data) -> ComparisonResult {
        precondition(lhs.count == rhs.count)
        for (left, right) in zip(lhs, rhs) {
            if left < right { return .orderedAscending }
            if left > right { return .orderedDescending }
        }
        return .orderedSame
    }

    /// Computes `minuend - subtrahend`, whose caller has already proven does
    /// not underflow. Both values are fixed-width big-endian scalar bytes.
    private static func subtract(_ subtrahend: Data, from minuend: Data) -> Data {
        precondition(subtrahend.count == 32 && minuend.count == 32)
        let minuendBytes = Array(minuend)
        let subtrahendBytes = Array(subtrahend)
        var result = Array(repeating: UInt8.zero, count: 32)
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            var value = Int(minuendBytes[index]) - Int(subtrahendBytes[index]) - borrow
            if value < 0 {
                value += 256
                borrow = 1
            } else {
                borrow = 0
            }
            result[index] = UInt8(value)
        }
        precondition(borrow == 0)
        return Data(result)
    }
}

public struct Sensitive<Value: CustomStringConvertible & Sendable>: Sendable, CustomStringConvertible {
    public let value: Value
    public init(_ value: Value) { self.value = value }
    public var description: String { "[redacted]" }
}

/// A narrow logging boundary. Callers pass stable identifiers only; payloads,
/// bearer tokens, credentials, and blobs deliberately have no logging API.
public struct SwanLog: Sendable {
    public let logger: Logger

    public init(label: String) {
        logger = Logger(label: label)
    }

    public func event(_ message: Logger.Message, fields: [String: String] = [:]) {
        logger.info(message, metadata: fields.mapValues(Logger.MetadataValue.string))
    }
}
