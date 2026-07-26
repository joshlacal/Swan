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
