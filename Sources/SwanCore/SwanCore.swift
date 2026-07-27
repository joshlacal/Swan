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

    /// A pinned upstream implementation gap that Swan deliberately fills for
    /// interop testing. Keeping these in the immutable profile prevents a
    /// locally implemented endpoint from being mistaken for behavior that was
    /// executable in the reference checkout at the pinned SHA.
    public struct IntentionalDivergence: Codable, Sendable, Equatable {
        public let endpoint: String
        public let referenceBehavior: String
        public let swanBehavior: String
    }

    /// A narrowly identified wire/runtime accommodation which is not an XRPC
    /// endpoint divergence. Each entry names the pinned upstream component so
    /// a laboratory exception cannot silently become production policy.
    public struct CompatibilityException: Codable, Sendable, Equatable {
        public let id: String
        public let pinnedComponent: String
        public let referenceBehavior: String
        public let swanBehavior: String
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
    public let intentionalDivergences: [IntentionalDivergence]
    public let compatibilityExceptions: [CompatibilityException]

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
        guard intentionalDivergences.allSatisfy({ endpoints.contains($0.endpoint) }) else {
            throw SwanError.invalidProfile("divergence references an endpoint outside the profile")
        }
        guard compatibilityExceptions.allSatisfy({
            !$0.id.isEmpty && !$0.pinnedComponent.isEmpty
                && !$0.referenceBehavior.isEmpty && !$0.swanBehavior.isEmpty
        }) else {
            throw SwanError.invalidProfile("compatibility exception is incomplete")
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
    /// The issuer-side subset of the qualified scope grammar. Resource
    /// matching deliberately accepts wildcard grants for compatibility with
    /// the pinned implementation; an interactive localhost client must not
    /// mint one of those ambient grants by spelling it into its client ID.
    ///
    /// This is intentionally separate from ``isQualified(_:)``: the latter
    /// is a structural parser used by a resource server, while this function
    /// validates an *issuable* whole-space/record permission tuple.
    public static func isIssuableQualified(_ scope: String) -> Bool {
        guard isQualified(scope),
              let type = strictSpaceType(scope),
              validNSID(type),
              let parameters = strictQualifiedParameters(scope),
              Set(parameters.keys) == ["authority", "skey", "action"] ||
                Set(parameters.keys) == ["authority", "skey", "action", "collection"],
              let authority = parameters["authority"], validDID(authority),
              let skey = parameters["skey"], validRecordKey(skey),
              let action = parameters["action"],
              ["read", "read_self", "create", "update", "delete"].contains(action)
        else {
            return false
        }
        if let collection = parameters["collection"], !validNSID(collection) {
            return false
        }
        // A complete space read is the only collection-free action.  The
        // other actions need a concrete collection so their authorization
        // cannot become a latent whole-repository capability.
        return action == "read" || parameters["collection"] != nil
    }

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

    /// Returns whether an OAuth grant can be exchanged for a whole-space
    /// read delegation.  This is deliberately stricter than a normal record
    /// read: a collection-qualified grant (including `collection=*`) and
    /// `read_self` can never be amplified into a credential which reads every
    /// member repository.
    ///
    /// The broad `atproto` scope remains the one explicit whole-account
    /// grant. Profile-specific grants follow the pinned TypeScript matcher's
    /// tuple comparison: each of type, authority, and skey may name the
    /// requested value or `*`. They must still name exactly `action=read` and
    /// have no collection parameter; extra or duplicate decoded query members
    /// fail closed.
    public static func permitsWholeSpaceRead(
        _ scopes: Set<String>,
        spaceType: String,
        authority: String,
        skey: String
    ) -> Bool {
        guard !spaceType.isEmpty, !authority.isEmpty, !skey.isEmpty else {
            return false
        }
        if scopes.contains("atproto") { return true }

        return scopes.contains { scope in
            guard let type = strictSpaceType(scope),
                  (type == spaceType || type == "*"),
                  let parameters = strictQualifiedParameters(scope),
                  parameters.count == 3,
                  tupleElement(parameters["authority"], matches: authority),
                  tupleElement(parameters["skey"], matches: skey),
                  parameters["action"] == "read" else {
                return false
            }
            return Set(parameters.keys) == ["authority", "skey", "action"]
        }
    }

    /// Returns whether a grant can enumerate the authenticated account's
    /// *local* hosted-space identities for exactly the requested aggregate
    /// dimensions.  Unlike a record read, this cannot safely broaden a
    /// type/authority filter after storage has listed rows: an omitted
    /// request dimension is therefore the literal `*` target and requires a
    /// literal wildcard grant in that dimension.  The `skey` must always be
    /// `*`, so a grant for one concrete space never becomes a membership or
    /// repository inventory capability.
    public static func permitsAggregateSpaceList(
        _ scopes: Set<String>,
        spaceType: String?,
        authority: String?
    ) -> Bool {
        if scopes.contains("atproto") { return true }
        let requestedType = spaceType ?? "*"
        let requestedAuthority = authority ?? "*"
        return scopes.contains { scope in
            guard let grantType = strictSpaceType(scope),
                  let parameters = strictQualifiedParameters(scope),
                  Set(parameters.keys) == ["authority", "skey", "action"],
                  parameters["skey"] == "*",
                  parameters["action"] == "read",
                  aggregateDimension(grantType, covers: requestedType),
                  aggregateDimension(parameters["authority"], covers: requestedAuthority)
            else {
                return false
            }
            return true
        }
    }

    /// The pinned `SpacePermission.matches` compares each tuple element to
    /// its target and treats a literal `*` as an overlap.  `self` is resolved
    /// by the reference authorization server before its runtime matcher sees
    /// a grant; this resource server has no issuance-time authority context,
    /// so it deliberately does not synthesize that resolution here.
    private static func tupleElement(_ grant: String?, matches target: String) -> Bool {
        grant == target || grant == "*"
    }

    /// A wildcard request cannot be satisfied by a concrete grant because
    /// the list route intentionally does not fetch a broad result and then
    /// hide rows. For a concrete requested dimension, the pinned literal
    /// wildcard still covers it.
    private static func aggregateDimension(_ grant: String?, covers requested: String) -> Bool {
        if requested == "*" { return grant == "*" }
        return grant == requested || grant == "*"
    }

    /// This endpoint accepts the positional TypeScript `space:<type>` form.
    /// The request target is an already-validated concrete `SpaceURI`, so an
    /// unmatched type cannot convey authority; only its exact value or the
    /// reference matcher's literal wildcard may satisfy the tuple.
    private static func strictSpaceType(_ scope: String) -> String? {
        let prefix = "space:"
        guard scope.hasPrefix(prefix),
              let queryStart = scope.firstIndex(of: "?"),
              queryStart > scope.index(scope.startIndex, offsetBy: prefix.count) else {
            return nil
        }
        let type = scope[scope.index(scope.startIndex, offsetBy: prefix.count) ..< queryStart]
        guard !type.isEmpty,
              type.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            return nil
        }
        return String(type)
    }

    /// Decodes the already-qualified permissioned-space query with a
    /// singleton-after-decoding rule.  A raw `authority` plus a percent-coded
    /// duplicate such as `%61uthority` must not escape the duplicate-key
    /// check performed by ``isQualified(_:)``.
    private static func strictQualifiedParameters(_ scope: String) -> [String: String]? {
        guard isQualified(scope),
              let queryStart = scope.firstIndex(of: "?") else {
            return nil
        }

        var parameters: [String: String] = [:]
        for component in scope[scope.index(after: queryStart)...]
            .split(separator: "&", omittingEmptySubsequences: false)
        {
            let pair = component.split(
                separator: "=", maxSplits: 1, omittingEmptySubsequences: false
            )
            guard pair.count == 2,
                  let key = strictPercentDecode(pair[0]),
                  let value = strictPercentDecode(pair[1]),
                  !key.isEmpty, !value.isEmpty,
                  parameters[key] == nil else {
                return nil
            }
            parameters[key] = value
        }
        return parameters
    }

    private static func strictPercentDecode(_ value: Substring) -> String? {
        var decoded: [UInt8] = []
        decoded.reserveCapacity(value.utf8.count)
        var iterator = value.utf8.makeIterator()
        while let byte = iterator.next() {
            if byte == UInt8(ascii: "%") {
                guard let high = iterator.next(), let low = iterator.next(),
                      let highValue = hexValue(high), let lowValue = hexValue(low) else {
                    return nil
                }
                decoded.append(highValue << 4 | lowValue)
            } else {
                decoded.append(byte)
            }
        }
        guard let result = String(bytes: decoded, encoding: .utf8),
              result.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            return nil
        }
        return result
    }

    private static func validDID(_ value: String) -> Bool {
        let parts = value.split(separator: ":", omittingEmptySubsequences: false)
        return parts.count >= 3 && parts[0] == "did" && !parts[1].isEmpty &&
            !parts.dropFirst(2).joined(separator: ":").isEmpty &&
            value.utf8.allSatisfy { $0 >= 33 && $0 <= 126 && $0 != 47 && $0 != 63 && $0 != 35 }
    }

    private static func validNSID(_ value: String) -> Bool {
        let labels = value.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 3, value.utf8.count <= 317 else { return false }
        return labels.allSatisfy { label in
            guard !label.isEmpty, label.utf8.count <= 63, label.first?.isLetter == true else { return false }
            return label.utf8.allSatisfy { byte in
                (48 ... 57).contains(byte) || (65 ... 90).contains(byte) ||
                    (97 ... 122).contains(byte) || byte == 45
            }
        }
    }

    private static func validRecordKey(_ value: String) -> Bool {
        guard (1 ... 512).contains(value.utf8.count), value != ".", value != ".." else { return false }
        return value.utf8.allSatisfy { byte in
            (48 ... 57).contains(byte) || (65 ... 90).contains(byte) ||
                (97 ... 122).contains(byte) || [45, 46, 95, 58, 126].contains(byte)
        }
    }

    private static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0") ... UInt8(ascii: "9"):
            byte - UInt8(ascii: "0")
        case UInt8(ascii: "A") ... UInt8(ascii: "F"):
            byte - UInt8(ascii: "A") + 10
        case UInt8(ascii: "a") ... UInt8(ascii: "f"):
            byte - UInt8(ascii: "a") + 10
        default:
            nil
        }
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
