import Foundation

/// Durable lifecycle states for an account control plane. Only `active`
/// authorizes an account; every other known or future state fails closed.
public enum AccountControlStatus: Codable, Sendable, Equatable {
    case active
    case deactivated
    case deleted
    case takendown
    case suspended
    case desynchronized
    case throttled
    case unknown(String)

    public init(rawValue: String) throws {
        guard Self.isCanonicalToken(rawValue) else {
            throw AccountControlStoreError.invalidStatus
        }
        self = switch rawValue {
        case "active": .active
        case "deactivated": .deactivated
        case "deleted": .deleted
        case "takendown": .takendown
        case "suspended": .suspended
        case "desynchronized": .desynchronized
        case "throttled": .throttled
        default: .unknown(rawValue)
        }
    }

    public var rawValue: String {
        switch self {
        case .active: "active"
        case .deactivated: "deactivated"
        case .deleted: "deleted"
        case .takendown: "takendown"
        case .suspended: "suspended"
        case .desynchronized: "desynchronized"
        case .throttled: "throttled"
        case let .unknown(value): value
        }
    }

    public var authorizesAccount: Bool { self == .active }

    /// A public enum case can be constructed directly, so a syntactically
    /// valid `.unknown("active")` must not be accepted as a distinct status
    /// which serializes to the authorizing `active` token. Every durable
    /// boundary requires this exact enum/raw-value round trip.
    public var isCanonicalValue: Bool {
        (try? AccountControlStatus(rawValue: rawValue)) == self
    }

    public init(from decoder: any Decoder) throws {
        try self.init(rawValue: decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        guard isCanonicalValue else {
            throw AccountControlStoreError.invalidStatus
        }
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    public static func isCanonicalToken(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 64,
              let first = value.utf8.first,
              (97 ... 122).contains(first) else {
            return false
        }
        return value.utf8.allSatisfy {
            (97 ... 122).contains($0)
                || (48 ... 57).contains($0)
                || $0 == 45
                || $0 == 95
        }
    }
}

/// The only legal account lifecycle edges. This policy is intentionally a
/// value, rather than allowing a storage caller to write arbitrary strings.
/// Operational moderation states remain fail-closed, but an operator may move
/// a non-deleted account to `active` or `deactivated` after remediation.
public struct AccountStatusTransitionPolicy: Sendable, Equatable {
    public static let standard = AccountStatusTransitionPolicy()

    public init() {}

    public func permits(from source: AccountControlStatus, to destination: AccountControlStatus) -> Bool {
        guard source.isCanonicalValue, destination.isCanonicalValue,
              source != .deleted else { return false }
        if source == destination { return true }
        switch destination {
        case .active, .deactivated, .deleted:
            return true
        case .takendown, .suspended, .desynchronized, .throttled, .unknown:
            return true
        }
    }

    public func validate(from source: AccountControlStatus, to destination: AccountControlStatus) throws {
        guard source.isCanonicalValue, destination.isCanonicalValue else {
            throw AccountControlStoreError.invalidStatus
        }
        guard permits(from: source, to: destination) else {
            throw AccountControlStoreError.invalidTransition
        }
    }
}

/// A durable reference to key material that is held by an external key store.
/// It deliberately contains only a purpose, generation, and deterministic
/// identifier. Private key bytes and export envelopes are not representable.
public struct AccountControlKeyReference: Codable, Sendable, Equatable, Hashable {
    public enum Purpose: String, Codable, Sendable, CaseIterable {
        case signing = "account-signing"
        case rotation = "account-rotation"
    }

    public let purpose: Purpose
    public let generation: UInt64
    public let reference: String

    public init(purpose: Purpose, generation: UInt64, reference: String? = nil) throws {
        guard generation > 0, generation <= UInt64(Int.max) else {
            throw AccountControlStoreError.invalidInput
        }
        let expected = "\(purpose.rawValue):\(generation)"
        guard reference == nil || reference == expected else {
            throw AccountControlStoreError.invalidInput
        }
        self.purpose = purpose
        self.generation = generation
        self.reference = expected
    }

    /// Codable synthesis would assign stored properties directly and bypass
    /// the deterministic-reference invariant in `init`. Keep it explicit so
    /// decoded input cannot smuggle arbitrary text (including key material)
    /// into a later control-store write.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            purpose: container.decode(Purpose.self, forKey: .purpose),
            generation: container.decode(UInt64.self, forKey: .generation),
            reference: container.decode(String.self, forKey: .reference)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        guard isCanonicalValue else { throw AccountControlStoreError.invalidInput }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(purpose, forKey: .purpose)
        try container.encode(generation, forKey: .generation)
        try container.encode(reference, forKey: .reference)
    }

    /// Mirrors the initializer check for callers receiving a value through an
    /// opaque boundary. This is repeated by registration and SQLite writes as
    /// defense in depth.
    public var isCanonicalValue: Bool {
        (try? AccountControlKeyReference(
            purpose: purpose,
            generation: generation,
            reference: reference
        )) == self
    }

    private enum CodingKeys: String, CodingKey {
        case purpose
        case generation
        case reference
    }
}

/// Optional operator-declared facts retained after a logical deletion. The
/// metadata is intentionally limited to a timestamp and bounded explanation;
/// data/key erasure is a separate explicit operation outside this control API.
public struct AccountTombstoneMetadata: Codable, Sendable, Equatable {
    public let declaredAt: Date
    public let reason: String?

    public init(declaredAt: Date = Date(), reason: String? = nil) throws {
        guard AccountControlMetadata.isControlDate(declaredAt),
              reason.map(AccountControlMetadata.isSafeText) ?? true else {
            throw AccountControlStoreError.invalidInput
        }
        self.declaredAt = declaredAt
        self.reason = reason
    }

    /// Codable synthesis would assign stored properties directly and bypass
    /// the bounded operator-text and timestamp boundary above.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            declaredAt: container.decode(Date.self, forKey: .declaredAt),
            reason: container.decodeIfPresent(String.self, forKey: .reason)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        guard isCanonicalValue else { throw AccountControlStoreError.invalidInput }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(declaredAt, forKey: .declaredAt)
        try container.encodeIfPresent(reason, forKey: .reason)
    }

    /// Keeps decoded or opaque-boundary values within the same operator-text
    /// and timestamp constraints as the initializer.
    public var isCanonicalValue: Bool {
        AccountControlMetadata.isControlDate(declaredAt)
            && (reason.map(AccountControlMetadata.isSafeText) ?? true)
    }

    private enum CodingKeys: String, CodingKey {
        case declaredAt
        case reason
    }
}

/// A declaration that an export manifest was prepared elsewhere. `reference`
/// is a canonical SHA-256 digest of that manifest (`sha256:` followed by 64
/// lowercase hexadecimal characters), never an export payload, key, recovery
/// phrase, or repository data. This is the only export value permitted in
/// `control.sqlite`.
public struct AccountExportMetadata: Codable, Sendable, Equatable {
    public let declaredAt: Date
    public let reference: String

    public init(declaredAt: Date = Date(), reference: String) throws {
        guard AccountControlMetadata.isControlDate(declaredAt),
              Self.isCanonicalManifestDigestReference(reference) else {
            throw AccountControlStoreError.invalidInput
        }
        self.declaredAt = declaredAt
        self.reference = reference
    }

    /// Codable synthesis would otherwise permit an arbitrary export string to
    /// bypass the digest-only initializer and be written by a later lifecycle
    /// transition.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            declaredAt: container.decode(Date.self, forKey: .declaredAt),
            reference: container.decode(String.self, forKey: .reference)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        guard isCanonicalValue else { throw AccountControlStoreError.invalidInput }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(declaredAt, forKey: .declaredAt)
        try container.encode(reference, forKey: .reference)
    }

    /// A nonrecoverable reference to an externally stored export manifest.
    /// This is deliberately stricter than general safe text so no secret-like
    /// payload can use an export declaration as a persistence channel.
    public static func isCanonicalManifestDigestReference(_ value: String) -> Bool {
        guard value.utf8.count == 71, value.hasPrefix("sha256:") else { return false }
        return value.utf8.dropFirst(7).allSatisfy {
            (48 ... 57).contains($0) || (97 ... 102).contains($0)
        }
    }

    /// Mirrors the initializer for values that crossed an opaque boundary.
    public var isCanonicalValue: Bool {
        AccountControlMetadata.isControlDate(declaredAt)
            && Self.isCanonicalManifestDigestReference(reference)
    }

    private enum CodingKeys: String, CodingKey {
        case declaredAt
        case reference
    }
}

/// A declaration applied alongside a lifecycle transition. Keeping it
/// explicit prevents status changes from being mistaken for physical deletion.
public struct AccountLifecycleDeclaration: Sendable, Equatable {
    public let tombstone: AccountTombstoneMetadata?
    public let export: AccountExportMetadata?

    public init(
        tombstone: AccountTombstoneMetadata? = nil,
        export: AccountExportMetadata? = nil
    ) {
        self.tombstone = tombstone
        self.export = export
    }
}

public enum AccountCredentialState: String, Codable, Sendable, Equatable {
    case missing
    case configured
}

/// Registry/control information returned to ordinary callers. The password
/// verifier intentionally does not appear here; callers must use the narrow
/// credential method on `AccountControlStore` when authentication is needed.
public struct AccountControlAccount: Sendable, Equatable {
    public let did: String
    public let canonicalHandle: String
    public let status: AccountControlStatus
    public let createdAt: Date
    public let updatedAt: Date
    public let credentialState: AccountCredentialState
    public let signingKey: AccountControlKeyReference?
    public let rotationKey: AccountControlKeyReference?
    /// Immutable public commitment to the verified empty public repository
    /// genesis which authorized this local registration. Legacy rows may lack
    /// it; callers requiring local-install provenance must reject that case.
    public let publicGenesisCommitCID: String?
    public let tombstone: AccountTombstoneMetadata?
    public let export: AccountExportMetadata?

    public init(
        did: String,
        canonicalHandle: String,
        status: AccountControlStatus,
        createdAt: Date,
        updatedAt: Date,
        credentialState: AccountCredentialState,
        signingKey: AccountControlKeyReference?,
        rotationKey: AccountControlKeyReference?,
        publicGenesisCommitCID: String? = nil,
        tombstone: AccountTombstoneMetadata? = nil,
        export: AccountExportMetadata? = nil
    ) throws {
        switch (signingKey, rotationKey) {
        case (.none, .none):
            break
        case let (.some(signing), .some(rotation)) where signing.generation == rotation.generation:
            break
        default:
            throw AccountControlStoreError.invalidInput
        }
        guard status.isCanonicalValue else {
            throw AccountControlStoreError.invalidStatus
        }
        guard AccountControlMetadata.isDID(did),
              AccountControlMetadata.isCanonicalHandle(canonicalHandle),
              signingKey?.isCanonicalValue ?? true,
              rotationKey?.isCanonicalValue ?? true,
              signingKey?.purpose == .signing || signingKey == nil,
              rotationKey?.purpose == .rotation || rotationKey == nil,
              publicGenesisCommitCID.map(AccountControlMetadata.isPublicGenesisCommitCID) ?? true,
              tombstone?.isCanonicalValue ?? true,
              export?.isCanonicalValue ?? true else {
            throw AccountControlStoreError.invalidInput
        }
        self.did = did
        self.canonicalHandle = canonicalHandle
        self.status = status
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.credentialState = credentialState
        self.signingKey = signingKey
        self.rotationKey = rotationKey
        self.publicGenesisCommitCID = publicGenesisCommitCID
        self.tombstone = tombstone
        self.export = export
    }
}

/// The exact atomic input for a new account. A verifier is stored atomically
/// with its registry entry, but it is only readable through `credential`.
public struct AccountControlRegistration: Sendable {
    public let did: String
    public let canonicalHandle: String
    public let passwordVerifier: String
    public let signingKey: AccountControlKeyReference
    public let rotationKey: AccountControlKeyReference
    /// Optional only to keep legacy non-local registration paths explicit.
    /// `LocalAccountProvisioner` always supplies this verified public CID.
    public let publicGenesisCommitCID: String?
    public let createdAt: Date

    public init(
        did: String,
        canonicalHandle: String,
        passwordVerifier: String,
        signingKey: AccountControlKeyReference,
        rotationKey: AccountControlKeyReference,
        publicGenesisCommitCID: String? = nil,
        createdAt: Date = Date()
    ) throws {
        guard signingKey.generation == rotationKey.generation,
              AccountControlMetadata.isDID(did),
              AccountControlMetadata.isCanonicalHandle(canonicalHandle),
              AccountControlMetadata.isVerifier(passwordVerifier),
              signingKey.isCanonicalValue,
              rotationKey.isCanonicalValue,
              signingKey.purpose == .signing,
              rotationKey.purpose == .rotation,
              publicGenesisCommitCID.map(AccountControlMetadata.isPublicGenesisCommitCID) ?? true else {
            throw AccountControlStoreError.invalidInput
        }
        self.did = did
        self.canonicalHandle = canonicalHandle
        self.passwordVerifier = passwordVerifier
        self.signingKey = signingKey
        self.rotationKey = rotationKey
        self.publicGenesisCommitCID = publicGenesisCommitCID
        self.createdAt = createdAt
    }
}

/// Authentication-only credential material. It is deliberately separate from
/// `AccountControlAccount` so ordinary DID/handle lookups cannot leak it.
public struct AccountControlCredential: Sendable {
    public let did: String
    public let verifier: String
    public let updatedAt: Date

    public init(did: String, verifier: String, updatedAt: Date) throws {
        guard AccountControlMetadata.isDID(did),
              AccountControlMetadata.isVerifier(verifier) else {
            throw AccountControlStoreError.invalidInput
        }
        self.did = did
        self.verifier = verifier
        self.updatedAt = updatedAt
    }
}

public enum AccountCredentialReplacement: Sendable, Equatable {
    case replaced
    /// Another successful authentication already replaced this verifier. The
    /// caller must not overwrite it with a stale rehash result.
    case unchanged
}

/// Result of the storage transaction which is the linearization point between
/// a verified password and an account becoming authenticated. It intentionally
/// contains no verifier.
public struct AccountAuthenticationFinalization: Sendable, Equatable {
    public let account: AccountControlAccount
    public let credentialWasReplaced: Bool

    public init(account: AccountControlAccount, credentialWasReplaced: Bool) {
        self.account = account
        self.credentialWasReplaced = credentialWasReplaced
    }
}

public enum AccountControlStoreError: Error, Sendable, Equatable {
    case notFound
    case duplicateDID
    case duplicateHandle
    case invalidInput
    case invalidStatus
    case invalidTransition
    case malformedRecord
    case unavailable
}

/// Domain-shaped durable account-control storage. It contains registry,
/// lifecycle, verifier, key-reference, tombstone, and export-declaration
/// facts only. Repository contents and private key material belong elsewhere.
public protocol AccountControlStore: Sendable {
    func createAccount(_ registration: AccountControlRegistration) async throws -> AccountControlAccount
    func account(did: String) async throws -> AccountControlAccount?
    func account(canonicalHandle: String) async throws -> AccountControlAccount?
    /// Lists only canonical, active account DIDs in binary lexical order.
    ///
    /// This is a trusted startup inventory, not a request-time account
    /// discovery surface. Implementations must not load credential, key,
    /// handle, export, or repository fields to answer it.
    func activeAccountDIDs() async throws -> [String]
    func credential(did: String) async throws -> AccountControlCredential?
    func replaceCredential(
        did: String,
        expectedVerifier: String,
        replacementVerifier: String,
        now: Date
    ) async throws -> AccountCredentialReplacement
    /// Atomically verifies that the account is still active and the verified
    /// credential remains current, optionally upgrades its verifier, and
    /// returns the active account snapshot. `nil` is a fail-closed result.
    func finalizeAuthentication(
        did: String,
        expectedVerifier: String,
        replacementVerifier: String?,
        now: Date
    ) async throws -> AccountAuthenticationFinalization?
    func transitionStatus(
        did: String,
        to status: AccountControlStatus,
        declaration: AccountLifecycleDeclaration,
        now: Date
    ) async throws -> AccountControlAccount
}

public extension AccountControlStore {
    /// Stores that predate the startup inventory capability must fail closed:
    /// a service must never infer an account-database location by probing a
    /// request's authority DID.
    func activeAccountDIDs() async throws -> [String] {
        throw AccountControlStoreError.unavailable
    }
}

/// Strict lexical account identifiers shared by durable adapters that cannot
/// depend on the higher-level account service. `SwanAccounts.AccountIdentifiers`
/// validates the same DID and handle forms before public service calls.
public enum AccountControlIdentifiers {
    public static func isDID(_ value: String) -> Bool {
        AccountControlMetadata.isDID(value)
    }

    public static func isCanonicalHandle(_ value: String) -> Bool {
        AccountControlMetadata.isCanonicalHandle(value)
    }

    public static func isPublicGenesisCommitCID(_ value: String) -> Bool {
        AccountControlMetadata.isPublicGenesisCommitCID(value)
    }
}

enum AccountControlMetadata {
    static func isIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 2_048 &&
            value.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7e }
    }

    static func isSafeText(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 4_096 &&
            value.unicodeScalars.allSatisfy {
                !CharacterSet.controlCharacters.contains($0)
            }
    }

    static func isControlDate(_ value: Date) -> Bool {
        let seconds = value.timeIntervalSince1970
        let microseconds = seconds * 1_000_000
        return seconds.isFinite && seconds >= 0 &&
            microseconds.isFinite && microseconds <= Double(Int.max)
    }

    /// A public repository commit CID is Swan's canonical CIDv1 dag-cbor
    /// SHA-256 base32 representation. Full CAR/CID verification is owned by
    /// SwanPublicRepository; this control-plane boundary prevents arbitrary
    /// text from becoming a provenance marker.
    static func isPublicGenesisCommitCID(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        let alphabet = Set("abcdefghijklmnopqrstuvwxyz234567".utf8)
        return bytes.count == 59
            && value.hasPrefix("bafyrei")
            && bytes.allSatisfy(alphabet.contains)
    }

    static func isVerifier(_ value: String) -> Bool {
        value.hasPrefix("$argon2id$v=19$") && value.utf8.count <= 1_024 &&
            value.utf8.allSatisfy { $0 >= 0x20 && $0 <= 0x7e }
    }

    /// Storage cannot depend on SwanAccounts without a cycle, so it retains
    /// the same strict lexical boundary as `AccountIdentifiers`. The account
    /// service repeats validation before every store call as its public-edge
    /// guard; this second check protects direct store consumers and migration
    /// decoders as well.
    static func isDID(_ did: String) -> Bool {
        let bytes = Array(did.utf8)
        guard bytes.count <= 2_048,
              bytes.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            return false
        }
        let components = did.split(separator: ":", omittingEmptySubsequences: false)
        guard components.count >= 3, components[0] == "did" else { return false }
        switch components[1] {
        case "plc":
            return components.count == 3 && components[2].utf8.count == 24 &&
                components[2].utf8.allSatisfy {
                    ($0 >= 97 && $0 <= 122) || ($0 >= 50 && $0 <= 55)
                }
        case "web":
            return isWebDID(components)
        default:
            return false
        }
    }

    static func isCanonicalHandle(_ handle: String) -> Bool {
        let bytes = Array(handle.utf8)
        guard !bytes.isEmpty, bytes.count <= 253,
              bytes.allSatisfy({
                  ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 46
              }) else {
            return false
        }
        return isCanonicalDNSName(handle)
    }

    private static func isWebDID(_ components: [Substring]) -> Bool {
        let authorityParts = String(components[2]).components(separatedBy: "%3A")
        guard (1 ... 2).contains(authorityParts.count),
              !authorityParts[0].contains("%"),
              isCanonicalDNSName(authorityParts[0]) else {
            return false
        }
        if authorityParts.count == 2 {
            let port = authorityParts[1]
            guard !port.isEmpty, !port.contains("%"),
                  port.count == 1 || port.first != "0",
                  let number = UInt16(port), number > 0 else {
                return false
            }
        }
        return components.dropFirst(3).allSatisfy(isCanonicalWebPathSegment)
    }

    private static func isCanonicalDNSName(_ name: String) -> Bool {
        guard name.utf8.count <= 253,
              name.utf8.allSatisfy({
                  ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 46
              }) else {
            return false
        }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        let finalLabelStartsWithASCIIAlpha = labels.last?.utf8.first.map {
            ($0 >= 97 && $0 <= 122)
        } == true
        return labels.count >= 2 && labels.allSatisfy {
            !$0.isEmpty && $0.utf8.count <= 63 && $0.first != "-" && $0.last != "-"
        } && finalLabelStartsWithASCIIAlpha
    }

    private static func isCanonicalWebPathSegment(_ segment: Substring) -> Bool {
        guard !segment.isEmpty, segment != ".", segment != ".." else { return false }
        let bytes = Array(segment.utf8)
        var index = 0
        while index < bytes.count {
            if bytes[index] == 0x25 {
                guard index + 2 < bytes.count,
                      isUppercaseHex(bytes[index + 1]), isUppercaseHex(bytes[index + 2]),
                      let decoded = decodedHex(bytes[index + 1], bytes[index + 2]),
                      !isUnreserved(decoded) else { return false }
                index += 3
            } else {
                guard isUnreserved(bytes[index]) else { return false }
                index += 1
            }
        }
        return true
    }

    private static func isUnreserved(_ byte: UInt8) -> Bool {
        (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122) ||
            (byte >= 48 && byte <= 57) || byte == 45 || byte == 46 || byte == 95 || byte == 126
    }

    private static func isUppercaseHex(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 70)
    }

    private static func decodedHex(_ first: UInt8, _ second: UInt8) -> UInt8? {
        func value(_ byte: UInt8) -> UInt8? {
            if byte >= 48, byte <= 57 { return byte - 48 }
            if byte >= 65, byte <= 70 { return byte - 55 }
            return nil
        }
        guard let high = value(first), let low = value(second) else { return nil }
        return high * 16 + low
    }
}
