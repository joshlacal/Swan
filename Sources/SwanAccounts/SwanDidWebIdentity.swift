import Crypto
import Foundation
#if canImport(CoreFoundation)
import CoreFoundation
#endif
import SwanCore
import SwanStorage

/// The public signing material Swan reserves for one did:web claim. The key is
/// a binding check; it is never used as an assertion key for the external DID.
public struct SwanReservedSigningKey: Codable, Sendable, Equatable {
    public let keyID: String
    public let keyType: String
    public let publicKey: Data

    public init(keyID: String, keyType: String, publicKey: Data) throws {
        guard !keyID.isEmpty, !keyType.isEmpty,
              publicKey.count == 32 || publicKey.count == 33 else {
            throw SwanError.invalidIdentifier("reserved signing key")
        }
        self.keyID = keyID
        self.keyType = keyType
        self.publicKey = publicKey
    }
}

public struct SwanDidWebClaimReservation: Codable, Sendable, Equatable {
    public let requestID: String
    public let accountDID: String?
    public let targetDID: String
    public let handle: String
    public let key: SwanReservedSigningKey
    public let nonce: Data
    public let expiresAt: Date
    public let claimBytes: Data
    public let claimReceiptDigest: Data
    public let claimServiceEndpoint: String

    public init(
        requestID: String, accountDID: String?, targetDID: String, handle: String,
        key: SwanReservedSigningKey, nonce: Data, expiresAt: Date,
        claimBytes: Data, claimReceiptDigest: Data, claimServiceEndpoint: String
    ) throws {
        guard !requestID.isEmpty, nonce.count == 32,
              claimReceiptDigest.count == 32, !claimBytes.isEmpty,
              URL(string: claimServiceEndpoint)?.scheme == "https" else {
            throw SwanError.invalidIdentifier("did:web claim reservation")
        }
        self.requestID = requestID
        self.accountDID = accountDID
        self.targetDID = targetDID
        self.handle = handle
        self.key = key
        self.nonce = nonce
        self.expiresAt = expiresAt
        self.claimBytes = claimBytes
        self.claimReceiptDigest = claimReceiptDigest
        self.claimServiceEndpoint = claimServiceEndpoint
    }
}

public protocol SwanSigningKeyReservationService: Sendable {
    func reserveSigningKey(requestID: String) async throws -> (key: SwanReservedSigningKey, nonce: Data)
    func consumeSigningKeyReservation(requestID: String) async throws
}

public protocol SwanSigningKeyProviding: Sendable {
    func configuredSigningKey() async throws -> SwanReservedSigningKey
}

public protocol SwanContextualSigningKeyReservationService: SwanDurableSigningKeyReservationService {
    func reserveSigningKey(requestID: String, accountDID: String?, targetDID: String, handle: String,
                           expiresAt: Date, pdsURL: String, publicURL: String,
                           signingKey: SwanSigningKeyMaterial) async throws -> (key: SwanReservedSigningKey, nonce: Data)
}

/// Production composition adapter. SQLite owns the durable tuple and this
/// adapter injects the configured public material; it never generates a key.
public struct SwanDurableSigningKeyReservationAdapter: SwanContextualSigningKeyReservationService, SwanSigningKeyProviding {
    private let store: any SwanDidWebReservationStore
    private let provider: any SwanSigningKeyProviding

    public init(store: any SwanDidWebReservationStore, provider: any SwanSigningKeyProviding) {
        self.store = store; self.provider = provider
    }
    public func configuredSigningKey() async throws -> SwanReservedSigningKey { try await provider.configuredSigningKey() }
    public func reserveSigningKey(requestID: String, accountDID: String?, targetDID: String, handle: String,
                                 expiresAt: Date, pdsURL: String, publicURL: String,
                                 signingKey: SwanSigningKeyMaterial) async throws -> (key: SwanReservedSigningKey, nonce: Data) {
        let row = try await store.reserveDidWebSigningKey(requestID: requestID, accountDID: accountDID,
                                                          targetDID: targetDID, handle: handle, expiresAt: expiresAt,
                                                          pdsURL: pdsURL, publicURL: publicURL, signingKey: signingKey)
        return (try SwanReservedSigningKey(keyID: row.keyID, keyType: row.keyType, publicKey: row.publicKey), row.nonce)
    }
    public func reserveSigningKey(requestID: String) async throws -> (key: SwanReservedSigningKey, nonce: Data) {
        let key = try await provider.configuredSigningKey()
        let material = try SwanSigningKeyMaterial(keyID: key.keyID, keyType: key.keyType, publicKey: key.publicKey)
        // This legacy entry point cannot bind the full DID tuple. Refuse it
        // rather than persisting placeholder identity material.
        _ = material
        throw SwanError.unavailable("contextual did:web reservation required")
    }
    public func consumeSigningKeyReservation(requestID: String) async throws { try await markReservationCommitted(requestID: requestID) }
    public func issuedReservation(requestID: String) async throws -> SwanDidWebClaimReservation? {
        guard let row = try await store.loadDidWebSigningReservation(requestID: requestID), !row.claimBytes.isEmpty else { return nil }
        return try claim(row)
    }
    public func issuedReservation(nonce: Data) async throws -> SwanDidWebClaimReservation? {
        guard let row = try await store.loadDidWebSigningReservation(nonce: nonce),
              row.state == .issued, !row.claimBytes.isEmpty else { return nil }
        return try claim(row)
    }
    public func committedReservation(accountDID: String) async throws -> SwanDidWebClaimReservation? {
        guard let row = try await store.committedDidWebSigningReservation(accountDID: accountDID) else { return nil }
        return try claim(row)
    }
    public func recordIssuedReservation(_ reservation: SwanDidWebClaimReservation) async throws {
        guard let existing = try await store.loadDidWebSigningReservation(requestID: reservation.requestID) else {
            throw SwanError.invalidIdentifier("unknown did:web reservation")
        }
        try await store.persistDidWebSigningReservation(SwanPersistedDidWebReservation(
            requestID: reservation.requestID, accountDID: reservation.accountDID, targetDID: reservation.targetDID,
            handle: reservation.handle, keyID: reservation.key.keyID, keyType: reservation.key.keyType,
            publicKey: reservation.key.publicKey, nonce: reservation.nonce, expiresAt: reservation.expiresAt,
            claimBytes: reservation.claimBytes, claimReceiptDigest: reservation.claimReceiptDigest,
            pdsURL: existing.pdsURL, claimServiceEndpoint: reservation.claimServiceEndpoint, state: existing.state))
    }
    public func markReservationCommitted(requestID: String) async throws { try await store.markDidWebSigningReservationCommitted(requestID: requestID) }
    public func releaseSigningKeyReservation(requestID: String) async throws { try await store.releaseDidWebSigningReservation(requestID: requestID) }
    public func repairCommittedReservation(requestID: String) async throws { try await store.repairDidWebSigningReservation(requestID: requestID) }
    private func claim(_ row: SwanPersistedDidWebReservation) throws -> SwanDidWebClaimReservation {
        try SwanDidWebClaimReservation(requestID: row.requestID, accountDID: row.accountDID, targetDID: row.targetDID,
                                       handle: row.handle, key: try SwanReservedSigningKey(keyID: row.keyID, keyType: row.keyType, publicKey: row.publicKey),
                                       nonce: row.nonce, expiresAt: row.expiresAt, claimBytes: row.claimBytes,
                                       claimReceiptDigest: row.claimReceiptDigest, claimServiceEndpoint: row.claimServiceEndpoint)
    }
}

/// Durable providers implement this extension to make the reservation tuple
/// authoritative across retries and process crashes. The base protocol stays
/// source-compatible with existing callers and test doubles.
public protocol SwanDurableSigningKeyReservationService: SwanSigningKeyReservationService {
    func issuedReservation(requestID: String) async throws -> SwanDidWebClaimReservation?
    func issuedReservation(nonce: Data) async throws -> SwanDidWebClaimReservation?
    func committedReservation(accountDID: String) async throws -> SwanDidWebClaimReservation?
    func recordIssuedReservation(_ reservation: SwanDidWebClaimReservation) async throws
    func markReservationCommitted(requestID: String) async throws
    func releaseSigningKeyReservation(requestID: String) async throws
    func repairCommittedReservation(requestID: String) async throws
}

public struct SwanDidWebReplacementAuthorization: Sendable, Equatable {
    public enum MFAStrength: String, Codable, Sendable { case phishingResistant }
    public let accountDID: String
    public let sessionAccountDID: String
    public let sessionID: String
    public let stepUpAt: Date
    public let stepUpReceiptDigest: Data
    public let mfaStrength: MFAStrength

    public init(accountDID: String, sessionAccountDID: String, sessionID: String,
                stepUpAt: Date, stepUpReceiptDigest: Data,
                mfaStrength: MFAStrength) throws {
        guard !sessionID.isEmpty, stepUpReceiptDigest.count == 32 else {
            throw SwanError.invalidIdentifier("did:web replacement authorization")
        }
        self.accountDID = accountDID
        self.sessionAccountDID = sessionAccountDID
        self.sessionID = sessionID
        self.stepUpAt = stepUpAt
        self.stepUpReceiptDigest = stepUpReceiptDigest
        self.mfaStrength = mfaStrength
    }
}

public enum SwanIdentityStepUpOperation: String, Sendable { case replace, remove }
public protocol SwanStepUpReceiptConsumptionStore: Sendable {
    func consume(sessionID: String, accountDID: String, operation: SwanIdentityStepUpOperation,
                 receiptDigest: Data, verifiedAt: Date, expiresAt: Date, now: Date) async throws
}

/// Dependency inversion adapter used by production composition: SQLite (or
/// another durable store) owns the compare-and-set, while Accounts owns the
/// typed operation vocabulary.
public struct SwanDurableStepUpReceiptConsumer: SwanStepUpReceiptConsumptionStore {
    private let store: any SwanIdentityStepUpReceiptStore
    public init(store: any SwanIdentityStepUpReceiptStore) { self.store = store }
    public func consume(sessionID: String, accountDID: String, operation: SwanIdentityStepUpOperation,
                        receiptDigest: Data, verifiedAt: Date, expiresAt: Date, now: Date) async throws {
        try await store.consumeIdentityStepUpReceipt(sessionID: sessionID, accountDID: accountDID,
                                                     operation: operation.rawValue, mfaStrength: "phishingResistant",
                                                     verifiedAt: verifiedAt, expiresAt: expiresAt,
                                                     receiptDigest: receiptDigest, now: now)
    }
}

public actor InMemorySwanStepUpReceiptConsumptionStore: SwanStepUpReceiptConsumptionStore {
    private var consumed: Set<Data> = []
    public init() {}
    public func consume(sessionID: String, accountDID: String, operation: SwanIdentityStepUpOperation, receiptDigest: Data, verifiedAt: Date, expiresAt: Date, now: Date) async throws {
        guard !sessionID.isEmpty, !accountDID.isEmpty, receiptDigest.count == 32,
              verifiedAt <= now, now < expiresAt else { throw SwanError.unauthorized("invalid step-up receipt") }
        guard consumed.insert(receiptDigest).inserted else { throw SwanError.conflict(expected: 0, actual: 1) }
        _ = operation
    }
}

public protocol SwanDidWebReplacementAuthorizing: Sendable {
    func authorize(_ authorization: SwanDidWebReplacementAuthorization, now: Date) async throws -> Bool
}

/// Network boundary for the claim and revalidation paths. Production callers
/// provide the existing peer-pinned DID fetcher; tests can inject a fixture
/// without weakening the resolver policy.
public protocol SwanDidWebDocumentFetching: Sendable {
    func documentJSON(forDID did: String) async throws -> Data
}

/// Small durable-boundary-compatible fixture and default process-local
/// provider. Production deployments may replace it with a key-store-backed
/// implementation without changing claim validation or transaction ordering.
public actor InMemorySwanSigningKeyReservationService: SwanDurableSigningKeyReservationService {
    private enum State { case issued, committed, released }
    private var reservations: [String: (SwanReservedSigningKey, Data, State, SwanDidWebClaimReservation?)] = [:]
    private var failNextCommit = false

    public init() {}

    public func reserveSigningKey(requestID: String) async throws -> (key: SwanReservedSigningKey, nonce: Data) {
        guard !requestID.isEmpty else { throw SwanError.invalidIdentifier("claim request") }
        if let existing = reservations[requestID], existing.2 != .released {
            return (existing.0, existing.1)
        }
        var generator = SystemRandomNumberGenerator()
        let bytes = Data((0 ..< 32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
        let key = try SwanReservedSigningKey(keyID: "#atproto", keyType: "Multikey", publicKey: bytes)
        let nonce = Data((0 ..< 32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
        reservations[requestID] = (key, nonce, .issued, nil)
        return (key, nonce)
    }

    public func consumeSigningKeyReservation(requestID: String) async throws {
        try await markReservationCommitted(requestID: requestID)
    }

    public func issuedReservation(requestID: String) async throws -> SwanDidWebClaimReservation? {
        guard let value = reservations[requestID], value.2 != .released else { return nil }
        return value.3
    }

    public func issuedReservation(nonce: Data) async throws -> SwanDidWebClaimReservation? {
        guard let value = reservations.values.first(where: { $0.1 == nonce }),
              value.2 == .issued else { return nil }
        return value.3
    }

    public func committedReservation(accountDID: String) async throws -> SwanDidWebClaimReservation? {
        for value in reservations.values {
            if value.2 == .committed, let reservation = value.3,
               reservation.accountDID == accountDID {
                return reservation
            }
        }
        return nil
    }

    public func recordIssuedReservation(_ reservation: SwanDidWebClaimReservation) async throws {
        guard let value = reservations[reservation.requestID], value.2 != .released,
              value.0 == reservation.key, value.1 == reservation.nonce else {
            throw SwanError.unauthorized("reservation tuple mismatch")
        }
        if let existing = value.3 {
            guard existing == reservation else { throw SwanError.conflict(expected: 0, actual: 1) }
            return
        }
        reservations[reservation.requestID] = (value.0, value.1, value.2, reservation)
    }

    public func markReservationCommitted(requestID: String) async throws {
        if failNextCommit { failNextCommit = false; throw SwanError.unavailable("provider finalization failure") }
        guard let value = reservations[requestID], value.2 != .released else {
            throw SwanError.invalidIdentifier("unknown claim reservation")
        }
        reservations[requestID] = (value.0, value.1, .committed, value.3)
    }

    public func releaseSigningKeyReservation(requestID: String) async throws {
        guard let value = reservations[requestID] else { return }
        guard value.2 != .committed else { throw SwanError.conflict(expected: 0, actual: 1) }
        reservations[requestID] = (value.0, value.1, .released, value.3)
    }

    public func repairCommittedReservation(requestID: String) async throws {
        try await markReservationCommitted(requestID: requestID)
    }

    public func failNextCommitFinalization() { failNextCommit = true }
}

public enum SwanDidWebClaimCanonicalizer {
    public static let domainSeparator = Data("swan.didweb.claim.v1\0".utf8)

    /// Frozen claim wire format: domain separator, five length-delimited UTF-8
    /// strings (DID, at:// handle, PDS URL, key id, base64url key bytes), then
    /// a raw 32-byte nonce and big-endian Unix milliseconds.
    public static func canonicalBytes(
        did: String, handle: String, pdsURL: String, keyID: String,
        keyType _: String, publicKey: Data, nonce: Data, expiresAt: Date
    ) throws -> Data {
        guard nonce.count == 32, let milliseconds = unixMilliseconds(expiresAt) else {
            throw SwanError.invalidIdentifier("did:web claim expiry or nonce")
        }
        var output = domainSeparator
        for text in [did, "at://\(handle)", pdsURL, keyID, publicKey.base64URLEncodedString()] {
            let bytes = Data(text.utf8)
            output.append(contentsOf: UInt64(bytes.count).bigEndianBytes)
            output.append(bytes)
        }
        output.append(nonce)
        output.append(contentsOf: UInt64(milliseconds).bigEndianBytes)
        return output
    }

    public static func receiptDigest(for bytes: Data) -> Data {
        Data(SHA256.hash(data: bytes))
    }

    private static func unixMilliseconds(_ date: Date) -> UInt64? {
        let value = date.timeIntervalSince1970 * 1_000
        guard value.isFinite, value >= 0, value <= Double(UInt64.max) else { return nil }
        return UInt64(value.rounded(.down))
    }
}

public struct SwanValidatedDidWebDocument: Sendable, Equatable {
    public let did: String
    public let documentDigest: Data
    public let canonicalJSON: Data
}

public enum SwanDidWebCanonicalizer {
    public static func canonical(_ did: String) throws -> String {
        guard did.hasPrefix("did:web:") else { throw SwanError.invalidIdentifier("did:web") }
        let value = String(did.dropFirst("did:web:".count))
        let parts = value.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        guard let authority = parts.first, !authority.isEmpty else { throw SwanError.invalidIdentifier("did:web authority") }
        let authorityParts = authority.components(separatedBy: "%3A")
        guard authorityParts.count <= 2,
              authorityParts[0].lowercased() == authorityParts[0],
              authorityParts[0].utf8.allSatisfy({ $0 == 45 || $0 == 46 || ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 122) }),
              authorityParts[0].split(separator: ".", omittingEmptySubsequences: false).allSatisfy({ !$0.isEmpty && !$0.hasPrefix("-") && !$0.hasSuffix("-") }),
              (authorityParts.count == 1 || ((1...65535).contains(Int(authorityParts[1]) ?? 0) && authorityParts[1] == String(Int(authorityParts[1])!))) else {
            throw SwanError.invalidIdentifier("did:web authority")
        }
        let path = parts.dropFirst()
        guard path.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy { $0 == 45 || $0 == 46 || $0 == 95 || $0 == 126 || ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) } }) else {
            throw SwanError.invalidIdentifier("did:web path")
        }
        let result = "did:web:" + authority + (path.isEmpty ? "" : ":" + path.joined(separator: ":"))
        guard result == did else { throw SwanError.invalidIdentifier("noncanonical did:web") }
        return result
    }
}

public enum SwanATMultikey {
    public static func encode(publicKey: Data) throws -> String {
        let prefix: Data
        switch publicKey.count {
        case 32: prefix = Data([0xed, 0x01])
        case 33: prefix = Data([0x80, 0x24])
        default: throw SwanError.invalidIdentifier("Multikey public key")
        }
        return "z" + Base58.encode(prefix + publicKey)
    }

    public static func decode(_ value: String, expected: Data) -> Bool {
        guard value.first == "z", let decoded = Base58.decode(String(value.dropFirst())),
              decoded.count == expected.count + 2, Data(decoded.dropFirst(2)) == expected else { return false }
        let prefix = Array(decoded.prefix(2))
        return (expected.count == 32 && prefix == [0xed, 0x01]) ||
            (expected.count == 33 && prefix == [0x80, 0x24])
    }
}

public enum SwanDidWebDocumentValidator {
    public static func validate(
        json: Data, did: String, handle: String, pdsURL: String,
        reservedKey: SwanReservedSigningKey, claimEndpoint: String
    ) throws -> SwanValidatedDidWebDocument {
        guard try SwanDidWebCanonicalizer.canonical(did) == did,
              try AccountIdentifiers.canonicalHandle(handle) == handle else {
            throw SwanError.invalidIdentifier("did:web claim identity")
        }
        let object = try canonicalJSONObject(json)
        guard let dictionary = object.value as? [String: Any],
              dictionary["id"] as? String == did else {
            throw SwanError.unauthorized("did:web document subject mismatch")
        }
        let aliases = dictionary["alsoKnownAs"] as? [Any] ?? []
        guard aliases.contains(where: { ($0 as? String) == "at://\(handle)" }) else {
            throw SwanError.unauthorized("did:web handle binding mismatch")
        }

        let keyID = did + reservedKey.keyID
        let methods = dictionary["verificationMethod"] as? [[String: Any]] ?? []
        let matchingKeys = methods.filter { method in
            guard method["id"] as? String == keyID,
                  method["type"] as? String == reservedKey.keyType,
                  method["controller"] as? String == did else { return false }
            guard let multibase = method["publicKeyMultibase"] as? String else { return false }
            return SwanATMultikey.decode(multibase, expected: reservedKey.publicKey)
        }
        let assertions = dictionary["assertionMethod"] as? [Any] ?? []
        guard matchingKeys.count == 1,
              assertions.contains(where: { ($0 as? String) == keyID
                  || (($0 as? [String: Any])?["id"] as? String) == keyID }) else {
            throw SwanError.unauthorized("did:web reserved signing key mismatch")
        }

        let services = dictionary["service"] as? [[String: Any]] ?? []
        let pdsMatches = services.filter {
            ($0["type"] as? String) == "AtprotoPersonalDataServer"
                && ($0["serviceEndpoint"] as? String) == pdsURL
        }
        let claimMatches = services.filter {
            ($0["id"] as? String) == "\(did)#swan-claim"
                && ($0["type"] as? String) == "SwanDidWebClaim"
                && ($0["serviceEndpoint"] as? String) == claimEndpoint
        }
        guard pdsMatches.count == 1, claimMatches.count == 1 else {
            throw SwanError.unauthorized("did:web service binding mismatch")
        }
        return SwanValidatedDidWebDocument(
            did: did, documentDigest: Data(SHA256.hash(data: object.canonicalJSON)),
            canonicalJSON: object.canonicalJSON
        )
    }

    private struct CanonicalObject {
        let value: Any
        let canonicalJSON: Data
    }

    private static func canonicalJSONObject(_ data: Data) throws -> CanonicalObject {
        let value = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        guard JSONSerialization.isValidJSONObject(value) else { throw SwanError.malformed("DID document JSON") }
        let canonical = try SwanRFC8785JSON.canonicalize(data)
        return CanonicalObject(value: value, canonicalJSON: canonical)
    }

}

/// RFC 8785 canonical JSON for the Foundation JSON value subset. It sorts
/// object members by UTF-16 code units, uses JSON escaping for strings, and
/// applies the JCS decimal/exponent thresholds for finite IEEE-754 numbers.
public enum SwanRFC8785JSON {
    public static func canonicalize(_ data: Data) throws -> Data {
        let value = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        var output = Data()
        try append(value, to: &output)
        return output
    }

    private static func append(_ value: Any, to output: inout Data) throws {
        if value is NSNull { output.append(contentsOf: [110, 117, 108, 108]); return }
        #if canImport(CoreFoundation)
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                output.append(contentsOf: Data((number.boolValue ? "true" : "false").utf8)); return
            }
            let text = canonicalNumber(number)
            guard let bytes = text.data(using: .utf8) else { throw SwanError.malformed("JCS number") }
            output.append(bytes); return
        }
        #else
        if let bool = value as? Bool {
            output.append(contentsOf: Data((bool ? "true" : "false").utf8)); return
        }
        if let number = value as? NSNumber {
            let text = canonicalNumber(number)
            guard let bytes = text.data(using: .utf8) else { throw SwanError.malformed("JCS number") }
            output.append(bytes); return
        }
        #endif
        if let string = value as? String {
            let encoded = try JSONSerialization.data(withJSONObject: [string], options: [.withoutEscapingSlashes])
            output.append(encoded.dropFirst().dropLast()); return
        }
        if let array = value as? [Any] {
            output.append(91)
            for (index, item) in array.enumerated() {
                if index != 0 { output.append(44) }
                try append(item, to: &output)
            }
            output.append(93); return
        }
        if let object = value as? [String: Any] {
            output.append(123)
            let keys = object.keys.sorted { lhs, rhs in
                Array(lhs.utf16).lexicographicallyPrecedes(Array(rhs.utf16))
            }
            for (index, key) in keys.enumerated() {
                if index != 0 { output.append(44) }
                try append(key, to: &output); output.append(58)
                guard let member = object[key] else { throw SwanError.malformed("JCS object") }
                try append(member, to: &output)
            }
            output.append(125); return
        }
        throw SwanError.malformed("unsupported JCS value")
    }

    private static func canonicalNumber(_ number: NSNumber) -> String {
        let value = number.doubleValue
        guard value.isFinite, value != 0 else { return "0" }
        var text = String(value)
        if text.hasSuffix(".0") { text.removeLast(2) }
        guard let marker = text.firstIndex(where: { $0 == "e" || $0 == "E" }) else { return text }
        let mantissa = String(text[..<marker])
        let exponent = Int(text[text.index(after: marker)...]) ?? 0
        let unsignedMantissa = mantissa.first == "-" ? String(mantissa.dropFirst()) : mantissa
        let absoluteExponent = exponent + (unsignedMantissa.split(separator: ".").first?.count ?? 1) - 1
        if absoluteExponent >= -6 && absoluteExponent < 21 {
            return expandDecimal(mantissa: mantissa, exponent: exponent)
        }
        let normalizedExponent = exponent >= 0 ? "e+\(exponent)" : "e\(exponent)"
        return "\(mantissa)e" + normalizedExponent.dropFirst(1)
    }

    private static func expandDecimal(mantissa: String, exponent: Int) -> String {
        let negative = mantissa.first == "-"
        let digits = mantissa.filter { $0 != "-" && $0 != "." }
        let unsignedMantissa = mantissa.first == "-" ? String(mantissa.dropFirst()) : mantissa
        let integerCount = (unsignedMantissa.split(separator: ".").first?.count ?? 0) + exponent
        let body: String
        if integerCount <= 0 {
            body = "0." + String(repeating: "0", count: -integerCount) + digits
        } else if integerCount >= digits.count {
            body = digits + String(repeating: "0", count: integerCount - digits.count)
        } else {
            let index = digits.index(digits.startIndex, offsetBy: integerCount)
            body = String(digits[..<index]) + "." + String(digits[index...])
        }
        return negative ? "-\(body)" : body
    }
}

public actor InMemoryIdentityBindingStore: SwanAtomicDidWebClaimStore, SwanAtomicIdentityContinuityStore, SwanExpiredIdentityClaimReleasingStore, SwanIdentityBindingEnumerating, SwanIdentityBindingHistoryStore {
    private var claims: [String: DidWebClaimTransaction] = [:]
    private var bindings: [String: IdentityBinding] = [:]
    private var consumedNonces: Set<Data> = []
    private var history: [String: [IdentityBindingHistoryEntry]] = [:]
    private var consumedStepUpReceipts: Set<Data> = []

    public init() {}
    public func identityBindings(afterAccountDID: String?, limit: Int) async throws -> [IdentityBinding] {
        let ordered = bindings.values.sorted { $0.accountDID < $1.accountDID }
        return Array(ordered.filter { binding in afterAccountDID.map { binding.accountDID > $0 } ?? true }.prefix(min(max(limit, 0), 256)))
    }
    public func identityBinding(accountDID: String) async throws -> IdentityBinding? { bindings[accountDID] }
    public func reserveDidWebClaim(_ transaction: DidWebClaimTransaction, now: Date) async throws {
        if let existing = claims[transaction.requestID] {
            guard existing == transaction else { throw SwanError.conflict(expected: 0, actual: 1) }
            return
        }
        guard now < transaction.expiresAt else { throw SwanError.expired }
        guard !consumedNonces.contains(transaction.claimNonceDigest) else { throw SwanError.conflict(expected: 0, actual: 1) }
        claims[transaction.requestID] = transaction
    }
    public func transitionDidWebClaim(_ transaction: DidWebClaimTransaction, from expected: DidWebClaimTransactionState, now: Date) async throws {
        guard let current = claims[transaction.requestID], current.state == expected,
              current.requestID == transaction.requestID,
              current.accountDID == transaction.accountDID,
              current.targetDID == transaction.targetDID,
              current.handle == transaction.handle,
              current.claimNonceDigest == transaction.claimNonceDigest else {
            throw SwanError.conflict(expected: 0, actual: 1)
        }
        claims[transaction.requestID] = transaction
        _ = now
    }
    public func commitDidWebClaim(_ request: DidWebClaimCommitRequest, history entry: IdentityBindingHistoryEntry?, now: Date) async throws {
        try await commitDidWebClaim(request, history: entry, now: now, gracePeriod: 86_400)
    }
    public func commitDidWebClaim(_ request: DidWebClaimCommitRequest, history entry: IdentityBindingHistoryEntry?, now: Date, gracePeriod: TimeInterval) async throws {
        guard let transaction = claims[request.requestID], transaction.state == .committing,
              !consumedNonces.contains(request.claimNonceDigest) else {
            throw SwanError.conflict(expected: 0, actual: 1)
        }
        if let current = bindings[request.accountDID], current == request.identityBinding {
            claims[request.requestID] = try transaction.transition(to: .committed, now: now)
            consumedNonces.insert(request.claimNonceDigest)
            return
        }
        let source = request.identityBinding
        guard !bindings.values.contains(where: {
            $0.accountDID != request.accountDID && $0.state != .released &&
            ($0.identityDID == source.identityDID || $0.handle == source.handle)
        }) else { throw SwanError.conflict(expected: 0, actual: 1) }
        let binding = try IdentityBinding(
            accountDID: source.accountDID, identityDID: source.identityDID,
            method: source.method, handle: source.handle,
            documentDigest: source.documentDigest,
            claimReceiptDigest: source.claimReceiptDigest,
            reservedKeyID: source.reservedKeyID,
            lastValidatedAt: source.lastValidatedAt,
            graceExpiresAt: now.addingTimeInterval(gracePeriod), state: source.state
        )
        if bindings[request.accountDID] != nil { bindings[request.accountDID] = nil }
        bindings[request.accountDID] = binding
        if let entry { history[request.accountDID, default: []].append(entry) }
        claims[request.requestID] = try transaction.transition(to: .committed, now: now)
        consumedNonces.insert(request.claimNonceDigest)
    }
    public func commitDidWebClaimAtomically(_ request: DidWebClaimCommitRequest,
                                            history entry: IdentityBindingHistoryEntry?, now: Date,
                                            gracePeriod: TimeInterval,
                                            stepUpReceipt: SwanIdentityStepUpReceipt?) async throws -> Bool {
        if let receipt = stepUpReceipt { try consumeStepUpReceipt(receipt, now: now, operation: .replace) }
        do {
            try await commitDidWebClaim(request, history: entry, now: now, gracePeriod: gracePeriod)
        } catch {
            if let receipt = stepUpReceipt { consumedStepUpReceipts.remove(receipt.receiptDigest) }
            throw error
        }
        return false
    }
    public func persistIdentityContinuity(_ binding: IdentityBinding) async throws -> IdentityBinding {
        guard bindings[binding.accountDID] != nil else { throw SwanError.invalidIdentifier("unknown identity binding") }
        bindings[binding.accountDID] = binding
        return binding
    }
    public func compareAndPersistIdentityContinuity(expected: IdentityBinding, replacement: IdentityBinding) async throws -> IdentityBinding {
        guard bindings[expected.accountDID] == expected else { throw SwanError.conflict(expected: 0, actual: 1) }
        bindings[expected.accountDID] = replacement
        return replacement
    }
    public func compareAndPersistIdentityContinuityAtomically(expected: IdentityBinding,
                                                              replacement: IdentityBinding,
                                                              now: Date,
                                                              stepUpReceipt: SwanIdentityStepUpReceipt?) async throws -> IdentityBinding {
        if let receipt = stepUpReceipt { try consumeStepUpReceipt(receipt, now: now, operation: .remove) }
        do {
            return try await compareAndPersistIdentityContinuity(expected: expected, replacement: replacement)
        } catch {
            if let receipt = stepUpReceipt { consumedStepUpReceipts.remove(receipt.receiptDigest) }
            throw error
        }
    }

    public func identityBindingHistory(accountDID: String) async throws -> [IdentityBindingHistoryEntry] {
        history[accountDID, default: []].sorted { $0.replacedAt < $1.replacedAt }
    }

    private func consumeStepUpReceipt(_ receipt: SwanIdentityStepUpReceipt, now: Date,
                                      operation: SwanIdentityStepUpOperation) throws {
        guard receipt.operation == operation.rawValue, receipt.mfaStrength == "phishingResistant",
              receipt.verifiedAt <= now, now < receipt.expiresAt,
              receipt.accountDID != "", consumedStepUpReceipts.insert(receipt.receiptDigest).inserted else {
            throw SwanError.unauthorized("invalid or replayed step-up receipt")
        }
    }
    public func purgeExpiredIdentityClaims(now: Date) async throws {
        claims = claims.filter { $0.value.expiresAt > now || $0.value.state == .committed }
    }
    public func purgeExpiredIdentityClaimsReturningRequests(now: Date) async throws -> [String] {
        let expired = claims.filter { $0.value.expiresAt <= now && $0.value.state != .committed }.map(\.key)
        try await purgeExpiredIdentityClaims(now: now)
        return expired
    }
}

public actor SwanDidWebIdentityService {
    private let reservations: any SwanDurableSigningKeyReservationService
    private let bindings: any IdentityBindingStore & SwanIdentityContinuityStore
    private let publicPDSURL: String
    private let publicURL: String
    private let gracePeriod: TimeInterval
    private let replacementAuthorizer: (any SwanDidWebReplacementAuthorizing)?
    private let stepUps: any SwanStepUpReceiptConsumptionStore
    private let signingKeyProvider: (any SwanSigningKeyProviding)?

    public init(
        reservations: any SwanDurableSigningKeyReservationService,
        bindings: any IdentityBindingStore & SwanIdentityContinuityStore,
        publicPDSURL: String, publicURL: String,
        gracePeriod: TimeInterval = 86_400,
        replacementAuthorizer: (any SwanDidWebReplacementAuthorizing)? = nil,
        stepUps: any SwanStepUpReceiptConsumptionStore,
        signingKeyProvider: (any SwanSigningKeyProviding)? = nil
    ) {
        self.reservations = reservations; self.bindings = bindings
        self.publicPDSURL = publicPDSURL; self.publicURL = publicURL
        self.gracePeriod = gracePeriod
        self.replacementAuthorizer = replacementAuthorizer
        self.stepUps = stepUps
        self.signingKeyProvider = signingKeyProvider
    }

    public func reserveSigningKey(
        requestID: String, accountDID: String?, targetDID: String, handle: String,
        expiresAt: Date, now: Date = Date()
    ) async throws -> SwanDidWebClaimReservation {
        guard expiresAt > now else { throw SwanError.expired }
        guard !requestID.isEmpty else { throw SwanError.invalidIdentifier("claim request") }
        guard try SwanDidWebCanonicalizer.canonical(targetDID) == targetDID else { throw SwanError.invalidIdentifier("did:web target") }
        if let accountDID {
            guard try AccountIdentifiers.validateDID(accountDID) == accountDID else { throw SwanError.invalidIdentifier("claim account") }
        }
        let canonicalHandle = try AccountIdentifiers.canonicalHandle(handle)
        let reserved: (key: SwanReservedSigningKey, nonce: Data)
        if let contextual = reservations as? any SwanContextualSigningKeyReservationService,
           let signingKeyProvider = signingKeyProvider ?? (reservations as? any SwanSigningKeyProviding) {
            let key = try await signingKeyProvider.configuredSigningKey()
            reserved = try await contextual.reserveSigningKey(
                requestID: requestID, accountDID: accountDID, targetDID: targetDID,
                handle: canonicalHandle, expiresAt: expiresAt, pdsURL: publicPDSURL,
                publicURL: publicURL,
                signingKey: try SwanSigningKeyMaterial(keyID: key.keyID, keyType: key.keyType, publicKey: key.publicKey))
        } else {
            reserved = try await reservations.reserveSigningKey(requestID: requestID)
        }
        let claimBytes = try SwanDidWebClaimCanonicalizer.canonicalBytes(
            did: targetDID, handle: canonicalHandle, pdsURL: publicPDSURL,
            keyID: reserved.key.keyID, keyType: reserved.key.keyType,
            publicKey: reserved.key.publicKey, nonce: reserved.nonce, expiresAt: expiresAt
        )
        let nonce = reserved.nonce.base64URLEncodedString()
        let endpoint = "\(publicURL)/.well-known/swan/did-web-claim/\(nonce)"
        let result = try SwanDidWebClaimReservation(
            requestID: requestID, accountDID: accountDID, targetDID: targetDID,
            handle: canonicalHandle, key: reserved.key, nonce: reserved.nonce,
            expiresAt: expiresAt, claimBytes: claimBytes,
            claimReceiptDigest: SwanDidWebClaimCanonicalizer.receiptDigest(for: claimBytes),
            claimServiceEndpoint: endpoint
        )
        try await reservations.recordIssuedReservation(result)
        return result
    }

    public func claim(
        reservation: SwanDidWebClaimReservation, documentJSON: Data, now: Date = Date(),
        authorization: SwanDidWebReplacementAuthorization? = nil
    ) async throws -> IdentityBinding {
        guard now < reservation.expiresAt else {
            try? await releaseSigningKeyReservation(reservation, now: now)
            throw SwanError.expired
        }
        guard let accountDID = reservation.accountDID else { throw SwanError.invalidIdentifier("claim account") }
        guard let issued = try await reservations.issuedReservation(requestID: reservation.requestID),
              issued == reservation else {
            throw SwanError.unauthorized("did:web reservation tuple mismatch")
        }
        let recomputedClaim = try SwanDidWebClaimCanonicalizer.canonicalBytes(
            did: reservation.targetDID, handle: reservation.handle, pdsURL: publicPDSURL,
            keyID: reservation.key.keyID, keyType: reservation.key.keyType,
            publicKey: reservation.key.publicKey, nonce: reservation.nonce,
            expiresAt: reservation.expiresAt
        )
        guard recomputedClaim == reservation.claimBytes,
              SwanDidWebClaimCanonicalizer.receiptDigest(for: recomputedClaim) == reservation.claimReceiptDigest,
              reservation.claimServiceEndpoint == "\(publicURL)/.well-known/swan/did-web-claim/\(reservation.nonce.base64URLEncodedString())" else {
            throw SwanError.unauthorized("did:web reservation canonical tuple mismatch")
        }
        let validated: SwanValidatedDidWebDocument
        do {
            validated = try SwanDidWebDocumentValidator.validate(
                json: documentJSON, did: reservation.targetDID, handle: reservation.handle,
                pdsURL: publicPDSURL, reservedKey: reservation.key,
                claimEndpoint: reservation.claimServiceEndpoint
            )
        } catch {
            try? await releaseSigningKeyReservation(reservation, now: now)
            throw error
        }
        let existingBinding = try await bindings.identityBinding(accountDID: accountDID)
        if let existing = existingBinding,
           existing.identityDID == reservation.targetDID,
           existing.handle == reservation.handle,
           existing.documentDigest == validated.documentDigest,
           existing.claimReceiptDigest == reservation.claimReceiptDigest,
           existing.reservedKeyID == reservation.key.keyID {
            try? await reservations.repairCommittedReservation(requestID: reservation.requestID)
            return existing
        }
        var stepUpReceipt: SwanIdentityStepUpReceipt?
        if existingBinding != nil {
            guard let authorization, authorization.accountDID == accountDID,
                  let replacementAuthorizer,
                  authorization.mfaStrength == .phishingResistant,
                  now.timeIntervalSince(authorization.stepUpAt) <= 300,
                  try await replacementAuthorizer.authorize(authorization, now: now) else {
                throw SwanError.unauthorized("fresh step-up required for identity replacement")
            }
            stepUpReceipt = try SwanIdentityStepUpReceipt(
                sessionID: authorization.sessionID, accountDID: accountDID,
                operation: SwanIdentityStepUpOperation.replace.rawValue,
                mfaStrength: "phishingResistant", verifiedAt: authorization.stepUpAt,
                expiresAt: authorization.stepUpAt.addingTimeInterval(300),
                receiptDigest: authorization.stepUpReceiptDigest
            )
        }
        let transaction = try DidWebClaimTransaction(
            requestID: reservation.requestID, accountDID: accountDID,
            targetDID: reservation.targetDID, handle: reservation.handle,
            claimNonceDigest: Data(SHA256.hash(data: reservation.nonce)),
            requestedDocumentDigest: validated.documentDigest, state: .reserved,
            expiresAt: reservation.expiresAt,
            stepUpReceiptDigest: authorization?.stepUpReceiptDigest,
            reservedKeyID: reservation.key.keyID,
            claimReceiptDigest: reservation.claimReceiptDigest
        )
        try await bindings.reserveDidWebClaim(transaction, now: now)
        let pending = try transaction.transition(to: .pendingValidation, now: now)
        try await bindings.transitionDidWebClaim(pending, from: .reserved, now: now)
        let committing = try pending.transition(to: .committing, now: now)
        try await bindings.transitionDidWebClaim(committing, from: .pendingValidation, now: now)
        let request = try DidWebClaimCommitRequest(
            transaction: committing, accountDID: accountDID, targetDID: reservation.targetDID,
            handle: reservation.handle, documentDigest: validated.documentDigest,
            reservedKeyID: reservation.key.keyID,
            claimNonceDigest: transaction.claimNonceDigest,
            claimReceiptDigest: reservation.claimReceiptDigest,
            idempotencyKey: reservation.requestID, now: now,
            reservation: SwanPersistedDidWebReservation(
                requestID: reservation.requestID, accountDID: reservation.accountDID,
                targetDID: reservation.targetDID, handle: reservation.handle,
                keyID: reservation.key.keyID, keyType: reservation.key.keyType,
                publicKey: reservation.key.publicKey, nonce: reservation.nonce,
                expiresAt: reservation.expiresAt, claimBytes: reservation.claimBytes,
                claimReceiptDigest: reservation.claimReceiptDigest,
                pdsURL: publicPDSURL, claimServiceEndpoint: reservation.claimServiceEndpoint,
                state: .issued
            )
        )
        let history = try existingBinding.map {
            try IdentityBindingHistoryEntry(
                accountDID: $0.accountDID, identityDID: $0.identityDID,
                documentDigest: $0.documentDigest,
                claimReceiptDigest: $0.claimReceiptDigest,
                reservedKeyID: $0.reservedKeyID, replacedAt: now
            )
        }
        // A claim consumes a one-time externally published nonce. Never allow
        // type erasure or a wrapper around the durable store to downgrade the
        // binding commit into a second transaction. In-memory test stores may
        // implement the same atomic capability and report that their separate
        // reservation fixture still needs finalization below.
        guard let atomic = bindings as? any SwanAtomicDidWebClaimStore else {
            throw SwanError.unavailable("identity claim requires atomic store")
        }
        let reservationFinalizedInTransaction = try await atomic.commitDidWebClaimAtomically(
            request, history: history, now: now, gracePeriod: gracePeriod,
            stepUpReceipt: stepUpReceipt
        )
        if !reservationFinalizedInTransaction {
            do {
                try await reservations.markReservationCommitted(requestID: reservation.requestID)
            } catch {
                // The durable binding is committed, so leave the provider tuple in
                // repairable committed/outbox state rather than releasing it.
                throw SwanError.unavailable("identity claim provider finalization pending")
            }
        }
        return try await bindings.identityBinding(accountDID: accountDID) ?? request.identityBinding
    }

    public func claim(
        reservation: SwanDidWebClaimReservation,
        documents: any SwanDidWebDocumentFetching,
        now: Date = Date(), authorization: SwanDidWebReplacementAuthorization? = nil
    ) async throws -> IdentityBinding {
        let document = try await documents.documentJSON(forDID: reservation.targetDID)
        return try await claim(reservation: reservation, documentJSON: document, now: now, authorization: authorization)
    }

    public func releaseSigningKeyReservation(_ reservation: SwanDidWebClaimReservation, now: Date = Date()) async throws {
        _ = now
        try await reservations.releaseSigningKeyReservation(requestID: reservation.requestID)
    }

    public func purgeExpiredClaims(now: Date = Date()) async throws {
        guard let store = bindings as? any SwanExpiredIdentityClaimReleasingStore else {
            try await bindings.purgeExpiredIdentityClaims(now: now); return
        }
        for requestID in try await store.purgeExpiredIdentityClaimsReturningRequests(now: now) {
            try? await reservations.releaseSigningKeyReservation(requestID: requestID)
        }
    }

    public func repairCommittedClaim(_ reservation: SwanDidWebClaimReservation) async throws {
        try await reservations.repairCommittedReservation(requestID: reservation.requestID)
    }

    public func removeIdentity(accountDID: String, authorization: SwanDidWebReplacementAuthorization,
                               now: Date = Date()) async throws -> IdentityBinding {
        guard let binding = try await bindings.identityBinding(accountDID: accountDID),
              binding.method == .didWeb, binding.accountDID == authorization.accountDID,
              let replacementAuthorizer,
              authorization.mfaStrength == .phishingResistant,
              now.timeIntervalSince(authorization.stepUpAt) <= 300,
              try await replacementAuthorizer.authorize(authorization, now: now) else {
            throw SwanError.unauthorized("fresh step-up required for identity removal")
        }
        let stepUpReceipt = try SwanIdentityStepUpReceipt(
            sessionID: authorization.sessionID, accountDID: accountDID,
            operation: SwanIdentityStepUpOperation.remove.rawValue,
            mfaStrength: "phishingResistant", verifiedAt: authorization.stepUpAt,
            expiresAt: authorization.stepUpAt.addingTimeInterval(300),
            receiptDigest: authorization.stepUpReceiptDigest
        )
        let released = try IdentityBinding(
            accountDID: binding.accountDID, identityDID: binding.identityDID,
            method: binding.method, handle: binding.handle,
            documentDigest: binding.documentDigest,
            claimReceiptDigest: binding.claimReceiptDigest,
            reservedKeyID: binding.reservedKeyID,
            lastValidatedAt: binding.lastValidatedAt,
            graceExpiresAt: binding.graceExpiresAt, state: .released
        )
        guard let atomic = bindings as? any SwanAtomicIdentityContinuityStore else {
            throw SwanError.unavailable("identity removal requires conditional durable store")
        }
        return try await atomic.compareAndPersistIdentityContinuityAtomically(
            expected: binding, replacement: released, now: now, stepUpReceipt: stepUpReceipt
        )
    }

    public func revalidate(
        binding: IdentityBinding, documents: any SwanDidWebDocumentFetching,
        now: Date = Date()
    ) async throws -> IdentityBinding {
        guard binding.method == .didWeb, binding.identityDID.hasPrefix("did:web:") else {
            throw SwanError.invalidIdentifier("did:web binding")
        }
        guard let reservation = try await reservations.committedReservation(accountDID: binding.accountDID) else {
            let suspended = try IdentityBinding(
                accountDID: binding.accountDID, identityDID: binding.identityDID,
                method: binding.method, handle: binding.handle,
                documentDigest: binding.documentDigest,
                claimReceiptDigest: binding.claimReceiptDigest,
                reservedKeyID: binding.reservedKeyID,
                lastValidatedAt: binding.lastValidatedAt,
                graceExpiresAt: binding.graceExpiresAt,
                state: .suspended
            )
            return try await persistContinuity(suspended)
        }
        return try await revalidate(binding: binding, reservation: reservation, documents: documents, now: now)
    }

    private func revalidate(binding: IdentityBinding, reservation: SwanDidWebClaimReservation,
                            documents: any SwanDidWebDocumentFetching, now: Date) async throws -> IdentityBinding {
        guard reservation.accountDID == binding.accountDID,
              reservation.targetDID == binding.identityDID,
              reservation.handle == binding.handle,
              reservation.key.keyID == binding.reservedKeyID,
              reservation.claimReceiptDigest == binding.claimReceiptDigest else {
            throw SwanError.unavailable("did:web binding material mismatch")
        }
        let document: Data
        do {
            document = try await documents.documentJSON(forDID: binding.identityDID)
        } catch {
            return try await applyValidatedRevalidation(binding: binding, validated: nil, now: now, transientFailure: true)
        }
        do {
            let validated = try SwanDidWebDocumentValidator.validate(
                json: document, did: binding.identityDID, handle: binding.handle,
                pdsURL: publicPDSURL, reservedKey: reservation.key,
                claimEndpoint: reservation.claimServiceEndpoint
            )
            return try await applyValidatedRevalidation(binding: binding, validated: validated, now: now)
        } catch {
            return try await applyValidatedRevalidation(binding: binding, validated: nil, now: now)
        }
    }

    /// Applies only a document already validated with the stored reserved key
    /// and exact claim endpoint. Startup/background/sensitive-operation
    /// composition calls this after fetching and validating the full binding.
    public func applyValidatedRevalidation(binding: IdentityBinding,
                                           validated: SwanValidatedDidWebDocument?,
                                           now: Date = Date(), transientFailure: Bool = false) async throws -> IdentityBinding {
        guard binding.method == .didWeb, let digest = binding.documentDigest else {
            throw SwanError.invalidIdentifier("did:web binding")
        }
        if transientFailure {
            let withinGrace = binding.graceExpiresAt.map { now <= $0 } ?? false
            let next = try IdentityBinding(accountDID: binding.accountDID, identityDID: binding.identityDID,
                                           method: binding.method, handle: binding.handle,
                                           documentDigest: binding.documentDigest, claimReceiptDigest: binding.claimReceiptDigest,
                                           reservedKeyID: binding.reservedKeyID, lastValidatedAt: binding.lastValidatedAt,
                                           graceExpiresAt: binding.graceExpiresAt,
                                           state: withinGrace ? .active : .suspended)
            return try await persistContinuity(next)
        }
        guard let validated, validated.documentDigest == digest else {
            let next = try IdentityBinding(accountDID: binding.accountDID, identityDID: binding.identityDID,
                                           method: binding.method, handle: binding.handle,
                                           documentDigest: binding.documentDigest, claimReceiptDigest: binding.claimReceiptDigest,
                                           reservedKeyID: binding.reservedKeyID, lastValidatedAt: binding.lastValidatedAt,
                                           graceExpiresAt: binding.graceExpiresAt, state: .suspended)
            return try await persistContinuity(next)
        }
        let next = try IdentityBinding(accountDID: binding.accountDID, identityDID: binding.identityDID,
                                       method: binding.method, handle: binding.handle,
                                       documentDigest: digest, claimReceiptDigest: binding.claimReceiptDigest,
                                       reservedKeyID: binding.reservedKeyID, lastValidatedAt: now,
                                       graceExpiresAt: now.addingTimeInterval(gracePeriod), state: .active)
        return try await persistContinuity(next)
    }

    private func persistContinuity(_ binding: IdentityBinding) async throws -> IdentityBinding {
        try await bindings.persistIdentityContinuity(binding)
    }

    public static let defaultGracePeriod: TimeInterval = 86_400
    public var revalidationGracePeriod: TimeInterval { gracePeriod }

    public func admission(for binding: IdentityBinding, now: Date = Date()) -> SwanIdentityAdmissionDecision {
        admission(for: binding, now: now, revalidationFailed: false)
    }

    public func admission(for binding: IdentityBinding, now: Date = Date(), revalidationFailed: Bool) -> SwanIdentityAdmissionDecision {
        let state = SwanIdentityContinuity.evaluate(
            state: binding.state, lastValidatedAt: binding.lastValidatedAt,
            now: now, grace: binding.graceExpiresAt.map { $0.timeIntervalSince(binding.lastValidatedAt ?? now) } ?? gracePeriod,
            revalidationFailed: revalidationFailed
        )
        return SwanIdentityAdmissionDecision(
            continuity: state, allowsRead: true,
            allowsWrite: SwanIdentityContinuity.allowsWrite(state),
            allowsTokenIssuance: SwanIdentityContinuity.allowsTokenIssuance(state)
        )
    }
}

public struct SwanIdentityAdmissionDecision: Sendable, Equatable {
    public let continuity: SwanIdentityContinuityState
    public let allowsRead: Bool
    public let allowsWrite: Bool
    public let allowsTokenIssuance: Bool

    public init(
        continuity: SwanIdentityContinuityState,
        allowsRead: Bool = true,
        allowsWrite: Bool,
        allowsTokenIssuance: Bool
    ) {
        self.continuity = continuity
        self.allowsRead = allowsRead
        self.allowsWrite = allowsWrite
        self.allowsTokenIssuance = allowsTokenIssuance
    }
}

/// Narrow durable identity-admission interface injected into repository
/// mutation and OAuth/legacy token issuance. PLC-only accounts (no binding)
/// and active did:web identities admit writes and new tokens; suspended or
/// failed-grace did:web identities deny both while preserving public reads.
/// Store/resolver failure must fail closed: implementations throw and every
/// caller treats a thrown error as a denial.
public protocol SwanIdentityAdmissionEvaluating: Sendable {
    func identityAdmission(accountDID: String, now: Date) async throws -> SwanIdentityAdmissionDecision
}

/// Production evaluator backed by the durable identity-binding store. The
/// did:web service owns the same continuity evaluation; this adapter only
/// resolves the binding (nil = PLC-only = full admission) and applies the
/// frozen continuity rules. It is constructible before the did:web service
/// composition because it depends only on the control store and the grace
/// policy value.
public struct SwanDurableIdentityAdmission: SwanIdentityAdmissionEvaluating, Sendable {
    private let bindings: any IdentityBindingStore
    private let gracePeriod: TimeInterval

    public init(bindings: any IdentityBindingStore, gracePeriod: TimeInterval = 86_400) {
        precondition(gracePeriod.isFinite && gracePeriod > 0 && gracePeriod <= 86_400)
        self.bindings = bindings
        self.gracePeriod = gracePeriod
    }

    public func identityAdmission(accountDID: String, now: Date) async throws -> SwanIdentityAdmissionDecision {
        guard !accountDID.isEmpty else {
            throw SwanError.invalidIdentifier("identity admission account")
        }
        // Any thrown store error propagates to the caller, which must treat it
        // as a denial (fail closed). It never becomes a permissive decision.
        let binding = try await bindings.identityBinding(accountDID: accountDID)
        guard let binding else {
            // PLC-only account: no identity binding, full admission.
            return SwanIdentityAdmissionDecision(
                continuity: .active, allowsWrite: true, allowsTokenIssuance: true
            )
        }
        guard binding.method == .didWeb else {
            // A PLC binding is not subject to did:web continuity fencing.
            return SwanIdentityAdmissionDecision(
                continuity: .active, allowsWrite: true, allowsTokenIssuance: true
            )
        }
        let state = SwanIdentityContinuity.evaluate(
            state: binding.state,
            lastValidatedAt: binding.lastValidatedAt,
            now: now,
            grace: binding.graceExpiresAt.map {
                $0.timeIntervalSince(binding.lastValidatedAt ?? now)
            } ?? gracePeriod,
            revalidationFailed: false
        )
        return SwanIdentityAdmissionDecision(
            continuity: state,
            allowsWrite: SwanIdentityContinuity.allowsWrite(state),
            allowsTokenIssuance: SwanIdentityContinuity.allowsTokenIssuance(state)
        )
    }
}

/// Bounded startup/background revalidation. Enumeration is deliberately a
/// storage capability so callers cannot accidentally scan unbounded account
/// state in one event-loop turn.
public actor SwanDidWebRevalidationScheduler {
    private let service: SwanDidWebIdentityService
    private let documents: any SwanDidWebDocumentFetching
    private let bindings: any SwanIdentityBindingEnumerating
    private let pageSize: Int
    private var lastFailures: [String] = []

    public init(service: SwanDidWebIdentityService, documents: any SwanDidWebDocumentFetching,
                bindings: any SwanIdentityBindingEnumerating, pageSize: Int = 64) {
        self.service = service
        self.documents = documents
        self.bindings = bindings
        self.pageSize = min(max(pageSize, 1), 256)
    }

    public func runOnce(now: Date = Date()) async throws -> Int {
        var cursor: String?
        var processed = 0
        var failures: [String] = []
        lastFailures = []
        while processed < pageSize {
            let limit = min(16, pageSize - processed)
            let page: [IdentityBinding]
            do {
                page = try await bindings.identityBindings(afterAccountDID: cursor, limit: limit)
            } catch {
                lastFailures = ["enumeration"]
                throw error
            }
            if page.isEmpty { break }
            guard page.count <= limit,
                  let lastAccountDID = page.last?.accountDID,
                  cursor.map({ lastAccountDID > $0 }) ?? true else {
                lastFailures = ["enumeration"]
                throw SwanError.unavailable("did:web identity enumeration made no bounded progress")
            }
            for binding in page {
                processed += 1
                guard binding.method == .didWeb, binding.state != .released else { continue }
                do {
                    _ = try await service.revalidate(binding: binding, documents: documents, now: now)
                } catch {
                    failures.append(binding.accountDID)
                }
            }
            cursor = page.last?.accountDID
            if page.count < limit { break }
        }
        lastFailures = failures
        if !failures.isEmpty {
            throw SwanError.unavailable("did:web revalidation failed for (failures.count) account(s)")
        }
        return processed
    }

    public func failures() -> [String] { lastFailures }
}

public enum SwanIdentityContinuityState: String, Codable, Sendable { case active, grace, suspended }

public enum SwanIdentityContinuity {
    public static func evaluate(
        state: IdentityBindingState, lastValidatedAt: Date?, now: Date,
        grace: TimeInterval = 86_400, revalidationFailed: Bool = false
    ) -> SwanIdentityContinuityState {
        guard state == .active else { return .suspended }
        guard let lastValidatedAt else { return .suspended }
        guard now.timeIntervalSince(lastValidatedAt) <= grace else { return .suspended }
        return revalidationFailed ? .grace : .active
    }
    public static func allowsRead(_ state: SwanIdentityContinuityState) -> Bool { _ = state; return true }
    public static func allowsWrite(_ state: SwanIdentityContinuityState) -> Bool { state == .active }
    public static func allowsTokenIssuance(_ state: SwanIdentityContinuityState) -> Bool { state == .active }
}

private extension UInt64 {
    var bigEndianBytes: [UInt8] {
        let value = bigEndian
        return withUnsafeBytes(of: value) { Array($0) }
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}

private enum Base58 {
    static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    static func encode(_ value: Data) -> String {
        guard !value.isEmpty else { return "" }
        var digits = [UInt8]()
        for byte in value {
            var carry = Int(byte)
            for index in digits.indices {
                let number = Int(digits[index]) * 256 + carry
                digits[index] = UInt8(number % 58)
                carry = number / 58
            }
            while carry > 0 { digits.append(UInt8(carry % 58)); carry /= 58 }
        }
        var result = String(repeating: "1", count: value.prefix { $0 == 0 }.count)
        result += digits.reversed().map { String(alphabet[Int($0)]) }.joined()
        return result
    }
    static func decode(_ value: String) -> Data? {
        var bytes = [UInt8]()
        for character in value {
            guard let index = alphabet.firstIndex(of: character) else { return nil }
            var carry = index
            for i in bytes.indices {
                let number = Int(bytes[i]) * 58 + carry
                bytes[i] = UInt8(number & 0xff); carry = number >> 8
            }
            while carry > 0 { bytes.append(UInt8(carry & 0xff)); carry >>= 8 }
        }
        let zeros = value.prefix { $0 == "1" }.count
        return Data(repeating: 0, count: zeros) + Data(bytes.reversed())
    }
}
