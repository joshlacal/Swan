import Crypto
import Foundation
import SwanCore
import SwanStorage

/// The public signing material Swan reserves for one did:web claim. The key is
/// a binding check; it is never used as an assertion key for the external DID.
public struct SwanReservedSigningKey: Codable, Sendable, Equatable {
    public let keyID: String
    public let keyType: String
    public let publicKey: Data

    public init(keyID: String, keyType: String, publicKey: Data) throws {
        guard !keyID.isEmpty, !keyType.isEmpty, !publicKey.isEmpty,
              publicKey.count <= 4_096 else {
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

/// Durable providers implement this extension to make the reservation tuple
/// authoritative across retries and process crashes. The base protocol stays
/// source-compatible with existing callers and test doubles.
public protocol SwanDurableSigningKeyReservationService: SwanSigningKeyReservationService {
    func issuedReservation(requestID: String) async throws -> (key: SwanReservedSigningKey, nonce: Data)?
    func markReservationCommitted(requestID: String) async throws
    func releaseSigningKeyReservation(requestID: String) async throws
    func repairCommittedReservation(requestID: String) async throws
}

public struct SwanDidWebReplacementAuthorization: Sendable, Equatable {
    public let accountDID: String
    public let sessionAccountDID: String
    public let sessionID: String
    public let stepUpAt: Date
    public let stepUpReceiptDigest: Data

    public init(accountDID: String, sessionAccountDID: String, sessionID: String,
                stepUpAt: Date, stepUpReceiptDigest: Data) throws {
        guard !sessionID.isEmpty, stepUpReceiptDigest.count == 32 else {
            throw SwanError.invalidIdentifier("did:web replacement authorization")
        }
        self.accountDID = accountDID
        self.sessionAccountDID = sessionAccountDID
        self.sessionID = sessionID
        self.stepUpAt = stepUpAt
        self.stepUpReceiptDigest = stepUpReceiptDigest
    }
}

public protocol SwanDidWebReplacementAuthorizing: Sendable {
    func authorize(_ authorization: SwanDidWebReplacementAuthorization, now: Date) async throws -> Bool
}

public struct SwanDefaultDidWebReplacementAuthorizer: SwanDidWebReplacementAuthorizing {
    public init() {}
    public func authorize(_ authorization: SwanDidWebReplacementAuthorization, now: Date) async throws -> Bool {
        authorization.accountDID == authorization.sessionAccountDID
            && !authorization.sessionID.isEmpty
            && authorization.stepUpReceiptDigest.count == 32
            && authorization.stepUpAt <= now
            && now.timeIntervalSince(authorization.stepUpAt) <= 300
    }
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
    private var reservations: [String: (SwanReservedSigningKey, Data, State)] = [:]
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
        reservations[requestID] = (key, nonce, .issued)
        return (key, nonce)
    }

    public func consumeSigningKeyReservation(requestID: String) async throws {
        try await markReservationCommitted(requestID: requestID)
    }

    public func issuedReservation(requestID: String) async throws -> (key: SwanReservedSigningKey, nonce: Data)? {
        guard let value = reservations[requestID], value.2 != .released else { return nil }
        return (value.0, value.1)
    }

    public func markReservationCommitted(requestID: String) async throws {
        if failNextCommit { failNextCommit = false; throw SwanError.unavailable("provider finalization failure") }
        guard let value = reservations[requestID], value.2 != .released else {
            throw SwanError.invalidIdentifier("unknown claim reservation")
        }
        reservations[requestID] = (value.0, value.1, .committed)
    }

    public func releaseSigningKeyReservation(requestID: String) async throws {
        guard let value = reservations[requestID] else { return }
        guard value.2 != .committed else { throw SwanError.conflict(expected: 0, actual: 1) }
        reservations[requestID] = (value.0, value.1, .released)
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

public enum SwanDidWebDocumentValidator {
    public static func validate(
        json: Data, did: String, handle: String, pdsURL: String,
        reservedKey: SwanReservedSigningKey, claimEndpoint: String
    ) throws -> SwanValidatedDidWebDocument {
        guard try AccountIdentifiers.validateDID(did) == did, did.hasPrefix("did:web:"),
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
            return encodedPublicKey(method) == reservedKey.publicKey
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

    private static func encodedPublicKey(_ method: [String: Any]) -> Data? {
        if let value = method["publicKeyBase64"] as? String { return Data(base64Encoded: value) }
        if let value = method["publicKeyMultibase"] as? String, value.first == "z" {
            return Base58.decode(String(value.dropFirst()))
        }
        return nil
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
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                output.append(contentsOf: Data((number.boolValue ? "true" : "false").utf8)); return
            }
            let text = canonicalNumber(number)
            guard let bytes = text.data(using: .utf8) else { throw SwanError.malformed("JCS number") }
            output.append(bytes); return
        }
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
        let absoluteExponent = exponent + (mantissa.split(separator: ".").first?.count ?? 1) - 1
        if absoluteExponent >= -6 && absoluteExponent < 21 {
            return expandDecimal(mantissa: mantissa, exponent: exponent)
        }
        let normalizedExponent = exponent >= 0 ? "e+\(exponent)" : "e\(exponent)"
        return "\(mantissa)e" + normalizedExponent.dropFirst(1)
    }

    private static func expandDecimal(mantissa: String, exponent: Int) -> String {
        let negative = mantissa.first == "-"
        let digits = mantissa.filter { $0 != "-" && $0 != "." }
        let integerCount = (mantissa.split(separator: ".").first?.count ?? 0) + exponent
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

public actor InMemoryIdentityBindingStore: SwanGraceAwareIdentityBindingStore, SwanIdentityContinuityStore {
    private var claims: [String: DidWebClaimTransaction] = [:]
    private var bindings: [String: IdentityBinding] = [:]
    private var consumedNonces: Set<Data> = []
    private var history: [String: [IdentityBindingHistoryEntry]] = [:]

    public init() {}
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
    public func persistIdentityContinuity(_ binding: IdentityBinding) async throws -> IdentityBinding {
        guard bindings[binding.accountDID] != nil else { throw SwanError.invalidIdentifier("unknown identity binding") }
        bindings[binding.accountDID] = binding
        return binding
    }
    public func purgeExpiredIdentityClaims(now: Date) async throws {
        claims = claims.filter { $0.value.expiresAt > now || $0.value.state == .committed }
    }
}

public actor SwanDidWebIdentityService {
    private let reservations: any SwanSigningKeyReservationService
    private let bindings: any IdentityBindingStore
    private let publicPDSURL: String
    private let publicURL: String
    private let gracePeriod: TimeInterval
    private let replacementAuthorizer: any SwanDidWebReplacementAuthorizing
    private var issuedReservations: [String: SwanDidWebClaimReservation] = [:]

    public init(
        reservations: any SwanSigningKeyReservationService,
        bindings: any IdentityBindingStore,
        publicPDSURL: String, publicURL: String,
        gracePeriod: TimeInterval = 86_400,
        replacementAuthorizer: any SwanDidWebReplacementAuthorizing = SwanDefaultDidWebReplacementAuthorizer()
    ) {
        self.reservations = reservations; self.bindings = bindings
        self.publicPDSURL = publicPDSURL; self.publicURL = publicURL
        self.gracePeriod = gracePeriod
        self.replacementAuthorizer = replacementAuthorizer
    }

    public func reserveSigningKey(
        requestID: String, accountDID: String?, targetDID: String, handle: String,
        expiresAt: Date, now: Date = Date()
    ) async throws -> SwanDidWebClaimReservation {
        guard expiresAt > now else { throw SwanError.expired }
        _ = try AccountIdentifiers.validateDID(targetDID)
        let canonicalHandle = try AccountIdentifiers.canonicalHandle(handle)
        let reserved = try await reservations.reserveSigningKey(requestID: requestID)
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
        if let existing = issuedReservations[requestID] {
            guard existing.accountDID == result.accountDID,
                  existing.targetDID == result.targetDID,
                  existing.handle == result.handle,
                  existing.expiresAt == result.expiresAt else {
                throw SwanError.conflict(expected: 0, actual: 1)
            }
            return existing
        }
        issuedReservations[requestID] = result
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
        if let durable = reservations as? any SwanDurableSigningKeyReservationService {
            guard let issued = try await durable.issuedReservation(requestID: reservation.requestID),
                  issued.key == reservation.key, issued.nonce == reservation.nonce else {
                throw SwanError.unauthorized("did:web reservation tuple mismatch")
            }
        } else if issuedReservations[reservation.requestID] != reservation {
            throw SwanError.unauthorized("did:web reservation tuple mismatch")
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
            if let durable = reservations as? any SwanDurableSigningKeyReservationService {
                try? await durable.repairCommittedReservation(requestID: reservation.requestID)
            }
            return existing
        }
        if existingBinding != nil {
            guard let authorization,
                  authorization.accountDID == accountDID,
                  try await replacementAuthorizer.authorize(authorization, now: now) else {
                throw SwanError.unauthorized("fresh step-up required for identity replacement")
            }
        }
        let transaction = try DidWebClaimTransaction(
            requestID: reservation.requestID, accountDID: accountDID,
            targetDID: reservation.targetDID, handle: reservation.handle,
            claimNonceDigest: Data(SHA256.hash(data: reservation.nonce)),
            requestedDocumentDigest: validated.documentDigest, state: .reserved,
            expiresAt: reservation.expiresAt, reservedKeyID: reservation.key.keyID,
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
            idempotencyKey: reservation.requestID, now: now
        )
        let history = try existingBinding.map {
            try IdentityBindingHistoryEntry(
                accountDID: $0.accountDID, identityDID: $0.identityDID,
                documentDigest: $0.documentDigest,
                claimReceiptDigest: $0.claimReceiptDigest,
                reservedKeyID: $0.reservedKeyID, replacedAt: now
            )
        }
        if let graceAware = bindings as? any SwanGraceAwareIdentityBindingStore {
            try await graceAware.commitDidWebClaim(request, history: history, now: now, gracePeriod: gracePeriod)
        } else {
            try await bindings.commitDidWebClaim(request, history: history, now: now)
        }
        do {
            if let durable = reservations as? any SwanDurableSigningKeyReservationService {
                try await durable.markReservationCommitted(requestID: reservation.requestID)
            } else {
                try await reservations.consumeSigningKeyReservation(requestID: reservation.requestID)
            }
        } catch {
            // The durable binding is committed, so leave the provider tuple in
            // repairable committed/outbox state rather than releasing it.
            throw SwanError.unavailable("identity claim provider finalization pending")
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
        if let durable = reservations as? any SwanDurableSigningKeyReservationService {
            try await durable.releaseSigningKeyReservation(requestID: reservation.requestID)
        }
        issuedReservations.removeValue(forKey: reservation.requestID)
    }

    public func repairCommittedClaim(_ reservation: SwanDidWebClaimReservation) async throws {
        guard let durable = reservations as? any SwanDurableSigningKeyReservationService else {
            throw SwanError.unavailable("claim provider is not repairable")
        }
        try await durable.repairCommittedReservation(requestID: reservation.requestID)
    }

    public func revalidate(
        binding: IdentityBinding, documents: any SwanDidWebDocumentFetching,
        now: Date = Date()
    ) async throws -> IdentityBinding {
        guard binding.method == .didWeb else {
            throw SwanError.invalidIdentifier("did:web binding")
        }
        guard let grace = binding.graceExpiresAt else {
            throw SwanError.unavailable("did:web binding has no revalidation grace")
        }
        do {
            _ = try await documents.documentJSON(forDID: binding.identityDID)
        } catch {
            let transient = now <= grace
            let next = try IdentityBinding(
                accountDID: binding.accountDID, identityDID: binding.identityDID,
                method: .didWeb, handle: binding.handle,
                documentDigest: binding.documentDigest, claimReceiptDigest: binding.claimReceiptDigest,
                reservedKeyID: binding.reservedKeyID, lastValidatedAt: binding.lastValidatedAt,
                graceExpiresAt: binding.graceExpiresAt,
                state: transient ? .active : .suspended
            )
            return try await persistContinuity(next)
        }
        return try await persistContinuity(binding)
    }

    public func revalidate(
        binding: IdentityBinding, reservedKey: SwanReservedSigningKey,
        documents: any SwanDidWebDocumentFetching, now: Date = Date()
    ) async throws -> IdentityBinding {
        guard binding.method == .didWeb, binding.reservedKeyID == reservedKey.keyID,
              let digest = binding.documentDigest,
              let receipt = binding.claimReceiptDigest else {
            throw SwanError.invalidIdentifier("did:web binding")
        }
        let document = try await documents.documentJSON(forDID: binding.identityDID)
        let currentDigest = try Self.canonicalDocumentDigest(document)
        guard currentDigest == digest else {
            let next = try IdentityBinding(
                accountDID: binding.accountDID, identityDID: binding.identityDID,
                method: .didWeb, handle: binding.handle, documentDigest: digest,
                claimReceiptDigest: receipt, reservedKeyID: binding.reservedKeyID!,
                lastValidatedAt: binding.lastValidatedAt, graceExpiresAt: binding.graceExpiresAt,
                state: .suspended
            )
            return try await persistContinuity(next)
        }
        let next = try IdentityBinding(
            accountDID: binding.accountDID, identityDID: binding.identityDID,
            method: .didWeb, handle: binding.handle, documentDigest: digest,
            claimReceiptDigest: receipt, reservedKeyID: binding.reservedKeyID!,
            lastValidatedAt: now, graceExpiresAt: now.addingTimeInterval(gracePeriod), state: .active
        )
        return try await persistContinuity(next)
    }

    private func persistContinuity(_ binding: IdentityBinding) async throws -> IdentityBinding {
        if let store = bindings as? any SwanIdentityContinuityStore {
            return try await store.persistIdentityContinuity(binding)
        }
        return binding
    }

    private static func canonicalDocumentDigest(_ document: Data) throws -> Data {
        let canonical = try SwanRFC8785JSON.canonicalize(document)
        return Data(SHA256.hash(data: canonical))
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
    static func decode(_ value: String) -> Data? {
        var bytes = [UInt8]()
        for character in value {
            guard let index = alphabet.firstIndex(of: character) else { return nil }
            var carry = index
            for i in bytes.indices.reversed() {
                let number = Int(bytes[i]) * 58 + carry
                bytes[i] = UInt8(number & 0xff); carry = number >> 8
            }
            while carry > 0 { bytes.insert(UInt8(carry & 0xff), at: 0); carry >>= 8 }
        }
        for character in value where character == "1" { bytes.insert(0, at: 0) }
        return Data(bytes)
    }
}
