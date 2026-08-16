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

/// Network boundary for the claim and revalidation paths. Production callers
/// provide the existing peer-pinned DID fetcher; tests can inject a fixture
/// without weakening the resolver policy.
public protocol SwanDidWebDocumentFetching: Sendable {
    func documentJSON(forDID did: String) async throws -> Data
}

/// Small durable-boundary-compatible fixture and default process-local
/// provider. Production deployments may replace it with a key-store-backed
/// implementation without changing claim validation or transaction ordering.
public actor InMemorySwanSigningKeyReservationService: SwanSigningKeyReservationService {
    private var reservations: [String: (SwanReservedSigningKey, Data)] = [:]
    private var consumed: Set<String> = []

    public init() {}

    public func reserveSigningKey(requestID: String) async throws -> (key: SwanReservedSigningKey, nonce: Data) {
        guard !requestID.isEmpty else { throw SwanError.invalidIdentifier("claim request") }
        if let existing = reservations[requestID], !consumed.contains(requestID) { return existing }
        guard !consumed.contains(requestID) else { throw SwanError.conflict(expected: 0, actual: 1) }
        var generator = SystemRandomNumberGenerator()
        let bytes = Data((0 ..< 32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
        let key = try SwanReservedSigningKey(keyID: "#atproto", keyType: "Multikey", publicKey: bytes)
        let nonce = Data((0 ..< 32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
        reservations[requestID] = (key, nonce)
        return (key, nonce)
    }

    public func consumeSigningKeyReservation(requestID: String) async throws {
        guard reservations[requestID] != nil else { throw SwanError.invalidIdentifier("unknown claim reservation") }
        guard consumed.insert(requestID).inserted else { throw SwanError.conflict(expected: 0, actual: 1) }
    }
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
        let canonical = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
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

public actor InMemoryIdentityBindingStore: IdentityBindingStore {
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
        guard let transaction = claims[request.requestID], transaction.state == .committing,
              !consumedNonces.contains(request.claimNonceDigest) else {
            throw SwanError.conflict(expected: 0, actual: 1)
        }
        if let current = bindings[request.accountDID], current == request.identityBinding {
            claims[request.requestID] = try transaction.transition(to: .committed, now: now)
            consumedNonces.insert(request.claimNonceDigest)
            return
        }
        if bindings[request.accountDID] != nil { bindings[request.accountDID] = nil }
        bindings[request.accountDID] = request.identityBinding
        if let entry { history[request.accountDID, default: []].append(entry) }
        claims[request.requestID] = try transaction.transition(to: .committed, now: now)
        consumedNonces.insert(request.claimNonceDigest)
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
    private var issuedReservations: [String: SwanDidWebClaimReservation] = [:]

    public init(
        reservations: any SwanSigningKeyReservationService,
        bindings: any IdentityBindingStore,
        publicPDSURL: String, publicURL: String,
        gracePeriod: TimeInterval = 86_400
    ) {
        self.reservations = reservations; self.bindings = bindings
        self.publicPDSURL = publicPDSURL; self.publicURL = publicURL
        self.gracePeriod = gracePeriod
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
        reservation: SwanDidWebClaimReservation, documentJSON: Data, now: Date = Date()
    ) async throws -> IdentityBinding {
        guard now < reservation.expiresAt else { throw SwanError.expired }
        guard let accountDID = reservation.accountDID else { throw SwanError.invalidIdentifier("claim account") }
        let validated = try SwanDidWebDocumentValidator.validate(
            json: documentJSON, did: reservation.targetDID, handle: reservation.handle,
            pdsURL: publicPDSURL, reservedKey: reservation.key,
            claimEndpoint: reservation.claimServiceEndpoint
        )
        let existingBinding = try await bindings.identityBinding(accountDID: accountDID)
        if let existing = existingBinding,
           existing.identityDID == reservation.targetDID,
           existing.handle == reservation.handle,
           existing.documentDigest == validated.documentDigest,
           existing.claimReceiptDigest == reservation.claimReceiptDigest,
           existing.reservedKeyID == reservation.key.keyID {
            return existing
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
        try await bindings.commitDidWebClaim(request, history: history, now: now)
        try await reservations.consumeSigningKeyReservation(requestID: reservation.requestID)
        return request.identityBinding
    }

    public func claim(
        reservation: SwanDidWebClaimReservation,
        documents: any SwanDidWebDocumentFetching,
        now: Date = Date()
    ) async throws -> IdentityBinding {
        let document = try await documents.documentJSON(forDID: reservation.targetDID)
        return try await claim(reservation: reservation, documentJSON: document, now: now)
    }

    public func revalidate(
        binding: IdentityBinding, documents: any SwanDidWebDocumentFetching,
        now: Date = Date()
    ) async throws -> IdentityBinding {
        guard binding.method == .didWeb else {
            throw SwanError.invalidIdentifier("did:web binding")
        }
        throw SwanError.unavailable("did:web reserved key material is unavailable")
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
            return try IdentityBinding(
                accountDID: binding.accountDID, identityDID: binding.identityDID,
                method: .didWeb, handle: binding.handle, documentDigest: digest,
                claimReceiptDigest: receipt, reservedKeyID: binding.reservedKeyID!,
                lastValidatedAt: binding.lastValidatedAt, graceExpiresAt: binding.graceExpiresAt,
                state: .suspended
            )
        }
        return try IdentityBinding(
            accountDID: binding.accountDID, identityDID: binding.identityDID,
            method: .didWeb, handle: binding.handle, documentDigest: digest,
            claimReceiptDigest: receipt, reservedKeyID: binding.reservedKeyID!,
            lastValidatedAt: now, graceExpiresAt: now.addingTimeInterval(gracePeriod), state: .active
        )
    }

    private static func canonicalDocumentDigest(_ document: Data) throws -> Data {
        let object = try JSONSerialization.jsonObject(with: document)
        let canonical = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        return Data(SHA256.hash(data: canonical))
    }

    public static let defaultGracePeriod: TimeInterval = 86_400
    public var revalidationGracePeriod: TimeInterval { gracePeriod }
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
    public static func allowsWrite(_ state: SwanIdentityContinuityState) -> Bool { state == .active || state == .grace }
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
