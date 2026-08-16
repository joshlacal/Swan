import Crypto
import Foundation
import SwanAccounts
import SwanCore
import SwanStorage

/// Stable typed failures for the did:web identity surface, mapped from the
/// account/identity service vocabulary to the spec §3.3 wire contract. The
/// integration owner translates these into HTTP responses; the adapter never
/// emits a raw `SwanError` or a provider response.
public enum SwanDidWebIdentityHTTPError: Error, Sendable, Equatable {
    case authenticationRequired
    case requestNotAllowed
    case stepUpRequired
    case accountUnavailable
    case insufficientScope
    case unprocessable(String)
    case conflict
    case rateLimited
    case serviceUnavailable

    public var statusCode: Int {
        switch self {
        case .authenticationRequired: 401
        case .requestNotAllowed, .stepUpRequired, .accountUnavailable, .insufficientScope: 403
        case .unprocessable: 422
        case .conflict: 409
        case .rateLimited: 429
        case .serviceUnavailable: 503
        }
    }

    public var code: String {
        switch self {
        case .authenticationRequired: "authentication_required"
        case .requestNotAllowed: "request_not_allowed"
        case .stepUpRequired: "step_up_required"
        case .accountUnavailable: "account_unavailable"
        case .insufficientScope: "insufficient_scope"
        case .unprocessable: "unprocessable_entity"
        case .conflict: "conflict"
        case .rateLimited: "rate_limited"
        case .serviceUnavailable: "service_unavailable"
        }
    }
}

// MARK: - Wire DTOs

public struct SwanDidWebReserveRequest: Codable, Sendable, Equatable {
    public let requestID: String
    public let targetDID: String
    public let handle: String
    public let expiresAt: Date

    public init(requestID: String, targetDID: String, handle: String, expiresAt: Date) {
        self.requestID = requestID
        self.targetDID = targetDID
        self.handle = handle
        self.expiresAt = expiresAt
    }
}

public struct SwanDidWebClaimRequest: Codable, Sendable, Equatable {
    public let requestID: String
    /// The raw one-time step-up receipt value echoed from the step-up
    /// endpoint. Required only when the account already holds a did:web
    /// binding (replacement); the adapter hashes it to the receipt digest.
    public let stepUpReceipt: String?

    public init(requestID: String, stepUpReceipt: String? = nil) {
        self.requestID = requestID
        self.stepUpReceipt = stepUpReceipt
    }
}

public struct SwanDidWebRotateRequest: Codable, Sendable, Equatable {
    public let requestID: String
    public let targetDID: String
    public let handle: String
    public let expiresAt: Date
    public let stepUpReceipt: String

    public init(requestID: String, targetDID: String, handle: String, expiresAt: Date, stepUpReceipt: String) {
        self.requestID = requestID
        self.targetDID = targetDID
        self.handle = handle
        self.expiresAt = expiresAt
        self.stepUpReceipt = stepUpReceipt
    }
}

public struct SwanDidWebRemoveRequest: Codable, Sendable, Equatable {
    public let stepUpReceipt: String

    public init(stepUpReceipt: String) {
        self.stepUpReceipt = stepUpReceipt
    }
}

public struct SwanDidWebReservationResponse: Codable, Sendable, Equatable {
    public let requestID: String
    public let targetDID: String
    public let handle: String
    public let keyID: String
    public let keyType: String
    public let publicKey: String
    public let nonce: String
    public let expiresAt: Date
    public let claimServiceEndpoint: String

    public init(reservation: SwanDidWebClaimReservation) {
        self.requestID = reservation.requestID
        self.targetDID = reservation.targetDID
        self.handle = reservation.handle
        self.keyID = reservation.key.keyID
        self.keyType = reservation.key.keyType
        self.publicKey = Self.base64URL(reservation.key.publicKey)
        self.nonce = Self.base64URL(reservation.nonce)
        self.expiresAt = reservation.expiresAt
        self.claimServiceEndpoint = reservation.claimServiceEndpoint
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

public struct SwanDidWebIdentityBindingResponse: Codable, Sendable, Equatable {
    public let accountDID: String
    public let identityDID: String
    public let method: String
    public let handle: String
    public let state: String
    public let lastValidatedAt: Date?
    public let graceExpiresAt: Date?

    public init(binding: IdentityBinding) {
        self.accountDID = binding.accountDID
        self.identityDID = binding.identityDID
        self.method = binding.method.rawValue
        self.handle = binding.handle
        self.state = binding.state.rawValue
        self.lastValidatedAt = binding.lastValidatedAt
        self.graceExpiresAt = binding.graceExpiresAt
    }
}

public struct SwanDidWebAdmissionResponse: Codable, Sendable, Equatable {
    public let continuity: String
    public let allowsRead: Bool
    public let allowsWrite: Bool
    public let allowsTokenIssuance: Bool

    public init(decision: SwanIdentityAdmissionDecision) {
        self.continuity = decision.continuity.rawValue
        self.allowsRead = decision.allowsRead
        self.allowsWrite = decision.allowsWrite
        self.allowsTokenIssuance = decision.allowsTokenIssuance
    }
}

// MARK: - Durable replacement authorizer

/// Durable pre-check for identity replacement/removal step-up receipts.
///
/// The atomic identity store is the authoritative consumer: it consumes the
/// receipt row in the same transaction as the binding mutation. This
/// conformer therefore only *verifies* that the presented receipt row exists,
/// is unexpired, and is not already consumed, so a stale or replayed step-up
/// fails fast before reaching the durable CAS. It never consumes, because a
/// second consumption would make the atomic store's in-transaction consume
/// fail with "invalid or replayed identity step-up receipt".
public struct SwanDurableDidWebReplacementAuthorizer: SwanDidWebReplacementAuthorizing {
    private let verifier: any SwanIdentityStepUpReceiptVerifying

    public init(verifier: any SwanIdentityStepUpReceiptVerifying) {
        self.verifier = verifier
    }

    public func authorize(_ authorization: SwanDidWebReplacementAuthorization, now: Date) async throws -> Bool {
        guard authorization.accountDID == authorization.sessionAccountDID,
              authorization.mfaStrength == .phishingResistant,
              authorization.stepUpAt <= now,
              now.timeIntervalSince(authorization.stepUpAt) <= 300 else {
            return false
        }
        return try await verifier.verifyIdentityStepUpReceipt(
            sessionID: authorization.sessionID,
            accountDID: authorization.accountDID,
            mfaStrength: "phishingResistant",
            receiptDigest: authorization.stepUpReceiptDigest,
            now: now
        )
    }
}

// MARK: - HTTP adapter

/// Management-session-authenticated did:web identity surface. Route assembly
/// (the integration owner) owns cookie/CSRF/origin policy and calls these
/// operations with the authenticated session value; the adapter owns
/// management-session authentication, fresh step-up construction, and the
/// stable §3.3 error vocabulary.
///
/// The adapter also exposes the two wiring seams the owner needs:
/// - `claimEndpoint`: the public one-time claim endpoint, backed by a durable
///   nonce -> reservation lookup that serves only `.issued` reservations, so a
///   consumed nonce 404s.
/// - `revalidationScheduler`: the bounded background revalidation scheduler
///   the owner starts/stops with the application lifecycle.
public struct SwanDidWebIdentityHTTP: Sendable {
    public let service: SwanDidWebIdentityService
    public let sessions: SwanManagementSessionRuntime
    public let documents: any SwanDidWebDocumentFetching
    public let reservations: any SwanDurableSigningKeyReservationService
    public let bindings: any IdentityBindingStore & SwanIdentityContinuityStore & SwanIdentityBindingEnumerating

    public init(
        service: SwanDidWebIdentityService,
        sessions: SwanManagementSessionRuntime,
        documents: any SwanDidWebDocumentFetching,
        reservations: any SwanDurableSigningKeyReservationService,
        bindings: any IdentityBindingStore & SwanIdentityContinuityStore & SwanIdentityBindingEnumerating
    ) {
        self.service = service
        self.sessions = sessions
        self.documents = documents
        self.reservations = reservations
        self.bindings = bindings
    }

    // MARK: Wiring

    /// Public one-time claim endpoint. The lookup decodes the base64url nonce
    /// and serves only reservations still in the `.issued` state, so a
    /// committed (consumed) or released nonce returns 404.
    public var claimEndpoint: SwanDidWebClaimEndpoint {
        SwanDidWebClaimEndpoint { [reservations] nonce in
            guard let data = Self.decodeBase64URL(nonce), data.count == 32 else { return nil }
            return try await reservations.issuedReservation(nonce: data)
        }
    }

    /// Bounded background revalidation scheduler. The owner starts it with
    /// the application lifecycle and stops it on shutdown.
    public var revalidationScheduler: SwanDidWebRevalidationScheduler {
        SwanDidWebRevalidationScheduler(service: service, documents: documents, bindings: bindings)
    }

    // MARK: Operations

    public func reserve(
        _ request: SwanDidWebReserveRequest,
        sessionValue: String?,
        now: Date = Date()
    ) async throws -> SwanDidWebReservationResponse {
        let metadata = try await authenticatedMetadata(sessionValue: sessionValue, now: now)
        do {
            let reservation = try await service.reserveSigningKey(
                requestID: request.requestID,
                accountDID: metadata.accountDID,
                targetDID: request.targetDID,
                handle: request.handle,
                expiresAt: request.expiresAt,
                now: now
            )
            return SwanDidWebReservationResponse(reservation: reservation)
        } catch {
            throw Self.map(error)
        }
    }

    public func claim(
        _ request: SwanDidWebClaimRequest,
        sessionValue: String?,
        now: Date = Date()
    ) async throws -> SwanDidWebIdentityBindingResponse {
        let metadata = try await authenticatedMetadata(sessionValue: sessionValue, now: now)
        do {
            guard let reservation = try await reservations.issuedReservation(requestID: request.requestID) else {
                throw SwanDidWebIdentityHTTPError.unprocessable("unknown claim reservation")
            }
            guard reservation.accountDID == metadata.accountDID else {
                throw SwanDidWebIdentityHTTPError.insufficientScope
            }
            // The service enforces fresh step-up only when the claim actually
            // replaces a different binding. An idempotent retry of the same
            // claim tuple returns the committed binding without step-up, so
            // the adapter must not pre-require a receipt here.
            let authorization = try await stepUpAuthorization(
                metadata: metadata, receiptValue: request.stepUpReceipt,
                now: now, required: false
            )
            let binding = try await service.claim(
                reservation: reservation, documents: documents, now: now,
                authorization: authorization
            )
            return SwanDidWebIdentityBindingResponse(binding: binding)
        } catch {
            throw Self.map(error)
        }
    }

    /// Rotation is a new reservation plus a fresh step-up claim. The reserve
    /// is idempotent on `requestID`, so a client that already reserved and
    /// published the temporary claim service can retry the same tuple.
    public func rotate(
        _ request: SwanDidWebRotateRequest,
        sessionValue: String?,
        now: Date = Date()
    ) async throws -> SwanDidWebIdentityBindingResponse {
        let metadata = try await authenticatedMetadata(sessionValue: sessionValue, now: now)
        do {
            let authorization = try await stepUpAuthorization(
                metadata: metadata, receiptValue: request.stepUpReceipt,
                now: now, required: true
            )
            let reservation = try await service.reserveSigningKey(
                requestID: request.requestID,
                accountDID: metadata.accountDID,
                targetDID: request.targetDID,
                handle: request.handle,
                expiresAt: request.expiresAt,
                now: now
            )
            let binding = try await service.claim(
                reservation: reservation, documents: documents, now: now,
                authorization: authorization
            )
            return SwanDidWebIdentityBindingResponse(binding: binding)
        } catch {
            throw Self.map(error)
        }
    }

    public func remove(
        _ request: SwanDidWebRemoveRequest,
        sessionValue: String?,
        now: Date = Date()
    ) async throws -> SwanDidWebIdentityBindingResponse {
        let metadata = try await authenticatedMetadata(sessionValue: sessionValue, now: now)
        do {
            guard let authorization = try await stepUpAuthorization(
                metadata: metadata, receiptValue: request.stepUpReceipt,
                now: now, required: true
            ) else {
                throw SwanDidWebIdentityHTTPError.stepUpRequired
            }
            let binding = try await service.removeIdentity(
                accountDID: metadata.accountDID, authorization: authorization, now: now
            )
            return SwanDidWebIdentityBindingResponse(binding: binding)
        } catch {
            throw Self.map(error)
        }
    }

    public func reverify(
        sessionValue: String?,
        now: Date = Date()
    ) async throws -> SwanDidWebIdentityBindingResponse {
        let metadata = try await authenticatedMetadata(sessionValue: sessionValue, now: now)
        do {
            guard let binding = try await bindings.identityBinding(accountDID: metadata.accountDID) else {
                throw SwanDidWebIdentityHTTPError.unprocessable("no identity binding")
            }
            let updated = try await service.revalidate(binding: binding, documents: documents, now: now)
            return SwanDidWebIdentityBindingResponse(binding: updated)
        } catch {
            throw Self.map(error)
        }
    }

    /// The admission decision the owner applies to repository writes and
    /// new-token issuance. Suspended/expired-grace identities keep public
    /// reads (`allowsRead`) while fencing writes and token issuance.
    public func admission(
        sessionValue: String?,
        now: Date = Date()
    ) async throws -> SwanDidWebAdmissionResponse {
        let metadata = try await authenticatedMetadata(sessionValue: sessionValue, now: now)
        do {
            guard let binding = try await bindings.identityBinding(accountDID: metadata.accountDID) else {
                throw SwanDidWebIdentityHTTPError.unprocessable("no identity binding")
            }
            let decision = await service.admission(for: binding, now: now)
            return SwanDidWebAdmissionResponse(decision: decision)
        } catch {
            throw Self.map(error)
        }
    }

    // MARK: Internals

    private func authenticatedMetadata(
        sessionValue: String?,
        now: Date
    ) async throws -> ManagementSessionMetadata {
        guard let sessionValue, !sessionValue.isEmpty else {
            throw SwanDidWebIdentityHTTPError.authenticationRequired
        }
        do {
            return try await sessions.authenticate(sessionValue: sessionValue, now: now)
        } catch is SwanManagementSessionError {
            throw SwanDidWebIdentityHTTPError.authenticationRequired
        } catch {
            throw SwanDidWebIdentityHTTPError.serviceUnavailable
        }
    }

    /// Builds the replacement authorization from the session's fresh step-up
    /// state and the client-echoed one-time receipt value. The receipt digest
    /// is the SHA-256 of the presented value, matching the keyed digest the
    /// step-up flow persists. Only phishing-resistant step-up is accepted,
    /// consistent with the reviewed identity service.
    private func stepUpAuthorization(
        metadata: ManagementSessionMetadata,
        receiptValue: String?,
        now: Date,
        required: Bool
    ) async throws -> SwanDidWebReplacementAuthorization? {
        guard let receiptValue, !receiptValue.isEmpty else {
            if required { throw SwanDidWebIdentityHTTPError.stepUpRequired }
            return nil
        }
        guard metadata.strength.isStepUp, let stepUpAt = metadata.lastStepUpAt else {
            throw SwanDidWebIdentityHTTPError.stepUpRequired
        }
        let digest = Data(SHA256.hash(data: Data(receiptValue.utf8)))
        return try SwanDidWebReplacementAuthorization(
            accountDID: metadata.accountDID,
            sessionAccountDID: metadata.accountDID,
            sessionID: metadata.sessionID.rawValue,
            stepUpAt: stepUpAt,
            stepUpReceiptDigest: digest,
            mfaStrength: .phishingResistant
        )
    }

    static func map(_ error: any Error) -> SwanDidWebIdentityHTTPError {
        switch error {
        case let error as SwanDidWebIdentityHTTPError:
            return error
        case let error as SwanManagementSessionError:
            switch error {
            case .unauthorized: return .authenticationRequired
            case .requestNotAllowed: return .requestNotAllowed
            case .unavailable: return .serviceUnavailable
            }
        case let error as SwanError:
            switch error {
            case let .unauthorized(message):
                if message.contains("step-up") { return .stepUpRequired }
                if message.contains("replayed") { return .conflict }
                // DID-document and reservation-tuple mismatches are
                // field-safe validation failures, not authentication ones.
                return .unprocessable(message)
            case .conflict:
                return .conflict
            case .expired:
                return .unprocessable("expired")
            case let .invalidIdentifier(message):
                return .unprocessable(message)
            case let .malformed(message):
                return .unprocessable(message)
            case .invalidProfile:
                return .serviceUnavailable
            case .unavailable:
                // Storage, resolver, key-store, or provider outage.
                return .serviceUnavailable
            }
        case let error as AccountControlStoreError:
            switch error {
            case .invalidInput, .malformedRecord:
                return .unprocessable("invalid record")
            case .duplicateDID, .duplicateHandle:
                return .conflict
            case .invalidStatus, .invalidTransition:
                return .conflict
            case .notFound:
                return .unprocessable("not found")
            case .unavailable:
                return .serviceUnavailable
            }
        default:
            return .serviceUnavailable
        }
    }

    private static func decodeBase64URL(_ value: String) -> Data? {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64.append("=") }
        return Data(base64Encoded: base64)
    }
}
