import Foundation
import Crypto
import SwanCore

public enum IdentityMethod: String, Codable, CaseIterable, Sendable {
    case plc
    case didWeb
}

public enum IdentityBindingState: String, Codable, CaseIterable, Sendable {
    case active
    case suspended
    case released
}

public struct IdentityBinding: Codable, Sendable, Equatable {
    public let accountDID: String
    public let identityDID: String
    public let method: IdentityMethod
    public let handle: String
    public let documentDigest: Data?
    public let claimReceiptDigest: Data?
    public let reservedKeyID: String?
    public let lastValidatedAt: Date?
    public let graceExpiresAt: Date?
    public let state: IdentityBindingState

    public init(
        accountDID: String,
        identityDID: String,
        method: IdentityMethod,
        handle: String,
        documentDigest: Data? = nil,
        claimReceiptDigest: Data? = nil,
        reservedKeyID: String? = nil,
        lastValidatedAt: Date? = nil,
        graceExpiresAt: Date? = nil,
        state: IdentityBindingState = .active
    ) throws {
        guard [documentDigest, claimReceiptDigest].compactMap({ $0 }).allSatisfy({ $0.count == 32 }) else {
            throw SwanError.invalidIdentifier("identity binding digest")
        }
        let methodMaterialValid: Bool = switch method {
        case .plc:
            documentDigest == nil && claimReceiptDigest == nil && reservedKeyID == nil
        case .didWeb:
            documentDigest != nil && claimReceiptDigest != nil && reservedKeyID.map { !$0.isEmpty } == true
        }
        guard methodMaterialValid else {
            throw SwanError.invalidIdentifier("PLC identity binding")
        }
        self.accountDID = accountDID
        self.identityDID = identityDID
        self.method = method
        self.handle = handle
        self.documentDigest = documentDigest
        self.claimReceiptDigest = claimReceiptDigest
        self.reservedKeyID = reservedKeyID
        self.lastValidatedAt = lastValidatedAt
        self.graceExpiresAt = graceExpiresAt
        self.state = state
    }

    private enum CodingKeys: String, CodingKey {
        case accountDID, identityDID, method, handle, documentDigest, claimReceiptDigest,
             reservedKeyID, lastValidatedAt, graceExpiresAt, state
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            accountDID: c.decode(String.self, forKey: .accountDID),
            identityDID: c.decode(String.self, forKey: .identityDID),
            method: c.decode(IdentityMethod.self, forKey: .method),
            handle: c.decode(String.self, forKey: .handle),
            documentDigest: c.decodeIfPresent(Data.self, forKey: .documentDigest),
            claimReceiptDigest: c.decodeIfPresent(Data.self, forKey: .claimReceiptDigest),
            reservedKeyID: c.decodeIfPresent(String.self, forKey: .reservedKeyID),
            lastValidatedAt: c.decodeIfPresent(Date.self, forKey: .lastValidatedAt),
            graceExpiresAt: c.decodeIfPresent(Date.self, forKey: .graceExpiresAt),
            state: c.decode(IdentityBindingState.self, forKey: .state)
        )
    }
}

public struct IdentityBindingHistoryEntry: Codable, Sendable, Equatable {
    public let accountDID: String
    public let identityDID: String
    public let documentDigest: Data?
    public let claimReceiptDigest: Data?
    public let reservedKeyID: String?
    public let replacedAt: Date

    public init(accountDID: String, identityDID: String, documentDigest: Data?, claimReceiptDigest: Data?, reservedKeyID: String?, replacedAt: Date) throws {
        guard [documentDigest, claimReceiptDigest].compactMap({ $0 }).allSatisfy({ $0.count == 32 }) else {
            throw SwanError.invalidIdentifier("identity history digest")
        }
        self.accountDID = accountDID
        self.identityDID = identityDID
        self.documentDigest = documentDigest
        self.claimReceiptDigest = claimReceiptDigest
        self.reservedKeyID = reservedKeyID
        self.replacedAt = replacedAt
    }

    private enum CodingKeys: String, CodingKey {
        case accountDID, identityDID, documentDigest, claimReceiptDigest, reservedKeyID, replacedAt
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            accountDID: c.decode(String.self, forKey: .accountDID),
            identityDID: c.decode(String.self, forKey: .identityDID),
            documentDigest: c.decodeIfPresent(Data.self, forKey: .documentDigest),
            claimReceiptDigest: c.decodeIfPresent(Data.self, forKey: .claimReceiptDigest),
            reservedKeyID: c.decodeIfPresent(String.self, forKey: .reservedKeyID),
            replacedAt: c.decode(Date.self, forKey: .replacedAt)
        )
    }
}

public enum DidWebClaimTransactionState: String, Codable, CaseIterable, Sendable {
    case reserved
    case pendingValidation
    case committing
    case committed
    case failed
    case expired
}

public struct DidWebClaimTransaction: Codable, Sendable, Equatable {
    public let requestID: String
    public let accountDID: String?
    public let targetDID: String
    public let handle: String
    public let claimNonceDigest: Data
    public let requestedDocumentDigest: Data?
    public let state: DidWebClaimTransactionState
    public let expiresAt: Date
    public let stepUpReceiptDigest: Data?
    public let reservedKeyID: String?
    public let claimReceiptDigest: Data?

    public init(requestID: String, accountDID: String?, targetDID: String, handle: String, claimNonceDigest: Data, requestedDocumentDigest: Data? = nil, state: DidWebClaimTransactionState = .reserved, expiresAt: Date, stepUpReceiptDigest: Data? = nil, reservedKeyID: String? = nil, claimReceiptDigest: Data? = nil) throws {
        guard !requestID.isEmpty, claimNonceDigest.count == 32,
              requestedDocumentDigest.map({ $0.count == 32 }) ?? true,
              stepUpReceiptDigest.map({ $0.count == 32 }) ?? true,
              claimReceiptDigest.map({ $0.count == 32 }) ?? true else {
            throw SwanError.invalidIdentifier("did:web claim transaction")
        }
        self.requestID = requestID
        self.accountDID = accountDID
        self.targetDID = targetDID
        self.handle = handle
        self.claimNonceDigest = claimNonceDigest
        self.requestedDocumentDigest = requestedDocumentDigest
        self.state = state
        self.expiresAt = expiresAt
        self.stepUpReceiptDigest = stepUpReceiptDigest
        self.reservedKeyID = reservedKeyID
        self.claimReceiptDigest = claimReceiptDigest
    }

    public func transition(to next: DidWebClaimTransactionState, now: Date) throws -> Self {
        guard now < expiresAt || next == .expired else { throw SwanError.expired }
        let valid: Bool
        switch (state, next) {
        case (.reserved, .pendingValidation), (.pendingValidation, .committing),
             (.failed, .pendingValidation), (.failed, .reserved),
             (.committing, .committed), (.reserved, .failed),
             (.pendingValidation, .failed), (.committing, .failed),
             (.reserved, .expired), (.pendingValidation, .expired), (.committing, .expired):
            valid = true
        default: valid = false
        }
        guard valid else { throw SwanError.invalidIdentifier("invalid did:web claim transition") }
        return try Self(
            requestID: requestID, accountDID: accountDID, targetDID: targetDID,
            handle: handle, claimNonceDigest: claimNonceDigest,
            requestedDocumentDigest: requestedDocumentDigest, state: next,
            expiresAt: expiresAt, stepUpReceiptDigest: stepUpReceiptDigest,
            reservedKeyID: reservedKeyID, claimReceiptDigest: claimReceiptDigest
        )
    }

    private enum CodingKeys: String, CodingKey {
        case requestID, accountDID, targetDID, handle, claimNonceDigest, requestedDocumentDigest,
             state, expiresAt, stepUpReceiptDigest, reservedKeyID, claimReceiptDigest
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            requestID: c.decode(String.self, forKey: .requestID),
            accountDID: c.decodeIfPresent(String.self, forKey: .accountDID),
            targetDID: c.decode(String.self, forKey: .targetDID),
            handle: c.decode(String.self, forKey: .handle),
            claimNonceDigest: c.decode(Data.self, forKey: .claimNonceDigest),
            requestedDocumentDigest: c.decodeIfPresent(Data.self, forKey: .requestedDocumentDigest),
            state: c.decode(DidWebClaimTransactionState.self, forKey: .state),
            expiresAt: c.decode(Date.self, forKey: .expiresAt),
            stepUpReceiptDigest: c.decodeIfPresent(Data.self, forKey: .stepUpReceiptDigest),
            reservedKeyID: c.decodeIfPresent(String.self, forKey: .reservedKeyID),
            claimReceiptDigest: c.decodeIfPresent(Data.self, forKey: .claimReceiptDigest)
        )
    }
}

public struct DidWebClaimCommitRequest: Sendable, Equatable {
    public let requestID: String
    public let accountDID: String
    public let targetDID: String
    public let handle: String
    public let documentDigest: Data
    public let reservedKeyID: String
    public let claimNonceDigest: Data
    public let claimReceiptDigest: Data
    public let idempotencyKey: String
    public let identityBinding: IdentityBinding
    /// The issued reservation tuple is carried into the durable claim commit.
    /// SQLite consumes this row in the same transaction as the binding CAS.
    public let reservation: SwanPersistedDidWebReservation?

    public init(transaction: DidWebClaimTransaction, accountDID: String, targetDID: String, handle: String, documentDigest: Data, reservedKeyID: String, claimNonceDigest: Data, claimReceiptDigest: Data, idempotencyKey: String, now: Date, reservation: SwanPersistedDidWebReservation? = nil) throws {
        guard transaction.state == .committing,
              transaction.accountDID == accountDID,
              transaction.targetDID == targetDID,
              transaction.handle == handle,
              transaction.requestedDocumentDigest == documentDigest,
              transaction.reservedKeyID == reservedKeyID,
              transaction.claimNonceDigest == claimNonceDigest,
              transaction.claimReceiptDigest == claimReceiptDigest,
              transaction.requestID == idempotencyKey,
              documentDigest.count == 32, claimNonceDigest.count == 32,
              claimReceiptDigest.count == 32, !reservedKeyID.isEmpty,
              now < transaction.expiresAt else {
            throw SwanError.invalidIdentifier("did:web claim commit")
        }
        if let reservation {
            guard reservation.requestID == idempotencyKey,
                  reservation.accountDID == accountDID,
                  reservation.targetDID == targetDID,
                  reservation.handle == handle,
                  reservation.keyID == reservedKeyID,
                  reservation.nonce.count == 32,
                  Data(SHA256.hash(data: reservation.nonce)) == claimNonceDigest,
                  reservation.claimReceiptDigest == claimReceiptDigest,
                  reservation.claimBytes.isEmpty == false,
                  reservation.state == .issued else {
                throw SwanError.invalidIdentifier("did:web reservation commit tuple")
            }
        }
        self.requestID = transaction.requestID
        self.accountDID = accountDID
        self.targetDID = targetDID
        self.handle = handle
        self.documentDigest = documentDigest
        self.reservedKeyID = reservedKeyID
        self.claimNonceDigest = claimNonceDigest
        self.claimReceiptDigest = claimReceiptDigest
        self.idempotencyKey = idempotencyKey
        self.reservation = reservation
        self.identityBinding = try IdentityBinding(
            accountDID: accountDID,
            identityDID: targetDID,
            method: .didWeb,
            handle: handle,
            documentDigest: documentDigest,
            claimReceiptDigest: claimReceiptDigest,
            reservedKeyID: reservedKeyID,
            lastValidatedAt: now,
            graceExpiresAt: now.addingTimeInterval(86_400)
        )
    }
}

public protocol IdentityBindingStore: Sendable {
    func identityBinding(accountDID: String) async throws -> IdentityBinding?
    func reserveDidWebClaim(_ transaction: DidWebClaimTransaction, now: Date) async throws
    func transitionDidWebClaim(_ transaction: DidWebClaimTransaction, from expected: DidWebClaimTransactionState, now: Date) async throws
    func commitDidWebClaim(_ request: DidWebClaimCommitRequest, history: IdentityBindingHistoryEntry?, now: Date) async throws
    func purgeExpiredIdentityClaims(now: Date) async throws
}

public struct ManagementSessionMetadata: Codable, Sendable, Equatable {
    public let sessionID: ManagementSessionID
    public let accountDID: String
    public let issuedAt: Date
    public let idleExpiresAt: Date
    public let absoluteExpiresAt: Date
    public let lastStepUpAt: Date?
    public let strength: AuthenticationStrength
    public let revokedAt: Date?

    public init(sessionID: ManagementSessionID, accountDID: String, issuedAt: Date, idleExpiresAt: Date, absoluteExpiresAt: Date, lastStepUpAt: Date? = nil, strength: AuthenticationStrength, revokedAt: Date? = nil) throws {
        guard idleExpiresAt >= issuedAt, absoluteExpiresAt >= idleExpiresAt,
              lastStepUpAt.map({ $0 >= issuedAt && $0 <= absoluteExpiresAt }) ?? true,
              revokedAt.map({ $0 >= issuedAt }) ?? true else {
            throw SwanError.invalidIdentifier("management session metadata")
        }
        self.sessionID = sessionID
        self.accountDID = accountDID
        self.issuedAt = issuedAt
        self.idleExpiresAt = idleExpiresAt
        self.absoluteExpiresAt = absoluteExpiresAt
        self.lastStepUpAt = lastStepUpAt
        self.strength = strength
        self.revokedAt = revokedAt
    }

    private enum CodingKeys: String, CodingKey {
        case sessionID, accountDID, issuedAt, idleExpiresAt, absoluteExpiresAt, lastStepUpAt, strength, revokedAt
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            sessionID: c.decode(ManagementSessionID.self, forKey: .sessionID),
            accountDID: c.decode(String.self, forKey: .accountDID),
            issuedAt: c.decode(Date.self, forKey: .issuedAt),
            idleExpiresAt: c.decode(Date.self, forKey: .idleExpiresAt),
            absoluteExpiresAt: c.decode(Date.self, forKey: .absoluteExpiresAt),
            lastStepUpAt: c.decodeIfPresent(Date.self, forKey: .lastStepUpAt),
            strength: c.decode(AuthenticationStrength.self, forKey: .strength),
            revokedAt: c.decodeIfPresent(Date.self, forKey: .revokedAt)
        )
    }
}

public struct LegacySessionFamilyMetadata: Codable, Sendable, Equatable {
    public let familyID: String
    public let accountDID: String
    public let appPasswordID: String?
    public let createdAt: Date
    public let expiresAt: Date
    public let revokedAt: Date?
    public let reuseDetectedAt: Date?

    public init(familyID: String, accountDID: String, appPasswordID: String?, createdAt: Date, expiresAt: Date, revokedAt: Date? = nil, reuseDetectedAt: Date? = nil) throws {
        guard !familyID.isEmpty, expiresAt >= createdAt,
              revokedAt.map({ $0 >= createdAt }) ?? true,
              reuseDetectedAt.map({ $0 >= createdAt }) ?? true,
              reuseDetectedAt.map({ detectedAt in revokedAt.map({ $0 >= detectedAt }) ?? false }) ?? true else {
            throw SwanError.invalidIdentifier("legacy session family metadata")
        }
        self.familyID = familyID
        self.accountDID = accountDID
        self.appPasswordID = appPasswordID
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.revokedAt = revokedAt
        self.reuseDetectedAt = reuseDetectedAt
    }

    private enum CodingKeys: String, CodingKey { case familyID, accountDID, appPasswordID, createdAt, expiresAt, revokedAt, reuseDetectedAt }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            familyID: c.decode(String.self, forKey: .familyID),
            accountDID: c.decode(String.self, forKey: .accountDID),
            appPasswordID: c.decodeIfPresent(String.self, forKey: .appPasswordID),
            createdAt: c.decode(Date.self, forKey: .createdAt),
            expiresAt: c.decode(Date.self, forKey: .expiresAt),
            revokedAt: c.decodeIfPresent(Date.self, forKey: .revokedAt),
            reuseDetectedAt: c.decodeIfPresent(Date.self, forKey: .reuseDetectedAt)
        )
    }
}

public struct LegacySessionMetadata: Codable, Sendable, Equatable {
    public let sessionID: LegacySessionID
    public let familyID: String
    public let accountDID: String
    public let appPasswordID: String?
    public let scopeStrings: Set<String>
    public let issuedAt: Date
    public let expiresAt: Date
    public let revokedAt: Date?

    public init(sessionID: LegacySessionID, familyID: String, accountDID: String, appPasswordID: String?, scopeStrings: Set<String>, issuedAt: Date, expiresAt: Date, revokedAt: Date? = nil, rotatedAt: Date? = nil, replacedByDigest: Data? = nil, previousSessionDigest: Data? = nil, reuseDetectedAt: Date? = nil) throws {
        guard !familyID.isEmpty, expiresAt >= issuedAt,
              [replacedByDigest, previousSessionDigest].compactMap({ $0 }).allSatisfy({ $0.count == 32 }),
              rotatedAt.map({ $0 >= issuedAt }) ?? true,
              reuseDetectedAt.map({ $0 >= issuedAt }) ?? true,
              replacedByDigest == nil || rotatedAt != nil,
              reuseDetectedAt.map({ detectedAt in revokedAt.map({ $0 >= detectedAt }) ?? false }) ?? true else {
            throw SwanError.invalidIdentifier("legacy session metadata")
        }
        self.sessionID = sessionID
        self.familyID = familyID
        self.accountDID = accountDID
        self.appPasswordID = appPasswordID
        self.scopeStrings = scopeStrings
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.revokedAt = revokedAt
        self.rotatedAt = rotatedAt
        self.replacedByDigest = replacedByDigest
        self.previousSessionDigest = previousSessionDigest
        self.reuseDetectedAt = reuseDetectedAt
    }

    public let rotatedAt: Date?
    public let replacedByDigest: Data?
    public let previousSessionDigest: Data?
    public let reuseDetectedAt: Date?

    private enum CodingKeys: String, CodingKey {
        case sessionID, familyID, accountDID, appPasswordID, scopeStrings, issuedAt, expiresAt, revokedAt, rotatedAt, replacedByDigest, previousSessionDigest, reuseDetectedAt
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            sessionID: c.decode(LegacySessionID.self, forKey: .sessionID),
            familyID: c.decode(String.self, forKey: .familyID),
            accountDID: c.decode(String.self, forKey: .accountDID),
            appPasswordID: c.decodeIfPresent(String.self, forKey: .appPasswordID),
            scopeStrings: c.decode(Set<String>.self, forKey: .scopeStrings),
            issuedAt: c.decode(Date.self, forKey: .issuedAt),
            expiresAt: c.decode(Date.self, forKey: .expiresAt),
            revokedAt: c.decodeIfPresent(Date.self, forKey: .revokedAt),
            rotatedAt: c.decodeIfPresent(Date.self, forKey: .rotatedAt),
            replacedByDigest: c.decodeIfPresent(Data.self, forKey: .replacedByDigest),
            previousSessionDigest: c.decodeIfPresent(Data.self, forKey: .previousSessionDigest),
            reuseDetectedAt: c.decodeIfPresent(Date.self, forKey: .reuseDetectedAt)
        )
    }
}

public struct AppPasswordMetadata: Codable, Sendable, Equatable {
    public let id: String
    public let accountDID: String
    public let canonicalName: String
    public let scopeStrings: Set<String>
    public let secretDigest: Data
    public let createdAt: Date
    public let lastUsedAt: Date?
    public let revokedAt: Date?

    public init(id: String, accountDID: String, canonicalName: String, scopeStrings: Set<String>, secretDigest: Data, createdAt: Date, lastUsedAt: Date? = nil, revokedAt: Date? = nil) throws {
        guard !id.isEmpty, !canonicalName.isEmpty, secretDigest.count == 32,
              lastUsedAt.map({ $0 >= createdAt }) ?? true,
              revokedAt.map({ $0 >= createdAt }) ?? true else { throw SwanError.invalidIdentifier("app-password metadata") }
        self.id = id
        self.accountDID = accountDID
        self.canonicalName = canonicalName
        self.scopeStrings = scopeStrings
        self.secretDigest = secretDigest
        self.createdAt = createdAt
        self.lastUsedAt = lastUsedAt
        self.revokedAt = revokedAt
    }

    private enum CodingKeys: String, CodingKey { case id, accountDID, canonicalName, scopeStrings, secretDigest, createdAt, lastUsedAt, revokedAt }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            id: c.decode(String.self, forKey: .id),
            accountDID: c.decode(String.self, forKey: .accountDID),
            canonicalName: c.decode(String.self, forKey: .canonicalName),
            scopeStrings: c.decode(Set<String>.self, forKey: .scopeStrings),
            secretDigest: c.decode(Data.self, forKey: .secretDigest),
            createdAt: c.decode(Date.self, forKey: .createdAt),
            lastUsedAt: c.decodeIfPresent(Date.self, forKey: .lastUsedAt),
            revokedAt: c.decodeIfPresent(Date.self, forKey: .revokedAt)
        )
    }
}

public protocol ManagementSessionStore: Sendable {
    func createManagementSession(_ session: ManagementSessionMetadata, sessionDigest: Data, csrfDigest: Data, now: Date) async throws
    func managementSession(digest: Data, now: Date) async throws -> ManagementSessionMetadata?
    func revokeManagementSession(digest: Data, now: Date) async throws
    func revokeOtherManagementSessions(accountDID: String, except sessionID: ManagementSessionID, now: Date) async throws
    func purgeExpiredManagementSessions(now: Date) async throws
}

/// Durable one-time state used before an account-management session exists.
/// The browser only receives the bearer value; implementations persist its
/// keyed digest and must consume it atomically.
public protocol SwanManagementPreAuthStore: Sendable {
    func put(digest: Data, expiresAt: Date) async
    func contains(digest: Data, now: Date) async -> Bool
    func take(digest: Data, now: Date) async -> Bool
}

/// Durable double-submit CSRF state for management sessions. Implementations
/// must retain only the digest and compare it in constant time at the runtime
/// boundary.
public protocol SwanManagementCSRFStore: Sendable {
    func put(sessionDigest: Data, csrfDigest: Data) async throws
    func digest(for sessionDigest: Data) async throws -> Data?
    func remove(sessionDigest: Data) async throws
}

/// Atomic bridge used by login and signup: pre-auth consumption and
/// management-session creation must share one durable transaction so a race or
/// failed consume cannot leave an orphaned authenticated session.
public protocol SwanManagementPreAuthSessionCoordinator: Sendable {
    func consumePreAuthAndCreateManagementSession(
        preAuthDigest: Data,
        session: ManagementSessionMetadata,
        sessionDigest: Data,
        csrfDigest: Data,
        now: Date
    ) async throws -> Bool
}

public protocol LegacySessionStore: Sendable {
    func createLegacySessionFamily(_ family: LegacySessionFamilyMetadata, session: LegacySessionMetadata, sessionDigest: Data, now: Date) async throws
    func legacySession(digest: Data, now: Date) async throws -> LegacySessionMetadata?
    func rotateOrRevokeFamilyOnReuse(_ request: LegacySessionRotationRequest) async throws -> LegacySessionRotationOutcome
    func revokeLegacySessionFamily(familyID: String, now: Date) async throws
    func purgeExpiredLegacySessions(now: Date) async throws
}

public struct AuthenticationFactorMetadata: Codable, Sendable, Equatable {
    public let id: String
    public let accountDID: String
    public let kind: AuthenticationFactorKind
    public let label: String
    public let lookupDigest: Data
    public let createdAt: Date
    public let lastUsedAt: Date?
    public let disabledAt: Date?

    public init(id: String, accountDID: String, kind: AuthenticationFactorKind, label: String, lookupDigest: Data, createdAt: Date, lastUsedAt: Date? = nil, disabledAt: Date? = nil) throws {
        guard !id.isEmpty, !label.isEmpty, lookupDigest.count == 32,
              lastUsedAt.map({ $0 >= createdAt }) ?? true,
              disabledAt.map({ $0 >= createdAt }) ?? true else { throw SwanError.invalidIdentifier("factor metadata") }
        self.id = id
        self.accountDID = accountDID
        self.kind = kind
        self.label = label
        self.lookupDigest = lookupDigest
        self.createdAt = createdAt
        self.lastUsedAt = lastUsedAt
        self.disabledAt = disabledAt
    }

    private enum CodingKeys: String, CodingKey { case id, accountDID, kind, label, lookupDigest, createdAt, lastUsedAt, disabledAt }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            id: c.decode(String.self, forKey: .id),
            accountDID: c.decode(String.self, forKey: .accountDID),
            kind: c.decode(AuthenticationFactorKind.self, forKey: .kind),
            label: c.decode(String.self, forKey: .label),
            lookupDigest: c.decode(Data.self, forKey: .lookupDigest),
            createdAt: c.decode(Date.self, forKey: .createdAt),
            lastUsedAt: c.decodeIfPresent(Date.self, forKey: .lastUsedAt),
            disabledAt: c.decodeIfPresent(Date.self, forKey: .disabledAt)
        )
    }
}

public enum FactorChallengePurpose: String, Codable, CaseIterable, Sendable {
    case enrollment
    case assertion
    case stepUp
}

public struct FactorChallenge: Codable, Sendable, Equatable {
    public let challengeDigest: Data
    public let accountDID: String
    public let factorID: String?
    public let purpose: FactorChallengePurpose
    public let issuedAt: Date
    public let expiresAt: Date
    public let consumedAt: Date?

    public init(challengeDigest: Data, accountDID: String, factorID: String? = nil, purpose: FactorChallengePurpose, issuedAt: Date, expiresAt: Date, consumedAt: Date? = nil) throws {
        guard challengeDigest.count == 32, expiresAt >= issuedAt,
              consumedAt.map({ $0 >= issuedAt }) ?? true else { throw SwanError.invalidIdentifier("factor challenge") }
        self.challengeDigest = challengeDigest
        self.accountDID = accountDID
        self.factorID = factorID
        self.purpose = purpose
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.consumedAt = consumedAt
    }

    private enum CodingKeys: String, CodingKey { case challengeDigest, accountDID, factorID, purpose, issuedAt, expiresAt, consumedAt }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            challengeDigest: c.decode(Data.self, forKey: .challengeDigest),
            accountDID: c.decode(String.self, forKey: .accountDID),
            factorID: c.decodeIfPresent(String.self, forKey: .factorID),
            purpose: c.decode(FactorChallengePurpose.self, forKey: .purpose),
            issuedAt: c.decode(Date.self, forKey: .issuedAt),
            expiresAt: c.decode(Date.self, forKey: .expiresAt),
            consumedAt: c.decodeIfPresent(Date.self, forKey: .consumedAt)
        )
    }
}

public protocol AuthenticationFactorStore: Sendable {
    func listFactors(accountDID: String, now: Date) async throws -> [AuthenticationFactorMetadata]
    func saveFactor(_ factor: AuthenticationFactorMetadata, now: Date) async throws
    func disableFactor(id: String, accountDID: String, now: Date) async throws
    func reserveChallenge(_ challenge: FactorChallenge, now: Date) async throws
    func consumeChallenge(digest: Data, now: Date) async throws -> FactorChallenge
    func purgeExpiredFactorState(now: Date) async throws
}

/// TOTP storage is an encrypted envelope contract only. The control database
/// never receives the seed or a decryption key; the factor service owns that
/// boundary and supplies the envelope to an external key store.
public struct TOTPSecretEnvelope: Codable, Sendable, Equatable {
    public let factorID: String
    public let keyReference: String
    public let nonce: Data
    public let ciphertext: Data
    public let authenticationTag: Data

    public init(factorID: String, keyReference: String, nonce: Data, ciphertext: Data, authenticationTag: Data) throws {
        guard !factorID.isEmpty, !keyReference.isEmpty,
              nonce.count == 12, !ciphertext.isEmpty, authenticationTag.count == 16 else {
            throw SwanError.invalidIdentifier("TOTP encrypted envelope")
        }
        self.factorID = factorID
        self.keyReference = keyReference
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.authenticationTag = authenticationTag
    }

    private enum CodingKeys: String, CodingKey { case factorID, keyReference, nonce, ciphertext, authenticationTag }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            factorID: c.decode(String.self, forKey: .factorID),
            keyReference: c.decode(String.self, forKey: .keyReference),
            nonce: c.decode(Data.self, forKey: .nonce),
            ciphertext: c.decode(Data.self, forKey: .ciphertext),
            authenticationTag: c.decode(Data.self, forKey: .authenticationTag)
        )
    }
}

public struct RecoveryCodeDigest: Codable, Sendable, Equatable {
    public let accountDID: String
    public let digest: Data
    public let issuedAt: Date
    public let consumedAt: Date?

    public init(accountDID: String, digest: Data, issuedAt: Date, consumedAt: Date? = nil) throws {
        guard digest.count == 32, consumedAt.map({ $0 >= issuedAt }) ?? true else { throw SwanError.invalidIdentifier("recovery code digest") }
        self.accountDID = accountDID
        self.digest = digest
        self.issuedAt = issuedAt
        self.consumedAt = consumedAt
    }

    private enum CodingKeys: String, CodingKey { case accountDID, digest, issuedAt, consumedAt }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            accountDID: c.decode(String.self, forKey: .accountDID),
            digest: c.decode(Data.self, forKey: .digest),
            issuedAt: c.decode(Date.self, forKey: .issuedAt),
            consumedAt: c.decodeIfPresent(Date.self, forKey: .consumedAt)
        )
    }
}

public struct WebAuthnCredentialMetadata: Codable, Sendable, Equatable {
    public let credentialIDDigest: Data
    public let accountDID: String
    public let factorID: String
    public let publicKeyReference: String
    public let signCount: UInt32
    public let transports: Set<String>
    public let createdAt: Date
    public let lastUsedAt: Date?
    public let disabledAt: Date?

    public init(credentialIDDigest: Data, accountDID: String, factorID: String, publicKeyReference: String, signCount: UInt32 = 0, transports: Set<String> = [], createdAt: Date, lastUsedAt: Date? = nil, disabledAt: Date? = nil) throws {
        guard credentialIDDigest.count == 32, !factorID.isEmpty, !publicKeyReference.isEmpty,
              lastUsedAt.map({ $0 >= createdAt }) ?? true,
              disabledAt.map({ $0 >= createdAt }) ?? true else {
            throw SwanError.invalidIdentifier("WebAuthn credential")
        }
        self.credentialIDDigest = credentialIDDigest
        self.accountDID = accountDID
        self.factorID = factorID
        self.publicKeyReference = publicKeyReference
        self.signCount = signCount
        self.transports = transports
        self.createdAt = createdAt
        self.lastUsedAt = lastUsedAt
        self.disabledAt = disabledAt
    }

    private enum CodingKeys: String, CodingKey { case credentialIDDigest, accountDID, factorID, publicKeyReference, signCount, transports, createdAt, lastUsedAt, disabledAt }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            credentialIDDigest: c.decode(Data.self, forKey: .credentialIDDigest),
            accountDID: c.decode(String.self, forKey: .accountDID),
            factorID: c.decode(String.self, forKey: .factorID),
            publicKeyReference: c.decode(String.self, forKey: .publicKeyReference),
            signCount: c.decode(UInt32.self, forKey: .signCount),
            transports: c.decode(Set<String>.self, forKey: .transports),
            createdAt: c.decode(Date.self, forKey: .createdAt),
            lastUsedAt: c.decodeIfPresent(Date.self, forKey: .lastUsedAt),
            disabledAt: c.decodeIfPresent(Date.self, forKey: .disabledAt)
        )
    }
}

/// A WebAuthn assertion challenge is retained separately from generic factor
/// challenges so the adapter can bind RP ID/origin and (when appropriate) a
/// credential without persisting the challenge bytes themselves.
public struct WebAuthnChallenge: Codable, Sendable, Equatable {
    public let challengeDigest: Data
    public let accountDID: String
    public let credentialIDDigest: Data?
    public let relyingPartyID: String
    public let origin: String
    public let issuedAt: Date
    public let expiresAt: Date
    public let consumedAt: Date?

    public init(
        challengeDigest: Data,
        accountDID: String,
        credentialIDDigest: Data? = nil,
        relyingPartyID: String,
        origin: String,
        issuedAt: Date,
        expiresAt: Date,
        consumedAt: Date? = nil
    ) throws {
        guard challengeDigest.count == 32,
              credentialIDDigest.map({ $0.count == 32 }) ?? true,
              !relyingPartyID.isEmpty,
              !origin.isEmpty,
              expiresAt >= issuedAt,
              consumedAt.map({ $0 >= issuedAt }) ?? true else {
            throw SwanError.invalidIdentifier("WebAuthn challenge")
        }
        self.challengeDigest = challengeDigest
        self.accountDID = accountDID
        self.credentialIDDigest = credentialIDDigest
        self.relyingPartyID = relyingPartyID
        self.origin = origin
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.consumedAt = consumedAt
    }

    private enum CodingKeys: String, CodingKey { case challengeDigest, accountDID, credentialIDDigest, relyingPartyID, origin, issuedAt, expiresAt, consumedAt }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            challengeDigest: c.decode(Data.self, forKey: .challengeDigest),
            accountDID: c.decode(String.self, forKey: .accountDID),
            credentialIDDigest: c.decodeIfPresent(Data.self, forKey: .credentialIDDigest),
            relyingPartyID: c.decode(String.self, forKey: .relyingPartyID),
            origin: c.decode(String.self, forKey: .origin),
            issuedAt: c.decode(Date.self, forKey: .issuedAt),
            expiresAt: c.decode(Date.self, forKey: .expiresAt),
            consumedAt: c.decodeIfPresent(Date.self, forKey: .consumedAt)
        )
    }
}

public enum WebAuthnSignCountUpdateOutcome: Sendable, Equatable {
    case updated(newCount: UInt32)
    case rollbackDetected(storedCount: UInt32)
}

public struct WebAuthnSignCountUpdate: Sendable, Equatable {
    public let credentialIDDigest: Data
    public let accountDID: String
    public let expectedCurrent: UInt32
    public let proposed: UInt32
    public let now: Date

    public init(credentialIDDigest: Data, accountDID: String, expectedCurrent: UInt32, proposed: UInt32, now: Date) throws {
        guard credentialIDDigest.count == 32, proposed > expectedCurrent else {
            throw SwanError.invalidIdentifier("WebAuthn sign-count update")
        }
        self.credentialIDDigest = credentialIDDigest
        self.accountDID = accountDID
        self.expectedCurrent = expectedCurrent
        self.proposed = proposed
        self.now = now
    }
}

public protocol TOTPSecretStore: Sendable {
    func saveTOTPEnvelope(_ envelope: TOTPSecretEnvelope, now: Date) async throws
    func totpEnvelope(factorID: String, accountDID: String) async throws -> TOTPSecretEnvelope?
    func deleteTOTPEnvelope(factorID: String, accountDID: String, now: Date) async throws
}

public protocol RecoveryCodeStore: Sendable {
    func replaceRecoveryCodeDigests(accountDID: String, digests: [RecoveryCodeDigest], now: Date) async throws
    func consumeRecoveryCode(digest: Data, accountDID: String, now: Date) async throws -> RecoveryCodeDigest
}

public protocol WebAuthnCredentialStore: Sendable {
    func saveWebAuthnCredential(_ credential: WebAuthnCredentialMetadata, now: Date) async throws
    func webAuthnCredential(credentialIDDigest: Data, accountDID: String, now: Date) async throws -> WebAuthnCredentialMetadata?
    func compareAndSwapWebAuthnSignCount(_ update: WebAuthnSignCountUpdate) async throws -> WebAuthnSignCountUpdateOutcome
    func disableWebAuthnCredential(credentialIDDigest: Data, accountDID: String, now: Date) async throws
}

public struct LegacySessionRotationOutcome: Sendable, Equatable {
    public enum Kind: Sendable, Equatable {
        case rotated
        case reuseDetectedAndFamilyRevoked
    }

    public let kind: Kind
    public let sessionID: LegacySessionID?
    public let familyID: String?
    public let detectedAt: Date?
    public let revokedAt: Date?

    private init(kind: Kind, sessionID: LegacySessionID?, familyID: String?, detectedAt: Date?, revokedAt: Date?) {
        self.kind = kind
        self.sessionID = sessionID
        self.familyID = familyID
        self.detectedAt = detectedAt
        self.revokedAt = revokedAt
    }

    public static func rotated(sessionID: LegacySessionID) -> Self {
        Self(kind: .rotated, sessionID: sessionID, familyID: nil, detectedAt: nil, revokedAt: nil)
    }

    public static func reuseDetectedAndFamilyRevoked(familyID: String, detectedAt: Date, revokedAt: Date) throws -> Self {
        guard !familyID.isEmpty, revokedAt >= detectedAt else {
            throw SwanError.invalidIdentifier("legacy reuse revocation ordering")
        }
        return Self(kind: .reuseDetectedAndFamilyRevoked, sessionID: nil, familyID: familyID, detectedAt: detectedAt, revokedAt: revokedAt)
    }
}

public struct LegacySessionRotationRequest: Sendable, Equatable {
    public let oldDigest: Data
    public let replacement: LegacySessionMetadata
    public let replacementDigest: Data
    public let now: Date

    public init(oldDigest: Data, replacement: LegacySessionMetadata, replacementDigest: Data, now: Date) throws {
        guard oldDigest.count == 32, replacementDigest.count == 32 else { throw SwanError.invalidIdentifier("legacy rotation digest") }
        self.oldDigest = oldDigest
        self.replacement = replacement
        self.replacementDigest = replacementDigest
        self.now = now
    }
}

public protocol WebAuthnChallengeStore: Sendable {
    func reserveWebAuthnChallenge(_ challenge: WebAuthnChallenge, now: Date) async throws
    func consumeWebAuthnChallenge(digest: Data, accountDID: String, now: Date) async throws -> WebAuthnChallenge
}
