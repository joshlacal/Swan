import Foundation
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
        guard method == .didWeb || (documentDigest == nil && claimReceiptDigest == nil && reservedKeyID == nil) else {
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

    public init(requestID: String, accountDID: String?, targetDID: String, handle: String, claimNonceDigest: Data, requestedDocumentDigest: Data? = nil, state: DidWebClaimTransactionState = .reserved, expiresAt: Date, stepUpReceiptDigest: Data? = nil) throws {
        guard !requestID.isEmpty, claimNonceDigest.count == 32,
              requestedDocumentDigest.map({ $0.count == 32 }) ?? true,
              stepUpReceiptDigest.map({ $0.count == 32 }) ?? true else {
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
    }
}

public protocol IdentityBindingStore: Sendable {
    func identityBinding(accountDID: String) async throws -> IdentityBinding?
    func reserveDidWebClaim(_ transaction: DidWebClaimTransaction, now: Date) async throws
    func updateDidWebClaim(_ transaction: DidWebClaimTransaction, now: Date) async throws
    func commitIdentityBinding(_ binding: IdentityBinding, history: IdentityBindingHistoryEntry?, transaction: DidWebClaimTransaction, now: Date) async throws
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

    public init(sessionID: ManagementSessionID, accountDID: String, issuedAt: Date, idleExpiresAt: Date, absoluteExpiresAt: Date, lastStepUpAt: Date? = nil, strength: AuthenticationStrength, revokedAt: Date? = nil) {
        self.sessionID = sessionID
        self.accountDID = accountDID
        self.issuedAt = issuedAt
        self.idleExpiresAt = idleExpiresAt
        self.absoluteExpiresAt = absoluteExpiresAt
        self.lastStepUpAt = lastStepUpAt
        self.strength = strength
        self.revokedAt = revokedAt
    }
}

public struct LegacySessionFamilyMetadata: Codable, Sendable, Equatable {
    public let familyID: String
    public let accountDID: String
    public let appPasswordID: String?
    public let createdAt: Date
    public let expiresAt: Date
    public let revokedAt: Date?
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
        guard secretDigest.count == 32 else { throw SwanError.invalidIdentifier("app-password digest") }
        self.id = id
        self.accountDID = accountDID
        self.canonicalName = canonicalName
        self.scopeStrings = scopeStrings
        self.secretDigest = secretDigest
        self.createdAt = createdAt
        self.lastUsedAt = lastUsedAt
        self.revokedAt = revokedAt
    }
}

public protocol ManagementSessionStore: Sendable {
    func createManagementSession(_ session: ManagementSessionMetadata, sessionDigest: Data, csrfDigest: Data, now: Date) async throws
    func managementSession(digest: Data, now: Date) async throws -> ManagementSessionMetadata?
    func revokeManagementSession(digest: Data, now: Date) async throws
    func revokeOtherManagementSessions(accountDID: String, except sessionID: ManagementSessionID, now: Date) async throws
    func purgeExpiredManagementSessions(now: Date) async throws
}

public protocol LegacySessionStore: Sendable {
    func createLegacySessionFamily(_ family: LegacySessionFamilyMetadata, session: LegacySessionMetadata, sessionDigest: Data, now: Date) async throws
    func legacySession(digest: Data, now: Date) async throws -> LegacySessionMetadata?
    func rotateLegacySession(oldDigest: Data, replacement: LegacySessionMetadata, replacementDigest: Data, now: Date) async throws
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
        guard lookupDigest.count == 32 else { throw SwanError.invalidIdentifier("factor lookup digest") }
        self.id = id
        self.accountDID = accountDID
        self.kind = kind
        self.label = label
        self.lookupDigest = lookupDigest
        self.createdAt = createdAt
        self.lastUsedAt = lastUsedAt
        self.disabledAt = disabledAt
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
        guard challengeDigest.count == 32, expiresAt >= issuedAt else { throw SwanError.invalidIdentifier("factor challenge") }
        self.challengeDigest = challengeDigest
        self.accountDID = accountDID
        self.factorID = factorID
        self.purpose = purpose
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.consumedAt = consumedAt
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
}

public struct RecoveryCodeDigest: Codable, Sendable, Equatable {
    public let accountDID: String
    public let digest: Data
    public let issuedAt: Date
    public let consumedAt: Date?

    public init(accountDID: String, digest: Data, issuedAt: Date, consumedAt: Date? = nil) throws {
        guard digest.count == 32 else { throw SwanError.invalidIdentifier("recovery code digest") }
        self.accountDID = accountDID
        self.digest = digest
        self.issuedAt = issuedAt
        self.consumedAt = consumedAt
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
        guard credentialIDDigest.count == 32, !factorID.isEmpty, !publicKeyReference.isEmpty else {
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
              expiresAt >= issuedAt else {
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
    func updateWebAuthnSignCount(credentialIDDigest: Data, accountDID: String, signCount: UInt32, now: Date) async throws
    func disableWebAuthnCredential(credentialIDDigest: Data, accountDID: String, now: Date) async throws
}

public protocol WebAuthnChallengeStore: Sendable {
    func reserveWebAuthnChallenge(_ challenge: WebAuthnChallenge, now: Date) async throws
    func consumeWebAuthnChallenge(digest: Data, accountDID: String, now: Date) async throws -> WebAuthnChallenge
}
