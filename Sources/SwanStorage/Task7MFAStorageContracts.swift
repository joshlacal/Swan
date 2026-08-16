import Foundation
import SwanCore

/// Durable replay state for TOTP. Implementations must perform the compare
/// and swap in the same transaction as the accepted counter update.
public protocol TOTPReplayStore: Sendable {
    func compareAndSwapTOTPReplay(factorID: String, accountDID: String, expected: UInt64?, proposed: UInt64, now: Date) async throws -> Bool
}

public protocol WebAuthnChallengeLookupStore: WebAuthnChallengeStore {
    func webAuthnChallenge(digest: Data, accountDID: String, now: Date) async throws -> WebAuthnChallenge?
}

public protocol WebAuthnAtomicVerificationStore: WebAuthnChallengeLookupStore {
    func compareAndSwapWebAuthnSignCountAndConsumeChallenge(_ update: WebAuthnSignCountUpdate, challengeDigest: Data, now: Date) async throws -> WebAuthnSignCountUpdateOutcome
}

public protocol WebAuthnEnrollmentStore: WebAuthnChallengeLookupStore {
    func consumeEnrollmentChallengeAndSaveCredential(challengeDigest: Data, accountDID: String, credential: WebAuthnCredentialMetadata, now: Date) async throws
}

public struct DurableFactorTokenRecord: Codable, Sendable, Equatable {
    public let digest: Data
    public let accountDID: String
    public let sessionID: String
    public let purpose: String
    public let factor: AuthenticationFactorKind
    public let strength: AuthenticationStrength
    public let issuedAt: Date
    public let expiresAt: Date

    public init(digest: Data, accountDID: String, sessionID: String, purpose: String, factor: AuthenticationFactorKind, strength: AuthenticationStrength, issuedAt: Date, expiresAt: Date) throws {
        guard digest.count == 32, !accountDID.isEmpty, !sessionID.isEmpty, !purpose.isEmpty, expiresAt > issuedAt else { throw SwanError.invalidIdentifier("factor token") }
        self.digest = digest; self.accountDID = accountDID; self.sessionID = sessionID; self.purpose = purpose; self.factor = factor; self.strength = strength; self.issuedAt = issuedAt; self.expiresAt = expiresAt
    }
}

public protocol DurableFactorTokenStore: Sendable {
    func saveFactorToken(_ record: DurableFactorTokenRecord, now: Date) async throws
    func consumeFactorToken(digest: Data, accountDID: String, sessionID: String, purpose: String, factor: AuthenticationFactorKind, strength: AuthenticationStrength, now: Date) async throws -> DurableFactorTokenRecord
    func revokeFactorTokens(accountDID: String, sessionID: String?, now: Date) async throws
}

public protocol MFAAuditStore: Sendable {
    func appendMFAAuditEvent(_ event: MFAAuditEventRecord, now: Date) async throws
}

public struct MFAAuditEventRecord: Codable, Sendable, Equatable {
    public let event: String
    public let accountDID: String
    public let factorID: String?
    public let success: Bool
    public let occurredAt: Date

    public init(event: String, accountDID: String, factorID: String? = nil, success: Bool, occurredAt: Date) throws {
        guard !event.isEmpty, !accountDID.isEmpty, event.utf8.count <= 64, factorID.map({ $0.utf8.count <= 128 }) ?? true else { throw SwanError.invalidIdentifier("MFA audit event") }
        self.event = event; self.accountDID = accountDID; self.factorID = factorID; self.success = success; self.occurredAt = occurredAt
    }
}
