import Foundation
import SwanCore

/// Canonical account-login seam for a durable factor token. The account
/// directory remains the sole password/authentication authority; this narrow
/// adapter only validates a factor token after password verification and
/// returns the typed authentication strength it earned.
public protocol AccountLoginFactorTokenVerifying: Sendable {
    func verifyLoginFactorToken(
        token: String,
        accountDID: String,
        now: Date
    ) async throws -> AuthenticationStrength
}

/// Management-portal login adds the pre-auth session binding to the opaque
/// factor receipt. OAuth/legacy callers retain the account-only capability
/// above because they do not have a management-session cookie at this
/// boundary; the portal uses this narrower capability when it does.
public protocol AccountLoginFactorTokenSessionVerifying: AccountLoginFactorTokenVerifying {
    func verifyLoginFactorToken(
        token: String,
        accountDID: String,
        sessionID: String,
        now: Date
    ) async throws -> AuthenticationStrength
}

/// The login grant boundary used by production directories.  Implementations
/// consume the opaque receipt and re-check the active-factor policy in one
/// durable transaction, so activation/revocation cannot race the grant.
public protocol AccountLoginFactorTokenAtomicVerifying: AccountLoginFactorTokenSessionVerifying {
    func verifyLoginFactorTokenAtomically(token: String, accountDID: String, now: Date) async throws -> AuthenticationStrength
    func verifyLoginFactorTokenAtomically(token: String, accountDID: String, sessionID: String, now: Date) async throws -> AuthenticationStrength
}

/// The credential channel is part of a factor receipt's authority.  A receipt
/// minted for an OAuth browser transaction must never be consumable by the
/// account portal or the bearer legacy session surface, even when the account
/// and factor happen to match.
public enum AccountAuthorizationChannel: String, Codable, Sendable, Equatable {
    case account
    case portal
    case oauth
    case legacy
}

/// Exact browser/request binding carried to the durable login-grant store.
/// Digests are used for CSRF/request material so the control database never
/// needs to retain browser bearer values or raw request URIs.
public struct AccountAuthorizationContext: Codable, Sendable, Equatable {
    public let channel: AccountAuthorizationChannel
    public let sessionID: String
    public let csrfDigest: Data?
    public let clientID: String?
    public let requestDigest: Data?
    /// The exact receipt purpose is part of the authorization capability. It
    /// is intentionally not inferred from a channel at consumption time:
    /// recovery and login receipts share account/session storage but must not
    /// cross-authorize one another.
    public let purpose: String

    public init(
        channel: AccountAuthorizationChannel,
        sessionID: String,
        csrfDigest: Data? = nil,
        clientID: String? = nil,
        requestDigest: Data? = nil,
        purpose: String = "managementLogin"
    ) throws {
        guard !sessionID.isEmpty, sessionID.utf8.count <= 512,
              !sessionID.utf8.contains(0),
              csrfDigest.map({ $0.count == 32 }) ?? true,
              clientID.map({ !$0.isEmpty && $0.utf8.count <= 4_096 && !$0.utf8.contains(0) }) ?? true,
              requestDigest.map({ $0.count == 32 }) ?? true,
              ["managementLogin", "oauthToken", "loginRecovery"].contains(purpose) else {
            throw SwanError.invalidIdentifier("authorization context")
        }
        if channel == .oauth {
            guard purpose == "oauthToken", csrfDigest != nil, clientID != nil, requestDigest != nil else {
                throw SwanError.invalidIdentifier("OAuth authorization context")
            }
        }
        self.channel = channel
        self.sessionID = sessionID
        self.csrfDigest = csrfDigest
        self.clientID = clientID
        self.requestDigest = requestDigest
        self.purpose = purpose
    }
}

/// A short-lived, one-time authorization capability.  Only its digest is
/// persisted; callers retain the opaque value long enough to complete the
/// corresponding session/code/family issuance operation.
public struct AccountAuthorizationGrant: Codable, Sendable, Equatable {
    public let grantDigest: Data
    public let accountDID: String
    public let context: AccountAuthorizationContext
    public let factorRevision: Int64
    public let strength: AuthenticationStrength
    public let issuedAt: Date
    public let expiresAt: Date

    public init(
        grantDigest: Data,
        accountDID: String,
        context: AccountAuthorizationContext,
        factorRevision: Int64,
        strength: AuthenticationStrength,
        issuedAt: Date,
        expiresAt: Date
    ) throws {
        guard grantDigest.count == 32, !accountDID.isEmpty,
              factorRevision >= 0, expiresAt > issuedAt else {
            throw SwanError.invalidIdentifier("authorization grant")
        }
        self.grantDigest = grantDigest
        self.accountDID = accountDID
        self.context = context
        self.factorRevision = factorRevision
        self.strength = strength
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
    }
}

/// The SQLite authority used by authentication and every protected issuance
/// path.  Implementations must perform the active-factor/revision decision and
/// grant insertion in one transaction.
public protocol AccountAuthorizationGrantStore: Sendable {
    func createPasswordAuthorizationGrant(
        grantDigest: Data,
        accountDID: String,
        context: AccountAuthorizationContext,
        now: Date
    ) async throws -> AccountAuthorizationGrant

    func consumeAuthorizationGrant(
        grantDigest: Data,
        accountDID: String,
        context: AccountAuthorizationContext,
        now: Date
    ) async throws -> AccountAuthorizationGrant

    func factorRevision(accountDID: String, now: Date) async throws -> Int64
}

/// Channel-aware factor login.  The old account-only verifier remains for
/// source compatibility, but production login callers use this stricter seam.
public protocol AccountLoginAuthorizationGrantVerifying: Sendable {
    func authorizeLoginWithFactorToken(
        token: String,
        accountDID: String,
        context: AccountAuthorizationContext,
        now: Date
    ) async throws -> AccountAuthorizationGrant
}

/// Password-admitted OAuth phase. The browser may render/submit a factor form
/// only while this exact request/session/CSRF tuple is live. It is separate
/// from the one-time login grant because a phase can be consumed before proof
/// work begins without exposing a reusable authorization capability.
public struct OAuthMFAAdmission: Sendable, Equatable {
    public let accountDID: String
    public let context: AccountAuthorizationContext
    public let factorRevision: Int64
    public let issuedAt: Date
    public let expiresAt: Date

    public init(
        accountDID: String,
        context: AccountAuthorizationContext,
        factorRevision: Int64,
        issuedAt: Date,
        expiresAt: Date
    ) {
        self.accountDID = accountDID
        self.context = context
        self.factorRevision = factorRevision
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
    }
}

public protocol OAuthMFAAdmissionStore: Sendable {
    func beginOAuthMFAAdmission(
        accountDID: String,
        context: AccountAuthorizationContext,
        now: Date
    ) async throws -> OAuthMFAAdmission

    func consumeOAuthMFAAdmission(
        accountDID: String,
        context: AccountAuthorizationContext,
        now: Date
    ) async throws -> OAuthMFAAdmission
}

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
    public let factorID: String
    public let strength: AuthenticationStrength
    public let issuedAt: Date
    public let expiresAt: Date
    public let channel: AccountAuthorizationChannel
    public let bindingDigest: Data?
    public let clientID: String?
    public let requestDigest: Data?

    public init(
        digest: Data,
        accountDID: String,
        sessionID: String,
        purpose: String,
        factor: AuthenticationFactorKind,
        factorID: String,
        strength: AuthenticationStrength,
        issuedAt: Date,
        expiresAt: Date,
        channel: AccountAuthorizationChannel = .account,
        bindingDigest: Data? = nil,
        clientID: String? = nil,
        requestDigest: Data? = nil
    ) throws {
        guard digest.count == 32, !accountDID.isEmpty, !sessionID.isEmpty, !purpose.isEmpty, !factorID.isEmpty, factorID.utf8.count <= 128, expiresAt > issuedAt else { throw SwanError.invalidIdentifier("factor token") }
        guard bindingDigest.map({ $0.count == 32 }) ?? true,
              requestDigest.map({ $0.count == 32 }) ?? true,
              clientID.map({ !$0.isEmpty && $0.utf8.count <= 4_096 && !$0.utf8.contains(0) }) ?? true else {
            throw SwanError.invalidIdentifier("factor token binding")
        }
        self.digest = digest; self.accountDID = accountDID; self.sessionID = sessionID; self.purpose = purpose; self.factor = factor; self.factorID = factorID; self.strength = strength; self.issuedAt = issuedAt; self.expiresAt = expiresAt
        self.channel = channel; self.bindingDigest = bindingDigest; self.clientID = clientID; self.requestDigest = requestDigest
    }
}

public protocol DurableFactorTokenStore: Sendable {
    func saveFactorToken(_ record: DurableFactorTokenRecord, now: Date) async throws
    func consumeFactorToken(digest: Data, accountDID: String, sessionID: String, purpose: String, factor: AuthenticationFactorKind, factorID: String, strength: AuthenticationStrength, now: Date) async throws -> DurableFactorTokenRecord
    func consumeFactorTokenForStepUp(digest: Data, accountDID: String, sessionID: String, now: Date) async throws -> DurableFactorTokenRecord
    func consumeFactorTokenForLogin(digest: Data, accountDID: String, now: Date) async throws -> DurableFactorTokenRecord
    func consumeFactorTokenForLogin(digest: Data, accountDID: String, sessionID: String, now: Date) async throws -> DurableFactorTokenRecord
    func revokeFactorTokens(accountDID: String, sessionID: String?, now: Date) async throws
}

public protocol DurableFactorTokenAuthorizationStore: DurableFactorTokenStore, AccountAuthorizationGrantStore {
    func consumeFactorTokenForLoginAndAuthorize(digest: Data, accountDID: String, now: Date) async throws -> DurableFactorTokenRecord
    func consumeFactorTokenForLoginAndAuthorize(digest: Data, accountDID: String, sessionID: String, now: Date) async throws -> DurableFactorTokenRecord
    func consumeFactorTokenForLoginAndCreateGrant(
        digest: Data,
        accountDID: String,
        context: AccountAuthorizationContext,
        grantDigest: Data,
        now: Date
    ) async throws -> AccountAuthorizationGrant
}

public extension DurableFactorTokenAuthorizationStore {
    func consumeFactorTokenForLoginAndAuthorize(digest: Data, accountDID: String, sessionID: String, now: Date) async throws -> DurableFactorTokenRecord {
        try await consumeFactorTokenForLogin(digest: digest, accountDID: accountDID, sessionID: sessionID, now: now)
    }
    func consumeFactorTokenForLoginAndAuthorize(digest: Data, accountDID: String, now: Date) async throws -> DurableFactorTokenRecord {
        try await consumeFactorTokenForLogin(digest: digest, accountDID: accountDID, now: now)
    }
}

public extension DurableFactorTokenStore {
    /// Session-bound login consumption is deliberately fail-closed for older
    /// adapters. Production SQLite supplies the atomic implementation; a
    /// fixture that has not opted into the binding must not silently widen a
    /// portal token to account-only authority.
    func consumeFactorTokenForLogin(
        digest: Data,
        accountDID: String,
        sessionID: String,
        now: Date
    ) async throws -> DurableFactorTokenRecord {
        throw AccountControlStoreError.notFound
    }
}

public extension DurableFactorTokenStore {
    func consumeFactorTokenForStepUp(
        digest: Data,
        accountDID: String,
        sessionID: String,
        now: Date
    ) async throws -> DurableFactorTokenRecord {
        throw AccountControlStoreError.notFound
    }
}

public extension DurableFactorTokenStore {
    /// Login validation intentionally has no request-supplied factor/session
    /// metadata to trust. Stores that support the production account-program
    /// runtime atomically consume a token from the narrow login-purpose set;
    /// older focused fixtures retain a fail-closed default.
    func consumeFactorTokenForLogin(
        digest: Data,
        accountDID: String,
        now: Date
    ) async throws -> DurableFactorTokenRecord {
        throw AccountControlStoreError.notFound
    }
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
