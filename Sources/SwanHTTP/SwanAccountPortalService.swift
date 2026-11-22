import Crypto
import Foundation
import SwanAccounts
import SwanCore
import SwanStorage

/// Stable failures from the account portal domain boundary. The HTTP adapter
/// intentionally maps these without exposing storage, token, or credential
/// details.
public enum SwanAccountPortalServiceError: Error, Sendable, Equatable {
    case unauthorized
    case forbidden
    case rateLimited
    case notFound
    case invalidRequest
    case unavailable
    case unsupported
}

/// The account-directory seam is deliberately narrow. Production composition
/// supplies ``DurableAccountDirectory``; tests may use a rejecting implementation
/// without manufacturing account state or credentials.
public protocol SwanAccountPortalAccountDirectory: Sendable {
    func account(did: String) async throws -> AccountControlAccount?
    func resolve(handle: String) async throws -> AccountControlAccount?
    func authenticateForLogin(handle: String, password: String, now: Date) async throws -> AccountLoginAuthenticationOutcome
}

extension DurableAccountDirectory: SwanAccountPortalAccountDirectory {}

/// The public account endpoints use the same durable admission bucket as
/// OAuth and legacy login. HTTP obtains the accepted socket peer and invokes
/// this seam before the directory performs Argon2 or an MFA challenge.
public protocol SwanAccountPortalLoginAdmissionDirectory: SwanAccountPortalAccountDirectory {
    func admitLogin(handle: String, directPeer: String, now: Date) async throws -> AccountLoginAdmissionDecision
}

extension DurableAccountDirectory: SwanAccountPortalLoginAdmissionDirectory {}

public protocol SwanAccountPortalLoginAdmissionServing: Sendable {
    func admitLogin(handle: String, directPeer: String, now: Date) async throws -> AccountLoginAdmissionDecision
}

/// Optional extension of the canonical directory seam used when the account
/// program has composed durable MFA. Keeping it separate preserves the narrow
/// test/integration directory contract while making a presented factor token
/// an explicit capability check rather than an ignored field.
public protocol SwanAccountPortalFactorTokenAccountDirectory: SwanAccountPortalAccountDirectory {
    func authenticateForLogin(
        handle: String,
        password: String,
        authFactorToken: String?,
        now: Date
    ) async throws -> AccountLoginAuthenticationOutcome
}

extension DurableAccountDirectory: SwanAccountPortalFactorTokenAccountDirectory {}

/// The management portal binds its factor receipt to the pre-auth session
/// that issued the ceremony. This is additive to the canonical account-only
/// login seam used by OAuth and legacy callers.
public protocol SwanAccountPortalSessionBoundFactorTokenAccountDirectory: SwanAccountPortalFactorTokenAccountDirectory {
    func authenticateForLogin(
        handle: String,
        password: String,
        authFactorToken: String?,
        authFactorSessionID: String?,
        now: Date
    ) async throws -> AccountLoginAuthenticationOutcome
}

extension DurableAccountDirectory: SwanAccountPortalSessionBoundFactorTokenAccountDirectory {}

/// Password half of the two-step login ceremony. It deliberately does not
/// create a session; the caller must complete an active factor and present
/// the resulting management-login token to the canonical login endpoint.
public protocol SwanAccountPortalMFAChallengeAccountDirectory: SwanAccountPortalAccountDirectory {
    func authenticatePasswordForMFAChallenge(
        handle: String,
        password: String,
        now: Date
    ) async throws -> AccountLoginAuthenticationOutcome
}

extension DurableAccountDirectory: SwanAccountPortalMFAChallengeAccountDirectory {}

/// Production login callers carry the exact browser/request binding into the
/// canonical directory. This keeps OAuth's one-time grant authority out of
/// the older account-only fixture seam.
public protocol SwanAccountPortalAuthorizationGrantAccountDirectory: SwanAccountPortalAccountDirectory {
    func authenticateForLogin(
        handle: String,
        password: String,
        authFactorToken: String?,
        authorizationContext: AccountAuthorizationContext,
        now: Date
    ) async throws -> AccountLoginAuthenticationOutcome

    func authenticateFactorForLogin(
        accountDID: String,
        authFactorToken: String,
        authorizationContext: AccountAuthorizationContext,
        now: Date
    ) async throws -> AccountLoginAuthenticationOutcome
}

extension DurableAccountDirectory: SwanAccountPortalAuthorizationGrantAccountDirectory {}

/// Portal mutations for factor enrollment, assertion verification, recovery
/// rotation, and factor-token issuance. The portal service owns management
/// session/account binding; this capability owns only the additive MFA
/// services and their durable factor store.
public protocol SwanAccountPortalMFAService: Sendable {
    func mutate(
        path: String,
        accountDID: String,
        sessionID: String,
        strength: AuthenticationStrength,
        expectedRevision: Int64?,
        payload: Data?,
        now: Date
    ) async throws -> SwanAccountPortalMutation
}

public extension SwanAccountPortalMFAService {
    /// Source-compatible convenience for callers that do not participate in
    /// the revision-bound factor-mutation discipline (OAuth proofs, fixtures).
    func mutate(
        path: String,
        accountDID: String,
        sessionID: String,
        strength: AuthenticationStrength,
        payload: Data?,
        now: Date
    ) async throws -> SwanAccountPortalMutation {
        try await mutate(
            path: path,
            accountDID: accountDID,
            sessionID: sessionID,
            strength: strength,
            expectedRevision: nil,
            payload: payload,
            now: now
        )
    }
}

/// Optional production-only MFA seam for OAuth. Its context is durable and
/// channel-specific; callers cannot accidentally reuse a portal/account
/// receipt by selecting a different form endpoint.
public protocol SwanAccountPortalOAuthMFAService: SwanAccountPortalMFAService {
    func mutateOAuth(
        path: String,
        accountDID: String,
        sessionID: String,
        authorizationContext: AccountAuthorizationContext,
        payload: Data?,
        now: Date
    ) async throws -> SwanAccountPortalMutation
}

/// OAuth owns the browser ceremony, while this adapter owns only the durable
/// factor proof and canonical one-time management-login receipt.  Keeping the
/// two operations separate makes it impossible for an OAuth form to ask the
/// account portal for (or accept) a portal-issued bearer value.
public protocol SwanOAuthMFAService: Sendable {
    func beginOAuthFactor(accountDID: String, sessionID: String, factorID: String?, now: Date) async throws -> SwanAccountPortalMutation
    func verifyOAuthFactor(accountDID: String, sessionID: String, payload: Data?, now: Date) async throws -> SwanAccountPortalMutation
    func beginOAuthFactor(accountDID: String, sessionID: String, context: AccountAuthorizationContext, factorID: String?, now: Date) async throws -> SwanAccountPortalMutation
    func verifyOAuthFactor(accountDID: String, sessionID: String, context: AccountAuthorizationContext, payload: Data?, now: Date) async throws -> SwanAccountPortalMutation
}

public extension SwanOAuthMFAService {
    /// Context-aware overloads preserve source compatibility for fixtures but
    /// give production adapters a strict channel/request binding seam.
    func beginOAuthFactor(accountDID: String, sessionID: String, context: AccountAuthorizationContext, factorID: String?, now: Date) async throws -> SwanAccountPortalMutation {
        try await beginOAuthFactor(accountDID: accountDID, sessionID: sessionID, factorID: factorID, now: now)
    }

    func verifyOAuthFactor(accountDID: String, sessionID: String, context: AccountAuthorizationContext, payload: Data?, now: Date) async throws -> SwanAccountPortalMutation {
        try await verifyOAuthFactor(accountDID: accountDID, sessionID: sessionID, payload: payload, now: now)
    }
}

/// Small composition adapter used when OAuth is assembled before the portal
/// facade. It deliberately delegates both proof operations to the same MFA
/// service and factor store; it does not create an alternate token authority.
public struct SwanOAuthMFAServiceAdapter: SwanOAuthMFAService, Sendable {
    private let factors: any AuthenticationFactorStore
    private let mfa: any SwanAccountPortalMFAService
    // Keep the refined OAuth capability before existential erasure. A value
    // stored only as `any SwanAccountPortalMFAService` cannot be dynamically
    // cast back to its protocol refinement, which would silently select the
    // legacy account-purpose token path.
    private let oauthMFA: (any SwanAccountPortalOAuthMFAService)?

    public init(factors: any AuthenticationFactorStore, mfa: any SwanAccountPortalMFAService) {
        self.factors = factors
        self.mfa = mfa
        self.oauthMFA = nil
    }

    public init(factors: any AuthenticationFactorStore, mfa: any SwanAccountPortalOAuthMFAService) {
        self.factors = factors
        self.mfa = mfa
        self.oauthMFA = mfa
    }

    public init(factors: any AuthenticationFactorStore, oauthMFA: any SwanAccountPortalOAuthMFAService) {
        self.factors = factors
        self.mfa = oauthMFA
        self.oauthMFA = oauthMFA
    }

    public func beginOAuthFactor(accountDID: String, sessionID: String, factorID: String?, now: Date) async throws -> SwanAccountPortalMutation {
        let active = try await factors.listFactors(accountDID: accountDID, now: now)
        guard let factor = factorID.flatMap({ id in active.first(where: { $0.id == id }) })
                ?? active.first(where: { $0.kind == .passkey })
                ?? active.first(where: { $0.kind == .totp })
                ?? active.first(where: { $0.kind == .recoveryCode }) else {
            throw SwanAccountPortalServiceError.unauthorized
        }
        if factor.kind == .passkey {
            return try await mfa.mutate(
                path: "factors/passkeys/step-up-challenge", accountDID: accountDID,
                sessionID: sessionID, strength: .password,
                payload: try JSONSerialization.data(withJSONObject: ["factorID": factor.id]), now: now)
        }
        return .init(message: "Authentication factor proof required", accountDID: accountDID, factorID: factor.id, factorKind: factor.kind)
    }

    public func beginOAuthFactor(accountDID: String, sessionID: String, context: AccountAuthorizationContext, factorID: String?, now: Date) async throws -> SwanAccountPortalMutation {
        if let admission = factors as? any OAuthMFAAdmissionStore {
            _ = try await admission.beginOAuthMFAAdmission(accountDID: accountDID, context: context, now: now)
        }
        let active = try await factors.listFactors(accountDID: accountDID, now: now)
        guard let factor = factorID.flatMap({ id in active.first(where: { $0.id == id }) })
                ?? active.first(where: { $0.kind == .passkey })
                ?? active.first(where: { $0.kind == .totp })
                ?? active.first(where: { $0.kind == .recoveryCode }) else {
            throw SwanAccountPortalServiceError.unauthorized
        }
        if let contextual = oauthMFA ?? (mfa as? any SwanAccountPortalOAuthMFAService) {
            if factor.kind == .passkey {
                return try await contextual.mutateOAuth(path: "factors/passkeys/step-up-challenge", accountDID: accountDID, sessionID: sessionID, authorizationContext: context, payload: try JSONSerialization.data(withJSONObject: ["factorID": factor.id]), now: now)
            }
            return .init(message: "Authentication factor proof required", accountDID: accountDID, factorID: factor.id, factorKind: factor.kind)
        }
        return try await beginOAuthFactor(accountDID: accountDID, sessionID: sessionID, factorID: factorID, now: now)
    }

    public func verifyOAuthFactor(accountDID: String, sessionID: String, payload: Data?, now: Date) async throws -> SwanAccountPortalMutation {
        try await mfa.mutate(path: "factors/login", accountDID: accountDID, sessionID: sessionID, strength: .password, payload: payload, now: now)
    }

    public func verifyOAuthFactor(accountDID: String, sessionID: String, context: AccountAuthorizationContext, payload: Data?, now: Date) async throws -> SwanAccountPortalMutation {
        if let admission = factors as? any OAuthMFAAdmissionStore {
            // Consume the password-admitted phase before any factor proof
            // work. A direct POST, a replay, or a stale factor revision never
            // reaches TOTP/WebAuthn verification.
            _ = try await admission.consumeOAuthMFAAdmission(accountDID: accountDID, context: context, now: now)
        }
        if let contextual = oauthMFA ?? (mfa as? any SwanAccountPortalOAuthMFAService) {
            return try await contextual.mutateOAuth(path: "factors/login", accountDID: accountDID, sessionID: sessionID, authorizationContext: context, payload: payload, now: now)
        }
        return try await verifyOAuthFactor(accountDID: accountDID, sessionID: sessionID, payload: payload, now: now)
    }
}

/// OAuth projections are supplied by the durable OAuth composition. The
/// projection contains no bearer tokens and mutations are bound to the
/// management session supplied by the portal adapter.
public protocol SwanAccountPortalOAuthProjection: Sendable {
    func connectedApps(accountDID: String, now: Date) async throws -> [SwanAccountPortalSnapshot.App]
    func revokeConnectedApp(accountDID: String, appID: String, sessionID: String, stepUpToken: String?, now: Date) async throws
}

/// Identity projections are supplied by the durable did:web/PLC composition.
/// The facade does not synthesize identity state when that capability is absent.
public protocol SwanAccountPortalIdentityProjection: Sendable {
    func identity(accountDID: String, now: Date) async throws -> SwanAccountPortalSnapshot.Identity?
    func mutateIdentity(path: String, accountDID: String, sessionID: String, strength: AuthenticationStrength, stepUpToken: String?, payload: Data?, now: Date) async throws
}

/// The portal never treats a bearer string as proof of step-up. Route
/// composition supplies a durable verifier for the receipt echoed by the
/// browser, while tests can inject a one-time verifier without manufacturing
/// database state.
public protocol SwanAccountPortalStepUpReceiptVerifying: Sendable {
    func verifyStepUpReceipt(
        sessionID: String,
        accountDID: String,
        receipt: String,
        strength: AuthenticationStrength,
        now: Date
    ) async throws -> Bool
}

/// Operations that consume a management step-up receipt before a portal
/// mutation. The value is persisted in the receipt row and is part of the
/// atomic SQLite predicate; a receipt issued for identity replacement cannot
/// authorize an app-password operation (or vice versa).
public enum SwanAccountPortalStepUpOperation: String, Sendable, Equatable {
    case createAppPassword = "app-passwords.create"
    case revokeAppPassword = "app-passwords.revoke"
}

/// A durable receipt was absent, expired, already consumed, or bound to a
/// different account/session/operation. This deliberately exposes no storage
/// detail to the HTTP adapter.
public enum SwanAccountPortalStepUpReceiptError: Error, Sendable, Equatable {
    case rejected
}

/// The one-time consumer used by portal mutations. This is intentionally a
/// different capability from the read-only verifier used by did:web's
/// replacement pre-check: app-password mutations have no enclosing identity
/// transaction, so they must consume the receipt at their own linearization
/// point before invoking the canonical app-password store.
public protocol SwanAccountPortalStepUpReceiptConsuming: Sendable {
    func consumeStepUpReceipt(
        sessionID: String,
        accountDID: String,
        operation: SwanAccountPortalStepUpOperation,
        strength: AuthenticationStrength,
        now: Date,
        receipt: String
    ) async throws
}

/// Adapter from the canonical identity-store receipt verifier to the portal
/// boundary. The store only sees a keyed digest and the typed session
/// strength; plaintext receipt values remain at the HTTP/service boundary.
public struct SwanAccountPortalDurableStepUpReceiptVerifier:
    SwanAccountPortalStepUpReceiptVerifying, Sendable
{
    private let verifier: any SwanIdentityStepUpReceiptVerifying

    public init(verifier: any SwanIdentityStepUpReceiptVerifying) {
        self.verifier = verifier
    }

    public func verifyStepUpReceipt(
        sessionID: String,
        accountDID: String,
        receipt: String,
        strength: AuthenticationStrength,
        now: Date
    ) async throws -> Bool {
        guard let mfaStrength = Self.storageStrength(for: strength),
              !receipt.isEmpty else { return false }
        let digest = Data(SHA256.hash(data: Data(receipt.utf8)))
        return try await verifier.verifyIdentityStepUpReceipt(
            sessionID: sessionID,
            accountDID: accountDID,
            mfaStrength: mfaStrength,
            receiptDigest: digest,
            now: now
        )
    }

    fileprivate static func storageStrength(for strength: AuthenticationStrength) -> String? {
        switch strength {
        case .stepUpPassword:
            return "stepUpPassword"
        case let .stepUpMFA(base, _):
            return "stepUpMFA:\(base.rawValue)"
        default:
            return nil
        }
    }
}

/// Durable adapter for portal mutations. SQLite performs a single conditional
/// `UPDATE ... RETURNING` over the exact account/session/operation/strength
/// tuple, so sequential and concurrent reuse of one receipt cannot both pass.
/// The receipt is consumed before the app-password write; if that later write
/// fails, the user must obtain a fresh step-up receipt rather than receiving a
/// reusable authorization after a partial failure.
public struct SwanAccountPortalDurableStepUpReceiptConsumer:
    SwanAccountPortalStepUpReceiptConsuming, Sendable
{
    private let store: any SwanIdentityStepUpReceiptStore

    public init(store: any SwanIdentityStepUpReceiptStore) {
        self.store = store
    }

    public func consumeStepUpReceipt(
        sessionID: String,
        accountDID: String,
        operation: SwanAccountPortalStepUpOperation,
        strength: AuthenticationStrength,
        now: Date,
        receipt: String
    ) async throws {
        guard !receipt.isEmpty,
              let mfaStrength = SwanAccountPortalDurableStepUpReceiptVerifier.storageStrength(for: strength),
              let verifiedAt = Self.verifiedAt(for: strength),
              verifiedAt <= now else {
            throw SwanAccountPortalStepUpReceiptError.rejected
        }
        let digest = Data(SHA256.hash(data: Data(receipt.utf8)))
        do {
            try await store.consumeIdentityStepUpReceipt(
                sessionID: sessionID,
                accountDID: accountDID,
                operation: operation.rawValue,
                mfaStrength: mfaStrength,
                verifiedAt: verifiedAt,
                expiresAt: verifiedAt.addingTimeInterval(300),
                receiptDigest: digest,
                now: now
            )
        } catch {
            // The caller must not distinguish a missing/replayed receipt from
            // a mismatched operation or account. All such failures fail closed
            // at the portal boundary.
            throw SwanAccountPortalStepUpReceiptError.rejected
        }
    }

    private static func verifiedAt(for strength: AuthenticationStrength) -> Date? {
        switch strength {
        case let .stepUpPassword(verifiedAt), let .stepUpMFA(_, verifiedAt):
            return verifiedAt
        default:
            return nil
        }
    }
}

/// Production implementation of ``SwanAccountPortalServing``. Every read and
/// mutation crosses a durable service boundary; absent capabilities fail closed
/// with a typed error instead of falling back to process memory.
public protocol SwanAccountPortalManagementLoginServing: SwanAccountPortalServing {
    func managementLoginFactor(
        handle: String,
        password: String,
        sessionID: String,
        payload: Data?,
        challengeOnly: Bool,
        now: Date
    ) async throws -> SwanAccountPortalMutation
}

/// HTTP login can supply the pre-auth CSRF value as the management-factor
/// session binding without changing the source-compatible portal protocol.
public protocol SwanAccountPortalSessionBoundAuthenticationServing: SwanAccountPortalServing {
    func authenticate(
        handle: String,
        password: String,
        authFactorToken: String?,
        authFactorSessionID: String?,
        now: Date
    ) async throws -> SwanAccountPortalAuthentication
}

public struct SwanAccountPortalService: SwanAccountPortalManagementLoginServing, SwanAccountPortalSessionBoundAuthenticationServing, SwanAccountPortalLoginAdmissionServing, Sendable {
    private let accountDirectory: any SwanAccountPortalAccountDirectory
    private let accountStore: (any AccountControlStore)?
    private let appPasswords: (any AppPasswordStore)?
    private let appPasswordCredentials: AppPasswordCredentials?
    private let factors: (any AuthenticationFactorStore)?
    private let lifecycle: AccountLifecycleService?
    private let identity: (any SwanAccountPortalIdentityProjection)?
    private let oauth: (any SwanAccountPortalOAuthProjection)?
    private let mfa: (any SwanAccountPortalMFAService)?
    private let factorTokens: FactorTokenService?
    private let stepUpReceiptConsumer: (any SwanAccountPortalStepUpReceiptConsuming)?
    private let sessions: SwanManagementSessionRuntime
    private let legacySessions: (any LegacySessionStore)?

    public init(
        accountDirectory: any SwanAccountPortalAccountDirectory,
        accountStore: (any AccountControlStore)? = nil,
        appPasswords: (any AppPasswordStore)? = nil,
        appPasswordCredentials: AppPasswordCredentials? = nil,
        factors: (any AuthenticationFactorStore)? = nil,
        lifecycle: AccountLifecycleService? = nil,
        identity: (any SwanAccountPortalIdentityProjection)? = nil,
        oauth: (any SwanAccountPortalOAuthProjection)? = nil,
        mfa: (any SwanAccountPortalMFAService)? = nil,
        factorTokens: FactorTokenService? = nil,
        stepUpReceiptVerifier: (any SwanAccountPortalStepUpReceiptVerifying)? = nil,
        stepUpReceiptConsumer: (any SwanAccountPortalStepUpReceiptConsuming)? = nil,
        sessions: SwanManagementSessionRuntime,
        legacySessions: (any LegacySessionStore)? = nil
    ) {
        self.accountDirectory = accountDirectory
        self.accountStore = accountStore
        self.appPasswords = appPasswords
        self.appPasswordCredentials = appPasswordCredentials
        self.factors = factors
        self.lifecycle = lifecycle
        self.identity = identity
        self.oauth = oauth
        self.mfa = mfa
        self.factorTokens = factorTokens
        // Kept as a source-compatible argument for callers that still pass
        // the former read-only verifier. Mutating app-password operations use
        // the operation-bound consumer below; retaining the verifier here
        // would make it look authoritative despite its inability to consume.
        _ = stepUpReceiptVerifier
        self.stepUpReceiptConsumer = stepUpReceiptConsumer
        self.sessions = sessions
        self.legacySessions = legacySessions
    }

    public func bootstrap(now: Date) async throws -> SwanAccountPortalBootstrap {
        let csrf = await sessions.issuePreAuth(now: now)
        return SwanAccountPortalBootstrap(csrf: csrf)
    }

    public func admitLogin(
        handle: String,
        directPeer: String,
        now: Date
    ) async throws -> AccountLoginAdmissionDecision {
        guard let directory = accountDirectory as? any SwanAccountPortalLoginAdmissionDirectory else {
            throw AccountLoginAdmissionError.unavailable
        }
        return try await directory.admitLogin(handle: handle, directPeer: directPeer, now: now)
    }

    /// Start the OAuth-owned second-factor ceremony using the same durable MFA
    /// runtime as the account portal.  The returned value contains only
    /// server-generated ceremony material and metadata; no token is exposed to
    /// the browser at this stage.
    public func beginOAuthFactor(
        accountDID: String,
        sessionID: String,
        factorID: String? = nil,
        now: Date
    ) async throws -> SwanAccountPortalMutation {
        guard let factors, let mfa else { throw SwanAccountPortalServiceError.unsupported }
        let active: [AuthenticationFactorMetadata]
        do { active = try await factors.listFactors(accountDID: accountDID, now: now) }
        catch { throw SwanAccountPortalServiceError.unavailable }
        guard let factor = factorID.flatMap({ id in active.first(where: { $0.id == id && $0.disabledAt == nil }) })
                ?? active.first(where: { $0.disabledAt == nil && $0.kind == .passkey })
                ?? active.first(where: { $0.disabledAt == nil && $0.kind == .totp })
                ?? active.first(where: { $0.disabledAt == nil && $0.kind == .recoveryCode }) else {
            throw SwanAccountPortalServiceError.unauthorized
        }
        do {
            switch factor.kind {
            case .passkey:
                return try await mfa.mutate(path: "factors/passkeys/step-up-challenge", accountDID: accountDID, sessionID: sessionID, strength: .password, payload: try Self.json(["factorID": factor.id]), now: now)
            case .totp, .recoveryCode:
        return .init(message: "Authentication factor proof required", accountDID: accountDID, factorID: factor.id, factorKind: factor.kind)
            }
        } catch { throw Self.mapDomainError(error) }
    }

    /// Complete an OAuth-owned proof and issue a canonical, session-bound
    /// management-login receipt.  Callers receive the receipt only as an
    /// in-process hand-off to the account directory.
    public func verifyOAuthFactor(
        accountDID: String,
        sessionID: String,
        payload: Data?,
        now: Date
    ) async throws -> SwanAccountPortalMutation {
        guard let mfa else { throw SwanAccountPortalServiceError.unsupported }
        do {
            return try await mfa.mutate(path: "factors/login", accountDID: accountDID, sessionID: sessionID, strength: .password, payload: payload, now: now)
        } catch { throw Self.mapDomainError(error) }
    }

    private static func json(_ value: [String: String]) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    }

    public func authenticate(
        handle: String,
        password: String,
        authFactorToken: String?,
        now: Date
    ) async throws -> SwanAccountPortalAuthentication {
        try await authenticate(
            handle: handle,
            password: password,
            authFactorToken: authFactorToken,
            authFactorSessionID: nil,
            now: now
        )
    }

    public func authenticate(
        handle: String,
        password: String,
        authFactorToken: String?,
        authFactorSessionID: String?,
        now: Date
    ) async throws -> SwanAccountPortalAuthentication {
        do {
            let outcome: AccountLoginAuthenticationOutcome
            if let authFactorSessionID {
                // Production portal login binds the one-time authorization
                // grant to the pre-auth session that issued the factor
                // ceremony. The grant is consumed by the session-insert
                // transaction at issuance (Finding 2 carry-forward).
                guard let grantDirectory = accountDirectory as? any SwanAccountPortalAuthorizationGrantAccountDirectory else {
                    throw SwanAccountPortalServiceError.unavailable
                }
                let context = try AccountAuthorizationContext(
                    channel: .portal,
                    sessionID: authFactorSessionID,
                    purpose: "managementLogin"
                )
                outcome = try await grantDirectory.authenticateForLogin(
                    handle: handle,
                    password: password,
                    authFactorToken: authFactorToken,
                    authorizationContext: context,
                    now: now
                )
                switch outcome {
                case let .authenticated(result):
                    guard result.account.status.authorizesAccount else {
                        throw SwanAccountPortalServiceError.unauthorized
                    }
                    return SwanAccountPortalAuthentication(
                        accountDID: result.account.did,
                        strength: result.strength,
                        authorizationGrantDigest: result.authorizationGrantDigest,
                        authorizationContext: context
                    )
                case .rejected:
                    throw SwanAccountPortalServiceError.unauthorized
                }
            }
            if authFactorToken != nil {
                if let factorDirectory = accountDirectory as? any SwanAccountPortalFactorTokenAccountDirectory {
                    // Non-production fixtures may expose only the canonical
                    // account-bound adapter. Production composition always
                    // supplies the session-bound DurableAccountDirectory.
                    outcome = try await factorDirectory.authenticateForLogin(
                        handle: handle,
                        password: password,
                        authFactorToken: authFactorToken,
                        now: now
                    )
                } else {
                    // Do not let a caller turn an unsupported token field into
                    // a password-only management session.
                    throw SwanAccountPortalServiceError.unauthorized
                }
            } else {
                outcome = try await accountDirectory.authenticateForLogin(
                    handle: handle,
                    password: password,
                    now: now
                )
            }
            switch outcome {
            case let .authenticated(result):
                guard result.account.status.authorizesAccount else {
                    throw SwanAccountPortalServiceError.unauthorized
                }
                return SwanAccountPortalAuthentication(accountDID: result.account.did, strength: result.strength)
            case .rejected:
                throw SwanAccountPortalServiceError.unauthorized
            }
        } catch let error as SwanAccountPortalServiceError {
            throw error
        } catch is AccountLoginAuthenticationError {
            throw SwanAccountPortalServiceError.unavailable
        } catch {
            throw SwanAccountPortalServiceError.unavailable
        }
    }

    /// Issues either a server-generated passkey challenge or a one-time
    /// management-login factor token after the password half has succeeded.
    /// The account directory remains the only password authority.
    public func managementLoginFactor(
        handle: String,
        password: String,
        sessionID: String,
        payload: Data?,
        challengeOnly: Bool,
        now: Date
    ) async throws -> SwanAccountPortalMutation {
        guard let directory = accountDirectory as? any SwanAccountPortalMFAChallengeAccountDirectory,
              let mfa else {
            throw SwanAccountPortalServiceError.unsupported
        }
        let outcome: AccountLoginAuthenticationOutcome
        do {
            outcome = try await directory.authenticatePasswordForMFAChallenge(
                handle: handle,
                password: password,
                now: now
            )
        } catch is AccountLoginAuthenticationError {
            throw SwanAccountPortalServiceError.unavailable
        } catch {
            throw SwanAccountPortalServiceError.unavailable
        }
        guard case let .authenticated(result) = outcome,
              result.account.status.authorizesAccount else {
            throw SwanAccountPortalServiceError.unauthorized
        }
        let path = challengeOnly ? "factors/passkeys/step-up-challenge" : "factors/login"
        do {
            return try await mfa.mutate(
                path: path,
                accountDID: result.account.did,
                sessionID: sessionID,
                strength: .password,
                payload: payload,
                now: now
            )
        } catch {
            throw Self.mapDomainError(error)
        }
    }

    /// Re-authenticates the account password and upgrades the existing
    /// management session with a fresh password verification timestamp. This
    /// is the only password-strength bootstrap for the first factor; callers
    /// cannot turn an old 30-day session into a fresh mutation proof.
    private func passwordReauthenticate(
        account: AccountControlAccount,
        sessionValue: String,
        password: String,
        now: Date
    ) async throws -> SwanAccountPortalMutation {
        let outcome: AccountLoginAuthenticationOutcome
        do {
            outcome = try await accountDirectory.authenticateForLogin(
                handle: account.canonicalHandle,
                password: password,
                now: now
            )
        } catch is AccountLoginAuthenticationError {
            throw SwanAccountPortalServiceError.unauthorized
        } catch {
            throw SwanAccountPortalServiceError.unavailable
        }
        guard case let .authenticated(result) = outcome,
              result.account.did == account.did,
              result.strength == .password,
              result.account.status.authorizesAccount else {
            throw SwanAccountPortalServiceError.unauthorized
        }
        do {
            _ = try await sessions.upgradeFromPasswordReauth(
                sessionValue: sessionValue,
                accountDID: account.did,
                now: now
            )
        } catch {
            throw Self.mapDomainError(error)
        }
        return .init(message: "Password reauthentication accepted", accountDID: account.did)
    }

    public func portal(accountDID: String, currentSessionID: String? = nil, now: Date = Date()) async throws -> SwanAccountPortalSnapshot {
        let account: AccountControlAccount
        do {
            guard let resolved = try await accountDirectory.account(did: accountDID) else {
                throw SwanAccountPortalServiceError.notFound
            }
            account = resolved
        } catch let error as SwanAccountPortalServiceError {
            throw error
        } catch {
            throw SwanAccountPortalServiceError.unavailable
        }
        guard account.status.authorizesAccount else { throw SwanAccountPortalServiceError.unauthorized }

        let email: String?
        do {
            email = try await accountStore?.verifiedEmail(did: account.did)?.value
        } catch {
            throw SwanAccountPortalServiceError.unavailable
        }

        let identity: SwanAccountPortalSnapshot.Identity?
        do {
            identity = try await self.identity?.identity(accountDID: account.did, now: now)
        } catch {
            throw SwanAccountPortalServiceError.unavailable
        }

        let factorValues: [[String: String]]
        if let factors {
            do {
                factorValues = try await factors.listFactors(accountDID: account.did, now: now).map {
                    ["id": $0.id, "kind": $0.kind.rawValue, "label": $0.label, "enabled": $0.disabledAt == nil ? "true" : "false"]
                }
            } catch {
                throw SwanAccountPortalServiceError.unavailable
            }
        } else {
            factorValues = []
        }

        let passwords: [SwanAccountPortalSnapshot.Password]
        if let appPasswords {
            do {
                passwords = try await appPasswords.listAppPasswords(did: account.did).map {
                    .init(
                        name: $0.name,
                        scopes: $0.scopes.split(separator: " ").map(String.init).sorted(),
                        createdAt: Self.iso8601($0.createdAt),
                        // The canonical public record deliberately does not
                        // expose credential-use timestamps.
                        lastUsedAt: nil
                    )
                }
            } catch {
                throw SwanAccountPortalServiceError.unavailable
            }
        } else {
            passwords = []
        }

        let apps: [SwanAccountPortalSnapshot.App]
        if let oauth {
            do { apps = try await oauth.connectedApps(accountDID: account.did, now: now) }
            catch { throw SwanAccountPortalServiceError.unavailable }
        } else {
            apps = []
        }

        // Management sessions: digest-derived stable identifiers, never
        // bearer values. The presenting session is marked `current`.
        var sessionRows: [SwanAccountPortalSnapshot.Session] = []
        do {
            let management = try await self.sessions.managementSessions(
                accountDID: account.did, now: now
            )
            sessionRows += management.map { metadata in
                SwanAccountPortalSnapshot.Session(
                    id: metadata.sessionID.rawValue,
                    label: "Swan management session",
                    kind: "management",
                    lastSeen: Self.iso8601(metadata.lastStepUpAt ?? metadata.issuedAt),
                    current: metadata.sessionID.rawValue == currentSessionID
                )
            }
        } catch {
            throw SwanAccountPortalServiceError.unavailable
        }
        if let legacySessions {
            do {
                let families = try await legacySessions.legacySessionFamilies(
                    did: account.did, now: now
                )
                sessionRows += families.map { family in
                    SwanAccountPortalSnapshot.Session(
                        id: family.familyID,
                        label: family.appPasswordID.map { "App password \($0)" } ?? "Full legacy access",
                        kind: "legacy",
                        lastSeen: Self.iso8601(family.createdAt),
                        current: false
                    )
                }
            } catch {
                throw SwanAccountPortalServiceError.unavailable
            }
        }

        return SwanAccountPortalSnapshot(
            account: .init(did: account.did, handle: account.canonicalHandle, email: email, lifecycle: account.status.rawValue),
            identity: identity,
            strength: "password",
            factors: factorValues,
            sessions: sessionRows,
            apps: apps,
            passwords: passwords
        )
    }

    public func mutate(
        path: String,
        context: SwanAccountPortalMutationContext,
        payload: Data?,
        now: Date
    ) async throws -> SwanAccountPortalMutation {
        guard !context.accountDID.isEmpty, !context.sessionID.isEmpty else {
            throw SwanAccountPortalServiceError.unauthorized
        }
        let session: ManagementSessionMetadata
        do {
            session = try await sessions.authenticate(sessionValue: context.sessionID, now: now)
        } catch {
            throw SwanAccountPortalServiceError.unauthorized
        }
        guard session.accountDID == context.accountDID,
              session.strength == context.strength else {
            throw SwanAccountPortalServiceError.unauthorized
        }
        let account: AccountControlAccount
        do {
            guard let resolved = try await accountDirectory.account(did: context.accountDID), resolved.status.authorizesAccount else {
                throw SwanAccountPortalServiceError.unauthorized
            }
            account = resolved
        } catch let error as SwanAccountPortalServiceError {
            throw error
        } catch {
            throw SwanAccountPortalServiceError.unavailable
        }
        switch path {
        case "step-up/password":
            if let admission = accountDirectory as? any SwanAccountPortalLoginAdmissionDirectory {
                guard let directPeer = context.directPeer else {
                    throw SwanAccountPortalServiceError.unavailable
                }
                do {
                    switch try await admission.admitLogin(handle: account.canonicalHandle, directPeer: directPeer, now: now) {
                    case .allowed: break
                    case .rateLimited: throw SwanAccountPortalServiceError.rateLimited
                    }
                } catch let error as SwanAccountPortalServiceError {
                    throw error
                } catch is AccountLoginAdmissionError {
                    throw SwanAccountPortalServiceError.unavailable
                } catch {
                    throw SwanAccountPortalServiceError.unavailable
                }
            }
            let request = try Self.decodePasswordReauthentication(payload)
            return try await passwordReauthenticate(
                account: account,
                sessionValue: context.sessionID,
                password: request.password,
                now: now
            )
        case "password":
            guard let changer = accountDirectory as? DurableAccountDirectory else {
                throw SwanAccountPortalServiceError.unsupported
            }
            if let admission = accountDirectory as? any SwanAccountPortalLoginAdmissionDirectory {
                guard let directPeer = context.directPeer else { throw SwanAccountPortalServiceError.unavailable }
                switch (try? await admission.admitLogin(handle: account.canonicalHandle, directPeer: directPeer, now: now)) {
                case .allowed?: break
                case .rateLimited?: throw SwanAccountPortalServiceError.rateLimited
                case nil: throw SwanAccountPortalServiceError.unavailable
                }
            }
            let request: PasswordChangeRequest
            do {
                guard let payload else { throw SwanAccountPortalServiceError.invalidRequest }
                request = try JSONDecoder().decode(PasswordChangeRequest.self, from: payload)
            } catch {
                throw SwanAccountPortalServiceError.invalidRequest
            }
            let outcome: DurableAccountDirectory.PasswordChangeOutcome
            do {
                outcome = try await changer.changePassword(
                    did: account.did,
                    currentPassword: request.currentPassword,
                    newPassword: request.newPassword,
                    now: now
                )
            } catch {
                throw SwanAccountPortalServiceError.unavailable
            }
            switch outcome {
            case .changed: break
            case .rejected: throw SwanAccountPortalServiceError.unauthorized
            case .invalidPassword: throw SwanAccountPortalServiceError.invalidRequest
            }
            // A changed password ends every other management session.
            try? await sessions.revokeOthers(accountDID: account.did, except: context.sessionID, now: now)
            return .init(message: "Password changed", accountDID: account.did)
        case "logout":
            do { try await sessions.revoke(sessionValue: context.sessionID, now: now) }
            catch { throw SwanAccountPortalServiceError.unavailable }
            return .init(message: "Signed out")
        case "sessions/revoke-others":
            // Revoking every other session is a sensitive account operation:
            // it requires a fresh step-up whenever MFA is active.
            do {
                let activeFactors = try await factors?.listFactors(accountDID: account.did, now: now) ?? []
                try StepUpPolicy().authorize(
                    .sessionRevocation,
                    strength: session.strength,
                    mfaEnabled: !activeFactors.isEmpty,
                    now: now
                )
            } catch {
                throw SwanAccountPortalServiceError.forbidden
            }
            do { try await sessions.revokeOthers(accountDID: account.did, except: context.sessionID, now: now) }
            catch { throw SwanAccountPortalServiceError.unavailable }
            return .init(message: "Other sessions revoked")
        case let sessionPath where sessionPath.hasPrefix("sessions/") && sessionPath != "sessions/revoke-others":
            // Per-session revocation (management or legacy) is account-bound,
            // idempotent, immediately effective, and step-up protected.
            let identifier = String(sessionPath.dropFirst("sessions/".count)).removingPercentEncoding ?? ""
            guard !identifier.isEmpty, !identifier.contains("/") else {
                throw SwanAccountPortalServiceError.invalidRequest
            }
            do {
                let activeFactors = try await factors?.listFactors(accountDID: account.did, now: now) ?? []
                try StepUpPolicy().authorize(
                    .sessionRevocation,
                    strength: session.strength,
                    mfaEnabled: !activeFactors.isEmpty,
                    now: now
                )
            } catch {
                throw SwanAccountPortalServiceError.forbidden
            }
            // Management session identifiers are 64-hex digest values; legacy
            // families are UUIDs. Both revocations are account-bound and
            // idempotent, so a retry after a partial failure is safe. A
            // non-hex identifier is a legacy family, not a management error.
            var revokedManagement = false
            if identifier.utf8.count == 64,
               identifier.allSatisfy({ $0.isHexDigit }) {
                do {
                    try await sessions.revokeManagementSession(id: identifier, accountDID: account.did, now: now)
                    revokedManagement = true
                } catch is SwanManagementSessionError {
                    throw SwanAccountPortalServiceError.forbidden
                } catch {
                    throw SwanAccountPortalServiceError.unavailable
                }
            }
            if let legacySessions, !revokedManagement {
                do {
                    try await legacySessions.revokeLegacySessionFamily(
                        familyID: identifier, did: account.did, now: now
                    )
                } catch {
                    throw SwanAccountPortalServiceError.unavailable
                }
            }
            return .init(message: "Session revoked", accountDID: account.did)
        case "app-passwords":
            guard let appPasswords, let appPasswordCredentials else {
                throw SwanAccountPortalServiceError.unsupported
            }
            guard let stepUpToken = context.stepUpToken,
                  let stepUpReceiptConsumer else {
                throw SwanAccountPortalServiceError.forbidden
            }
            do {
                let activeFactors = try await factors?.listFactors(accountDID: account.did, now: now) ?? []
                try StepUpPolicy().authorize(
                    .appPassword,
                    strength: session.strength,
                    mfaEnabled: !activeFactors.isEmpty,
                    now: now
                )
            } catch {
                throw SwanAccountPortalServiceError.forbidden
            }
            let request = try Self.decodeAppPasswordRequest(payload)
            do {
                try await stepUpReceiptConsumer.consumeStepUpReceipt(
                    sessionID: session.sessionID.rawValue,
                    accountDID: account.did,
                    operation: .createAppPassword,
                    strength: session.strength,
                    now: now,
                    receipt: stepUpToken,
                )
                // Credential policy and persistence belong to the canonical
                // app-password service, which validates the scope grammar
                // before writing the one authoritative row.
                let scopes = try AppPasswordScopes.validate(request.scopes)
                let issuance = try await appPasswordCredentials.issue(
                    did: account.did,
                    name: request.name,
                    scopes: scopes,
                    into: appPasswords,
                    now: now
                )
                return .init(
                    message: "App password created",
                    accountDID: account.did,
                    password: issuance.password
                )
            } catch is AppPasswordScopeError {
                throw SwanAccountPortalServiceError.invalidRequest
            } catch {
                throw Self.mapDomainError(error)
            }
        case "lifecycle/delete":
            guard let lifecycle else { throw SwanAccountPortalServiceError.unsupported }
            do {
                let activeFactors = try await factors?.listFactors(accountDID: account.did, now: now) ?? []
                try StepUpPolicy().authorize(
                    .deleteAccount,
                    strength: context.strength,
                    mfaEnabled: !activeFactors.isEmpty,
                    now: now
                )
            } catch {
                throw SwanAccountPortalServiceError.forbidden
            }
            do { _ = try await lifecycle.delete(did: account.did, now: now) }
            catch { throw Self.mapDomainError(error) }
            return .init(message: "Account deletion started", accountDID: account.did)
        default:
            if path == "step-up" || path == "factors" || path.hasPrefix("factors/") {
                guard let mfa else { throw SwanAccountPortalServiceError.unsupported }
                if path == "step-up" || path == "factors/step-up" {
                    guard let factorTokens else { throw SwanAccountPortalServiceError.unsupported }
                    do {
                        let issued = try await mfa.mutate(
                            path: "factors/step-up",
                            accountDID: account.did,
                            sessionID: session.sessionID.rawValue,
                            strength: session.strength,
                            payload: payload,
                            now: now
                        )
                        guard let token = issued.factorToken else {
                            throw SwanAccountPortalServiceError.forbidden
                        }
                        _ = try await sessions.upgradeFromStepUp(
                            sessionValue: context.sessionID,
                            token: token,
                            factorTokens: factorTokens,
                            now: now
                        )
                        return .init(message: "MFA step-up accepted", accountDID: account.did)
                    } catch {
                        throw Self.mapDomainError(error)
                    }
                }
                // Adding a factor is an authenticated account mutation; a
                // destructive operation or recovery rotation requires an
                // already-established step-up. The step-up endpoint itself
                // performs the second-factor proof and issues a one-time
                // durable token.
                let isStepUpCeremony = path == "factors/passkeys/step-up-challenge"
                    || path == "factors/passkeys/assertion"
                    || path == "factors/step-up/passkey-challenge"
                    || path == "factors/login"
                var expectedRevision: Int64?
                if !isStepUpCeremony {
                    let activeFactors = try await factors?.listFactors(
                        accountDID: account.did,
                        now: now
                    ) ?? []
                    do {
                        // A factor mutation is always committed under a
                        // fresh proof. First-factor bootstrap accepts only a
                        // fresh password reauthentication; once a factor is
                        // active, only a fresh MFA step-up can mutate it.
                        try StepUpPolicy().authorize(
                            .factorChange,
                            strength: context.strength,
                            mfaEnabled: !activeFactors.isEmpty,
                            now: now
                        )
                    } catch {
                        throw SwanAccountPortalServiceError.forbidden
                    }
                    // Bind the authorization to the revision observed now: the
                    // mutation store compares-and-swaps against this value in
                    // the SAME transaction as the mutation and revision
                    // increment (Task 3 Finding 1 carry-forward). A concurrent
                    // factor change between authorization and commit fails the
                    // predicate and denies the stale mutation.
                    if let grantStore = factors as? any AccountAuthorizationGrantStore {
                        do {
                            expectedRevision = try await grantStore.factorRevision(
                                accountDID: account.did, now: now
                            )
                        } catch {
                            throw SwanAccountPortalServiceError.unavailable
                        }
                    }
                }
                do {
                    return try await mfa.mutate(
                        path: path,
                        accountDID: account.did,
                        sessionID: session.sessionID.rawValue,
                        strength: context.strength,
                        expectedRevision: expectedRevision,
                        payload: payload,
                        now: now
                    )
                } catch {
                    throw Self.mapDomainError(error)
                }
            }
            if path.hasPrefix("identity") {
                guard let identity else { throw SwanAccountPortalServiceError.unsupported }
                do {
                    try await identity.mutateIdentity(path: path, accountDID: account.did, sessionID: context.sessionID, strength: context.strength, stepUpToken: context.stepUpToken, payload: payload, now: now)
                } catch { throw Self.mapDomainError(error) }
                return .init(message: "Identity updated", accountDID: account.did)
            }
            if path.hasPrefix("connected-apps/") {
                guard let oauth else { throw SwanAccountPortalServiceError.unsupported }
                guard context.strength.isStepUp else { throw SwanAccountPortalServiceError.forbidden }
                let appID = String(path.dropFirst("connected-apps/".count))
                guard !appID.isEmpty, !appID.contains("/") else { throw SwanAccountPortalServiceError.invalidRequest }
                do { try await oauth.revokeConnectedApp(accountDID: account.did, appID: appID, sessionID: context.sessionID, stepUpToken: context.stepUpToken, now: now) }
                catch { throw Self.mapDomainError(error) }
                return .init(message: "Connected app revoked", accountDID: account.did)
            }
            if path.hasPrefix("app-passwords/") {
                guard let appPasswords, let stepUpReceiptConsumer else { throw SwanAccountPortalServiceError.unsupported }
                guard context.strength.isStepUp, let stepUpToken = context.stepUpToken else { throw SwanAccountPortalServiceError.forbidden }
                let name = String(path.dropFirst("app-passwords/".count)).removingPercentEncoding ?? ""
                guard !name.isEmpty, !name.contains("/") else { throw SwanAccountPortalServiceError.invalidRequest }
                do {
                    try await stepUpReceiptConsumer.consumeStepUpReceipt(
                        sessionID: session.sessionID.rawValue,
                        accountDID: account.did,
                        operation: .revokeAppPassword,
                        strength: session.strength,
                        now: now,
                        receipt: stepUpToken
                    )
                    try await appPasswords.revokeAppPassword(did: account.did, name: name)
                }
                catch { throw Self.mapDomainError(error) }
                return .init(message: "App password revoked", accountDID: account.did)
            }
            throw SwanAccountPortalServiceError.unsupported
        }
    }

    private struct AppPasswordRequest: Decodable {
        let name: String
        let scopes: [String]
    }

    private struct PasswordChangeRequest: Decodable {
        let currentPassword: String
        let newPassword: String
    }

    private struct PasswordReauthenticationRequest: Decodable {
        let password: String
    }

    private static func decodePasswordReauthentication(_ payload: Data?) throws -> PasswordReauthenticationRequest {
        guard let payload else { throw SwanAccountPortalServiceError.invalidRequest }
        do {
            let request = try JSONDecoder().decode(PasswordReauthenticationRequest.self, from: payload)
            guard !request.password.isEmpty, request.password.utf8.count <= 4_096 else {
                throw SwanAccountPortalServiceError.invalidRequest
            }
            return request
        } catch let error as SwanAccountPortalServiceError {
            throw error
        } catch {
            throw SwanAccountPortalServiceError.invalidRequest
        }
    }

    private static func decodeAppPasswordRequest(_ payload: Data?) throws -> AppPasswordRequest {
        guard let payload else { throw SwanAccountPortalServiceError.invalidRequest }
        do {
            let request = try JSONDecoder().decode(AppPasswordRequest.self, from: payload)
            guard !request.name.isEmpty, !request.scopes.isEmpty else { throw SwanAccountPortalServiceError.invalidRequest }
            return request
        } catch let error as SwanAccountPortalServiceError { throw error }
        catch { throw SwanAccountPortalServiceError.invalidRequest }
    }

    private static func mapDomainError(_ error: Error) -> SwanAccountPortalServiceError {
        if let error = error as? SwanAccountPortalServiceError { return error }
        if error is SwanAccountPortalStepUpReceiptError { return .forbidden }
        if error is SwanManagementSessionError { return .unauthorized }
        if let error = error as? MFAError {
            switch error {
            case .invalidRequest: return .invalidRequest
            case .credentialNotFound: return .notFound
            case .storageUnavailable: return .unavailable
            case .stepUpRequired, .tokenInvalid, .invalidCode, .replay,
                 .expired, .invalidEnvelope, .invalidChallenge, .invalidOrigin,
                 .invalidRelyingParty, .invalidClientData, .invalidAuthenticatorData,
                 .invalidSignature, .counterRollback:
                return .forbidden
            }
        }
        if let error = error as? SwanError {
            switch error {
            case .unauthorized: return .unauthorized
            case .conflict: return .forbidden
            default: return .unavailable
            }
        }
        return .unavailable
    }

    private static func iso8601(_ date: Date) -> String {
        ISO8601DateFormatter().string(from: date)
    }
}

extension SwanAccountPortalService: SwanOAuthMFAService {}
