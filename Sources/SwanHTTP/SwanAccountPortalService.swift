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
public struct SwanAccountPortalService: SwanAccountPortalServing, Sendable {
    private let accountDirectory: any SwanAccountPortalAccountDirectory
    private let accountStore: (any AccountControlStore)?
    private let appPasswords: (any AppPasswordStore)?
    private let appPasswordCredentials: AppPasswordCredentials?
    private let factors: (any AuthenticationFactorStore)?
    private let lifecycle: AccountLifecycleService?
    private let identity: (any SwanAccountPortalIdentityProjection)?
    private let oauth: (any SwanAccountPortalOAuthProjection)?
    private let stepUpReceiptConsumer: (any SwanAccountPortalStepUpReceiptConsuming)?
    private let sessions: SwanManagementSessionRuntime

    public init(
        accountDirectory: any SwanAccountPortalAccountDirectory,
        accountStore: (any AccountControlStore)? = nil,
        appPasswords: (any AppPasswordStore)? = nil,
        appPasswordCredentials: AppPasswordCredentials? = nil,
        factors: (any AuthenticationFactorStore)? = nil,
        lifecycle: AccountLifecycleService? = nil,
        identity: (any SwanAccountPortalIdentityProjection)? = nil,
        oauth: (any SwanAccountPortalOAuthProjection)? = nil,
        stepUpReceiptVerifier: (any SwanAccountPortalStepUpReceiptVerifying)? = nil,
        stepUpReceiptConsumer: (any SwanAccountPortalStepUpReceiptConsuming)? = nil,
        sessions: SwanManagementSessionRuntime
    ) {
        self.accountDirectory = accountDirectory
        self.accountStore = accountStore
        self.appPasswords = appPasswords
        self.appPasswordCredentials = appPasswordCredentials
        self.factors = factors
        self.lifecycle = lifecycle
        self.identity = identity
        self.oauth = oauth
        // Kept as a source-compatible argument for callers that still pass
        // the former read-only verifier. Mutating app-password operations use
        // the operation-bound consumer below; retaining the verifier here
        // would make it look authoritative despite its inability to consume.
        _ = stepUpReceiptVerifier
        self.stepUpReceiptConsumer = stepUpReceiptConsumer
        self.sessions = sessions
    }

    public func bootstrap(now: Date) async throws -> SwanAccountPortalBootstrap {
        let csrf = await sessions.issuePreAuth(now: now)
        return SwanAccountPortalBootstrap(csrf: csrf)
    }

    public func authenticate(
        handle: String,
        password: String,
        authFactorToken: String?,
        now: Date
    ) async throws -> SwanAccountPortalAuthentication {
        // MFA enrollment/verification is a separate capability. Never silently
        // accept a factor token before that capability is composed.
        guard authFactorToken == nil else { throw SwanAccountPortalServiceError.unsupported }
        do {
            switch try await accountDirectory.authenticateForLogin(handle: handle, password: password, now: now) {
            case let .authenticated(result):
                guard result.account.status.authorizesAccount else {
                    throw SwanAccountPortalServiceError.unauthorized
                }
                return SwanAccountPortalAuthentication(accountDID: result.account.did)
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

    public func portal(accountDID: String, now: Date) async throws -> SwanAccountPortalSnapshot {
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

        return SwanAccountPortalSnapshot(
            account: .init(did: account.did, handle: account.canonicalHandle, email: email, lifecycle: account.status.rawValue),
            identity: identity,
            strength: "password",
            factors: factorValues,
            sessions: [],
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
        case "logout":
            do { try await sessions.revoke(sessionValue: context.sessionID, now: now) }
            catch { throw SwanAccountPortalServiceError.unavailable }
            return .init(message: "Signed out")
        case "sessions/revoke-others":
            do { try await sessions.revokeOthers(accountDID: account.did, except: context.sessionID, now: now) }
            catch { throw SwanAccountPortalServiceError.unavailable }
            return .init(message: "Other sessions revoked")
        case "app-passwords":
            guard let appPasswords, let appPasswordCredentials else {
                throw SwanAccountPortalServiceError.unsupported
            }
            guard session.strength.isStepUp,
                  let stepUpToken = context.stepUpToken,
                  let stepUpReceiptConsumer else {
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
            guard context.strength.isStepUp else { throw SwanAccountPortalServiceError.forbidden }
            do { _ = try await lifecycle.delete(did: account.did, now: now) }
            catch { throw Self.mapDomainError(error) }
            return .init(message: "Account deletion started", accountDID: account.did)
        default:
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
