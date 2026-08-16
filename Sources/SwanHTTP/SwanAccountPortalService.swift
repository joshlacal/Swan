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

/// Production implementation of ``SwanAccountPortalServing``. Every read and
/// mutation crosses a durable service boundary; absent capabilities fail closed
/// with a typed error instead of falling back to process memory.
public struct SwanAccountPortalService: SwanAccountPortalServing, Sendable {
    private let accountDirectory: any SwanAccountPortalAccountDirectory
    private let accountStore: (any AccountControlStore)?
    private let appPasswords: (any AppPasswordStore)?
    private let factors: (any AuthenticationFactorStore)?
    private let legacy: LegacyAuthService?
    private let lifecycle: AccountLifecycleService?
    private let identity: (any SwanAccountPortalIdentityProjection)?
    private let oauth: (any SwanAccountPortalOAuthProjection)?
    private let sessions: SwanManagementSessionRuntime

    public init(
        accountDirectory: any SwanAccountPortalAccountDirectory,
        accountStore: (any AccountControlStore)? = nil,
        appPasswords: (any AppPasswordStore)? = nil,
        factors: (any AuthenticationFactorStore)? = nil,
        legacy: LegacyAuthService? = nil,
        lifecycle: AccountLifecycleService? = nil,
        identity: (any SwanAccountPortalIdentityProjection)? = nil,
        oauth: (any SwanAccountPortalOAuthProjection)? = nil,
        sessions: SwanManagementSessionRuntime
    ) {
        self.accountDirectory = accountDirectory
        self.accountStore = accountStore
        self.appPasswords = appPasswords
        self.factors = factors
        self.legacy = legacy
        self.lifecycle = lifecycle
        self.identity = identity
        self.oauth = oauth
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
                passwords = try await appPasswords.listAppPasswords(accountDID: account.did, now: now).map {
                    .init(name: $0.canonicalName, scopes: $0.scopeStrings.sorted(), createdAt: Self.iso8601($0.createdAt), lastUsedAt: $0.lastUsedAt.map(Self.iso8601))
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
        guard session.accountDID == context.accountDID else {
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
            guard let legacy else { throw SwanAccountPortalServiceError.unsupported }
            guard context.strength.isStepUp, let stepUpToken = context.stepUpToken else {
                throw SwanAccountPortalServiceError.forbidden
            }
            let request = try Self.decodeAppPasswordRequest(payload)
            do {
                _ = try await legacy.createAppPassword(accountDID: account.did, name: request.name, scopes: Set(request.scopes), managementSessionToken: context.sessionID, stepUpToken: stepUpToken, now: now)
            } catch { throw Self.mapDomainError(error) }
            return .init(message: "App password created", accountDID: account.did)
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
                guard let legacy else { throw SwanAccountPortalServiceError.unsupported }
                guard context.strength.isStepUp, let stepUpToken = context.stepUpToken else { throw SwanAccountPortalServiceError.forbidden }
                let name = String(path.dropFirst("app-passwords/".count)).removingPercentEncoding ?? ""
                guard !name.isEmpty, !name.contains("/") else { throw SwanAccountPortalServiceError.invalidRequest }
                do { try await legacy.revokeAppPassword(accountDID: account.did, name: name, managementSessionToken: context.sessionID, stepUpToken: stepUpToken, now: now) }
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
