import Foundation
import Crypto
import HTTPTypes
import Hummingbird
import NIOCore
import SwanAccounts
import SwanCore
import SwanStorage

/// A deliberately narrow service protocol: route assembly owns authentication
/// and this adapter owns HTTP policy; account/domain services remain injectable.
public protocol SwanAccountPortalServing: Sendable {
    func bootstrap(now: Date) async throws -> SwanAccountPortalBootstrap
    func authenticate(handle: String, password: String, authFactorToken: String?, now: Date) async throws -> SwanAccountPortalAuthentication
    /// `currentSessionID` is the digest-derived stable identifier of the
    /// management session presenting the request; the projection marks exactly
    /// that session as `current`. It is `nil` for login-time snapshots.
    func portal(accountDID: String, currentSessionID: String?, now: Date) async throws -> SwanAccountPortalSnapshot
    func mutate(path: String, context: SwanAccountPortalMutationContext, payload: Data?, now: Date) async throws -> SwanAccountPortalMutation
}

public struct SwanAccountPortalMutationContext: Sendable, Equatable {
    public let sessionID: String
    public let accountDID: String
    public let strength: AuthenticationStrength
    /// The accepted socket peer for mutations that re-enter the canonical
    /// login admission bucket (currently password reauthentication).  It is
    /// deliberately optional for source-compatible domain callers; the HTTP
    /// production adapter always supplies it for those routes.
    public let directPeer: String?
    /// The one-time receipt echoed by the browser. The service verifies this
    /// value against durable state; it is not accepted as proof by itself.
    public let stepUpToken: String?
    public init(sessionID: String, accountDID: String, strength: AuthenticationStrength, stepUpToken: String? = nil, directPeer: String? = nil) {
        self.sessionID = sessionID; self.accountDID = accountDID; self.strength = strength; self.stepUpToken = stepUpToken; self.directPeer = directPeer
    }
}

public struct SwanAccountPortalAuthentication: Sendable, Equatable {
    public let accountDID: String
    public let strength: AuthenticationStrength
    /// The one-time revision-bound authorization grant created by the
    /// canonical directory at login. The portal session issuance consumes it
    /// in the same transaction that creates the management session; no
    /// protected session is issued without a successful consume result.
    public let authorizationGrantDigest: Data?
    /// The exact channel/session/purpose binding the grant was created
    /// against. It is required whenever a grant is present.
    public let authorizationContext: AccountAuthorizationContext?

    public init(
        accountDID: String,
        strength: AuthenticationStrength = .password,
        authorizationGrantDigest: Data? = nil,
        authorizationContext: AccountAuthorizationContext? = nil
    ) {
        self.accountDID = accountDID
        self.strength = strength
        self.authorizationGrantDigest = authorizationGrantDigest
        self.authorizationContext = authorizationContext
    }
}

private struct PortalLoginCredentials: Decodable {
    let handle: String
    let password: String
    let authFactorToken: String?
    enum CodingKeys: String, CodingKey, CaseIterable { case handle, password, authFactorToken }
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let keys = Set(container.allKeys)
        guard keys == [.handle, .password] || keys == Set(CodingKeys.allCases) else {
            throw PortalRequestError.malformed
        }
        handle = try container.decode(String.self, forKey: .handle)
        password = try container.decode(String.self, forKey: .password)
        authFactorToken = try container.decodeIfPresent(String.self, forKey: .authFactorToken)
        guard (1...2_048).contains(handle.utf8.count), (1...4_096).contains(password.utf8.count),
              !handle.utf8.contains(0), !password.utf8.contains(0) else { throw PortalRequestError.malformed }
    }
}

private struct PortalLoginFactorCredentials: Decodable {
    let handle: String
    let password: String
    let kind: AuthenticationFactorKind
    let factorID: String
    let code: String?
    let challenge: String?
    let clientDataJSON: String?
    let authenticatorData: String?
    let credentialID: String?
    let signature: String?
    enum CodingKeys: String, CodingKey { case handle, password, kind, factorID, code, challenge, clientDataJSON, authenticatorData, credentialID, signature }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        handle = try c.decode(String.self, forKey: .handle)
        password = try c.decode(String.self, forKey: .password)
        kind = try c.decode(AuthenticationFactorKind.self, forKey: .kind)
        factorID = try c.decode(String.self, forKey: .factorID)
        code = try c.decodeIfPresent(String.self, forKey: .code)
        challenge = try c.decodeIfPresent(String.self, forKey: .challenge)
        clientDataJSON = try c.decodeIfPresent(String.self, forKey: .clientDataJSON)
        authenticatorData = try c.decodeIfPresent(String.self, forKey: .authenticatorData)
        credentialID = try c.decodeIfPresent(String.self, forKey: .credentialID)
        signature = try c.decodeIfPresent(String.self, forKey: .signature)
        guard (1 ... 2_048).contains(handle.utf8.count),
              (1 ... 4_096).contains(password.utf8.count),
              !factorID.isEmpty, factorID.utf8.count <= 128 else {
            throw PortalRequestError.malformed
        }
    }

    func factorPayload() throws -> Data {
        var object: [String: Any] = [
            "kind": kind.rawValue,
            "factorID": factorID,
        ]
        if let code { object["code"] = code }
        if let challenge { object["challenge"] = challenge }
        if let clientDataJSON { object["clientDataJSON"] = clientDataJSON }
        if let authenticatorData { object["authenticatorData"] = authenticatorData }
        if let credentialID { object["credentialID"] = credentialID }
        if let signature { object["signature"] = signature }
        return try JSONSerialization.data(withJSONObject: object, options: [])
    }
}

private enum PortalRequestError: Error { case malformed, tooLarge }

public struct SwanAccountPortalBootstrap: Codable, Sendable, Equatable {
    public let csrf: String
    public init(csrf: String) { self.csrf = csrf }
}

public struct SwanAccountPortalSnapshot: Codable, Sendable, Equatable {
    public struct Account: Codable, Sendable, Equatable { public let did: String; public let handle: String; public let email: String?; public let lifecycle: String }
    public struct Identity: Codable, Sendable, Equatable { public let method: String; public let handle: String; public let state: String }
    public struct Session: Codable, Sendable, Equatable { public let id: String; public let label: String; public let kind: String; public let lastSeen: String; public let current: Bool }
    public struct App: Codable, Sendable, Equatable { public let id: String; public let name: String; public let scopes: [String]; public let createdAt: String }
    public struct Password: Codable, Sendable, Equatable { public let name: String; public let scopes: [String]; public let createdAt: String; public let lastUsedAt: String? }
    public let account: Account
    public let identity: Identity?
    public let strength: String
    public let factors: [[String: String]]
    public let sessions: [Session]
    public let apps: [App]
    public let passwords: [Password]
}

public struct SwanAccountPortalMutation: Codable, Sendable, Equatable {
    public let accepted: Bool
    public let message: String
    public let accountDID: String?
    /// Creation-only plaintext. Listing/projection types intentionally do not
    /// carry this field, and all non-creation mutations leave it nil.
    public let password: String?
    /// A one-time MFA receipt. It is present only on a successful step-up
    /// response and is never included in portal projections.
    public let factorToken: String?
    /// Recovery codes are returned only by an explicit rotation request; the
    /// durable store retains digests, never these plaintext values.
    public let recoveryCodes: [String]?
    /// Server-generated WebAuthn ceremony material. The challenge is safe to
    /// echo to the browser; only its digest is retained durably.
    public let challenge: String?
    public let factorID: String?
    public let factorKind: AuthenticationFactorKind?
    public init(
        accepted: Bool = true,
        message: String = "Accepted",
        accountDID: String? = nil,
        password: String? = nil,
        factorToken: String? = nil,
        recoveryCodes: [String]? = nil,
        challenge: String? = nil,
        factorID: String? = nil,
        factorKind: AuthenticationFactorKind? = nil
    ) {
        self.accepted = accepted
        self.message = message
        self.accountDID = accountDID
        self.password = password
        self.factorToken = factorToken
        self.recoveryCodes = recoveryCodes
        self.challenge = challenge
        self.factorID = factorID
        self.factorKind = factorKind
    }
}
private struct AuthenticatedPortalResponse: Encodable {
    let snapshot: SwanAccountPortalSnapshot
    let csrf: String
}

public struct SwanAccountPortalConfiguration: Sendable, Equatable {
    public let publicOrigin: URL
    public let staticDirectory: URL
    public let signupPolicy: SignupPolicy
    public init(publicOrigin: URL, staticDirectory: URL, signupPolicy: SignupPolicy = .closed) throws {
        guard let components = URLComponents(url: publicOrigin, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https", components.host != nil,
              components.user == nil, components.password == nil,
              components.path.isEmpty || components.path == "/",
              components.query == nil, components.fragment == nil else {
            throw SwanAccountPortalHTTPError.invalidConfiguration
        }
        self.publicOrigin = publicOrigin
        self.staticDirectory = staticDirectory
        self.signupPolicy = signupPolicy
    }
}

public enum SwanAccountPortalHTTPError: Error, Sendable, Equatable { case invalidConfiguration }

public enum SwanAccountPortalRegistrationPhase: String, Sendable, Equatable {
    case api
    case assets
    case unknownGuards
}

/// Registration for the public account prefix. Call this before any broad
/// public catch-all: API routes are registered first and therefore cannot be
/// mistaken for static pages.
public struct SwanAccountPortalHTTP: Sendable {
    public static let registrationPhases: [SwanAccountPortalRegistrationPhase] = [
        .api, .assets, .unknownGuards,
    ]

    public let configuration: SwanAccountPortalConfiguration
    private let sessions: SwanManagementSessionRuntime
    private let service: any SwanAccountPortalServing

    public init(configuration: SwanAccountPortalConfiguration, sessions: SwanManagementSessionRuntime, service: any SwanAccountPortalServing) {
        self.configuration = configuration
        self.sessions = sessions
        self.service = service
    }

    /// Compatibility helper for isolated portal tests. Production composition
    /// calls the three phases explicitly so the shared router's source order
    /// is reviewable and cannot be hidden inside this helper.
    public func register(on router: Router<SwanHTTPRequestContext>) {
        registerAPI(on: router)
        registerAssets(on: router)
        registerUnknownGuards(on: router)
    }

    public func registerAPI(on router: Router<SwanHTTPRequestContext>) {
        router.get("/account/api/signup/policy") { [configuration] _ , _ -> Response in
            accountJSON(.ok, SignupPolicyView(policy: configuration.signupPolicy))
        }
        router.get("/account/api/bootstrap") { [configuration, sessions] request, _ async -> Response in
            guard originPermits(request, expected: configuration.publicOrigin), fetchSiteAllows(request) else { return accountError(.forbidden) }
            let token = await sessions.issuePreAuth()
            return accountJSON(.ok, SwanAccountPortalBootstrap(csrf: token), cookies: [preAuthCookie(token)])
        }

        router.get("/account/api/portal") { [sessions, service] request, _ async -> Response in
            guard let session = accountCookie(named: SwanManagementSessionRuntime.sessionCookieName, request: request),
                  let metadata = try? await sessions.authenticate(sessionValue: session) else { return accountError(.unauthorized) }
            do { return accountJSON(.ok, try await service.portal(accountDID: metadata.accountDID, currentSessionID: metadata.sessionID.rawValue, now: Date())) }
            catch { return portalErrorResponse(error) }
        }

        // Register every read surface explicitly. They all share the same
        // sanitized snapshot until their domain adapter supplies a narrower
        // projection; none can fall through to the SPA.
        for path in ["session", "sessions", "profile", "identity", "app-passwords", "scope-presets", "factors", "connected-apps", "export", "migration"] {
            router.get("/account/api/\(path)") { [sessions, service] request, _ async -> Response in
                guard let session = accountCookie(named: SwanManagementSessionRuntime.sessionCookieName, request: request),
                      let metadata = try? await sessions.authenticate(sessionValue: session) else { return accountError(.unauthorized) }
                do { return accountJSON(.ok, try await service.portal(accountDID: metadata.accountDID, currentSessionID: metadata.sessionID.rawValue, now: Date())) }
                catch { return portalErrorResponse(error) }
            }
        }

        router.post("/account/api/login") { [configuration, sessions, service] request, context async -> Response in
            guard mutationHeadersAllow(request, expectedOrigin: configuration.publicOrigin),
                  let csrf = accountCookie(named: SwanManagementSessionRuntime.preAuthCookieName, request: request),
                  let header = request.headers[HTTPField.Name("X-Swan-CSRF")!],
                  constantTime(csrf, header), await sessions.validatesPreAuth(csrf) else { return accountError(.forbidden) }
            do {
                let admitted = try await collectAdmittedRequestBody(request, mediaType: .json, admission: .managementProcessShared, policy: .productionDefault, maximumBytes: 16 * 1024, termination: context.jsonWriteBodyTermination)
                defer { admitted.release() }
                guard let bytes = admitted.getBytes(at: admitted.readerIndex, length: admitted.readableBytes) else { throw PortalRequestError.malformed }
                let credentials = try JSONDecoder().decode(PortalLoginCredentials.self, from: Data(bytes))
                if let admissionStatus = await accountLoginAdmissionStatus(
                    service: service,
                    handle: credentials.handle,
                    context: context
                ) {
                    return accountError(admissionStatus)
                }
                let authentication: SwanAccountPortalAuthentication
                if let sessionBound = service as? any SwanAccountPortalSessionBoundAuthenticationServing {
                    authentication = try await sessionBound.authenticate(
                        handle: credentials.handle,
                        password: credentials.password,
                        authFactorToken: credentials.authFactorToken,
                        authFactorSessionID: csrf,
                        now: Date()
                    )
                } else {
                    authentication = try await service.authenticate(
                        handle: credentials.handle,
                        password: credentials.password,
                        authFactorToken: credentials.authFactorToken,
                        now: Date()
                    )
                }
                let snapshot = try await service.portal(accountDID: authentication.accountDID, currentSessionID: nil, now: Date())
                let issued = try await sessions.issueAfterPreAuth(
                    csrf,
                    accountDID: authentication.accountDID,
                    strength: authentication.strength,
                    authorizationGrantDigest: authentication.authorizationGrantDigest,
                    authorizationContext: authentication.authorizationContext
                )
                return accountJSON(.ok, AuthenticatedPortalResponse(snapshot: snapshot, csrf: issued.csrfValue), cookies: [managementCookie(issued.sessionValue), csrfCookie(issued.csrfValue), expiredPreAuthCookie()])
            } catch is PortalRequestError { await sessions.releasePreAuth(csrf); return accountError(.badRequest) }
            catch { await sessions.releasePreAuth(csrf); return accountError(.unauthorized) }
        }

        for (path, challengeOnly) in [("login/factor-challenge", true), ("login/factor", false)] {
            router.post("/account/api/\(path)") { [configuration, sessions, service] request, context async -> Response in
                guard mutationHeadersAllow(request, expectedOrigin: configuration.publicOrigin),
                      let csrf = accountCookie(named: SwanManagementSessionRuntime.preAuthCookieName, request: request),
                      let header = request.headers[HTTPField.Name("X-Swan-CSRF")!],
                      constantTime(csrf, header), await sessions.validatesPreAuth(csrf) else {
                    return accountError(.forbidden)
                }
                do {
                    let admitted = try await collectAdmittedRequestBody(
                        request,
                        mediaType: .json,
                        admission: .managementProcessShared,
                        policy: .productionDefault,
                        maximumBytes: 16 * 1024,
                        termination: context.jsonWriteBodyTermination
                    )
                    defer { admitted.release() }
                    guard let bytes = admitted.getBytes(at: admitted.readerIndex, length: admitted.readableBytes) else { throw PortalRequestError.malformed }
                    let credentials = try JSONDecoder().decode(PortalLoginFactorCredentials.self, from: Data(bytes))
                    if let admissionStatus = await accountLoginAdmissionStatus(
                        service: service,
                        handle: credentials.handle,
                        context: context
                    ) {
                        return accountError(admissionStatus)
                    }
                    let payload = try credentials.factorPayload()
                    guard let management = service as? any SwanAccountPortalManagementLoginServing else {
                        throw SwanAccountPortalServiceError.unsupported
                    }
                    let result = try await management.managementLoginFactor(
                        handle: credentials.handle,
                        password: credentials.password,
                        sessionID: csrf,
                        payload: payload,
                        challengeOnly: challengeOnly,
                        now: Date()
                    )
                    return accountJSON(.ok, result)
                } catch is PortalRequestError {
                    return accountError(.badRequest)
                } catch {
                    return portalErrorResponse(error)
                }
            }
        }

        for path in ["signup/email/request", "signup/authorize", "signup"] {
            router.post("/account/api/\(path)") { [configuration, sessions, service] request, context async -> Response in
                guard mutationHeadersAllow(request, expectedOrigin: configuration.publicOrigin),
                      let csrf = accountCookie(named: SwanManagementSessionRuntime.preAuthCookieName, request: request),
                      let header = request.headers[HTTPField.Name("X-Swan-CSRF")!], constantTime(csrf, header),
                      await sessions.validatesPreAuth(csrf) else { return accountError(.forbidden) }
                do {
                    let admitted = try await collectAdmittedRequestBody(request, mediaType: .json, admission: .managementProcessShared, policy: .productionDefault, maximumBytes: 16 * 1024, termination: context.jsonWriteBodyTermination)
                    defer { admitted.release() }
                    let payload = admitted.getBytes(at: admitted.readerIndex, length: admitted.readableBytes).map { Data($0) }
                    let result = try await service.mutate(path: path, context: .init(sessionID: "preauth", accountDID: "", strength: .password), payload: payload, now: Date())
                    if path == "signup" {
                        guard let accountDID = result.accountDID else { return accountError(.serviceUnavailable) }
                        let issued = try await sessions.issueAfterPreAuth(csrf, accountDID: accountDID)
                        return accountJSON(.ok, result, cookies: [managementCookie(issued.sessionValue), csrfCookie(issued.csrfValue), expiredPreAuthCookie()])
                    }
                    return accountJSON(.ok, result)
                } catch { await sessions.releasePreAuth(csrf); return accountError(.badRequest) }
            }
        }

        for path in ["logout", "profile", "identity", "app-passwords", "scopes/validate", "factors", "factors/totp", "factors/totp/verify", "factors/passkeys", "factors/passkeys/challenge", "factors/passkeys/options", "factors/passkeys/step-up-challenge", "factors/passkeys/assertion", "factors/step-up/passkey-challenge", "factors/recovery-codes/rotate", "factors/step-up", "connected-apps", "export", "export/request", "migration", "migration/request", "lifecycle/delete", "step-up", "step-up/password", "sessions/revoke-others"] {
            router.on("/account/api/\(path)", method: .post) { [configuration, sessions, service] request, context async -> Response in
                guard mutationHeadersAllow(request, expectedOrigin: configuration.publicOrigin),
                      let session = accountCookie(named: SwanManagementSessionRuntime.sessionCookieName, request: request),
                      let csrf = accountCookie(named: SwanManagementSessionRuntime.csrfCookieName, request: request),
                      let header = request.headers[HTTPField.Name("X-Swan-CSRF")!],
                      constantTime(csrf, header),
                      (try? await sessions.authenticate(sessionValue: session)) != nil,
                      (try? await sessions.acceptsCSRF(sessionValue: session, csrfValue: csrf)) == true else { return accountError(.forbidden) }
                do {
                    let metadata = try await sessions.authenticate(sessionValue: session)
                    let admitted = try await collectAdmittedRequestBody(request, mediaType: .json, admission: .managementProcessShared, policy: .productionDefault, maximumBytes: 16 * 1024, termination: context.jsonWriteBodyTermination)
                    defer { admitted.release() }
                    let payload = admitted.getBytes(at: admitted.readerIndex, length: admitted.readableBytes).map { Data($0) }
                    let mutation = try await service.mutate(path: path, context: .init(sessionID: session, accountDID: metadata.accountDID, strength: metadata.strength, stepUpToken: stepUpReceipt(from: request), directPeer: context.remoteAddress?.ipAddress), payload: payload, now: Date())
                    if path == "logout" { try await sessions.revoke(sessionValue: session) }
                    return accountJSON(.ok, mutation, cookies: path == "logout" ? [expiredManagementCookie(), expiredCSRFToken()] : [])
                } catch { return portalErrorResponse(error) }
            }
        }

        // The passkey contract also accepts an explicit factor identifier on
        // enrollment. Exact challenge/enrollment routes above win trie
        // precedence; this wildcard is only the id-bound completion form.
        router.on("/account/api/factors/passkeys/*", method: .post) { [configuration, sessions, service] request, context async -> Response in
            guard mutationHeadersAllow(request, expectedOrigin: configuration.publicOrigin),
                  let session = accountCookie(named: SwanManagementSessionRuntime.sessionCookieName, request: request),
                  let csrf = accountCookie(named: SwanManagementSessionRuntime.csrfCookieName, request: request),
                  let header = request.headers[HTTPField.Name("X-Swan-CSRF")!],
                  constantTime(csrf, header),
                  (try? await sessions.acceptsCSRF(sessionValue: session, csrfValue: csrf)) == true else {
                return accountError(.forbidden)
            }
            do {
                let metadata = try await sessions.authenticate(sessionValue: session)
                let admitted = try await collectAdmittedRequestBody(
                    request,
                    mediaType: .json,
                    admission: .managementProcessShared,
                    policy: .productionDefault,
                    maximumBytes: 16 * 1024,
                    termination: context.jsonWriteBodyTermination
                )
                defer { admitted.release() }
                let payload = admitted.getBytes(at: admitted.readerIndex, length: admitted.readableBytes).map { Data($0) }
                let mutationPath = String(request.uri.path.dropFirst("/account/api/".count))
                let mutation = try await service.mutate(
                    path: mutationPath,
                    context: .init(sessionID: session, accountDID: metadata.accountDID, strength: metadata.strength, stepUpToken: stepUpReceipt(from: request), directPeer: context.remoteAddress?.ipAddress),
                    payload: payload,
                    now: Date()
                )
                return accountJSON(.ok, mutation)
            } catch { return portalErrorResponse(error) }
        }

        for path in ["sessions", "identity", "app-passwords", "factors/passkeys", "factors/totp", "connected-apps"] {
            router.on("/account/api/\(path)", method: .delete) { [configuration, sessions, service] request, context async -> Response in
                guard mutationHeadersAllow(request, expectedOrigin: configuration.publicOrigin),
                      let session = accountCookie(named: SwanManagementSessionRuntime.sessionCookieName, request: request),
                      let csrf = accountCookie(named: SwanManagementSessionRuntime.csrfCookieName, request: request),
                      let header = request.headers[HTTPField.Name("X-Swan-CSRF")!], constantTime(csrf, header),
                      (try? await sessions.acceptsCSRF(sessionValue: session, csrfValue: csrf)) == true else { return accountError(.forbidden) }
                do {
                    let metadata = try await sessions.authenticate(sessionValue: session)
                    return accountJSON(.ok, try await service.mutate(path: path, context: .init(sessionID: session, accountDID: metadata.accountDID, strength: metadata.strength, stepUpToken: stepUpReceipt(from: request), directPeer: context.remoteAddress?.ipAddress), payload: nil, now: Date()))
                } catch { return portalErrorResponse(error) }
            }
        }

        for prefix in ["sessions", "app-passwords", "factors/passkeys"] {
            router.on("/account/api/\(prefix)/*", method: .delete) { [configuration, sessions, service] request, context async -> Response in
                guard mutationHeadersAllow(request, expectedOrigin: configuration.publicOrigin),
                      let session = accountCookie(named: SwanManagementSessionRuntime.sessionCookieName, request: request),
                      let csrf = accountCookie(named: SwanManagementSessionRuntime.csrfCookieName, request: request),
                      let header = request.headers[HTTPField.Name("X-Swan-CSRF")!],
                      constantTime(csrf, header),
                      (try? await sessions.acceptsCSRF(sessionValue: session, csrfValue: csrf)) == true else { return accountError(.forbidden) }
                do {
                    let metadata = try await sessions.authenticate(sessionValue: session)
                    let admitted = try await collectAdmittedRequestBody(request, mediaType: .json, admission: .managementProcessShared, policy: .productionDefault, maximumBytes: 16 * 1024, termination: context.jsonWriteBodyTermination)
                    defer { admitted.release() }
                    let payload = admitted.getBytes(at: admitted.readerIndex, length: admitted.readableBytes).map { Data($0) }
                    let mutationPath = String(request.uri.path.dropFirst("/account/api/".count))
                    return accountJSON(.ok, try await service.mutate(path: mutationPath, context: .init(sessionID: session, accountDID: metadata.accountDID, strength: metadata.strength, stepUpToken: stepUpReceipt(from: request), directPeer: context.remoteAddress?.ipAddress), payload: payload, now: Date()))
                } catch { return portalErrorResponse(error) }
            }
        }

    }

    public func registerAssets(on router: Router<SwanHTTPRequestContext>) {
        router.get("/account") { [configuration] _, _ -> Response in staticAccountResponse(configuration: configuration, requestPath: "/account") }
        router.get("/account/**") { [configuration] request, _ -> Response in staticAccountResponse(configuration: configuration, requestPath: request.uri.path) }
    }

    public func registerUnknownGuards(on router: Router<SwanHTTPRequestContext>) {
        let methods: [HTTPRequest.Method] = [.get, .head, .post, .put, .patch, .delete, .options, .connect, .trace]
        for method in methods {
            router.on("/account/api/*", method: method) { _, _ -> Response in accountError(.notFound) }
            router.on("/account/api/*/*", method: method) { _, _ -> Response in accountError(.notFound) }
            router.on("/account/api/*/*/*", method: method) { _, _ -> Response in accountError(.notFound) }
            router.on("/account/api/*/*/*/*", method: method) { _, _ -> Response in accountError(.notFound) }
        }
    }
}

private struct SignupPolicyView: Encodable {
    let policy: String
    let inviteCodeRequired: Bool
    let turnstileRequired: Bool
    let emailVerificationRequired: Bool

    init(policy: SignupPolicy) {
        self.policy = policy.rawValue
        inviteCodeRequired = policy.advertisesInviteCodeRequired
        turnstileRequired = policy.requiresTurnstile
        emailVerificationRequired = policy != .closed
    }
}

private func staticAccountResponse(configuration: SwanAccountPortalConfiguration, requestPath: String) -> Response {
    let relative = String(requestPath.dropFirst("/account".count)).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    let hasExtension = relative.contains(".")
    let safeRelative = relative.isEmpty ? "index.html" : relative
    guard !safeRelative.contains(".."), !safeRelative.contains("\\") else { return accountError(.notFound) }
    let file = configuration.staticDirectory.appending(path: safeRelative)
    let data: Data?
    let responsePath: String
    if let asset = try? Data(contentsOf: file) {
        data = asset; responsePath = safeRelative
    } else if !hasExtension {
        // Only extensionless navigations receive the SPA shell. Missing
        // scripts, styles, images, and source maps remain ordinary 404s.
        data = try? Data(contentsOf: configuration.staticDirectory.appending(path: "index.html")); responsePath = "index.html"
    } else {
        data = nil; responsePath = safeRelative
    }
    guard let data else { return accountError(.notFound) }
    let contentType = staticContentType(for: responsePath)
    let cache = hasExtension && !safeRelative.hasSuffix(".html") ? "public, max-age=31536000, immutable" : "no-cache"
    let csp = staticCSP(for: data, contentType: contentType)
    return Response(status: .ok, headers: [.contentType: contentType, .cacheControl: cache, HTTPField.Name("Content-Security-Policy")!: csp], body: .init(byteBuffer: ByteBuffer(data: data)))
}

private func staticCSP(for data: Data, contentType: String) -> String {
    var scriptSource = "'self'"
    if contentType.hasPrefix("text/html"), let html = String(data: data, encoding: .utf8),
       let start = html.range(of: "<script>"), let end = html.range(of: "</script>", range: start.upperBound..<html.endIndex) {
        let script = String(html[start.upperBound..<end.lowerBound])
        let digest = Data(SHA256.hash(data: Data(script.utf8))).base64EncodedString()
        scriptSource += " 'sha256-\(digest)'"
    }
    return "default-src 'none'; script-src \(scriptSource); style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
}

private func staticContentType(for path: String) -> String {
    switch path.split(separator: ".").last?.lowercased() {
    case "html": "text/html; charset=utf-8"
    case "css": "text/css; charset=utf-8"
    case "js", "mjs": "text/javascript; charset=utf-8"
    case "json", "map": "application/json; charset=utf-8"
    case "svg": "image/svg+xml"
    case "png": "image/png"
    case "jpg", "jpeg": "image/jpeg"
    case "woff": "font/woff"
    case "woff2": "font/woff2"
    default: "application/octet-stream"
    }
}

private func mutationHeadersAllow(_ request: Request, expectedOrigin: URL) -> Bool {
    sameOrigin(request, expected: expectedOrigin) && fetchSiteAllows(request, requireHeader: true) && exactJSONMediaType(request.headers[.contentType])
}

private func exactJSONMediaType(_ value: String?) -> Bool {
    guard let value else { return false }
    let parts = value.split(separator: ";", omittingEmptySubsequences: false)
    return parts.count == 1 && parts[0].trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "application/json"
}

private func sameOrigin(_ request: Request, expected: URL) -> Bool {
    guard let origin = request.headers[HTTPField.Name("Origin")!], let expectedComponents = URLComponents(url: expected, resolvingAgainstBaseURL: false), let actual = URL(string: origin), let actualComponents = URLComponents(url: actual, resolvingAgainstBaseURL: false) else { return false }
    guard actualComponents.user == nil, actualComponents.password == nil,
          actualComponents.path.isEmpty || actualComponents.path == "/",
          actualComponents.query == nil, actualComponents.fragment == nil else { return false }
    return actualComponents.scheme?.lowercased() == expectedComponents.scheme?.lowercased() && actualComponents.host?.lowercased() == expectedComponents.host?.lowercased() && (actualComponents.port ?? (actualComponents.scheme == "https" ? 443 : 80)) == (expectedComponents.port ?? (expectedComponents.scheme == "https" ? 443 : 80))
}

private func originPermits(_ request: Request, expected: URL) -> Bool {
    request.headers[HTTPField.Name("Origin")!] == nil || sameOrigin(request, expected: expected)
}

private func fetchSiteAllows(_ request: Request, requireHeader: Bool = false) -> Bool {
    guard let site = request.headers[HTTPField.Name("Sec-Fetch-Site")!] else { return !requireHeader }
    return site == "same-origin" || site == "none"
}

private func accountCookie(named name: String, request: Request) -> String? {
    // Hummingbird may surface a single `Cookie: a=1; b=2` header as multiple
    // values split on `;`, so every value must be searched — reading only the
    // first would silently drop the CSRF cookie on real browser requests.
    for header in request.headers[values: .cookie] {
        for part in header.split(separator: ";").map(String.init) {
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("\(name)=") else { continue }
            return String(trimmed.dropFirst(name.count + 1))
        }
    }
    return nil
}

private func stepUpReceipt(from request: Request) -> String? {
    let name = HTTPField.Name("X-Swan-Step-Up")!
    let values = request.headers[values: name]
    guard values.count == 1, let value = values.first,
          !value.isEmpty, value.utf8.count <= 4096 else { return nil }
    return value
}

/// Returns a response status only for production services that expose the
/// canonical durable admission seam. Test doubles intentionally omit the
/// capability so they can exercise HTTP policy without constructing SQLite
/// rate-limit state; production ``SwanAccountPortalService`` always exposes it
/// and fails closed when the accepted socket peer is unavailable.
private func accountLoginAdmissionStatus(
    service: any SwanAccountPortalServing,
    handle: String,
    context: SwanHTTPRequestContext
) async -> AccountStatus? {
    guard let admission = service as? any SwanAccountPortalLoginAdmissionServing else {
        return nil
    }
    guard let directPeer = context.remoteAddress?.ipAddress else {
        return .serviceUnavailable
    }
    do {
        switch try await admission.admitLogin(handle: handle, directPeer: directPeer, now: Date()) {
        case .allowed: return nil
        case .rateLimited: return .rateLimited
        }
    } catch {
        return .serviceUnavailable
    }
}

private func constantTime(_ lhs: String, _ rhs: String) -> Bool { guard lhs.utf8.count == rhs.utf8.count else { return false }; var result: UInt8 = 0; for (a, b) in zip(lhs.utf8, rhs.utf8) { result |= a ^ b }; return result == 0 }

private func accountJSON(_ status: HTTPResponse.Status, _ body: some Encodable, cookies: [String] = []) -> Response { var headers: HTTPFields = [.contentType: "application/json", .cacheControl: "no-store"]; for cookie in cookies { headers.append(.init(name: HTTPField.Name("Set-Cookie")!, value: cookie)) }; let data = (try? JSONEncoder().encode(body)) ?? Data("{}".utf8); return Response(status: status, headers: headers, body: .init(byteBuffer: ByteBuffer(data: data))) }
private enum AccountStatus { case ok, badRequest, unauthorized, forbidden, conflict, unprocessable, rateLimited, notFound, serviceUnavailable }
private func accountError(_ status: AccountStatus) -> Response { let code = switch status { case .badRequest: "invalid_request"; case .unauthorized: "authentication_required"; case .forbidden: "request_not_allowed"; case .conflict: "conflict"; case .unprocessable: "unprocessable_entity"; case .rateLimited: "rate_limited"; case .notFound: "not_found"; case .serviceUnavailable: "service_unavailable"; case .ok: "ok" }; let http: HTTPResponse.Status = switch status { case .badRequest: .badRequest; case .unauthorized: .unauthorized; case .forbidden: .forbidden; case .conflict: .conflict; case .unprocessable: HTTPResponse.Status(code: 422); case .rateLimited: .tooManyRequests; case .notFound: .notFound; case .serviceUnavailable: .serviceUnavailable; case .ok: .ok }; return accountJSON(http, ["code": code, "message": code == "request_not_allowed" ? "Request not allowed." : code == "invalid_request" ? "Invalid request." : "The account service is unavailable."]) }
private func portalErrorResponse(_ error: Error) -> Response {
    guard let error = error as? SwanAccountPortalServiceError else {
        return accountError(.serviceUnavailable)
    }
    switch error {
    case .unauthorized: return accountError(.unauthorized)
    case .forbidden: return accountError(.forbidden)
    case .rateLimited: return accountError(.rateLimited)
    case .notFound: return accountError(.notFound)
    case .invalidRequest: return accountError(.badRequest)
    case .unsupported, .unavailable: return accountError(.serviceUnavailable)
    }
}

private func managementCookie(_ value: String) -> String { "\(SwanManagementSessionRuntime.sessionCookieName)=\(value); Path=/account; Secure; HttpOnly; SameSite=Strict" }
private func csrfCookie(_ value: String) -> String { "\(SwanManagementSessionRuntime.csrfCookieName)=\(value); Path=/account; Secure; SameSite=Strict" }
private func preAuthCookie(_ value: String) -> String { "\(SwanManagementSessionRuntime.preAuthCookieName)=\(value); Path=/account; Secure; SameSite=Strict" }
private func expiredPreAuthCookie() -> String { "\(SwanManagementSessionRuntime.preAuthCookieName)=; Path=/account; Secure; SameSite=Strict; Max-Age=0" }
private func expiredManagementCookie() -> String { "\(SwanManagementSessionRuntime.sessionCookieName)=; Path=/account; Secure; HttpOnly; SameSite=Strict; Max-Age=0" }
private func expiredCSRFToken() -> String { "\(SwanManagementSessionRuntime.csrfCookieName)=; Path=/account; Secure; SameSite=Strict; Max-Age=0" }
