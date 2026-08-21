import Foundation
import HTTPTypes
import Hummingbird
import NIOCore
import Petrel
import SwanAccounts
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage

/// `com.atproto.server.{createSession,refreshSession,getSession,deleteSession}`
/// — the legacy session family the official Bluesky client uses.
///
/// ## Account password OR app password, matching upstream
///
/// `account-manager.ts:587-641`: try the account password; if it does not match,
/// try the account's app passwords; reject if neither. Swan does the same.
///
/// An earlier revision here accepted only app passwords, on the argument that
/// the credential a legacy client holds should be narrower than the account.
/// That argument loses to two facts. There is no app-password UI, so
/// app-password-only means nobody can sign in at all — a login path that cannot
/// be used is not a safer login path. And divergence from the reference costs
/// interop for no gain: the official client offers one password field, and a
/// user who types their account password into it expects it to work.
///
/// The two differ in AUTHORITY, which is where the narrowing actually lives: an
/// app-password session carries exactly its row's scopes, an account-password
/// session carries full legacy authority. Neither reaches the permissioned-data
/// surface.
///
/// ## The types are Petrel's
///
/// `SwanPublicWire` carries a deliberately pinned 21-lexicon inventory for the
/// permissioned-data surface, and the session family is not part of it. These
/// are ordinary `com.atproto.server.*` methods, so they use Petrel's generated
/// types exactly as `SwanAccountEmailXRPC` already does for the email family —
/// no pinned manifest is touched.
public enum SwanLegacySessionXRPCFailure: Error, Sendable, Equatable {
    case invalidRequest
    /// Bad identifier, bad password, unknown account, or an account whose status
    /// does not authorize it. **One code for all of them**, so the boundary is
    /// not an account-existence oracle.
    case authenticationRequired
    /// The account password verified successfully, but the account has active
    /// authentication factors and no `authFactorToken` was presented on the
    /// request. Lexicon: `AuthFactorTokenRequired`.
    case authFactorTokenRequired
    case invalidToken
    case expiredToken
    case payloadTooLarge
    case rateLimited
    /// Infrastructure, never credentials. Reported as 503 so a storage outage
    /// does not look to a client like a wrong password and trigger a re-login
    /// loop that locks the user out of their own session.
    case unavailable
}

/// Why a `createSession` was refused, for the operator log only.
///
/// The wire response is one fixed error for every value here — the boundary is
/// still not an account-existence oracle — but a failed password login that
/// leaves no server-side trace is undiagnosable, which is how a live 401 from
/// bsky.app ended up unattributable.
enum LegacyLoginStage: String, Sendable {
    /// The identifier is not a DID or handle of an account this server
    /// authorizes. An email address lands here too: this server resolves DIDs
    /// and handles only.
    case identifierUnresolved = "identifier_unresolved"
    /// The identifier resolved, but neither the account password nor any app
    /// password matched.
    case noCredentialMatched = "no_credential_matched"
    /// The account password verified, but the account has active authentication
    /// factors and no factor token was presented.
    case authFactorTokenRequired = "auth_factor_token_required"
    case rateLimited = "rate_limited"
    case malformedRequest = "malformed_request"
    case tokenRejected = "token_rejected"
    case unavailable = "unavailable"
}

/// A refusal that carries its stage. `failure` is what reaches the client.
struct LegacyLoginRejection: Error {
    let stage: LegacyLoginStage
    var failure: SwanLegacySessionXRPCFailure = .authenticationRequired
}

func legacyLoginStage(for error: any Error) -> LegacyLoginStage {
    if let rejection = error as? LegacyLoginRejection { return rejection.stage }
    switch (error as? SwanLegacySessionXRPCFailure) ?? .invalidRequest {
    case .rateLimited: return .rateLimited
    case .unavailable: return .unavailable
    case .invalidToken, .expiredToken: return .tokenRejected
    case .invalidRequest, .payloadTooLarge: return .malformedRequest
    case .authenticationRequired: return .noCredentialMatched
    case .authFactorTokenRequired: return .authFactorTokenRequired
    }
}

/// Resolves a login identifier to an account.
public protocol SwanLegacySessionDirectory: Sendable {
    /// Handle, DID, or email → the DID of an account whose status authorizes it.
    /// `nil` for every failure, so no caller can distinguish them.
    func resolveLoginIdentifier(_ identifier: String) async throws -> String?
    /// The handle to echo back in the session response.
    func canonicalHandle(did: String) async throws -> String?
}

public protocol SwanLegacySessionRateLimiting: Sendable {
    /// `false` refuses the attempt.
    func admitSessionCreation(identifier: String, now: Date) async -> Bool
}

public struct SwanLegacySessionXRPCServer: Sendable {
    static let maximumJSONBytes = 8 * 1024

    /// The eight methods this service owns.
    public static let methodNSIDs: Set<String> = [
        ComAtprotoServerCreateSession.typeIdentifier,
        ComAtprotoServerRefreshSession.typeIdentifier,
        ComAtprotoServerGetSession.typeIdentifier,
        ComAtprotoServerDeleteSession.typeIdentifier,
        ComAtprotoServerGetServiceAuth.typeIdentifier,
        ComAtprotoServerCreateAppPassword.typeIdentifier,
        ComAtprotoServerListAppPasswords.typeIdentifier,
        ComAtprotoServerRevokeAppPassword.typeIdentifier,
    ]

    /// Also handed to the resource authorizers, so a legacy bearer token is
    /// recognised on the protected routes and not only on this service's own.
    public let sessions: DurableLegacySessionService
    private let credentials: AppPasswordCredentials
    private let appPasswords: any AppPasswordStore
    private let accounts: DurableAccountDirectory
    private let directory: any SwanLegacySessionDirectory
    private let rateLimiter: any SwanLegacySessionRateLimiting
    /// Account-key-backed service-JWT issuer. The route remains installed when
    /// composition has no key store, but fails closed as unavailable rather
    /// than falling back to the obsolete HMAC ``LegacyAuthService``.
    private let serviceAuthIssuer: (any SwanProxyServiceTokenIssuing)?
    /// A floor on how long a failed `createSession` takes.
    ///
    /// Upstream pads every login to 350ms (`account-manager.ts:640`) for exactly
    /// this reason: resolving an identifier touches storage, and without a floor
    /// the difference between "no such handle" and "wrong password" is
    /// measurable. Swan already uses this technique for password recovery.
    private let minimumFailedLoginDuration: Duration

    public init(
        sessions: DurableLegacySessionService,
        credentials: AppPasswordCredentials,
        appPasswords: any AppPasswordStore,
        accounts: DurableAccountDirectory,
        directory: any SwanLegacySessionDirectory,
        rateLimiter: any SwanLegacySessionRateLimiting,
        serviceAuthIssuer: (any SwanProxyServiceTokenIssuing)? = nil,
        minimumFailedLoginDuration: Duration = .milliseconds(350)
    ) {
        self.sessions = sessions
        self.credentials = credentials
        self.appPasswords = appPasswords
        self.accounts = accounts
        self.directory = directory
        self.rateLimiter = rateLimiter
        self.serviceAuthIssuer = serviceAuthIssuer
        self.minimumFailedLoginDuration = minimumFailedLoginDuration
    }

    /// Installs the four routes as EXACT paths.
    ///
    /// They coexist with `registerUnknownPublicEndpointGuards`, which closes
    /// `/xrpc/com.atproto.server.*` with a flat 404: exact paths outrank a
    /// `<prefix>.*` guard in Hummingbird's trie regardless of registration
    /// order, which is how `describeServer` already survives it. The guard is
    /// NOT weakened — every other `com.atproto.server.*` method still 404s.
    func register(
        on router: Router<SwanHTTPRequestContext>,
        requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
    ) {
        let handlers = Handlers(
            sessions: sessions,
            credentials: credentials,
            appPasswords: appPasswords,
            accounts: accounts,
            directory: directory,
            rateLimiter: rateLimiter,
            serviceAuthIssuer: serviceAuthIssuer,
            requestBodyAdmission: requestBodyAdmission,
            minimumFailedLoginDuration: minimumFailedLoginDuration
        )
        router.post("/xrpc/\(ComAtprotoServerCreateSession.typeIdentifier)") {
            request, context async -> Response in
            await handlers.createSession(request, context: context)
        }
        router.post("/xrpc/\(ComAtprotoServerRefreshSession.typeIdentifier)") {
            request, context async -> Response in
            await handlers.refreshSession(request, context: context)
        }
        router.get("/xrpc/\(ComAtprotoServerGetSession.typeIdentifier)") {
            request, context async -> Response in
            await handlers.getSession(request, context: context)
        }
        router.get("/xrpc/\(ComAtprotoServerGetServiceAuth.typeIdentifier)") {
            request, context async -> Response in
            await handlers.getServiceAuth(request, context: context)
        }
        router.post("/xrpc/\(ComAtprotoServerDeleteSession.typeIdentifier)") {
            request, context async -> Response in
            await handlers.deleteSession(request, context: context)
        }
        router.post("/xrpc/\(ComAtprotoServerCreateAppPassword.typeIdentifier)") {
            request, context async -> Response in
            await handlers.createAppPassword(request, context: context)
        }
        router.get("/xrpc/\(ComAtprotoServerListAppPasswords.typeIdentifier)") {
            request, context async -> Response in
            await handlers.listAppPasswords(request, context: context)
        }
        router.post("/xrpc/\(ComAtprotoServerRevokeAppPassword.typeIdentifier)") {
            request, context async -> Response in
            await handlers.revokeAppPassword(request, context: context)
        }
    }
}

private struct Handlers: Sendable {
    let sessions: DurableLegacySessionService
    let credentials: AppPasswordCredentials
    let appPasswords: any AppPasswordStore
    let accounts: DurableAccountDirectory
    let directory: any SwanLegacySessionDirectory
    let rateLimiter: any SwanLegacySessionRateLimiting
    let serviceAuthIssuer: (any SwanProxyServiceTokenIssuing)?
    let requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
    let minimumFailedLoginDuration: Duration

    // MARK: createSession

    func createSession(_ request: Request, context: SwanHTTPRequestContext) async -> Response {
        let started = ContinuousClock.now
        // Set after the body decodes, read by the rejection log below.
        var factorTokenShape = "absent"
        do {
            try await requireNoQuery(request, context: context)
            let input: ComAtprotoServerCreateSession.Input = try await decodeExactJSON(
                request,
                context: context,
                required: ["identifier", "password"],
                // Both are sent by the official client. `authFactorToken` is
                // optional for password-only accounts and is validated by the
                // canonical directory when the additive MFA runtime is active.
                optional: ["authFactorToken", "allowTakendown"]
            )
            guard await rateLimiter.admitSessionCreation(
                identifier: input.identifier, now: Date()
            ) else {
                throw SwanLegacySessionXRPCFailure.rateLimited
            }

            // An empty `authFactorToken` is a client sending the field it always
            // sends, not a token: several clients populate the key with `""`
            // when the user never entered a code. Treating it as present sends
            // the request down the factor-verification branch, where an empty
            // string can only fail, and turns a correct password into
            // `AuthenticationRequired` with no way for the user to tell.
            let presentedFactorToken = input.authFactorToken.flatMap {
                $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : $0
            }
            factorTokenShape =
                input.authFactorToken == nil
                ? "absent" : (presentedFactorToken == nil ? "empty" : "present")
            let tokens = try await authenticate(
                identifier: input.identifier,
                password: input.password,
                authFactorToken: presentedFactorToken,
                sessionBinding: UUID().uuidString.lowercased()
            )
            let handle = try await directory.canonicalHandle(did: tokens.did)
            return try json(
                .ok,
                ComAtprotoServerCreateSession.Output(
                    accessJwt: tokens.accessJWT,
                    refreshJwt: tokens.refreshJWT,
                    handle: try Handle(handleString: handle ?? ""),
                    did: try DID(didString: tokens.did),
                    didDoc: nil,
                    email: nil,
                    emailConfirmed: nil,
                    emailAuthFactor: nil,
                    active: true,
                    status: nil
                )
            )
        } catch {
            // Every failed login costs the same floor, so the boundary does not
            // leak whether the identifier exists. Applied to failures only:
            // padding successes would slow every legitimate sign-in for nothing.
            await padTo(minimumFailedLoginDuration, since: started)
            // The wire response stays the fixed opaque error; the operator gets
            // the stage. Without this a failed password login is invisible
            // server-side — the state that made a live bsky.app 401 impossible
            // to attribute. `LegacyLoginStage` is a fixed vocabulary and never
            // carries an identifier, a password, or a token.
            // `factorToken` records the SHAPE of the field, never its value:
            // `absent`, `empty` (the key was sent with no code in it), or
            // `present`. That distinction is the difference between "wrong
            // password" and "client sent a field this server mishandled", and
            // guessing between the two is what made the last 401 opaque.
            context.logger.info(
                "legacy createSession rejected",
                metadata: [
                    "stage": .string(legacyLoginStage(for: error).rawValue),
                    "factorToken": .string(factorTokenShape),
                ]
            )
            return response(for: error)
        }
    }

    /// Account password first, then app passwords — upstream's order
    /// (`account-manager.ts:620-633`).
    ///
    /// Written so the work does not depend on whether the account exists. Both
    /// verifications run on every path: `authenticateForLogin` performs exactly
    /// one Argon2id on every route including the unknown-account one, using its
    /// boot-generated dummy verifier, and the app-password digest is a second
    /// fixed-cost Argon2id salted by the DID (or, for an unknown account, by the
    /// identifier presented). Neither "the expensive step happened" nor "it
    /// happened twice" separates a missing account from a wrong password.
    private func authenticate(
        identifier: String,
        password: String,
        authFactorToken: String? = nil,
        sessionBinding: String
    ) async throws -> SwanOAuth.LegacySessionTokens {
        let resolved: String?
        let handle: String?
        do {
            resolved = try await directory.resolveLoginIdentifier(identifier)
            if let resolved {
                handle = try await directory.canonicalHandle(did: resolved)
            } else {
                handle = nil
            }
        } catch {
            throw SwanLegacySessionXRPCFailure.unavailable
        }

        // 1. The account password. `authenticateForLogin` is already
        //    enumeration-resistant, so it is handed the presented identifier
        //    when nothing resolved rather than being skipped. The legacy
        //    channel context binds the one-time authorization grant to this
        //    issuance; the family insert consumes it in the same transaction
        //    (Task 3 Finding 2 carry-forward).
        let context = try AccountAuthorizationContext(
            channel: .legacy,
            sessionID: sessionBinding,
            purpose: "managementLogin"
        )
        let outcome: AccountLoginAuthenticationOutcome
        do {
            outcome = try await accounts.authenticateForLogin(
                handle: handle ?? identifier,
                password: password,
                authFactorToken: authFactorToken,
                authorizationContext: context
            )
        } catch {
            // `AccountLoginAuthenticationError.unavailable` is infrastructure,
            // never a credential verdict.
            throw SwanLegacySessionXRPCFailure.unavailable
        }

        // 2. The app-password digest, computed unconditionally so step 1's
        //    outcome is not observable in the cost of step 2.
        let did = resolved ?? identifier
        let digest: Data
        do {
            digest = try credentials.digest(did: did, password: password)
        } catch {
            throw SwanLegacySessionXRPCFailure.unavailable
        }

        if case let .authenticated(success) = outcome, let resolved {
            if success.requiresFactor {
                // The account password verified successfully, but the account
                // has active authentication factors and no factor token was
                // presented on this request. We signal `AuthFactorTokenRequired`
                // so standard ATProto clients (such as bsky.app) know to prompt
                // the user for their 2FA factor token.
                //
                // Enumeration defense:
                // This branch is reachable only because password verification
                // succeeded. A wrong password on a factor-enrolled account
                // returns `.rejected`, which falls through to step 2 (app passwords)
                // and ultimately returns opaque `AuthenticationRequired`. The
                // endpoint therefore never acts as an existence-or-MFA oracle
                // when probed with incorrect credentials.
                //
                // An invalid, expired, or wrong-purpose `authFactorToken` likewise
                // returns `.rejected` from factor verification, keeping the opaque
                // `AuthenticationRequired` response instead of this error.
                throw LegacyLoginRejection(
                    stage: .authFactorTokenRequired,
                    failure: .authFactorTokenRequired
                )
            }
            // Full legacy authority, upstream's `AuthScope.Access`. The
            // revision-bound grant created by the directory is consumed at
            // family insertion.
            return try await open(
                did: resolved,
                appPassword: nil,
                authorizationGrantDigest: success.authorizationGrantDigest,
                authorizationContext: success.authorizationGrantDigest == nil ? nil : context
            )
        }
        guard let resolved else {
            throw LegacyLoginRejection(stage: .identifierUnresolved)
        }
        let record: AppPasswordRecord?
        do {
            record = try await appPasswords.appPassword(did: resolved, digest: digest)
        } catch {
            throw SwanLegacySessionXRPCFailure.unavailable
        }
        guard let record else {
            // Step 1 already refused the account password, and no app password
            // matches either. Which of the two the caller intended is not
            // knowable here, so the stage names the last gate that ran.
            throw LegacyLoginRejection(stage: .noCredentialMatched)
        }
        // An app-password session's authority is the live credential row: it
        // is re-read on every use, so no revision-bound grant exists for this
        // path. Issuance still fails when the credential is revoked or absent.
        return try await open(did: resolved, appPassword: record)
    }

    private func open(
        did: String,
        appPassword: AppPasswordRecord?,
        authorizationGrantDigest: Data? = nil,
        authorizationContext: AccountAuthorizationContext? = nil
    ) async throws -> SwanOAuth.LegacySessionTokens {
        do {
            return try await sessions.issue(
                did: did,
                appPassword: appPassword,
                authorizationGrantDigest: authorizationGrantDigest,
                authorizationContext: authorizationContext
            )
        } catch {
            throw SwanLegacySessionXRPCFailure.unavailable
        }
    }

    // MARK: refreshSession

    func refreshSession(_ request: Request, context: SwanHTTPRequestContext) async -> Response {
        do {
            try await requireNoQuery(request, context: context)
            let presented = try bearerToken(request)
            let tokens: SwanOAuth.LegacySessionTokens
            do {
                tokens = try await sessions.refresh(refreshJWT: presented)
            } catch {
                throw SwanLegacySessionXRPCFailure.expiredToken
            }
            let handle = try await directory.canonicalHandle(did: tokens.did)
            return try json(
                .ok,
                ComAtprotoServerRefreshSession.Output(
                    accessJwt: tokens.accessJWT,
                    refreshJwt: tokens.refreshJWT,
                    handle: try Handle(handleString: handle ?? ""),
                    did: try DID(didString: tokens.did),
                    didDoc: nil,
                    active: true,
                    status: nil
                )
            )
        } catch {
            return response(for: error)
        }
    }

    // MARK: getSession

    func getSession(_ request: Request, context: SwanHTTPRequestContext) async -> Response {
        do {
            let presented = try bearerToken(request)
            let authorization: AuthorizationContext
            do {
                authorization = try await sessions.authorize(accessJWT: presented)
            } catch {
                throw SwanLegacySessionXRPCFailure.expiredToken
            }
            guard case let .accountLegacySession(did, _) = authorization else {
                throw SwanLegacySessionXRPCFailure.expiredToken
            }
            let handle = try await directory.canonicalHandle(did: did)
            return try json(
                .ok,
                ComAtprotoServerGetSession.Output(
                    handle: try Handle(handleString: handle ?? ""),
                    did: try DID(didString: did),
                    didDoc: nil,
                    // Swan does not disclose the account's address to a bearer
                    // credential. `transition:email` is the scope that would
                    // govern it, and no preset grants it by default.
                    email: nil,
                    emailConfirmed: nil,
                    emailAuthFactor: nil,
                    active: true,
                    status: nil
                )
            )
        } catch {
            return response(for: error)
        }
    }

    // MARK: deleteSession

    func deleteSession(_ request: Request, context: SwanHTTPRequestContext) async -> Response {
        do {
            try await requireNoQuery(request, context: context)
            let presented = try bearerToken(request)
            // Idempotent and silent. Reporting whether the token was genuine
            // would make logout a probe.
            try? await sessions.revoke(refreshJWT: presented)
            return Response(status: .ok, headers: [:], body: .init())
        } catch {
            return response(for: error)
        }
    }

    // MARK: getServiceAuth

    /// Mints the canonical ES256 service token only after the durable legacy
    /// access token has been authorized and the typed scope evaluator admits
    /// the exact `(lxm, aud)` target. This endpoint never enters the obsolete
    /// HMAC ``LegacyAuthService`` path.
    func getServiceAuth(_ request: Request, context: SwanHTTPRequestContext) async -> Response {
        do {
            let now = Date()
            guard let issuer = serviceAuthIssuer else {
                throw SwanLegacySessionXRPCFailure.unavailable
            }
            let presented = try bearerToken(request)
            let parameters = try serviceAuthParameters(from: request.uri.query)
            if let requestedExpiry = parameters.exp {
                let nowEpoch = Int64(now.timeIntervalSince1970.rounded(.towardZero))
                guard requestedExpiry > nowEpoch,
                      requestedExpiry <= nowEpoch + Int64(ProxyServiceJWT.maximumLifetime) else {
                    throw SwanLegacySessionXRPCFailure.invalidRequest
                }
            }
            let authorization: AuthorizationContext
            do {
                authorization = try await sessions.authorize(accessJWT: presented, now: now)
            } catch {
                throw SwanLegacySessionXRPCFailure.expiredToken
            }
            guard case let .accountLegacySession(did, permissions) = authorization else {
                throw SwanLegacySessionXRPCFailure.expiredToken
            }
            do {
                try permissions.requireRPC(
                    .init(lxm: parameters.method, aud: parameters.audience)
                )
            } catch {
                throw SwanLegacySessionXRPCFailure.authenticationRequired
            }
            let token: String
            do {
                token = try await issuer.issueProxyServiceToken(
                    issuer: did,
                    audience: parameters.audience,
                    method: parameters.method,
                    now: now,
                    requestedExpiry: parameters.exp.map {
                        Date(timeIntervalSince1970: TimeInterval($0))
                    }
                )
            } catch {
                throw SwanLegacySessionXRPCFailure.unavailable
            }
            return try json(.ok, ComAtprotoServerGetServiceAuth.Output(token: token))
        } catch {
            return response(for: error)
        }
    }

    // MARK: - App-password management

    /// Every one of these requires a FULL-ACCESS session — upstream's
    /// `ACCESS_FULL` (`createAppPassword.ts:11`). The rule that matters is
    /// anti-escalation: an app password must not mint further app passwords, nor
    /// revoke the credential that would have contained it.
    private func fullAccessSubject(_ request: Request) async throws -> String {
        let presented = try bearerToken(request)
        do {
            return try await sessions.authorizeFullAccess(accessJWT: presented)
        } catch {
            throw SwanLegacySessionXRPCFailure.expiredToken
        }
    }

    func createAppPassword(_ request: Request, context: SwanHTTPRequestContext) async -> Response {
        do {
            try await requireNoQuery(request, context: context)
            let input: ComAtprotoServerCreateAppPassword.Input = try await decodeExactJSON(
                request, context: context, required: ["name"], optional: ["privileged"]
            )
            let subject = try await fullAccessSubject(request)
            guard !input.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  input.name.utf8.count <= 256 else {
                throw SwanLegacySessionXRPCFailure.invalidRequest
            }
            // Petrel's generated Input carries `name` and `privileged` — the
            // standard lexicon has no `scopes` field, so the design's proposed
            // extension is not expressible without a lexicon change. The
            // backward-compatible default IS the mapping the design specifies:
            // `privileged` decides only whether DMs are reachable.
            let scopes = AppPasswordScopes.defaultScopes(privileged: input.privileged ?? false)
            let issued: AppPasswordIssuance
            do {
                issued = try await credentials.issue(
                    did: subject, name: input.name, scopes: scopes, into: appPasswords
                )
            } catch let failure as AppPasswordStoreError {
                switch failure {
                case .duplicateName, .limitReached: throw SwanLegacySessionXRPCFailure.invalidRequest
                case .unknownAccount: throw SwanLegacySessionXRPCFailure.expiredToken
                }
            } catch {
                throw SwanLegacySessionXRPCFailure.unavailable
            }
            // The one and only time the secret is returned.
            return try json(
                .ok,
                ComAtprotoServerCreateAppPassword.AppPassword(
                    name: issued.record.name,
                    password: issued.password,
                    createdAt: ATProtocolDate(date: issued.record.createdAt),
                    privileged: input.privileged ?? false
                )
            )
        } catch {
            return response(for: error)
        }
    }

    func listAppPasswords(_ request: Request, context: SwanHTTPRequestContext) async -> Response {
        do {
            let subject = try await fullAccessSubject(request)
            let rows: [AppPasswordRecord]
            do {
                rows = try await appPasswords.listAppPasswords(did: subject)
            } catch {
                throw SwanLegacySessionXRPCFailure.unavailable
            }
            return try json(
                .ok,
                ComAtprotoServerListAppPasswords.Output(
                    passwords: rows.map { record in
                        ComAtprotoServerListAppPasswords.AppPassword(
                            name: record.name,
                            createdAt: ATProtocolDate(date: record.createdAt),
                            // Derived from the stored scopes rather than a
                            // separate column, so the two can never disagree.
                            privileged: record.scopes
                                .split(separator: " ")
                                .contains("transition:chat.bsky")
                        )
                    }
                )
            )
        } catch {
            return response(for: error)
        }
    }

    func revokeAppPassword(_ request: Request, context: SwanHTTPRequestContext) async -> Response {
        do {
            try await requireNoQuery(request, context: context)
            let input: ComAtprotoServerRevokeAppPassword.Input = try await decodeExactJSON(
                request, context: context, required: ["name"], optional: []
            )
            let subject = try await fullAccessSubject(request)
            do {
                // Deleting the row cascades to its session families and their
                // tokens, so revocation ends the credential's live sessions in
                // the same statement.
                try await appPasswords.revokeAppPassword(did: subject, name: input.name)
            } catch {
                throw SwanLegacySessionXRPCFailure.unavailable
            }
            return Response(status: .ok, headers: [:], body: .init())
        } catch {
            return response(for: error)
        }
    }

    // MARK: shared

    private func bearerToken(_ request: Request) throws -> String {
        guard let header = request.headers[.authorization],
              header.hasPrefix("Bearer "),
              case let token = String(header.dropFirst("Bearer ".count)),
              !token.isEmpty else {
            throw SwanLegacySessionXRPCFailure.invalidToken
        }
        return token
    }

    private struct ServiceAuthParameters: Sendable {
        let audience: String
        let method: String
        let exp: Int64?
    }

    /// Strictly parses the generated `getServiceAuth` query shape. Both
    /// audience and method are required even for transition grants; omitting
    /// either would let a narrow legacy bearer mint a token with a broader
    /// downstream meaning.
    private func serviceAuthParameters(from query: String?) throws -> ServiceAuthParameters {
        guard let query, !query.isEmpty,
              let components = URLComponents(string: "https://swan.invalid/?\(query)"),
              let items = components.queryItems else {
            throw SwanLegacySessionXRPCFailure.authenticationRequired
        }
        var audience: String?
        var method: String?
        var exp: Int64?
        for item in items {
            switch item.name {
            case "aud":
                guard audience == nil, let value = item.value, !value.isEmpty else {
                    throw SwanLegacySessionXRPCFailure.authenticationRequired
                }
                audience = value
            case "lxm":
                guard method == nil, let value = item.value,
                      let nsid = try? NSID(nsidString: value) else {
                    throw SwanLegacySessionXRPCFailure.authenticationRequired
                }
                method = nsid.description
            case "exp":
                guard exp == nil, let value = item.value, let parsed = Int64(value), parsed >= 0 else {
                    throw SwanLegacySessionXRPCFailure.invalidRequest
                }
                exp = parsed
            default:
                throw SwanLegacySessionXRPCFailure.invalidRequest
            }
        }
        guard let audience, let method else {
            throw SwanLegacySessionXRPCFailure.authenticationRequired
        }
        return ServiceAuthParameters(audience: audience, method: method, exp: exp)
    }

    private func padTo(_ floor: Duration, since started: ContinuousClock.Instant) async {
        let elapsed = ContinuousClock.now - started
        guard elapsed < floor else { return }
        try? await Task.sleep(for: floor - elapsed)
    }

    private func json(_ status: HTTPResponse.Status, _ value: some Encodable) throws -> Response {
        let data = try JSONEncoder().encode(value)
        return Response(
            status: status,
            headers: [.contentType: "application/json"],
            body: .init(byteBuffer: ByteBuffer(bytes: data))
        )
    }

    private func response(for error: any Error) -> Response {
        // A staged rejection uses its configured failure on the wire.
        // For noCredentialMatched / identifierUnresolved, failure is
        // AuthenticationRequired. For authFactorTokenRequired, failure is
        // AuthFactorTokenRequired (HTTP 401).
        let failure =
            (error as? LegacyLoginRejection)?.failure
            ?? (error as? SwanLegacySessionXRPCFailure)
            ?? .invalidRequest
        switch failure {
        case .invalidRequest:
            return errorResponse(.badRequest, "InvalidRequest")
        case .authenticationRequired:
            return errorResponse(.unauthorized, "AuthenticationRequired")
        case .authFactorTokenRequired:
            return errorResponse(.unauthorized, "AuthFactorTokenRequired")
        case .invalidToken:
            return errorResponse(.badRequest, "InvalidToken")
        case .expiredToken:
            return errorResponse(.badRequest, "ExpiredToken")
        case .payloadTooLarge:
            return errorResponse(.contentTooLarge, "InvalidRequest")
        case .rateLimited:
            return errorResponse(.tooManyRequests, "RateLimitExceeded")
        case .unavailable:
            return errorResponse(.serviceUnavailable, "temporarily_unavailable")
        }
    }

    private func errorResponse(_ status: HTTPResponse.Status, _ code: String) -> Response {
        Response(
            status: status,
            headers: [.contentType: "application/json"],
            body: .init(byteBuffer: ByteBuffer(string: "{\"error\":\"\(code)\"}"))
        )
    }

    private func requireNoQuery(_ request: Request, context: SwanHTTPRequestContext) async throws {
        guard request.uri.query?.isEmpty ?? true else {
            try? await drainRejectedRequestBody(
                request,
                admission: requestBodyAdmission.admission,
                policy: requestBodyAdmission.policy,
                termination: context.jsonWriteBodyTermination
            )
            throw SwanLegacySessionXRPCFailure.invalidRequest
        }
    }

    private func decodeExactJSON<Value: Decodable>(
        _ request: Request,
        context: SwanHTTPRequestContext,
        required: Set<String>,
        optional: Set<String>
    ) async throws -> Value {
        let buffer: SwanAdmittedRequestBody
        do {
            buffer = try await collectAdmittedRequestBody(
                request,
                mediaType: .json,
                admission: requestBodyAdmission.admission,
                policy: requestBodyAdmission.policy,
                maximumBytes: SwanLegacySessionXRPCServer.maximumJSONBytes,
                termination: context.jsonWriteBodyTermination
            )
        } catch let failure as SwanRequestBodyCollectionFailure {
            switch failure {
            case .invalidRequest: throw SwanLegacySessionXRPCFailure.invalidRequest
            case .payloadTooLarge: throw SwanLegacySessionXRPCFailure.payloadTooLarge
            case .unavailable: throw SwanLegacySessionXRPCFailure.unavailable
            }
        } catch {
            throw SwanLegacySessionXRPCFailure.invalidRequest
        }
        defer { withExtendedLifetime(buffer) {} }
        guard buffer.readableBytes > 0,
              let bytes = buffer.getBytes(
                  at: buffer.readerIndex, length: buffer.readableBytes
              ) else {
            throw SwanLegacySessionXRPCFailure.invalidRequest
        }
        let data = Data(bytes)
        do {
            try StrictJSON.validate(data)
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw SwanLegacySessionXRPCFailure.invalidRequest
            }
            let keys = Set(object.keys)
            guard required.isSubset(of: keys),
                  keys.isSubset(of: required.union(optional)),
                  !object.values.contains(where: { $0 is NSNull }) else {
                throw SwanLegacySessionXRPCFailure.invalidRequest
            }
            return try JSONDecoder().decode(Value.self, from: data)
        } catch let failure as SwanLegacySessionXRPCFailure {
            throw failure
        } catch {
            throw SwanLegacySessionXRPCFailure.invalidRequest
        }
    }
}

/// Production identifier resolution, over the account control store.
///
/// Handle and DID only. Upstream also accepts an EMAIL as the login identifier
/// (`account-manager.ts:603-607`); Swan does not, and the refusal is the same
/// `authenticationRequired` every other failure gets, so declining an email is
/// not distinguishable from declining a wrong password. Supporting it would need
/// a reverse index from address to account, and that index is itself an
/// enumeration surface — `associatedEmail` is deliberately one-directional here.
public struct SwanDurableLegacySessionDirectory: SwanLegacySessionDirectory {
    private let store: any AccountControlStore

    public init(store: any AccountControlStore) {
        self.store = store
    }

    public func resolveLoginIdentifier(_ identifier: String) async throws -> String? {
        let normalized = identifier.trimmingCharacters(in: .whitespacesAndNewlines)
        // A DID identifier is used as presented; anything else must canonicalize
        // as a handle. Both paths end at the same status check, so a
        // deactivated account is refused exactly like an absent one.
        if let did = try? AccountIdentifiers.validateDID(normalized) {
            let account = try await store.account(did: did)
            return account?.status.authorizesAccount == true ? account?.did : nil
        }
        guard let handle = try? AccountIdentifiers.canonicalHandle(normalized) else {
            return nil
        }
        let account = try await store.account(canonicalHandle: handle)
        return account?.status.authorizesAccount == true ? account?.did : nil
    }

    public func canonicalHandle(did: String) async throws -> String? {
        try await store.account(did: did)?.canonicalHandle
    }
}

/// A per-identifier sliding-window limit on `createSession`.
///
/// An app password is a machine-generated 100-bit secret and the account
/// password is Argon2id-verified, so this is not the thing standing between an
/// attacker and a guess. It bounds COST: every attempt spends two Argon2id
/// evaluations at 64 MiB each, so an unthrottled login endpoint is a memory and
/// CPU amplifier pointed at the host by anyone who can name a handle.
///
/// Keyed by the presented identifier rather than by account, deliberately: an
/// unknown identifier must be throttled the same as a known one, or the limiter
/// itself becomes the existence oracle the login path is careful not to be.
public actor SwanInProcessLegacySessionRateLimiter: SwanLegacySessionRateLimiting {
    private let limit: Int
    private let window: TimeInterval
    private var attempts: [String: [Date]] = [:]

    public init(limit: Int = 30, window: TimeInterval = 300) {
        self.limit = limit
        self.window = window
    }

    public func admitSessionCreation(identifier: String, now: Date) async -> Bool {
        let key = identifier.lowercased()
        let cutoff = now.addingTimeInterval(-window)
        var recent = (attempts[key] ?? []).filter { $0 > cutoff }
        guard recent.count < limit else {
            attempts[key] = recent
            return false
        }
        recent.append(now)
        attempts[key] = recent
        // Opportunistic sweep so a long-lived process does not accumulate one
        // entry per identifier ever presented.
        if attempts.count > 4096 {
            attempts = attempts.compactMapValues { stamps in
                let live = stamps.filter { $0 > cutoff }
                return live.isEmpty ? nil : live
            }
        }
        return true
    }
}
