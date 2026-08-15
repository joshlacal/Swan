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
    case invalidToken
    case expiredToken
    case payloadTooLarge
    case rateLimited
    /// Infrastructure, never credentials. Reported as 503 so a storage outage
    /// does not look to a client like a wrong password and trigger a re-login
    /// loop that locks the user out of their own session.
    case unavailable
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

struct SwanLegacySessionXRPCServer: Sendable {
    static let maximumJSONBytes = 8 * 1024

    /// The four methods this service owns.
    static let methodNSIDs: Set<String> = [
        ComAtprotoServerCreateSession.typeIdentifier,
        ComAtprotoServerRefreshSession.typeIdentifier,
        ComAtprotoServerGetSession.typeIdentifier,
        ComAtprotoServerDeleteSession.typeIdentifier,
    ]

    private let sessions: DurableLegacySessionService
    private let credentials: AppPasswordCredentials
    private let appPasswords: any AppPasswordStore
    private let accounts: DurableAccountDirectory
    private let directory: any SwanLegacySessionDirectory
    private let rateLimiter: any SwanLegacySessionRateLimiting
    private let requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
    /// A floor on how long a failed `createSession` takes.
    ///
    /// Upstream pads every login to 350ms (`account-manager.ts:640`) for exactly
    /// this reason: resolving an identifier touches storage, and without a floor
    /// the difference between "no such handle" and "wrong password" is
    /// measurable. Swan already uses this technique for password recovery.
    private let minimumFailedLoginDuration: Duration

    init(
        sessions: DurableLegacySessionService,
        credentials: AppPasswordCredentials,
        appPasswords: any AppPasswordStore,
        accounts: DurableAccountDirectory,
        directory: any SwanLegacySessionDirectory,
        rateLimiter: any SwanLegacySessionRateLimiting,
        requestBodyAdmission: SwanRequestBodyAdmissionConfiguration,
        minimumFailedLoginDuration: Duration = .milliseconds(350)
    ) {
        self.sessions = sessions
        self.credentials = credentials
        self.appPasswords = appPasswords
        self.accounts = accounts
        self.directory = directory
        self.rateLimiter = rateLimiter
        self.requestBodyAdmission = requestBodyAdmission
        self.minimumFailedLoginDuration = minimumFailedLoginDuration
    }

    /// Installs the four routes as EXACT paths.
    ///
    /// They coexist with `registerUnknownPublicEndpointGuards`, which closes
    /// `/xrpc/com.atproto.server.*` with a flat 404: exact paths outrank a
    /// `<prefix>.*` guard in Hummingbird's trie regardless of registration
    /// order, which is how `describeServer` already survives it. The guard is
    /// NOT weakened — every other `com.atproto.server.*` method still 404s.
    func register(on router: Router<SwanHTTPRequestContext>) {
        let handlers = Handlers(
            sessions: sessions,
            credentials: credentials,
            appPasswords: appPasswords,
            accounts: accounts,
            directory: directory,
            rateLimiter: rateLimiter,
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
        router.post("/xrpc/\(ComAtprotoServerDeleteSession.typeIdentifier)") {
            request, context async -> Response in
            await handlers.deleteSession(request, context: context)
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
    let requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
    let minimumFailedLoginDuration: Duration

    // MARK: createSession

    func createSession(_ request: Request, context: SwanHTTPRequestContext) async -> Response {
        let started = ContinuousClock.now
        do {
            try await requireNoQuery(request, context: context)
            let input: ComAtprotoServerCreateSession.Input = try await decodeExactJSON(
                request,
                context: context,
                required: ["identifier", "password"],
                // Both are sent by the official client. `authFactorToken` is
                // accepted and ignored: Swan has no second factor, and rejecting
                // an unknown key would fail a client that always sends it.
                optional: ["authFactorToken", "allowTakendown"]
            )
            guard await rateLimiter.admitSessionCreation(
                identifier: input.identifier, now: Date()
            ) else {
                throw SwanLegacySessionXRPCFailure.rateLimited
            }

            let tokens = try await authenticate(
                identifier: input.identifier,
                password: input.password
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
        password: String
    ) async throws -> LegacySessionTokens {
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
        //    when nothing resolved rather than being skipped.
        let outcome: AccountLoginAuthenticationOutcome
        do {
            outcome = try await accounts.authenticateForLogin(
                handle: handle ?? identifier,
                password: password
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

        if case .authenticated = outcome, let resolved {
            // Full legacy authority, upstream's `AuthScope.Access`.
            return try await open(did: resolved, appPassword: nil)
        }
        guard let resolved else {
            throw SwanLegacySessionXRPCFailure.authenticationRequired
        }
        let record: AppPasswordRecord?
        do {
            record = try await appPasswords.appPassword(did: resolved, digest: digest)
        } catch {
            throw SwanLegacySessionXRPCFailure.unavailable
        }
        guard let record else {
            throw SwanLegacySessionXRPCFailure.authenticationRequired
        }
        return try await open(did: resolved, appPassword: record)
    }

    private func open(
        did: String,
        appPassword: AppPasswordRecord?
    ) async throws -> LegacySessionTokens {
        do {
            return try await sessions.issue(did: did, appPassword: appPassword)
        } catch {
            throw SwanLegacySessionXRPCFailure.unavailable
        }
    }

    // MARK: refreshSession

    func refreshSession(_ request: Request, context: SwanHTTPRequestContext) async -> Response {
        do {
            try await requireNoQuery(request, context: context)
            let presented = try bearerToken(request)
            let tokens: LegacySessionTokens
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
        let failure = (error as? SwanLegacySessionXRPCFailure) ?? .invalidRequest
        switch failure {
        case .invalidRequest:
            return errorResponse(.badRequest, "InvalidRequest")
        case .authenticationRequired:
            return errorResponse(.unauthorized, "AuthenticationRequired")
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
