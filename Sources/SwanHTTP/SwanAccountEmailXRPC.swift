import Foundation
import Hummingbird
import HTTPTypes
import Logging
import NIOCore
import SwanAccounts
import SwanOAuth
import SwanPublicWire
import SwanSpaces
import SwanStorage

/// Narrow OAuth boundary used by the account-email XRPC adapter. Tests can
/// substitute an authorizer without constructing bearer tokens; production
/// delegates to the same DPoP resource authorizer as repository mutations.
public protocol SwanAccountEmailResourceAuthorizing: Sendable {
    func authorizeAccountEmail(
        request: Request,
        method: String,
        fixedPath: String,
        now: Date
    ) async throws -> AuthorizationContext

    func issueAccountEmailNonce(now: Date) async -> String
}

extension SwanOAuthResourceAuthorizer: SwanAccountEmailResourceAuthorizing {
    public func authorizeAccountEmail(
        request: Request,
        method: String,
        fixedPath: String,
        now: Date
    ) async throws -> AuthorizationContext {
        try await authorize(
            request: request,
            method: method,
            fixedPath: fixedPath,
            now: now
        )
    }

    public func issueAccountEmailNonce(now: Date) async -> String {
        issueNonce(now: now)
    }
}

/// The four state-changing or delivery-producing operations which receive
/// durable rate-limit admission. Unsupported email-update operations never
/// reach this boundary.
public enum SwanAccountEmailRateLimitOperation: String, Sendable, Equatable {
    case requestEmailConfirmation = "request-email-confirmation"
    case confirmEmail = "confirm-email"
    case requestPasswordReset = "request-password-reset"
    case resetPassword = "reset-password"
}

/// Only canonical domain identifiers and the client IP selected by
/// ``SwanLoginClientIdentityPolicy`` can reach the rate limiter. The field
/// retains its storage-scope name for compatibility; arbitrary forwarding
/// headers have no representation in this type.
public struct SwanAccountEmailRateLimitRequest: Sendable, Equatable {
    public let operation: SwanAccountEmailRateLimitOperation
    public let did: String?
    public let email: AccountEmailAddress?
    public let directPeer: String

    public init(
        operation: SwanAccountEmailRateLimitOperation,
        did: String? = nil,
        email: AccountEmailAddress? = nil,
        directPeer: String
    ) throws {
        let peerBytes = Array(directPeer.utf8)
        guard did.map(AccountControlIdentifiers.isDID) ?? true,
              email.map({ (try? AccountEmailAddress($0.value)) == $0 }) ?? true,
              (1 ... 128).contains(peerBytes.count),
              peerBytes.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw AccountControlStoreError.invalidInput
        }
        self.operation = operation
        self.did = did
        self.email = email
        self.directPeer = directPeer
    }
}

public protocol SwanAccountEmailXRPCRateLimiting: Sendable {
    func permits(
        _ request: SwanAccountEmailRateLimitRequest,
        now: Date
    ) async throws -> Bool
}

/// Durable, multi-window throttling using only HMAC-derived keys. A bucket
/// label is included in the HMAC input so hour/day limits never overwrite one
/// another in the single-row-per-digest store.
public struct SwanDurableAccountEmailXRPCRateLimiter:
    SwanAccountEmailXRPCRateLimiting,
    Sendable
{
    private struct Rule: Sendable {
        let scope: AccountEmailRateLimitScope
        let bucket: String
        let policy: AccountEmailRateLimitPolicy
    }

    private let store: any AccountControlStore
    private let proofCodec: AccountEmailProofCodec

    public init(
        store: any AccountControlStore,
        proofCodec: AccountEmailProofCodec
    ) {
        self.store = store
        self.proofCodec = proofCodec
    }

    public func permits(
        _ request: SwanAccountEmailRateLimitRequest,
        now: Date
    ) async throws -> Bool {
        let rules = try Self.rules(for: request.operation)
        var allowed = true

        // Consume every applicable bucket even after one reports limited.
        // This keeps the externally visible path independent of which
        // dimension (DID, address, or peer) exhausted its budget.
        for rule in rules {
            guard let rawValue = Self.value(for: rule.scope, request: request)
            else { continue }
            let key = try proofCodec.rateLimitKey(
                scope: rule.scope,
                value: "\(request.operation.rawValue):\(rule.bucket):\(rawValue)"
            )
            switch try await store.consumeEmailRateLimit(
                key: key,
                policy: rule.policy,
                now: now
            ) {
            case .allowed:
                break
            case .limited:
                allowed = false
            }
        }
        return allowed
    }

    private static func value(
        for scope: AccountEmailRateLimitScope,
        request: SwanAccountEmailRateLimitRequest
    ) -> String? {
        switch scope {
        case .did: request.did
        case .email: request.email?.value
        case .directPeer: request.directPeer
        }
    }

    private static func rules(
        for operation: SwanAccountEmailRateLimitOperation
    ) throws -> [Rule] {
        func rule(
            _ scope: AccountEmailRateLimitScope,
            _ bucket: String,
            _ maximumAttempts: Int,
            _ window: TimeInterval
        ) throws -> Rule {
            Rule(
                scope: scope,
                bucket: bucket,
                policy: try AccountEmailRateLimitPolicy(
                    maximumAttempts: maximumAttempts,
                    window: window
                )
            )
        }

        switch operation {
        case .requestEmailConfirmation:
            // The DID windows match the pinned TypeScript host. Direct-peer
            // windows are an additional abuse boundary required by Swan's
            // enumeration-resistant public listener.
            return try [
                rule(.did, "hour", 5, 60 * 60),
                rule(.did, "day", 15, 24 * 60 * 60),
                rule(.directPeer, "hour", 30, 60 * 60),
                rule(.directPeer, "day", 100, 24 * 60 * 60),
            ]
        case .confirmEmail:
            return try [
                rule(.did, "five-minute", 20, 5 * 60),
                rule(.email, "five-minute", 20, 5 * 60),
                rule(.directPeer, "five-minute", 50, 5 * 60),
            ]
        case .requestPasswordReset:
            return try [
                rule(.email, "hour", 5, 60 * 60),
                rule(.email, "day", 15, 24 * 60 * 60),
                rule(.directPeer, "hour", 15, 60 * 60),
                rule(.directPeer, "day", 50, 24 * 60 * 60),
            ]
        case .resetPassword:
            return try [
                rule(.directPeer, "five-minute", 50, 5 * 60),
            ]
        }
    }
}

/// Injectable domain boundary for the six account-email XRPC methods. The
/// unsupported update methods intentionally do not appear here.
public protocol SwanAccountEmailXRPCRecovering: Sendable {
    func requestEmailConfirmation(did: String, now: Date) async throws
    func confirmEmail(
        did: String,
        email: AccountEmailAddress,
        proof: String,
        now: Date
    ) async throws -> AccountEmailConfirmationOutcome
    func requestPasswordRecovery(
        email: AccountEmailAddress,
        now: Date
    ) async throws
    func resetPassword(
        proof: String,
        password: String,
        now: Date
    ) async throws -> AccountPasswordResetOutcome
}

/// Production bridge from an authenticated DID to its current associated
/// mailbox. This lookup is deliberately inside the service adapter: HTTP never
/// accepts an address for requestEmailConfirmation.
public struct SwanAccountEmailRecoveryXRPCAdapter:
    SwanAccountEmailXRPCRecovering,
    Sendable
{
    private let service: AccountEmailRecoveryService
    private let store: any AccountControlStore

    public init(
        service: AccountEmailRecoveryService,
        store: any AccountControlStore
    ) {
        self.service = service
        self.store = store
    }

    public func requestEmailConfirmation(
        did: String,
        now: Date
    ) async throws {
        guard let email = try await store.associatedEmail(did: did) else {
            throw AccountEmailRecoveryError.accountNotFound
        }
        try await service.requestEmailConfirmation(
            did: did,
            email: email,
            now: now
        )
    }

    public func confirmEmail(
        did: String,
        email: AccountEmailAddress,
        proof: String,
        now: Date
    ) async throws -> AccountEmailConfirmationOutcome {
        try await service.confirmEmail(
            did: did,
            email: email,
            proof: proof,
            now: now
        )
    }

    public func requestPasswordRecovery(
        email: AccountEmailAddress,
        now: Date
    ) async throws {
        try await service.requestPasswordRecovery(email: email, now: now)
    }

    public func resetPassword(
        proof: String,
        password: String,
        now: Date
    ) async throws -> AccountPasswordResetOutcome {
        try await service.resetPassword(
            proof: proof,
            password: password,
            now: now
        )
    }
}

/// The account-email handlers deliberately use the same accepted-peer context
/// as the public listener.  Keeping one context type makes it possible to
/// compose these routes into the live Hummingbird application without creating
/// a second application (and a second listener) that could drift in proxy or
/// upload-limit policy.
public typealias SwanAccountEmailRequestContext = SwanHTTPRequestContext

/// Standalone public XRPC application for the bounded account-email slice.
///
/// Keeping this adapter independently constructible permits focused HTTP
/// testing without adding any alternate forwarded-header interpretation.
public struct SwanAccountEmailXRPCServer: Sendable {
    public static let maximumJSONBytes = 8 * 1024
    /// Bounds the remote timing signal from the account-dependent recovery
    /// transaction. The floor is intentionally applied only after syntax,
    /// authorization, and rate-limit admission have succeeded.
    public static let defaultMinimumPasswordRecoveryResponseDuration: Duration =
        .milliseconds(50)

    private let authorizer: any SwanAccountEmailResourceAuthorizing
    private let recovery: any SwanAccountEmailXRPCRecovering
    private let rateLimiter: any SwanAccountEmailXRPCRateLimiting
    private let loginClientIdentityPolicy: SwanLoginClientIdentityPolicy
    private let minimumPasswordRecoveryResponseDuration: Duration

    public init(
        authorizer: any SwanAccountEmailResourceAuthorizing,
        recovery: any SwanAccountEmailXRPCRecovering,
        rateLimiter: any SwanAccountEmailXRPCRateLimiting,
        loginClientIdentityPolicy: SwanLoginClientIdentityPolicy,
        minimumPasswordRecoveryResponseDuration: Duration =
            SwanAccountEmailXRPCServer.defaultMinimumPasswordRecoveryResponseDuration
    ) {
        self.authorizer = authorizer
        self.recovery = recovery
        self.rateLimiter = rateLimiter
        self.loginClientIdentityPolicy = loginClientIdentityPolicy
        self.minimumPasswordRecoveryResponseDuration =
            minimumPasswordRecoveryResponseDuration
    }

    public func buildRouter() -> Router<SwanHTTPRequestContext> {
        let router = Router(context: SwanAccountEmailRequestContext.self)
        register(on: router)
        return router
    }

    /// Installs the bounded account-email routes into an already assembled
    /// public router.  Callers must invoke this before constructing the
    /// Hummingbird `Application`; adding routes after application construction
    /// is intentionally unsupported by Hummingbird.
    public func register(on router: Router<SwanHTTPRequestContext>) {
        register(
            on: router,
            requestBodyAdmission: .init(
                admission: .processShared,
                policy: .productionDefault
            )
        )
    }

    func register(
        on router: Router<SwanHTTPRequestContext>,
        requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
    ) {
        let handlers = SwanAccountEmailXRPCHandlers(
            authorizer: authorizer,
            recovery: recovery,
            rateLimiter: rateLimiter,
            loginClientIdentityPolicy: loginClientIdentityPolicy,
            minimumPasswordRecoveryResponseDuration:
                minimumPasswordRecoveryResponseDuration,
            requestBodyAdmission: requestBodyAdmission
        )
        let requestConfirmationPath = Self.path(
            ComAtprotoServerRequestEmailConfirmation.endpointDescriptor.nsid
        )
        let confirmationPath = Self.path(
            ComAtprotoServerConfirmEmail.endpointDescriptor.nsid
        )
        let requestUpdatePathString =
            "/xrpc/\(ComAtprotoServerRequestEmailUpdate.endpointDescriptor.nsid)"
        let requestUpdatePath = RouterPath(requestUpdatePathString)
        let updatePathString =
            "/xrpc/\(ComAtprotoServerUpdateEmail.endpointDescriptor.nsid)"
        let updatePath = RouterPath(updatePathString)
        let requestResetPath = Self.path(
            ComAtprotoServerRequestPasswordReset.endpointDescriptor.nsid
        )
        let resetPath = Self.path(
            ComAtprotoServerResetPassword.endpointDescriptor.nsid
        )

        router.post(requestConfirmationPath) { request, context async -> Response in
            await handlers.requestEmailConfirmation(request, context: context)
        }
        router.post(confirmationPath) { request, context async -> Response in
            await handlers.confirmEmail(request, context: context)
        }
        router.post(requestUpdatePath) { request, context async -> Response in
            await handlers.rejectRequestEmailUpdate(
                request,
                context: context,
                path: requestUpdatePathString
            )
        }
        router.post(updatePath) { request, context async -> Response in
            await handlers.rejectUpdateEmail(
                request,
                context: context,
                path: updatePathString
            )
        }
        router.post(requestResetPath) { request, context async -> Response in
            await handlers.requestPasswordReset(request, context: context)
        }
        router.post(resetPath) { request, context async -> Response in
            await handlers.resetPassword(request, context: context)
        }

        let paths = [
            requestConfirmationPath,
            confirmationPath,
            requestUpdatePath,
            updatePath,
            requestResetPath,
            resetPath,
        ]
        let wrongMethods: [HTTPRequest.Method] = [
            .get, .head, .put, .patch, .delete, .options, .connect, .trace,
        ]
        for path in paths {
            for method in wrongMethods {
                router.on(path, method: method) { _, _ -> Response in
                    accountEmailError(.notFound, "EndpointUnavailable")
                }
            }
        }
    }

    public func buildApplication(logger: Logger) -> some ApplicationProtocol {
        Application(
            router: buildRouter(),
            configuration: .init(
                address: .hostname("127.0.0.1", port: 0),
                serverName: "swan-account-email"
            ),
            logger: logger
        )
    }

    private static func path(_ nsid: String) -> RouterPath {
        RouterPath("/xrpc/\(nsid)")
    }
}

private enum AccountEmailXRPCFailure: Error {
    case invalidRequest
    case payloadTooLarge
    case invalidEmail
    case accountNotFound
    case invalidToken
    case expiredToken
    case unauthorized
    case nonce
    case rateLimited
    case unavailable
}

private struct SwanAccountEmailXRPCHandlers: Sendable {
    let authorizer: any SwanAccountEmailResourceAuthorizing
    let recovery: any SwanAccountEmailXRPCRecovering
    let rateLimiter: any SwanAccountEmailXRPCRateLimiting
    let loginClientIdentityPolicy: SwanLoginClientIdentityPolicy
    let minimumPasswordRecoveryResponseDuration: Duration
    let requestBodyAdmission: SwanRequestBodyAdmissionConfiguration

    func requestEmailConfirmation(
        _ request: Request,
        context: SwanAccountEmailRequestContext
    ) async -> Response {
        let path = "/xrpc/\(ComAtprotoServerRequestEmailConfirmation.endpointDescriptor.nsid)"
        let now = Date()
        do {
            // Validate before DPoP authorization so a malformed request cannot
            // consume the proof's durable replay reservation.
            try await requireNoQuery(
                request, context: context,
                requestBodyAdmission: requestBodyAdmission)
            try await requireEmptyBody(
                request,
                context: context,
                requestBodyAdmission: requestBodyAdmission
            )
            let subject = try await authorizedSubject(
                request,
                path: path,
                now: now
            )
            try await admit(
                operation: .requestEmailConfirmation,
                did: subject,
                email: nil,
                request: request,
                context: context,
                now: now
            )
            try await recovery.requestEmailConfirmation(
                did: subject,
                now: now
            )
            return accountEmailSuccess()
        } catch {
            return await response(for: error, now: now)
        }
    }

    func confirmEmail(
        _ request: Request,
        context: SwanAccountEmailRequestContext
    ) async -> Response {
        let path = "/xrpc/\(ComAtprotoServerConfirmEmail.endpointDescriptor.nsid)"
        let now = Date()
        do {
            try await requireNoQuery(
                request, context: context,
                requestBodyAdmission: requestBodyAdmission)
            let input: ComAtprotoServerConfirmEmail.Input =
                try await decodeExactJSON(
                    request,
                    context: context,
                    requestBodyAdmission: requestBodyAdmission,
                    required: ["email", "token"],
                    optional: []
                )
            let email: AccountEmailAddress
            do {
                email = try AccountEmailAddress(input.email)
            } catch {
                throw AccountEmailXRPCFailure.invalidEmail
            }
            guard validProof(input.token) else {
                throw AccountEmailXRPCFailure.invalidToken
            }
            let subject = try await authorizedSubject(
                request,
                path: path,
                now: now
            )
            try await admit(
                operation: .confirmEmail,
                did: subject,
                email: email,
                request: request,
                context: context,
                now: now
            )
            switch try await recovery.confirmEmail(
                did: subject,
                email: email,
                proof: input.token,
                now: now
            ) {
            case .confirmed:
                return accountEmailSuccess()
            case .accountNotFound:
                throw AccountEmailXRPCFailure.accountNotFound
            case .invalidEmail:
                throw AccountEmailXRPCFailure.invalidEmail
            case .expiredToken:
                throw AccountEmailXRPCFailure.expiredToken
            case .invalidToken:
                throw AccountEmailXRPCFailure.invalidToken
            }
        } catch {
            return await response(for: error, now: now)
        }
    }

    func rejectRequestEmailUpdate(
        _ request: Request,
        context: SwanHTTPRequestContext,
        path: String
    ) async -> Response {
        let now = Date()
        do {
            try await requireNoQuery(
                request, context: context,
                requestBodyAdmission: requestBodyAdmission)
            try await requireEmptyBody(
                request,
                context: context,
                requestBodyAdmission: requestBodyAdmission
            )
            _ = try await authorizedSubject(request, path: path, now: now)
            return accountEmailError(.forbidden, "Forbidden")
        } catch {
            return await response(for: error, now: now)
        }
    }

    func rejectUpdateEmail(
        _ request: Request,
        context: SwanHTTPRequestContext,
        path: String
    ) async -> Response {
        let now = Date()
        do {
            try await requireNoQuery(
                request, context: context,
                requestBodyAdmission: requestBodyAdmission)
            let input: ComAtprotoServerUpdateEmail.Input =
                try await decodeExactJSON(
                    request,
                    context: context,
                    requestBodyAdmission: requestBodyAdmission,
                    required: ["email"],
                    optional: ["emailAuthFactor", "token"]
                )
            guard (try? AccountEmailAddress(input.email)) != nil,
                  input.token.map(validOpaqueEmailToken) ?? true else {
                throw AccountEmailXRPCFailure.invalidRequest
            }
            _ = try await authorizedSubject(request, path: path, now: now)
            return accountEmailError(.forbidden, "Forbidden")
        } catch {
            return await response(for: error, now: now)
        }
    }

    func requestPasswordReset(
        _ request: Request,
        context: SwanAccountEmailRequestContext
    ) async -> Response {
        let now = Date()
        do {
            try await requireNoQuery(
                request, context: context,
                requestBodyAdmission: requestBodyAdmission)
            let input: ComAtprotoServerRequestPasswordReset.Input =
                try await decodeExactJSON(
                    request,
                    context: context,
                    requestBodyAdmission: requestBodyAdmission,
                    required: ["email"],
                    optional: []
                )
            let email: AccountEmailAddress
            do {
                email = try AccountEmailAddress(input.email)
            } catch {
                throw AccountEmailXRPCFailure.invalidRequest
            }
            let started = ContinuousClock().now
            try await admit(
                operation: .requestPasswordReset,
                did: nil,
                email: email,
                request: request,
                context: context,
                now: now
            )
            do {
                try await recovery.requestPasswordRecovery(
                    email: email,
                    now: now
                )
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                // Account-dependent failures must not become an account
                // existence oracle. The durable service already uses a blind
                // marker for canonical requests; this boundary also collapses
                // storage, capacity, and delivery failures to the same empty
                // response while retaining a bounded timing floor.
            }
            return await passwordRecoverySuccess(startedAt: started)
        } catch {
            return await response(for: error, now: now)
        }
    }

    private func passwordRecoverySuccess(
        startedAt: ContinuousClock.Instant
    ) async -> Response {
        await waitForPasswordRecoveryFloor(startedAt: startedAt)
        return accountEmailSuccess()
    }

    private func passwordRecoveryFailure(
        _ error: any Error,
        now: Date,
        startedAt: ContinuousClock.Instant
    ) async -> Response {
        await waitForPasswordRecoveryFloor(startedAt: startedAt)
        return await response(for: error, now: now)
    }

    private func waitForPasswordRecoveryFloor(
        startedAt: ContinuousClock.Instant
    ) async {
        let clock = ContinuousClock()
        let deadline = startedAt.advanced(
            by: minimumPasswordRecoveryResponseDuration
        )
        if clock.now < deadline {
            try? await clock.sleep(until: deadline)
        }
    }

    func resetPassword(
        _ request: Request,
        context: SwanAccountEmailRequestContext
    ) async -> Response {
        let now = Date()
        let started = ContinuousClock().now
        do {
            try await requireNoQuery(
                request, context: context,
                requestBodyAdmission: requestBodyAdmission)
            let input: ComAtprotoServerResetPassword.Input =
                try await decodeExactJSON(
                    request,
                    context: context,
                    requestBodyAdmission: requestBodyAdmission,
                    required: ["token", "password"],
                    optional: []
                )
            guard validProof(input.token) else {
                throw AccountEmailXRPCFailure.invalidToken
            }
            guard (8 ... 256).contains(input.password.utf8.count) else {
                throw AccountEmailXRPCFailure.invalidRequest
            }
            try await admit(
                operation: .resetPassword,
                did: nil,
                email: nil,
                request: request,
                context: context,
                now: now
            )
            switch try await recovery.resetPassword(
                proof: input.token,
                password: input.password,
                now: now
            ) {
            case .completed:
                return await passwordRecoverySuccess(startedAt: started)
            case .expiredToken:
                throw AccountEmailXRPCFailure.expiredToken
            case .invalidToken:
                throw AccountEmailXRPCFailure.invalidToken
            }
        } catch {
            return await passwordRecoveryFailure(
                error,
                now: now,
                startedAt: started
            )
        }
    }

    private func authorizedSubject(
        _ request: Request,
        path: String,
        now: Date
    ) async throws -> String {
        let authorization: AuthorizationContext
        do {
            authorization = try await authorizer.authorizeAccountEmail(
                request: request,
                method: "POST",
                fixedPath: path,
                now: now
            )
        } catch let failure as SwanResourceAuthorizationFailure {
            switch failure {
            case .nonceChallengeRequired:
                throw AccountEmailXRPCFailure.nonce
            case .denied:
                throw AccountEmailXRPCFailure.unauthorized
            case .unavailable:
                throw AccountEmailXRPCFailure.unavailable
            }
        } catch {
            throw AccountEmailXRPCFailure.unavailable
        }
        guard case let .accountOAuth(subject, scopes) = authorization,
              scopes.contains("atproto") else {
            throw AccountEmailXRPCFailure.unauthorized
        }
        return subject
    }

    private func admit(
        operation: SwanAccountEmailRateLimitOperation,
        did: String?,
        email: AccountEmailAddress?,
        request: Request,
        context: SwanAccountEmailRequestContext,
        now: Date
    ) async throws {
        let clientIPAddress: String
        do {
            clientIPAddress = try loginClientIdentityPolicy.clientIPAddress(
                directPeer: context.remoteAddress?.ipAddress,
                headers: request.headers
            )
        } catch {
            throw AccountEmailXRPCFailure.unavailable
        }
        let admission: SwanAccountEmailRateLimitRequest
        do {
            admission = try SwanAccountEmailRateLimitRequest(
                operation: operation,
                did: did,
                email: email,
                directPeer: clientIPAddress
            )
        } catch {
            throw AccountEmailXRPCFailure.unavailable
        }
        do {
            guard try await rateLimiter.permits(admission, now: now) else {
                throw AccountEmailXRPCFailure.rateLimited
            }
        } catch let failure as AccountEmailXRPCFailure {
            throw failure
        } catch {
            throw AccountEmailXRPCFailure.unavailable
        }
    }

    private func response(for error: any Error, now: Date) async -> Response {
        if let failure = error as? AccountEmailXRPCFailure {
            switch failure {
            case .invalidRequest:
                return accountEmailError(.badRequest, "InvalidRequest")
            case .payloadTooLarge:
                return accountEmailError(.contentTooLarge, "PayloadTooLarge")
            case .invalidEmail:
                return accountEmailError(.badRequest, "InvalidEmail")
            case .accountNotFound:
                return accountEmailError(.badRequest, "AccountNotFound")
            case .invalidToken:
                return accountEmailError(.badRequest, "InvalidToken")
            case .expiredToken:
                return accountEmailError(.badRequest, "ExpiredToken")
            case .unauthorized:
                return accountEmailError(.unauthorized, "Unauthorized")
            case .nonce:
                let nonce = await authorizer.issueAccountEmailNonce(now: now)
                var headers: HTTPFields = [
                    .contentType: "application/json",
                    .cacheControl: "no-store",
                    .wwwAuthenticate: #"DPoP error="use_dpop_nonce""#,
                ]
                headers[HTTPField.Name("DPoP-Nonce")!] = nonce
                return accountEmailError(
                    .unauthorized,
                    "use_dpop_nonce",
                    headers: headers
                )
            case .rateLimited:
                return accountEmailError(
                    .tooManyRequests,
                    "RateLimitExceeded"
                )
            case .unavailable:
                return accountEmailError(
                    .serviceUnavailable,
                    "temporarily_unavailable"
                )
            }
        }
        if let recoveryError = error as? AccountEmailRecoveryError {
            switch recoveryError {
            case .accountNotFound:
                return accountEmailError(.badRequest, "AccountNotFound")
            case .invalidEmail:
                return accountEmailError(.badRequest, "InvalidEmail")
            case .capacityExhausted, .deliveryUnavailable:
                return accountEmailError(
                    .serviceUnavailable,
                    "temporarily_unavailable"
                )
            case .invalidProof:
                return accountEmailError(.badRequest, "InvalidToken")
            case .invalidProofKey:
                return accountEmailError(
                    .serviceUnavailable,
                    "temporarily_unavailable"
                )
            }
        }
        if let storageError = error as? AccountControlStoreError {
            return accountEmailError(
                storageError == .unavailable
                    ? .serviceUnavailable
                    : .badRequest,
                storageError == .unavailable
                    ? "temporarily_unavailable"
                    : "InvalidRequest"
            )
        }
        return accountEmailError(
            .serviceUnavailable,
            "temporarily_unavailable"
        )
    }
}

private func decodeExactJSON<Value: Decodable>(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration,
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
            maximumBytes: SwanAccountEmailXRPCServer.maximumJSONBytes,
            termination: context.jsonWriteBodyTermination
        )
    } catch let failure as SwanRequestBodyCollectionFailure {
        switch failure {
        case .invalidRequest:
            throw AccountEmailXRPCFailure.invalidRequest
        case .payloadTooLarge:
            throw AccountEmailXRPCFailure.payloadTooLarge
        case .unavailable:
            throw AccountEmailXRPCFailure.unavailable
        }
    } catch {
        throw AccountEmailXRPCFailure.invalidRequest
    }
    defer { withExtendedLifetime(buffer) {} }
    guard buffer.readableBytes > 0,
          let bytes = buffer.getBytes(
              at: buffer.readerIndex,
              length: buffer.readableBytes
          ) else {
        throw AccountEmailXRPCFailure.invalidRequest
    }
    let data = Data(bytes)
    do {
        try StrictJSON.validate(data)
        guard let object = try JSONSerialization.jsonObject(
            with: data,
            options: []
        ) as? [String: Any] else {
            throw AccountEmailXRPCFailure.invalidRequest
        }
        let keys = Set(object.keys)
        guard required.isSubset(of: keys),
              keys.isSubset(of: required.union(optional)),
              !object.values.contains(where: { $0 is NSNull }) else {
            throw AccountEmailXRPCFailure.invalidRequest
        }
        return try JSONDecoder().decode(Value.self, from: data)
    } catch let failure as AccountEmailXRPCFailure {
        throw failure
    } catch {
        throw AccountEmailXRPCFailure.invalidRequest
    }
}

private func requireNoQuery(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws {
    guard request.uri.query?.isEmpty ?? true else {
        do {
            try await drainRejectedRequestBody(
                request,
                admission: requestBodyAdmission.admission,
                policy: requestBodyAdmission.policy,
                termination: context.jsonWriteBodyTermination
            )
        } catch {
            throw AccountEmailXRPCFailure.unavailable
        }
        throw AccountEmailXRPCFailure.invalidRequest
    }
}

private func requireEmptyBody(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws {
    do {
        let body = try await collectAdmittedRequestBody(
            request,
            mediaType: .unspecified,
            admission: requestBodyAdmission.admission,
            policy: requestBodyAdmission.policy,
            maximumBytes: 1,
            termination: context.jsonWriteBodyTermination
        )
        defer { withExtendedLifetime(body) {} }
        guard body.readableBytes == 0 else {
            throw AccountEmailXRPCFailure.invalidRequest
        }
    } catch let failure as SwanRequestBodyCollectionFailure {
        if failure == .unavailable {
            throw AccountEmailXRPCFailure.unavailable
        }
        throw AccountEmailXRPCFailure.invalidRequest
    }
}

private func validProof(_ value: String) -> Bool {
    value.utf8.count == 43 && value.utf8.allSatisfy {
        (48 ... 57).contains($0)
            || (65 ... 90).contains($0)
            || (97 ... 122).contains($0)
            || $0 == 45 || $0 == 95
    }
}

private func validOpaqueEmailToken(_ value: String) -> Bool {
    let bytes = Array(value.utf8)
    return (1 ... 256).contains(bytes.count)
        && bytes.allSatisfy { $0 >= 0x21 && $0 <= 0x7e }
}

private func accountEmailSuccess() -> Response {
    Response(status: .ok, headers: [.cacheControl: "no-store"])
}

private func accountEmailError(
    _ status: HTTPResponse.Status,
    _ code: String,
    headers: HTTPFields? = nil
) -> Response {
    struct Body: Encodable {
        let error: String
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = (try? encoder.encode(Body(error: code))) ?? Data("{}".utf8)
    return Response(
        status: status,
        headers: headers ?? [
            .contentType: "application/json",
            .cacheControl: "no-store",
        ],
        body: .init(byteBuffer: ByteBuffer(data: data))
    )
}
