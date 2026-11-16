import Foundation
import HTTPTypes
import Hummingbird
import NIOCore
import Petrel
import PetrelPLC
import SwanAccounts
import SwanCore
import SwanOAuth
import SwanStorage

/// `com.atproto.server.requestAccountDelete` and
/// `com.atproto.server.deleteAccount`: the standard two-step, in-app account
/// deletion, matching the reference PDS.
///
/// 1. `requestAccountDelete` requires a full-access password session (a
///    legacy session opened with the account password). OAuth credentials and
///    app-password sessions are refused, as upstream does. It mints a
///    single-use, short-lived proof and queues it to the account's email
///    address through the durable account-email outbox.
/// 2. `deleteAccount` takes `{did, password, token}` and no bearer. It checks
///    the account password, then consumes the emailed proof, then runs the
///    same permanent-deletion coordinator the operator path uses: control-plane
///    scrub with the `#account` deleted event, PLC tombstone, key destruction,
///    and account data removal. There is no second deletion implementation.
///
/// Every refusal before the proof is consumed leaves the account untouched.
public struct SwanAccountDeletionXRPCServer: Sendable {
    static let maximumJSONBytes = 8 * 1024
    /// The reference host rejects longer passwords on this route before
    /// hashing (`OLD_PASSWORD_MAX_LENGTH`).
    static let maximumPasswordBytes = 512

    public static let methodNSIDs: Set<String> = [
        ComAtprotoServerRequestAccountDelete.typeIdentifier,
        ComAtprotoServerDeleteAccount.typeIdentifier,
    ]

    private let handlers: SwanAccountDeletionHandlers

    public init(
        sessions: DurableLegacySessionService,
        accounts: DurableAccountDirectory,
        controlStore: any AccountControlStore,
        email: any SwanAccountDeletionEmailing,
        rateLimiter: any SwanAccountEmailXRPCRateLimiting,
        deletion: any AccountPermanentDeletionCoordinating,
        deletionProgress: (any AccountDeletionControlStore)?,
        loginClientIdentityPolicy: SwanLoginClientIdentityPolicy = .direct,
        minimumFailedResponseDuration: Duration = .milliseconds(350)
    ) {
        handlers = SwanAccountDeletionHandlers(
            sessions: sessions,
            accounts: accounts,
            controlStore: controlStore,
            email: email,
            rateLimiter: rateLimiter,
            deletion: deletion,
            deletionProgress: deletionProgress,
            loginClientIdentityPolicy: loginClientIdentityPolicy,
            minimumFailedResponseDuration: minimumFailedResponseDuration
        )
    }

    /// Standalone router for focused HTTP tests.
    public func buildRouter() -> Router<SwanHTTPRequestContext> {
        let router = Router(context: SwanHTTPRequestContext.self)
        register(
            on: router,
            requestBodyAdmission: .init(
                admission: .processShared,
                policy: .productionDefault
            )
        )
        return router
    }

    /// Installs both methods as exact paths. Exact paths outrank the
    /// `com.atproto.server.*` unknown-method guard, which stays in force for
    /// every other method in the namespace.
    func register(
        on router: Router<SwanHTTPRequestContext>,
        requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
    ) {
        let handlers = handlers.with(requestBodyAdmission: requestBodyAdmission)
        let requestNSID = ComAtprotoServerRequestAccountDelete.typeIdentifier
        let deleteNSID = ComAtprotoServerDeleteAccount.typeIdentifier
        router.post("/xrpc/\(requestNSID)") { request, context async -> Response in
            await handlers.requestAccountDelete(request, context: context)
        }
        router.post("/xrpc/\(deleteNSID)") { request, context async -> Response in
            await handlers.deleteAccount(request, context: context)
        }
        let wrongMethods: [HTTPRequest.Method] = [
            .get, .head, .put, .patch, .delete, .connect, .trace,
        ]
        for nsid in [requestNSID, deleteNSID] {
            let path = RouterPath("/xrpc/\(nsid)")
            for method in wrongMethods {
                router.on(path, method: method) { _, _ -> Response in
                    accountDeletionError(.notFound, "EndpointUnavailable")
                }
            }
        }
    }
}

/// The email half of the flow: issue a proof to the account's current
/// address, and consume a presented proof.
public protocol SwanAccountDeletionEmailing: Sendable {
    /// Throws ``AccountEmailRecoveryError/invalidEmail`` when the account has
    /// no address to send the proof to.
    func requestAccountDeletion(did: String, now: Date) async throws
    func consumeAccountDeletionProof(
        did: String,
        proof: String,
        now: Date
    ) async throws -> AccountDeletionProofOutcome
}

/// Production adapter over the durable account-email service. The address is
/// looked up here, from the authenticated DID; HTTP never accepts one.
public struct SwanAccountDeletionEmailAdapter: SwanAccountDeletionEmailing {
    private let service: AccountEmailRecoveryService
    private let store: any AccountControlStore

    public init(
        service: AccountEmailRecoveryService,
        store: any AccountControlStore
    ) {
        self.service = service
        self.store = store
    }

    public func requestAccountDeletion(did: String, now: Date) async throws {
        guard let email = try await store.associatedEmail(did: did) else {
            throw AccountEmailRecoveryError.invalidEmail
        }
        try await service.requestAccountDeletion(did: did, email: email, now: now)
    }

    public func consumeAccountDeletionProof(
        did: String,
        proof: String,
        now: Date
    ) async throws -> AccountDeletionProofOutcome {
        try await service.consumeAccountDeletionProof(did: did, proof: proof, now: now)
    }
}

private enum AccountDeletionXRPCFailure: Error, Equatable {
    case invalidRequest
    case payloadTooLarge
    case noEmail
    case oauthNotSupported
    case badTokenScope
    case expiredSession
    case authenticationRequired
    case invalidToken
    case expiredToken
    case rateLimited
    case unavailable
}

private struct SwanAccountDeletionHandlers: Sendable {
    let sessions: DurableLegacySessionService
    let accounts: DurableAccountDirectory
    let controlStore: any AccountControlStore
    let email: any SwanAccountDeletionEmailing
    let rateLimiter: any SwanAccountEmailXRPCRateLimiting
    let deletion: any AccountPermanentDeletionCoordinating
    let deletionProgress: (any AccountDeletionControlStore)?
    let loginClientIdentityPolicy: SwanLoginClientIdentityPolicy
    let minimumFailedResponseDuration: Duration
    var requestBodyAdmission = SwanRequestBodyAdmissionConfiguration(
        admission: .processShared,
        policy: .productionDefault
    )

    func with(
        requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
    ) -> SwanAccountDeletionHandlers {
        var copy = self
        copy.requestBodyAdmission = requestBodyAdmission
        return copy
    }

    // MARK: requestAccountDelete

    func requestAccountDelete(
        _ request: Request,
        context: SwanHTTPRequestContext
    ) async -> Response {
        let now = Date()
        do {
            try await requireNoQuery(request, context: context)
            try await requireEmptyBody(request, context: context)
            let did = try await fullAccessSubject(request, now: now)
            try await admit(
                operation: .requestAccountDelete,
                did: did,
                request: request,
                context: context,
                now: now
            )
            do {
                try await email.requestAccountDeletion(did: did, now: now)
            } catch AccountEmailRecoveryError.invalidEmail {
                throw AccountDeletionXRPCFailure.noEmail
            } catch AccountEmailRecoveryError.accountNotFound {
                throw AccountDeletionXRPCFailure.expiredSession
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                throw AccountDeletionXRPCFailure.unavailable
            }
            return Response(status: .ok, headers: [.cacheControl: "no-store"])
        } catch {
            return response(for: error)
        }
    }

    /// Upstream gates this route on `ACCESS_FULL` and refuses OAuth outright.
    private func fullAccessSubject(_ request: Request, now: Date) async throws -> String {
        guard let header = request.headers[.authorization] else {
            throw AccountDeletionXRPCFailure.expiredSession
        }
        if header.lowercased().hasPrefix("dpop ") {
            throw AccountDeletionXRPCFailure.oauthNotSupported
        }
        guard header.hasPrefix("Bearer "),
              case let token = String(header.dropFirst("Bearer ".count)),
              !token.isEmpty else {
            throw AccountDeletionXRPCFailure.expiredSession
        }
        do {
            return try await sessions.authorizeFullAccess(accessJWT: token, now: now)
        } catch let error as SwanError {
            if case .unavailable = error {
                throw AccountDeletionXRPCFailure.unavailable
            }
        } catch {
            throw AccountDeletionXRPCFailure.unavailable
        }
        // The token is genuine and live but not full access: an app-password
        // session. Distinguish it the way upstream does ("Bad token scope").
        if (try? await sessions.authorize(accessJWT: token, now: now)) != nil {
            throw AccountDeletionXRPCFailure.badTokenScope
        }
        throw AccountDeletionXRPCFailure.expiredSession
    }

    // MARK: deleteAccount

    func deleteAccount(
        _ request: Request,
        context: SwanHTTPRequestContext
    ) async -> Response {
        let now = Date()
        let started = ContinuousClock.now
        do {
            try await requireNoQuery(request, context: context)
            let input = try await decodeInput(request, context: context)
            let did: String
            do {
                did = try AccountIdentifiers.validateDID(input.did)
            } catch {
                throw AccountDeletionXRPCFailure.invalidRequest
            }
            guard input.password.utf8.count <= SwanAccountDeletionXRPCServer.maximumPasswordBytes
            else {
                throw AccountDeletionXRPCFailure.authenticationRequired
            }
            let clientIP = try clientIPAddress(request, context: context)
            try await admit(
                operation: .deleteAccount,
                did: nil,
                directPeer: clientIP,
                now: now
            )

            // The account password, never an app password, and never the
            // factor ceremony: the emailed proof is this flow's second factor.
            // An unknown or inactive DID takes the same one-Argon2id path as
            // a wrong password, so the route is not an account oracle.
            let handle: String?
            do {
                handle = try await controlStore.account(did: did)?.canonicalHandle
            } catch {
                throw AccountDeletionXRPCFailure.unavailable
            }
            let loginHandle = handle ?? did
            do {
                guard try await accounts.admitLogin(
                    handle: loginHandle,
                    directPeer: clientIP,
                    now: now
                ) == .allowed else {
                    throw AccountDeletionXRPCFailure.rateLimited
                }
            } catch let failure as AccountDeletionXRPCFailure {
                throw failure
            } catch {
                throw AccountDeletionXRPCFailure.unavailable
            }
            let outcome: AccountLoginAuthenticationOutcome
            do {
                outcome = try await accounts.authenticatePasswordForMFAChallenge(
                    handle: loginHandle,
                    password: input.password,
                    now: now
                )
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                throw AccountDeletionXRPCFailure.unavailable
            }
            guard case let .authenticated(success) = outcome,
                  handle != nil,
                  success.account.did == did else {
                throw AccountDeletionXRPCFailure.authenticationRequired
            }

            switch try await consumeProof(did: did, token: input.token, now: now) {
            case .consumed:
                break
            case .expiredToken:
                throw AccountDeletionXRPCFailure.expiredToken
            case .invalidToken:
                throw AccountDeletionXRPCFailure.invalidToken
            }

            try await runPermanentDeletion(did: did, now: now)
            return Response(status: .ok, headers: [.cacheControl: "no-store"])
        } catch {
            if (error as? AccountDeletionXRPCFailure) == .authenticationRequired {
                await padTo(minimumFailedResponseDuration, since: started)
            }
            return response(for: error)
        }
    }

    /// Consumes the emailed proof before the shared deletion coordinator
    /// runs. A proof that passed every check is spent even if the coordinator
    /// then fails before its first durable stage; the account holder gets a
    /// 503 and requests a new email.
    private func consumeProof(
        did: String,
        token: String,
        now: Date
    ) async throws -> AccountDeletionProofOutcome {
        do {
            return try await email.consumeAccountDeletionProof(did: did, proof: token, now: now)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw AccountDeletionXRPCFailure.unavailable
        }
    }

    /// Runs the shared coordinator. Once its first durable stage has
    /// committed the account can no longer authenticate and the remaining
    /// stages resume at the next startup, so a failure after that point is
    /// still a completed request from the account holder's point of view.
    private func runPermanentDeletion(did: String, now: Date) async throws {
        do {
            _ = try await deletion.beginAndResume(
                did: did,
                declaration: AccountLifecycleDeclaration(
                    tombstone: try AccountTombstoneMetadata(
                        declaredAt: now,
                        reason: "account-holder-request"
                    )
                ),
                now: now
            )
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            if let deletionProgress {
                let job = try? await deletionProgress.deletionJob(did: did)
                let tombstone = try? await deletionProgress.tombstone(did: did)
                if job != nil || tombstone != nil { return }
            }
            throw AccountDeletionXRPCFailure.unavailable
        }
    }

    private struct Input: Decodable {
        let did: String
        let password: String
        let token: String
    }

    private func decodeInput(
        _ request: Request,
        context: SwanHTTPRequestContext
    ) async throws -> Input {
        let buffer: SwanAdmittedRequestBody
        do {
            buffer = try await collectAdmittedRequestBody(
                request,
                mediaType: .json,
                admission: requestBodyAdmission.admission,
                policy: requestBodyAdmission.policy,
                maximumBytes: SwanAccountDeletionXRPCServer.maximumJSONBytes,
                termination: context.jsonWriteBodyTermination
            )
        } catch let failure as SwanRequestBodyCollectionFailure {
            switch failure {
            case .invalidRequest: throw AccountDeletionXRPCFailure.invalidRequest
            case .payloadTooLarge: throw AccountDeletionXRPCFailure.payloadTooLarge
            case .unavailable: throw AccountDeletionXRPCFailure.unavailable
            }
        } catch {
            throw AccountDeletionXRPCFailure.invalidRequest
        }
        defer { withExtendedLifetime(buffer) {} }
        guard buffer.readableBytes > 0,
              let bytes = buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes)
        else {
            throw AccountDeletionXRPCFailure.invalidRequest
        }
        let data = Data(bytes)
        do {
            try StrictJSON.validate(data)
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  Set(object.keys) == ["did", "password", "token"],
                  object.values.allSatisfy({ $0 is String }) else {
                throw AccountDeletionXRPCFailure.invalidRequest
            }
            return try JSONDecoder().decode(Input.self, from: data)
        } catch let failure as AccountDeletionXRPCFailure {
            throw failure
        } catch {
            throw AccountDeletionXRPCFailure.invalidRequest
        }
    }

    // MARK: shared

    private func clientIPAddress(
        _ request: Request,
        context: SwanHTTPRequestContext
    ) throws -> String {
        do {
            return try loginClientIdentityPolicy.clientIPAddress(
                directPeer: context.remoteAddress?.ipAddress,
                headers: request.headers
            )
        } catch {
            throw AccountDeletionXRPCFailure.unavailable
        }
    }

    private func admit(
        operation: SwanAccountEmailRateLimitOperation,
        did: String?,
        request: Request,
        context: SwanHTTPRequestContext,
        now: Date
    ) async throws {
        try await admit(
            operation: operation,
            did: did,
            directPeer: clientIPAddress(request, context: context),
            now: now
        )
    }

    private func admit(
        operation: SwanAccountEmailRateLimitOperation,
        did: String?,
        directPeer: String,
        now: Date
    ) async throws {
        let admission: SwanAccountEmailRateLimitRequest
        do {
            admission = try SwanAccountEmailRateLimitRequest(
                operation: operation,
                did: did,
                directPeer: directPeer
            )
        } catch {
            throw AccountDeletionXRPCFailure.unavailable
        }
        let permitted: Bool
        do {
            permitted = try await rateLimiter.permits(admission, now: now)
        } catch {
            throw AccountDeletionXRPCFailure.unavailable
        }
        guard permitted else { throw AccountDeletionXRPCFailure.rateLimited }
    }

    private func requireNoQuery(
        _ request: Request,
        context: SwanHTTPRequestContext
    ) async throws {
        guard request.uri.query?.isEmpty ?? true else {
            try? await drainRejectedRequestBody(
                request,
                admission: requestBodyAdmission.admission,
                policy: requestBodyAdmission.policy,
                termination: context.jsonWriteBodyTermination
            )
            throw AccountDeletionXRPCFailure.invalidRequest
        }
    }

    private func requireEmptyBody(
        _ request: Request,
        context: SwanHTTPRequestContext
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
                throw AccountDeletionXRPCFailure.invalidRequest
            }
        } catch let failure as SwanRequestBodyCollectionFailure {
            if failure == .unavailable {
                throw AccountDeletionXRPCFailure.unavailable
            }
            throw AccountDeletionXRPCFailure.invalidRequest
        }
    }

    private func padTo(_ floor: Duration, since started: ContinuousClock.Instant) async {
        let elapsed = ContinuousClock.now - started
        guard elapsed < floor else { return }
        try? await Task.sleep(for: floor - elapsed)
    }

    private func response(for error: any Error) -> Response {
        guard let failure = error as? AccountDeletionXRPCFailure else {
            return accountDeletionError(.serviceUnavailable, "temporarily_unavailable")
        }
        switch failure {
        case .invalidRequest:
            return accountDeletionError(.badRequest, "InvalidRequest")
        case .payloadTooLarge:
            return accountDeletionError(.contentTooLarge, "InvalidRequest")
        case .noEmail:
            return accountDeletionError(
                .badRequest, "InvalidRequest",
                message: "account does not have an email address"
            )
        case .oauthNotSupported:
            return accountDeletionError(
                .forbidden, "Forbidden",
                message: "OAuth credentials are not supported for this endpoint"
            )
        case .badTokenScope:
            return accountDeletionError(.badRequest, "InvalidToken", message: "Bad token scope")
        case .expiredSession:
            return accountDeletionError(.badRequest, "ExpiredToken")
        case .authenticationRequired:
            return accountDeletionError(
                .unauthorized, "AuthenticationRequired",
                message: "Invalid did or password"
            )
        case .invalidToken:
            return accountDeletionError(.badRequest, "InvalidToken", message: "Token is invalid")
        case .expiredToken:
            return accountDeletionError(.badRequest, "ExpiredToken", message: "Token is expired")
        case .rateLimited:
            return accountDeletionError(.tooManyRequests, "RateLimitExceeded")
        case .unavailable:
            return accountDeletionError(.serviceUnavailable, "temporarily_unavailable")
        }
    }
}

private func accountDeletionError(
    _ status: HTTPResponse.Status,
    _ code: String,
    message: String? = nil
) -> Response {
    var body = ["error": code]
    if let message { body["message"] = message }
    let data = (try? SwanJSONEncoders.sortedKeys.encode(body)) ?? Data("{}".utf8)
    return Response(
        status: status,
        headers: [.contentType: "application/json", .cacheControl: "no-store"],
        body: .init(byteBuffer: ByteBuffer(data: data))
    )
}
