import Crypto
import Foundation
import SwanCore
import SwanStorage

// MARK: - Public signup advertisement

public struct SignupPolicyDescription: Codable, Sendable, Equatable {
    public let policy: SignupPolicy
    public let inviteCodeRequired: Bool
    public let turnstileRequired: Bool
    public let emailVerificationRequired: Bool

    public init(policy: SignupPolicy, emailVerificationRequired: Bool = true) {
        self.policy = policy
        inviteCodeRequired = policy.advertisesInviteCodeRequired
        turnstileRequired = policy.requiresTurnstile
        self.emailVerificationRequired = policy != .closed && emailVerificationRequired
    }
}

public struct SignupPolicyService: Sendable {
    public let policy: SignupPolicy
    public let allowedHandleDomains: [String]

    public init(policy: SignupPolicy, allowedHandleDomains: [String] = []) throws {
        guard allowedHandleDomains.count <= 64,
              allowedHandleDomains.allSatisfy(Self.validDomain)
        else {
            throw SwanError.invalidIdentifier("signup handle domains")
        }
        self.policy = policy
        self.allowedHandleDomains = allowedHandleDomains.map { $0.lowercased() }.sorted()
    }

    public var description: SignupPolicyDescription {
        .init(policy: policy)
    }

    public func permits(handle: String, inviteCode: String?) -> Bool {
        guard policy.permitsPublicSignup,
              AccountControlIdentifiers.isCanonicalHandle(handle) else { return false }
        guard allowedHandleDomains.isEmpty || allowedHandleDomains.contains(where: { handle == $0 || handle.hasSuffix("." + $0) }) else { return false }
        return policy != .inviteRequired || !(inviteCode?.isEmpty ?? true)
    }

    private static func validDomain(_ value: String) -> Bool {
        let value = value.lowercased()
        return (1 ... 253).contains(value.utf8.count)
            && value.split(separator: ".").allSatisfy { label in
                !label.isEmpty && label.utf8.count <= 63
                    && label.first != "-" && label.last != "-"
                    && label.utf8.allSatisfy { ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) || $0 == 45 }
            }
    }
}

// MARK: - Hashed invite material

public struct SignupSecret: Sendable {
    fileprivate let bytes: Data
    public init(_ bytes: Data) throws {
        guard bytes.count == 32 else { throw SwanError.invalidIdentifier("signup secret") }
        self.bytes = bytes
    }
}

public struct SignupInviteIssue: Sendable, Equatable {
    public let code: String
    public let digest: Data
    public let expiresAt: Date?
}

public struct SignupInviteService: Sendable {
    private let secret: SignupSecret
    public init(secret: SignupSecret) {
        self.secret = secret
    }

    public func issue(code: String, expiresAt: Date? = nil) throws -> SignupInviteIssue {
        guard Self.validCode(code), expiresAt.map({ $0 > Date() }) ?? true else {
            throw SwanError.invalidIdentifier("signup invite")
        }
        return .init(code: code, digest: digest(code: code), expiresAt: expiresAt)
    }

    /// Generates the one-time bearer value for an operator. Only the caller
    /// that receives this result may present the code; storage receives the
    /// digest from ``SignupInviteIssue``.
    public func generate(expiresAt: Date? = nil) throws -> SignupInviteIssue {
        var generator = SystemRandomNumberGenerator()
        let bytes = Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255, using: &generator) })
        let code = bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        return try issue(code: code, expiresAt: expiresAt)
    }

    public func digest(code: String) throws -> Data {
        guard Self.validCode(code) else { throw SwanError.invalidIdentifier("signup invite") }
        return digestUnchecked(code: code)
    }

    fileprivate func digestUnchecked(code: String) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data("swan.signup.invite.v1\0".utf8) + Data(code.utf8), using: SymmetricKey(data: secret.bytes)))
    }

    private static func validCode(_ code: String) -> Bool {
        (16 ... 256).contains(code.utf8.count) && code.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || $0 == 45 || $0 == 95
        }
    }
}

public struct SignupEmailProofIssue: Sendable, Equatable {
    public let code: String
    public let digest: Data
    public let email: AccountEmailAddress
    public let handle: String
    public let expiresAt: Date
}

/// Generates and verifies email proofs without retaining the bearer code.
/// Delivery is deliberately left to the existing durable email outbox; the
/// returned digest is the only value accepted by the signup authorization.
public struct SignupEmailProofService: Sendable {
    private let secret: SignupSecret
    public init(secret: SignupSecret) {
        self.secret = secret
    }

    public func issue(email: AccountEmailAddress, handle: String, expiresAt: Date) throws -> SignupEmailProofIssue {
        guard AccountControlIdentifiers.isCanonicalHandle(handle), expiresAt > Date() else { throw SwanError.invalidIdentifier("signup email proof") }
        var generator = SystemRandomNumberGenerator()
        let random = Data((0 ..< 24).map { _ in UInt8.random(in: 0 ... 255, using: &generator) })
        let code = random.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        return try .init(code: code, digest: digestUnchecked(code: code, email: email, handle: handle), email: email, handle: handle, expiresAt: expiresAt)
    }

    public func digest(code: String, email: AccountEmailAddress, handle: String) throws -> Data {
        guard (16 ... 256).contains(code.utf8.count), AccountControlIdentifiers.isCanonicalHandle(handle) else { throw SwanError.invalidIdentifier("signup email proof") }
        return digestUnchecked(code: code, email: email, handle: handle)
    }

    private func digestUnchecked(code: String, email: AccountEmailAddress, handle: String) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data("swan.signup.email-proof.v1\0\(email.value)\0\(handle)\0\(code)".utf8), using: SymmetricKey(data: secret.bytes)))
    }
}

// MARK: - Turnstile siteverify

public struct TurnstileSiteVerifyRequest: Sendable, Equatable {
    public let secret: Data
    public let response: String
    public let remoteIP: String?
    public init(secret: Data, response: String, remoteIP: String?) {
        self.secret = secret; self.response = response; self.remoteIP = remoteIP
    }
}

public struct TurnstileSiteVerifyResponse: Sendable, Equatable {
    public let success: Bool
    public let challengeTimestamp: Date?
    public let hostname: String?
    public let action: String?
    public let errorCodes: [String]
    public init(success: Bool, challengeTimestamp: Date? = nil, hostname: String? = nil, action: String? = nil, errorCodes: [String] = []) {
        self.success = success; self.challengeTimestamp = challengeTimestamp; self.hostname = hostname; self.action = action; self.errorCodes = errorCodes
    }
}

public protocol TurnstileHTTPTransport: Sendable {
    func verify(_ request: TurnstileSiteVerifyRequest) async throws -> TurnstileSiteVerifyResponse
}

public enum TurnstileVerificationError: Error, Sendable, Equatable {
    case missing, transport, failed, expired, duplicate, wrongHostname, wrongAction, malformed
}

public actor TurnstileVerifier {
    private let secret: Data
    private let hostname: String
    private let action: String
    private let maxAge: TimeInterval
    private let timeout: Duration
    private let transport: any TurnstileHTTPTransport
    private var used: Set<Data> = []
    private var reservations: [Data: Date] = [:]
    private let maximumReservations = 1024

    public init(secret: Data, hostname: String, action: String, maxAge: TimeInterval = 300, timeout: Duration = .seconds(5), transport: any TurnstileHTTPTransport) throws {
        guard secret.count >= 16, !hostname.isEmpty, !action.isEmpty, maxAge.isFinite, (1 ... 900).contains(maxAge) else { throw SwanError.invalidIdentifier("Turnstile configuration") }
        self.secret = secret; self.hostname = hostname.lowercased(); self.action = action; self.maxAge = maxAge; self.timeout = timeout; self.transport = transport
    }

    public func verify(token: String, remoteIP: String?, now: Date = Date()) async throws {
        guard !token.isEmpty, token.utf8.count <= 2048 else { throw TurnstileVerificationError.missing }
        let digest = Data(SHA256.hash(data: Data(token.utf8)))
        guard !used.contains(digest) else { throw TurnstileVerificationError.duplicate }
        reservations = reservations.filter { $0.value > now }
        guard reservations.count < maximumReservations else { throw TurnstileVerificationError.transport }
        guard reservations.updateValue(now.addingTimeInterval(maxAge), forKey: digest) == nil else { throw TurnstileVerificationError.duplicate }
        let transport = transport
        let request = TurnstileSiteVerifyRequest(secret: secret, response: token, remoteIP: remoteIP)
        let response: TurnstileSiteVerifyResponse
        do {
            response = try await withThrowingTaskGroup(of: TurnstileSiteVerifyResponse.self) { group in
                group.addTask { try await transport.verify(request) }
                group.addTask { try await Task.sleep(for: self.timeout); throw TurnstileVerificationError.transport }
                defer { group.cancelAll() }
                return try await group.next()!
            }
        } catch let error as TurnstileVerificationError { reservations.removeValue(forKey: digest); throw error }
        catch { reservations.removeValue(forKey: digest); throw TurnstileVerificationError.transport }
        guard response.success else { reservations.removeValue(forKey: digest); throw TurnstileVerificationError.failed }
        guard let challenged = response.challengeTimestamp, abs(now.timeIntervalSince(challenged)) <= maxAge else { reservations.removeValue(forKey: digest); throw TurnstileVerificationError.expired }
        guard response.hostname?.lowercased() == hostname else { reservations.removeValue(forKey: digest); throw TurnstileVerificationError.wrongHostname }
        guard response.action == action else { reservations.removeValue(forKey: digest); throw TurnstileVerificationError.wrongAction }
        reservations.removeValue(forKey: digest)
        used.insert(digest)
    }
}

/// Production-neutral URLSession adapter. It is deliberately supplied as an
/// injected transport so tests never contact Cloudflare and deployments can
/// provide a peer-pinned/bounded HTTP client without changing verification
/// policy.
public struct URLSessionTurnstileTransport: TurnstileHTTPTransport {
    public let endpoint: URL
    public let timeout: TimeInterval
    public init(endpoint: URL = URL(string: "https://challenges.cloudflare.com/turnstile/v0/siteverify")!, timeout: TimeInterval = 5) throws {
        guard endpoint.scheme?.lowercased() == "https",
              endpoint.host?.lowercased() == "challenges.cloudflare.com",
              endpoint.path == "/turnstile/v0/siteverify",
              timeout.isFinite, (0.1 ... 30).contains(timeout) else { throw SwanError.invalidIdentifier("Turnstile endpoint") }
        self.endpoint = endpoint; self.timeout = timeout
    }

    public func verify(_ request: TurnstileSiteVerifyRequest) async throws -> TurnstileSiteVerifyResponse {
        var urlRequest = URLRequest(url: endpoint, timeoutInterval: timeout)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        var components = URLComponents(); components.queryItems = [URLQueryItem(name: "secret", value: String(decoding: request.secret, as: UTF8.self)), URLQueryItem(name: "response", value: request.response)]
        if let remoteIP = request.remoteIP { components.queryItems?.append(URLQueryItem(name: "remoteip", value: remoteIP)) }
        urlRequest.httpBody = components.percentEncodedQuery?.data(using: .utf8)
        let (data, response) = try await URLSession.shared.data(for: urlRequest)
        guard (200 ..< 300).contains((response as? HTTPURLResponse)?.statusCode ?? 0) else { throw TurnstileVerificationError.transport }
        struct Wire: Decodable { let success: Bool; let challenge_ts: String?; let hostname: String?; let action: String?; let `error-codes`: [String]? }
        let wire = try JSONDecoder().decode(Wire.self, from: data)
        let timestamp = wire.challenge_ts.flatMap { ISO8601DateFormatter().date(from: $0) }
        return TurnstileSiteVerifyResponse(success: wire.success, challengeTimestamp: timestamp, hostname: wire.hostname, action: wire.action, errorCodes: wire.`error-codes` ?? [])
    }
}

// MARK: - Authenticated SMTP transport boundary

public enum SMTPMode: Sendable, Equatable { case startTLS, implicitTLS, plaintextLab }
public enum SMTPAuthMechanism: Sendable, Equatable { case plain, login, xoauth2 }

public struct AuthenticatedSMTPConfiguration: Sendable, Equatable {
    public let host: String; public let port: Int; public let mode: SMTPMode
    public let username: String?; public let password: String?; public let mechanism: SMTPAuthMechanism?
    public let expectedHostname: String?; public let maximumAttempts: Int
    public init(host: String, port: Int, mode: SMTPMode, username: String? = nil, password: String? = nil, mechanism: SMTPAuthMechanism? = nil, expectedHostname: String? = nil, maximumAttempts: Int = 3) throws {
        guard (1 ... 65535).contains(port), !host.isEmpty, (1 ... 8).contains(maximumAttempts), mode == .plaintextLab || (username != nil && password != nil && mechanism != nil) else { throw SwanError.invalidIdentifier("SMTP configuration") }
        if mode != .plaintextLab { guard expectedHostname != nil else { throw SwanError.invalidIdentifier("SMTP TLS hostname") } }
        self.host = host; self.port = port; self.mode = mode; self.username = username; self.password = password; self.mechanism = mechanism; self.expectedHostname = expectedHostname; self.maximumAttempts = maximumAttempts
    }
}

public protocol AuthenticatedSMTPTransport: Sendable {
    func deliver(configuration: AuthenticatedSMTPConfiguration, to: AccountEmailAddress, subject: String, body: String, idempotencyKey: String) async throws
}

/// Concrete transport seam for the NIO SMTP implementation. A TLS session
/// must report the hostname authenticated by certificate validation before
/// this adapter permits SMTP AUTH; callers cannot downgrade that check.
public protocol SMTPTLSConnection: Sendable {
    var authenticatedHostname: String { get }
    func authenticate(username: String, password: String, mechanism: SMTPAuthMechanism) async throws
    func send(to: AccountEmailAddress, subject: String, body: String, idempotencyKey: String) async throws
}

public struct AuthenticatedSMTPNetworkTransport: AuthenticatedSMTPTransport {
    private let connect: @Sendable (AuthenticatedSMTPConfiguration) async throws -> any SMTPTLSConnection
    public init(connect: @escaping @Sendable (AuthenticatedSMTPConfiguration) async throws -> any SMTPTLSConnection) {
        self.connect = connect
    }

    public func deliver(configuration: AuthenticatedSMTPConfiguration, to: AccountEmailAddress, subject: String, body: String, idempotencyKey: String) async throws {
        let connection = try await connect(configuration)
        if configuration.mode != .plaintextLab {
            guard connection.authenticatedHostname.lowercased() == configuration.expectedHostname?.lowercased() else { throw MailpitSMTPDeliveryError.unavailable }
            guard let username = configuration.username, let password = configuration.password, let mechanism = configuration.mechanism else { throw MailpitSMTPDeliveryError.invalidConfiguration }
            try await connection.authenticate(username: username, password: password, mechanism: mechanism)
        }
        try await connection.send(to: to, subject: subject, body: body, idempotencyKey: idempotencyKey)
    }
}

public actor AuthenticatedSMTPDelivery: AccountEmailDelivery {
    public nonisolated let cancellationContract: AccountEmailDeliveryCancellationContract = .bounded
    private let configuration: AuthenticatedSMTPConfiguration
    private let transport: any AuthenticatedSMTPTransport
    private let attemptTimeout: Duration
    private var delivered: Set<String> = []
    public init(configuration: AuthenticatedSMTPConfiguration, transport: any AuthenticatedSMTPTransport, attemptTimeout: Duration = .seconds(30)) throws {
        guard attemptTimeout > .zero else { throw SwanError.invalidIdentifier("SMTP attempt timeout") }
        self.configuration = configuration; self.transport = transport; self.attemptTimeout = attemptTimeout
    }

    public func deliver(to: AccountEmailAddress, subject: String, body: String) async throws {
        guard !subject.contains("\r"), !subject.contains("\n"), body.utf8.count <= 32768 else { throw MailpitSMTPDeliveryError.invalidMessage }
        let key = String(SHA256.hash(data: Data("\(to.value)\0\(subject)\0\(body)".utf8)).description)
        if delivered.contains(key) { return }
        var last: Error?
        for attempt in 0 ..< configuration.maximumAttempts {
            do {
                try await withThrowingTaskGroup(of: Void.self) { group in
                    group.addTask { try await transport.deliver(configuration: configuration, to: to, subject: subject, body: body, idempotencyKey: key) }
                    group.addTask { try await Task.sleep(for: attemptTimeout); throw MailpitSMTPDeliveryError.timedOut }
                    defer { group.cancelAll() }
                    try await group.next()!
                }
                delivered.insert(key); return
            } catch { last = error; if attempt + 1 < configuration.maximumAttempts { try? await Task.sleep(for: .milliseconds(Int64(100 * (1 << attempt)))) } }
        }
        throw last ?? MailpitSMTPDeliveryError.unavailable
    }
}

// MARK: - Recovery-wide revocation and lifecycle

public protocol AccountRecoveryRevocationHooks: Sendable {
    func revokeOAuthSessions(did: String, now: Date) async throws
    func revokeLegacySessions(did: String, now: Date) async throws
    func revokeManagementSessions(did: String, now: Date) async throws
    func revokeAppDerivedSessions(did: String, now: Date) async throws
}

public struct AccountRecoveryRevocationCoordinator: Sendable {
    private let hooks: any AccountRecoveryRevocationHooks
    public init(hooks: any AccountRecoveryRevocationHooks) {
        self.hooks = hooks
    }

    public func revokeAll(for did: String, now: Date = Date()) async throws {
        try await hooks.revokeOAuthSessions(did: did, now: now)
        try await hooks.revokeLegacySessions(did: did, now: now)
        try await hooks.revokeManagementSessions(did: did, now: now)
        try await hooks.revokeAppDerivedSessions(did: did, now: now)
    }
}

public struct AccountLifecycleService: Sendable {
    private let store: any AccountControlStore
    private let deletion: (any AccountDeletionControlStore)?
    private let invites: SignupInviteService?
    public init(store: any AccountControlStore, deletion: (any AccountDeletionControlStore)? = nil, invites: SignupInviteService? = nil) {
        self.store = store; self.deletion = deletion; self.invites = invites
    }

    public func createAccount(_ registration: AccountControlRegistration) async throws -> AccountControlAccount {
        try await store.createAccount(registration)
    }

    public func activate(did: String, now: Date = Date()) async throws -> AccountControlAccount {
        try await store.transitionStatus(did: did, to: .active, declaration: .init(), emitting: nil, now: now)
    }

    public func status(did: String) async throws -> AccountControlAccount? {
        try await store.account(did: did)
    }

    public func deactivate(did: String, now: Date = Date()) async throws -> AccountControlAccount {
        try await store.transitionStatus(did: did, to: .deactivated, declaration: .init(), emitting: nil, now: now)
    }

    public func delete(did: String, now: Date = Date()) async throws -> AccountDeletionJob {
        guard let deletion else { throw AccountDeletionStoreError.unavailable }
        return try await deletion.beginDeletion(did: did, declaration: .init(), now: now)
    }

    public func invite(code: String, expiresAt: Date? = nil) throws -> SignupInviteIssue {
        guard let invites else { throw SwanError.unavailable("invites unavailable") }
        return try invites.issue(code: code, expiresAt: expiresAt)
    }
}

// MARK: - Two-phase signup service

public struct SignupAuthorizationInput: Sendable, Equatable {
    public let requestID: String
    public let authorizationID: SignupAuthorizationID
    public let handle: String
    public let email: AccountEmailAddress?
    public let identityDID: String
    public let emailProofDigest: Data?
    public let inviteDigest: Data?
    public let clientIPBucketDigest: Data
    public init(requestID: String, authorizationID: SignupAuthorizationID, handle: String, email: AccountEmailAddress?, identityDID: String, emailProofDigest: Data?, inviteDigest: Data?, clientIPBucketDigest: Data) throws {
        guard clientIPBucketDigest.count == 32, [emailProofDigest, inviteDigest].compactMap(\.self).allSatisfy({ $0.count == 32 }) else { throw SwanError.invalidIdentifier("signup authorization input") }
        self.requestID = requestID; self.authorizationID = authorizationID; self.handle = handle; self.email = email; self.identityDID = identityDID; self.emailProofDigest = emailProofDigest; self.inviteDigest = inviteDigest; self.clientIPBucketDigest = clientIPBucketDigest
    }
}

public protocol SignupFoundationBundle: Sendable {
    func commitSignup(_ input: SignupFinalizationRequest, now: Date) async throws -> SignupFinalizationResult
}

public enum SignupServiceError: Error, Sendable, Equatable { case closed, inviteRequired, emailProofRequired, turnstileRequired, invalidIdentity, duplicateRequest }

public struct SignupService: Sendable {
    private let policy: SignupPolicyService
    private let store: any SignupAuthorizationStore
    private let turnstile: TurnstileVerifier?
    public init(policy: SignupPolicyService, store: any SignupAuthorizationStore, turnstile: TurnstileVerifier? = nil) {
        self.policy = policy; self.store = store; self.turnstile = turnstile
    }

    public func authorize(_ input: SignupAuthorizationInput, turnstileToken: String? = nil, remoteIP: String? = nil, now: Date = Date(), lifetime: TimeInterval = 600) async throws -> SignupAuthorization {
        guard policy.policy.permitsPublicSignup else { throw SignupServiceError.closed }
        guard input.email != nil, input.emailProofDigest != nil else { throw SignupServiceError.emailProofRequired }
        guard policy.permits(handle: input.handle, inviteCode: input.inviteDigest == nil ? nil : "present") else { throw SignupServiceError.inviteRequired }
        if policy.policy == .openProtected {
            guard input.emailProofDigest != nil else { throw SignupServiceError.emailProofRequired }
            guard let turnstile else { throw SignupServiceError.turnstileRequired }
            guard let turnstileToken, !turnstileToken.isEmpty else { throw SignupServiceError.turnstileRequired }
            try await turnstile.verify(token: turnstileToken, remoteIP: remoteIP, now: now)
        }
        guard input.identityDID.hasPrefix("did:") else { throw SignupServiceError.invalidIdentity }
        let authorization = try SignupAuthorization(id: input.authorizationID, requestID: input.requestID, policy: policy.policy, handle: input.handle, email: input.email?.value, identityDID: input.identityDID, emailProofDigest: input.emailProofDigest, inviteDigest: input.inviteDigest, clientIPBucketDigest: input.clientIPBucketDigest, issuedAt: now, expiresAt: now.addingTimeInterval(lifetime), leaseExpiresAt: now.addingTimeInterval(120))
        try await store.reserve(authorization, now: now)
        return authorization
    }

    public func finalize(_ request: SignupFinalizationRequest, foundation: any SignupFoundationBundle, now: Date = Date()) async throws -> SignupFinalizationResult {
        guard let authorization = try await store.authorization(id: request.authorizationID, now: now), authorization.requestID == request.idempotencyKey else { throw AccountControlStoreError.notFound }
        guard authorization.handle == request.handle, authorization.identityDID == request.identityDID else { throw SignupServiceError.duplicateRequest }
        do {
            _ = try await foundation.commitSignup(request, now: now)
            return try await store.finalize(request, now: now)
        } catch { try? await store.fail(id: request.authorizationID, now: now); throw error }
    }
}

public struct AccountEmailUpdateService: Sendable {
    private let store: any AccountControlStore
    private let recovery: AccountEmailRecoveryService
    public init(store: any AccountControlStore, recovery: AccountEmailRecoveryService) {
        self.store = store; self.recovery = recovery
    }

    public func requestUpdate(did: String, email: AccountEmailAddress, now: Date = Date()) async throws {
        try await store.associateEmail(did: did, email: email, now: now)
        try await recovery.requestEmailConfirmation(did: did, email: email, now: now)
    }
}
