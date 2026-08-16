import Crypto
import Foundation
import NIOCore
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
        return try .init(code: code, digest: digest(code: code), expiresAt: expiresAt)
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

public protocol SignupInvitePersistence: Sendable {
    func persistInvite(_ invite: SignupInvite) async throws
    func listInvites(limit: Int) async throws -> [SignupInvite]
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

    public func protectedEnvelope(code: String, email: AccountEmailAddress, handle: String, deliveryID: String, keyVersion: UInt8 = 1) throws -> Data {
        guard keyVersion == 1, (16 ... 256).contains(code.utf8.count), !deliveryID.isEmpty, AccountControlIdentifiers.isCanonicalHandle(handle) else { throw SwanError.invalidIdentifier("signup email envelope") }
        let key = SymmetricKey(data: secret.bytes)
        let aad = Data("swan.signup.email-envelope.v1\0\(keyVersion)\0\(deliveryID)\0\(email.value)\0\(handle)".utf8)
        let plaintext = Data(code.utf8)
        let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: aad)
        return Data([keyVersion]) + aad + sealed.combined!
    }

    public func openProtectedEnvelope(_ envelope: Data, email: AccountEmailAddress, handle: String, deliveryID: String) throws -> String {
        guard envelope.count > 1, envelope[0] == 1 else { throw SwanError.invalidIdentifier("signup email envelope") }
        let aad = Data("swan.signup.email-envelope.v1\0\(envelope[0])\0\(deliveryID)\0\(email.value)\0\(handle)".utf8)
        guard envelope.dropFirst().prefix(aad.count) == aad else { throw SwanError.invalidIdentifier("signup email envelope") }
        let combined = envelope.dropFirst().dropFirst(aad.count)
        let box = try AES.GCM.SealedBox(combined: combined)
        let code = try AES.GCM.open(box, using: SymmetricKey(data: secret.bytes), authenticating: aad)
        guard (16 ... 256).contains(code.count) else { throw SwanError.invalidIdentifier("signup email code") }
        return String(decoding: code, as: UTF8.self)
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
    func verify(_ request: TurnstileSiteVerifyRequest, deadline: ContinuousClock.Instant) async throws -> TurnstileSiteVerifyResponse
}

public extension TurnstileHTTPTransport {
    func verify(_ request: TurnstileSiteVerifyRequest, deadline _: ContinuousClock.Instant) async throws -> TurnstileSiteVerifyResponse {
        try await verify(request)
    }
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
    private var used: [Data: Date] = [:]
    private var reservations: [Data: Date] = [:]
    private let maximumReservations = 1024
    private let maximumUsed = 4096

    public init(secret: Data, hostname: String, action: String, maxAge: TimeInterval = 300, timeout: Duration = .seconds(5), transport: any TurnstileHTTPTransport) throws {
        guard secret.count >= 16, (1 ... 253).contains(hostname.utf8.count), (1 ... 128).contains(action.utf8.count), maxAge.isFinite, (1 ... 900).contains(maxAge), timeout > .zero, timeout <= .seconds(30) else { throw SwanError.invalidIdentifier("Turnstile configuration") }
        self.secret = secret; self.hostname = hostname.lowercased(); self.action = action; self.maxAge = maxAge; self.timeout = timeout; self.transport = transport
    }

    public func verify(token: String, remoteIP: String?, now: Date = Date()) async throws {
        guard !token.isEmpty, token.utf8.count <= 2048 else { throw TurnstileVerificationError.missing }
        let digest = Data(SHA256.hash(data: Data(token.utf8)))
        used = used.filter { $0.value > now }
        guard used[digest] == nil else { throw TurnstileVerificationError.duplicate }
        guard used.count < maximumUsed else { throw TurnstileVerificationError.transport }
        reservations = reservations.filter { $0.value > now }
        guard reservations.count < maximumReservations else { throw TurnstileVerificationError.transport }
        guard reservations.updateValue(now.addingTimeInterval(maxAge), forKey: digest) == nil else { throw TurnstileVerificationError.duplicate }
        let transport = transport
        let request = TurnstileSiteVerifyRequest(secret: secret, response: token, remoteIP: remoteIP)
        let response: TurnstileSiteVerifyResponse
        do {
            response = try await transport.verify(request, deadline: .now.advanced(by: timeout))
        } catch let error as TurnstileVerificationError { reservations.removeValue(forKey: digest); throw error }
        catch { reservations.removeValue(forKey: digest); throw TurnstileVerificationError.transport }
        guard response.success else { reservations.removeValue(forKey: digest); throw TurnstileVerificationError.failed }
        guard let challenged = response.challengeTimestamp,
              challenged <= now,
              now.timeIntervalSince(challenged) <= maxAge else { reservations.removeValue(forKey: digest); throw TurnstileVerificationError.expired }
        guard response.hostname?.lowercased() == hostname else { reservations.removeValue(forKey: digest); throw TurnstileVerificationError.wrongHostname }
        guard response.action == action else { reservations.removeValue(forKey: digest); throw TurnstileVerificationError.wrongAction }
        reservations.removeValue(forKey: digest)
        used[digest] = now.addingTimeInterval(maxAge)
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
              endpoint.port == nil,
              endpoint.user == nil, endpoint.password == nil,
              endpoint.query == nil, endpoint.fragment == nil,
              endpoint.path == "/turnstile/v0/siteverify",
              timeout.isFinite, (0.1 ... 30).contains(timeout) else { throw SwanError.invalidIdentifier("Turnstile endpoint") }
        self.endpoint = endpoint; self.timeout = timeout
    }

    public func verify(_ request: TurnstileSiteVerifyRequest) async throws -> TurnstileSiteVerifyResponse {
        try await verify(request, deadline: .now.advanced(by: .seconds(timeout)))
    }

    public func verify(_ request: TurnstileSiteVerifyRequest, deadline: ContinuousClock.Instant) async throws -> TurnstileSiteVerifyResponse {
        let now = ContinuousClock.now
        guard deadline > now else { throw TurnstileVerificationError.transport }
        let duration = now.duration(to: deadline)
        let seconds = Double(duration.components.seconds) + Double(duration.components.attoseconds) / 1e18
        guard seconds > 0 else { throw TurnstileVerificationError.transport }
        var urlRequest = URLRequest(url: endpoint, timeoutInterval: min(timeout, seconds))
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        var components = URLComponents(); components.queryItems = [URLQueryItem(name: "secret", value: String(decoding: request.secret, as: UTF8.self)), URLQueryItem(name: "response", value: request.response)]
        if let remoteIP = request.remoteIP { components.queryItems?.append(URLQueryItem(name: "remoteip", value: remoteIP)) }
        urlRequest.httpBody = components.percentEncodedQuery?.data(using: .utf8)
        try Task.checkCancellation()
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

public protocol AuthenticatedSMTPDeadlineTransport: AuthenticatedSMTPTransport {
    func deliver(configuration: AuthenticatedSMTPConfiguration, to: AccountEmailAddress, subject: String, body: String, idempotencyKey: String, deadline: ContinuousClock.Instant) async throws
}

/// Concrete transport seam for the NIO SMTP implementation. A TLS session
/// must report the hostname authenticated by certificate validation before
/// this adapter permits SMTP AUTH; callers cannot downgrade that check.
public protocol SMTPTLSConnection: Sendable {
    var authenticatedHostname: String { get }
    func authenticate(username: String, password: String, mechanism: SMTPAuthMechanism) async throws
    func send(to: AccountEmailAddress, subject: String, body: String, idempotencyKey: String) async throws
}

/// NIO implementations should close the channel at this deadline; this is a
/// transport contract, not merely a cooperative task-group timeout.
public protocol SMTPTLSConnectionWithDeadline: SMTPTLSConnection {
    func authenticate(username: String, password: String, mechanism: SMTPAuthMechanism, deadline: ContinuousClock.Instant) async throws
    func send(to: AccountEmailAddress, subject: String, body: String, idempotencyKey: String, deadline: ContinuousClock.Instant) async throws
}

public struct AuthenticatedSMTPNetworkTransport: AuthenticatedSMTPDeadlineTransport {
    private let connect: @Sendable (AuthenticatedSMTPConfiguration, ContinuousClock.Instant) async throws -> any SMTPTLSConnectionWithDeadline
    public init(connect: @escaping @Sendable (AuthenticatedSMTPConfiguration, ContinuousClock.Instant) async throws -> any SMTPTLSConnectionWithDeadline) {
        self.connect = connect
    }

    public func deliver(configuration: AuthenticatedSMTPConfiguration, to: AccountEmailAddress, subject: String, body: String, idempotencyKey: String) async throws {
        try await deliver(configuration: configuration, to: to, subject: subject, body: body, idempotencyKey: idempotencyKey, deadline: .now.advanced(by: .seconds(30)))
    }

    public func deliver(configuration: AuthenticatedSMTPConfiguration, to: AccountEmailAddress, subject: String, body: String, idempotencyKey: String, deadline: ContinuousClock.Instant) async throws {
        guard configuration.mode != .plaintextLab else { throw MailpitSMTPDeliveryError.invalidConfiguration }
        let connection = try await connect(configuration, deadline)
        if configuration.mode != .plaintextLab {
            guard connection.authenticatedHostname.lowercased() == configuration.expectedHostname?.lowercased() else { throw MailpitSMTPDeliveryError.unavailable }
            guard let username = configuration.username, let password = configuration.password, let mechanism = configuration.mechanism else { throw MailpitSMTPDeliveryError.invalidConfiguration }
            try await connection.authenticate(username: username, password: password, mechanism: mechanism, deadline: deadline)
        }
        try await connection.send(to: to, subject: subject, body: body, idempotencyKey: idempotencyKey, deadline: deadline)
    }
}

public struct MailpitSMTPConfiguration: Sendable, Equatable {
    public let host: String
    public let port: Int
    public init(host: String = "127.0.0.1", port: Int = 1025) throws {
        guard !host.isEmpty, (1 ... 65535).contains(port) else { throw SwanError.invalidIdentifier("Mailpit configuration") }
        self.host = host; self.port = port
    }
}

public actor AuthenticatedSMTPDelivery: AccountEmailDelivery {
    public nonisolated let cancellationContract: AccountEmailDeliveryCancellationContract = .bounded
    private let configuration: AuthenticatedSMTPConfiguration
    private let transport: any AuthenticatedSMTPTransport
    private let attemptTimeout: Duration
    public init(configuration: AuthenticatedSMTPConfiguration, transport: any AuthenticatedSMTPTransport, attemptTimeout: Duration = .seconds(30)) throws {
        guard attemptTimeout > .zero, attemptTimeout <= .seconds(300) else { throw SwanError.invalidIdentifier("SMTP attempt timeout") }
        self.configuration = configuration; self.transport = transport; self.attemptTimeout = attemptTimeout
    }

    public func deliver(to: AccountEmailAddress, subject: String, body: String) async throws {
        let key = String(SHA256.hash(data: Data("\(to.value)\0\(subject)\0\(body)".utf8)).description)
        try await deliver(to: to, subject: subject, body: body, idempotencyKey: key)
    }

    public func deliver(to: AccountEmailAddress, subject: String, body: String, idempotencyKey key: String) async throws {
        guard !key.isEmpty, !subject.contains("\r"), !subject.contains("\n"), body.utf8.count <= 32768 else { throw MailpitSMTPDeliveryError.invalidMessage }
        var last: Error?
        guard let deadlineTransport = transport as? any AuthenticatedSMTPDeadlineTransport else { throw MailpitSMTPDeliveryError.invalidConfiguration }
        let configuration = self.configuration
        let attemptTimeout = self.attemptTimeout
        for attempt in 0 ..< configuration.maximumAttempts {
            do {
                try await deadlineTransport.deliver(configuration: configuration, to: to, subject: subject, body: body, idempotencyKey: key, deadline: .now.advanced(by: attemptTimeout))
                return
            } catch {
                if Task.isCancelled { throw CancellationError() }
                last = error
                if attempt + 1 < configuration.maximumAttempts {
                    try Task.checkCancellation()
                    try await Task.sleep(for: .milliseconds(Int64(100 * (1 << attempt))))
                }
            }
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

    public struct Failure: Error, Sendable {
        public let credentialClass: String
        public init(credentialClass: String) {
            self.credentialClass = credentialClass
        }
    }

    public struct AggregateError: Error, Sendable {
        public let failures: [Failure]
        public init(failures: [Failure]) {
            self.failures = failures
        }
    }

    public func revokeAll(for did: String, now: Date = Date()) async throws {
        var failures: [Failure] = []
        do { try await hooks.revokeOAuthSessions(did: did, now: now) } catch { failures.append(.init(credentialClass: "oauth")) }
        do { try await hooks.revokeLegacySessions(did: did, now: now) } catch { failures.append(.init(credentialClass: "legacy")) }
        do { try await hooks.revokeManagementSessions(did: did, now: now) } catch { failures.append(.init(credentialClass: "management")) }
        do { try await hooks.revokeAppDerivedSessions(did: did, now: now) } catch { failures.append(.init(credentialClass: "appDerived")) }
        if !failures.isEmpty { throw AggregateError(failures: failures) }
    }
}

public struct AccountLifecycleService: Sendable {
    private let store: any AccountControlStore
    private let deletion: (any AccountDeletionControlStore)?
    private let invites: SignupInviteService?
    private let invitePersistence: (any SignupInvitePersistence)?
    public init(store: any AccountControlStore, deletion: (any AccountDeletionControlStore)? = nil, invites: SignupInviteService? = nil, invitePersistence: (any SignupInvitePersistence)? = nil) {
        self.store = store; self.deletion = deletion; self.invites = invites; self.invitePersistence = invitePersistence
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

    public func issueInvite(code: String, expiresAt: Date? = nil) async throws -> SignupInviteIssue {
        let issue = try invite(code: code, expiresAt: expiresAt)
        guard let invitePersistence else { throw SwanError.unavailable("invite persistence unavailable") }
        let invite = try SignupInvite(digest: issue.digest, issuedAt: Date(), expiresAt: expiresAt)
        try await invitePersistence.persistInvite(invite)
        return issue
    }

    public func listInvites(limit: Int = 100) async throws -> [SignupInvite] {
        guard let invitePersistence else { throw SwanError.unavailable("invite persistence unavailable") }
        return try await invitePersistence.listInvites(limit: limit)
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
    private var trustedBucket: Bool
    init(requestID: String, authorizationID: SignupAuthorizationID, handle: String, email: AccountEmailAddress?, identityDID: String, emailProofDigest: Data?, inviteDigest: Data?, clientIPBucketDigest: Data) throws {
        guard clientIPBucketDigest.count == 32, [emailProofDigest, inviteDigest].compactMap(\.self).allSatisfy({ $0.count == 32 }) else { throw SwanError.invalidIdentifier("signup authorization input") }
        self.requestID = requestID; self.authorizationID = authorizationID; self.handle = handle; self.email = email; self.identityDID = identityDID; self.emailProofDigest = emailProofDigest; self.inviteDigest = inviteDigest; self.clientIPBucketDigest = clientIPBucketDigest
        trustedBucket = false
    }

    fileprivate var isTrustedBucket: Bool {
        trustedBucket
    }

    public static func make(requestID: String, authorizationID: SignupAuthorizationID, handle: String, email: AccountEmailAddress?, identityDID: String, emailProofDigest: Data?, inviteDigest: Data?, peer: SignupTrustedPeerIPBucket) throws -> Self {
        var value = try Self(requestID: requestID, authorizationID: authorizationID, handle: handle, email: email, identityDID: identityDID, emailProofDigest: emailProofDigest, inviteDigest: inviteDigest, clientIPBucketDigest: peer.digest)
        value.trustedBucket = true
        return value
    }
}

public protocol SignupTrustedPeerIPExtractor: Sendable {
    func bucket(forCanonicalPeerIP peerIP: String) throws -> SignupTrustedPeerIPBucket
}

public struct SignupTrustedPeerIPBucket: Sendable, Equatable {
    public let digest: Data
    fileprivate init(digest: Data) {
        self.digest = digest
    }
}

public struct SocketAddressSignupPeerExtractor: SignupTrustedPeerIPExtractor, Sendable {
    private let secret: Data
    public init(serverSecret: Data) throws {
        guard serverSecret.count >= 16 else { throw SwanError.invalidIdentifier("peer bucket secret") }
        secret = serverSecret
    }

    public func bucket(forCanonicalPeerIP peerIP: String) throws -> SignupTrustedPeerIPBucket {
        guard let address = try? SocketAddress(ipAddress: peerIP, port: 0), let canonical = address.ipAddress, canonical == peerIP else { throw SwanError.invalidIdentifier("peer IP") }
        return SignupTrustedPeerIPBucket(digest: Data(HMAC<SHA256>.authenticationCode(for: Data("swan.signup.ip-bucket.v1\0\(canonical)".utf8), using: SymmetricKey(data: secret))))
    }
}

@available(*, deprecated, message: "Use SignupFinalizationCoordinator; generic callback finalization is not atomic")
public protocol SignupFoundationBundle: Sendable {
    /// The foundation implementation performs account/identity/session work
    /// and invokes the storage-owned transaction exactly once from its
    /// idempotent commit path. Retrying returns the persisted result.
    func commitSignup(_ input: SignupFinalizationRequest, transaction: any SignupFinalizationTransaction, now: Date) async throws -> SignupFinalizationResult
}

@available(*, deprecated, message: "Use SignupFinalizationCoordinator")
public protocol SignupFinalizationTransaction: Sendable {
    func commit() async throws -> SignupFinalizationResult
}

/// Storage implementations may return a transaction bound to their durable
/// connection. Foundation must retain and commit this object inside its own
/// account/identity/session transaction boundary.
@available(*, deprecated, message: "Use SignupFinalizationCoordinator")
public protocol SignupAtomicFinalizationStore: SignupAuthorizationStore {
    func makeFinalizationTransaction(_ request: SignupFinalizationRequest, now: Date) async throws -> any SignupFinalizationTransaction
}

/// Required single-connection finalization seam. Implementations must perform
/// foundation writes and Task 4 consumption/result writes in this transaction.
public protocol SignupFinalizationCoordinator: Sendable {
    func finalizeSignup(_ request: SignupFinalizationRequest, now: Date) async throws -> SignupFinalizationResult
}

private struct StoreOwnedSignupFinalizationTransaction: SignupFinalizationTransaction {
    let store: any SignupAuthorizationStore
    let request: SignupFinalizationRequest
    let now: Date
    func commit() async throws -> SignupFinalizationResult {
        try await store.finalize(request, now: now)
    }
}

public enum SignupServiceError: Error, Sendable, Equatable { case closed, inviteRequired, emailProofRequired, turnstileRequired, invalidIdentity, duplicateRequest }

public protocol SignupRateAdmission: Sendable {
    func permits(bucket: Data, now: Date) async throws -> Bool
}

/// Small bounded admission gate for invite mode. Production can replace this
/// with the shared IP/token-bucket service through the protocol seam.
public actor SignupInviteRateAdmission: SignupRateAdmission {
    private let maximum: Int
    private let window: TimeInterval
    private var buckets: [Data: (started: Date, count: Int)] = [:]
    private let maximumBuckets = 4096

    public init(maximum: Int = 5, window: TimeInterval = 60) throws {
        guard (1 ... 100).contains(maximum), window.isFinite, (1 ... 3600).contains(window) else { throw SwanError.invalidIdentifier("signup admission") }
        self.maximum = maximum; self.window = window
    }

    public func permits(bucket: Data, now: Date) async throws -> Bool {
        guard bucket.count == 32 else { throw SwanError.invalidIdentifier("signup bucket") }
        buckets = buckets.filter { now.timeIntervalSince($0.value.started) < window }
        guard buckets[bucket] != nil || buckets.count < maximumBuckets else { return false }
        if let current = buckets[bucket], current.count >= maximum { return false }
        let current = buckets[bucket] ?? (now, 0)
        buckets[bucket] = (current.started, current.count + 1)
        return true
    }
}

public struct SignupService: Sendable {
    private let policy: SignupPolicyService
    private let store: any SignupAuthorizationStore
    private let finalizationCoordinator: (any SignupFinalizationCoordinator)?
    private let turnstile: TurnstileVerifier?
    private let rateAdmission: (any SignupRateAdmission)?
    private let proofVerifier: (any SignupEmailProofVerifier)?
    private let proofService: SignupEmailProofService?
    public init(policy: SignupPolicyService, store: any SignupAuthorizationStore, finalizationCoordinator: (any SignupFinalizationCoordinator)? = nil, turnstile: TurnstileVerifier? = nil, rateAdmission: (any SignupRateAdmission)? = nil, proofVerifier: (any SignupEmailProofVerifier)? = nil, proofService: SignupEmailProofService? = nil) {
        self.policy = policy; self.store = store; self.finalizationCoordinator = finalizationCoordinator; self.turnstile = turnstile; self.rateAdmission = rateAdmission; self.proofVerifier = proofVerifier; self.proofService = proofService
    }

    public func authorize(_ input: SignupAuthorizationInput, verificationCode: String? = nil, turnstileToken: String? = nil, remoteIP: String? = nil, now: Date = Date(), lifetime: TimeInterval = 600) async throws -> SignupAuthorization {
        guard policy.policy.permitsPublicSignup, input.isTrustedBucket else { throw SignupServiceError.closed }
        guard lifetime.isFinite, (1 ... 900).contains(lifetime) else { throw SwanError.invalidIdentifier("signup authorization lifetime") }
        guard input.email != nil, input.emailProofDigest != nil else { throw SignupServiceError.emailProofRequired }
        if policy.policy == .openProtected { guard proofVerifier != nil, proofService != nil, verificationCode != nil else { throw SignupServiceError.emailProofRequired } }
        guard policy.permits(handle: input.handle, inviteCode: input.inviteDigest == nil ? nil : "present") else { throw SignupServiceError.inviteRequired }
        if policy.policy == .inviteRequired {
            guard let rateAdmission, try await rateAdmission.permits(bucket: input.clientIPBucketDigest, now: now) else { throw SignupServiceError.inviteRequired }
        }
        if policy.policy == .openProtected {
            guard input.emailProofDigest != nil else { throw SignupServiceError.emailProofRequired }
            guard let turnstile else { throw SignupServiceError.turnstileRequired }
            guard let turnstileToken, !turnstileToken.isEmpty else { throw SignupServiceError.turnstileRequired }
            try await turnstile.verify(token: turnstileToken, remoteIP: remoteIP, now: now)
        }
        guard AccountControlIdentifiers.isDID(input.identityDID) else { throw SignupServiceError.invalidIdentity }
        let authorization = try SignupAuthorization(id: input.authorizationID, requestID: input.requestID, policy: policy.policy, handle: input.handle, email: input.email?.value, identityDID: input.identityDID, emailProofDigest: input.emailProofDigest, inviteDigest: input.inviteDigest, clientIPBucketDigest: input.clientIPBucketDigest, issuedAt: now, expiresAt: now.addingTimeInterval(lifetime), leaseExpiresAt: now.addingTimeInterval(120))
        try await store.reserve(authorization, now: now)
        if let verificationCode, let verifier = proofVerifier, let proofService, let email = input.email {
            let digest = try await verifier.verifySubmittedCode(verificationCode, email: email, handle: input.handle, authorizationID: input.authorizationID, proof: proofService, now: now)
            guard digest == input.emailProofDigest else { throw SignupServiceError.emailProofRequired }
        }
        return authorization
    }

    public func authorize(requestID: String, authorizationID: SignupAuthorizationID, handle: String, email: AccountEmailAddress?, identityDID: String, emailProofDigest: Data?, inviteDigest: Data?, verificationCode: String?, turnstileToken: String? = nil, peerAddress: SocketAddress, extractor: any SignupTrustedPeerIPExtractor, now: Date = Date(), lifetime: TimeInterval = 600) async throws -> SignupAuthorization {
        guard let peerIP = peerAddress.ipAddress else { throw SwanError.invalidIdentifier("peer address") }
        let bucket = try extractor.bucket(forCanonicalPeerIP: peerIP)
        let input = try SignupAuthorizationInput.make(requestID: requestID, authorizationID: authorizationID, handle: handle, email: email, identityDID: identityDID, emailProofDigest: emailProofDigest, inviteDigest: inviteDigest, peer: bucket)
        return try await authorize(input, verificationCode: verificationCode, turnstileToken: turnstileToken, remoteIP: peerIP, now: now, lifetime: lifetime)
    }

    public func finalize(_ request: SignupFinalizationRequest, now: Date = Date()) async throws -> SignupFinalizationResult {
        guard let authorization = try await store.authorization(id: request.authorizationID, now: now), authorization.requestID == request.idempotencyKey else { throw AccountControlStoreError.notFound }
        guard authorization.handle == request.handle, authorization.identityDID == request.identityDID else { throw SignupServiceError.duplicateRequest }
        guard let coordinator = finalizationCoordinator else { throw SwanError.unavailable("atomic signup coordinator unavailable") }
        return try await coordinator.finalizeSignup(request, now: now)
    }
}

public struct AccountEmailUpdateService: Sendable {
    private let store: any AccountControlStore
    private let recovery: AccountEmailRecoveryService
    public init(store: any AccountControlStore, recovery: AccountEmailRecoveryService) {
        self.store = store; self.recovery = recovery
    }

    public func requestUpdate(did: String, email: AccountEmailAddress, now: Date = Date()) async throws {
        guard let atomic = store as? any AccountEmailUpdateAtomicStore else { throw SwanError.unavailable("atomic email update unavailable") }
        try await atomic.associateEmailAndEnqueueConfirmation(did: did, email: email, now: now, recovery: recovery)
    }
}

public protocol AccountEmailUpdateAtomicStore: AccountControlStore {
    func associateEmailAndEnqueueConfirmation(did: String, email: AccountEmailAddress, now: Date, recovery: AccountEmailRecoveryService) async throws
}

public struct SignupEmailRequestOutcome: Sendable, Equatable {
    public let accepted: Bool
    public init(accepted: Bool = true) {
        self.accepted = accepted
    }
}

/// Durable proof issuance is deliberately split from delivery. Implementors
/// persist the proof and enqueue an outbox row in one transaction; callers get
/// the same response for existing and new addresses.
public protocol SignupEmailRequestStore: Sendable {
    func persistSignupEmailRequest(email: AccountEmailAddress, handle: String, proofDigest: Data, protectedEnvelope: Data, issuedAt: Date, expiresAt: Date) async throws
}

public struct SignupEmailRequestService: Sendable {
    private let store: any SignupEmailRequestStore
    public init(store: any SignupEmailRequestStore) {
        self.store = store
    }

    public func request(email: AccountEmailAddress, handle: String, proof: SignupEmailProofService, now: Date = Date(), lifetime: TimeInterval = 600, keyVersion: UInt8 = 1) async throws -> SignupEmailRequestOutcome {
        var generator = SystemRandomNumberGenerator()
        let bytes = Data((0 ..< 24).map { _ in UInt8.random(in: 0 ... 255, using: &generator) })
        let code = bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        let digest = try proof.digest(code: code, email: email, handle: handle)
        let deliveryID = "signup-" + digest.map { String(format: "%02x", $0) }.joined()
        let envelope = try proof.protectedEnvelope(code: code, email: email, handle: handle, deliveryID: deliveryID, keyVersion: keyVersion)
        return try await request(email: email, handle: handle, proofDigest: digest, protectedEnvelope: envelope, now: now, lifetime: lifetime)
    }

    fileprivate func verifySubmittedCode(_ code: String, email: AccountEmailAddress, handle: String, proof: SignupEmailProofService) throws -> Data {
        try proof.digest(code: code, email: email, handle: handle)
    }

    private func request(email: AccountEmailAddress, handle: String, proofDigest: Data, protectedEnvelope: Data, now: Date, lifetime: TimeInterval) async throws -> SignupEmailRequestOutcome {
        guard AccountControlIdentifiers.isCanonicalHandle(handle), proofDigest.count == 32,
              !protectedEnvelope.isEmpty, protectedEnvelope.count <= 16384,
              lifetime.isFinite, (60 ... 900).contains(lifetime) else { throw SwanError.invalidIdentifier("signup email request") }
        try await store.persistSignupEmailRequest(email: email, handle: handle, proofDigest: proofDigest, protectedEnvelope: protectedEnvelope, issuedAt: now, expiresAt: now.addingTimeInterval(lifetime))
        return SignupEmailRequestOutcome()
    }
}

public protocol SignupEmailProofVerifier: Sendable {
    func verifySubmittedCode(_ code: String, email: AccountEmailAddress, handle: String, authorizationID: SignupAuthorizationID, proof: SignupEmailProofService, now: Date) async throws -> Data
}

public actor BoundedSignupEmailProofVerifier: SignupEmailProofVerifier {
    private let store: any SignupEmailProofVerifier
    private var attempts: [String: (started: Date, count: Int)] = [:]
    public init(store: any SignupEmailProofVerifier) {
        self.store = store
    }

    public func verifySubmittedCode(_ code: String, email: AccountEmailAddress, handle: String, authorizationID: SignupAuthorizationID, proof: SignupEmailProofService, now: Date = Date()) async throws -> Data {
        let key = try "\(proof.digest(code: code, email: email, handle: handle).base64EncodedString())\0\(email.value)"
        attempts = attempts.filter { now.timeIntervalSince($0.value.started) < 900 }
        guard attempts[key] != nil || attempts.count < 4096 else { throw SwanError.unavailable("email proof capacity") }
        if let current = attempts[key] {
            guard current.count < 5 else { throw SwanError.unavailable("email proof rate limited") }
            attempts[key] = (current.started, current.count + 1)
        } else {
            attempts[key] = (now, 1)
        }
        return try await store.verifySubmittedCode(code, email: email, handle: handle, authorizationID: authorizationID, proof: proof, now: now)
    }
}

public protocol SignupEmailOutboxStore: Sendable {
    associatedtype Message: Sendable
    func claim(now: Date) async throws -> Message?
    func markDelivered(_ message: Message, now: Date) async throws
    func markFailed(_ message: Message, now: Date) async throws
}

public struct SignupEmailOutboxWorker<Store: SignupEmailOutboxStore>: Sendable where Store.Message: Sendable {
    private let store: Store
    private let deliver: @Sendable (Store.Message) async throws -> Void
    public init(store: Store, deliver: @escaping @Sendable (Store.Message) async throws -> Void) {
        self.store = store; self.deliver = deliver
    }

    public func runOnce(now: Date = Date()) async throws -> Bool {
        guard let message = try await store.claim(now: now) else { return false }
        do { try await deliver(message); try await store.markDelivered(message, now: now) }
        catch { try? await store.markFailed(message, now: now); throw error }
        return true
    }
}
