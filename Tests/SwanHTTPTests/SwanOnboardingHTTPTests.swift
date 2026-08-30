import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
@testable import SwanAccounts
@testable import SwanHTTP
import SwanCore
import SwanOAuth
import SwanSQLite
import SwanStorage
import XCTest

/// Task 3: exact `com.atproto.server.createAccount` route registration and
/// fail-closed security behavior through the production `SwanHTTPServer`.
final class SwanOnboardingHTTPTests: XCTestCase, @unchecked Sendable {
    /// Without an assembled lifecycle adapter the route is not registered and
    /// the method stays a bare 404 — never a proxy fallback.
    func testCreateAccountIsNotRegisteredWithoutLifecycleAdapter() async throws {
        let fixture = try await makeServer(lifecycle: false)
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanOnboardingHTTPTests.unregistered")
            )
            try await app.test(.router) { client in
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: ByteBuffer(string: #"{"handle":"alice.test","email":"alice@example.com","password":"hunter2"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// With the adapter assembled, the route answers locally. A body that
    /// cannot satisfy the openProtected policy fails closed with a 422
    /// invalid_request — never a 404 and never a proxy hop.
    func testCreateAccountFailsClosedOnMissingProofWhenAssembled() async throws {
        let fixture = try await makeServer(lifecycle: true)
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanOnboardingHTTPTests.assembled")
            )
            try await app.test(.live) { client in
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: ByteBuffer(string: #"{"handle":"alice.test","email":"alice@example.com","password":"hunter2"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .unprocessableContent)
                    let body = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertTrue(body.contains("invalid_request"), body)
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// A closed policy assembles no adapter, so the route is not registered:
    /// the closed deployment never advertises a signup surface.
    func testClosedPolicyDoesNotRegisterCreateAccount() async throws {
        let fixture = try await makeServer(lifecycle: false, policy: .closed)
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanOnboardingHTTPTests.closed")
            )
            try await app.test(.router) { client in
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: ByteBuffer(string: #"{"handle":"alice.test","email":"alice@example.com","password":"hunter2"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// A malformed body (unknown field) is a 422, not a 500.
    func testCreateAccountRejectsUnknownFields() async throws {
        let fixture = try await makeServer(lifecycle: true)
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanOnboardingHTTPTests.strict")
            )
            try await app.test(.router) { client in
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: ByteBuffer(string: #"{"handle":"alice.test","email":"alice@example.com","password":"hunter2","unknownField":1}"#)
                ) { response in
                    XCTAssertEqual(response.status, .unprocessableContent)
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// The happy path through the real services: a stored email proof and
    /// invite, a valid Turnstile token, and a caller-supplied PLC DID produce
    /// a 200 with the reference response shape (empty JWTs — OAuth session
    /// issuance is a later task).
    func testCreateAccountHappyPathReturns200WithReferenceShape() async throws {
        let fixture = try await makeServer(lifecycle: true)
        defer { fixture.cleanup() }
        do {
            let now = Date()
            let handle = "alice.example.com"
            let email = try AccountEmailAddress("alice@example.com")
            let did = "did:plc:abcdefghijklmnopqrstuvwx"
            let secret = try SignupSecret(Data(repeating: 0x24, count: 32))
            let proofService = SignupEmailProofService(secret: secret)
            let inviteService = SignupInviteService(secret: secret)
            let invite = try inviteService.issue(
                code: "invite-code-1234567890",
                expiresAt: now.addingTimeInterval(600)
            )
            try await fixture.control.persistInvite(
                try SignupInvite(
                    digest: invite.digest,
                    issuedAt: now,
                    expiresAt: now.addingTimeInterval(600)
                )
            )
            let proofCode = "proof-code-123456789012"
            let proofDigest = try proofService.digest(
                code: proofCode,
                email: email,
                handle: handle
            )
            try await fixture.control.insertSignupEmailProof(
                digest: proofDigest,
                email: email,
                handle: handle,
                issuedAt: now,
                expiresAt: now.addingTimeInterval(600)
            )

            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanOnboardingHTTPTests.happy")
            )
            try await app.test(.live) { client in
                let body = """
                {"handle":"\(handle)","email":"\(email.value)","password":"hunter2",\
                "verificationCode":"\(proofCode)","inviteCode":"\(invite.code)",\
                "did":"\(did)","turnstileToken":"test-token"}
                """
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: ByteBuffer(string: body)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let decoded = try JSONDecoder().decode(
                        CreateAccountWire.self,
                        from: Data(response.body.readableBytesView)
                    )
                    XCTAssertEqual(decoded.did, did)
                    XCTAssertEqual(decoded.handle, handle)
                    XCTAssertEqual(decoded.accessJwt, "")
                    XCTAssertEqual(decoded.refreshJwt, "")
                }
            }
            // The account is durably committed and the proof consumed.
            let committed = try await fixture.control.account(did: did)
            XCTAssertNotNil(committed)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// The bounded proof verifier's rate limit surfaces as HTTP 429
    /// rate_limited — not a 503 — while other unavailable errors stay 503.
    func testCreateAccountRateLimitMapsTo429() async throws {
        let fixture = try await makeServer(lifecycle: true)
        defer { fixture.cleanup() }
        do {
            let now = Date()
            let handle = "carol.example.com"
            let email = try AccountEmailAddress("carol@example.com")
            let did = "did:plc:abcdefghijklmnopqrstuvwx"
            let secret = try SignupSecret(Data(repeating: 0x24, count: 32))
            let proofService = SignupEmailProofService(secret: secret)
            let proofCode = "proof-code-123456789012"
            let proofDigest = try proofService.digest(
                code: proofCode,
                email: email,
                handle: handle
            )
            try await fixture.control.insertSignupEmailProof(
                digest: proofDigest,
                email: email,
                handle: handle,
                issuedAt: now,
                expiresAt: now.addingTimeInterval(600)
            )

            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanOnboardingHTTPTests.rate")
            )
            try await app.test(.live) { client in
                // The first attempt consumes the proof; attempts 2-5 fail at
                // the store; the sixth is refused by the bounded verifier.
                // Each attempt uses a fresh Turnstile token (tokens are
                // single-use).
                for index in 0 ..< 5 {
                    let attemptBody = """
                    {"handle":"\(handle)","email":"\(email.value)","password":"hunter2",\
                    "verificationCode":"\(proofCode)","did":"\(did)","turnstileToken":"token-\(index)"}
                    """
                    try await client.execute(
                        uri: "/xrpc/com.atproto.server.createAccount",
                        method: .post,
                        headers: [.contentType: "application/json"],
                        body: ByteBuffer(string: attemptBody)
                    ) { response in
                        XCTAssertNotEqual(response.status, .tooManyRequests)
                    }
                }
                let finalBody = """
                {"handle":"\(handle)","email":"\(email.value)","password":"hunter2",\
                "verificationCode":"\(proofCode)","did":"\(did)","turnstileToken":"token-final"}
                """
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: ByteBuffer(string: finalBody)
                ) { response in
                    XCTAssertEqual(response.status, .tooManyRequests)
                    let body = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertTrue(body.contains("rate_limited"), body)
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }
    /// When the peer address cannot be resolved (such as an in-memory router
    /// invocation without an accepted socket address), signup fails closed with
    /// 503 service_unavailable rather than substituting loopback.
    func testCreateAccountFailsClosedWhenPeerAddressIsUnavailable() async throws {
        let fixture = try await makeServer(lifecycle: true)
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanOnboardingHTTPTests.nilPeer")
            )
            try await app.test(.router) { client in
                let body = """
                {"handle":"nil-peer.example.com","email":"nil-peer@example.com","password":"hunter2",\
                "verificationCode":"proof-code-123456789012","did":"did:plc:abcdefghijklmnopqrstuvwx",\
                "turnstileToken":"test-token"}
                """
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: ByteBuffer(string: body)
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    let responseBody = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertTrue(responseBody.contains("service_unavailable"), responseBody)
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// Behind a trusted proxy, distinct `X-Swan-Client-IP` headers derive distinct
    /// client rate-admission buckets.
    func testCreateAccountBehindTrustedProxyUsesForwardedClientIPForAdmission() async throws {
        let policy = try SwanLoginClientIdentityPolicy(
            trustedProxyPeerLiterals: ["127.0.0.1", "::1"]
        )
        let rateAdmission = try SignupInviteRateAdmission(maximum: 2, globalMaximum: 10)
        let fixture = try await makeServer(
            lifecycle: true,
            loginClientIdentityPolicy: policy,
            rateAdmission: rateAdmission
        )
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanOnboardingHTTPTests.trustedProxy")
            )
            try await app.test(.live) { client in
                // Client A sends 2 requests: both admitted (fail at proof/Turnstile with 422, not 429/503)
                for index in 0 ..< 2 {
                    var headers = HTTPFields()
                    headers[.contentType] = "application/json"
                    headers[SwanLoginClientIdentityPolicy.clientIPHeader] = "203.0.113.10"
                    let body = """
                    {"handle":"client-a.example.com","email":"client-a@example.com","password":"hunter2",\
                    "verificationCode":"proof-code-\(index)-123456789","did":"did:plc:abcdefghijklmnopqrstuvwx",\
                    "turnstileToken":"token-\(index)"}
                    """
                    try await client.execute(
                        uri: "/xrpc/com.atproto.server.createAccount",
                        method: .post,
                        headers: headers,
                        body: ByteBuffer(string: body)
                    ) { response in
                        XCTAssertEqual(response.status, .unprocessableContent)
                    }
                }

                // Client A's 3rd request hits its per-peer rate limit (429)
                var clientAHeaders = HTTPFields()
                clientAHeaders[.contentType] = "application/json"
                clientAHeaders[SwanLoginClientIdentityPolicy.clientIPHeader] = "203.0.113.10"
                let clientABody = """
                {"handle":"client-a.example.com","email":"client-a@example.com","password":"hunter2",\
                "verificationCode":"proof-code-3-123456789012","did":"did:plc:abcdefghijklmnopqrstuvwx",\
                "turnstileToken":"token-3"}
                """
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: clientAHeaders,
                    body: ByteBuffer(string: clientABody)
                ) { response in
                    XCTAssertEqual(response.status, .tooManyRequests)
                    let responseBody = String(decoding: response.body.readableBytesView, as: UTF8.self)
                    XCTAssertTrue(responseBody.contains("rate_limited"), responseBody)
                }

                // Client B with distinct IP is admitted under its own fresh bucket (not 429)
                var clientBHeaders = HTTPFields()
                clientBHeaders[.contentType] = "application/json"
                clientBHeaders[SwanLoginClientIdentityPolicy.clientIPHeader] = "203.0.113.20"
                let clientBBody = """
                {"handle":"client-b.example.com","email":"client-b@example.com","password":"hunter2",\
                "verificationCode":"proof-code-b-123456789012","did":"did:plc:abcdefghijklmnopqrstuvwx",\
                "turnstileToken":"token-b"}
                """
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: clientBHeaders,
                    body: ByteBuffer(string: clientBBody)
                ) { response in
                    XCTAssertEqual(response.status, .unprocessableContent)
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// An untrusted direct peer cannot spoof client identity by injecting `X-Swan-Client-IP`.
    func testCreateAccountUntrustedPeerCannotSpoofClientIP() async throws {
        let rateAdmission = try SignupInviteRateAdmission(maximum: 2, globalMaximum: 10)
        let fixture = try await makeServer(
            lifecycle: true,
            loginClientIdentityPolicy: .direct,
            rateAdmission: rateAdmission
        )
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanOnboardingHTTPTests.untrustedSpoof")
            )
            try await app.test(.live) { client in
                // Attacker sends 2 requests pretending to have different client IPs
                for index in 0 ..< 2 {
                    var headers = HTTPFields()
                    headers[.contentType] = "application/json"
                    headers[SwanLoginClientIdentityPolicy.clientIPHeader] = "198.51.100.\(index + 1)"
                    let body = """
                    {"handle":"attacker-\(index).example.com","email":"attacker-\(index)@example.com","password":"hunter2",\
                    "verificationCode":"proof-code-\(index)-123456789","did":"did:plc:abcdefghijklmnopqrstuvwx",\
                    "turnstileToken":"token-\(index)"}
                    """
                    try await client.execute(
                        uri: "/xrpc/com.atproto.server.createAccount",
                        method: .post,
                        headers: headers,
                        body: ByteBuffer(string: body)
                    ) { response in
                        XCTAssertEqual(response.status, .unprocessableContent)
                    }
                }

                // 3rd request from same socket peer with yet another spoofed IP is rate limited (429)
                var headers = HTTPFields()
                headers[.contentType] = "application/json"
                headers[SwanLoginClientIdentityPolicy.clientIPHeader] = "198.51.100.99"
                let body = """
                {"handle":"attacker-3.example.com","email":"attacker-3@example.com","password":"hunter2",\
                "verificationCode":"proof-code-3-123456789012","did":"did:plc:abcdefghijklmnopqrstuvwx",\
                "turnstileToken":"token-3"}
                """
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: headers,
                    body: ByteBuffer(string: body)
                ) { response in
                    XCTAssertEqual(response.status, .tooManyRequests)
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    /// Behind a trusted proxy, missing or malformed client IP headers fail closed (503).
    func testCreateAccountBehindTrustedProxyMalformedOrMissingClientIPFailsClosed() async throws {
        let policy = try SwanLoginClientIdentityPolicy(
            trustedProxyPeerLiterals: ["127.0.0.1", "::1"]
        )
        let fixture = try await makeServer(
            lifecycle: true,
            loginClientIdentityPolicy: policy
        )
        defer { fixture.cleanup() }
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanOnboardingHTTPTests.proxyMalformed")
            )
            try await app.test(.live) { client in
                let validBody = """
                {"handle":"test.example.com","email":"test@example.com","password":"hunter2",\
                "verificationCode":"proof-code-123456789012","did":"did:plc:abcdefghijklmnopqrstuvwx",\
                "turnstileToken":"token"}
                """

                // 1. Missing header
                var headersMissing = HTTPFields()
                headersMissing[.contentType] = "application/json"
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: headersMissing,
                    body: ByteBuffer(string: validBody)
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                }

                // 2. Malformed IP literal
                var headersMalformed = HTTPFields()
                headersMalformed[.contentType] = "application/json"
                headersMalformed[SwanLoginClientIdentityPolicy.clientIPHeader] = "not-an-ip-address"
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: headersMalformed,
                    body: ByteBuffer(string: validBody)
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                }

                // 3. Duplicate headers
                var headersDuplicate = HTTPFields()
                headersDuplicate[.contentType] = "application/json"
                headersDuplicate.append(HTTPField(
                    name: SwanLoginClientIdentityPolicy.clientIPHeader,
                    value: "203.0.113.1"
                ))
                headersDuplicate.append(HTTPField(
                    name: SwanLoginClientIdentityPolicy.clientIPHeader,
                    value: "203.0.113.2"
                ))
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: headersDuplicate,
                    body: ByteBuffer(string: validBody)
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                }
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    // MARK: - Fixture

    private struct Fixture {
        let root: URL
        let control: SQLiteControlDatabase
        let server: SwanHTTPServer

        func close() async throws {
            try await control.close()
        }

        func cleanup() {
            try? FileManager.default.removeItem(at: root)
        }
    }

    private func makeServer(
        lifecycle: Bool,
        policy: SignupPolicy = .openProtected,
        loginClientIdentityPolicy: SwanLoginClientIdentityPolicy = .direct,
        rateAdmission: (any SignupRateAdmission)? = nil
    ) async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanOnboardingHTTPTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let profile = try ProtocolProfile.load(
                from: packageRoot().appending(
                    path: "Profiles/permissioned-data-0016-2026-07-30.json"
                )
            )
            let oauthRuntime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x5C, count: 32)
            )
            let accountLifecycleXRPC: SwanAccountLifecycleXRPCAdapter?
            if lifecycle {
                let keyDirectory = root.appending(path: "signup-keys")
                try FileManager.default.createDirectory(
                    at: keyDirectory,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700]
                )
                let keyStore = try FileAccountKeyStore(
                    root: keyDirectory,
                    configuration: try AccountKeyEncryptionConfiguration(
                        activeKeyID: "primary",
                        activeKey: Data(repeating: 0x42, count: 32)
                    )
                )
                let signupSecret = try SignupSecret(Data(repeating: 0x24, count: 32))
                let passwordHasher = try LibsodiumArgon2idHasher()
                let proofService = SignupEmailProofService(secret: signupSecret)
                let extractor = try SocketAddressSignupPeerExtractor(
                    serverSecret: Data(repeating: 0x5C, count: 32)
                )
                let policyService = try SignupPolicyService(policy: policy)
                let turnstile: TurnstileVerifier?
                if policy == .openProtected {
                    turnstile = try TurnstileVerifier(
                        secret: Data(repeating: 0x11, count: 32),
                        hostname: "swan.example",
                        action: "signup",
                        transport: StubTurnstileTransport(
                            response: .init(
                                success: true,
                                challengeTimestamp: Date(),
                                hostname: "swan.example",
                                action: "signup"
                            )
                        )
                    )
                } else {
                    turnstile = nil
                }
                let sessions = SwanManagementSessionRuntime(
                    store: control,
                    preAuthStore: control,
                    csrfStore: control,
                    preAuthSessionCoordinator: control
                )
                let provisioning = SwanCreateAccountProvisioningProduction(
                    passwordHasher: passwordHasher,
                    keyProvisioner: AccountKeyProvisioner(keyStore: keyStore),
                    sessionRuntime: sessions,
                    database: control,
                    signupSecret: signupSecret
                )
                let resolvedRateAdmission = try (rateAdmission ?? SignupInviteRateAdmission())
                let service = SignupService(
                    policy: policyService,
                    store: control,
                    turnstile: turnstile,
                    rateAdmission: resolvedRateAdmission,
                    proofVerifier: BoundedSignupEmailProofVerifier(store: control),
                    proofService: proofService
                )
                let authorization = SwanCreateAccountAuthorizationPipelineProduction(
                    service: service,
                    extractor: extractor,
                    proofService: proofService,
                    signupSecret: signupSecret
                )
                let lifecycleService = AccountLifecycleService(
                    store: control,
                    deletion: control,
                    invites: SignupInviteService(secret: signupSecret),
                    invitePersistence: control
                )
                accountLifecycleXRPC = SwanAccountLifecycleXRPCAdapter(
                    lifecycle: lifecycleService,
                    provisioning: provisioning,
                    authorization: authorization,
                    capabilityVerifier: try SwanAccountLifecycleCapabilityVerifier(
                        sessionStore: control,
                        stepUpStore: control
                    )
                )
            } else {
                accountLifecycleXRPC = nil
            }
            let server = SwanHTTPServer(
                profile: profile,
                configuration: .init(
                    host: "127.0.0.1",
                    port: 3_000,
                    publicURL: URL(string: "https://swan.example")!,
                    inviteCodeRequired: policy == .inviteRequired
                ),
                oauthRuntime: oauthRuntime,
                accountControlStore: control,
                accountLifecycleXRPC: accountLifecycleXRPC,
                loginClientIdentityPolicy: loginClientIdentityPolicy
            )
            return Fixture(root: root, control: control, server: server)
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    private func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}

/// Serves a canned Turnstile siteverify response so the openProtected
/// fixture never contacts Cloudflare.
private struct StubTurnstileTransport: TurnstileHTTPTransport {
    let response: TurnstileSiteVerifyResponse
    func verify(_: TurnstileSiteVerifyRequest) async throws -> TurnstileSiteVerifyResponse {
        response
    }
}

/// The reference `com.atproto.server.createAccount` response shape.
private struct CreateAccountWire: Decodable {
    let did: String
    let handle: String
    let accessJwt: String
    let refreshJwt: String
}
