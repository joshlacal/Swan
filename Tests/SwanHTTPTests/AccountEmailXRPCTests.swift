import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import SwanAccounts
import SwanCore
import SwanOAuth
import SwanPublicWire
import SwanSpaces
import SwanSQLite
import SwanStorage
import XCTest

@testable import SwanHTTP

final class AccountEmailXRPCTests: XCTestCase, @unchecked Sendable {
    private static let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let otherDID = "did:plc:bcdefghijklmnopqrstuvwxy"
    private static let token = String(repeating: "t", count: 43)

    func testEmailRoutesComposeIntoTheMainServerBeforeApplicationConstruction() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanAccountEmailMainServer-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x3C, count: 32)
            )
            let email = makeServer(
                authorizer: EmailAuthorizer(
                    result: .success(.accountOAuth(
                        subject: Self.did,
                        scopes: ["atproto"]
                    ))
                ),
                recovery: EmailRecovery(),
                limiter: EmailRateLimiter()
            )
            let profile = try ProtocolProfile.load(
                from: packageRoot().appending(
                    path: "Profiles/permissioned-data-0016-2026-07-30.json"
                )
            )
            let server = SwanHTTPServer(
                profile: profile,
                configuration: .init(
                    host: "127.0.0.1",
                    port: 3_000,
                    publicURL: URL(string: "http://127.0.0.1:3000")!
                ),
                oauthRuntime: runtime,
                accountEmailXRPC: email
            )
            let app = server.buildApplication(
                logger: Logger(label: "AccountEmailXRPCTests.main-server")
            )
            try await app.test(.live) { client in
                try await client.execute(
                    uri: "/xrpc/\(ComAtprotoServerRequestPasswordReset.typeIdentifier)",
                    method: .post,
                    headers: self.jsonHeaders(),
                    body: ByteBuffer(string: #"{"email":"alice@example.com"}"#)
                ) { response in
                    self.assertEmptySuccess(response)
                }
            }
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    func testAuthenticatedConfirmationUsesExactGeneratedPathsAndOAuthSubject() async throws {
        let authorizer = EmailAuthorizer(
            result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"]))
        )
        let recovery = EmailRecovery()
        let limiter = EmailRateLimiter()
        let app = makeServer(
            authorizer: authorizer,
            recovery: recovery,
            limiter: limiter
        ).buildApplication(logger: Logger(label: "AccountEmailXRPCTests.success"))

        try await app.test(.live) { client in
            try await client.execute(
                uri: "/xrpc/\(ComAtprotoServerRequestEmailConfirmation.typeIdentifier)",
                method: .post
            ) { response in
                self.assertEmptySuccess(response)
            }
            try await client.execute(
                uri: "/xrpc/\(ComAtprotoServerConfirmEmail.typeIdentifier)",
                method: .post,
                headers: self.jsonHeaders(),
                body: ByteBuffer(
                    string: #"{"email":"Alice@Example.COM","token":"\#(Self.token)"}"#
                )
            ) { response in
                self.assertEmptySuccess(response)
            }
        }

        let authorizationCalls = await authorizer.snapshot()
        XCTAssertEqual(authorizationCalls, [
            .init(
                method: "POST",
                path: "/xrpc/com.atproto.server.requestEmailConfirmation"
            ),
            .init(
                method: "POST",
                path: "/xrpc/com.atproto.server.confirmEmail"
            ),
        ])
        let recoveryCalls = await recovery.snapshot()
        XCTAssertEqual(recoveryCalls, [
            .requestEmailConfirmation(did: Self.did),
            .confirmEmail(
                did: Self.did,
                email: "alice@example.com",
                proof: Self.token
            ),
        ])
    }

    func testAuthenticationRequiresLiteralATProtoScopeAndNeverMutatesOnFailure() async throws {
        let authorizer = EmailAuthorizer(
            result: .success(.accountOAuth(
                subject: Self.did,
                scopes: ["transition:generic"]
            ))
        )
        let recovery = EmailRecovery()
        let limiter = EmailRateLimiter()
        let app = makeServer(
            authorizer: authorizer,
            recovery: recovery,
            limiter: limiter
        ).buildApplication(logger: Logger(label: "AccountEmailXRPCTests.scope"))

        try await app.test(.live) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.confirmEmail",
                method: .post,
                headers: self.jsonHeaders(),
                body: ByteBuffer(
                    string: #"{"email":"alice@example.com","token":"\#(Self.token)"}"#
                )
            ) { response in
                self.assertError(response, status: .unauthorized, code: "Unauthorized")
            }
        }

        let recoveryCalls = await recovery.snapshot()
        let rateCalls = await limiter.snapshot()
        XCTAssertTrue(recoveryCalls.isEmpty)
        XCTAssertTrue(rateCalls.isEmpty)

        let nonceAuthorizer = EmailAuthorizer(result: .failure(.nonceChallengeRequired))
        let nonceApp = makeServer(
            authorizer: nonceAuthorizer,
            recovery: recovery,
            limiter: limiter
        ).buildApplication(logger: Logger(label: "AccountEmailXRPCTests.nonce"))
        try await nonceApp.test(.live) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.requestEmailConfirmation",
                method: .post
            ) { response in
                self.assertError(response, status: .unauthorized, code: "use_dpop_nonce")
                XCTAssertEqual(response.headers[HTTPField.Name("DPoP-Nonce")!], "test-nonce")
                XCTAssertEqual(
                    response.headers[.wwwAuthenticate],
                    #"DPoP error="use_dpop_nonce""#
                )
            }
        }
    }

    func testUpdateEndpointsAreAuthenticatedFixedForbiddenAndNeverMutate() async throws {
        let authorizer = EmailAuthorizer(
            result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"]))
        )
        let recovery = EmailRecovery()
        let limiter = EmailRateLimiter()
        let app = makeServer(
            authorizer: authorizer,
            recovery: recovery,
            limiter: limiter
        ).buildApplication(logger: Logger(label: "AccountEmailXRPCTests.forbidden"))
        let secret = "must-not-be-reflected"

        try await app.test(.live) { client in
            try await client.execute(
                uri: "/xrpc/\(ComAtprotoServerRequestEmailUpdate.typeIdentifier)",
                method: .post
            ) { response in
                self.assertError(response, status: .forbidden, code: "Forbidden")
            }
            try await client.execute(
                uri: "/xrpc/\(ComAtprotoServerUpdateEmail.typeIdentifier)",
                method: .post,
                headers: self.jsonHeaders(),
                body: ByteBuffer(
                    string: #"{"email":"other@example.com","token":"\#(secret)"}"#
                )
            ) { response in
                self.assertError(response, status: .forbidden, code: "Forbidden")
                let rendered = String(decoding: response.body.readableBytesView, as: UTF8.self)
                XCTAssertFalse(rendered.contains(secret))
                XCTAssertFalse(rendered.contains(Self.did))
            }
        }

        let recoveryCalls = await recovery.snapshot()
        let rateCalls = await limiter.snapshot()
        XCTAssertTrue(recoveryCalls.isEmpty)
        XCTAssertTrue(rateCalls.isEmpty)
    }

    func testStrictBodiesRejectDuplicatesUnknownFieldsAndOversizeBeforeMutation() async throws {
        let authorizer = EmailAuthorizer(
            result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"]))
        )
        let recovery = EmailRecovery()
        let limiter = EmailRateLimiter()
        let app = makeServer(
            authorizer: authorizer,
            recovery: recovery,
            limiter: limiter
        ).buildApplication(logger: Logger(label: "AccountEmailXRPCTests.strict"))

        try await app.test(.live) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.confirmEmail",
                method: .post,
                headers: self.jsonHeaders(),
                body: ByteBuffer(
                    string: #"{"email":"alice@example.com","email":"other@example.com","token":"\#(Self.token)"}"#
                )
            ) { response in
                self.assertError(response, status: .badRequest, code: "InvalidRequest")
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.server.requestPasswordReset",
                method: .post,
                headers: self.jsonHeaders(),
                body: ByteBuffer(
                    string: #"{"email":"alice@example.com","unexpected":true}"#
                )
            ) { response in
                self.assertError(response, status: .badRequest, code: "InvalidRequest")
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.server.resetPassword",
                method: .post,
                headers: [.contentType: "text/plain"],
                body: ByteBuffer(
                    string: #"{"token":"\#(Self.token)","password":"correct horse battery staple"}"#
                )
            ) { response in
                self.assertError(response, status: .badRequest, code: "InvalidRequest")
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.server.requestPasswordReset",
                method: .post,
                headers: self.jsonHeaders(),
                body: ByteBuffer(
                    string: #"{"email":"\#(String(repeating: "a", count: SwanAccountEmailXRPCServer.maximumJSONBytes))"}"#
                )
            ) { response in
                self.assertError(response, status: .contentTooLarge, code: "PayloadTooLarge")
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.server.requestPasswordReset",
                method: .get
            ) { response in
                self.assertError(response, status: .notFound, code: "EndpointUnavailable")
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.server.requestEmailConfirmation",
                method: .post,
                body: ByteBuffer(string: "must-be-empty")
            ) { response in
                self.assertError(response, status: .badRequest, code: "InvalidRequest")
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.server.updateEmail",
                method: .post,
                headers: self.jsonHeaders(),
                body: ByteBuffer(
                    string: #"{"email":"alice@example.com","email":"other@example.com"}"#
                )
            ) { response in
                self.assertError(response, status: .badRequest, code: "InvalidRequest")
            }
            // No Content-Length is supplied by the caller. The disabled
            // endpoint must still collect the actual stream under the same
            // 8 KiB cap before it reaches DPoP authorization.
            try await client.execute(
                uri: "/xrpc/com.atproto.server.updateEmail",
                method: .post,
                headers: self.jsonHeaders(),
                body: ByteBuffer(
                    string: #"{"email":"\#(String(repeating: "a", count: SwanAccountEmailXRPCServer.maximumJSONBytes))"}"#
                )
            ) { response in
                self.assertError(
                    response,
                    status: .contentTooLarge,
                    code: "PayloadTooLarge"
                )
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.server.confirmEmail?unexpected=true",
                method: .post,
                headers: self.jsonHeaders(),
                body: ByteBuffer(
                    string: #"{"email":"alice@example.com","token":"\#(Self.token)"}"#
                )
            ) { response in
                self.assertError(response, status: .badRequest, code: "InvalidRequest")
            }
        }

        let authorizationCalls = await authorizer.snapshot()
        let recoveryCalls = await recovery.snapshot()
        let rateCalls = await limiter.snapshot()
        XCTAssertTrue(authorizationCalls.isEmpty)
        XCTAssertTrue(recoveryCalls.isEmpty)
        XCTAssertTrue(rateCalls.isEmpty)
    }

    func testPasswordResetRequestIsOpaqueAndResetUsesOnlyDeclaredErrors() async throws {
        let authorizer = EmailAuthorizer(
            result: .success(.accountOAuth(subject: Self.otherDID, scopes: ["atproto"]))
        )
        let recovery = EmailRecovery(resetOutcomes: [.expiredToken, .invalidToken, .completed])
        let limiter = EmailRateLimiter()
        let app = makeServer(
            authorizer: authorizer,
            recovery: recovery,
            limiter: limiter
        ).buildApplication(logger: Logger(label: "AccountEmailXRPCTests.reset"))

        try await app.test(.live) { client in
            for email in ["known@example.com", "unknown@example.com"] {
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.requestPasswordReset",
                    method: .post,
                    headers: self.jsonHeaders(),
                    body: ByteBuffer(string: #"{"email":"\#(email)"}"#)
                ) { response in
                    self.assertEmptySuccess(response)
                }
            }
            let password = "correct horse battery staple"
            let expected: [(HTTPResponse.Status, String?)] = [
                (.badRequest, "ExpiredToken"),
                (.badRequest, "InvalidToken"),
                (.ok, nil),
            ]
            for (status, error) in expected {
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.resetPassword",
                    method: .post,
                    headers: self.jsonHeaders(),
                    body: ByteBuffer(
                        string: #"{"token":"\#(Self.token)","password":"\#(password)"}"#
                    )
                ) { response in
                    if let error {
                        self.assertError(response, status: status, code: error)
                    } else {
                        self.assertEmptySuccess(response)
                    }
                    let rendered = String(
                        decoding: response.body.readableBytesView,
                        as: UTF8.self
                    )
                    XCTAssertFalse(rendered.contains(password))
                    XCTAssertFalse(rendered.contains(Self.token))
                }
            }
        }

        let calls = await recovery.snapshot()
        XCTAssertEqual(calls, [
            .requestPasswordReset(email: "known@example.com"),
            .requestPasswordReset(email: "unknown@example.com"),
            .resetPassword(proof: Self.token, password: "correct horse battery staple"),
            .resetPassword(proof: Self.token, password: "correct horse battery staple"),
            .resetPassword(proof: Self.token, password: "correct horse battery staple"),
        ])
    }

    func testRateLimitingUsesOnlyTheDirectSocketPeerAndFailsClosed() async throws {
        let authorizer = EmailAuthorizer(
            result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"]))
        )
        let recovery = EmailRecovery()
        let limiter = EmailRateLimiter(results: [true, false])
        let app = makeServer(
            authorizer: authorizer,
            recovery: recovery,
            limiter: limiter
        ).buildApplication(logger: Logger(label: "AccountEmailXRPCTests.peer"))
        var headers = jsonHeaders()
        headers[HTTPField.Name("X-Forwarded-For")!] = "203.0.113.44"
        headers[SwanLoginClientIdentityPolicy.clientIPHeader] = "198.51.100.19"
        let forwardedHeaders = headers

        try await app.test(.live) { client in
            for status: HTTPResponse.Status in [.ok, .tooManyRequests] {
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.requestPasswordReset",
                    method: .post,
                    headers: forwardedHeaders,
                    body: ByteBuffer(string: #"{"email":"alice@example.com"}"#)
                ) { response in
                    if status == .ok {
                        self.assertEmptySuccess(response)
                    } else {
                        self.assertError(
                            response,
                            status: .tooManyRequests,
                            code: "RateLimitExceeded"
                        )
                    }
                }
            }
        }

        let rateCalls = await limiter.snapshot()
        XCTAssertEqual(rateCalls.count, 2)
        XCTAssertTrue(rateCalls.allSatisfy { !$0.directPeer.isEmpty })
        XCTAssertTrue(rateCalls.allSatisfy { $0.directPeer != "203.0.113.44" })
        XCTAssertTrue(rateCalls.allSatisfy { $0.directPeer != "198.51.100.19" })
        let expectedEmail = try AccountEmailAddress("alice@example.com")
        XCTAssertEqual(rateCalls.map(\.email), [
            expectedEmail,
            expectedEmail,
        ])
        let recoveryCalls = await recovery.snapshot()
        XCTAssertEqual(recoveryCalls, [
            .requestPasswordReset(email: "alice@example.com"),
        ])
    }

    func testUntrustedProxyIgnoresForgedInternalClientIdentity() async throws {
        let authorizer = EmailAuthorizer(
            result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"]))
        )
        let recovery = EmailRecovery()
        let limiter = EmailRateLimiter()
        let policy = try SwanLoginClientIdentityPolicy(
            trustedProxyPeerLiterals: ["192.0.2.10"]
        )
        let app = makeServer(
            authorizer: authorizer,
            recovery: recovery,
            limiter: limiter,
            loginClientIdentityPolicy: policy
        ).buildApplication(
            logger: Logger(label: "AccountEmailXRPCTests.untrusted-proxy")
        )
        var mutableHeaders = jsonHeaders()
        mutableHeaders[SwanLoginClientIdentityPolicy.clientIPHeader] =
            "203.0.113.44"
        let headers = mutableHeaders

        try await app.test(.live) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.requestPasswordReset",
                method: .post,
                headers: headers,
                body: ByteBuffer(string: #"{"email":"alice@example.com"}"#)
            ) { response in
                self.assertEmptySuccess(response)
            }
        }

        let rateCalls = await limiter.snapshot()
        XCTAssertEqual(rateCalls.count, 1)
        let rateCall = try XCTUnwrap(rateCalls.first)
        XCTAssertFalse(rateCall.directPeer.isEmpty)
        XCTAssertNotEqual(rateCall.directPeer, "203.0.113.44")
    }

    func testTrustedProxyCanonicalClientIPsUseDistinctRateLimitBuckets() async throws {
        let authorizer = EmailAuthorizer(
            result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"]))
        )
        let recovery = EmailRecovery()
        let limiter = EmailRateLimiter()
        let policy = try SwanLoginClientIdentityPolicy(
            trustedProxyPeerLiterals: ["127.0.0.1", "::1"]
        )
        let app = makeServer(
            authorizer: authorizer,
            recovery: recovery,
            limiter: limiter,
            loginClientIdentityPolicy: policy
        ).buildApplication(
            logger: Logger(label: "AccountEmailXRPCTests.trusted-proxy")
        )

        try await app.test(.live) { client in
            for value in ["203.0.113.44", "2001:db8:0:0::44"] {
                var headers = self.jsonHeaders()
                headers[SwanLoginClientIdentityPolicy.clientIPHeader] = value
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.requestPasswordReset",
                    method: .post,
                    headers: headers,
                    body: ByteBuffer(string: #"{"email":"alice@example.com"}"#)
                ) { response in
                    self.assertEmptySuccess(response)
                }
            }
        }

        let rateCalls = await limiter.snapshot()
        XCTAssertEqual(
            rateCalls.map(\.directPeer),
            ["203.0.113.44", "2001:db8::44"]
        )
        XCTAssertEqual(Set(rateCalls.map(\.directPeer)).count, 2)
        let recoveryCalls = await recovery.snapshot()
        XCTAssertEqual(recoveryCalls.count, 2)
    }

    func testTrustedProxyRejectsAmbiguousClientIdentityBeforeAdmissionOrRecovery() async throws {
        let authorizer = EmailAuthorizer(
            result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"]))
        )
        let recovery = EmailRecovery()
        let limiter = EmailRateLimiter()
        let policy = try SwanLoginClientIdentityPolicy(
            trustedProxyPeerLiterals: ["127.0.0.1", "::1"]
        )
        let app = makeServer(
            authorizer: authorizer,
            recovery: recovery,
            limiter: limiter,
            loginClientIdentityPolicy: policy
        ).buildApplication(
            logger: Logger(label: "AccountEmailXRPCTests.proxy-errors")
        )
        let values: [String?] = [
            nil,
            "203.0.113.44, 198.51.100.19",
            "203.0.113.44:443",
            "[2001:db8::44]",
            "client.example",
        ]

        try await app.test(.live) { client in
            for value in values {
                var headers = self.jsonHeaders()
                if let value {
                    headers[SwanLoginClientIdentityPolicy.clientIPHeader] = value
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.requestPasswordReset",
                    method: .post,
                    headers: headers,
                    body: ByteBuffer(string: #"{"email":"alice@example.com"}"#)
                ) { response in
                    self.assertError(
                        response,
                        status: .serviceUnavailable,
                        code: "temporarily_unavailable"
                    )
                }
            }

            var duplicate = self.jsonHeaders()
            duplicate.append(HTTPField(
                name: SwanLoginClientIdentityPolicy.clientIPHeader,
                value: "203.0.113.44"
            ))
            duplicate.append(HTTPField(
                name: SwanLoginClientIdentityPolicy.clientIPHeader,
                value: "198.51.100.19"
            ))
            try await client.execute(
                uri: "/xrpc/com.atproto.server.requestPasswordReset",
                method: .post,
                headers: duplicate,
                body: ByteBuffer(string: #"{"email":"alice@example.com"}"#)
            ) { response in
                self.assertError(
                    response,
                    status: .serviceUnavailable,
                    code: "temporarily_unavailable"
                )
            }
        }

        let rateCalls = await limiter.snapshot()
        let recoveryCalls = await recovery.snapshot()
        XCTAssertTrue(rateCalls.isEmpty)
        XCTAssertTrue(recoveryCalls.isEmpty)
    }

    func testRecoveryFailureIsFixedNoStoreAndDoesNotReflectRequestData() async throws {
        let authorizer = EmailAuthorizer(
            result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"]))
        )
        let recovery = EmailRecovery(
            requestPasswordFailure: .deliveryUnavailable
        )
        let limiter = EmailRateLimiter()
        let app = makeServer(
            authorizer: authorizer,
            recovery: recovery,
            limiter: limiter
        ).buildApplication(logger: Logger(label: "AccountEmailXRPCTests.secrecy"))
        let sensitiveEmail = "sensitive-person@example.com"

        try await app.test(.live) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.requestPasswordReset",
                method: .post,
                headers: self.jsonHeaders(),
                body: ByteBuffer(string: #"{"email":"\#(sensitiveEmail)"}"#)
            ) { response in
                // Delivery/storage failures are intentionally collapsed into
                // the same opaque success as an unknown address.
                self.assertEmptySuccess(response)
                let rendered = String(
                    decoding: response.body.readableBytesView,
                    as: UTF8.self
                )
                XCTAssertFalse(rendered.contains(sensitiveEmail))
                XCTAssertFalse(rendered.contains(Self.did))
            }
        }
    }

    private func makeServer(
        authorizer: EmailAuthorizer,
        recovery: EmailRecovery,
        limiter: EmailRateLimiter,
        loginClientIdentityPolicy: SwanLoginClientIdentityPolicy = .direct
    ) -> SwanAccountEmailXRPCServer {
        SwanAccountEmailXRPCServer(
            authorizer: authorizer,
            recovery: recovery,
            rateLimiter: limiter,
            loginClientIdentityPolicy: loginClientIdentityPolicy
        )
    }

    private func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func jsonHeaders() -> HTTPFields {
        [.contentType: "application/json"]
    }

    private func assertEmptySuccess(
        _ response: TestResponse,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(response.status, .ok, file: file, line: line)
        XCTAssertEqual(response.headers[.cacheControl], "no-store", file: file, line: line)
        XCTAssertEqual(response.body.readableBytes, 0, file: file, line: line)
    }

    private func assertError(
        _ response: TestResponse,
        status: HTTPResponse.Status,
        code: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(response.status, status, file: file, line: line)
        XCTAssertEqual(response.headers[.contentType], "application/json", file: file, line: line)
        XCTAssertEqual(response.headers[.cacheControl], "no-store", file: file, line: line)
        let actual = try? Self.errorCode(response.body)
        XCTAssertEqual(actual, code, file: file, line: line)
    }

    private static func errorCode(_ body: ByteBuffer) throws -> String {
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(buffer: body)) as? [String: Any]
        )
        XCTAssertEqual(Set(object.keys), ["error"])
        return try XCTUnwrap(object["error"] as? String)
    }
}

private actor EmailAuthorizer: SwanAccountEmailResourceAuthorizing {
    struct Call: Sendable, Equatable {
        let method: String
        let path: String
    }

    private let result: Result<AuthorizationContext, SwanResourceAuthorizationFailure>
    private var calls: [Call] = []

    init(result: Result<AuthorizationContext, SwanResourceAuthorizationFailure>) {
        self.result = result
    }

    func authorizeAccountEmail(
        request _: Request,
        method: String,
        fixedPath: String,
        now _: Date
    ) async throws -> AuthorizationContext {
        calls.append(.init(method: method, path: fixedPath))
        return try result.get()
    }

    func issueAccountEmailNonce(now _: Date) async -> String {
        "test-nonce"
    }

    func snapshot() -> [Call] {
        calls
    }
}

private actor EmailRecovery: SwanAccountEmailXRPCRecovering {
    enum Call: Sendable, Equatable {
        case requestEmailConfirmation(did: String)
        case confirmEmail(did: String, email: String, proof: String)
        case requestPasswordReset(email: String)
        case resetPassword(proof: String, password: String)
    }

    private let confirmationOutcome: AccountEmailConfirmationOutcome
    private var resetOutcomes: [AccountPasswordResetOutcome]
    private let requestPasswordFailure: AccountEmailRecoveryError?
    private var calls: [Call] = []

    init(
        confirmationOutcome: AccountEmailConfirmationOutcome = .confirmed,
        resetOutcomes: [AccountPasswordResetOutcome] = [.completed],
        requestPasswordFailure: AccountEmailRecoveryError? = nil
    ) {
        self.confirmationOutcome = confirmationOutcome
        self.resetOutcomes = resetOutcomes
        self.requestPasswordFailure = requestPasswordFailure
    }

    func requestEmailConfirmation(did: String, now _: Date) async throws {
        calls.append(.requestEmailConfirmation(did: did))
    }

    func confirmEmail(
        did: String,
        email: AccountEmailAddress,
        proof: String,
        now _: Date
    ) async throws -> AccountEmailConfirmationOutcome {
        calls.append(.confirmEmail(did: did, email: email.value, proof: proof))
        return confirmationOutcome
    }

    func requestPasswordRecovery(
        email: AccountEmailAddress,
        now _: Date
    ) async throws {
        calls.append(.requestPasswordReset(email: email.value))
        if let requestPasswordFailure {
            throw requestPasswordFailure
        }
    }

    func resetPassword(
        proof: String,
        password: String,
        now _: Date
    ) async throws -> AccountPasswordResetOutcome {
        calls.append(.resetPassword(proof: proof, password: password))
        return resetOutcomes.isEmpty ? .completed : resetOutcomes.removeFirst()
    }

    func snapshot() -> [Call] {
        calls
    }
}

private actor EmailRateLimiter: SwanAccountEmailXRPCRateLimiting {
    private var results: [Bool]
    private var calls: [SwanAccountEmailRateLimitRequest] = []

    init(results: [Bool] = [true]) {
        self.results = results
    }

    func permits(
        _ request: SwanAccountEmailRateLimitRequest,
        now _: Date
    ) async throws -> Bool {
        calls.append(request)
        return results.count <= 1 ? (results.first ?? true) : results.removeFirst()
    }

    func snapshot() -> [SwanAccountEmailRateLimitRequest] {
        calls
    }
}
