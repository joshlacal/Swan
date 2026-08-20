import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import SwanAccounts
import SwanCore
import SwanOAuth
import SwanSQLite
import SwanStorage
import XCTest
@testable import SwanHTTP

/// The four session endpoints, end to end over HTTP.
///
/// The property that matters most here is the one a status code alone cannot
/// show: an unknown account and a wrong password must be indistinguishable, in
/// body AND in shape, or the login boundary becomes an account-existence oracle.
final class LegacySessionHTTPTests: XCTestCase, @unchecked Sendable {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let handle = "legacy.example.com"
    /// The real account password, hashed with the same policy the directory
    /// verifies against — these tests exercise the account-password login path,
    /// so a placeholder verifier would not do.
    private static let accountPassword = "correct-horse-battery-staple"

    private struct AlwaysAdmits: SwanLegacySessionRateLimiting {
        func admitSessionCreation(identifier: String, now: Date) async -> Bool { true }
    }

    private struct NeverAdmits: SwanLegacySessionRateLimiting {
        func admitSessionCreation(identifier: String, now: Date) async -> Bool { false }
    }

    /// `Router` is not `Sendable`; the fixture is only ever used from the
    /// test's own task, so the escape hatch is accurate rather than a paper-over.
    private struct Fixture: @unchecked Sendable {
        let root: URL
        let database: SQLiteControlDatabase
        let credentials: AppPasswordCredentials
        let serviceAuthIssuer: TestServiceAuthIssuer
        let router: Router<SwanHTTPRequestContext>
    }

    private func makeFixture(
        rateLimiter: any SwanLegacySessionRateLimiting = AlwaysAdmits(),
        serviceAuthIssuer: TestServiceAuthIssuer? = nil
    ) async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "LegacySessionHTTPTests-" + UUID().uuidString)
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let hasher = try LibsodiumArgon2idHasher()
        let factorTokens = FactorTokenService(store: database)
        let accounts = DurableAccountDirectory(
            store: database,
            passwordHasher: hasher,
            verificationExecutor: try Argon2idVerificationExecutor(hasher: hasher),
            loginFactorTokenVerifier: factorTokens,
            authenticationFactors: database
        )
        _ = try await database.createAccount(
            try AccountControlRegistration(
                did: did,
                canonicalHandle: handle,
                passwordVerifier: try hasher.hash(Self.accountPassword),
                signingKey: try .init(purpose: .signing, generation: 1),
                rotationKey: try .init(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )
        let credentials = try AppPasswordCredentials()
        let serviceAuthIssuer = serviceAuthIssuer ?? TestServiceAuthIssuer()
        let router = Router(context: SwanHTTPRequestContext.self)
        SwanLegacySessionXRPCServer(
            sessions: try DurableLegacySessionService(
                store: database,
                appPasswords: database,
                credentials: credentials,
                serviceDID: "did:web:swan.test",
                serverKey: Data(repeating: 0x3c, count: 32)
            ),
            credentials: credentials,
            appPasswords: database,
            accounts: accounts,
            directory: SwanDurableLegacySessionDirectory(store: database),
            rateLimiter: rateLimiter,
            serviceAuthIssuer: serviceAuthIssuer,
            // These tests assert behaviour, not timing. The production floor is
            // 350ms and would add seconds across the suite.
            minimumFailedLoginDuration: .milliseconds(1)
        ).register(
            on: router,
            requestBodyAdmission: .init(
                admission: .processShared,
                policy: .productionDefault
            )
        )
        // The fence these routes must coexist with, registered exactly as the
        // production assembly does.
        registerUnknownPublicEndpointGuards(on: router)
        return Fixture(root: root, database: database, credentials: credentials, serviceAuthIssuer: serviceAuthIssuer, router: router)
    }

    private func app(_ fixture: Fixture) -> some ApplicationProtocol {
        Application(
            router: fixture.router,
            logger: Logger(label: "LegacySessionHTTPTests")
        )
    }

    private func issuePassword(
        _ fixture: Fixture,
        name: String = "Bluesky app",
        scopes: String = "atproto transition:generic"
    ) async throws -> String {
        try await fixture.credentials.issue(
            did: did, name: name, scopes: scopes, into: fixture.database
        ).password
    }

    private func body(_ response: TestResponse) -> String {
        String(decoding: response.body.readableBytesView, as: UTF8.self)
    }

    private func json(_ response: TestResponse) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(response.body.readableBytesView))
                as? [String: Any]
        )
    }

    // MARK: - createSession

    func testCreateSessionReturnsTheFieldsTheClientNeeds() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let password = try await issuePassword(fixture)
        try await app(fixture).test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.createSession",
                method: .post,
                headers: [.contentType: "application/json"],
                body: ByteBuffer(string:
                    "{\"identifier\":\"\(self.handle)\",\"password\":\"\(password)\"}"
                )
            ) { response in
                XCTAssertEqual(response.status, .ok, self.body(response))
                let payload = try self.json(response)
                XCTAssertEqual(payload["did"] as? String, self.did)
                XCTAssertEqual(payload["handle"] as? String, self.handle)
                XCTAssertNotNil(payload["accessJwt"] as? String)
                XCTAssertNotNil(payload["refreshJwt"] as? String)
            }
        }
    }

    /// The reason this path exists: there is no app-password UI, so the
    /// account password must work or nobody can sign in at all. Upstream
    /// accepts either (`account-manager.ts:620-633`).
    func testTheAccountPasswordSignsIn() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        try await app(fixture).test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.createSession",
                method: .post,
                headers: [.contentType: "application/json"],
                body: ByteBuffer(string:
                    "{\"identifier\":\"\(self.handle)\",\"password\":\"\(Self.accountPassword)\"}"
                )
            ) { response in
                XCTAssertEqual(response.status, .ok, self.body(response))
                let payload = try self.json(response)
                XCTAssertEqual(payload["did"] as? String, self.did)
                // The `scope` claim is upstream's credential-TYPE discriminator:
                // an account-password session is `com.atproto.access`, not
                // `com.atproto.appPass`.
                let access = try XCTUnwrap(payload["accessJwt"] as? String)
                let claims = try XCTUnwrap(
                    JSONSerialization.jsonObject(
                        with: try XCTUnwrap(
                            Data(base64URLEncoded: String(access.split(separator: ".")[1]))
                        )
                    ) as? [String: Any]
                )
                XCTAssertEqual(claims["scope"] as? String, "com.atproto.access")
            }
        }
    }

    /// Signing in with an app password produces a session of the SAME shape but
    /// a different credential type — which is where the narrowing lives.
    func testAnAppPasswordSignsInWithItsOwnDiscriminator() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let password = try await issuePassword(fixture)
        try await app(fixture).test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.createSession",
                method: .post,
                headers: [.contentType: "application/json"],
                body: ByteBuffer(string:
                    "{\"identifier\":\"\(self.handle)\",\"password\":\"\(password)\"}"
                )
            ) { response in
                XCTAssertEqual(response.status, .ok, self.body(response))
                let access = try XCTUnwrap(try self.json(response)["accessJwt"] as? String)
                let claims = try XCTUnwrap(
                    JSONSerialization.jsonObject(
                        with: try XCTUnwrap(
                            Data(base64URLEncoded: String(access.split(separator: ".")[1]))
                        )
                    ) as? [String: Any]
                )
                XCTAssertEqual(claims["scope"] as? String, "com.atproto.appPass")
            }
        }
    }

    /// The oracle test. A wrong password on a REAL account and any password on
    /// an account that does not exist must be identical to the caller.
    func testUnknownAccountAndWrongPasswordAreIndistinguishable() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        _ = try await issuePassword(fixture)
        try await app(fixture).test(.router) { client in
            var observed: [String] = []
            var statuses: [HTTPResponse.Status] = []
            for identifier in [self.handle, "nobody.example.com"] {
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createSession",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: ByteBuffer(string:
                        "{\"identifier\":\"\(identifier)\",\"password\":\"wrong-wrong-wrong-x\"}"
                    )
                ) { response in
                    statuses.append(response.status)
                    observed.append(self.body(response))
                }
            }
            XCTAssertEqual(statuses, [.unauthorized, .unauthorized])
            XCTAssertEqual(observed[0], observed[1], "the two must be byte-identical")
            XCTAssertEqual(observed[0], "{\"error\":\"AuthenticationRequired\"}")
        }
    }

    /// The official client always sends these two; rejecting an unknown key
    /// would fail every login.
    func testOptionalClientFieldsAreAccepted() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let password = try await issuePassword(fixture)
        try await app(fixture).test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.createSession",
                method: .post,
                headers: [.contentType: "application/json"],
                body: ByteBuffer(string:
                    "{\"identifier\":\"\(self.handle)\",\"password\":\"\(password)\","
                        + "\"authFactorToken\":\"ignored\",\"allowTakendown\":false}"
                )
            ) { response in
                XCTAssertEqual(response.status, .ok, self.body(response))
            }
        }
    }
    /// When an account has an active second factor enrolled, a login attempt
    /// presenting the correct account password but omitting `authFactorToken`
    /// must be refused with HTTP 401 and error name `AuthFactorTokenRequired`,
    /// matching the lexicon definition in com.atproto.server.createSession.
    func testFactorEnrolledCorrectPasswordNoTokenReturnsAuthFactorTokenRequired() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let factor = try AuthenticationFactorMetadata(
            id: "totp-factor",
            accountDID: did,
            kind: .totp,
            label: "Authenticator",
            lookupDigest: Data(repeating: 1, count: 32),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
        try await fixture.database.saveFactor(factor, now: Date(timeIntervalSince1970: 1_750_000_000))
        try await app(fixture).test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.createSession",
                method: .post,
                headers: [.contentType: "application/json"],
                body: ByteBuffer(string:
                    "{\"identifier\":\"\(self.handle)\",\"password\":\"\(Self.accountPassword)\"}"
                )
            ) { response in
                XCTAssertEqual(response.status, .unauthorized, self.body(response))
                let payload = try self.json(response)
                XCTAssertEqual(payload["error"] as? String, "AuthFactorTokenRequired")
            }
        }
    }

    /// A wrong password on a factor-enrolled account must return `AuthenticationRequired`,
    /// NEVER `AuthFactorTokenRequired`. Otherwise the error response becomes an
    /// existence-and-MFA oracle for handles probed by an attacker.
    func testFactorEnrolledWrongPasswordReturnsAuthenticationRequired() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let factor = try AuthenticationFactorMetadata(
            id: "totp-factor",
            accountDID: did,
            kind: .totp,
            label: "Authenticator",
            lookupDigest: Data(repeating: 1, count: 32),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
        try await fixture.database.saveFactor(factor, now: Date(timeIntervalSince1970: 1_750_000_000))
        try await app(fixture).test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.createSession",
                method: .post,
                headers: [.contentType: "application/json"],
                body: ByteBuffer(string:
                    "{\"identifier\":\"\(self.handle)\",\"password\":\"wrong-password-value\"}"
                )
            ) { response in
                XCTAssertEqual(response.status, .unauthorized, self.body(response))
                let payload = try self.json(response)
                XCTAssertEqual(payload["error"] as? String, "AuthenticationRequired")
            }
        }
    }

    /// Presenting an invalid or expired factor token alongside the correct password
    /// must fail closed with `AuthenticationRequired`, not `AuthFactorTokenRequired`
    /// (a bad code is not a missing code).
    func testFactorEnrolledCorrectPasswordBadTokenReturnsAuthenticationRequired() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let factor = try AuthenticationFactorMetadata(
            id: "totp-factor",
            accountDID: did,
            kind: .totp,
            label: "Authenticator",
            lookupDigest: Data(repeating: 1, count: 32),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
        try await fixture.database.saveFactor(factor, now: Date(timeIntervalSince1970: 1_750_000_000))
        try await app(fixture).test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.createSession",
                method: .post,
                headers: [.contentType: "application/json"],
                body: ByteBuffer(string:
                    "{\"identifier\":\"\(self.handle)\",\"password\":\"\(Self.accountPassword)\",\"authFactorToken\":\"bad-code-123456\"}"
                )
            ) { response in
                XCTAssertEqual(response.status, .unauthorized, self.body(response))
                let payload = try self.json(response)
                XCTAssertEqual(payload["error"] as? String, "AuthenticationRequired")
            }
        }
    }

    /// App password login on a factor-enrolled account must succeed without
    /// requiring an authFactorToken (app passwords bypass second-factor ceremony).
    func testFactorEnrolledAppPasswordBypassesMFA() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let factor = try AuthenticationFactorMetadata(
            id: "totp-factor",
            accountDID: did,
            kind: .totp,
            label: "Authenticator",
            lookupDigest: Data(repeating: 1, count: 32),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
        try await fixture.database.saveFactor(factor, now: Date(timeIntervalSince1970: 1_750_000_000))
        let appPassword = try await issuePassword(fixture)
        try await app(fixture).test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.createSession",
                method: .post,
                headers: [.contentType: "application/json"],
                body: ByteBuffer(string:
                    "{\"identifier\":\"\(self.handle)\",\"password\":\"\(appPassword)\"}"
                )
            ) { response in
                XCTAssertEqual(response.status, .ok, self.body(response))
                let payload = try self.json(response)
                XCTAssertEqual(payload["did"] as? String, self.did)
            }
        }
    }

    /// Directory-level channel semantics verification:
    /// 1. `.legacy` channel + factor enrolled + correct password → `.authenticated(requiresFactor: true)`
    /// 2. `.oauth` channel + factor enrolled + correct password → `.authenticated(requiresFactor: true)`
    /// 3. `.portal` channel + factor enrolled + correct password (without token) → `.rejected`
    /// 4. No factor enrolled + correct password → `.authenticated(requiresFactor: false)` across all channels
    func testDirectoryChannelAuthenticationSemantics() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let hasher = try LibsodiumArgon2idHasher()
        let factorTokens = FactorTokenService(store: fixture.database)
        let accounts = DurableAccountDirectory(
            store: fixture.database,
            passwordHasher: hasher,
            verificationExecutor: try Argon2idVerificationExecutor(hasher: hasher),
            loginFactorTokenVerifier: factorTokens,
            authenticationFactors: fixture.database
        )
        let now = Date(timeIntervalSince1970: 1_750_000_000)

        // 1. Without factors enrolled
        let legacyNoFactor = try await accounts.authenticateForLogin(
            handle: self.handle,
            password: Self.accountPassword,
            authFactorToken: nil,
            authorizationContext: try AccountAuthorizationContext(channel: .legacy, sessionID: "s1", purpose: "managementLogin"),
            now: now
        )
        guard case let .authenticated(legacyNoFactorSuccess) = legacyNoFactor else {
            XCTFail("expected .authenticated for legacy without factors")
            return
        }
        XCTAssertFalse(legacyNoFactorSuccess.requiresFactor)
        XCTAssertNotNil(legacyNoFactorSuccess.authorizationGrantDigest)

        let portalNoFactor = try await accounts.authenticateForLogin(
            handle: self.handle,
            password: Self.accountPassword,
            authFactorToken: nil,
            authorizationContext: try AccountAuthorizationContext(channel: .portal, sessionID: "s2", purpose: "managementLogin"),
            now: now
        )
        guard case let .authenticated(portalNoFactorSuccess) = portalNoFactor else {
            XCTFail("expected .authenticated for portal without factors")
            return
        }
        XCTAssertFalse(portalNoFactorSuccess.requiresFactor)
        XCTAssertNotNil(portalNoFactorSuccess.authorizationGrantDigest)

        // 2. Enroll a factor
        let factor = try AuthenticationFactorMetadata(
            id: "totp-factor",
            accountDID: did,
            kind: .totp,
            label: "Authenticator",
            lookupDigest: Data(repeating: 1, count: 32),
            createdAt: now
        )
        try await fixture.database.saveFactor(factor, now: now)

        // Legacy channel with factor enrolled + correct password → requiresFactor: true
        let legacyWithFactor = try await accounts.authenticateForLogin(
            handle: self.handle,
            password: Self.accountPassword,
            authFactorToken: nil,
            authorizationContext: try AccountAuthorizationContext(channel: .legacy, sessionID: "s3", purpose: "managementLogin"),
            now: now
        )
        guard case let .authenticated(legacyWithFactorSuccess) = legacyWithFactor else {
            XCTFail("expected .authenticated(requiresFactor: true) for legacy with factor enrolled")
            return
        }
        XCTAssertTrue(legacyWithFactorSuccess.requiresFactor)

        // OAuth channel with factor enrolled + correct password → requiresFactor: true
        let oauthContext = try AccountAuthorizationContext(
            channel: .oauth,
            sessionID: "s4",
            csrfDigest: Data(repeating: 0xAA, count: 32),
            clientID: "client.example",
            requestDigest: Data(repeating: 0xBB, count: 32),
            purpose: "oauthToken"
        )
        let oauthWithFactor = try await accounts.authenticateForLogin(
            handle: self.handle,
            password: Self.accountPassword,
            authFactorToken: nil,
            authorizationContext: oauthContext,
            now: now
        )
        guard case let .authenticated(oauthWithFactorSuccess) = oauthWithFactor else {
            XCTFail("expected .authenticated(requiresFactor: true) for oauth with factor enrolled")
            return
        }
        XCTAssertTrue(oauthWithFactorSuccess.requiresFactor)

        // Portal channel with factor enrolled + correct password (no token) → .rejected
        let portalWithFactor = try await accounts.authenticateForLogin(
            handle: self.handle,
            password: Self.accountPassword,
            authFactorToken: nil,
            authorizationContext: try AccountAuthorizationContext(channel: .portal, sessionID: "s5", purpose: "managementLogin"),
            now: now
        )
        XCTAssertEqual(portalWithFactor, .rejected)

        // Wrong password with factor enrolled → .rejected on all channels
        let legacyWrongPassword = try await accounts.authenticateForLogin(
            handle: self.handle,
            password: "wrong-password",
            authFactorToken: nil,
            authorizationContext: try AccountAuthorizationContext(channel: .legacy, sessionID: "s6", purpose: "managementLogin"),
            now: now
        )
        XCTAssertEqual(legacyWrongPassword, .rejected)
    }

    func testRateLimitedLoginIsRefused() async throws {
        let fixture = try await makeFixture(rateLimiter: NeverAdmits())
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let password = try await issuePassword(fixture)
        try await app(fixture).test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.createSession",
                method: .post,
                headers: [.contentType: "application/json"],
                body: ByteBuffer(string:
                    "{\"identifier\":\"\(self.handle)\",\"password\":\"\(password)\"}"
                )
            ) { response in
                XCTAssertEqual(response.status, .tooManyRequests)
            }
        }
    }

    // MARK: - The session lifecycle the app performs

    func testRefreshGetAndDeleteCompleteTheLifecycle() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let password = try await issuePassword(fixture)
        try await app(fixture).test(.router) { client in
            var access = ""
            var refresh = ""
            try await client.execute(
                uri: "/xrpc/com.atproto.server.createSession",
                method: .post,
                headers: [.contentType: "application/json"],
                body: ByteBuffer(string:
                    "{\"identifier\":\"\(self.handle)\",\"password\":\"\(password)\"}"
                )
            ) { response in
                let payload = try self.json(response)
                access = try XCTUnwrap(payload["accessJwt"] as? String)
                refresh = try XCTUnwrap(payload["refreshJwt"] as? String)
            }

            // getSession with the access token — the app calls this on resume.
            try await client.execute(
                uri: "/xrpc/com.atproto.server.getSession",
                method: .get,
                headers: [.authorization: "Bearer \(access)"]
            ) { response in
                XCTAssertEqual(response.status, .ok, self.body(response))
                XCTAssertEqual(try self.json(response)["did"] as? String, self.did)
            }

            // refreshSession with the REFRESH token, which is what makes an app
            // restart work without re-login.
            var rotated = ""
            try await client.execute(
                uri: "/xrpc/com.atproto.server.refreshSession",
                method: .post,
                headers: [.authorization: "Bearer \(refresh)"]
            ) { response in
                XCTAssertEqual(response.status, .ok, self.body(response))
                let payload = try self.json(response)
                rotated = try XCTUnwrap(payload["refreshJwt"] as? String)
                XCTAssertNotEqual(rotated, refresh, "refresh must rotate")
            }

            // An access token is not a refresh token.
            try await client.execute(
                uri: "/xrpc/com.atproto.server.refreshSession",
                method: .post,
                headers: [.authorization: "Bearer \(access)"]
            ) { response in
                XCTAssertNotEqual(response.status, .ok)
            }

            // deleteSession ends it, and is idempotent.
            try await client.execute(
                uri: "/xrpc/com.atproto.server.deleteSession",
                method: .post,
                headers: [.authorization: "Bearer \(rotated)"]
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.server.deleteSession",
                method: .post,
                headers: [.authorization: "Bearer \(rotated)"]
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
    }

    func testAMissingBearerIsRefused() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        try await app(fixture).test(.router) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.getSession",
                method: .get
            ) { response in
                XCTAssertNotEqual(response.status, .ok)
            }
        }
    }

    // MARK: - Service authentication

    func testGetServiceAuthRequiresBothMethodAndAudienceAndBindsTheSignedClaims() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let audience = "did:web:remote.example#pds"
        let method = "com.atproto.repo.getRecord"
        let password = try await issuePassword(
            fixture,
            scopes: "atproto rpc:\(method)?aud=did:web:remote.example%23pds"
        )
        try await app(fixture).test(.router) { client in
            var access = ""
            try await client.execute(
                uri: "/xrpc/com.atproto.server.createSession",
                method: .post,
                headers: [.contentType: "application/json"],
                body: ByteBuffer(string: "{\"identifier\":\"\(self.handle)\",\"password\":\"\(password)\"}")
            ) { response in
                access = try XCTUnwrap(try self.json(response)["accessJwt"] as? String)
            }

            try await client.execute(
                uri: "/xrpc/com.atproto.server.getServiceAuth?aud=\(audience.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)&lxm=\(method)",
                method: .get,
                headers: [.authorization: "Bearer \(access)"]
            ) { response in
                XCTAssertEqual(response.status, .ok, self.body(response))
                let token = try XCTUnwrap(try self.json(response)["token"] as? String)
                let pieces = token.split(separator: ".")
                XCTAssertEqual(pieces.count, 3)
                let claims = try XCTUnwrap(
                    JSONSerialization.jsonObject(
                        with: try XCTUnwrap(Data(base64URLEncoded: String(pieces[1])))
                    ) as? [String: Any]
                )
                XCTAssertEqual(claims["iss"] as? String, self.did)
                XCTAssertEqual(claims["aud"] as? String, audience)
                XCTAssertEqual(claims["lxm"] as? String, method)
                let issuedAt = try XCTUnwrap(claims["iat"] as? NSNumber).int64Value
                let expiresAt = try XCTUnwrap(claims["exp"] as? NSNumber).int64Value
                XCTAssertEqual(expiresAt - issuedAt, 60)
            }
            let calls = await fixture.serviceAuthIssuer.calls()
            XCTAssertEqual(calls.map(\.issuer), [self.did])
            XCTAssertEqual(calls.map(\.audience), [audience])
            XCTAssertEqual(calls.map(\.method), [method])

            // Omitting either binding must never mint a broad token.
            try await client.execute(
                uri: "/xrpc/com.atproto.server.getServiceAuth?aud=\(audience.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)",
                method: .get,
                headers: [.authorization: "Bearer \(access)"]
            ) { response in
                XCTAssertEqual(response.status, .unauthorized)
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.server.getServiceAuth?aud=\(audience.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)&lxm=com.atproto.repo.deleteRecord",
                method: .get,
                headers: [.authorization: "Bearer \(access)"]
            ) { response in
                XCTAssertEqual(response.status, .unauthorized)
            }
        }
    }

    // MARK: - App-password management

    private func fullAccessToken(
        _ client: some TestClientProtocol,
        fixture: Fixture
    ) async throws -> String {
        var token = ""
        try await client.execute(
            uri: "/xrpc/com.atproto.server.createSession",
            method: .post,
            headers: [.contentType: "application/json"],
            body: ByteBuffer(string:
                "{\"identifier\":\"\(self.handle)\",\"password\":\"\(Self.accountPassword)\"}"
            )
        ) { response in
            token = try XCTUnwrap(try self.json(response)["accessJwt"] as? String)
        }
        return token
    }

    func testCreateListAndRevokeAnAppPassword() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        try await app(fixture).test(.router) { client in
            let token = try await self.fullAccessToken(client, fixture: fixture)

            var issued = ""
            try await client.execute(
                uri: "/xrpc/com.atproto.server.createAppPassword",
                method: .post,
                headers: [.contentType: "application/json", .authorization: "Bearer \(token)"],
                body: ByteBuffer(string: "{\"name\":\"phone\"}")
            ) { response in
                XCTAssertEqual(response.status, .ok, self.body(response))
                let payload = try self.json(response)
                XCTAssertEqual(payload["name"] as? String, "phone")
                issued = try XCTUnwrap(payload["password"] as? String)
            }

            // Listing shows it and never carries the secret.
            try await client.execute(
                uri: "/xrpc/com.atproto.server.listAppPasswords",
                method: .get,
                headers: [.authorization: "Bearer \(token)"]
            ) { response in
                XCTAssertEqual(response.status, .ok, self.body(response))
                XCTAssertFalse(self.body(response).contains(issued))
                let passwords = try XCTUnwrap(
                    try self.json(response)["passwords"] as? [[String: Any]]
                )
                XCTAssertEqual(passwords.count, 1)
                XCTAssertEqual(passwords[0]["name"] as? String, "phone")
            }

            // The issued secret signs in.
            try await client.execute(
                uri: "/xrpc/com.atproto.server.createSession",
                method: .post,
                headers: [.contentType: "application/json"],
                body: ByteBuffer(string:
                    "{\"identifier\":\"\(self.handle)\",\"password\":\"\(issued)\"}"
                )
            ) { response in
                XCTAssertEqual(response.status, .ok, self.body(response))
            }

            // Revoking it stops that.
            try await client.execute(
                uri: "/xrpc/com.atproto.server.revokeAppPassword",
                method: .post,
                headers: [.contentType: "application/json", .authorization: "Bearer \(token)"],
                body: ByteBuffer(string: "{\"name\":\"phone\"}")
            ) { response in
                XCTAssertEqual(response.status, .ok, self.body(response))
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.server.createSession",
                method: .post,
                headers: [.contentType: "application/json"],
                body: ByteBuffer(string:
                    "{\"identifier\":\"\(self.handle)\",\"password\":\"\(issued)\"}"
                )
            ) { response in
                XCTAssertEqual(response.status, .unauthorized)
            }
        }
    }

    /// The anti-escalation rule, and the reason these endpoints require
    /// `ACCESS_FULL`: an app password must not mint further app passwords, nor
    /// revoke the credential that would have contained it.
    func testAnAppPasswordSessionCannotManageAppPasswords() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let scoped = try await issuePassword(fixture, name: "scoped")
        try await app(fixture).test(.router) { client in
            var token = ""
            try await client.execute(
                uri: "/xrpc/com.atproto.server.createSession",
                method: .post,
                headers: [.contentType: "application/json"],
                body: ByteBuffer(string:
                    "{\"identifier\":\"\(self.handle)\",\"password\":\"\(scoped)\"}"
                )
            ) { response in
                XCTAssertEqual(response.status, .ok, self.body(response))
                token = try XCTUnwrap(try self.json(response)["accessJwt"] as? String)
            }

            for (uri, method, payload) in [
                ("/xrpc/com.atproto.server.createAppPassword", HTTPRequest.Method.post, "{\"name\":\"escalated\"}"),
                ("/xrpc/com.atproto.server.revokeAppPassword", .post, "{\"name\":\"scoped\"}"),
            ] {
                try await client.execute(
                    uri: uri,
                    method: method,
                    headers: [.contentType: "application/json", .authorization: "Bearer \(token)"],
                    body: ByteBuffer(string: payload)
                ) { response in
                    XCTAssertNotEqual(response.status, .ok, "for \(uri)")
                }
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.server.listAppPasswords",
                method: .get,
                headers: [.authorization: "Bearer \(token)"]
            ) { response in
                XCTAssertNotEqual(response.status, .ok)
            }
        }
    }

    // MARK: - The fence still holds

    /// The four exact routes must coexist with the `com.atproto.server.*` guard
    /// without weakening it. Exact paths outrank a `<prefix>.*` guard in
    /// Hummingbird's trie regardless of registration order.
    func testEveryOtherServerMethodStill404s() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        try await app(fixture).test(.router) { client in
            for nsid in [
                "com.atproto.server.createAccount",
                "com.atproto.server.resetPassword",
                "com.atproto.server.requestPasswordReset",
            ] {
                try await client.execute(
                    uri: "/xrpc/\(nsid)",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: ByteBuffer(string: "{}")
                ) { response in
                    XCTAssertEqual(response.status, .notFound, "for \(nsid)")
                }
            }
        }
    }
}

private struct ServiceAuthCall: Sendable, Equatable {
    let issuer: String
    let audience: String
    let method: String
}

private actor TestServiceAuthIssuer: SwanProxyServiceTokenIssuing {
    private static let key = P256.Signing.PrivateKey()
    private var recordedCalls: [ServiceAuthCall] = []

    func issueProxyServiceToken(issuer: String, audience: String, method: String, now: Date) async throws -> String {
        recordedCalls.append(.init(issuer: issuer, audience: audience, method: method))
        return try ProxyServiceJWT.create(
            issuer: issuer,
            audience: audience,
            method: method,
            eventID: UUID().uuidString,
            key: Self.key,
            now: now
        )
    }

    func calls() -> [ServiceAuthCall] { recordedCalls }
}
