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
    private let verifier =
        "$argon2id$v=19$m=65536,t=2,p=1$initialsalt$initial-precomputed-verifier"

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
        let router: Router<SwanHTTPRequestContext>
    }

    private func makeFixture(
        rateLimiter: any SwanLegacySessionRateLimiting = AlwaysAdmits()
    ) async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "LegacySessionHTTPTests-" + UUID().uuidString)
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await database.createAccount(
            try AccountControlRegistration(
                did: did,
                canonicalHandle: handle,
                passwordVerifier: verifier,
                signingKey: try .init(purpose: .signing, generation: 1),
                rotationKey: try .init(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )
        let credentials = try AppPasswordCredentials()
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
            directory: SwanDurableLegacySessionDirectory(store: database),
            rateLimiter: rateLimiter,
            requestBodyAdmission: .init(
                admission: .processShared,
                policy: .productionDefault
            ),
            // These tests assert behaviour, not timing. The production floor is
            // 350ms and would add seconds across the suite.
            minimumFailedLoginDuration: .milliseconds(1)
        ).register(on: router)
        // The fence these routes must coexist with, registered exactly as the
        // production assembly does.
        registerUnknownPublicEndpointGuards(on: router)
        return Fixture(root: root, database: database, credentials: credentials, router: router)
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
                "com.atproto.server.getServiceAuth",
                "com.atproto.server.createAppPassword",
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
