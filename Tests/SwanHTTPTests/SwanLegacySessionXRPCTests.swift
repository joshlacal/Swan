import Foundation
import HTTPTypes
import Hummingbird
import HummingbirdTesting
import Logging
import NIOCore
import Petrel
@testable import SwanAccounts
@testable import SwanCore
@testable import SwanHTTP
import SwanOAuth
import SwanSpaces
import SwanSQLite
import SwanStorage
import XCTest

final class SwanLegacySessionXRPCTests: XCTestCase {
    private func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private struct Fixture {
        let root: URL
        let database: SQLiteControlDatabase
        let credentials: AppPasswordCredentials
        let server: SwanHTTPServer
    }

    private func makeFixture(
        enableLegacy: Bool = true,
        enableActorPreferences: Bool = false,
        loginClientIdentityPolicy: SwanLoginClientIdentityPolicy = .direct
    ) async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanLegacySessionXRPCTests-\(UUID().uuidString)")
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let passwordHasher = try LibsodiumArgon2idHasher()
        _ = try await database.createAccount(try AccountControlRegistration(
            did: "did:plc:abcdefghijklmnopqrstuvwx",
            canonicalHandle: "alice.example.com",
            passwordVerifier: try passwordHasher.hash("password"),
            signingKey: try AccountControlKeyReference(
                purpose: .signing,
                generation: 1
            ),
            rotationKey: try AccountControlKeyReference(
                purpose: .rotation,
                generation: 1
            )
        ))
        let credentials = try AppPasswordCredentials()
        let factorTokens = FactorTokenService(store: database)
        let accounts = DurableAccountDirectory(
            store: database,
            passwordHasher: passwordHasher,
            verificationExecutor: try Argon2idVerificationExecutor(hasher: passwordHasher),
            loginAdmissionService: AccountLoginAdmissionService(
                store: database,
                key: try AccountLoginAdmissionKey(Data(repeating: 0x88, count: 32))
            ),
            loginFactorTokenVerifier: factorTokens,
            authenticationFactors: database
        )
        let legacySessionXRPC: SwanLegacySessionXRPCServer?
        if enableLegacy {
            legacySessionXRPC = SwanLegacySessionXRPCServer(
                sessions: try DurableLegacySessionService(
                    store: database,
                    appPasswords: database,
                    accountControlStore: database,
                    credentials: credentials,
                    serviceDID: SwanServiceIdentity(publicURL: URL(string: "https://pds.swan.example")!).did,
                    serverKey: Data(repeating: 0x6E, count: 32)
                ),
                credentials: credentials,
                appPasswords: database,
                accounts: accounts,
                directory: SwanDurableLegacySessionDirectory(store: database),
                loginClientIdentityPolicy: loginClientIdentityPolicy,
                minimumFailedLoginDuration: .milliseconds(1)
            )
        } else {
            legacySessionXRPC = nil
        }

        let actorPreferencesXRPC: SwanActorPreferencesXRPCServer?
        if enableActorPreferences {
            actorPreferencesXRPC = SwanActorPreferencesXRPCServer(
                authorizer: DummyActorPreferencesAuthorizer(),
                store: database
            )
        } else {
            actorPreferencesXRPC = nil
        }

        let profile = try ProtocolProfile.load(
            from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-08-15.json")
        )
        let server = SwanHTTPServer(
            profile: profile,
            configuration: .init(
                host: "127.0.0.1",
                port: 3000,
                publicURL: URL(string: "https://pds.swan.example")!
            ),
            oauthRuntime: try SwanOAuthRuntime(
                controlStore: database,
                serverKey: Data(repeating: 0x71, count: 32)
            ),
            legacySessionXRPC: legacySessionXRPC,
            actorPreferencesXRPC: actorPreferencesXRPC,
            loginClientIdentityPolicy: loginClientIdentityPolicy
        )
        return Fixture(root: root, database: database, credentials: credentials, server: server)
    }

    private func cleanup(_ fixture: Fixture) async {
        try? await fixture.database.close()
        try? FileManager.default.removeItem(at: fixture.root)
    }

    func testAppPasswordMethodsFailClosedWhenLegacySessionsEnabled() async throws {
        let fixture = try await makeFixture(enableLegacy: true)
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanLegacySessionXRPCTests.failClosed")
            )
            try await app.test(.router) { client in
                let targets: [(path: String, methods: [HTTPRequest.Method])] = [
                    (
                        "/xrpc/com.atproto.server.createAppPassword",
                        [.post, .get, .put, .delete, .head, .patch, .options]
                    ),
                    (
                        "/xrpc/com.atproto.server.listAppPasswords",
                        [.get, .post, .put, .delete, .head, .patch, .options]
                    ),
                    (
                        "/xrpc/com.atproto.server.revokeAppPassword",
                        [.post, .get, .put, .delete, .head, .patch, .options]
                    ),
                ]

                for target in targets {
                    for method in target.methods {
                        // Test with no auth, with bearer, with invalid payload, with atproto-proxy header
                        var headers = HTTPFields()
                        headers[.contentType] = "application/json"
                        headers[HTTPField.Name("atproto-proxy")!] = "did:web:attacker.example#svc"
                        headers[.authorization] = "Bearer some-token"

                        try await client.execute(
                            uri: target.path,
                            method: method,
                            headers: headers,
                            body: ByteBuffer(string: #"{"name":"test"}"#)
                        ) { response in
                            XCTAssertEqual(
                                response.status,
                                .forbidden,
                                "\(method.rawValue) \(target.path) must return 403"
                            )
                            XCTAssertEqual(response.headers[.cacheControl], "no-store")
                            let bodyData = Data(buffer: response.body)
                            let json = try? JSONSerialization.jsonObject(with: bodyData) as? [String: Any]
                            XCTAssertEqual(
                                json?["error"] as? String,
                                "request_not_allowed",
                                "\(method.rawValue) \(target.path) error must be request_not_allowed"
                            )
                        }
                    }
                }
            }
            await cleanup(fixture)
        } catch {
            await cleanup(fixture)
            throw error
        }
    }

    func testAppPasswordMethods404WhenLegacySessionsDisabled() async throws {
        let fixture = try await makeFixture(enableLegacy: false)
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanLegacySessionXRPCTests.disabled404")
            )
            try await app.test(.router) { client in
                for path in [
                    "/xrpc/com.atproto.server.createAppPassword",
                    "/xrpc/com.atproto.server.listAppPasswords",
                    "/xrpc/com.atproto.server.revokeAppPassword",
                ] {
                    try await client.execute(
                        uri: path,
                        method: .post,
                        headers: [.contentType: "application/json"],
                        body: ByteBuffer(string: #"{"name":"test"}"#)
                    ) { response in
                        XCTAssertEqual(response.status, .notFound, "POST \(path) must 404 when legacy sessions disabled")
                    }
                    try await client.execute(
                        uri: path,
                        method: .get
                    ) { response in
                        XCTAssertEqual(response.status, .notFound, "GET \(path) must 404 when legacy sessions disabled")
                    }
                }
            }
            await cleanup(fixture)
        } catch {
            await cleanup(fixture)
            throw error
        }
    }

    func testCommunityServiceDescribeIncludesEnabledLegacySessionMethodsAndExcludesAppPasswords() async throws {
        let fixture = try await makeFixture(enableLegacy: true, enableActorPreferences: false)
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanLegacySessionXRPCTests.describeLegacy")
            )
            try await app.test(.router) { client in
                try await client.execute(
                    uri: "/xrpc/community.lexicon.service.describe",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let object = try XCTUnwrap(
                        JSONSerialization.jsonObject(with: Data(buffer: response.body)) as? [String: Any]
                    )
                    let methods = try XCTUnwrap(object["methods"] as? [[String: Any]])
                    let values = Set(methods.compactMap { $0["value"] as? String })

                    // Enabled legacy-session methods MUST be present
                    XCTAssertTrue(values.contains("com.atproto.server.createSession"))
                    XCTAssertTrue(values.contains("com.atproto.server.refreshSession"))
                    XCTAssertTrue(values.contains("com.atproto.server.getSession"))
                    XCTAssertTrue(values.contains("com.atproto.server.deleteSession"))
                    XCTAssertTrue(values.contains("com.atproto.server.getServiceAuth"))

                    // App-password methods MUST NOT be present
                    XCTAssertFalse(values.contains("com.atproto.server.createAppPassword"))
                    XCTAssertFalse(values.contains("com.atproto.server.listAppPasswords"))
                    XCTAssertFalse(values.contains("com.atproto.server.revokeAppPassword"))

                    // Actor preferences disabled -> not present
                    XCTAssertFalse(values.contains("app.bsky.actor.getPreferences"))
                    XCTAssertFalse(values.contains("app.bsky.actor.putPreferences"))
                }
            }
            await cleanup(fixture)
        } catch {
            await cleanup(fixture)
            throw error
        }
    }

    func testCommunityServiceDescribeIncludesActorPreferencesWhenEnabled() async throws {
        let fixture = try await makeFixture(enableLegacy: false, enableActorPreferences: true)
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "SwanLegacySessionXRPCTests.describeActorPrefs")
            )
            try await app.test(.router) { client in
                try await client.execute(
                    uri: "/xrpc/community.lexicon.service.describe",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let object = try XCTUnwrap(
                        JSONSerialization.jsonObject(with: Data(buffer: response.body)) as? [String: Any]
                    )
                    let methods = try XCTUnwrap(object["methods"] as? [[String: Any]])
                    let values = Set(methods.compactMap { $0["value"] as? String })

                    // Actor preferences enabled -> present
                    XCTAssertTrue(values.contains("app.bsky.actor.getPreferences"))
                    XCTAssertTrue(values.contains("app.bsky.actor.putPreferences"))

                    // Legacy session disabled -> not present
                    XCTAssertFalse(values.contains("com.atproto.server.createSession"))
                    XCTAssertFalse(values.contains("com.atproto.server.createAppPassword"))
                }
            }
            await cleanup(fixture)
        } catch {
            await cleanup(fixture)
            throw error
        }
    }
    func testLegacySessionLoginClientIdentityPolicyAndTrustedProxy() async throws {
        let trustedPolicy = try SwanLoginClientIdentityPolicy(trustedProxyPeerLiterals: ["127.0.0.1", "::1"])
        let fixture = try await makeFixture(loginClientIdentityPolicy: trustedPolicy)
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let app = fixture.server.buildApplication(logger: Logger(label: "test"))
        let password = try await fixture.credentials.issue(
            did: "did:plc:abcdefghijklmnopqrstuvwx",
            name: "test-app",
            scopes: "atproto",
            into: fixture.database
        ).password
        try await app.test(.live) { client in
            // 1. Trusted proxy forwards valid client IP
            try await client.execute(
                uri: "/xrpc/\(ComAtprotoServerCreateSession.typeIdentifier)",
                method: .post,
                headers: [
                    .contentType: "application/json",
                    HTTPField.Name("X-Swan-Client-IP")!: "203.0.113.195",
                ],
                body: ByteBuffer(string: "{\"identifier\":\"alice.example.com\",\"password\":\"\(password)\"}")
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }

            // 2. Malformed forwarded header fails closed with 503
            try await client.execute(
                uri: "/xrpc/\(ComAtprotoServerCreateSession.typeIdentifier)",
                method: .post,
                headers: [
                    .contentType: "application/json",
                    HTTPField.Name("X-Swan-Client-IP")!: "invalid,ip,header",
                ],
                body: ByteBuffer(string: "{\"identifier\":\"alice.example.com\",\"password\":\"\(password)\"}")
            ) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
            }
        }

        // Router tests have no socket peer; forwarding must not be trusted.
        try await app.test(.router) { client in
            try await client.execute(
                uri: "/xrpc/\(ComAtprotoServerCreateSession.typeIdentifier)",
                method: .post,
                headers: [
                    .contentType: "application/json",
                    HTTPField.Name("X-Swan-Client-IP")!: "203.0.113.195",
                ],
                body: ByteBuffer(string: "{\"identifier\":\"alice.example.com\",\"password\":\"\(password)\"}")
            ) { response in
                XCTAssertEqual(response.status, .serviceUnavailable)
            }
        }
    }
}

private actor DummyActorPreferencesAuthorizer: SwanActorPreferencesResourceAuthorizing {
    func authorizeActorPreferences(
        request: Request,
        method: String,
        fixedPath: String,
        now: Date
    ) async throws -> AuthorizationContext {
        throw SwanResourceAuthorizationFailure.denied
    }

    func issueActorPreferencesNonce(now: Date) async -> String {
        "test-nonce"
    }
}
