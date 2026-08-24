import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import PetrelCrypto
@testable import SwanAccounts
import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class AccountPortalSecurityHTTPTests: XCTestCase, @unchecked Sendable {
    func testProductionPortalFacadeRejectsUnknownAccountWithStableTypedError() async throws {
        let service = SwanAccountPortalService(
            accountDirectory: RejectingAccountDirectory(),
            sessions: SwanManagementSessionRuntime(
                store: PortalMemorySessionStore(),
                preAuthStore: SwanInMemoryManagementPreAuthStore(),
                csrfStore: SwanInMemoryManagementCSRFStore()
            )
        )

        do {
            _ = try await service.portal(accountDID: "did:plc:unknown", now: Date())
            XCTFail("unknown accounts must not produce a portal snapshot")
        } catch let error as SwanAccountPortalServiceError {
            XCTAssertEqual(error, .notFound)
        }
    }

    func testAppPasswordPostRequiresVerifiedStepUpReturnsSecretOnceAndNeverListsIt() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "AccountPortalSecurityHTTPTests-app-password-\(UUID().uuidString)")
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let handle = "portal.example.com"
        // The SQLite portal store persists timestamps at microsecond
        // precision; keep the fixture on that same stable boundary so the
        // returned step-up strength compares equal after a read-back.
        let now = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        _ = try await database.createAccount(
            try AccountControlRegistration(
                did: did,
                canonicalHandle: handle,
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$initialsalt$initial-precomputed-verifier",
                signingKey: try .init(purpose: .signing, generation: 1),
                rotationKey: try .init(purpose: .rotation, generation: 1),
                createdAt: now.addingTimeInterval(-100)
            )
        )
        let sessions = SwanManagementSessionRuntime(
            store: database,
            preAuthStore: database,
            csrfStore: database,
            preAuthSessionCoordinator: database
        )
        let issued = try await sessions.issue(
            accountDID: did,
            strength: .stepUpPassword(verifiedAt: now),
            now: now
        )
        let storedAccount = try await database.account(did: did)
        let account = try XCTUnwrap(storedAccount)
        let csrfAccepted = try await sessions.acceptsCSRF(sessionValue: issued.sessionValue, csrfValue: issued.csrfValue, now: now)
        XCTAssertTrue(csrfAccepted)
        try await insertStepUpReceipt(
            database,
            sessionID: issued.metadata.sessionID.rawValue,
            accountDID: did,
            operation: SwanAccountPortalStepUpOperation.createAppPassword.rawValue,
            receipt: "direct-receipt",
            now: now
        )
        try await insertStepUpReceipt(
            database,
            sessionID: issued.metadata.sessionID.rawValue,
            accountDID: did,
            operation: SwanAccountPortalStepUpOperation.createAppPassword.rawValue,
            receipt: "receipt-once",
            now: now
        )
        let durableVerifier = SwanAccountPortalDurableStepUpReceiptVerifier(verifier: database)
        let durableConsumer = SwanAccountPortalDurableStepUpReceiptConsumer(store: database)
        let service = SwanAccountPortalService(
            accountDirectory: FixedPortalAccountDirectory(account: account),
            appPasswords: database,
            appPasswordCredentials: try AppPasswordCredentials(policy: .interactive),
            stepUpReceiptVerifier: durableVerifier,
            stepUpReceiptConsumer: durableConsumer,
            sessions: sessions
        )
        let directService = SwanAccountPortalService(
            accountDirectory: FixedPortalAccountDirectory(account: account),
            appPasswords: database,
            appPasswordCredentials: try AppPasswordCredentials(policy: .interactive),
            stepUpReceiptVerifier: durableVerifier,
            stepUpReceiptConsumer: durableConsumer,
            sessions: sessions
        )
        let direct = try await directService.mutate(
            path: "app-passwords",
            context: .init(
                sessionID: issued.sessionValue,
                accountDID: did,
                strength: issued.metadata.strength,
                stepUpToken: "direct-receipt"
            ),
            payload: Data("{\"name\":\"direct\",\"scopes\":[\"atproto\"]}".utf8),
            now: now
        )
        XCTAssertFalse(try XCTUnwrap(direct.password).isEmpty)
        let configuration = try SwanAccountPortalConfiguration(
            publicOrigin: URL(string: "https://accounts.example")!,
            staticDirectory: packageRoot().appending(path: "web/build")
        )
        let router = Router(context: SwanHTTPRequestContext.self)
        SwanAccountPortalHTTP(configuration: configuration, sessions: sessions, service: service)
            .register(on: router)
        let application = Application(
            router: router,
            configuration: .init(address: .hostname("127.0.0.1", port: 0), serverName: "portal-app-password"),
            logger: Logger(label: "portal-app-password")
        )
        var mutableHeaders: HTTPFields = [
            .contentType: "application/json",
            HTTPField.Name("Origin")!: "https://accounts.example",
            HTTPField.Name("Sec-Fetch-Site")!: "same-origin",
            HTTPField.Name("X-Swan-CSRF")!: issued.csrfValue,
            HTTPField.Name("X-Swan-Step-Up")!: "receipt-once"
        ]
        mutableHeaders[.cookie] = "__Secure-swan_management=\(issued.sessionValue); swan_csrf=\(issued.csrfValue)"
        let headers = mutableHeaders
        XCTAssertEqual(headers[.cookie], "__Secure-swan_management=\(issued.sessionValue); swan_csrf=\(issued.csrfValue)")
        _ = try await sessions.authenticate(sessionValue: issued.sessionValue, now: now)

        try await application.test(.router) { client in
            var secret = ""
            try await client.execute(
                uri: "/account/api/app-passwords",
                method: .post,
                headers: headers,
                body: ByteBuffer(string: "{\"name\":\"browser\",\"scopes\":[\"atproto\"]}")
            ) { response in
                guard response.status == .ok else {
                    XCTFail(String(decoding: response.body.readableBytesView, as: UTF8.self))
                    return
                }
                guard let payload = try? JSONSerialization.jsonObject(
                    with: Data(response.body.readableBytesView)
                ) as? [String: Any],
                let value = payload["password"] as? String else {
                    XCTFail("creation response must carry the generated password")
                    return
                }
                secret = value
                XCTAssertFalse(secret.isEmpty)
            }

            try await client.execute(
                uri: "/account/api/portal",
                method: .get,
                headers: [.cookie: headers[.cookie]!]
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertFalse(String(decoding: response.body.readableBytesView, as: UTF8.self).contains(secret))
            }

            // The receipt is one-time at the verifier seam. A replay cannot
            // create a second credential, even though the session remains live.
            try await client.execute(
                uri: "/account/api/app-passwords",
                method: .post,
                headers: headers,
                body: ByteBuffer(string: "{\"name\":\"replay\",\"scopes\":[\"atproto\"]}")
            ) { response in
                XCTAssertEqual(response.status, .forbidden)
            }
        }
        let consumed = try await database.connection.query(
            "SELECT consumed_at FROM did_web_step_up_receipts WHERE session_id = ? AND operation = ? ORDER BY receipt_digest",
            [.text(issued.metadata.sessionID.rawValue), .text(SwanAccountPortalStepUpOperation.createAppPassword.rawValue)]
        )
        XCTAssertEqual(consumed.count, 2)
        XCTAssertEqual(consumed.compactMap { $0.column("consumed_at")?.integer }.count, 2)
    }

    func testSQLitePortalStepUpReceiptIsSingleUseUnderConcurrentCreation() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "AccountPortalSecurityHTTPTests-concurrent-" + UUID().uuidString)
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let now = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        _ = try await database.createAccount(
            try AccountControlRegistration(
                did: did,
                canonicalHandle: "concurrent.example.com",
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: try .init(purpose: .signing, generation: 1),
                rotationKey: try .init(purpose: .rotation, generation: 1),
                createdAt: now.addingTimeInterval(-100)
            )
        )
        let sessions = SwanManagementSessionRuntime(
            store: database,
            preAuthStore: database,
            csrfStore: database,
            preAuthSessionCoordinator: database
        )
        let issued = try await sessions.issue(
            accountDID: did,
            strength: .stepUpPassword(verifiedAt: now),
            now: now
        )
        try await insertStepUpReceipt(
            database,
            sessionID: issued.metadata.sessionID.rawValue,
            accountDID: did,
            operation: SwanAccountPortalStepUpOperation.createAppPassword.rawValue,
            receipt: "concurrent-receipt",
            now: now
        )
        let storedAccount = try await database.account(did: did)
        let account = try XCTUnwrap(storedAccount)
        let service = SwanAccountPortalService(
            accountDirectory: FixedPortalAccountDirectory(account: account),
            appPasswords: database,
            appPasswordCredentials: try AppPasswordCredentials(policy: .interactive),
            stepUpReceiptConsumer: SwanAccountPortalDurableStepUpReceiptConsumer(store: database),
            sessions: sessions
        )
        let context = SwanAccountPortalMutationContext(
            sessionID: issued.sessionValue,
            accountDID: did,
            strength: issued.metadata.strength,
            stepUpToken: "concurrent-receipt"
        )
        let successes = await withTaskGroup(of: Bool.self, returning: [Bool].self) { group in
            for name in ["concurrent-a", "concurrent-b"] {
                group.addTask {
                    do {
                        _ = try await service.mutate(
                            path: "app-passwords",
                            context: context,
                            payload: Data(("{\"name\":\"" + name + "\",\"scopes\":[\"atproto\"]}").utf8),
                            now: now
                        )
                        return true
                    } catch {
                        return false
                    }
                }
            }
            var values: [Bool] = []
            for await value in group { values.append(value) }
            return values
        }
        XCTAssertEqual(successes.filter { $0 }.count, 1)
        let created = try await database.listAppPasswords(did: did)
        XCTAssertEqual(created.count, 1)
    }

    func testSQLitePortalStepUpReceiptBindsRevocationOperationAndIsConsumed() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "AccountPortalSecurityHTTPTests-revoke-" + UUID().uuidString)
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let now = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        _ = try await database.createAccount(
            try AccountControlRegistration(
                did: did,
                canonicalHandle: "revoke.example.com",
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: try .init(purpose: .signing, generation: 1),
                rotationKey: try .init(purpose: .rotation, generation: 1),
                createdAt: now.addingTimeInterval(-100)
            )
        )
        let credentials = try AppPasswordCredentials(policy: .interactive)
        _ = try await credentials.issue(
            did: did,
            name: "revoke-me",
            scopes: "atproto",
            into: database,
            now: now
        )
        let sessions = SwanManagementSessionRuntime(
            store: database,
            preAuthStore: database,
            csrfStore: database,
            preAuthSessionCoordinator: database
        )
        let issued = try await sessions.issue(
            accountDID: did,
            strength: .stepUpPassword(verifiedAt: now),
            now: now
        )
        let wrongOperationReceipt = "wrong-operation-receipt"
        try await insertStepUpReceipt(
            database,
            sessionID: issued.metadata.sessionID.rawValue,
            accountDID: did,
            operation: SwanAccountPortalStepUpOperation.createAppPassword.rawValue,
            receipt: wrongOperationReceipt,
            now: now
        )
        let storedAccount = try await database.account(did: did)
        let account = try XCTUnwrap(storedAccount)
        let service = SwanAccountPortalService(
            accountDirectory: FixedPortalAccountDirectory(account: account),
            appPasswords: database,
            stepUpReceiptConsumer: SwanAccountPortalDurableStepUpReceiptConsumer(store: database),
            sessions: sessions
        )
        let wrongContext = SwanAccountPortalMutationContext(
            sessionID: issued.sessionValue,
            accountDID: did,
            strength: issued.metadata.strength,
            stepUpToken: wrongOperationReceipt
        )
        do {
            _ = try await service.mutate(
                path: "app-passwords/revoke-me",
                context: wrongContext,
                payload: nil,
                now: now
            )
            XCTFail("a create receipt must not authorize revocation")
        } catch let error as SwanAccountPortalServiceError {
            XCTAssertEqual(error, .forbidden)
        }
        let wrongRows = try await database.connection.query(
            "SELECT consumed_at FROM did_web_step_up_receipts WHERE receipt_digest = ?",
            [.blob(ByteBuffer(data: Data(SHA256.hash(data: Data(wrongOperationReceipt.utf8)))))]
        )
        guard let wrongConsumed = wrongRows.first?.column("consumed_at"), case .null = wrongConsumed else {
            XCTFail("an operation-mismatched receipt must remain unconsumed")
            return
        }

        let revokeReceipt = "revoke-receipt"
        try await insertStepUpReceipt(
            database,
            sessionID: issued.metadata.sessionID.rawValue,
            accountDID: did,
            operation: SwanAccountPortalStepUpOperation.revokeAppPassword.rawValue,
            receipt: revokeReceipt,
            now: now
        )
        let revokeContext = SwanAccountPortalMutationContext(
            sessionID: issued.sessionValue,
            accountDID: did,
            strength: issued.metadata.strength,
            stepUpToken: revokeReceipt
        )
        _ = try await service.mutate(path: "app-passwords/revoke-me", context: revokeContext, payload: nil, now: now)
        let remaining = try await database.listAppPasswords(did: did)
        XCTAssertTrue(remaining.isEmpty)
        do {
            _ = try await service.mutate(path: "app-passwords/revoke-me", context: revokeContext, payload: nil, now: now)
            XCTFail("a consumed revocation receipt must not be replayable")
        } catch let error as SwanAccountPortalServiceError {
            XCTAssertEqual(error, .forbidden)
        }
    }

    func testProductionFacadeUsesConfiguredStaticDirectoryWithDurableSessions() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "AccountPortalSecurityHTTPTests-static-\(UUID().uuidString)")
        let staticDirectory = root.appending(path: "account")
        try FileManager.default.createDirectory(at: staticDirectory, withIntermediateDirectories: true)
        try Data("<!doctype html><title>production portal</title>".utf8).write(to: staticDirectory.appending(path: "index.html"))
        defer { try? FileManager.default.removeItem(at: root) }

        let database = try await SQLiteControlDatabase(dataDirectory: root.appending(path: "data"))
        defer { Task { try? await database.close() } }
        try await database.migrateAccountPortalSessionSchema()
        let sessions = SwanManagementSessionRuntime(
            store: database,
            preAuthStore: database,
            csrfStore: database,
            preAuthSessionCoordinator: database
        )
        let service = SwanAccountPortalService(accountDirectory: RejectingAccountDirectory(), sessions: sessions)
        let configuration = try SwanAccountPortalConfiguration(
            publicOrigin: URL(string: "https://accounts.example")!,
            staticDirectory: staticDirectory
        )
        let router = Router(context: SwanHTTPRequestContext.self)
        SwanAccountPortalHTTP(configuration: configuration, sessions: sessions, service: service).register(on: router)
        let app = Application(
            router: router,
            configuration: .init(address: .hostname("127.0.0.1", port: 0), serverName: "portal-production-static"),
            logger: Logger(label: "portal-production-static")
        )
        try await app.test(.router) { client in
            try await client.execute(uri: "/account", method: .get) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(String(decoding: response.body.readableBytesView, as: UTF8.self), "<!doctype html><title>production portal</title>")
            }
        }
    }


    func testAccountAPIRoutesBeatRecursiveSPAAndExposeConfiguredPolicy() async throws {
        let router = try makePortalRouter(policy: .openProtected)
        let app = Application(
            router: router,
            configuration: .init(address: .hostname("127.0.0.1", port: 0), serverName: "portal-security-tests"),
            logger: Logger(label: "portal-security-tests")
        )
        try await app.test(.router) { client in
            try await client.execute(uri: "/account/api/unknown/deep", method: .get) { response in
                XCTAssertEqual(response.status, .notFound)
                XCTAssertEqual(response.headers[.contentType], "application/json")
            }
            try await client.execute(uri: "/account/api/signup/policy", method: .get) { response in
                XCTAssertEqual(response.status, .ok)
                let body = try XCTUnwrap(String(data: Data(response.body.readableBytesView), encoding: .utf8))
                XCTAssertTrue(body.contains("openProtected"))
                XCTAssertTrue(body.contains("turnstileRequired"))
            }
            try await client.execute(uri: "/account", method: .get) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertTrue(response.headers[HTTPField.Name("Content-Security-Policy")!]?.contains("default-src 'none'") == true)
            }
        }
    }

    func testOriginCSRFAndCookieScopesFailClosed() async throws {
        let router = try makePortalRouter()
        router.get("/xrpc/test") { request, _ -> Response in
            Response(status: request.headers[HTTPField.Name("Cookie")!] == nil ? .ok : .ok)
        }
        let app = Application(
            router: router,
            configuration: .init(address: .hostname("127.0.0.1", port: 0), serverName: "portal-security-tests"),
            logger: Logger(label: "portal-security-tests")
        )
        try await app.test(.router) { client in
            try await client.execute(
                uri: "/account/api/login",
                method: .post,
                headers: [HTTPField.Name("Origin")!: "https://evil.example", .contentType: "application/json", HTTPField.Name("X-Swan-CSRF")!: "bad"],
                body: ByteBuffer(string: #"{"handle":"alice","password":"password"}"#)
            ) { response in
                XCTAssertEqual(response.status, .forbidden)
            }
            try await client.execute(
                uri: "/account/api/portal",
                method: .get,
                headers: [HTTPField.Name("Cookie")!: "__Secure-swan_management=not-a-valid-session"]
            ) { response in
                XCTAssertEqual(response.status, .unauthorized)
            }
            try await client.execute(
                uri: "/xrpc/test",
                method: .get,
                headers: [HTTPField.Name("Cookie")!: "__Secure-swan_management=not-a-valid-session"]
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
    }

    // MARK: - Production construction path (Task 1)

    /// The portal installed through the production `SwanHTTPServer` hook —
    /// the type `swan serve` builds — must serve the compiled bundle without
    /// shadowing the portal's own API routes, `/xrpc/*`, health, discovery,
    /// or OAuth.
    func testPortalComposesIntoProductionServerWithoutShadowingRoutes() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "AccountPortalSecurityHTTPTests-production-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x5C, count: 32)
            )
            let profile = try ProtocolProfile.load(
                from: packageRoot().appending(
                    path: "Profiles/permissioned-data-0016-2026-07-30.json"
                )
            )
            let portal = try makePortal(policy: .openProtected)
            let server = SwanHTTPServer(
                profile: profile,
                configuration: .init(
                    host: "127.0.0.1",
                    port: 3_000,
                    publicURL: URL(string: "https://swan.example")!
                ),
                oauthRuntime: runtime,
                accountPortalHTTP: portal
            )
            let app = server.buildApplication(
                logger: Logger(label: "AccountPortalSecurityHTTPTests.production")
            )
            try await app.test(.router) { client in
                // The compiled bundle is served at /account/ and /account.
                for uri in ["/account/", "/account"] {
                    try await client.execute(uri: uri, method: .get) { response in
                        XCTAssertEqual(response.status, .ok, uri)
                        XCTAssertTrue(
                            response.headers[.contentType]?.hasPrefix("text/html") == true,
                            uri
                        )
                    }
                }
                // The portal's API routes beat the SPA fallback.
                try await client.execute(uri: "/account/api/bootstrap", method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.headers[.contentType], "application/json")
                }
                try await client.execute(uri: "/account/api/unknown/deep", method: .get) { response in
                    XCTAssertEqual(response.status, .notFound)
                    XCTAssertEqual(response.headers[.contentType], "application/json")
                }
                // /xrpc/*, health, discovery, and OAuth are untouched.
                try await client.execute(uri: "/xrpc/com.atproto.server.describeServer", method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: "/health", method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: "/.well-known/did.json", method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                try await client.execute(uri: "/oauth/authorize", method: .get) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                }
            }
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    /// Configuration truth through the production path: the portal advertises
    /// the signup policy, and `describeServer.inviteCodeRequired` must be
    /// derived from that same policy. RED until the CLI derives the
    /// configuration value from policy (Task 2): today the server is built
    /// with the default `false` while the portal carries `.inviteRequired`.
    func testDescribeServerInviteCodeRequiredAgreesWithPortalPolicy() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "AccountPortalSecurityHTTPTests-invite-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x5C, count: 32)
            )
            let profile = try ProtocolProfile.load(
                from: packageRoot().appending(
                    path: "Profiles/permissioned-data-0016-2026-07-30.json"
                )
            )
            let policy = SignupPolicy.inviteRequired
            let portal = try makePortal(policy: policy)
            let server = SwanHTTPServer(
                profile: profile,
                configuration: .init(
                    host: "127.0.0.1",
                    port: 3_000,
                    publicURL: URL(string: "https://swan.example")!,
                    // Mirrors the CLI derivation (spec §4.1): the
                    // configuration value is derived from the same policy the
                    // portal advertises, never set independently.
                    inviteCodeRequired: policy == .inviteRequired
                ),
                oauthRuntime: runtime,
                accountPortalHTTP: portal
            )
            let app = server.buildApplication(
                logger: Logger(label: "AccountPortalSecurityHTTPTests.invite")
            )
            try await app.test(.router) { client in
                try await client.execute(uri: "/account/api/signup/policy", method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = try XCTUnwrap(String(data: Data(response.body.readableBytesView), encoding: .utf8))
                    XCTAssertTrue(body.contains("\"inviteCodeRequired\":true"))
                }
                try await client.execute(uri: "/xrpc/com.atproto.server.describeServer", method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = try XCTUnwrap(String(data: Data(response.body.readableBytesView), encoding: .utf8))
                    XCTAssertTrue(
                        body.contains("\"inviteCodeRequired\":\(policy.advertisesInviteCodeRequired)")
                    )
                }
            }
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    /// Credential isolation through the production path: with the portal and
    /// a permissive proxy fallback both installed, `createSession` and
    /// `createAccount` remain stable local refusals — the credentials never
    /// leave the host, even when the client names a destination.
    func testCredentialMethodsStayLocalRefusalsWithPortalAndProxyInstalled() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "AccountPortalSecurityHTTPTests-credentials-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x5C, count: 32)
            )
            let profile = try ProtocolProfile.load(
                from: packageRoot().appending(
                    path: "Profiles/permissioned-data-0016-2026-07-30.json"
                )
            )
            let portal = try makePortal(policy: .openProtected)
            let sender = RecordingProxySender()
            let pipethrough = SwanXRPCPipethroughServer(
                authorizer: PipethroughAuthorizer(
                    result: .success(
                        .accountOAuth(
                            subject: "did:plc:alice",
                            permissions: SwanScopePermissions(
                                rawScopes: ["atproto"],
                                subject: "did:plc:alice"
                            )
                        )
                    )
                ),
                tokens: TestProxyServiceTokenIssuer(),
                sender: sender,
                resolver: SwanServiceEndpointResolver(
                    documents: StubDIDDocuments(
                        documents: [
                            "did:web:attacker.example": Data(
                                """
                                {"id":"did:web:attacker.example","service":[
                                  {"id":"#svc","type":"AtprotoPersonalDataServer",
                                   "serviceEndpoint":"https://attacker.example"}]}
                                """.utf8
                            )
                        ]
                    )
                ),
                appView: try SwanAppViewConfiguration()
            )
            let server = SwanHTTPServer(
                profile: profile,
                configuration: .init(
                    host: "127.0.0.1",
                    port: 3_000,
                    publicURL: URL(string: "https://swan.example")!
                ),
                oauthRuntime: runtime,
                accountPortalHTTP: portal,
                xrpcPipethrough: pipethrough
            )
            let app = server.buildApplication(
                logger: Logger(label: "AccountPortalSecurityHTTPTests.credentials")
            )
            try await app.test(.router) { client in
                var steered = HTTPFields()
                steered[.contentType] = "application/json"
                steered[HTTPField.Name("atproto-proxy")!] = "did:web:attacker.example#svc"
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createSession",
                    method: .post,
                    headers: steered,
                    body: ByteBuffer(string: #"{"identifier":"alice.test","password":"hunter2"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                }
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createAccount",
                    method: .post,
                    headers: steered,
                    body: ByteBuffer(string: #"{"handle":"alice.test","email":"alice@example.com","password":"hunter2"}"#)
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
                }
            }
            XCTAssertEqual(sender.recorded().count, 0)
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    func testStaticAssetsServeMultiSegmentPathsAndSPAFallback() async throws {
        let portal = try makePortal()
        let router = Router(context: SwanHTTPRequestContext.self)
        portal.register(on: router)
        let app = Application(router: router)

        // Write a multi-segment nested asset to the portal directory
        let nestedDir = portal.configuration.staticDirectory.appending(path: "_app/immutable/entry")
        try FileManager.default.createDirectory(at: nestedDir, withIntermediateDirectories: true)
        try Data("console.log('start');".utf8).write(to: nestedDir.appending(path: "start.js"))

        try await app.test(.router) { client in
            // Multi-segment asset request
            try await client.execute(uri: "/account/_app/immutable/entry/start.js", method: .get) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(response.headers[.contentType], "text/javascript; charset=utf-8")
                XCTAssertEqual(response.headers[.cacheControl], "public, max-age=31536000, immutable")
            }

            // Extensionless SPA navigation request
            try await client.execute(uri: "/account/login", method: .get) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(response.headers[.contentType], "text/html; charset=utf-8")
                XCTAssertEqual(response.headers[.cacheControl], "no-cache")
            }

            // Missing asset with extension returns 404
            try await client.execute(uri: "/account/_app/immutable/entry/missing.js", method: .get) { response in
                XCTAssertEqual(response.status, .notFound)
            }
        }
    }

    private func makePortalRouter(policy: SignupPolicy = .closed) throws -> Router<SwanHTTPRequestContext> {
        let router = Router(context: SwanHTTPRequestContext.self)
        try makePortal(policy: policy).register(on: router)
        return router
    }

    private func makePortal(policy: SignupPolicy = .closed) throws -> SwanAccountPortalHTTP {
        let sessions = SwanManagementSessionRuntime(
            store: PortalMemorySessionStore(),
            preAuthStore: SwanInMemoryManagementPreAuthStore(),
            csrfStore: SwanInMemoryManagementCSRFStore()
        )
        let service = PortalMemoryService()
        let buildDirectory = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appending(path: "portal-assets-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: buildDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try Data("<!doctype html><title>Swan account</title>".utf8)
            .write(to: buildDirectory.appending(path: "index.html"))
        addTeardownBlock {
            try? FileManager.default.removeItem(at: buildDirectory)
        }
        let configuration = try SwanAccountPortalConfiguration(
            publicOrigin: URL(string: "https://accounts.example")!,
            staticDirectory: buildDirectory,
            signupPolicy: policy
        )
        return SwanAccountPortalHTTP(configuration: configuration, sessions: sessions, service: service)
    }

    private func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}
private struct RejectingAccountDirectory: SwanAccountPortalAccountDirectory {
    func account(did _: String) async throws -> AccountControlAccount? { nil }
    func resolve(handle _: String) async throws -> AccountControlAccount? { nil }
    func authenticateForLogin(handle _: String, password _: String, now _: Date) async throws -> AccountLoginAuthenticationOutcome { .rejected }
}

private func insertStepUpReceipt(
    _ database: SQLiteControlDatabase,
    sessionID: String,
    accountDID: String,
    operation: String,
    receipt: String,
    now: Date
) async throws {
    let digest = Data(SHA256.hash(data: Data(receipt.utf8)))
    let verifiedAt = Int(now.timeIntervalSince1970 * 1_000_000)
    _ = try await database.connection.query(
        """
        INSERT INTO did_web_step_up_receipts
            (receipt_digest, session_id, account_did, operation, mfa_strength, verified_at, expires_at, consumed_at)
        VALUES (?, ?, ?, ?, 'stepUpPassword', ?, ?, NULL)
        """,
        [
            .blob(ByteBuffer(data: digest)),
            .text(sessionID),
            .text(accountDID),
            .text(operation),
            .integer(verifiedAt),
            .integer(verifiedAt + 300_000_000),
        ]
    )
}

private struct FixedPortalAccountDirectory: SwanAccountPortalAccountDirectory {
    let account: AccountControlAccount

    func account(did: String) async throws -> AccountControlAccount? {
        account.did == did ? account : nil
    }

    func resolve(handle: String) async throws -> AccountControlAccount? {
        account.canonicalHandle == handle ? account : nil
    }

    func authenticateForLogin(handle: String, password: String, now: Date) async throws -> AccountLoginAuthenticationOutcome {
        .rejected
    }
}

private actor PortalMemorySessionStore: ManagementSessionStore {
    private var values: [Data: ManagementSessionMetadata] = [:]
    func createManagementSession(_ session: ManagementSessionMetadata, sessionDigest: Data, csrfDigest _: Data, now _: Date) async throws { values[sessionDigest] = session }
    func managementSession(digest: Data, now _: Date) async throws -> ManagementSessionMetadata? { values[digest] }
    func revokeManagementSession(digest: Data, now _: Date) async throws { values.removeValue(forKey: digest) }
    func revokeManagementSession(digest: Data, accountDID: String, now _: Date) async throws {
        guard let session = values[digest], session.accountDID == accountDID else { return }
        values.removeValue(forKey: digest)
    }
    func managementSessions(accountDID: String, now _: Date) async throws -> [ManagementSessionMetadata] {
        values.values.filter { $0.accountDID == accountDID }
    }
    func revokeOtherManagementSessions(accountDID: String, except sessionID: ManagementSessionID, now _: Date) async throws { values = values.filter { $0.value.accountDID != accountDID || $0.value.sessionID == sessionID } }
    func purgeExpiredManagementSessions(now _: Date) async throws {}
}

private struct PortalMemoryService: SwanAccountPortalServing {
    func bootstrap(now _: Date) async throws -> SwanAccountPortalBootstrap { SwanAccountPortalBootstrap(csrf: "csrf") }
    func authenticate(handle _: String, password _: String, authFactorToken _: String?, now _: Date) async throws -> SwanAccountPortalAuthentication { throw SwanManagementSessionError.unauthorized }
    func portal(accountDID: String, currentSessionID _: String?, now _: Date) async throws -> SwanAccountPortalSnapshot {
        .init(account: .init(did: accountDID, handle: "alice.example", email: nil, lifecycle: "active"), identity: nil, strength: "password", factors: [], sessions: [], apps: [], passwords: [])
    }
    func mutate(path _: String, context _: SwanAccountPortalMutationContext, payload _: Data?, now _: Date) async throws -> SwanAccountPortalMutation { .init() }
}

// MARK: - Proxy doubles (production-construction credential-isolation tests)

/// Admits every pipethrough request, so a fail-open route would really reach
/// the sender. The credential-isolation tests assert the sender is never
/// consulted despite this permissive authorizer.
///
/// Sibling copies: `Tests/SwanCLITests/SwanAccountProgramCompositionTests.swift`
/// and `Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift` declare the same
/// double. Cross-target sharing is impossible — each test target is a
/// separate module and cannot import another test target's internals — so
/// the copies are kept minimal and scoped to what each file needs.
private struct PipethroughAuthorizer: SwanXRPCPipethroughResourceAuthorizing {
    let result: Result<AuthorizationContext, SwanResourceAuthorizationFailure>

    init(result: Result<AuthorizationContext, SwanResourceAuthorizationFailure>) {
        self.result = result
    }

    func authorizePipethrough(
        request _: Request,
        method _: String,
        fixedPath _: String,
        now _: Date
    ) async throws -> AuthorizationContext {
        try result.get()
    }

    func issuePipethroughNonce(now _: Date) async -> String { "test-nonce" }
}

/// Mints a real `ProxyServiceJWT` from a per-process test key, so the proxy
/// path is exercised with actual signed claims rather than a placeholder.
///
/// Sibling copies: `Tests/SwanCLITests/SwanAccountProgramCompositionTests.swift`
/// and `Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift` declare the same
/// double. Cross-target sharing is impossible — each test target is a
/// separate module and cannot import another test target's internals — so
/// the copies are kept minimal and scoped to what each file needs.
private struct TestProxyServiceTokenIssuer: SwanProxyServiceTokenIssuing {
    static let key = P256.Signing.PrivateKey()

    func issueProxyServiceToken(
        issuer: String,
        audience: String,
        method: String,
        now: Date
    ) async throws -> String {
        try ProxyServiceJWT.create(
            issuer: issuer,
            audience: audience,
            method: method,
            eventID: UUID().uuidString,
            key: Self.key,
            now: now
        )
    }
}

/// Sibling copies: `Tests/SwanCLITests/SwanAccountProgramCompositionTests.swift`
/// and `Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift` declare the same
/// double. Cross-target sharing is impossible — each test target is a
/// separate module and cannot import another test target's internals — so
/// the copies are kept minimal and scoped to what each file needs.
private struct StubDIDDocuments: SwanDIDDocumentFetching {
    let documents: [String: Data]

    func documentJSON(forDID did: String) async throws -> Data {
        guard let data = documents[did] else {
            throw SwanError.unavailable("no stub DID document")
        }
        return data
    }
}

/// Records every outbound proxy request. The credential-isolation tests
/// assert `recorded().isEmpty` — nothing left the host.
///
/// Sibling copies: `Tests/SwanCLITests/SwanAccountProgramCompositionTests.swift`
/// and `Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift` declare the same
/// double. Cross-target sharing is impossible — each test target is a
/// separate module and cannot import another test target's internals — so
/// the copies are kept minimal and scoped to what each file needs.
private final class RecordingProxySender: SwanProxySending, @unchecked Sendable {
    private let lock = NSLock()
    private var requests: [SwanProxyRequest] = []
    private let result: Result<OAuthRemoteHTTPResponse, any Error>

    init(result: Result<OAuthRemoteHTTPResponse, any Error>? = nil) {
        self.result = result
            ?? .success(
                OAuthRemoteHTTPResponse(
                    status: 200,
                    headers: ["Content-Type": ["application/json"]],
                    body: Data(#"{"feed":[]}"#.utf8),
                    responseURL: URL(string: "https://api.bsky.app/xrpc/x")!
                )
            )
    }

    func send(
        _ request: SwanProxyRequest, timeout _: TimeInterval, maximumBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        record(request)
        return try result.get()
    }

    private func record(_ request: SwanProxyRequest) {
        lock.lock()
        defer { lock.unlock() }
        requests.append(request)
    }

    func recorded() -> [SwanProxyRequest] {
        lock.lock()
        defer { lock.unlock() }
        return requests
    }
}
