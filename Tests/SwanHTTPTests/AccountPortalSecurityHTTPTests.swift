import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
@testable import SwanAccounts
@testable import SwanHTTP
import SwanStorage
import XCTest

final class AccountPortalSecurityHTTPTests: XCTestCase, @unchecked Sendable {
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

    private func makePortalRouter(policy: SignupPolicy = .closed) throws -> Router<SwanHTTPRequestContext> {
        let router = Router(context: SwanHTTPRequestContext.self)
        let sessions = SwanManagementSessionRuntime(
            store: PortalMemorySessionStore(),
            preAuthStore: SwanInMemoryManagementPreAuthStore(),
            csrfStore: SwanInMemoryManagementCSRFStore()
        )
        let service = PortalMemoryService()
        let buildDirectory = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "web/build")
        let configuration = try SwanAccountPortalConfiguration(
            publicOrigin: URL(string: "https://accounts.example")!,
            staticDirectory: buildDirectory,
            signupPolicy: policy
        )
        SwanAccountPortalHTTP(configuration: configuration, sessions: sessions, service: service).register(on: router)
        return router
    }
}

private actor PortalMemorySessionStore: ManagementSessionStore {
    private var values: [Data: ManagementSessionMetadata] = [:]
    func createManagementSession(_ session: ManagementSessionMetadata, sessionDigest: Data, csrfDigest _: Data, now _: Date) async throws { values[sessionDigest] = session }
    func managementSession(digest: Data, now _: Date) async throws -> ManagementSessionMetadata? { values[digest] }
    func revokeManagementSession(digest: Data, now _: Date) async throws { values.removeValue(forKey: digest) }
    func revokeOtherManagementSessions(accountDID: String, except sessionID: ManagementSessionID, now _: Date) async throws { values = values.filter { $0.value.accountDID != accountDID || $0.value.sessionID == sessionID } }
    func purgeExpiredManagementSessions(now _: Date) async throws {}
}

private struct PortalMemoryService: SwanAccountPortalServing {
    func bootstrap(now _: Date) async throws -> SwanAccountPortalBootstrap { SwanAccountPortalBootstrap(csrf: "csrf") }
    func authenticate(handle _: String, password _: String, authFactorToken _: String?, now _: Date) async throws -> SwanAccountPortalAuthentication { throw SwanManagementSessionError.unauthorized }
    func portal(accountDID: String, now _: Date) async throws -> SwanAccountPortalSnapshot {
        .init(account: .init(did: accountDID, handle: "alice.example", email: nil, lifecycle: "active"), identity: nil, strength: "password", factors: [], sessions: [], apps: [], passwords: [])
    }
    func mutate(path _: String, context _: SwanAccountPortalMutationContext, payload _: Data?, now _: Date) async throws -> SwanAccountPortalMutation { .init() }
}
