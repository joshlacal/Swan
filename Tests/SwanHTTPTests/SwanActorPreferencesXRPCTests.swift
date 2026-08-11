import Foundation
import HTTPTypes
import Hummingbird
import HummingbirdTesting
import Logging
import NIOCore
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanSQLite
import SwanStorage
import XCTest

@testable import SwanHTTP

final class SwanActorPreferencesXRPCTests: XCTestCase, @unchecked Sendable {
    private static let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let otherDID = "did:plc:bcdefghijklmnopqrstuvwxy"

    func testUnwrittenPreferencesReturnEmptyArray() async throws {
        try await withPreferencesStore { store in
            let app = self.makeApp(
                authorizer: PreferencesAuthorizer(
                    result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"]))
                ),
                store: store
            )
            try await app.test(.live) { client in
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.getPreferences",
                    method: .get
                ) { response in
                    // An account that has never called putPreferences must
                    // still resolve to an empty preferences array with 200 —
                    // never 404, which would make a client treat the account
                    // as broken.
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(
                        response.headers[.contentType],
                        "application/json"
                    )
                    XCTAssertEqual(
                        self.bodyString(response),
                        #"{"preferences":[]}"#
                    )
                }
            }
        }
    }

    func testRoundTripsWrittenPreferences() async throws {
        try await withPreferencesStore { store in
            let app = self.makeApp(
                authorizer: PreferencesAuthorizer(
                    result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"]))
                ),
                store: store
            )
            let written =
                #"{"preferences":[{"$type":"app.bsky.actor.defs#adultContentPref","enabled":true}]}"#
            try await app.test(.live) { client in
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.putPreferences",
                    method: .post,
                    headers: self.jsonHeaders(),
                    body: ByteBuffer(string: written)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.body.readableBytes, 0)
                }
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.getPreferences",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    // Exactly what was written, byte for byte.
                    XCTAssertEqual(self.bodyString(response), written)
                }
            }
        }
    }

    func testRejectsUnauthenticatedRequests() async throws {
        try await withPreferencesStore { store in
            let app = self.makeApp(
                authorizer: PreferencesAuthorizer(
                    result: .failure(.denied)
                ),
                store: store
            )
            try await app.test(.live) { client in
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.getPreferences",
                    method: .get
                ) { response in
                    self.assertError(response, status: .unauthorized, code: "Unauthorized")
                }
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.putPreferences",
                    method: .post,
                    headers: self.jsonHeaders(),
                    body: ByteBuffer(string: #"{"preferences":[]}"#)
                ) { response in
                    self.assertError(response, status: .unauthorized, code: "Unauthorized")
                }
            }
        }
    }

    func testOneAccountCannotReadAnothersPreferences() async throws {
        try await withPreferencesStore { store in
            let appA = self.makeApp(
                authorizer: PreferencesAuthorizer(
                    result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"]))
                ),
                store: store
            )
            let appB = self.makeApp(
                authorizer: PreferencesAuthorizer(
                    result: .success(.accountOAuth(subject: Self.otherDID, scopes: ["atproto"]))
                ),
                store: store
            )
            let secretToA =
                #"{"preferences":[{"$type":"app.bsky.actor.defs#personalDetailsPref","birthDate":"secret-to-a"}]}"#

            // Account A writes a distinguishing document.
            try await appA.test(.live) { client in
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.putPreferences",
                    method: .post,
                    headers: self.jsonHeaders(),
                    body: ByteBuffer(string: secretToA)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                }
            }

            // Account B, which never wrote anything, must observe an empty
            // array — never A's document. This is the security-critical
            // assertion: if storage were keyed by anything other than the
            // authenticated subject (e.g. a single global row, or a row
            // keyed off request data), B would see A's secret here.
            try await appB.test(.live) { client in
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.getPreferences",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let body = self.bodyString(response)
                    XCTAssertEqual(body, #"{"preferences":[]}"#)
                    XCTAssertFalse(body.contains("secret-to-a"))
                }
            }

            // Account B now writes its own, different document.
            let secretToB =
                #"{"preferences":[{"$type":"app.bsky.actor.defs#personalDetailsPref","birthDate":"secret-to-b"}]}"#
            try await appB.test(.live) { client in
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.putPreferences",
                    method: .post,
                    headers: self.jsonHeaders(),
                    body: ByteBuffer(string: secretToB)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                }
            }

            // Account A must still observe exactly its own original
            // document — never B's, and never a merge of the two.
            try await appA.test(.live) { client in
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.getPreferences",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(self.bodyString(response), secretToA)
                }
            }
        }
    }

    func testRejectsMalformedPreferencesBody() async throws {
        try await withPreferencesStore { store in
            let app = self.makeApp(
                authorizer: PreferencesAuthorizer(
                    result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"]))
                ),
                store: store
            )
            try await app.test(.live) { client in
                // Non-JSON body.
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.putPreferences",
                    method: .post,
                    headers: self.jsonHeaders(),
                    body: ByteBuffer(string: "this is not json")
                ) { response in
                    self.assertError(response, status: .badRequest, code: "InvalidRequest")
                }
                // Valid JSON, but "preferences" is not an array.
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.putPreferences",
                    method: .post,
                    headers: self.jsonHeaders(),
                    body: ByteBuffer(string: #"{"preferences":"not-an-array"}"#)
                ) { response in
                    self.assertError(response, status: .badRequest, code: "InvalidRequest")
                }
                // Nothing must have been persisted by either rejected write.
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.getPreferences",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(
                        self.bodyString(response),
                        #"{"preferences":[]}"#
                    )
                }
            }
        }
    }

    /// Regression guard for the routes being wired only into a standalone
    /// test router and never into `SwanHTTPServer`'s actual production
    /// composition. Unlike every other test in this file (which registers
    /// via `registerSwanActorPreferencesXRPC` directly against a bare
    /// `Router`), this builds a real `SwanHTTPServer` — the same type the
    /// CLI constructs for a deployed Swan — and asserts the route answers
    /// through `SwanHTTPServer.buildApplication(logger:)`. This mirrors
    /// `AccountEmailXRPCTests.testEmailRoutesComposeIntoTheMainServerBeforeApplicationConstruction`
    /// exactly, which is the established pattern for this exact regression
    /// class (a capability that exists but was never composed in).
    func testActorPreferencesRoutesComposeIntoTheMainServerBeforeApplicationConstruction() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanActorPreferencesMainServer-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x3D, count: 32)
            )
            let capability = SwanActorPreferencesXRPCServer(
                authorizer: PreferencesAuthorizer(
                    result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"]))
                ),
                store: control
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
                actorPreferencesXRPC: capability
            )
            let app = server.buildApplication(
                logger: Logger(label: "SwanActorPreferencesXRPCTests.main-server")
            )
            try await app.test(.live) { client in
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.getPreferences",
                    method: .get
                ) { response in
                    // If `SwanHTTPServer` never registered this capability,
                    // this falls through to the server's unknown-endpoint
                    // guard and comes back 404 instead of 200.
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(self.bodyString(response), #"{"preferences":[]}"#)
                }
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.putPreferences",
                    method: .post,
                    headers: self.jsonHeaders(),
                    body: ByteBuffer(string: #"{"preferences":[]}"#)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                }
            }
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    func testRejectsOversizedPreferencesBodyWith413() async throws {
        try await withPreferencesStore { store in
            let app = self.makeApp(
                authorizer: PreferencesAuthorizer(
                    result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"]))
                ),
                store: store
            )
            // One byte past the cap. The Content-Length check rejects this
            // before the body is ever read for JSON shape, so the content
            // does not need to be valid JSON.
            let oversized = String(
                repeating: "a",
                count: SwanActorPreferencesXRPC.maximumPreferencesJSONBytes + 1
            )
            try await app.test(.live) { client in
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.putPreferences",
                    method: .post,
                    headers: self.jsonHeaders(),
                    body: ByteBuffer(string: oversized)
                ) { response in
                    self.assertError(response, status: .contentTooLarge, code: "PayloadTooLarge")
                }
                // Nothing must have been persisted by the rejected write.
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.getPreferences",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(self.bodyString(response), #"{"preferences":[]}"#)
                }
            }
        }
    }

    // MARK: Helpers

    private func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func withPreferencesStore(
        _ body: (SQLiteControlDatabase) async throws -> Void
    ) async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanActorPreferences-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            try await body(store)
            try await store.close()
        } catch {
            try? await store.close()
            throw error
        }
    }

    private func makeApp(
        authorizer: PreferencesAuthorizer,
        store: any ActorPreferencesStore
    ) -> some ApplicationProtocol {
        let router = Router(context: SwanHTTPRequestContext.self)
        registerSwanActorPreferencesXRPC(
            on: router,
            authorizer: authorizer,
            store: store
        )
        return Application(
            router: router,
            configuration: .init(
                address: .hostname("127.0.0.1", port: 0),
                serverName: "swan-actor-preferences-tests"
            ),
            logger: Logger(label: "SwanActorPreferencesXRPCTests")
        )
    }

    private func jsonHeaders() -> HTTPFields {
        [.contentType: "application/json"]
    }

    private func bodyString(_ response: TestResponse) -> String {
        String(decoding: response.body.readableBytesView, as: UTF8.self)
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

private actor PreferencesAuthorizer: SwanActorPreferencesResourceAuthorizing {
    private let result: Result<AuthorizationContext, SwanResourceAuthorizationFailure>

    init(result: Result<AuthorizationContext, SwanResourceAuthorizationFailure>) {
        self.result = result
    }

    func authorizeActorPreferences(
        request _: Request,
        method _: String,
        fixedPath _: String,
        now _: Date
    ) async throws -> AuthorizationContext {
        try result.get()
    }

    func issueActorPreferencesNonce(now _: Date) async -> String {
        "test-nonce"
    }
}
