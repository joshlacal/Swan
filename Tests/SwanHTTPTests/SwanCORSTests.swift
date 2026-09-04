import Foundation
import HTTPTypes
import Hummingbird
import HummingbirdTesting
import Logging
import SwanCore
@testable import SwanHTTP
import SwanOAuth
import SwanSQLite
import XCTest

/// CORS on the public listener.
///
/// The regression these pin: the Bluesky web client at `https://bsky.app`
/// could not sign in to swan.place because its preflight
/// `OPTIONS /xrpc/com.atproto.server.createSession` answered 404. The path was
/// registered for `POST` only, so the router found no responder for the method
/// and fell through to not-found — and the browser reported that against the
/// `POST`, which it never sent. `createSession` itself was correct the whole
/// time, which is exactly why probing it with `curl` said nothing.
///
/// Every assertion here is about credential ADMISSION at the browser boundary,
/// the same class of gap that let a green suite ship a login nobody could use.
final class SwanCORSTests: XCTestCase {
    private static let createSessionPath = "/xrpc/com.atproto.server.createSession"
    private static let webClientOrigin = "https://bsky.app"

    private static let allowOrigin = HTTPField.Name("Access-Control-Allow-Origin")!
    private static let allowMethods = HTTPField.Name("Access-Control-Allow-Methods")!
    private static let allowHeaders = HTTPField.Name("Access-Control-Allow-Headers")!
    private static let allowCredentials = HTTPField.Name("Access-Control-Allow-Credentials")!
    private static let exposeHeaders = HTTPField.Name("Access-Control-Expose-Headers")!
    private static let maxAge = HTTPField.Name("Access-Control-Max-Age")!
    private static let requestMethod = HTTPField.Name("Access-Control-Request-Method")!
    private static let requestHeaders = HTTPField.Name("Access-Control-Request-Headers")!

    // MARK: - The regression

    /// The exact preflight Safari sent, reproduced from the Caddy access log
    /// that identified the fault: `Origin: https://bsky.app`,
    /// `Access-Control-Request-Method: POST`,
    /// `Access-Control-Request-Headers: content-type`.
    func testWebClientPreflightForCreateSessionIsAnswered() async throws {
        try await withRouter { client in
            try await client.execute(
                uri: Self.createSessionPath,
                method: .options,
                headers: [
                    .origin: Self.webClientOrigin,
                    Self.requestMethod: "POST",
                    Self.requestHeaders: "content-type",
                ]
            ) { response in
                XCTAssertEqual(response.status, .noContent)
                XCTAssertEqual(response.headers[Self.allowOrigin], "*")
                XCTAssertEqual(response.headers[Self.allowHeaders], "content-type")
                XCTAssertEqual(response.headers[Self.maxAge], "86400")
                let methods = try XCTUnwrap(response.headers[Self.allowMethods])
                // The verb the client asked about. Advertising anything else
                // while omitting this is the same failure wearing a 204.
                XCTAssertTrue(methods.contains("POST"), methods)
            }
        }
    }

    /// The requested header list is reflected, not matched against a fixed
    /// allowlist. A fixed list is the failure mode being avoided: it blocks the
    /// first client sending a header nobody enumerated, and the block surfaces
    /// as the same misleading browser-side error.
    func testPreflightReflectsHeadersNobodyEnumerated() async throws {
        try await withRouter { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.repo.getRecord",
                method: .options,
                headers: [
                    .origin: Self.webClientOrigin,
                    Self.requestMethod: "GET",
                    Self.requestHeaders: "atproto-proxy, atproto-accept-labelers, authorization",
                ]
            ) { response in
                XCTAssertEqual(response.status, .noContent)
                XCTAssertEqual(
                    response.headers[Self.allowHeaders],
                    "atproto-proxy, atproto-accept-labelers, authorization"
                )
                // Reflection means the answer depends on the request, so the
                // cache must be keyed on it.
                XCTAssertEqual(response.headers[.vary], "Access-Control-Request-Headers")
            }
        }
    }

    /// A preflight is answered ahead of routing, so it does not depend on the
    /// target path having a responder. This covers the not-found path, which is
    /// where the original 404 came from.
    func testPreflightIsAnsweredForAPathThatHasNoRouteAtAll() async throws {
        try await withRouter { client in
            try await client.execute(
                uri: "/xrpc/com.example.nothing.here",
                method: .options,
                headers: [
                    .origin: Self.webClientOrigin,
                    Self.requestMethod: "POST",
                ]
            ) { response in
                XCTAssertEqual(response.status, .noContent)
                XCTAssertEqual(response.headers[Self.allowOrigin], "*")
            }
        }
    }

    // MARK: - Actual requests

    func testCrossOriginResponseCarriesAllowOrigin() async throws {
        try await withRouter { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.describeServer",
                method: .get,
                headers: [.origin: Self.webClientOrigin]
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(response.headers[Self.allowOrigin], "*")
            }
        }
    }

    /// Not-found throws `HTTPError` rather than returning a response
    /// (`Router.swift:109`), so without the error branch a browser sees an
    /// opaque network failure instead of the status the client must act on.
    /// The same branch carries every thrown 401.
    func testThrownErrorResponseStillCarriesAllowOrigin() async throws {
        try await withRouter { client in
            try await client.execute(
                uri: "/xrpc/com.example.nothing.here",
                method: .get,
                headers: [.origin: Self.webClientOrigin]
            ) { response in
                XCTAssertEqual(response.status, .notFound)
                XCTAssertEqual(response.headers[Self.allowOrigin], "*")
            }
        }
    }

    /// `DPoP-Nonce` drives the OAuth nonce handshake; a browser client that
    /// cannot read it can never satisfy the retry.
    func testProtocolCriticalResponseHeadersAreReadable() async throws {
        try await withRouter { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.describeServer",
                method: .get,
                headers: [.origin: Self.webClientOrigin]
            ) { response in
                let exposed = try XCTUnwrap(response.headers[Self.exposeHeaders])
                XCTAssertTrue(exposed.contains("DPoP-Nonce"), exposed)
                XCTAssertTrue(exposed.contains("WWW-Authenticate"), exposed)
            }
        }
    }

    // MARK: - The invariant the wildcard rests on

    /// The wildcard origin is only safe while no credentials are allowed:
    /// together they would let any page make authenticated, cookie-bearing
    /// cross-origin calls and read the results. Browsers also reject the
    /// combination outright. This must fail if anyone adds the header.
    func testCredentialsAreNeverAllowed() async throws {
        try await withRouter { client in
            try await client.execute(
                uri: Self.createSessionPath,
                method: .options,
                headers: [
                    .origin: Self.webClientOrigin,
                    Self.requestMethod: "POST",
                ]
            ) { response in
                XCTAssertNil(response.headers[Self.allowCredentials])
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.server.describeServer",
                method: .get,
                headers: [.origin: Self.webClientOrigin]
            ) { response in
                XCTAssertNil(response.headers[Self.allowCredentials])
            }
        }
    }

    // MARK: - Non-browser traffic is untouched

    /// Federation, relays and other PDSes send no `Origin`. Their responses
    /// must stay byte-identical, so the middleware is a no-op for them.
    func testRequestsWithoutOriginAreUnchanged() async throws {
        try await withRouter { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.describeServer",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertNil(response.headers[Self.allowOrigin])
                XCTAssertNil(response.headers[Self.exposeHeaders])
            }
        }
    }

    /// The short-circuit is narrow: it fires for preflights, which are the only
    /// `OPTIONS` a browser sends unprompted. A bare `OPTIONS` still reaches the
    /// router, so the method guards keep deciding it.
    func testBareOptionsWithoutPreflightHeadersStillReachesTheRouter() async throws {
        try await withRouter { client in
            try await client.execute(
                uri: Self.createSessionPath,
                method: .options,
                headers: [.origin: Self.webClientOrigin]
            ) { response in
                XCTAssertNotEqual(response.status, .noContent)
            }
        }
    }

    /// Account management is a same-origin cookie surface. It must not inherit
    /// the public listener's wildcard preflight or response decoration, even
    /// when a hostile page supplies an Origin header. A look-alike path stays
    /// on the public CORS policy so the boundary cannot accidentally widen.
    func testAccountSurfaceBypassesGlobalCORSAndPreservesPathBoundary() async throws {
        try await withBoundaryRouter { client in
            try await client.execute(
                uri: "/account/api/test",
                method: .options,
                headers: [
                    .origin: "https://evil.example",
                    Self.requestMethod: "GET",
                    Self.requestHeaders: "content-type",
                ]
            ) { response in
                XCTAssertNotEqual(response.status, .noContent)
                XCTAssertNil(response.headers[Self.allowOrigin])
                XCTAssertNil(response.headers[Self.allowMethods])
            }
            try await client.execute(
                uri: "/account/api/test",
                method: .get,
                headers: [.origin: "https://evil.example"]
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertNil(response.headers[Self.allowOrigin])
                XCTAssertNil(response.headers[Self.exposeHeaders])
            }
            try await client.execute(
                uri: "/accounting",
                method: .get,
                headers: [.origin: "https://evil.example"]
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(response.headers[Self.allowOrigin], "*")
            }
        }
    }

    // MARK: - Harness

    private func withRouter(
        _ body: @escaping @Sendable (any TestClientProtocol) async throws -> Void
    ) async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanCORSTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x63, count: 32)
            )
            let profile = try ProtocolProfile.load(
                from: Self.packageRoot()
                    .appending(path: "Profiles/permissioned-data-0016-2026-09-10.json")
            )
            let server = SwanHTTPServer(
                profile: profile,
                configuration: SwanHTTPConfiguration(
                    host: "127.0.0.1",
                    port: 3000,
                    publicURL: URL(string: "https://swan.place")!
                ),
                oauthRuntime: runtime
            )
            let app = server.buildApplication(logger: Logger(label: "SwanCORSTests"))
            try await app.test(.router, body)
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    private func withBoundaryRouter(
        _ body: @escaping @Sendable (any TestClientProtocol) async throws -> Void
    ) async throws {
        let router = Router(context: SwanHTTPRequestContext.self)
        router.add(middleware: SwanCORSMiddleware<SwanHTTPRequestContext>())
        router.get("/account/api/test") { _, _ -> Response in
            Response(status: .ok)
        }
        router.get("/accounting") { _, _ -> Response in
            Response(status: .ok)
        }
        let app = Application(
            router: router,
            configuration: .init(address: .hostname("127.0.0.1", port: 0), serverName: "SwanCORSTests.boundary"),
            logger: Logger(label: "SwanCORSTests.boundary")
        )
        try await app.test(.router, body)
    }

    private static func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}
