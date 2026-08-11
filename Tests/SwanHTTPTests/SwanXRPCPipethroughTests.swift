import Crypto
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
import XCTest

@testable import SwanHTTP

/// Step 1 probe, kept as a permanent regression guard: Hummingbird's trie must
/// resolve an exact `/xrpc/<nsid>` route ahead of a `/xrpc/**` recursive
/// wildcard. If this ever inverts, Swan would silently forward its own
/// lexicons to a third party.
final class SwanXRPCRouterPrecedenceTests: XCTestCase, @unchecked Sendable {
    func testRecursiveWildcardNeverShadowsAnExactRoute() async throws {
        let router = Router(context: SwanHTTPRequestContext.self)
        router.get("/xrpc/com.atproto.server.describeServer") { _, _ -> Response in
            Response(status: .ok, body: .init(byteBuffer: ByteBuffer(string: "local")))
        }
        // Registered after the exact route, which is the order `buildRouter()`
        // uses. Trie priority, not registration order, must decide.
        router.get("/xrpc/**") { _, _ -> Response in
            Response(status: .ok, body: .init(byteBuffer: ByteBuffer(string: "proxied")))
        }
        router.post("/xrpc/**") { _, _ -> Response in
            Response(status: .ok, body: .init(byteBuffer: ByteBuffer(string: "proxied")))
        }
        // A prefix wildcard guard of the kind `registerUnknownPublicEndpointGuards`
        // installs must also beat the recursive wildcard.
        router.get("/xrpc/com.atproto.sync.*") { _, _ -> Response in
            Response(status: .notFound, body: .init(byteBuffer: ByteBuffer(string: "guard")))
        }

        let app = Application(
            router: router,
            configuration: .init(
                address: .hostname("127.0.0.1", port: 0),
                serverName: "swan-xrpc-router-precedence-tests"
            ),
            logger: Logger(label: "SwanXRPCRouterPrecedenceTests")
        )
        try await app.test(.live) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.describeServer",
                method: .get
            ) { response in
                XCTAssertEqual(self.body(response), "local")
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.sync.getBlocks",
                method: .get
            ) { response in
                XCTAssertEqual(self.body(response), "guard")
            }
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getTimeline?limit=3",
                method: .get
            ) { response in
                XCTAssertEqual(self.body(response), "proxied")
            }
        }
    }

    private func body(_ response: TestResponse) -> String {
        String(decoding: response.body.readableBytesView, as: UTF8.self)
    }
}

final class SwanXRPCPipethroughTests: XCTestCase, @unchecked Sendable {
    private static let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let appViewDID = "did:web:api.bsky.app"

    // MARK: Step 1

    func testCatchAllNeverShadowsALocalRoute() async throws {
        let sender = RecordingProxySender()
        let router = Router(context: SwanHTTPRequestContext.self)
        // A local Swan route, registered before the fallback exactly as
        // `buildRouter()` does.
        router.get("/xrpc/com.atproto.server.describeServer") { _, _ -> Response in
            Response(status: .ok, body: .init(byteBuffer: ByteBuffer(string: #"{"did":"local"}"#)))
        }
        try makeCapability(sender: sender).register(on: router)

        try await makeApp(router).test(.live) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.describeServer",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(self.body(response), #"{"did":"local"}"#)
            }
        }
        // The local route answered, so nothing may have left this host.
        XCTAssertEqual(sender.recorded().count, 0)
    }

    // MARK: Step 2

    func testProxiesAppBskyToConfiguredAppView() async throws {
        let sender = RecordingProxySender()
        try await withPipethrough(sender: sender) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getAuthorFeed?actor=alice.test&limit=2",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(self.body(response), #"{"feed":[]}"#)
                XCTAssertEqual(response.headers[.contentType], "application/json")
            }
        }
        let outbound = try XCTUnwrap(sender.recorded().first)
        XCTAssertEqual(sender.recorded().count, 1)
        XCTAssertEqual(outbound.method, "GET")
        XCTAssertEqual(outbound.url.host, "api.bsky.app")
        XCTAssertEqual(outbound.url.scheme, "https")
        // Path and query verbatim.
        let components = try XCTUnwrap(
            URLComponents(url: outbound.url, resolvingAgainstBaseURL: false)
        )
        XCTAssertEqual(components.percentEncodedPath, "/xrpc/app.bsky.feed.getAuthorFeed")
        XCTAssertEqual(components.percentEncodedQuery, "actor=alice.test&limit=2")
        XCTAssertNil(outbound.body)
    }

    func testStripsInboundCredentialHeaders() async throws {
        let sender = RecordingProxySender()
        let headers: HTTPFields = {
            var headers = HTTPFields()
            headers[.authorization] = "DPoP swan-access-token"
            headers[HTTPField.Name("Cookie")!] = "session=swan-session"
            headers[HTTPField.Name("DPoP")!] = "eyJhbGciOiJFUzI1NiJ9.e30.sig"
            headers[HTTPField.Name("DPoP-Nonce")!] = "swan-nonce"
            return headers
        }()
        try await withPipethrough(sender: sender) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getTimeline",
                method: .get,
                headers: headers
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
        let outbound = try XCTUnwrap(sender.recorded().first)
        let names = Set(outbound.headers.map { $0.name.lowercased() })
        // Asserted positively: none of the client's Swan credentials may reach
        // a third-party service.
        XCTAssertFalse(names.contains("cookie"))
        XCTAssertFalse(names.contains("dpop"))
        XCTAssertFalse(names.contains("dpop-nonce"))
        // The one Authorization present is the minted service token, not the
        // client's DPoP access token.
        let authorization = try XCTUnwrap(
            outbound.headers.first { $0.name.lowercased() == "authorization" }?.value
        )
        XCTAssertFalse(authorization.contains("swan-access-token"))
        XCTAssertTrue(authorization.hasPrefix("Bearer "))
        let claims = try Self.claims(ofJWT: String(authorization.dropFirst("Bearer ".count)))
        XCTAssertEqual(claims["iss"] as? String, Self.did)
        XCTAssertEqual(claims["aud"] as? String, Self.appViewDID)
        XCTAssertEqual(claims["lxm"] as? String, "app.bsky.feed.getTimeline")
    }

    func testForwardsOnlyAllowListedHeaders() async throws {
        let sender = RecordingProxySender()
        let headers: HTTPFields = {
            var headers = HTTPFields()
            headers[HTTPField.Name("accept-language")!] = "en-GB"
            headers[HTTPField.Name("atproto-accept-labelers")!] = "did:plc:labeler;redact"
            headers[HTTPField.Name("x-custom")!] = "leak-me"
            headers[HTTPField.Name("user-agent")!] = "swan-tests"
            return headers
        }()
        try await withPipethrough(sender: sender) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getTimeline",
                method: .get,
                headers: headers
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
        let outbound = try XCTUnwrap(sender.recorded().first)
        let forwarded = Dictionary(
            uniqueKeysWithValues: outbound.headers.map { ($0.name.lowercased(), $0.value) }
        )
        XCTAssertEqual(forwarded["accept-language"], "en-GB")
        XCTAssertEqual(forwarded["atproto-accept-labelers"], "did:plc:labeler;redact")
        XCTAssertNil(forwarded["x-custom"])
        XCTAssertNil(forwarded["user-agent"])
    }

    func testUnauthenticatedRequestIsRejectedWithoutContactingUpstream() async throws {
        let sender = RecordingProxySender()
        try await withPipethrough(
            sender: sender,
            authorizer: PipethroughAuthorizer(result: .failure(.denied))
        ) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getTimeline",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .unauthorized)
            }
        }
        XCTAssertEqual(sender.recorded().count, 0)
    }

    func testUpstreamErrorStatusAndBodyPassThrough() async throws {
        let sender = RecordingProxySender(
            result: .success(
                OAuthRemoteHTTPResponse(
                    status: 400,
                    headers: ["Content-Type": ["application/json"]],
                    body: Data(#"{"error":"InvalidRequest","message":"bad actor"}"#.utf8),
                    responseURL: URL(string: "https://api.bsky.app/xrpc/app.bsky.feed.getTimeline")!
                )
            )
        )
        try await withPipethrough(sender: sender) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getTimeline",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
                XCTAssertEqual(
                    self.body(response),
                    #"{"error":"InvalidRequest","message":"bad actor"}"#
                )
                XCTAssertEqual(response.headers[.contentType], "application/json")
            }
        }
        XCTAssertEqual(sender.recorded().count, 1)
    }

    func testUnreachableUpstreamBecomes502() async throws {
        let sender = RecordingProxySender(
            result: .failure(SwanError.unavailable("upstream is unreachable"))
        )
        try await withPipethrough(sender: sender) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getTimeline",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .badGateway)
            }
        }
        XCTAssertEqual(sender.recorded().count, 1)
    }

    func testMalformedProxyHeaderIsRejectedWithoutContactingUpstream() async throws {
        let sender = RecordingProxySender()
        let headers: HTTPFields = {
            var headers = HTTPFields()
            // No `#fragment`: unusable, and must never silently fall back to
            // the configured AppView.
            headers[HTTPField.Name("atproto-proxy")!] = "did:web:evil.example"
            return headers
        }()
        try await withPipethrough(sender: sender) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getTimeline",
                method: .get,
                headers: headers
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
            }
        }
        XCTAssertEqual(sender.recorded().count, 0)
    }

    func testDeniedNamespaceIsNotProxied() async throws {
        let sender = RecordingProxySender()
        let headers: HTTPFields = {
            var headers = HTTPFields()
            // Even an explicit proxy header must not override the deny-list.
            headers[HTTPField.Name("atproto-proxy")!] = "did:web:evil.example#atproto_pds"
            return headers
        }()
        try await withPipethrough(sender: sender) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.space.getSpace",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .notFound)
            }
            try await client.execute(
                uri: "/xrpc/blue.catbird.anything.here",
                method: .get,
                headers: headers
            ) { response in
                XCTAssertEqual(response.status, .notFound)
            }
        }
        XCTAssertEqual(sender.recorded().count, 0)
    }

    /// Preferences are PDS-owned state the AppView does not store. If they
    /// were proxied, a `putPreferences` would silently discard the write *and*
    /// disclose the account's saved feeds, content-label settings, and muted
    /// words to a third party. Asserted positively against the stub sender so
    /// this cannot regress into a silent leak.
    func testActorPreferencesAreNeverHandedToTheProxySender() async throws {
        let sender = RecordingProxySender()
        let steered: HTTPFields = {
            var headers = HTTPFields()
            headers[.contentType] = "application/json"
            // Even a client that explicitly names another service must not be
            // able to steer preferences off this host.
            headers[HTTPField.Name("atproto-proxy")!] = "did:web:evil.example#atproto_pds"
            return headers
        }()
        try await withPipethrough(sender: sender) { client in
            // The plain form is the one that matters most: with no proxy
            // header it would take the default `app.bsky.` route straight to
            // the configured AppView and reach the sender.
            try await client.execute(
                uri: "/xrpc/app.bsky.actor.putPreferences",
                method: .post,
                headers: [.contentType: "application/json"],
                body: ByteBuffer(string: #"{"preferences":[{"$type":"x","mutedWords":["secret"]}]}"#)
            ) { response in
                XCTAssertEqual(response.status, .notFound)
            }
            try await client.execute(
                uri: "/xrpc/app.bsky.actor.getPreferences",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .notFound)
            }
            try await client.execute(
                uri: "/xrpc/app.bsky.actor.putPreferences",
                method: .post,
                headers: steered,
                body: ByteBuffer(string: #"{"preferences":[]}"#)
            ) { response in
                XCTAssertEqual(response.status, .notFound)
            }
        }
        // Nothing left this host.
        XCTAssertEqual(sender.recorded().count, 0)
    }

    /// `HTTPFields[values:]` yields one entry per header line, so a request
    /// carrying two `atproto-proxy` lines is ambiguous, not absent. Treating it
    /// as absent would drop it onto the default `app.bsky.` route and forward
    /// the account's traffic to the AppView — the exact silent fallback the
    /// malformed-header rule exists to prevent.
    func testDuplicateProxyHeaderIsRejectedWithoutContactingUpstream() async throws {
        let sender = RecordingProxySender()
        let headers: HTTPFields = {
            var headers = HTTPFields()
            let name = HTTPField.Name("atproto-proxy")!
            headers.append(HTTPField(name: name, value: "did:web:feeds.example#bsky_fg"))
            headers.append(HTTPField(name: name, value: "did:web:feeds.example#bsky_fg"))
            return headers
        }()
        try await withPipethrough(sender: sender) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getFeedSkeleton",
                method: .get,
                headers: headers
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
            }
        }
        XCTAssertEqual(sender.recorded().count, 0)
    }

    /// Two *conflicting* lines must fail the same way; there is no
    /// "first one wins" or "last one wins" here.
    func testConflictingDuplicateProxyHeadersAreRejected() async throws {
        let sender = RecordingProxySender()
        let headers: HTTPFields = {
            var headers = HTTPFields()
            let name = HTTPField.Name("atproto-proxy")!
            headers.append(HTTPField(name: name, value: "did:web:a.example#bsky_fg"))
            headers.append(HTTPField(name: name, value: "did:web:b.example#bsky_fg"))
            return headers
        }()
        try await withPipethrough(sender: sender) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getFeedSkeleton",
                method: .get,
                headers: headers
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
            }
        }
        XCTAssertEqual(sender.recorded().count, 0)
    }

    /// The configured-endpoint shortcut is keyed on DID *and* fragment, so a
    /// client naming a different service at the AppView's own DID is not
    /// silently handed the AppView. Here the AppView's DID document has no
    /// `#atproto_labeler` entry, so it fails closed at 400 rather than being
    /// answered by a service the client did not ask for.
    func testDifferentFragmentAtTheAppViewDIDIsNotSilentlyTheAppView() async throws {
        let sender = RecordingProxySender()
        let documents = StubDIDDocuments(
            documents: [
                "did:web:api.bsky.app": Data(
                    """
                    {"id":"did:web:api.bsky.app","service":[
                      {"id":"#bsky_appview","type":"BskyAppView",
                       "serviceEndpoint":"https://api.bsky.app"}]}
                    """.utf8
                )
            ]
        )
        let headers: HTTPFields = {
            var headers = HTTPFields()
            headers[HTTPField.Name("atproto-proxy")!] = "did:web:api.bsky.app#atproto_labeler"
            return headers
        }()
        try await withPipethrough(sender: sender, documents: documents) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getTimeline",
                method: .get,
                headers: headers
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
            }
        }
        XCTAssertEqual(sender.recorded().count, 0)
    }

    /// A different fragment at the AppView DID that *does* resolve goes to the
    /// service the client named, not to the configured AppView URL.
    func testDifferentFragmentAtTheAppViewDIDResolvesToTheNamedService() async throws {
        let sender = RecordingProxySender()
        let documents = StubDIDDocuments(
            documents: [
                "did:web:api.bsky.app": Data(
                    """
                    {"id":"did:web:api.bsky.app","service":[
                      {"id":"#bsky_appview","type":"BskyAppView",
                       "serviceEndpoint":"https://api.bsky.app"},
                      {"id":"#atproto_labeler","type":"AtprotoLabeler",
                       "serviceEndpoint":"https://labeler.bsky.app"}]}
                    """.utf8
                )
            ]
        )
        let headers: HTTPFields = {
            var headers = HTTPFields()
            headers[HTTPField.Name("atproto-proxy")!] = "did:web:api.bsky.app#atproto_labeler"
            return headers
        }()
        try await withPipethrough(sender: sender, documents: documents) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getTimeline",
                method: .get,
                headers: headers
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
        let outbound = try XCTUnwrap(sender.recorded().first)
        XCTAssertEqual(outbound.url.host, "labeler.bsky.app")
    }

    /// `--appview-service-fragment` is load-bearing, not inert: an operator who
    /// configures a different fragment changes which service reference takes
    /// the no-resolution shortcut.
    func testConfiguredServiceFragmentSelectsTheShortcut() async throws {
        let sender = RecordingProxySender()
        let appView = try SwanAppViewConfiguration(
            did: "did:web:api.bsky.app",
            url: URL(string: "https://api.bsky.app")!,
            serviceFragment: "custom_appview"
        )
        let matching: HTTPFields = {
            var headers = HTTPFields()
            headers[HTTPField.Name("atproto-proxy")!] = "did:web:api.bsky.app#custom_appview"
            return headers
        }()
        try await withPipethrough(sender: sender, appView: appView) { client in
            // Matches the configured fragment: answered from configuration,
            // with no DID document available at all (the stub is empty).
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getTimeline",
                method: .get,
                headers: matching
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
        XCTAssertEqual(sender.recorded().first?.url.host, "api.bsky.app")

        // The stock fragment is no longer the shortcut under this
        // configuration, so it needs resolution and fails closed.
        let stale = RecordingProxySender()
        let notMatching: HTTPFields = {
            var headers = HTTPFields()
            headers[HTTPField.Name("atproto-proxy")!] = "did:web:api.bsky.app#bsky_appview"
            return headers
        }()
        try await withPipethrough(sender: stale, appView: appView) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getTimeline",
                method: .get,
                headers: notMatching
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
            }
        }
        XCTAssertEqual(stale.recorded().count, 0)
    }

    // MARK: Additional coverage

    func testUnroutedNamespaceIs404WithoutContactingUpstream() async throws {
        let sender = RecordingProxySender()
        try await withPipethrough(sender: sender) { client in
            try await client.execute(
                uri: "/xrpc/com.example.unknown.method",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .notFound)
            }
        }
        XCTAssertEqual(sender.recorded().count, 0)
    }

    func testNonNSIDTargetIs404WithoutContactingUpstream() async throws {
        let sender = RecordingProxySender()
        try await withPipethrough(sender: sender) { client in
            for uri in [
                "/xrpc/notannsid",
                "/xrpc/app.bsky.feed.getTimeline/extra",
                "/xrpc/app.bsky..getTimeline",
                "/xrpc/app%2Ebsky%2Efeed%2EgetTimeline",
            ] {
                try await client.execute(uri: uri, method: .get) { response in
                    XCTAssertEqual(response.status, .notFound, "for \(uri)")
                }
            }
        }
        XCTAssertEqual(sender.recorded().count, 0)
    }

    /// Covers endpoint selection and audience binding for the resolve path.
    ///
    /// It deliberately does NOT cover peer pinning: the injected
    /// `RecordingProxySender` replaces `SwanPeerPinnedProxySender`, so no
    /// resolve → policy-check → pin step runs here at all. That control is
    /// exercised by `SwanPeerPinnedProxySender`'s own tests and the live-TLS
    /// transport coverage in `SwanOAuthTests`. What this test does prove is
    /// that the handler hands the *resolved* endpoint to whatever sender it
    /// was given, rather than bypassing it or falling back to the AppView.
    func testResolvedServiceUsesTheResolvedEndpointAndAudience() async throws {
        let sender = RecordingProxySender()
        let documents = StubDIDDocuments(
            documents: [
                "did:web:feeds.example": Data(
                    """
                    {"id":"did:web:feeds.example","service":[
                      {"id":"#bsky_fg","type":"BskyFeedGenerator",
                       "serviceEndpoint":"https://feeds.example"}]}
                    """.utf8
                )
            ]
        )
        let headers: HTTPFields = {
            var headers = HTTPFields()
            headers[HTTPField.Name("atproto-proxy")!] = "did:web:feeds.example#bsky_fg"
            return headers
        }()
        try await withPipethrough(sender: sender, documents: documents) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getFeedSkeleton?feed=at://x",
                method: .get,
                headers: headers
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
        let outbound = try XCTUnwrap(sender.recorded().first)
        // The resolved endpoint reached the sender, not the AppView URL.
        XCTAssertEqual(outbound.url.host, "feeds.example")
        let authorization = try XCTUnwrap(
            outbound.headers.first { $0.name.lowercased() == "authorization" }?.value
        )
        let claims = try Self.claims(ofJWT: String(authorization.dropFirst("Bearer ".count)))
        XCTAssertEqual(claims["aud"] as? String, "did:web:feeds.example")
        XCTAssertEqual(claims["lxm"] as? String, "app.bsky.feed.getFeedSkeleton")
    }

    func testUnresolvableServiceIsRejectedWith400WithoutContactingUpstream() async throws {
        let sender = RecordingProxySender()
        let headers: HTTPFields = {
            var headers = HTTPFields()
            headers[HTTPField.Name("atproto-proxy")!] = "did:web:missing.example#bsky_fg"
            return headers
        }()
        try await withPipethrough(sender: sender, documents: StubDIDDocuments(documents: [:])) {
            client in
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getFeedSkeleton",
                method: .get,
                headers: headers
            ) { response in
                XCTAssertEqual(response.status, .badRequest)
            }
        }
        XCTAssertEqual(sender.recorded().count, 0)
    }

    func testProxiedPostForwardsBodyAndContentType() async throws {
        let sender = RecordingProxySender()
        let headers: HTTPFields = {
            var headers = HTTPFields()
            headers[.contentType] = "application/json"
            headers[.authorization] = "DPoP swan-access-token"
            return headers
        }()
        try await withPipethrough(sender: sender) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.notification.updateSeen",
                method: .post,
                headers: headers,
                body: ByteBuffer(string: #"{"seenAt":"2026-08-11T00:00:00Z"}"#)
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
        let outbound = try XCTUnwrap(sender.recorded().first)
        XCTAssertEqual(outbound.method, "POST")
        XCTAssertEqual(
            outbound.body.map { String(decoding: $0, as: UTF8.self) },
            #"{"seenAt":"2026-08-11T00:00:00Z"}"#
        )
        let forwarded = Dictionary(
            uniqueKeysWithValues: outbound.headers.map { ($0.name.lowercased(), $0.value) }
        )
        XCTAssertEqual(forwarded["content-type"], "application/json")
        XCTAssertTrue(forwarded["authorization"]?.hasPrefix("Bearer ") ?? false)
    }

    func testOversizedProxiedPostIsRejectedWith413() async throws {
        let sender = RecordingProxySender()
        let headers: HTTPFields = {
            var headers = HTTPFields()
            headers[.contentType] = "application/json"
            return headers
        }()
        let limits = SwanXRPCPipethroughLimits(maximumRequestBodyBytes: 1_024)
        try await withPipethrough(sender: sender, limits: limits) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.notification.updateSeen",
                method: .post,
                headers: headers,
                body: ByteBuffer(string: String(repeating: "a", count: 1_025))
            ) { response in
                XCTAssertEqual(response.status, .contentTooLarge)
            }
        }
        XCTAssertEqual(sender.recorded().count, 0)
    }

    func testExhaustedConcurrencyBudgetRejectsWithoutContactingUpstream() async throws {
        let sender = RecordingProxySender()
        let capability = try makeCapability(
            sender: sender,
            limits: SwanXRPCPipethroughLimits(maximumConcurrentRequests: 1)
        )
        // Hold the only slot, exactly as an in-flight proxied request would.
        // Driving this with two concurrent HTTP requests would depend on the
        // test client opening a second connection, which it does not.
        let held = capability.admission.acquire()
        XCTAssertNotNil(held)
        let router = Router(context: SwanHTTPRequestContext.self)
        capability.register(on: router)
        try await makeApp(router).test(.live) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getTimeline",
                method: .get
            ) { response in
                // The proxy's own budget, not the upstream's.
                XCTAssertEqual(response.status, .serviceUnavailable)
            }
        }
        // The refused request never reached the sender.
        XCTAssertEqual(sender.recorded().count, 0)
        held?.release()

        // With the slot returned, the same request proxies normally.
        let secondRouter = Router(context: SwanHTTPRequestContext.self)
        capability.register(on: secondRouter)
        try await makeApp(secondRouter).test(.live) { client in
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getTimeline",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
        XCTAssertEqual(sender.recorded().count, 1)
    }

    func testAdmissionLeaseIsReleasedExactlyOnce() {
        let admission = SwanXRPCPipethroughAdmission(limit: 1)
        let lease = admission.acquire()
        XCTAssertNotNil(lease)
        XCTAssertNil(admission.acquire())
        lease?.release()
        lease?.release()
        XCTAssertNotNil(admission.acquire())
    }

    // MARK: Composition

    /// Regression guard for the fallback existing but never being composed
    /// into `SwanHTTPServer`, and for the fallback shadowing a real local
    /// route inside the production router. Mirrors
    /// `SwanActorPreferencesXRPCTests.testActorPreferencesRoutesComposeIntoTheMainServerBeforeApplicationConstruction`.
    func testPipethroughComposesIntoTheMainServerWithoutShadowingLocalRoutes() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanXRPCPipethroughMainServer-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x3D, count: 32)
            )
            let sender = RecordingProxySender()
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
                // Both halves of the preferences fix, composed together the
                // way `serve` now composes them.
                actorPreferencesXRPC: SwanActorPreferencesXRPCServer(
                    authorizer: PipethroughAuthorizer(
                        result: .success(
                            .accountOAuth(subject: Self.did, scopes: ["atproto"])
                        )
                    ),
                    store: control
                ),
                xrpcPipethrough: try makeCapability(sender: sender)
            )
            let app = server.buildApplication(
                logger: Logger(label: "SwanXRPCPipethroughTests.main-server")
            )
            try await app.test(.live) { client in
                // A Swan-owned permissioned route still answers locally, with
                // its own exact closed-route shape. Asserting the specific
                // status and body matters: a bare "not 200" would also pass if
                // the proxy fallback had answered 404.
                try await client.execute(
                    uri: "/xrpc/com.atproto.space.getSpace",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    XCTAssertEqual(
                        self.body(response),
                        #"{"error":"permissioned_data_pending"}"#
                    )
                }
                // A generated public route still answers locally, likewise
                // with its own body rather than the fallback's.
                try await client.execute(
                    uri: "/xrpc/com.atproto.repo.getRecord",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                    XCTAssertEqual(
                        self.body(response),
                        #"{"error":"public_data_pending"}"#
                    )
                }
                // Preferences are answered by the local capability, not by the
                // fallback: 200 with the PDS's own empty-array shape, never
                // the proxied AppView body.
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.getPreferences",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(self.body(response), #"{"preferences":[]}"#)
                }
                try await client.execute(
                    uri: "/xrpc/app.bsky.actor.putPreferences",
                    method: .post,
                    headers: [.contentType: "application/json"],
                    body: ByteBuffer(string: #"{"preferences":[]}"#)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                }
                // And an app.bsky method is proxied.
                try await client.execute(
                    uri: "/xrpc/app.bsky.feed.getTimeline",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(self.body(response), #"{"feed":[]}"#)
                }
            }
            // Only the app.bsky request left the host.
            let recorded = sender.recorded()
            XCTAssertEqual(recorded.count, 1)
            XCTAssertEqual(
                URLComponents(url: recorded[0].url, resolvingAgainstBaseURL: false)?
                    .percentEncodedPath,
                "/xrpc/app.bsky.feed.getTimeline"
            )
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    // MARK: Helpers

    private func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func makeCapability(
        sender: RecordingProxySender,
        authorizer: PipethroughAuthorizer? = nil,
        documents: StubDIDDocuments = StubDIDDocuments(documents: [:]),
        appView: SwanAppViewConfiguration? = nil,
        limits: SwanXRPCPipethroughLimits = .default
    ) throws -> SwanXRPCPipethroughServer {
        SwanXRPCPipethroughServer(
            authorizer: authorizer
                ?? PipethroughAuthorizer(
                    result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"]))
                ),
            tokens: TestProxyServiceTokenIssuer(),
            sender: sender,
            resolver: SwanServiceEndpointResolver(documents: documents),
            appView: try appView ?? SwanAppViewConfiguration(),
            limits: limits
        )
    }

    private func makeApp(_ router: Router<SwanHTTPRequestContext>) -> some ApplicationProtocol {
        Application(
            router: router,
            configuration: .init(
                address: .hostname("127.0.0.1", port: 0),
                serverName: "swan-xrpc-pipethrough-tests"
            ),
            logger: Logger(label: "SwanXRPCPipethroughTests")
        )
    }

    private func withPipethrough(
        sender: RecordingProxySender,
        authorizer: PipethroughAuthorizer? = nil,
        documents: StubDIDDocuments = StubDIDDocuments(documents: [:]),
        appView: SwanAppViewConfiguration? = nil,
        limits: SwanXRPCPipethroughLimits = .default,
        _ body: @escaping @Sendable (any TestClientProtocol) async throws -> Void
    ) async throws {
        let router = Router(context: SwanHTTPRequestContext.self)
        try makeCapability(
            sender: sender,
            authorizer: authorizer,
            documents: documents,
            appView: appView,
            limits: limits
        ).register(on: router)
        try await makeApp(router).test(.live, body)
    }

    private func body(_ response: TestResponse) -> String {
        String(decoding: response.body.readableBytesView, as: UTF8.self)
    }

    private static func claims(ofJWT jwt: String) throws -> [String: Any] {
        let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else {
            throw PipethroughTestFailure.malformedJWT
        }
        var encoded = String(parts[1])
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while encoded.count % 4 != 0 { encoded.append("=") }
        guard let data = Data(base64Encoded: encoded),
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PipethroughTestFailure.malformedJWT
        }
        return object
    }
}

private enum PipethroughTestFailure: Error {
    case malformedJWT
}

// MARK: - Doubles

private struct PipethroughAuthorizer:
    SwanXRPCPipethroughResourceAuthorizing,
    SwanActorPreferencesResourceAuthorizing
{
    let result: Result<AuthorizationContext, SwanResourceAuthorizationFailure>

    func authorizePipethrough(
        request: Request,
        method: String,
        fixedPath: String,
        now: Date
    ) async throws -> AuthorizationContext {
        try result.get()
    }

    func issuePipethroughNonce(now: Date) async -> String { "test-nonce" }

    func authorizeActorPreferences(
        request: Request,
        method: String,
        fixedPath: String,
        now: Date
    ) async throws -> AuthorizationContext {
        try result.get()
    }

    func issueActorPreferencesNonce(now: Date) async -> String { "test-nonce" }
}

/// Mints a real `ProxyServiceJWT` from a per-process test key, so the tests
/// assert against actual signed claims rather than a placeholder string.
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

private struct StubDIDDocuments: SwanDIDDocumentFetching {
    let documents: [String: Data]

    func documentJSON(forDID did: String) async throws -> Data {
        guard let data = documents[did] else {
            throw SwanError.unavailable("no stub DID document")
        }
        return data
    }
}

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
        _ request: SwanProxyRequest, timeout: TimeInterval, maximumBodyBytes: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        record(request)
        return try result.get()
    }

    // Locking lives in a synchronous method: `NSLock.lock()` is unavailable
    // directly inside an async context under Swift 6.
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
