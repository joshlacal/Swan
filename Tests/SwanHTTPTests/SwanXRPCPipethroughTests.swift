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

    func testResolverCancellationRethrowsCancellationErrorWithoutMappingToBadRequest() async throws {
        struct CancellingDIDDocuments: SwanDIDDocumentFetching {
            func documentJSON(forDID _: String) async throws -> Data {
                throw CancellationError()
            }
        }
        let sender = RecordingProxySender()
        let headers: HTTPFields = {
            var headers = HTTPFields()
            headers[HTTPField.Name("atproto-proxy")!] = "did:web:cancelled.example#bsky_fg"
            return headers
        }()
        let router = Router(context: SwanHTTPRequestContext.self)
        let capability = try SwanXRPCPipethroughServer(
            authorizer: PipethroughAuthorizer(
                result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"]))
            ),
            tokens: TestProxyServiceTokenIssuer(),
            sender: sender,
            resolver: SwanServiceEndpointResolver(documents: CancellingDIDDocuments()),
            appView: try SwanAppViewConfiguration()
        )
        capability.register(on: router)

        do {
            try await makeApp(router).test(.live) { client in
                try await client.execute(
                    uri: "/xrpc/app.bsky.feed.getFeedSkeleton",
                    method: .get,
                    headers: headers
                ) { response in
                    XCTAssertNotEqual(response.status, .badRequest, "cancellation must not be mapped to 400 badRequest")
                }
            }
        } catch is CancellationError {
            // Expected propagation of CancellationError
        } catch {
            // Transport or framework propagation
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

    // MARK: Query-string admission

    /// The client's query reaches `URLComponents.percentEncodedQuery`, whose
    /// setter refuses characters outside the RFC 3986 query grammar with a
    /// **`fatalError`** — so a byte admitted here does not produce a bad
    /// outbound URL, it terminates the PDS process for every session.
    ///
    /// These are driven through the real registered route rather than through
    /// `pipethroughOutboundRequest`: the crash lived on the handler's path, and
    /// a helper-level test would have exercised the same guard from the wrong
    /// side of the wire and proved nothing about what a client can send.
    ///
    /// None of this needs an attacker. `cursor=100%` is what a truncated cursor
    /// looks like, and `q="foo"` is what a quoted phrase search looks like.
    func testUnforwardableQueryStringsAreRejectedWithoutContactingUpstream() async throws {
        let sender = RecordingProxySender()
        let rejected = [
            // The reproduction from the review: a trailing `%` in a cursor.
            "cursor=100%",
            // A lone `%` as the entire query.
            "%",
            // `%` with too few following characters to be an escape.
            "cursor=abc%",
            "cursor=abc%A",
            // `%` followed by two non-hex characters.
            "cursor=%zz",
            "cursor=%2z",
            // Brackets are gen-delims reserved for the host component. They are
            // not in the review's list, but they are the second reachable form
            // of the same crash: `llhttp` passes them through and the
            // `percentEncodedQuery` setter then rejects them fatally.
            "q=a[b]",
            "cursor=[",
        ]
        try await withPipethrough(sender: sender) { client in
            for query in rejected {
                try await client.execute(
                    uri: "/xrpc/app.bsky.feed.getAuthorFeed?" + query,
                    method: .get
                ) { response in
                    // A 400, and above all a live server: the next iteration
                    // reaching this assertion at all is the process-kill guard.
                    XCTAssertEqual(response.status, .badRequest, "for query \(query)")
                }
            }
            // The server is still answering normally afterwards.
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getAuthorFeed?actor=alice.test",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
        // Exactly the one well-formed request left this host.
        XCTAssertEqual(sender.recorded().count, 1)
    }

    /// The review also listed `q="foo"` and `q=a|b`. Measured against this
    /// stack they never reach the handler at all: NIO's HTTP/1.1 parser refuses
    /// `"`, `<`, `>`, `\`, `^`, `` ` ``, `{`, `|`, and `}` in a request target
    /// and fails the connection, so the guard added for C1 is not what stops
    /// them. That is recorded here rather than asserted as a 400, because
    /// asserting the wrong mechanism would quietly stop testing anything if the
    /// parser ever loosened: this test fails loudly the moment one of these
    /// starts being delivered, which is the point at which the handler-level
    /// guard has to catch it — and it does, since none of these bytes are in
    /// the RFC 3986 query grammar.
    func testParserRefusedQueryBytesNeverReachTheHandler() async throws {
        let sender = RecordingProxySender()
        for query in [#"q="foo""#, "q=a|b", "q=a^b", "q=a`b", "q=a{b}", "q=a\\b", "q=a<b>c"] {
            let delivered = PipethroughFlag()
            do {
                try await withPipethrough(sender: sender) { client in
                    // One well-formed round trip first, and it is load-bearing
                    // twice over.
                    //
                    // It is what makes the assertion below mean anything: a
                    // completed response proves the server accepted this
                    // connection and is reading it, so "not delivered" reports
                    // on bytes the parser saw and refused rather than on a
                    // connection that was never served at all.
                    //
                    // It also closes a teardown race that used to kill the
                    // whole xctest process. `client.execute` throws for these
                    // queries, and `HummingbirdTesting`'s live framework turns
                    // that throw into cancellation of the service group rather
                    // than a graceful shutdown. A connection that the event
                    // loop has accepted but not yet delivered to the server's
                    // async inbound stream at that instant is dropped by
                    // `NIOAsyncChannelHandler._deliverReads`, taking its
                    // `NIOAsyncChannel` — and that channel's never-finished
                    // `NIOAsyncWriter` — with it; the writer's `deinit` is a
                    // `preconditionFailure`, not a test failure, so the process
                    // died with the rest of the target unrun. Completing a
                    // request first means the accept is already delivered and
                    // being served before anything can cancel.
                    //
                    // `com.example.unknown.method` is unrouted, so it answers
                    // 404 from Swan itself and leaves the recorded count below
                    // untouched.
                    try await client.execute(
                        uri: "/xrpc/com.example.unknown.method",
                        method: .get
                    ) { response in
                        XCTAssertEqual(response.status, .notFound, "for query \(query)")
                    }
                    try await client.execute(
                        uri: "/xrpc/app.bsky.feed.getAuthorFeed?" + query,
                        method: .get
                    ) { _ in
                        delivered.set()
                    }
                }
            } catch {
                // Refused by the HTTP parser before routing. Expected.
            }
            XCTAssertFalse(delivered.isSet, "expected \(query) to be refused by the HTTP parser")
            // Whichever layer refused it, nothing left this host.
            XCTAssertEqual(sender.recorded().count, 0, "for query \(query)")
        }
        // And the guard itself rejects every one of them, so a future parser
        // that did deliver them would still get a 400 rather than a crash.
        for query in [#"q="foo""#, "q=a|b", "q=a^b", "q=a`b", "q=a{b}", "q=a\\b", "q=a<b>c"] {
            XCTAssertFalse(isPercentEncodedQuery(query), query)
        }
    }

    /// The counterpart the fix must not break. `%` is legal when it introduces
    /// a valid escape, so the guard validates rather than re-encodes: an
    /// already-percent-encoded cursor has to arrive upstream byte for byte, or
    /// pagination silently breaks. Every reserved character the grammar admits
    /// is exercised alongside it.
    func testLegitimatelyPercentEncodedQueryReachesUpstreamByteIdentical() async throws {
        let sender = RecordingProxySender()
        let queries = [
            "cursor=abc%3D%3D",
            "cursor=3jui%2Fabc%3d%3D&limit=50&actor=alice.test",
            // Every unescaped octet RFC 3986 admits in a query.
            "q=!$&'()*+,;=:@/?-._~ABCyz019&e=%F0%9F%90%A6",
        ]
        try await withPipethrough(sender: sender) { client in
            for query in queries {
                try await client.execute(
                    uri: "/xrpc/app.bsky.feed.getAuthorFeed?" + query,
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .ok, "for query \(query)")
                }
            }
        }
        let recorded = sender.recorded()
        XCTAssertEqual(recorded.count, queries.count)
        for (index, query) in queries.enumerated() {
            let components = try XCTUnwrap(
                URLComponents(url: recorded[index].url, resolvingAgainstBaseURL: false)
            )
            // Byte-identical, including the case of the hex digits: the
            // upstream service must see exactly what the client sent.
            XCTAssertEqual(components.percentEncodedQuery, query)
        }
    }

    /// `Location` is not forwarded, matching the reference PDS
    /// (`atproto/packages/pds/src/pipethrough.ts:527-531`, which forwards only
    /// `atproto-repo-rev`, `atproto-content-labelers`, `retry-after` and
    /// `content-*`). The status still reaches the client, so a caller can see
    /// the 3xx; it just cannot be steered by it.
    ///
    /// The concrete risk is a *relative* `Location`: resolved against the
    /// request URL it points back at `swan.place`, so a following client sends
    /// its Swan credentials to a path a third-party upstream chose. The
    /// absolute CDN redirect below is the benign case that is lost with it —
    /// a same-host restriction would keep it, but has no principled boundary,
    /// so the whole header goes.
    ///
    /// The rest of the forwarded set stays closed, so nothing the proxy has not
    /// reasoned about reaches the client.
    func testUpstreamLocationIsNotForwardedAndNeitherAreOtherHeaders() async throws {
        let upstreamLocations = [
            // The absolute CDN case the previous version of this test was
            // written to preserve. It goes too.
            "https://cdn.bsky.app/img/feed_thumbnail/x.jpg",
            // The case that motivated the change: relative, so a client that
            // resolves it against the request URL re-enters `swan.place` with
            // Swan credentials at a path the upstream chose.
            "/xrpc/com.atproto.server.createSession",
        ]
        for location in upstreamLocations {
            let sender = RecordingProxySender(
                result: .success(
                    OAuthRemoteHTTPResponse(
                        status: 302,
                        headers: [
                            "Location": [location],
                            "Set-Cookie": ["upstream-session=leak"],
                            "Content-Type": ["text/plain"],
                        ],
                        body: Data(),
                        responseURL: URL(
                            string: "https://api.bsky.app/xrpc/app.bsky.feed.getTimeline"
                        )!
                    )
                )
            )
            try await withPipethrough(sender: sender) { client in
                try await client.execute(
                    uri: "/xrpc/app.bsky.feed.getTimeline",
                    method: .get
                ) { response in
                    // The status is still relayed: the client can see that the
                    // upstream redirected, it just cannot be steered by it.
                    XCTAssertEqual(response.status, .found)
                    XCTAssertNil(response.headers[.location], "location: \(location)")
                    XCTAssertEqual(response.headers[.contentType], "text/plain")
                    XCTAssertNil(response.headers[.setCookie])
                }
            }
            XCTAssertEqual(sender.recorded().count, 1)
        }
    }

    // MARK: Proxyable-namespace allow-list

    /// Proxyability used to mean "no local route matched and not explicitly
    /// denied". Local routes are registered conditionally, so a nil capability
    /// or an off feature flag silently widened the proxy surface — toward
    /// whatever destination the client happened to name. The gate is now an
    /// allow-list of proxyable namespaces, so a route that disappears fails
    /// closed.
    ///
    /// `com.atproto.server.resetPassword` is the review's own example, and
    /// `createSession` shows the stakes: its body carries a password.
    func testNonProxyableNamespacesAreNotForwardedEvenWithAProxyHeader() async throws {
        let sender = RecordingProxySender()
        // The attacker's DID document resolves. Without it these requests would
        // fail closed at 400 for want of an endpoint, and the test would pass
        // for a reason that has nothing to do with the allow-list.
        let documents = StubDIDDocuments(
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
        let steered: HTTPFields = {
            var headers = HTTPFields()
            headers[.contentType] = "application/json"
            headers[HTTPField.Name("atproto-proxy")!] = "did:web:attacker.example#svc"
            return headers
        }()
        try await withPipethrough(sender: sender, documents: documents) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.server.resetPassword",
                method: .post,
                headers: steered,
                body: ByteBuffer(string: #"{"token":"ABCDE-FGHIJ","password":"hunter2"}"#)
            ) { response in
                XCTAssertEqual(response.status, .notFound)
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.server.createSession",
                method: .post,
                headers: steered,
                body: ByteBuffer(string: #"{"identifier":"alice.test","password":"hunter2"}"#)
            ) { response in
                XCTAssertEqual(response.status, .notFound)
            }
            for uri in [
                "/xrpc/com.atproto.identity.resolveHandle?handle=alice.test",
                "/xrpc/com.atproto.admin.getAccountInfo?did=did:plc:x",
                "/xrpc/com.example.custom.method",
                // A near-miss on an allow-listed prefix is not a match.
                "/xrpc/app.bskyx.feed.getTimeline",
            ] {
                try await client.execute(uri: uri, method: .get, headers: steered) { response in
                    XCTAssertEqual(response.status, .notFound, "for \(uri)")
                }
            }
        }
        // Nothing — no password, no handle — left this host.
        XCTAssertEqual(sender.recorded().count, 0)
    }

    /// The allow-list closes the set of methods, not the set of destinations.
    /// A client naming an arbitrary labeler or chat service must still be
    /// proxied there: general interoperability is the point of the feature.
    func testAllowListedNamespacesStillProxyToTheNamedService() async throws {
        let sender = RecordingProxySender()
        let documents = StubDIDDocuments(
            documents: [
                "did:web:labeler.example": Data(
                    """
                    {"id":"did:web:labeler.example","service":[
                      {"id":"#atproto_labeler","type":"AtprotoLabeler",
                       "serviceEndpoint":"https://labeler.example"}]}
                    """.utf8
                ),
                "did:web:api.bsky.chat": Data(
                    """
                    {"id":"did:web:api.bsky.chat","service":[
                      {"id":"#bsky_chat","type":"BskyChatService",
                       "serviceEndpoint":"https://api.bsky.chat"}]}
                    """.utf8
                )
            ]
        )
        let labeler: HTTPFields = {
            var headers = HTTPFields()
            headers[HTTPField.Name("atproto-proxy")!] = "did:web:labeler.example#atproto_labeler"
            return headers
        }()
        let chat: HTTPFields = {
            var headers = HTTPFields()
            headers[HTTPField.Name("atproto-proxy")!] = "did:web:api.bsky.chat#bsky_chat"
            return headers
        }()
        try await withPipethrough(sender: sender, documents: documents) { client in
            try await client.execute(
                uri: "/xrpc/tools.ozone.moderation.getRepo?did=did:plc:x",
                method: .get,
                headers: labeler
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
            try await client.execute(
                uri: "/xrpc/chat.bsky.convo.listConvos",
                method: .get,
                headers: chat
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
        let recorded = sender.recorded()
        XCTAssertEqual(recorded.count, 2)
        XCTAssertEqual(recorded.first?.url.host, "labeler.example")
        XCTAssertEqual(recorded.last?.url.host, "api.bsky.chat")
    }

    /// The two lexicons the allow-list fix restores: content reports and
    /// label queries are how a client talks to a third-party labeler about
    /// moderation, and both were bare `com.atproto.*` NSIDs with no local
    /// route — collateral damage from the allow-list migration having no
    /// `com.atproto.` entry at all. They come back as exact NSIDs (see the
    /// sibling-method regression guard in `SwanXRPCProxyRoutingTests`), not a
    /// prefix, so this must keep routing to whatever service the client
    /// names, exactly like every other allow-listed namespace.
    func testModerationReportingAndLabelQueryingAreProxiedToTheNamedService() async throws {
        let sender = RecordingProxySender()
        let documents = StubDIDDocuments(
            documents: [
                "did:web:labeler.example": Data(
                    """
                    {"id":"did:web:labeler.example","service":[
                      {"id":"#atproto_labeler","type":"AtprotoLabeler",
                       "serviceEndpoint":"https://labeler.example"}]}
                    """.utf8
                )
            ]
        )
        let labeler: HTTPFields = {
            var headers = HTTPFields()
            headers[.contentType] = "application/json"
            headers[HTTPField.Name("atproto-proxy")!] = "did:web:labeler.example#atproto_labeler"
            return headers
        }()
        try await withPipethrough(sender: sender, documents: documents) { client in
            try await client.execute(
                uri: "/xrpc/com.atproto.moderation.createReport",
                method: .post,
                headers: labeler,
                body: ByteBuffer(string: #"""
                {"reasonType":"com.atproto.moderation.defs#reasonSpam",
                 "subject":{"$type":"com.atproto.admin.defs#repoRef","did":"did:plc:x"}}
                """#)
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
            try await client.execute(
                uri: "/xrpc/com.atproto.label.queryLabels?uriPatterns=at://did:plc:x/*",
                method: .get,
                headers: labeler
            ) { response in
                XCTAssertEqual(response.status, .ok)
            }
        }
        let recorded = sender.recorded()
        XCTAssertEqual(recorded.count, 2)
        XCTAssertEqual(recorded.first?.url.host, "labeler.example")
        XCTAssertEqual(recorded.last?.url.host, "labeler.example")
    }

    // MARK: Route before authenticating

    /// Swan authenticated before it routed, so every NSID this host does not
    /// implement answered 401 instead of 404 — indistinguishable, from the
    /// outside, from a credential problem. That is why the missing-route list
    /// stayed invisible: a relay, an AppView, or another PDS probing Swan
    /// anonymously saw "unauthorized" everywhere and could not report which
    /// methods were actually absent.
    ///
    /// Routing may safely run first because it is pure — no I/O, no trust
    /// decision, no credential read. The first step that opens a socket is the
    /// endpoint resolver, and that still runs after authentication (see
    /// `testAnonymousCallerStillCannotCauseAnOutboundConnection`).
    func testUnknownNSIDReturns404NotUnauthorized() async throws {
        let sender = RecordingProxySender()
        let attempts = PipethroughCallRecorder()
        // No Authorization header, modelled as the `.denied` outcome
        // `SwanOAuthResourceAuthorizer` produces for a credential-less request.
        // If routing ran after authentication these would all be 401.
        let authorizer = PipethroughAuthorizer(result: .failure(.denied), attempts: attempts)
        try await withPipethrough(sender: sender, authorizer: authorizer) { client in
            for uri in [
                "/xrpc/com.atproto.identity.resolveHandle?handle=alice.test",
                "/xrpc/com.atproto.sync.getRepoStatus?did=did:plc:x",
                "/xrpc/com.atproto.server.createSession",
                "/xrpc/com.example.unknown.method",
            ] {
                try await client.execute(uri: uri, method: .get) { response in
                    XCTAssertEqual(response.status, .notFound, "for \(uri)")
                    // The 404 is the route surface's own opaque shape, not some
                    // other layer answering by coincidence.
                    XCTAssertEqual(
                        self.body(response),
                        #"{"error":"EndpointUnavailable"}"#,
                        "for \(uri)"
                    )
                }
            }
        }
        // An unrouted NSID costs no credential work at all.
        XCTAssertEqual(attempts.count, 0)
        XCTAssertEqual(sender.recorded().count, 0)
    }

    /// `blue.catbird.*` and `com.atproto.space.*` are Swan-owned namespaces the
    /// router denies outright. Those refusals are decided from the request
    /// target alone, so they must cost no credential validation — asserted with
    /// an authorizer that would *succeed* if it were consulted, because a
    /// status-only assertion cannot tell "refused before authenticating" from
    /// "authenticated, then refused".
    func testDeniedNamespaceReturns404WithoutTouchingCredentials() async throws {
        let sender = RecordingProxySender()
        let attempts = PipethroughCallRecorder()
        let authorizer = PipethroughAuthorizer(
            result: .success(.accountOAuth(subject: Self.did, scopes: ["atproto"])),
            attempts: attempts
        )
        let steered: HTTPFields = {
            var headers = HTTPFields()
            // An explicit destination must not change the answer either.
            headers[HTTPField.Name("atproto-proxy")!] = "did:web:evil.example#atproto_pds"
            return headers
        }()
        try await withPipethrough(sender: sender, authorizer: authorizer) { client in
            for uri in [
                "/xrpc/blue.catbird.anything.here",
                "/xrpc/com.atproto.space.getSpace",
                // Denied by exact NSID rather than by prefix.
                "/xrpc/app.bsky.actor.getPreferences",
            ] {
                try await client.execute(uri: uri, method: .get, headers: steered) { response in
                    XCTAssertEqual(response.status, .notFound, "for \(uri)")
                    // The same opaque body an unrouted namespace gets: a client
                    // still cannot enumerate which namespaces Swan reserves.
                    XCTAssertEqual(
                        self.body(response),
                        #"{"error":"EndpointUnavailable"}"#,
                        "for \(uri)"
                    )
                }
            }
        }
        XCTAssertEqual(attempts.count, 0)
        XCTAssertEqual(sender.recorded().count, 0)
    }

    /// The invariant the reordering must preserve. Routing first is only sound
    /// because routing is pure; everything that reaches the network — the DID
    /// document resolver and the proxy sender — has to stay behind
    /// authentication. Both are instrumented here, and the route chosen is one
    /// that genuinely needs resolution, with a DID document that genuinely
    /// resolves, so an ordering mistake would show up as real outbound work
    /// rather than as a failure for want of an endpoint.
    func testAnonymousCallerStillCannotCauseAnOutboundConnection() async throws {
        let sender = RecordingProxySender()
        let attempts = PipethroughCallRecorder()
        let fetches = PipethroughCallRecorder()
        let documents = StubDIDDocuments(
            documents: [
                "did:web:feeds.example": Data(
                    """
                    {"id":"did:web:feeds.example","service":[
                      {"id":"#bsky_fg","type":"BskyFeedGenerator",
                       "serviceEndpoint":"https://feeds.example"}]}
                    """.utf8
                )
            ],
            fetches: fetches
        )
        let authorizer = PipethroughAuthorizer(result: .failure(.denied), attempts: attempts)
        let named: HTTPFields = {
            var headers = HTTPFields()
            headers[HTTPField.Name("atproto-proxy")!] = "did:web:feeds.example#bsky_fg"
            return headers
        }()
        try await withPipethrough(
            sender: sender,
            authorizer: authorizer,
            documents: documents
        ) { client in
            // Routable and resolvable: only authentication stands between this
            // request and an outbound socket.
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getFeedSkeleton?feed=at://x",
                method: .get,
                headers: named
            ) { response in
                XCTAssertEqual(response.status, .unauthorized)
            }
            // The default AppView route, which needs no resolution at all but
            // still reaches the sender when authenticated.
            try await client.execute(
                uri: "/xrpc/app.bsky.feed.getTimeline",
                method: .get
            ) { response in
                XCTAssertEqual(response.status, .unauthorized)
            }
            // A POST, whose body must not be buffered either.
            try await client.execute(
                uri: "/xrpc/app.bsky.notification.updateSeen",
                method: .post,
                headers: [.contentType: "application/json"],
                body: ByteBuffer(string: #"{"seenAt":"2026-08-12T00:00:00Z"}"#)
            ) { response in
                XCTAssertEqual(response.status, .unauthorized)
            }
        }
        // Authentication really was reached and really did refuse: these are
        // proxyable namespaces, so routing let them through to the authorizer
        // rather than 404ing them for an unrelated reason.
        XCTAssertEqual(attempts.count, 3)
        // And nothing outbound happened. The resolver is the first step that
        // opens a socket in production; it never ran, nor did the sender.
        XCTAssertEqual(fetches.count, 0)
        XCTAssertEqual(sender.recorded().count, 0)
    }

    /// The same reordering, measured through the real production router rather
    /// than through a router carrying only this capability.
    ///
    /// This is the shape that actually matters operationally: the reason Swan's
    /// missing-route list was invisible is that an anonymous prober — a relay,
    /// an AppView, another PDS, an operator with `curl` — got 401 from
    /// `buildRouter()`'s composed surface. A capability-only test cannot show
    /// that, because it cannot show the fallback still being reached after
    /// every local registration has had its chance.
    func testProductionRouterAnswers404NotUnauthorizedToAnAnonymousProbe() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanXRPCPipethroughAnonymousProbe-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x3E, count: 32)
            )
            let sender = RecordingProxySender()
            let attempts = PipethroughCallRecorder()
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
                actorPreferencesXRPC: SwanActorPreferencesXRPCServer(
                    authorizer: PipethroughAuthorizer(
                        result: .success(
                            .accountOAuth(subject: Self.did, scopes: ["atproto"])
                        )
                    ),
                    store: control
                ),
                // Anonymous: the pipethrough authorizer refuses everything.
                xrpcPipethrough: try makeCapability(
                    sender: sender,
                    authorizer: PipethroughAuthorizer(
                        result: .failure(.denied),
                        attempts: attempts
                    )
                )
            )
            let app = server.buildApplication(
                logger: Logger(label: "SwanXRPCPipethroughTests.anonymous-probe")
            )
            try await app.test(.live) { client in
                // Methods nothing in the composed router implements. Every one
                // of these answered 401 before routing moved ahead of
                // authentication.
                for uri in [
                    "/xrpc/com.atproto.identity.resolveHandle?handle=alice.test",
                    "/xrpc/com.atproto.server.createSession",
                    "/xrpc/com.atproto.admin.getAccountInfo?did=did:plc:x",
                    "/xrpc/com.atproto.temp.checkSignupQueue",
                    "/xrpc/com.example.unknown.method",
                ] {
                    try await client.execute(uri: uri, method: .get) { response in
                        XCTAssertEqual(response.status, .notFound, "for \(uri)")
                    }
                }
                // The counterpart: a namespace Swan really does proxy still
                // demands credentials, so this is not a blanket 404.
                try await client.execute(
                    uri: "/xrpc/app.bsky.feed.getTimeline",
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
            }
            // Exactly one of the six probes was proxyable enough to reach the
            // authorizer at all; the other five were answered from the request
            // target alone.
            XCTAssertEqual(attempts.count, 1)
            XCTAssertEqual(sender.recorded().count, 0)
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
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
                // The attacker's document resolves, so a fail-open route
                // really would reach the sender rather than stalling at a
                // 400 for want of an endpoint.
                xrpcPipethrough: try makeCapability(
                    sender: sender,
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
                )
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
                // An NSID nothing in the production router claims must still
                // not become proxyable. `com.atproto.server.createSession` has
                // no local registration at all here, so before the
                // proxyable-namespace allow-list a client could steer it — and
                // the password in its body — at any service it named.
                var steered = HTTPFields()
                steered[.contentType] = "application/json"
                steered[HTTPField.Name("atproto-proxy")!] = "did:web:attacker.example#svc"
                try await client.execute(
                    uri: "/xrpc/com.atproto.server.createSession",
                    method: .post,
                    headers: steered,
                    body: ByteBuffer(
                        string: #"{"identifier":"alice.test","password":"hunter2"}"#
                    )
                ) { response in
                    XCTAssertEqual(response.status, .notFound)
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

/// Counts how many times a test double was consulted, from inside a
/// `@Sendable` handler. `PipethroughFlag`'s counting sibling: a boolean cannot
/// distinguish "never reached" from "reached once", and the ordering tests
/// below turn on exactly that distinction.
private final class PipethroughCallRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    func record() {
        lock.lock()
        value += 1
        lock.unlock()
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

/// A one-way flag settable from inside a `@Sendable` response assertion.
private final class PipethroughFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    func set() {
        lock.lock()
        value = true
        lock.unlock()
    }

    var isSet: Bool {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

// MARK: - Doubles

private struct PipethroughAuthorizer:
    SwanXRPCPipethroughResourceAuthorizing,
    SwanActorPreferencesResourceAuthorizing
{
    let result: Result<AuthorizationContext, SwanResourceAuthorizationFailure>
    /// Counts `authorizePipethrough` calls only. Several tests turn on the
    /// authorizer never being consulted at all, which is not the same claim as
    /// "it was consulted and refused" — the status code alone cannot tell the
    /// two apart, because both end at a 404 for a denied namespace.
    let attempts: PipethroughCallRecorder

    init(
        result: Result<AuthorizationContext, SwanResourceAuthorizationFailure>,
        attempts: PipethroughCallRecorder = PipethroughCallRecorder()
    ) {
        self.result = result
        self.attempts = attempts
    }

    func authorizePipethrough(
        request: Request,
        method: String,
        fixedPath: String,
        now: Date
    ) async throws -> AuthorizationContext {
        attempts.record()
        return try result.get()
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
    /// Resolution is the first step in the handler that would open a socket in
    /// production, so "was the resolver reached" is the observable proxy for
    /// "did an anonymous caller cause outbound work".
    let fetches: PipethroughCallRecorder

    init(documents: [String: Data], fetches: PipethroughCallRecorder = PipethroughCallRecorder()) {
        self.documents = documents
        self.fetches = fetches
    }

    func documentJSON(forDID did: String) async throws -> Data {
        fetches.record()
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
