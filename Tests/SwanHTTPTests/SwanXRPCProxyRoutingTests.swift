@testable import SwanHTTP
import XCTest

final class SwanXRPCProxyRoutingTests: XCTestCase {
    private let router = SwanXRPCProxyRouter(appViewDID: "did:web:api.bsky.app")

    func testAppBskyDefaultsToConfiguredAppView() throws {
        let route = try router.route(nsid: "app.bsky.actor.getProfile", proxyHeader: nil)
        XCTAssertEqual(route, .configuredAppView(did: "did:web:api.bsky.app"))
    }

    func testSwanOwnedNamespacesAreDeniedEvenWithoutLocalRoute() {
        for nsid in ["com.atproto.space.listSpaces", "blue.catbird.mlsChat.getConvos"] {
            XCTAssertThrowsError(try router.route(nsid: nsid, proxyHeader: nil)) { error in
                XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .denied)
            }
        }
    }

    /// Preferences are PDS state the AppView does not store. Proxying them
    /// would discard the write *and* disclose the account's saved feeds,
    /// content-label settings, and muted words to a third party.
    func testActorPreferencesAreDeniedEvenThoughAppBskyIsProxied() {
        for nsid in ["app.bsky.actor.getPreferences", "app.bsky.actor.putPreferences"] {
            XCTAssertThrowsError(try router.route(nsid: nsid, proxyHeader: nil)) { error in
                XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .denied, nsid)
            }
            // And an explicit proxy header must not override it either.
            XCTAssertThrowsError(
                try router.route(nsid: nsid, proxyHeader: "did:web:evil.example#atproto_pds")
            ) { error in
                XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .denied, nsid)
            }
        }
    }

    /// The exact-match deny entries must not become a `app.bsky.actor.` prefix:
    /// every other method in that namespace is genuinely AppView-owned.
    func testSiblingActorMethodsStillReachTheAppView() throws {
        for nsid in [
            "app.bsky.actor.getProfile",
            "app.bsky.actor.searchActors",
            "app.bsky.actor.getPreferencesExtended",
        ] {
            XCTAssertEqual(
                try router.route(nsid: nsid, proxyHeader: nil),
                .configuredAppView(did: "did:web:api.bsky.app"),
                nsid
            )
        }
    }

    func testDenyListWinsOverExplicitProxyHeader() {
        XCTAssertThrowsError(
            try router.route(
                nsid: "com.atproto.space.listSpaces",
                proxyHeader: "did:web:evil.example#bsky_appview"
            )
        ) { error in
            XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .denied)
        }
    }

    func testOzoneAndUnknownNamespacesAreUnrouted() {
        for nsid in ["tools.ozone.moderation.emitEvent", "com.example.custom.method"] {
            XCTAssertThrowsError(try router.route(nsid: nsid, proxyHeader: nil)) { error in
                XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .unrouted)
            }
        }
    }

    func testExplicitProxyHeaderNamingConfiguredAppViewSkipsResolution() throws {
        let route = try router.route(
            nsid: "app.bsky.actor.getProfile",
            proxyHeader: "did:web:api.bsky.app#bsky_appview"
        )
        XCTAssertEqual(route, .configuredAppView(did: "did:web:api.bsky.app"))
    }

    func testExplicitProxyHeaderForOtherServiceRequiresResolution() throws {
        let route = try router.route(
            nsid: "app.bsky.actor.getProfile",
            proxyHeader: "did:web:labeler.example#atproto_labeler"
        )
        XCTAssertEqual(
            route, .resolvedService(did: "did:web:labeler.example", fragment: "atproto_labeler")
        )
    }

    /// An explicit header for a lexicon that has no default route is still honoured:
    /// the client asked for a specific service, so "unrouted" does not apply.
    func testExplicitProxyHeaderHonouredForOtherwiseUnroutedLexicon() throws {
        let route = try router.route(
            nsid: "tools.ozone.moderation.emitEvent",
            proxyHeader: "did:web:mod.example#atproto_labeler"
        )
        XCTAssertEqual(route, .resolvedService(did: "did:web:mod.example", fragment: "atproto_labeler"))
    }

    func testMalformedProxyHeaderIsRejectedAndNeverFallsBack() {
        // Each of these must fail closed rather than silently using the AppView.
        let malformed = [
            "", // empty
            "did:web:api.bsky.app", // no fragment
            "#bsky_appview", // no DID
            "did:web:api.bsky.app#", // empty fragment
            "not-a-did#bsky_appview", // not a DID
            "did:web:api.bsky.app#a#b", // two fragments
            "did:web:api.bsky.app #frag", // whitespace
        ]
        for header in malformed {
            XCTAssertThrowsError(
                try router.route(nsid: "app.bsky.actor.getProfile", proxyHeader: header),
                "expected rejection for \(header)"
            ) { error in
                XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .malformedProxyHeader)
            }
        }
    }
}
