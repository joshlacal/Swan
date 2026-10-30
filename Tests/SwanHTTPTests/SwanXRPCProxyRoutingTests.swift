@testable import SwanHTTP
import XCTest

final class SwanXRPCProxyRoutingTests: XCTestCase {
    private let router = SwanXRPCProxyRouter(
        appViewDID: "did:web:api.bsky.app",
        appViewServiceFragment: "bsky_appview"
    )

    func testAppBskyDefaultsToConfiguredAppView() throws {
        let route = try router.route(nsid: "app.bsky.actor.getProfile", proxyHeader: nil)
        XCTAssertEqual(route, .configuredAppView(did: "did:web:api.bsky.app"))
    }

    func testSwanOwnedNamespacesAreDeniedEvenWithoutLocalRoute() {
        for nsid in [
            "com.atproto.space.listSpaces",
            "com.atproto.memberspace.listMembers",
            "com.atproto.managedspace.checkUserAccess",
            "com.atproto.personalspace.anything",
            "com.atproto.simplespace.getSpace",
            "blue.catbird.mlsChat.getConvos",
        ] {
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

    /// The configured-endpoint shortcut is keyed on the whole service
    /// reference, not just the DID. A client naming a *different* service at
    /// the AppView's DID asked for that service, and must not be silently
    /// handed the AppView: it takes the resolve path, where the DID document
    /// decides (and a missing entry becomes a 400 at the HTTP boundary).
    func testDifferentFragmentAtTheAppViewDIDIsNotTheConfiguredAppView() throws {
        let route = try router.route(
            nsid: "app.bsky.actor.getProfile",
            proxyHeader: "did:web:api.bsky.app#atproto_labeler"
        )
        XCTAssertEqual(
            route,
            .resolvedService(did: "did:web:api.bsky.app", fragment: "atproto_labeler")
        )
    }

    /// And the shortcut still requires the DID to match: the same fragment at
    /// another DID is a different service.
    func testConfiguredFragmentAtAnotherDIDIsNotTheConfiguredAppView() throws {
        let route = try router.route(
            nsid: "app.bsky.actor.getProfile",
            proxyHeader: "did:web:other.example#bsky_appview"
        )
        XCTAssertEqual(
            route,
            .resolvedService(did: "did:web:other.example", fragment: "bsky_appview")
        )
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

    /// Proxyability must be an allow-list, not "whatever no local route
    /// claimed". Local routes are registered conditionally, so a nil capability
    /// or an off feature flag used to widen the proxy surface silently — and it
    /// widened it toward whatever destination the client named.
    func testNonProxyableNamespacesAreUnroutedEvenWithAnExplicitProxyHeader() {
        for nsid in [
            "com.atproto.server.resetPassword",
            "com.atproto.server.createSession",
            "com.atproto.identity.resolveHandle",
            "com.atproto.admin.deleteAccount",
            "com.example.custom.method",
            // A near-miss on an allow-listed prefix must not squeak through.
            "app.bskyx.feed.getTimeline",
            "tools.ozonex.moderation.emitEvent",
        ] {
            XCTAssertThrowsError(
                try router.route(nsid: nsid, proxyHeader: "did:web:attacker.example#atproto_pds"),
                "expected \(nsid) to be unrouted"
            ) { error in
                XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .unrouted, nsid)
            }
        }
    }

    /// The allow-list closes the set of *methods*, not the set of services:
    /// naming an arbitrary labeler, feed generator, or chat service is the
    /// whole point of `atproto-proxy` and must keep working.
    func testAllowListedNamespacesStillProxyToArbitraryServices() throws {
        let cases: [(nsid: String, header: String, expected: SwanXRPCProxyRoute)] = [
            (
                "tools.ozone.moderation.emitEvent",
                "did:web:labeler.example#atproto_labeler",
                .resolvedService(did: "did:web:labeler.example", fragment: "atproto_labeler")
            ),
            (
                "chat.bsky.convo.listConvos",
                "did:web:api.bsky.chat#bsky_chat",
                .resolvedService(did: "did:web:api.bsky.chat", fragment: "bsky_chat")
            ),
            (
                "app.bsky.feed.getFeedSkeleton",
                "did:web:feeds.example#bsky_fg",
                .resolvedService(did: "did:web:feeds.example", fragment: "bsky_fg")
            ),
        ]
        for item in cases {
            XCTAssertEqual(
                try router.route(nsid: item.nsid, proxyHeader: item.header),
                item.expected,
                item.nsid
            )
        }
    }

    /// Restores the two lexicons a client proxies to a third-party labeler:
    /// reporting content and reading label state. Exact NSIDs, never a
    /// `com.atproto.` (or `com.atproto.moderation.`/`com.atproto.label.`)
    /// prefix — that would reopen the `createSession` hazard the allow-list
    /// exists to close.
    func testModerationReportingAndLabelQueryingAreExactlyAllowed() throws {
        for nsid in ["com.atproto.moderation.createReport", "com.atproto.label.queryLabels"] {
            XCTAssertEqual(
                try router.route(
                    nsid: nsid,
                    proxyHeader: "did:web:labeler.example#atproto_labeler"
                ),
                .resolvedService(did: "did:web:labeler.example", fragment: "atproto_labeler"),
                nsid
            )
        }
    }

    /// A sibling method in the same two namespaces must stay unrouted: the
    /// addition above is two exact NSIDs, not a `com.atproto.moderation.` or
    /// `com.atproto.label.` prefix.
    func testSiblingModerationAndLabelMethodsRemainUnrouted() {
        for nsid in ["com.atproto.moderation.createReportBatch", "com.atproto.label.subscribeLabels"] {
            XCTAssertThrowsError(
                try router.route(
                    nsid: nsid,
                    proxyHeader: "did:web:labeler.example#atproto_labeler"
                ),
                "expected \(nsid) to be unrouted"
            ) { error in
                XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .unrouted, nsid)
            }
        }
    }

    /// The deny-list still runs first, so an allow-listed namespace's
    /// Swan-owned exceptions report `.denied`, not `.unrouted`.
    func testDenyListStillPrecedesTheAllowList() {
        XCTAssertThrowsError(
            try router.route(
                nsid: "app.bsky.actor.putPreferences",
                proxyHeader: "did:web:attacker.example#atproto_pds"
            )
        ) { error in
            XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .denied)
        }
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
