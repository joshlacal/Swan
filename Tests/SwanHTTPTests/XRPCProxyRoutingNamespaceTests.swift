import XCTest

@testable import SwanHTTP
@testable import SwanStorage

/// Admission is by namespace, not by membership in the generated method
/// registry. The registry is derived from a pinned lexicon tree that trails
/// upstream, and a stale pin must not shrink what this host forwards.
final class XRPCProxyRoutingNamespaceTests: XCTestCase {
    private let router = SwanXRPCProxyRouter(
        appViewDID: "did:web:api.bsky.app",
        appViewServiceFragment: "bsky_appview"
    )
    private let chatProxy = "did:web:api.bsky.chat#bsky_chat"

    func testAnExplicitlyProxiedMethodMissingFromThePinnedRegistryIsStillForwarded() throws {
        // Observed live: bsky.app asked for this and got a 404 because the
        // pinned lexicons predate the method. It is published upstream and
        // lives at the chat service, which the client named.
        XCTAssertNil(GeneratedLegacyMethodRegistry.routing["chat.bsky.convo.getUnreadCounts"])
        XCTAssertEqual(
            try router.route(nsid: "chat.bsky.convo.getUnreadCounts", proxyHeader: chatProxy),
            .resolvedService(did: "did:web:api.bsky.chat", fragment: "bsky_chat")
        )
        // Same for AppView methods newer than the pin, with and without a header.
        XCTAssertNil(GeneratedLegacyMethodRegistry.routing["app.bsky.video.getUploadStatus"])
        XCTAssertEqual(
            try router.route(nsid: "app.bsky.video.getUploadStatus", proxyHeader: nil),
            .configuredAppView(did: "did:web:api.bsky.app")
        )
    }

    func testTheCredentialBearingNamespaceStaysUnroutedEvenWhenNamed() throws {
        // The hazard the allow-list exists to close: a local route vanishing
        // and its NSID becoming forwardable, with the account's password in the
        // body. `com.atproto.*` is outside every proxyable prefix.
        for nsid in [
            "com.atproto.server.createSession",
            "com.atproto.server.refreshSession",
            "com.atproto.server.resetPassword",
            "com.atproto.repo.uploadBlob",
            "com.atproto.identity.resolveHandle",
        ] {
            XCTAssertThrowsError(
                try router.route(nsid: nsid, proxyHeader: "did:web:attacker.example#svc"),
                "\(nsid) must never be forwardable"
            ) { error in
                XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .unrouted)
            }
        }
    }

    func testSwanOwnedNamespacesAndMethodsStayDenied() throws {
        for nsid in ["com.atproto.space.getSpace", "blue.catbird.mlsChat.getConvos"] {
            XCTAssertThrowsError(try router.route(nsid: nsid, proxyHeader: chatProxy)) { error in
                XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .denied)
            }
        }
        // Preferences are PDS state: forwarding them would discard the write
        // and disclose saved feeds and muted words to a third party.
        for nsid in ["app.bsky.actor.getPreferences", "app.bsky.actor.putPreferences"] {
            XCTAssertThrowsError(try router.route(nsid: nsid, proxyHeader: nil)) { error in
                XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .denied)
            }
        }
    }

    func testNamespacesAtOtherServicesRequireAnExplicitDestination() throws {
        // `chat.bsky.` and `tools.ozone.` do not live at the AppView, so
        // without a header there is nowhere to send them.
        for nsid in ["chat.bsky.convo.listConvos", "tools.ozone.report.getReport"] {
            XCTAssertThrowsError(try router.route(nsid: nsid, proxyHeader: nil)) { error in
                XCTAssertEqual(error as? SwanXRPCProxyRoutingFailure, .unrouted)
            }
        }
        XCTAssertEqual(
            try router.route(nsid: "tools.ozone.report.getReport", proxyHeader: chatProxy),
            .resolvedService(did: "did:web:api.bsky.chat", fragment: "bsky_chat")
        )
    }

    func testTheConfiguredAppViewShortcutStillNeedsTheExactService() throws {
        XCTAssertEqual(
            try router.route(
                nsid: "app.bsky.feed.getTimeline", proxyHeader: "did:web:api.bsky.app#bsky_appview"),
            .configuredAppView(did: "did:web:api.bsky.app")
        )
        // Same DID, different fragment: the DID document decides, not the
        // configured endpoint.
        XCTAssertEqual(
            try router.route(
                nsid: "app.bsky.feed.getTimeline",
                proxyHeader: "did:web:api.bsky.app#atproto_labeler"),
            .resolvedService(did: "did:web:api.bsky.app", fragment: "atproto_labeler")
        )
    }

    func testAMalformedProxyHeaderIsRefusedRatherThanDefaulted() throws {
        for header in ["did:web:api.bsky.chat", "#bsky_chat", "not-a-did#frag", "a#b#c", ""] {
            XCTAssertThrowsError(
                try router.route(nsid: "chat.bsky.convo.listConvos", proxyHeader: header)
            ) { error in
                XCTAssertEqual(
                    error as? SwanXRPCProxyRoutingFailure, .malformedProxyHeader,
                    "header \(header.debugDescription) must not fall back to a default route"
                )
            }
        }
    }
}
