import Foundation
import NIOHTTP1
import SwanCore
import XCTest

@testable import SwanOAuth

private actor RecordingTransport: SwanProxyTransporting {
    private(set) var approved: Set<OAuthIPAddress> = []
    private(set) var sent: SwanProxyRequest?
    private let overrideResponse: OAuthRemoteHTTPResponse?

    init(overrideResponse: OAuthRemoteHTTPResponse? = nil) {
        self.overrideResponse = overrideResponse
    }

    func send(
        _ request: SwanProxyRequest, approvedPeers: Set<OAuthIPAddress>,
        timeout _: TimeInterval, maximumBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        approved = approvedPeers
        sent = request
        if let overrideResponse {
            return overrideResponse
        }
        let chosenPeer = approvedPeers.sorted(by: { $0.description < $1.description }).first
        return OAuthRemoteHTTPResponse(
            status: 200,
            headers: [:],
            body: Data("{}".utf8),
            responseURL: request.url,
            connectedPeerAddress: chosenPeer
        )
    }

    func recorded() -> (Set<OAuthIPAddress>, SwanProxyRequest?) {
        (approved, sent)
    }
}

private struct StubResolver: OAuthHostnameResolving {
    let addresses: [OAuthIPAddress]
    func resolve(host _: String) async throws -> [OAuthIPAddress] {
        addresses
    }
}

/// Stands in for an attacker-controlled authoritative nameserver that accepts
/// the query and never answers.
private struct BlackholedResolver: OAuthHostnameResolving {
    func resolve(host _: String) async throws -> [OAuthIPAddress] {
        try await Task.sleep(nanoseconds: 5_000_000_000)
        return [OAuthIPAddress(literal: "93.184.216.34")!]
    }
}

final class SwanProxyHTTPTransportTests: XCTestCase {
    private func sender(
        resolving addresses: [String], transport: any SwanProxyTransporting
    ) throws -> SwanPeerPinnedProxySender {
        try SwanPeerPinnedProxySender(
            policy: OAuthRemoteFetchPolicy(),
            resolver: StubResolver(addresses: addresses.compactMap(OAuthIPAddress.init(literal:))),
            transport: transport
        )
    }

    func testPinsResolvedPublicAddress() async throws {
        let transport = RecordingTransport()
        let sender = try sender(resolving: ["93.184.216.34"], transport: transport)
        _ = try await sender.send(
            SwanProxyRequest(
                method: "GET", url: URL(string: "https://api.bsky.app/xrpc/app.bsky.actor.getProfile")!,
                headers: [], body: nil
            ),
            timeout: 5, maximumBodyBytes: 1_000_000
        )
        let (approved, sent) = await transport.recorded()
        XCTAssertEqual(approved, Set([OAuthIPAddress(literal: "93.184.216.34")!]))
        XCTAssertEqual(sent?.method, "GET")
    }

    /// The pipethrough lease is held across `send`, so an unbounded blocking
    /// resolve holds that lease past every advertised deadline. Resolution has
    /// to be bounded by the same policy deadline the transport uses.
    func testHostnameResolutionIsBoundedByThePolicyDeadline() async throws {
        let sender = try SwanPeerPinnedProxySender(
            policy: OAuthRemoteFetchPolicy(timeout: 0.25),
            resolver: BlackholedResolver(),
            transport: RecordingTransport()
        )
        let clock = ContinuousClock()
        let started = clock.now
        do {
            _ = try await sender.send(
                SwanProxyRequest(
                    method: "GET",
                    url: URL(string: "https://blackholed.example/xrpc/app.bsky.actor.getProfile")!,
                    headers: [], body: nil
                ),
                timeout: 5, maximumBodyBytes: 1_000_000
            )
            XCTFail("a blackholed resolver must not produce a proxied request")
        } catch let error as SwanError {
            guard case .unavailable = error else {
                return XCTFail("expected typed unavailable, got \(error)")
            }
        }
        XCTAssertLessThan(
            clock.now - started,
            .seconds(2),
            "the proxy lease must be released on the policy deadline"
        )
    }

    func testRejectsPrivateAndReservedAddresses() async throws {
        // Each of these must fail closed: a hostile service DID whose DNS answers
        // with an internal address must never be connected to.
        for address in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1"] {
            let transport = RecordingTransport()
            let sender = try sender(resolving: [address], transport: transport)
            do {
                _ = try await sender.send(
                    SwanProxyRequest(
                        method: "GET", url: URL(string: "https://evil.example/xrpc/x")!, headers: [], body: nil
                    ),
                    timeout: 5, maximumBodyBytes: 1_000
                )
                XCTFail("expected rejection for \(address)")
            } catch {}
            let (_, sent) = await transport.recorded()
            XCTAssertNil(sent, "transport must never be reached for \(address)")
        }
    }

    func testRejectsNonHTTPSURL() async throws {
        let sender = try sender(resolving: ["93.184.216.34"], transport: RecordingTransport())
        do {
            _ = try await sender.send(
                SwanProxyRequest(
                    method: "GET", url: URL(string: "http://api.bsky.app/xrpc/x")!, headers: [], body: nil
                ),
                timeout: 5, maximumBodyBytes: 1_000
            )
            XCTFail("expected rejection")
        } catch {}
    }

    func testRejectsUnsupportedMethod() async throws {
        let sender = try sender(resolving: ["93.184.216.34"], transport: RecordingTransport())
        for method in ["DELETE", "PUT", "CONNECT"] {
            do {
                _ = try await sender.send(
                    SwanProxyRequest(
                        method: method, url: URL(string: "https://api.bsky.app/xrpc/x")!, headers: [],
                        body: nil
                    ),
                    timeout: 5, maximumBodyBytes: 1_000
                )
                XCTFail("expected rejection for \(method)")
            } catch {}
        }
    }

    // MARK: - NIO transport connection plan

    /// The security property the whole transport exists for: the TCP peer is a
    /// policy-approved *literal*, while TLS SNI stays the URL hostname so
    /// certificate name verification is unchanged.
    func testConnectionPlanPinsLiteralPeerAndKeepsHostnameSNI() throws {
        let peers = Set([
            OAuthIPAddress(literal: "93.184.216.34")!,
            OAuthIPAddress(literal: "23.192.228.84")!,
        ])
        let plan = try SwanNIOPeerPinnedProxyTransport.makeConnectionPlan(
            request: SwanProxyRequest(
                method: "GET",
                url: URL(string: "https://api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=did%3Aplc%3Aabc")!,
                headers: [("authorization", "Bearer token")],
                body: nil
            ),
            approvedPeers: peers,
            timeout: 5,
            maximumTransportTimeout: 15,
            maximumRequestBodyBytes: 1_048_576,
            maximumBodyBytes: 1_048_576
        )
        // Deterministic selection: lowest-sorted literal.
        XCTAssertEqual(plan.peer, OAuthIPAddress(literal: "23.192.228.84")!)
        XCTAssertEqual(plan.peer.description, "23.192.228.84")
        // SNI/cert verification is still bound to the hostname, never the pin.
        XCTAssertEqual(plan.sniHostname, "api.bsky.app")
        XCTAssertNotEqual(plan.sniHostname, plan.peer.description)
        XCTAssertEqual(plan.port, 443)
        XCTAssertEqual(plan.scheme, "https")
        XCTAssertEqual(plan.method, HTTPMethod.GET)
        // Percent-encoding of the query survives proxying verbatim.
        XCTAssertEqual(plan.uri, "/xrpc/app.bsky.actor.getProfile?actor=did%3Aplc%3Aabc")
        XCTAssertEqual(plan.headers.first(name: "host"), "api.bsky.app")
        XCTAssertEqual(plan.headers.first(name: "authorization"), "Bearer token")
        XCTAssertEqual(plan.headers["content-length"], ["0"])
        XCTAssertEqual(plan.headers["connection"], ["close"])
    }

    func testConnectionPlanCarriesPOSTBodyAndFramesContentLength() throws {
        let body = Data(#"{"actor":"did:plc:abc"}"#.utf8)
        let plan = try SwanNIOPeerPinnedProxyTransport.makeConnectionPlan(
            request: SwanProxyRequest(
                method: "POST",
                url: URL(string: "https://api.bsky.app/xrpc/app.bsky.graph.muteActor")!,
                headers: [("content-type", "application/json")],
                body: body
            ),
            approvedPeers: [OAuthIPAddress(literal: "93.184.216.34")!],
            timeout: 5,
            maximumTransportTimeout: 15,
            maximumRequestBodyBytes: 1_048_576,
            maximumBodyBytes: 1_048_576
        )
        XCTAssertEqual(plan.method, HTTPMethod.POST)
        XCTAssertEqual(plan.body, body)
        XCTAssertEqual(plan.headers["content-length"], [String(body.count)])
        XCTAssertEqual(plan.headers.first(name: "content-type"), "application/json")
    }

    func testConnectionPlanDropsCallerFramingAndHopByHopHeaders() throws {
        let plan = try SwanNIOPeerPinnedProxyTransport.makeConnectionPlan(
            request: SwanProxyRequest(
                method: "POST",
                url: URL(string: "https://api.bsky.app/xrpc/app.bsky.graph.muteActor")!,
                headers: [
                    ("Host", "evil.example"),
                    ("Content-Length", "999999"),
                    ("Transfer-Encoding", "chunked"),
                    ("Connection", "keep-alive"),
                    ("Proxy-Connection", "keep-alive"),
                    ("Upgrade", "websocket"),
                    ("TE", "trailers"),
                    ("Accept", "application/json"),
                ],
                body: Data("{}".utf8)
            ),
            approvedPeers: [OAuthIPAddress(literal: "93.184.216.34")!],
            timeout: 5,
            maximumTransportTimeout: 15,
            maximumRequestBodyBytes: 1_048_576,
            maximumBodyBytes: 1_048_576
        )
        XCTAssertEqual(plan.headers["host"], ["api.bsky.app"])
        XCTAssertEqual(plan.headers["content-length"], ["2"])
        XCTAssertEqual(plan.headers["connection"], ["close"])
        XCTAssertTrue(plan.headers["transfer-encoding"].isEmpty)
        XCTAssertTrue(plan.headers["proxy-connection"].isEmpty)
        XCTAssertTrue(plan.headers["upgrade"].isEmpty)
        XCTAssertTrue(plan.headers["te"].isEmpty)
        XCTAssertEqual(plan.headers.first(name: "accept"), "application/json")
    }

    func testConnectionPlanRejectsHeaderInjectionAndBadNames() throws {
        let injections: [(String, String)] = [
            ("x-evil", "value\r\nX-Injected: 1"),
            ("x-evil", "value\nX-Injected: 1"),
            ("x-ev\r\nil", "value"),
            ("x evil", "value"),
            ("", "value"),
        ]
        for header in injections {
            XCTAssertThrowsError(
                try SwanNIOPeerPinnedProxyTransport.makeConnectionPlan(
                    request: SwanProxyRequest(
                        method: "GET", url: URL(string: "https://api.bsky.app/xrpc/x")!,
                        headers: [header], body: nil
                    ),
                    approvedPeers: [OAuthIPAddress(literal: "93.184.216.34")!],
                    timeout: 5,
                    maximumTransportTimeout: 15,
                    maximumRequestBodyBytes: 1_048_576,
                    maximumBodyBytes: 1_048_576
                ),
                "expected rejection for header \(header)"
            )
        }
    }

    func testConnectionPlanRejectsUnsupportedMethodsAndUnpinnedRequests() throws {
        let url = URL(string: "https://api.bsky.app/xrpc/x")!
        let peer = OAuthIPAddress(literal: "93.184.216.34")!

        for method in ["DELETE", "PUT", "CONNECT", "get", "post"] {
            XCTAssertThrowsError(
                try SwanNIOPeerPinnedProxyTransport.makeConnectionPlan(
                    request: SwanProxyRequest(method: method, url: url, headers: [], body: nil),
                    approvedPeers: [peer], timeout: 5, maximumTransportTimeout: 15,
                    maximumRequestBodyBytes: 1_048_576, maximumBodyBytes: 1_048_576
                ),
                "expected rejection for method \(method)"
            )
        }

        // No approved peers at all: the transport must never fall back to a
        // hostname connect (that is the DNS-rebinding hole this design closes).
        XCTAssertThrowsError(
            try SwanNIOPeerPinnedProxyTransport.makeConnectionPlan(
                request: SwanProxyRequest(method: "GET", url: url, headers: [], body: nil),
                approvedPeers: [], timeout: 5, maximumTransportTimeout: 15,
                maximumRequestBodyBytes: 1_048_576, maximumBodyBytes: 1_048_576
            )
        )

        // Plaintext, credentials in the URL, and fragments are all refused.
        for raw in [
            "http://api.bsky.app/xrpc/x",
            "https://user:pass@api.bsky.app/xrpc/x",
            "https://api.bsky.app/xrpc/x#fragment",
        ] {
            XCTAssertThrowsError(
                try SwanNIOPeerPinnedProxyTransport.makeConnectionPlan(
                    request: SwanProxyRequest(
                        method: "GET", url: URL(string: raw)!, headers: [], body: nil
                    ),
                    approvedPeers: [peer], timeout: 5, maximumTransportTimeout: 15,
                    maximumRequestBodyBytes: 1_048_576, maximumBodyBytes: 1_048_576
                ),
                "expected rejection for \(raw)"
            )
        }

        // A GET must not carry a request body, and a POST body must stay bounded.
        XCTAssertThrowsError(
            try SwanNIOPeerPinnedProxyTransport.makeConnectionPlan(
                request: SwanProxyRequest(
                    method: "GET", url: url, headers: [], body: Data("{}".utf8)
                ),
                approvedPeers: [peer], timeout: 5, maximumTransportTimeout: 15,
                maximumRequestBodyBytes: 1_048_576, maximumBodyBytes: 1_048_576
            )
        )
        XCTAssertThrowsError(
            try SwanNIOPeerPinnedProxyTransport.makeConnectionPlan(
                request: SwanProxyRequest(
                    method: "POST", url: url, headers: [], body: Data(repeating: 0x20, count: 33)
                ),
                approvedPeers: [peer], timeout: 5, maximumTransportTimeout: 15,
                maximumRequestBodyBytes: 32, maximumBodyBytes: 1_048_576
            )
        )
    }

    func testConnectionPlanRejectsOutOfRangeBounds() throws {
        let url = URL(string: "https://api.bsky.app/xrpc/x")!
        let peer = OAuthIPAddress(literal: "93.184.216.34")!
        func plan(timeout: TimeInterval, maximumBodyBytes: Int) throws {
            _ = try SwanNIOPeerPinnedProxyTransport.makeConnectionPlan(
                request: SwanProxyRequest(method: "GET", url: url, headers: [], body: nil),
                approvedPeers: [peer], timeout: timeout, maximumTransportTimeout: 15,
                maximumRequestBodyBytes: 1_048_576, maximumBodyBytes: maximumBodyBytes
            )
        }
        XCTAssertThrowsError(try plan(timeout: 0, maximumBodyBytes: 1_024))
        XCTAssertThrowsError(try plan(timeout: 16, maximumBodyBytes: 1_024))
        XCTAssertThrowsError(try plan(timeout: .infinity, maximumBodyBytes: 1_024))
        XCTAssertThrowsError(try plan(timeout: 5, maximumBodyBytes: 0))
        XCTAssertNoThrow(try plan(timeout: 5, maximumBodyBytes: 1_024))
    }

    func testConnectionPlanUsesExplicitPortAndPortedHostHeader() throws {
        let plan = try SwanNIOPeerPinnedProxyTransport.makeConnectionPlan(
            request: SwanProxyRequest(
                method: "GET", url: URL(string: "https://api.bsky.app:8443/xrpc/x")!,
                headers: [], body: nil
            ),
            approvedPeers: [OAuthIPAddress(literal: "93.184.216.34")!],
            timeout: 5, maximumTransportTimeout: 15,
            maximumRequestBodyBytes: 1_048_576, maximumBodyBytes: 1_048_576
        )
        XCTAssertEqual(plan.port, 8_443)
        XCTAssertEqual(plan.sniHostname, "api.bsky.app")
        XCTAssertEqual(plan.headers.first(name: "host"), "api.bsky.app:8443")
    }
}
