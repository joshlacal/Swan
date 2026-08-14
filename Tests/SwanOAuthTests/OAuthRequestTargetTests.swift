import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import XCTest
@testable import SwanAccounts
@testable import SwanOAuth
import SwanCore

/// F22 residual: the three peer-pinned NIO transports used to build their
/// origin-form request target from `url.path` / `url.query`, which
/// percent-DECODE. A path containing `%2F`, `%3F`, `%23` or `%20` therefore
/// reached the peer as a *different* resource than the one the caller pinned
/// and policy-checked. These tests observe the bytes on the wire through a
/// local HTTP peer that records the request line verbatim.
///
/// The original F22 (CRLF injection through the request target) is REFUTED:
/// `syncOperations.addHTTPClientHandlers()` installs
/// `NIOHTTPRequestHeadersValidator` on every one of these pipelines and it
/// rejects any URI byte outside the RFC 9112 request-target grammar before the
/// encoder runs. The `0x21 ... 0x7E` guard in the transports is defence in
/// depth only.
final class OAuthRequestTargetTests: XCTestCase {
    /// Percent-encoded path segments that all decode into structurally
    /// significant characters: `/`, `?`, `#`, and SP.
    private static let encodedPath = "/a%2Fb/c%3Fd/e%23f/g%20h"
    private static let encodedQuery = "q=%2Fx&r=1%26still-one-value"

    // MARK: - Pure derivation

    func testOAuthTargetKeepsPercentEncodingAndReportsDenotedURL() throws {
        let url = try XCTUnwrap(
            URL(string: "https://pds.example/a%2Fb/c%3Fd/e%23f/g%20h?\(Self.encodedQuery)")
        )
        // Positive control: this is exactly the loss the fix removes.
        //
        // Assert that the loss happens, not one platform's spelling of it.
        // `URL.path` decodes structurally significant bytes, but *which*
        // ones differs by Foundation implementation: Darwin decodes `%2F`
        // into `/`, while corelibs-foundation on Linux preserves it and
        // decodes only `%3F`, `%23`, and `%20`. Pinning Darwin's exact
        // output made this control fail on the deployment platform while
        // the assertions below — the ones that test the fix — passed on
        // both.
        XCTAssertNotEqual(url.path, Self.encodedPath)

        let components = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        let target = try oauthOriginFormRequestTarget(
            components,
            failure: SwanError.malformed("test")
        )
        XCTAssertEqual(target.uri, "\(Self.encodedPath)?\(Self.encodedQuery)")
        XCTAssertEqual(target.denotedURL.absoluteString, url.absoluteString)
    }

    func testOAuthTargetTurnsEmptyPathIntoRootWithoutRewritingTheURL() throws {
        let url = try XCTUnwrap(URL(string: "https://pds.example"))
        let components = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        let target = try oauthOriginFormRequestTarget(
            components,
            failure: SwanError.malformed("test")
        )
        XCTAssertEqual(target.uri, "/")
        // Origin form requires at least "/", but RFC 3986 6.2.3 makes an empty
        // http(s) path equivalent to "/", so the denoted URL must still compare
        // equal to what the caller pinned.
        XCTAssertEqual(target.denotedURL.absoluteString, "https://pds.example")
    }

    func testOAuthTargetKeepsQueryOnEmptyPath() throws {
        let url = try XCTUnwrap(URL(string: "https://pds.example?q=%2Fx"))
        let components = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        let target = try oauthOriginFormRequestTarget(
            components,
            failure: SwanError.malformed("test")
        )
        XCTAssertEqual(target.uri, "/?q=%2Fx")
        XCTAssertEqual(target.denotedURL.absoluteString, url.absoluteString)
    }

    func testATHandleTargetKeepsPercentEncodingAndReportsDenotedURL() throws {
        let url = try XCTUnwrap(
            URL(string: "https://handle.example/a%2Fb/c%3Fd/e%23f/g%20h?\(Self.encodedQuery)")
        )
        let components = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        let target = try atHandleOriginFormRequestTarget(components)
        XCTAssertEqual(target.uri, "\(Self.encodedPath)?\(Self.encodedQuery)")
        XCTAssertEqual(target.denotedURL.absoluteString, url.absoluteString)
    }

    func testATHandleTargetTurnsEmptyPathIntoRoot() throws {
        let url = try XCTUnwrap(URL(string: "https://handle.example"))
        let components = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        let target = try atHandleOriginFormRequestTarget(components)
        XCTAssertEqual(target.uri, "/")
        XCTAssertEqual(target.denotedURL.absoluteString, "https://handle.example")
    }

    // MARK: - OAuth document transport (GET)

    func testDocumentTransportEmitsPercentEncodedTargetOnTheWire() async throws {
        try await withEchoPeer { server in
            let url = try XCTUnwrap(
                URL(string: "http://localhost:\(server.port)\(Self.encodedPath)?\(Self.encodedQuery)")
            )
            let transport = try NIOPeerPinnedOAuthDocumentTransport(maximumTransportTimeout: 2)
            let response = try await transport.get(
                url: url,
                approvedPeers: [server.oauthPeer],
                timeout: 2,
                maximumBodyBytes: 1_024
            )

            XCTAssertEqual(response.status, 200)
            XCTAssertEqual(server.observedURIs(), ["\(Self.encodedPath)?\(Self.encodedQuery)"])
            XCTAssertEqual(response.responseURL.absoluteString, url.absoluteString)
        }
    }

    func testDocumentTransportEmitsRootForAnEmptyPath() async throws {
        try await withEchoPeer { server in
            let url = try XCTUnwrap(URL(string: "http://localhost:\(server.port)"))
            let transport = try NIOPeerPinnedOAuthDocumentTransport(maximumTransportTimeout: 2)
            let response = try await transport.get(
                url: url,
                approvedPeers: [server.oauthPeer],
                timeout: 2,
                maximumBodyBytes: 1_024
            )

            XCTAssertEqual(server.observedURIs(), ["/"])
            XCTAssertEqual(response.responseURL.absoluteString, url.absoluteString)
        }
    }

    // MARK: - OAuth notification transport (POST)

    func testPostTransportEmitsPercentEncodedTargetOnTheWire() async throws {
        try await withEchoPeer { server in
            let url = try XCTUnwrap(
                URL(string: "http://localhost:\(server.port)\(Self.encodedPath)?\(Self.encodedQuery)")
            )
            let transport = NIOPeerPinnedOAuthPostTransport(configuration: try .init(
                endpointPeers: [url.absoluteString: server.oauthPeer]
            ))
            let response = try await transport.post(
                url: url,
                approvedPeers: [server.oauthPeer],
                headers: ["content-type": "application/json"],
                body: Data("{}".utf8),
                timeout: 2,
                maximumResponseBodyBytes: 1_024
            )

            XCTAssertEqual(response.status, 200)
            XCTAssertEqual(server.observedURIs(), ["\(Self.encodedPath)?\(Self.encodedQuery)"])
            XCTAssertEqual(response.responseURL.absoluteString, url.absoluteString)
        }
    }

    func testPostTransportEmitsRootForAnEmptyPath() async throws {
        try await withEchoPeer { server in
            let url = try XCTUnwrap(URL(string: "http://localhost:\(server.port)"))
            let transport = NIOPeerPinnedOAuthPostTransport(configuration: try .init(
                endpointPeers: [url.absoluteString: server.oauthPeer]
            ))
            let response = try await transport.post(
                url: url,
                approvedPeers: [server.oauthPeer],
                headers: [:],
                body: Data("{}".utf8),
                timeout: 2,
                maximumResponseBodyBytes: 1_024
            )

            XCTAssertEqual(server.observedURIs(), ["/"])
            XCTAssertEqual(response.responseURL.absoluteString, url.absoluteString)
        }
    }

    // MARK: - AT handle transport (GET)

    func testATHandleTransportEmitsPercentEncodedTargetOnTheWire() async throws {
        try await withEchoPeer { server in
            let url = try XCTUnwrap(
                URL(string: "http://127.0.0.1:\(server.port)\(Self.encodedPath)?\(Self.encodedQuery)")
            )
            let transport = try NIOPeerPinnedATHandleHTTPTransport(maximumTransportTimeout: 2)
            let response = try await transport.get(
                url: url,
                approvedPeers: [server.handlePeer],
                timeout: 2,
                maximumBodyBytes: 1_024
            )

            XCTAssertEqual(response.status, 200)
            XCTAssertEqual(server.observedURIs(), ["\(Self.encodedPath)?\(Self.encodedQuery)"])
            XCTAssertEqual(response.responseURL.absoluteString, url.absoluteString)
        }
    }

    func testATHandleTransportEmitsRootForAnEmptyPath() async throws {
        try await withEchoPeer { server in
            let url = try XCTUnwrap(URL(string: "http://127.0.0.1:\(server.port)"))
            let transport = try NIOPeerPinnedATHandleHTTPTransport(maximumTransportTimeout: 2)
            let response = try await transport.get(
                url: url,
                approvedPeers: [server.handlePeer],
                timeout: 2,
                maximumBodyBytes: 1_024
            )

            XCTAssertEqual(server.observedURIs(), ["/"])
            XCTAssertEqual(response.responseURL.absoluteString, url.absoluteString)
        }
    }

    /// Runs one wire test against a fresh echo peer and shuts that peer's
    /// event-loop group down before the test returns, on both the success and
    /// the failure path. A `defer { Task { await close() } }` would only
    /// *schedule* the shutdown, so the group could outlive the test and
    /// accumulate a thread per case across the suite.
    private func withEchoPeer(
        _ body: (RequestTargetEchoPeer) async throws -> Void
    ) async throws {
        let server = try await RequestTargetEchoPeer.start()
        do {
            try await body(server)
        } catch {
            await server.close()
            throw error
        }
        await server.close()
    }
}


/// A plaintext HTTP/1.1 peer on 127.0.0.1 that records the exact request-target
/// bytes of every request line it decodes. Plaintext keeps the test free of
/// certificate fixtures; all three transports permit `http` for loopback.
private final class RequestTargetEchoPeer: @unchecked Sendable {
    let port: Int
    let oauthPeer: OAuthIPAddress
    let handlePeer: ATHandleIPAddress
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private let log: RequestTargetLog

    private init(
        port: Int,
        oauthPeer: OAuthIPAddress,
        handlePeer: ATHandleIPAddress,
        group: MultiThreadedEventLoopGroup,
        channel: Channel,
        log: RequestTargetLog
    ) {
        self.port = port
        self.oauthPeer = oauthPeer
        self.handlePeer = handlePeer
        self.group = group
        self.channel = channel
        self.log = log
    }

    static func start() async throws -> RequestTargetEchoPeer {
        let oauthPeer = try XCTUnwrap(OAuthIPAddress(literal: "127.0.0.1"))
        let handlePeer = try XCTUnwrap(ATHandleIPAddress(literal: "127.0.0.1"))
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        do {
            let log = RequestTargetLog()
            let bootstrap = ServerBootstrap(group: group)
                .childChannelInitializer { channel in
                    do {
                        try channel.pipeline.syncOperations.addHandler(
                            ByteToMessageHandler(HTTPRequestDecoder())
                        )
                        try channel.pipeline.syncOperations.addHandler(HTTPResponseEncoder())
                        try channel.pipeline.syncOperations.addHandler(
                            RequestTargetResponder(log: log)
                        )
                        return channel.eventLoop.makeSucceededFuture(())
                    } catch {
                        return channel.eventLoop.makeFailedFuture(error)
                    }
                }
            let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
            let port = try XCTUnwrap(channel.localAddress?.port)
            return RequestTargetEchoPeer(
                port: port,
                oauthPeer: oauthPeer,
                handlePeer: handlePeer,
                group: group,
                channel: channel,
                log: log
            )
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    func observedURIs() -> [String] {
        log.snapshot()
    }

    func close() async {
        try? await channel.close().get()
        try? await group.shutdownGracefully()
    }
}

private final class RequestTargetLog: @unchecked Sendable {
    private let lock = NSLock()
    private var uris: [String] = []

    func record(_ uri: String) {
        lock.lock()
        defer { lock.unlock() }
        uris.append(uri)
    }

    func snapshot() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return uris
    }
}

private final class RequestTargetResponder: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let log: RequestTargetLog
    private var responded = false

    init(log: RequestTargetLog) {
        self.log = log
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case let .head(head):
            log.record(head.uri)
        case .body:
            ()
        case .end:
            guard !responded else { return }
            responded = true
            let payload = Data("ok".utf8)
            var headers = HTTPHeaders()
            headers.add(name: "content-length", value: String(payload.count))
            headers.add(name: "connection", value: "close")
            let head = HTTPResponseHead(version: .http1_1, status: .ok, headers: headers)
            context.write(wrapOutboundOut(.head(head)), promise: nil)
            var buffer = context.channel.allocator.buffer(capacity: payload.count)
            buffer.writeBytes(payload)
            context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
            context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error _: Error) {
        context.close(promise: nil)
    }
}
