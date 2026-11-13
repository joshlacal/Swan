import Foundation
import NIOCore
import NIOEmbedded
import NIOHTTP1
import NIOPosix
import NIOSSL
import XCTest
@testable import SwanOAuth
import SwanCore

final class NIOPeerPinnedOAuthPostTransportTests: XCTestCase {
    func testDocumentTransportConnectsToApprovedLiteralAndReportsPeer() async throws {
        let expectedBody = Data("document".utf8)
        let server = try await LocalTLSPeer.start(responseBody: expectedBody)
        defer { Task { await server.close() } }

        let connector = try NIOPeerPinnedOAuthDocumentTransport(
            maximumTransportTimeout: 2,
            additionalTrustRootsPEM: Data(LocalTLSCertificate.authority.utf8)
        )
        let response = try await connector.get(
            url: server.endpoint,
            approvedPeers: [server.peer],
            timeout: 2,
            maximumBodyBytes: 1_024
        )
        XCTAssertEqual(response.status, 200)
        XCTAssertEqual(response.body, expectedBody)
        XCTAssertEqual(response.connectedPeerAddress, server.peer)
        let requests = try await server.receivedRequest()
        XCTAssertEqual(requests, 1)
    }

    func testPinnedTransportConnectsToConfiguredLiteralAndVerifiesTLSHostname() async throws {
        let server = try await LocalTLSPeer.start()
        defer { Task { await server.close() } }

        let endpoint = server.endpoint
        let poster = try makePoster(endpoint: endpoint, resolver: PeerTestResolver(answers: [[server.peer], [server.peer]]))
        try await poster.postJSON(
            to: endpoint,
            headers: ["content-type": "application/json"],
            body: Data("{}".utf8)
        )
        let received = try await server.receivedRequest()
        XCTAssertEqual(received, 1)
        XCTAssertEqual(server.receivedBodyByteCount(), 2)
    }

    func testPinnedTransportRejectsDNSRebindingAfterLiveRequest() async throws {
        let server = try await LocalTLSPeer.start()
        defer { Task { await server.close() } }

        let rebound = try XCTUnwrap(OAuthIPAddress(literal: "8.8.8.8"))
        let poster = try makePoster(
            endpoint: server.endpoint,
            resolver: PeerTestResolver(answers: [[server.peer], [rebound]])
        )
        do {
            try await poster.postJSON(
                to: server.endpoint,
                headers: ["content-type": "application/json"],
                body: Data("{}".utf8)
            )
            XCTFail("the post-request DNS answer must reject the completed request")
        } catch let error as SwanError {
            guard case .unauthorized = error else {
                return XCTFail("expected rebinding rejection, got \(error)")
            }
        }
        let received = try await server.receivedRequest()
        XCTAssertEqual(received, 1)
    }

    func testPinnedTransportRejectsConfiguredPeerMissingFromPreflightBeforeConnectOrBody() async throws {
        let server = try await LocalTLSPeer.start()
        defer { Task { await server.close() } }

        let differentApprovedPeer = try XCTUnwrap(OAuthIPAddress(literal: "8.8.8.8"))
        let poster = try makePoster(
            endpoint: server.endpoint,
            resolver: PeerTestResolver(answers: [[differentApprovedPeer]])
        )

        do {
            try await poster.postJSON(
                to: server.endpoint,
                headers: ["content-type": "application/json"],
                body: Data("{\"must_not_be_delivered\":true}".utf8)
            )
            XCTFail("a configured pin absent from the approved DNS set must fail before connecting")
        } catch let error as SwanError {
            guard case .unauthorized = error else {
                return XCTFail("expected a preflight peer-pin rejection, got \(error)")
            }
        }

        XCTAssertEqual(server.connectionCount(), 0)
        XCTAssertEqual(server.receivedBodyByteCount(), 0)
        XCTAssertEqual(server.completedRequestCount(), 0)
    }

    func testDocumentTransportTimeoutCompletesAndClosesUnresponsivePeer() async throws {
        let server = try await LocalTLSPeer.start(responseDelay: .seconds(1))
        defer { Task { await server.close() } }
        let connector = try NIOPeerPinnedOAuthDocumentTransport(
            maximumTransportTimeout: 1,
            additionalTrustRootsPEM: Data(LocalTLSCertificate.authority.utf8)
        )
        let startedAt = Date()

        do {
            _ = try await connector.get(
                url: server.endpoint,
                approvedPeers: [server.peer],
                timeout: 0.03,
                maximumBodyBytes: 1_024
            )
            XCTFail("the document transport must time out")
        } catch let error as SwanError {
            guard case .unavailable = error else {
                return XCTFail("expected timeout unavailability, got \(error)")
            }
        }

        XCTAssertLessThan(Date().timeIntervalSince(startedAt), 0.5)
        try await server.waitForDisconnect()
        XCTAssertEqual(server.disconnectCount(), 1)
    }

    func testPostTransportTimeoutCompletesAndClosesUnresponsivePeer() async throws {
        let server = try await LocalTLSPeer.start(responseDelay: .seconds(1))
        defer { Task { await server.close() } }
        let poster = try makePoster(
            endpoint: server.endpoint,
            resolver: PeerTestResolver(answers: [[server.peer]]),
            timeout: 0.03
        )
        let startedAt = Date()

        do {
            try await poster.postJSON(
                to: server.endpoint,
                headers: ["content-type": "application/json"],
                body: Data("{}".utf8)
            )
            XCTFail("the POST transport must time out")
        } catch let error as SwanError {
            guard case .unavailable = error else {
                return XCTFail("expected timeout unavailability, got \(error)")
            }
        }

        XCTAssertLessThan(Date().timeIntervalSince(startedAt), 0.5)
        try await server.waitForDisconnect()
        XCTAssertEqual(server.disconnectCount(), 1)
    }

    func testDocumentTransportRejectsResponseBeyondConfiguredBound() async throws {
        let server = try await LocalTLSPeer.start(responseBody: Data("four".utf8))
        defer { Task { await server.close() } }
        let connector = try NIOPeerPinnedOAuthDocumentTransport(
            maximumTransportTimeout: 2,
            additionalTrustRootsPEM: Data(LocalTLSCertificate.authority.utf8)
        )

        do {
            _ = try await connector.get(
                url: server.endpoint,
                approvedPeers: [server.peer],
                timeout: 2,
                maximumBodyBytes: 3
            )
            XCTFail("the document transport must reject a response beyond its byte bound")
        } catch let error as SwanError {
            guard case .unauthorized = error else {
                return XCTFail("expected response-bound rejection, got \(error)")
            }
        }
    }

    func testPostTransportRejectsResponseBeyondConfiguredBound() async throws {
        let server = try await LocalTLSPeer.start(responseBody: Data("four".utf8))
        defer { Task { await server.close() } }
        let connector = NIOPeerPinnedOAuthPostTransport(configuration: try .init(
            endpointPeers: [server.endpoint.absoluteString: server.peer],
            additionalTrustRootsPEM: Data(LocalTLSCertificate.authority.utf8)
        ))

        do {
            _ = try await connector.post(
                url: server.endpoint,
                approvedPeers: [server.peer],
                headers: ["content-type": "application/json"],
                body: Data("{}".utf8),
                timeout: 2,
                maximumResponseBodyBytes: 3
            )
            XCTFail("the POST transport must reject a response beyond its byte bound")
        } catch let error as SwanError {
            guard case .unauthorized = error else {
                return XCTFail("expected response-bound rejection, got \(error)")
            }
        }
    }

    func testDocumentHandlerRemovalFailsOnceAndClosesActiveChannel() throws {
        let channel = EmbeddedChannel()
        let promise = channel.eventLoop.makePromise(of: OAuthRemoteHTTPResponse.self)
        let peer = try XCTUnwrap(OAuthIPAddress(literal: "127.0.0.1"))
        let url = try XCTUnwrap(URL(string: "https://hummingbird.codes/oauth-client-metadata.json"))
        let handler = OAuthDocumentResponseHandler(
            responsePromise: promise,
            expectedPeer: peer,
            requestURL: url,
            maximumBodyBytes: 1_024,
            timeout: 1
        )
        try channel.pipeline.syncOperations.addHandler(handler, name: "response")
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 443)).wait()
        XCTAssertTrue(channel.isActive)

        try channel.pipeline.syncOperations.removeHandler(name: "response").wait()
        assertRemovalFailure(
            promise.futureResult,
            equals: .unavailable("OAuth document response handler was removed before response")
        )
        XCTAssertFalse(channel.isActive)

        channel.embeddedEventLoop.advanceTime(by: .seconds(2))
        assertRemovalFailure(
            promise.futureResult,
            equals: .unavailable("OAuth document response handler was removed before response")
        )
        _ = handler
        XCTAssertNoThrow(try channel.finish(acceptAlreadyClosed: true))
    }

    func testPostHandlerRemovalFailsOnceAndClosesActiveChannel() throws {
        let channel = EmbeddedChannel()
        let promise = channel.eventLoop.makePromise(of: OAuthRemoteHTTPResponse.self)
        let peer = try XCTUnwrap(OAuthIPAddress(literal: "127.0.0.1"))
        let url = try XCTUnwrap(URL(string: "https://hummingbird.codes/xrpc/com.atproto.space.notifyRepoUpdate"))
        let handler = PeerPinnedHTTPResponseHandler(
            responsePromise: promise,
            expectedPeer: peer,
            requestURL: url,
            maximumResponseBodyBytes: 1_024,
            timeout: 1
        )
        try channel.pipeline.syncOperations.addHandler(handler, name: "response")
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 443)).wait()
        XCTAssertTrue(channel.isActive)

        try channel.pipeline.syncOperations.removeHandler(name: "response").wait()
        assertRemovalFailure(
            promise.futureResult,
            equals: .unavailable("notification response handler was removed before response")
        )
        XCTAssertFalse(channel.isActive)

        channel.embeddedEventLoop.advanceTime(by: .seconds(2))
        assertRemovalFailure(
            promise.futureResult,
            equals: .unavailable("notification response handler was removed before response")
        )
        _ = handler
        XCTAssertNoThrow(try channel.finish(acceptAlreadyClosed: true))
    }

    private func assertRemovalFailure(
        _ future: EventLoopFuture<OAuthRemoteHTTPResponse>,
        equals expectedError: SwanError,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try future.wait(), file: file, line: line) { error in
            XCTAssertEqual(error as? SwanError, expectedError, file: file, line: line)
        }
    }

    /// Erratum 03's dynamic peer selection: an endpoint with NO configured
    /// pin connects to a member of the policy-approved DNS answer set — the
    /// full path including TLS hostname verification against the local CA —
    /// while the same configuration with dynamic selection OFF refuses
    /// before any socket I/O.
    func testDynamicPeerSelectionConnectsUnpinnedEndpointFromApprovedAnswers() async throws {
        let server = try await LocalTLSPeer.start()
        defer { Task { await server.close() } }

        let dynamicConnector = NIOPeerPinnedOAuthPostTransport(configuration: try .init(
            endpointPeers: [:],
            allowsDynamicPeerSelection: true,
            additionalTrustRootsPEM: Data(LocalTLSCertificate.authority.utf8)
        ))
        let policy = try OAuthRemoteFetchPolicy(
            networkAllowlist: .init(addresses: [server.peer]),
            timeout: 2
        )
        let dynamicPoster = OAuthBoundedJSONPoster(
            policy: policy,
            resolver: PeerTestResolver(answers: [[server.peer], [server.peer]]),
            transport: dynamicConnector
        )
        try await dynamicPoster.postJSON(
            to: server.endpoint,
            headers: ["content-type": "application/json"],
            body: Data("{}".utf8)
        )
        let received = try await server.receivedRequest()
        XCTAssertEqual(received, 1)

        let staticConnector = NIOPeerPinnedOAuthPostTransport(configuration: try .init(
            endpointPeers: [:],
            additionalTrustRootsPEM: Data(LocalTLSCertificate.authority.utf8)
        ))
        let staticPoster = OAuthBoundedJSONPoster(
            policy: policy,
            resolver: PeerTestResolver(answers: [[server.peer], [server.peer]]),
            transport: staticConnector
        )
        do {
            try await staticPoster.postJSON(
                to: server.endpoint,
                headers: ["content-type": "application/json"],
                body: Data("{}".utf8)
            )
            XCTFail("an unpinned endpoint without dynamic selection must refuse")
        } catch {}
        XCTAssertEqual(
            server.connectionCount(), 1,
            "the refusal must happen before any socket I/O — only the dynamic post connected"
        )
    }

    /// A configured pin keeps priority under dynamic selection, and a pin
    /// missing from the approved answers still refuses — dynamic mode must
    /// not become a fallback around a failed pin check.
    func testConfiguredPinStillGovernsUnderDynamicSelection() async throws {
        let server = try await LocalTLSPeer.start()
        defer { Task { await server.close() } }

        let foreign = try XCTUnwrap(OAuthIPAddress(literal: "8.8.8.8"))
        let connector = NIOPeerPinnedOAuthPostTransport(configuration: try .init(
            endpointPeers: [server.endpoint.absoluteString: foreign],
            allowsDynamicPeerSelection: true,
            additionalTrustRootsPEM: Data(LocalTLSCertificate.authority.utf8)
        ))
        let poster = OAuthBoundedJSONPoster(
            policy: try OAuthRemoteFetchPolicy(
                networkAllowlist: .init(addresses: [server.peer]),
                timeout: 2
            ),
            resolver: PeerTestResolver(answers: [[server.peer], [server.peer]]),
            transport: connector
        )
        do {
            try await poster.postJSON(
                to: server.endpoint,
                headers: ["content-type": "application/json"],
                body: Data("{}".utf8)
            )
            XCTFail("a pin outside the approved answers must refuse")
        } catch {}
        // Synchronous snapshots — `receivedRequest()` AWAITS a request, and
        // this test's whole point is that none is ever made.
        XCTAssertEqual(server.connectionCount(), 0, "no socket may open for a refused pin")
        XCTAssertEqual(server.receivedBodyByteCount(), 0)
    }

    private func makePoster(
        endpoint: URL,
        resolver: any OAuthHostnameResolving,
        timeout: TimeInterval = 2
    ) throws -> OAuthBoundedJSONPoster {
        let peer = try XCTUnwrap(OAuthIPAddress(literal: "127.0.0.1"))
        let connector = NIOPeerPinnedOAuthPostTransport(configuration: try .init(
            endpointPeers: [endpoint.absoluteString: peer],
            additionalTrustRootsPEM: Data(LocalTLSCertificate.authority.utf8)
        ))
        return OAuthBoundedJSONPoster(
            policy: try OAuthRemoteFetchPolicy(
                networkAllowlist: .init(addresses: [peer]),
                timeout: timeout
            ),
            resolver: resolver,
            transport: connector
        )
    }
}

private actor PeerTestResolver: OAuthHostnameResolving {
    private var answers: [[OAuthIPAddress]]
    private var index = 0

    init(answers: [[OAuthIPAddress]]) {
        self.answers = answers
    }

    func resolve(host _: String) async throws -> [OAuthIPAddress] {
        guard !answers.isEmpty else {
            throw SwanError.unavailable("test DNS has no answer")
        }
        defer { index += 1 }
        return answers[min(index, answers.count - 1)]
    }
}

private final class LocalTLSPeer: @unchecked Sendable {
    let peer: OAuthIPAddress
    let endpoint: URL
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private let receipt: LocalTLSReceipt
    private let disconnectReceipt: LocalTLSReceipt
    private let observation: LocalTLSPeerObservation

    private init(
        peer: OAuthIPAddress,
        endpoint: URL,
        group: MultiThreadedEventLoopGroup,
        channel: Channel,
        receipt: LocalTLSReceipt,
        disconnectReceipt: LocalTLSReceipt,
        observation: LocalTLSPeerObservation
    ) {
        self.peer = peer
        self.endpoint = endpoint
        self.group = group
        self.channel = channel
        self.receipt = receipt
        self.disconnectReceipt = disconnectReceipt
        self.observation = observation
    }

    static func start(
        responseDelay: TimeAmount = .zero,
        responseBody: Data = Data()
    ) async throws -> LocalTLSPeer {
        let peer = try XCTUnwrap(OAuthIPAddress(literal: "127.0.0.1"))
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        do {
            let tlsContext = try NIOSSLContext(configuration: LocalTLSCertificate.serverConfiguration())
            let receipt = LocalTLSReceipt(
                promise: group.next().makePromise(of: Void.self)
            )
            let disconnectReceipt = LocalTLSReceipt(
                promise: group.next().makePromise(of: Void.self)
            )
            let observation = LocalTLSPeerObservation()
            let bootstrap = ServerBootstrap(group: group)
                .childChannelInitializer { channel in
                    do {
                        observation.recordConnection()
                        let tls = NIOSSLServerHandler(context: tlsContext)
                        // NIO assigns this closure and its handlers to one
                        // event loop. Use the synchronous pipeline view rather
                        // than asserting that NIOSSL's legacy handlers are
                        // Sendable across Swift tasks.
                        try channel.pipeline.syncOperations.addHandler(tls)
                        try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(HTTPRequestDecoder()))
                        try channel.pipeline.syncOperations.addHandler(HTTPResponseEncoder())
                        try channel.pipeline.syncOperations.addHandler(
                            LocalTLSResponder(
                                receipt: receipt,
                                disconnectReceipt: disconnectReceipt,
                                observation: observation,
                                responseDelay: responseDelay,
                                responseBody: responseBody
                            )
                        )
                        return channel.eventLoop.makeSucceededFuture(())
                    } catch {
                        return channel.eventLoop.makeFailedFuture(error)
                    }
                }
            let channel = try await bootstrap.bind(host: peer.description, port: 0).get()
            let port = try XCTUnwrap(channel.localAddress?.port)
            let endpoint = try XCTUnwrap(URL(string: "https://hummingbird.codes:\(port)/xrpc/com.atproto.space.notifyRepoUpdate"))
            return LocalTLSPeer(
                peer: peer,
                endpoint: endpoint,
                group: group,
                channel: channel,
                receipt: receipt,
                disconnectReceipt: disconnectReceipt,
                observation: observation
            )
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    func receivedRequest() async throws -> Int {
        try await receipt.value()
        return 1
    }

    func connectionCount() -> Int {
        observation.snapshot().connections
    }

    func receivedBodyByteCount() -> Int {
        observation.snapshot().bodyBytes
    }

    func completedRequestCount() -> Int {
        observation.snapshot().completedRequests
    }

    func disconnectCount() -> Int {
        observation.snapshot().disconnects
    }

    func waitForDisconnect() async throws {
        try await disconnectReceipt.value()
    }

    func close() async {
        receipt.failIfPending()
        disconnectReceipt.failIfPending()
        try? await channel.close().get()
        try? await group.shutdownGracefully()
    }
}

private final class LocalTLSResponder: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let receipt: LocalTLSReceipt
    private let disconnectReceipt: LocalTLSReceipt
    private let observation: LocalTLSPeerObservation
    private let responseDelay: TimeAmount
    private let responseBody: Data
    private var responded = false
    private weak var handlerContext: ChannelHandlerContext?
    private var responseTask: Scheduled<Void>?

    init(
        receipt: LocalTLSReceipt,
        disconnectReceipt: LocalTLSReceipt,
        observation: LocalTLSPeerObservation,
        responseDelay: TimeAmount,
        responseBody: Data
    ) {
        self.receipt = receipt
        self.disconnectReceipt = disconnectReceipt
        self.observation = observation
        self.responseDelay = responseDelay
        self.responseBody = responseBody
    }

    func handlerAdded(context: ChannelHandlerContext) {
        handlerContext = context
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let part = unwrapInboundIn(data)
        if case let .body(buffer) = part {
            observation.recordBodyBytes(buffer.readableBytes)
        }
        guard case .end = part, !responded else { return }
        responded = true
        observation.recordCompletedRequest()
        receipt.succeed()
        if responseDelay.nanoseconds == 0 {
            respond()
        } else {
            responseTask = context.eventLoop.scheduleTask(
                in: responseDelay
            ) { [weak self] in
                self?.respond()
            }
        }
    }

    func channelInactive(context _: ChannelHandlerContext) {
        responseTask?.cancel()
        responseTask = nil
        handlerContext = nil
        observation.recordDisconnect()
        disconnectReceipt.succeed()
    }

    private func respond() {
        guard let context = handlerContext else { return }
        var headers = HTTPHeaders()
        headers.add(name: "content-length", value: String(responseBody.count))
        headers.add(name: "connection", value: "close")
        let status: HTTPResponseStatus = responseBody.isEmpty ? .noContent : .ok
        let head = HTTPResponseHead(version: .http1_1, status: status, headers: headers)
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        if !responseBody.isEmpty {
            var buffer = context.channel.allocator.buffer(capacity: responseBody.count)
            buffer.writeBytes(responseBody)
            context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        }
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
    }

    func errorCaught(context: ChannelHandlerContext, error _: Error) {
        receipt.failIfPending()
        context.close(promise: nil)
    }
}

private final class LocalTLSReceipt: @unchecked Sendable {
    private let lock = NSLock()
    private let promise: EventLoopPromise<Void>
    private var completed = false

    init(promise: EventLoopPromise<Void>) {
        self.promise = promise
    }

    func succeed() {
        lock.lock()
        guard !completed else {
            lock.unlock()
            return
        }
        completed = true
        lock.unlock()
        promise.succeed(())
    }

    func failIfPending() {
        lock.lock()
        guard !completed else {
            lock.unlock()
            return
        }
        completed = true
        lock.unlock()
        promise.fail(CancellationError())
    }

    func value() async throws {
        try await promise.futureResult.get()
    }
}

private final class LocalTLSPeerObservation: @unchecked Sendable {
    private let lock = NSLock()
    private var connections = 0
    private var bodyBytes = 0
    private var completedRequests = 0
    private var disconnects = 0

    func recordConnection() {
        lock.lock()
        connections += 1
        lock.unlock()
    }

    func recordBodyBytes(_ count: Int) {
        lock.lock()
        bodyBytes += count
        lock.unlock()
    }

    func recordCompletedRequest() {
        lock.lock()
        completedRequests += 1
        lock.unlock()
    }

    func recordDisconnect() {
        lock.lock()
        disconnects += 1
        lock.unlock()
    }

    func snapshot() -> (connections: Int, bodyBytes: Int, completedRequests: Int, disconnects: Int) {
        lock.lock()
        defer { lock.unlock() }
        return (connections, bodyBytes, completedRequests, disconnects)
    }
}

// Test-only certificate material copied from Hummingbird's Apache-2.0 test
// fixture. Its SAN is `hummingbird.codes`, which proves that the connector
// uses the URL hostname for TLS/SNI while TCP is pinned to 127.0.0.1.
private enum LocalTLSCertificate {
    static let authority = """
    -----BEGIN CERTIFICATE-----
    MIIDZDCCAkwCCQD0NlEDBAHjqjANBgkqhkiG9w0BAQsFADB0MQswCQYDVQQGEwJV
    SzESMBAGA1UECAwJRWRpbmJ1cmdoMRIwEAYDVQQHDAlFZGluYnVyZ2gxFDASBgNV
    BAoMC0h1bW1pbmdiaXJkMQswCQYDVQQLDAJDQTEaMBgGA1UEAwwRaHVtbWluZ2Jp
    cmQuY29kZXMwHhcNMjUwMTI3MDg1NTM5WhcNMzAwMTI2MDg1NTM5WjB0MQswCQYD
    VQQGEwJVSzESMBAGA1UECAwJRWRpbmJ1cmdoMRIwEAYDVQQHDAlFZGluYnVyZ2gx
    FDASBgNVBAoMC0h1bW1pbmdiaXJkMQswCQYDVQQLDAJDQTEaMBgGA1UEAwwRaHVt
    bWluZ2JpcmQuY29kZXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDI
    uzaSit8quh4TvdVPAT0QqH6gYluhsGgVjU+w55E+Yx698Os44IE5pudYiI/ufo2a
    Ttc14uNqx15/irz6xWHYlPrAoBaH6Q14gs4Zw7ZPh1ngx8/JqzEwJ523a+CPCc73
    Q9VdwjfN09C9DpkRpym6Kuoo3+h9/StgTmf1izf5fyNKtr1sWlRAps1H1AZpFP0B
    K/qxCXC/oOfRzjeaQ+vw/vdEA4w998ePX0CaCkDOa/aQKZEFsjJ5w3xEhRipgzPw
    6pMdNhvrL/MzSwJvdt9Y2EjXzhlqj6H+JU8tCseUf8u1ij0Mv6ux+oBCBmRUs2vm
    CROEulZKLPAubjGUqi89AgMBAAEwDQYJKoZIhvcNAQELBQADggEBALkJRZaH6GtK
    fyFP3PnTdu319XShP6feBz1v0XlTGSJYA+ufE8fruoJoB+a/AonB0BqNnt5UUBL3
    fz3z3GEcEHiu9h83bq7vRnKYTyflqKn7YMtQegRMROLFmtPyPOvZTWt0OCKR2OwP
    OFAdj8yblVy/rYetoOBGjvX2H9UuAn9w+3fDbWExPD4BEyeEoZnMh9xUgXau8GMu
    bhQmaGE4lDGL8XU6a2M+XkI+YdwKQs+HviT2Cmv3QwCfBZuMnOD4U4+tcnYlz3q2
    O67quuvn46uQFcgxaZwuzQ2vVBzSWSj5JA2GDej4UQipGFLkoLtXdckiJI0LFkHr
    jGFTl9ts7yg=
    -----END CERTIFICATE-----
    """

    static let certificate = """
    -----BEGIN CERTIFICATE-----
    MIIDuzCCAqOgAwIBAgIJAIKDFx1aQwi8MA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNV
    BAYTAlVLMRIwEAYDVQQIDAlFZGluYnVyZ2gxEjAQBgNVBAcMCUVkaW5idXJnaDEU
    MBIGA1UECgwLSHVtbWluZ2JpcmQxCzAJBgNVBAsMAkNBMRowGAYDVQQDDBFodW1t
    aW5nYmlyZC5jb2RlczAeFw0yNTAxMjcwODU1MzlaFw0zMDAxMjYwODU1MzlaMHgx
    CzAJBgNVBAYTAlVLMRIwEAYDVQQIDAlFZGluYnVyZ2gxEjAQBgNVBAcMCUVkaW5i
    dXJnaDEUMBIGA1UECgwLSHVtbWluZ2JpcmQxDzANBgNVBAsMBlNlcnZlcjEaMBgG
    A1UEAwwRaHVtbWluZ2JpcmQuY29kZXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
    ggEKAoIBAQChAarpHioO8b3MVwPFOPq+1YEFAeLZxOXnPRPof+qT0apRsYsDpQQu
    hPWF6fvW1HcpkAGCb9e935Sx172FqHCfAMKI7JaNPn1+wZNAHd0d4tho8bgONdkf
    s9XQZcVLRbc4Gym14sIcfKEOsPUDJISXYQ2nNprSgBVb709SO/JxpTTugJAeAqyW
    bln4db98LpaXNoakaL9py1yUgkosD2GLJl8maueR7Aimf40MmOaVZvvTce11raVg
    iUZtz3CkOdzFLFdQSP9CczkM7Bon8+RyXgM7BUpF9bXu8dL7kRkSu5E9S6bR8CR5
    lwBtoXzw6187GBThVc0R9hiYM/e6cjIHAgMBAAGjTDBKMAsGA1UdDwQEAwIFoDAd
    BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHAYDVR0RBBUwE4IRaHVtbWlu
    Z2JpcmQuY29kZXMwDQYJKoZIhvcNAQELBQADggEBACGATnuWnyBK97EeiI+c+8QK
    Aqr9DCt2NQDrC/RIjPgTMfQ3GFWB+8O2rdr2EwGSVj7ovdw8T8LNvccg8P8B6CFL
    E2oPftWghIg5o23BnO5IovpbQKeDien9oUwiEloYvVc6k221Ah3iC/mW9VYJeFYd
    29fhSypXao0mWnzl8CKeB665XX9Q64wRL6tzoiFzRVJCCfF3cQytpI2FzuWmkJfJ
    ECf8CLOYAK3Ko218h14e02J3T1ZMbXJa8mSAG32HqRpABxxfBZdi88XsA6h8qKT/
    dTF/dRScAjFXwxAwFIUVCqct+IfGokUHvkij73bCIJNZL79kRZh2MrndM/OOkNw=
    -----END CERTIFICATE-----
    """

    static let privateKey = """
    -----BEGIN PRIVATE KEY-----
    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQChAarpHioO8b3M
    VwPFOPq+1YEFAeLZxOXnPRPof+qT0apRsYsDpQQuhPWF6fvW1HcpkAGCb9e935Sx
    172FqHCfAMKI7JaNPn1+wZNAHd0d4tho8bgONdkfs9XQZcVLRbc4Gym14sIcfKEO
    sPUDJISXYQ2nNprSgBVb709SO/JxpTTugJAeAqyWbln4db98LpaXNoakaL9py1yU
    gkosD2GLJl8maueR7Aimf40MmOaVZvvTce11raVgiUZtz3CkOdzFLFdQSP9CczkM
    7Bon8+RyXgM7BUpF9bXu8dL7kRkSu5E9S6bR8CR5lwBtoXzw6187GBThVc0R9hiY
    M/e6cjIHAgMBAAECggEABBDdtwta9oumRl3AK5/XvS/5FR5KE0PEpoVFVm68hsUZ
    rvxzzUDCjUYwSRRylqdA5xzK3PdkFFhsEd2n3JM3XNyRDRIkbyav1p6e0FSwu8t5
    uZS5GCrF8+X/tUaMp+z3xoPxFrXGPx/qlUtktJKcgpIh3SIk4MH5SBwP/byjz7jZ
    DfqDIbVG07PCwXe0LEmd8AEGT6vOXULG5SBkTwz/7BSdzgKvDWIgCDjIdDAahdhW
    LSIn9FT1xDeCeOimFwA4ZdM96ZnFlLJwP4WBmqUWgKfsXBc+Oa8ZDlmsDEkhmzCy
    mBNDOxJVgJ5YOURTpTRPeMoDBxkQbQ1V5MRJng9q0QKBgQDRrVORq74LqtgMOb9o
    Ff2T3z/RE1PzW8jlXnrK3lBcW4Ivt4N4xmFCSWlW7PBTtkCGJfSMZA1MNkK1sBl7
    L2FWqh6KymTdBCedsGFrwNiaVXmJWtUimxS3OAFr4/mJWYIIwz43wzXsxhmSOQD+
    T3/kquDCtYq1cvPHtOdTgu/26QKBgQDEk7BNdIZw0TM8YprdC+OiaO05juXEnp2+
    ObKCVDH0KJjpQ9OfqhppMOBG/RP34zGX8c7iJ0uRIgjlIhTHkeDQp974ei8geCTK
    PI90/fhO8pkkpLJZVPreAdj7502jyFYuy79FjQQRMUVOF3YgCYc3kf9aqWGsGT7O
    KkVP3GUrbwKBgFEC37vzmBzX6Fto4GwtuuisI/L6vb/T4Z3FUDobhP76GCWpiLFc
    LG25AWslZoFhdDKgbYjki0K74DBklqPCnaAnYF+NbUT7evbxE+LXApk2lxubraeO
    NYXIrLvrvBj2LUiHbv2KfcY6j9ywC5M2UhqebvKrw6jxfgDWA15/w4kpAoGAK682
    asAOcFvNKwouqBjQSXNP5I6g+QTWwUNJLDVRtJShBpWQHddLbzzxWlU7bscKal3O
    P+vDm0kY+PKN85uzfisQHd/pQSnx4w96QeF+oOzAo6gGClwcM+HtOm24j0EiBdw5
    cVdZJAjzAdus4Im9htfnC1rA3eHuVxqFtK2hvfkCgYEAttVDzfbXDWo4X4g5ZvON
    7ZAldvxQuHhb5JDPwfWR3H/W99tUma5T8e4UhSOU+7dng3xE+LK2aLJXZN6H4VsR
    GeLymDyXs3JLtJyO4JvRp6C+acALua/pyLfeJj+Mk+A+76bmAftqcJ2e7rzp/EgH
    7VbyN0IbfqD+MmEjFat0hRw=
    -----END PRIVATE KEY-----
    """

    static func serverConfiguration() throws -> TLSConfiguration {
        let certificate = try NIOSSLCertificate(bytes: [UInt8](certificate.utf8), format: .pem)
        let privateKey = try NIOSSLPrivateKey(bytes: [UInt8](privateKey.utf8), format: .pem)
        return TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(certificate)],
            privateKey: .privateKey(privateKey)
        )
    }
}
