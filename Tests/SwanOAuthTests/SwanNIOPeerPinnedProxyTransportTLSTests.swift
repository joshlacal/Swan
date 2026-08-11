import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import SwanCore
import XCTest

@testable import SwanOAuth

/// Live-socket coverage for `SwanNIOPeerPinnedProxyTransport`, ported from
/// `Tests/SwanAccountsTests/NIOPeerPinnedATHandleHTTPTransportTests.swift`.
///
/// The plan-level tests prove the transport *computed* the right peer and SNI
/// hostname. They cannot prove those values were wired into the socket and the
/// TLS handler, so they would still pass if `serverHostname:` were changed to
/// the pinned IP — silently removing certificate name verification. These tests
/// close that gap: the server's certificate is valid **only** for
/// `hummingbird.codes`, while the TCP connection is pinned to `127.0.0.1`, so a
/// successful request is itself proof that the socket used the literal and TLS
/// used the hostname.
final class SwanNIOPeerPinnedProxyTransportTLSTests: XCTestCase {
    func testConnectsToApprovedLiteralWhileVerifyingURLHostname() async throws {
        let server = try await LocalProxyTLSPeer.start()
        defer { Task { await server.close() } }
        let transport = try testTransport()

        let response = try await transport.send(
            SwanProxyRequest(
                method: "GET",
                url: server.endpoint,
                headers: [("atproto-accept-labelers", "did:plc:labeler")],
                body: nil
            ),
            approvedPeers: [server.peer],
            timeout: 1,
            maximumBodyBytes: 1_024
        )

        XCTAssertEqual(response.status, 200)
        XCTAssertEqual(response.body, Data(#"{"did":"did:plc:abcdefghijklmnopqrstuvwx"}"#.utf8))
        // The socket really was opened to the approved literal.
        XCTAssertEqual(response.connectedPeerAddress, server.peer)
        XCTAssertEqual(server.peer.description, "127.0.0.1")

        // ...and the request was addressed to the hostname, not the pin.
        let request = try await server.receivedRequest()
        let endpointPort = try XCTUnwrap(server.endpoint.port)
        XCTAssertEqual(request.host, "hummingbird.codes:\(endpointPort)")
        XCTAssertNotEqual(request.host, "\(server.peer.description):\(endpointPort)")
        XCTAssertEqual(request.uri, "/xrpc/app.bsky.actor.getProfile?actor=did%3Aplc%3Aabc")
        XCTAssertEqual(request.method, .GET)
        XCTAssertEqual(request.labelers, "did:plc:labeler")
    }

    func testPOSTBodyReachesTheApprovedLiteralPeer() async throws {
        let server = try await LocalProxyTLSPeer.start()
        defer { Task { await server.close() } }
        let transport = try testTransport()
        let body = Data(#"{"actor":"did:plc:abc"}"#.utf8)

        let response = try await transport.send(
            SwanProxyRequest(
                method: "POST",
                url: server.endpoint,
                headers: [("content-type", "application/json")],
                body: body
            ),
            approvedPeers: [server.peer],
            timeout: 1,
            maximumBodyBytes: 1_024
        )

        XCTAssertEqual(response.status, 200)
        XCTAssertEqual(response.connectedPeerAddress, server.peer)
        let request = try await server.receivedRequest()
        XCTAssertEqual(request.method, .POST)
        XCTAssertEqual(request.body, body)
        XCTAssertEqual(request.contentLength, String(body.count))
    }

    func testRejectsWrongTLSHostnameAndWrongApprovedLiteral() async throws {
        let server = try await LocalProxyTLSPeer.start()
        defer { Task { await server.close() } }
        let transport = try testTransport()

        // Same pinned peer, but a hostname the server certificate does not
        // cover: certificate name verification must fail the request.
        var wrongHost = try XCTUnwrap(
            URLComponents(url: server.endpoint, resolvingAgainstBaseURL: false)
        )
        wrongHost.host = "wrong.example"
        // Unwrapped outside the autoclosure: an unwrap failure inside it would
        // be caught by `assertThrows` and silently satisfy the assertion.
        let wrongHostURL = try XCTUnwrap(wrongHost.url)
        await assertThrows(
            try await transport.send(
                SwanProxyRequest(
                    method: "GET", url: wrongHostURL, headers: [], body: nil
                ),
                approvedPeers: [server.peer],
                timeout: 1,
                maximumBodyBytes: 1_024
            ),
            "expected TLS hostname rejection"
        )

        // Correct hostname, but the approved literal is not where the server
        // lives. The transport must connect to the pin and fail, never fall
        // back to resolving `hummingbird.codes`.
        let unrelatedPeer = try XCTUnwrap(OAuthIPAddress(literal: "127.0.0.2"))
        await assertThrows(
            try await transport.send(
                SwanProxyRequest(
                    method: "GET", url: server.endpoint, headers: [], body: nil
                ),
                approvedPeers: [unrelatedPeer],
                timeout: 0.5,
                maximumBodyBytes: 1_024
            ),
            "expected wrong-peer rejection"
        )
    }

    func testResponseBodyIsCappedAtTheCallerBound() async throws {
        let server = try await LocalProxyTLSPeer.start(bodyByteCount: 4_096)
        defer { Task { await server.close() } }
        let transport = try testTransport()

        await assertThrows(
            try await transport.send(
                SwanProxyRequest(method: "GET", url: server.endpoint, headers: [], body: nil),
                approvedPeers: [server.peer],
                timeout: 1,
                maximumBodyBytes: 512
            ),
            "expected oversized response rejection"
        )
    }

    private func testTransport(
        maximumTimeout: TimeInterval = 2
    ) throws -> SwanNIOPeerPinnedProxyTransport {
        try SwanNIOPeerPinnedProxyTransport(
            maximumTransportTimeout: maximumTimeout,
            maximumRequestBodyBytes: 1_048_576,
            additionalTrustRootsPEM: Data(ProxyLocalTLSCertificate.authority.utf8)
        )
    }

    private func assertThrows(
        _ expression: @autoclosure () async throws -> some Any,
        _ message: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await expression()
            XCTFail(message, file: file, line: line)
        } catch {}
    }
}

private struct ReceivedProxyRequest: Sendable {
    let method: HTTPMethod
    let uri: String
    let host: String
    let contentLength: String?
    let labelers: String?
    let body: Data
}

private final class LocalProxyTLSPeer: @unchecked Sendable {
    let peer: OAuthIPAddress
    let endpoint: URL
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private let receipt: LocalProxyRequestReceipt

    private init(
        peer: OAuthIPAddress,
        endpoint: URL,
        group: MultiThreadedEventLoopGroup,
        channel: Channel,
        receipt: LocalProxyRequestReceipt
    ) {
        self.peer = peer
        self.endpoint = endpoint
        self.group = group
        self.channel = channel
        self.receipt = receipt
    }

    static func start(bodyByteCount: Int = 0) async throws -> LocalProxyTLSPeer {
        let peer = try XCTUnwrap(OAuthIPAddress(literal: "127.0.0.1"))
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        do {
            let tlsContext = try NIOSSLContext(
                configuration: ProxyLocalTLSCertificate.serverConfiguration()
            )
            let receipt = LocalProxyRequestReceipt(
                promise: group.next().makePromise(of: ReceivedProxyRequest.self)
            )
            let bootstrap = ServerBootstrap(group: group)
                .childChannelInitializer { channel in
                    do {
                        try channel.pipeline.syncOperations.addHandler(
                            NIOSSLServerHandler(context: tlsContext)
                        )
                        try channel.pipeline.syncOperations.addHandler(
                            ByteToMessageHandler(HTTPRequestDecoder())
                        )
                        try channel.pipeline.syncOperations.addHandler(HTTPResponseEncoder())
                        try channel.pipeline.syncOperations.addHandler(
                            LocalProxyTLSResponder(receipt: receipt, bodyByteCount: bodyByteCount)
                        )
                        return channel.eventLoop.makeSucceededFuture(())
                    } catch {
                        return channel.eventLoop.makeFailedFuture(error)
                    }
                }
            let channel = try await bootstrap.bind(host: peer.description, port: 0).get()
            let port = try XCTUnwrap(channel.localAddress?.port)
            // The certificate's only SAN is `hummingbird.codes`, so this URL
            // can only be fetched if TLS verified the hostname while the TCP
            // connection went to the 127.0.0.1 pin.
            let endpoint = try XCTUnwrap(URL(
                string: "https://hummingbird.codes:\(port)/xrpc/app.bsky.actor.getProfile?actor=did%3Aplc%3Aabc"
            ))
            return LocalProxyTLSPeer(
                peer: peer, endpoint: endpoint, group: group, channel: channel, receipt: receipt
            )
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    func receivedRequest() async throws -> ReceivedProxyRequest {
        try await receipt.value()
    }

    func close() async {
        receipt.failIfPending()
        try? await channel.close().get()
        try? await group.shutdownGracefully()
    }
}

private final class LocalProxyRequestReceipt: @unchecked Sendable {
    private let lock = NSLock()
    private let promise: EventLoopPromise<ReceivedProxyRequest>
    private var completed = false

    init(promise: EventLoopPromise<ReceivedProxyRequest>) {
        self.promise = promise
    }

    func succeed(_ request: ReceivedProxyRequest) {
        lock.lock()
        guard !completed else {
            lock.unlock()
            return
        }
        completed = true
        lock.unlock()
        promise.succeed(request)
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

    func value() async throws -> ReceivedProxyRequest {
        try await promise.futureResult.get()
    }
}

private final class LocalProxyTLSResponder: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let receipt: LocalProxyRequestReceipt
    private let bodyByteCount: Int
    private var head: HTTPRequestHead?
    private var body = Data()
    private var responded = false
    private weak var handlerContext: ChannelHandlerContext?

    init(receipt: LocalProxyRequestReceipt, bodyByteCount: Int) {
        self.receipt = receipt
        self.bodyByteCount = bodyByteCount
    }

    func handlerAdded(context: ChannelHandlerContext) {
        handlerContext = context
    }

    func channelRead(context _: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case let .head(head):
            self.head = head
        case let .body(buffer):
            body.append(contentsOf: buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes) ?? [])
        case .end:
            guard !responded, let head else { return }
            responded = true
            receipt.succeed(ReceivedProxyRequest(
                method: head.method,
                uri: head.uri,
                host: head.headers.first(name: "host") ?? "",
                contentLength: head.headers.first(name: "content-length"),
                labelers: head.headers.first(name: "atproto-accept-labelers"),
                body: body
            ))
            respond()
        }
    }

    func errorCaught(context: ChannelHandlerContext, error _: Error) {
        context.close(promise: nil)
    }

    private func respond() {
        guard let context = handlerContext, context.channel.isActive else { return }
        let payload = bodyByteCount > 0
            ? Data(repeating: UInt8(ascii: "a"), count: bodyByteCount)
            : Data(#"{"did":"did:plc:abcdefghijklmnopqrstuvwx"}"#.utf8)
        var headers = HTTPHeaders()
        headers.add(name: "content-length", value: String(payload.count))
        headers.add(name: "content-type", value: "application/json")
        headers.add(name: "connection", value: "close")
        let head = HTTPResponseHead(version: .http1_1, status: .ok, headers: headers)
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        var buffer = context.channel.allocator.buffer(capacity: payload.count)
        buffer.writeBytes(payload)
        context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
    }
}

/// Test-only certificate material copied from Hummingbird's Apache-2.0 test
/// fixture, by way of `Tests/SwanAccountsTests/NIOPeerPinnedATHandleHTTPTransportTests.swift`.
/// Its SAN is `hummingbird.codes`, proving that TCP can be pinned to 127.0.0.1
/// without weakening URL-hostname certificate verification.
private enum ProxyLocalTLSCertificate {
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
        let certificate = try NIOSSLCertificate(
            bytes: [UInt8](certificate.utf8), format: .pem
        )
        let privateKey = try NIOSSLPrivateKey(
            bytes: [UInt8](privateKey.utf8), format: .pem
        )
        return TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(certificate)],
            privateKey: .privateKey(privateKey)
        )
    }
}
