import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import XCTest
@testable import SwanAccounts

final class NIOPeerPinnedATHandleHTTPTransportTests: XCTestCase {
    func testConnectsToApprovedLiteralWhileVerifyingURLHostname() async throws {
        let server = try await LocalATHandleTLSPeer.start()
        defer { Task { await server.close() } }
        let transport = try testTransport()

        let response = try await transport.get(
            url: server.endpoint,
            approvedPeers: [server.peer],
            timeout: 1,
            maximumBodyBytes: 1_024
        )

        XCTAssertEqual(response.status, 200)
        XCTAssertEqual(response.body, Data("did:plc:abcdefghijklmnopqrstuvwx".utf8))
        XCTAssertEqual(response.connectedPeer, server.peer)
        let receivedHost = try await server.receivedHost()
        let endpointPort = try XCTUnwrap(server.endpoint.port)
        XCTAssertEqual(
            receivedHost,
            "hummingbird.codes:\(endpointPort)"
        )
    }

    func testRejectsWrongTLSHostnameAndWrongApprovedLiteral() async throws {
        let server = try await LocalATHandleTLSPeer.start()
        defer { Task { await server.close() } }
        let transport = try testTransport()
        var wrongHost = try XCTUnwrap(
            URLComponents(url: server.endpoint, resolvingAgainstBaseURL: false)
        )
        wrongHost.host = "wrong.example"

        await assertUnavailable(
            try await transport.get(
                url: try XCTUnwrap(wrongHost.url),
                approvedPeers: [server.peer],
                timeout: 1,
                maximumBodyBytes: 1_024
            )
        )
        await assertUnavailable(
            try await transport.get(
                url: server.endpoint,
                approvedPeers: [
                    try XCTUnwrap(ATHandleIPAddress(literal: "127.0.0.2")),
                ],
                timeout: 0.2,
                maximumBodyBytes: 1_024
            )
        )
    }

    func testTransportTimeoutClosesAnUnresponsivePeer() async throws {
        let server = try await LocalATHandleTLSPeer.start(responseDelay: .seconds(1))
        defer { Task { await server.close() } }
        let transport = try testTransport(maximumTimeout: 1)
        let start = Date()

        await assertUnavailable(
            try await transport.get(
                url: server.endpoint,
                approvedPeers: [server.peer],
                timeout: 0.03,
                maximumBodyBytes: 1_024
            )
        )
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.5)
    }

    private func testTransport(
        maximumTimeout: TimeInterval = 2
    ) throws -> NIOPeerPinnedATHandleHTTPTransport {
        try NIOPeerPinnedATHandleHTTPTransport(
            maximumTransportTimeout: maximumTimeout,
            additionalTrustRootsPEM: Data(ATHandleLocalTLSCertificate.authority.utf8)
        )
    }

    private func assertUnavailable<T>(
        _ expression: @autoclosure () async throws -> T,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await expression()
            XCTFail("expected unavailable transport", file: file, line: line)
        } catch {
            XCTAssertEqual(
                error as? ATHandleVerificationError,
                .unavailable,
                file: file,
                line: line
            )
        }
    }
}

private final class LocalATHandleTLSPeer: @unchecked Sendable {
    let peer: ATHandleIPAddress
    let endpoint: URL
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private let hostReceipt: LocalATHandleHostReceipt

    private init(
        peer: ATHandleIPAddress,
        endpoint: URL,
        group: MultiThreadedEventLoopGroup,
        channel: Channel,
        hostReceipt: LocalATHandleHostReceipt
    ) {
        self.peer = peer
        self.endpoint = endpoint
        self.group = group
        self.channel = channel
        self.hostReceipt = hostReceipt
    }

    static func start(
        responseDelay: TimeAmount = .zero
    ) async throws -> LocalATHandleTLSPeer {
        let peer = try XCTUnwrap(ATHandleIPAddress(literal: "127.0.0.1"))
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        do {
            let tlsContext = try NIOSSLContext(
                configuration: ATHandleLocalTLSCertificate.serverConfiguration()
            )
            let receipt = LocalATHandleHostReceipt(
                promise: group.next().makePromise(of: String.self)
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
                        try channel.pipeline.syncOperations.addHandler(
                            HTTPResponseEncoder()
                        )
                        try channel.pipeline.syncOperations.addHandler(
                            LocalATHandleTLSResponder(
                                hostReceipt: receipt,
                                responseDelay: responseDelay
                            )
                        )
                        return channel.eventLoop.makeSucceededFuture(())
                    } catch {
                        return channel.eventLoop.makeFailedFuture(error)
                    }
                }
            let channel = try await bootstrap.bind(
                host: peer.description,
                port: 0
            ).get()
            let port = try XCTUnwrap(channel.localAddress?.port)
            let endpoint = try XCTUnwrap(URL(
                string: "https://hummingbird.codes:\(port)/.well-known/atproto-did"
            ))
            return LocalATHandleTLSPeer(
                peer: peer,
                endpoint: endpoint,
                group: group,
                channel: channel,
                hostReceipt: receipt
            )
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    func receivedHost() async throws -> String {
        try await hostReceipt.value()
    }

    func close() async {
        hostReceipt.failIfPending()
        try? await channel.close().get()
        try? await group.shutdownGracefully()
    }
}

private final class LocalATHandleHostReceipt: @unchecked Sendable {
    private let lock = NSLock()
    private let promise: EventLoopPromise<String>
    private var completed = false

    init(promise: EventLoopPromise<String>) {
        self.promise = promise
    }

    func succeed(_ host: String) {
        lock.lock()
        guard !completed else {
            lock.unlock()
            return
        }
        completed = true
        lock.unlock()
        promise.succeed(host)
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

    func value() async throws -> String {
        try await promise.futureResult.get()
    }
}

private final class LocalATHandleTLSResponder:
    ChannelInboundHandler,
    @unchecked Sendable
{
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let hostReceipt: LocalATHandleHostReceipt
    private let responseDelay: TimeAmount
    private var host: String?
    private var responded = false
    private weak var handlerContext: ChannelHandlerContext?
    private var responseTask: Scheduled<Void>?

    init(
        hostReceipt: LocalATHandleHostReceipt,
        responseDelay: TimeAmount
    ) {
        self.hostReceipt = hostReceipt
        self.responseDelay = responseDelay
    }

    func handlerAdded(context: ChannelHandlerContext) {
        handlerContext = context
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case let .head(head):
            host = head.headers.first(name: "host")
        case .body:
            break
        case .end:
            guard !responded, let host else { return }
            responded = true
            hostReceipt.succeed(host)
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
    }

    func channelInactive(context _: ChannelHandlerContext) {
        responseTask?.cancel()
    }

    func errorCaught(context: ChannelHandlerContext, error _: Error) {
        responseTask?.cancel()
        context.close(promise: nil)
    }

    private func respond() {
        guard let context = handlerContext, context.channel.isActive else {
            return
        }
        let body = Data("did:plc:abcdefghijklmnopqrstuvwx".utf8)
        var headers = HTTPHeaders()
        headers.add(name: "content-length", value: String(body.count))
        headers.add(name: "content-type", value: "text/plain")
        headers.add(name: "connection", value: "close")
        let head = HTTPResponseHead(
            version: .http1_1,
            status: .ok,
            headers: headers
        )
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        var buffer = context.channel.allocator.buffer(capacity: body.count)
        buffer.writeBytes(body)
        context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
    }
}

// Test-only certificate material copied from Hummingbird's Apache-2.0 test
// fixture. Its SAN is `hummingbird.codes`, proving that TCP can be pinned to
// 127.0.0.1 without weakening URL-hostname certificate verification.
private enum ATHandleLocalTLSCertificate {
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
            bytes: [UInt8](certificate.utf8),
            format: .pem
        )
        let privateKey = try NIOSSLPrivateKey(
            bytes: [UInt8](privateKey.utf8),
            format: .pem
        )
        return TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(certificate)],
            privateKey: .privateKey(privateKey)
        )
    }
}
