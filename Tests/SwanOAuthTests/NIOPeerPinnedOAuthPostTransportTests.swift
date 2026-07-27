import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import XCTest
@testable import SwanOAuth
import SwanCore

final class NIOPeerPinnedOAuthPostTransportTests: XCTestCase {
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

    private func makePoster(
        endpoint: URL,
        resolver: any OAuthHostnameResolving
    ) throws -> OAuthBoundedJSONPoster {
        let peer = try XCTUnwrap(OAuthIPAddress(literal: "127.0.0.1"))
        let connector = NIOPeerPinnedOAuthPostTransport(configuration: try .init(
            endpointPeers: [endpoint.absoluteString: peer],
            additionalTrustRootsPEM: Data(LocalTLSCertificate.authority.utf8)
        ))
        return OAuthBoundedJSONPoster(
            policy: try OAuthRemoteFetchPolicy(
                networkAllowlist: .init(addresses: [peer]),
                timeout: 2
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
    private let receipt: EventLoopPromise<Void>

    private init(
        peer: OAuthIPAddress,
        endpoint: URL,
        group: MultiThreadedEventLoopGroup,
        channel: Channel,
        receipt: EventLoopPromise<Void>
    ) {
        self.peer = peer
        self.endpoint = endpoint
        self.group = group
        self.channel = channel
        self.receipt = receipt
    }

    static func start() async throws -> LocalTLSPeer {
        let peer = try XCTUnwrap(OAuthIPAddress(literal: "127.0.0.1"))
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        do {
            let tlsContext = try NIOSSLContext(configuration: LocalTLSCertificate.serverConfiguration())
            let receipt = group.next().makePromise(of: Void.self)
            let bootstrap = ServerBootstrap(group: group)
                .childChannelInitializer { channel in
                    do {
                        let tls = NIOSSLServerHandler(context: tlsContext)
                        // NIO assigns this closure and its handlers to one
                        // event loop. Use the synchronous pipeline view rather
                        // than asserting that NIOSSL's legacy handlers are
                        // Sendable across Swift tasks.
                        try channel.pipeline.syncOperations.addHandler(tls)
                        try channel.pipeline.syncOperations.addHandler(ByteToMessageHandler(HTTPRequestDecoder()))
                        try channel.pipeline.syncOperations.addHandler(HTTPResponseEncoder())
                        try channel.pipeline.syncOperations.addHandler(LocalTLSResponder(receipt: receipt))
                        return channel.eventLoop.makeSucceededFuture(())
                    } catch {
                        return channel.eventLoop.makeFailedFuture(error)
                    }
                }
            let channel = try await bootstrap.bind(host: peer.description, port: 0).get()
            let port = try XCTUnwrap(channel.localAddress?.port)
            let endpoint = try XCTUnwrap(URL(string: "https://hummingbird.codes:\(port)/xrpc/com.atproto.space.notifyWrite"))
            return LocalTLSPeer(peer: peer, endpoint: endpoint, group: group, channel: channel, receipt: receipt)
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    func receivedRequest() async throws -> Int {
        try await receipt.futureResult.get()
        return 1
    }

    func close() async {
        try? await channel.close().get()
        try? await group.shutdownGracefully()
    }
}

private final class LocalTLSResponder: ChannelInboundHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let receipt: EventLoopPromise<Void>
    private var responded = false

    init(receipt: EventLoopPromise<Void>) {
        self.receipt = receipt
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard case .end = unwrapInboundIn(data), !responded else { return }
        responded = true
        receipt.succeed(())
        var headers = HTTPHeaders()
        headers.add(name: "content-length", value: "0")
        headers.add(name: "connection", value: "close")
        let head = HTTPResponseHead(version: .http1_1, status: .noContent, headers: headers)
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
    }

    func errorCaught(context: ChannelHandlerContext, error _: Error) {
        receipt.fail(SwanError.unavailable("local TLS peer failed"))
        context.close(promise: nil)
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
