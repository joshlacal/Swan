import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import SwanCore
import SwanSpaces
import SwanStorage
@testable import SwanOAuth
import XCTest

/// The delivery service answers `deleteSpaceGeneration` with 429
/// `RateLimited` (with `Retry-After`) or 503 for transient conditions. Those
/// must keep the owner's deletion pending and retryable, and must not surface
/// as an authorization denial. A loopback peer answers each status over the
/// checker's real peer-pinned request path.
final class ConversationSpaceDeletionStatusTests: XCTestCase, @unchecked Sendable {
    private let authority = "did:plc:abcdefghijklmnopqrstuvwx"

    func testTransientDeletionStatusesStayRetryableAndDenialsStayDenied() async throws {
        let space = try SpaceURI(
            authority: authority,
            spaceType: "blue.catbird.labyrinth.conversation",
            skey: UUID().uuidString.lowercased()
        )
        let deleted = try JSONSerialization.data(withJSONObject: [
            "space": space.rawValue, "generation": space.skey, "deleted": true,
        ])
        let errorBody = Data(#"{"error":"Denied","message":"test"}"#.utf8)
        let cases: [(status: Int, body: Data, retryAfter: String?, expected: Outcome)] = [
            (200, deleted, nil, .deleted),
            (429, Data(#"{"error":"RateLimited","message":"slow down"}"#.utf8), "1", .retryable),
            (503, errorBody, nil, .retryable),
            (500, errorBody, nil, .retryable),
            (502, errorBody, nil, .retryable),
            (408, errorBody, nil, .retryable),
            (401, errorBody, nil, .denied),
            (403, errorBody, nil, .denied),
            (404, errorBody, nil, .denied),
            (410, errorBody, nil, .denied),
        ]
        for testCase in cases {
            let peer = try await DeletionStatusPeer.start(
                status: testCase.status,
                body: testCase.body,
                retryAfter: testCase.retryAfter
            )
            do {
                let checker = try makeChecker(port: peer.port, peer: peer.address)
                let outcome: Outcome
                do {
                    try await checker.deleteGeneration(space: space, now: Date())
                    outcome = .deleted
                } catch let error as SwanError {
                    switch error {
                    case .unavailable: outcome = .retryable
                    case .unauthorized: outcome = .denied
                    default: outcome = .other("\(error)")
                    }
                }
                XCTAssertEqual(outcome, testCase.expected, "HTTP \(testCase.status)")
                XCTAssertEqual(
                    peer.observedTargets(),
                    ["/xrpc/\(RemoteConversationSpaceMembershipChecker.deletionMethod)"],
                    "HTTP \(testCase.status) must reach the peer exactly once"
                )
            } catch {
                await peer.close()
                throw error
            }
            await peer.close()
        }
    }

    private enum Outcome: Equatable {
        case deleted
        case retryable
        case denied
        case other(String)
    }

    private func makeChecker(port: Int, peer: OAuthIPAddress) throws -> RemoteConversationSpaceMembershipChecker {
        let origin = try XCTUnwrap(URL(string: "http://localhost:\(port)"))
        let transport = NIOPeerPinnedOAuthPostTransport(configuration: try .init(
            endpointPeers: [origin.absoluteString: peer]
        ))
        return try RemoteConversationSpaceMembershipChecker(
            origin: origin,
            audience: "did:web:ds.example.test",
            signer: FixedServiceTokenIssuer(),
            policy: .init(
                allowLocalhostDevelopment: true,
                networkAllowlist: .init(addresses: [peer]),
                maximumBodyBytes: 8_192,
                timeout: 5
            ),
            transport: transport,
            resolver: LoopbackResolver(address: peer)
        )
    }
}

private struct FixedServiceTokenIssuer: SpaceServiceAuthenticationIssuer {
    func issue(
        issuer: String,
        audience: String,
        method: String,
        eventID: String,
        requestBodyDigest: String?,
        now: Date
    ) async throws -> String {
        "test-service-token"
    }
}

private struct LoopbackResolver: OAuthHostnameResolving {
    let address: OAuthIPAddress

    func resolve(host: String) async throws -> [OAuthIPAddress] {
        [address]
    }
}

/// A plaintext HTTP/1.1 peer on 127.0.0.1 that answers every request with one
/// configured status, JSON body and optional `Retry-After`.
private final class DeletionStatusPeer: @unchecked Sendable {
    let port: Int
    let address: OAuthIPAddress
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private let log: DeletionStatusLog

    private init(
        port: Int,
        address: OAuthIPAddress,
        group: MultiThreadedEventLoopGroup,
        channel: Channel,
        log: DeletionStatusLog
    ) {
        self.port = port
        self.address = address
        self.group = group
        self.channel = channel
        self.log = log
    }

    static func start(status: Int, body: Data, retryAfter: String?) async throws -> DeletionStatusPeer {
        let address = try XCTUnwrap(OAuthIPAddress(literal: "127.0.0.1"))
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        do {
            let log = DeletionStatusLog()
            let bootstrap = ServerBootstrap(group: group)
                .childChannelInitializer { channel in
                    do {
                        try channel.pipeline.syncOperations.addHandler(
                            ByteToMessageHandler(HTTPRequestDecoder())
                        )
                        try channel.pipeline.syncOperations.addHandler(HTTPResponseEncoder())
                        try channel.pipeline.syncOperations.addHandler(DeletionStatusResponder(
                            status: status,
                            body: body,
                            retryAfter: retryAfter,
                            log: log
                        ))
                        return channel.eventLoop.makeSucceededFuture(())
                    } catch {
                        return channel.eventLoop.makeFailedFuture(error)
                    }
                }
            let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
            let port = try XCTUnwrap(channel.localAddress?.port)
            return DeletionStatusPeer(port: port, address: address, group: group, channel: channel, log: log)
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    func observedTargets() -> [String] {
        log.snapshot()
    }

    func close() async {
        try? await channel.close().get()
        try? await group.shutdownGracefully()
    }
}

private final class DeletionStatusLog: @unchecked Sendable {
    private let lock = NSLock()
    private var targets: [String] = []

    func record(_ target: String) {
        lock.lock()
        defer { lock.unlock() }
        targets.append(target)
    }

    func snapshot() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return targets
    }
}

private final class DeletionStatusResponder: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let status: Int
    private let body: Data
    private let retryAfter: String?
    private let log: DeletionStatusLog
    private var responded = false

    init(status: Int, body: Data, retryAfter: String?, log: DeletionStatusLog) {
        self.status = status
        self.body = body
        self.retryAfter = retryAfter
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
            var headers = HTTPHeaders()
            headers.add(name: "content-type", value: "application/json")
            headers.add(name: "content-length", value: String(body.count))
            headers.add(name: "connection", value: "close")
            if let retryAfter {
                headers.add(name: "retry-after", value: retryAfter)
            }
            let head = HTTPResponseHead(
                version: .http1_1,
                status: HTTPResponseStatus(statusCode: status),
                headers: headers
            )
            context.write(wrapOutboundOut(.head(head)), promise: nil)
            var buffer = context.channel.allocator.buffer(capacity: body.count)
            buffer.writeBytes(body)
            context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
            context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
        }
    }
}
