import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import SwanCore

/// A one-hop GET transport which connects to a policy-approved literal while
/// retaining the requested hostname for TLS verification and the Host header.
/// Redirect handling deliberately remains in `ATProtocolHandleVerifier`.
public struct NIOPeerPinnedATHandleHTTPTransport: ATHandleHTTPFetching {
    private let maximumTransportTimeout: TimeInterval
    private let additionalTrustRootsPEM: Data?

    public init(
        maximumTransportTimeout: TimeInterval = 5,
        additionalTrustRootsPEM: Data? = nil
    ) throws {
        guard maximumTransportTimeout > 0, maximumTransportTimeout <= 30,
              maximumTransportTimeout.isFinite,
              additionalTrustRootsPEM.map({
                  !$0.isEmpty && $0.count <= 128 * 1_024
              }) ?? true else {
            throw ATHandleVerificationError.verificationFailed
        }
        self.maximumTransportTimeout = maximumTransportTimeout
        self.additionalTrustRootsPEM = additionalTrustRootsPEM
    }

    public func get(
        url: URL,
        approvedPeers: Set<ATHandleIPAddress>,
        timeout: TimeInterval,
        maximumBodyBytes: Int
    ) async throws -> ATHandleHTTPResponse {
        guard timeout > 0, timeout <= maximumTransportTimeout, timeout.isFinite,
              (1 ... 16_384).contains(maximumBodyBytes),
              let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = parts.scheme?.lowercased(),
              let hostname = parts.host, !hostname.isEmpty,
              parts.user == nil, parts.password == nil, parts.fragment == nil,
              !approvedPeers.isEmpty, approvedPeers.count <= 32,
              let peer = approvedPeers.sorted(by: {
                  $0.description < $1.description
              }).first,
              scheme == "https" || (
                  scheme == "http"
                      && ATHandleIPAddress(literal: hostname)?.isLoopback == true
              ) else {
            throw ATHandleVerificationError.verificationFailed
        }
        let port = parts.port ?? (scheme == "https" ? 443 : 80)
        guard (1 ... 65_535).contains(port) else {
            throw ATHandleVerificationError.verificationFailed
        }

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        do {
            let response = try await request(
                group: group,
                url: url,
                hostname: hostname,
                peer: peer,
                port: port,
                scheme: scheme,
                timeout: timeout,
                maximumBodyBytes: maximumBodyBytes
            )
            try await group.shutdownGracefully()
            return response
        } catch {
            try? await group.shutdownGracefully()
            throw ATHandleVerificationError.unavailable
        }
    }

    private func request(
        group: MultiThreadedEventLoopGroup,
        url: URL,
        hostname: String,
        peer: ATHandleIPAddress,
        port: Int,
        scheme: String,
        timeout: TimeInterval,
        maximumBodyBytes: Int
    ) async throws -> ATHandleHTTPResponse {
        let promise = group.next().makePromise(of: ATHandleHTTPResponse.self)
        let bootstrap = ClientBootstrap(group: group)
            .channelOption(
                ChannelOptions.connectTimeout,
                value: .milliseconds(Int64(timeout * 1_000))
            )
            .channelOption(
                ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY),
                value: 1
            )
            .channelInitializer { channel in
                do {
                    if scheme == "https" {
                        var configuration = TLSConfiguration.makeClientConfiguration()
                        if let pem = additionalTrustRootsPEM {
                            configuration.trustRoots = .certificates(
                                try NIOSSLCertificate.fromPEMBytes([UInt8](pem))
                            )
                        }
                        let context = try NIOSSLContext(configuration: configuration)
                        try channel.pipeline.syncOperations.addHandler(
                            try NIOSSLClientHandler(
                                context: context,
                                serverHostname: hostname
                            )
                        )
                    }
                    try channel.pipeline.syncOperations.addHTTPClientHandlers()
                    try channel.pipeline.syncOperations.addHandler(
                        ATHandleResponseHandler(
                            promise: promise,
                            expectedPeer: peer,
                            requestURL: url,
                            maximumBodyBytes: maximumBodyBytes,
                            timeout: timeout
                        )
                    )
                    return channel.eventLoop.makeSucceededFuture(())
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }

        let channel: Channel
        do {
            channel = try await bootstrap.connect(
                host: peer.description,
                port: port
            ).get()
        } catch {
            // The response handler is not guaranteed to be installed when
            // connect/initialization fails. Resolve the request promise here
            // as well, otherwise SwiftNIO reports a leaked promise during
            // event-loop shutdown on Linux.
            promise.fail(ATHandleVerificationError.unavailable)
            throw error
        }
        do {
            guard atHandleSocketPeer(channel.remoteAddress) == peer else {
                throw ATHandleVerificationError.verificationFailed
            }
            var headers = HTTPHeaders()
            headers.add(
                name: "host",
                value: atHandleHostHeader(
                    hostname: hostname,
                    port: port,
                    scheme: scheme
                )
            )
            headers.add(name: "accept", value: "text/plain, */*;q=0.1")
            headers.add(name: "connection", value: "close")
            let path: String = {
                let path = url.path.isEmpty ? "/" : url.path
                guard let query = url.query, !query.isEmpty else { return path }
                return "\(path)?\(query)"
            }()
            let head = HTTPRequestHead(
                version: .http1_1,
                method: .GET,
                uri: path,
                headers: headers
            )
            try await channel.writeAndFlush(HTTPClientRequestPart.head(head)).get()
            try await channel.writeAndFlush(HTTPClientRequestPart.end(nil)).get()
            let response = try await promise.futureResult.get()
            try? await channel.close().get()
            return response
        } catch {
            // Covers failures before the response handler observes
            // channelInactive (for example a write failure during TLS
            // teardown). `EventLoopPromise` ignores duplicate completion.
            promise.fail(ATHandleVerificationError.unavailable)
            try? await channel.close().get()
            throw error
        }
    }
}

private final class ATHandleResponseHandler:
    ChannelInboundHandler,
    @unchecked Sendable
{
    typealias InboundIn = HTTPClientResponsePart

    private let promise: EventLoopPromise<ATHandleHTTPResponse>
    private let expectedPeer: ATHandleIPAddress
    private let requestURL: URL
    private let maximumBodyBytes: Int
    private let timeoutInterval: TimeInterval
    private var head: HTTPResponseHead?
    private var body: ByteBuffer?
    private var timeoutTask: Scheduled<Void>?
    private var completed = false
    private weak var handlerContext: ChannelHandlerContext?

    init(
        promise: EventLoopPromise<ATHandleHTTPResponse>,
        expectedPeer: ATHandleIPAddress,
        requestURL: URL,
        maximumBodyBytes: Int,
        timeout: TimeInterval
    ) {
        self.promise = promise
        self.expectedPeer = expectedPeer
        self.requestURL = requestURL
        self.maximumBodyBytes = maximumBodyBytes
        self.timeoutInterval = timeout
    }

    func handlerAdded(context: ChannelHandlerContext) {
        handlerContext = context
        timeoutTask = context.eventLoop.scheduleTask(
            in: .milliseconds(Int64(timeoutInterval * 1_000))
        ) { [weak self] in
            self?.timeout()
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case let .head(head):
            guard self.head == nil else {
                fail(context)
                return
            }
            self.head = head
        case let .body(part):
            guard head != nil else {
                fail(context)
                return
            }
            var aggregate = body
                ?? context.channel.allocator.buffer(capacity: part.readableBytes)
            var copy = part
            aggregate.writeBuffer(&copy)
            guard aggregate.readableBytes <= maximumBodyBytes else {
                fail(context)
                return
            }
            body = aggregate
        case .end:
            guard let head,
                  let peer = atHandleSocketPeer(context.channel.remoteAddress),
                  peer == expectedPeer else {
                fail(context)
                return
            }
            timeoutTask?.cancel()
            completed = true
            let bytes = body.flatMap {
                $0.getBytes(at: $0.readerIndex, length: $0.readableBytes)
            } ?? []
            let headers = head.headers.reduce(into: [String: [String]]()) {
                result, header in
                result[header.name.lowercased(), default: []].append(header.value)
            }
            promise.succeed(.init(
                status: Int(head.status.code),
                headers: headers,
                body: Data(bytes),
                responseURL: requestURL,
                connectedPeer: peer
            ))
        }
    }

    func errorCaught(context: ChannelHandlerContext, error _: Error) {
        fail(context)
    }

    func channelInactive(context: ChannelHandlerContext) {
        if !completed { fail(context) }
    }

    func handlerRemoved(context _: ChannelHandlerContext) {
        // A TLS/HTTP pipeline can be removed without delivering
        // channelInactive to every downstream handler. Complete the promise
        // before deinitialization so the event-loop leak detector cannot
        // mistake an expected connection failure for an orphaned request.
        guard !completed else { return }
        completed = true
        timeoutTask?.cancel()
        promise.fail(ATHandleVerificationError.unavailable)
    }

    private func fail(_ context: ChannelHandlerContext) {
        guard !completed else { return }
        completed = true
        timeoutTask?.cancel()
        promise.fail(ATHandleVerificationError.unavailable)
        context.close(promise: nil)
    }

    private func timeout() {
        guard let handlerContext else {
            guard !completed else { return }
            completed = true
            promise.fail(ATHandleVerificationError.unavailable)
            return
        }
        fail(handlerContext)
    }
}

private func atHandleSocketPeer(
    _ address: SocketAddress?
) -> ATHandleIPAddress? {
    address?.ipAddress.flatMap(ATHandleIPAddress.init(literal:))
}

private func atHandleHostHeader(
    hostname: String,
    port: Int,
    scheme: String
) -> String {
    port == (scheme == "https" ? 443 : 80)
        ? hostname
        : "\(hostname):\(port)"
}
