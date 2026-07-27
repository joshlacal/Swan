import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import SwanCore

/// A concrete notification-only HTTP/1.1 connector which owns the socket
/// selection.  It never asks the system resolver to connect a hostname: the
/// caller provides one literal peer for each exact configured endpoint, and
/// TLS still verifies the URL hostname through SNI/certificate validation.
///
/// ``OAuthBoundedJSONPoster`` remains responsible for pre- and post-request
/// DNS policy. This connector provides the missing third fact: the actual
/// connected peer was the configured literal pin. The poster then requires
/// that peer to occur in both approved DNS answer sets before a delivery is
/// accepted.
public struct NIOPeerPinnedOAuthPostTransport: OAuthRemotePostTransport {
    /// `endpointPeers` is keyed by the exact absolute endpoint URL chosen by
    /// operator configuration, never by an incoming registration. The values
    /// are literal IPs rather than hostnames so NIO performs no second DNS
    /// lookup between the poster's validation and the TCP connect.
    public struct Configuration: Sendable {
        public let endpointPeers: [String: OAuthIPAddress]
        /// Optional PEM trust roots are only for a local interop lab. Normal
        /// construction leaves NIOSSL's platform/default trust policy intact.
        public let additionalTrustRootsPEM: Data?

        public init(
            endpointPeers: [String: OAuthIPAddress],
            additionalTrustRootsPEM: Data? = nil
        ) throws {
            guard endpointPeers.count <= 4_096,
                  endpointPeers.keys.allSatisfy({ raw in
                      guard let url = URL(string: raw),
                            let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
                            let scheme = components.scheme?.lowercased(),
                            components.host != nil,
                            components.user == nil,
                            components.password == nil,
                            components.fragment == nil else {
                          return false
                      }
                      return scheme == "https" || scheme == "http"
                  }),
                  additionalTrustRootsPEM.map({ !$0.isEmpty && $0.count <= 128 * 1_024 }) ?? true else {
                throw SwanError.malformed("peer-pinned notification transport configuration is invalid")
            }
            self.endpointPeers = endpointPeers
            self.additionalTrustRootsPEM = additionalTrustRootsPEM
        }
    }

    private let configuration: Configuration

    public init(configuration: Configuration) {
        self.configuration = configuration
    }

    public func post(
        url: URL,
        headers: [String: String],
        body: Data,
        timeout: TimeInterval,
        maximumResponseBodyBytes: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        guard body.count <= 64 * 1_024,
              maximumResponseBodyBytes >= 0,
              timeout > 0,
              timeout <= 30,
              timeout.isFinite,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              let hostname = components.host,
              components.user == nil,
              components.password == nil,
              components.fragment == nil,
              let peer = configuration.endpointPeers[url.absoluteString] else {
            throw SwanError.unauthorized("notification endpoint is not peer-pinned")
        }
        guard scheme == "https" || (scheme == "http" && hostname == "localhost") else {
            throw SwanError.unauthorized("notification endpoint scheme is invalid")
        }
        let port = components.port ?? (scheme == "https" ? 443 : 80)
        guard (1 ... 65_535).contains(port) else {
            throw SwanError.malformed("notification endpoint port is invalid")
        }

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        do {
            let response = try await makeRequest(
                group: group,
                url: url,
                hostname: hostname,
                peer: peer,
                port: port,
                scheme: scheme,
                headers: headers,
                body: body,
                timeout: timeout,
                maximumResponseBodyBytes: maximumResponseBodyBytes
            )
            try await group.shutdownGracefully()
            return response
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    private func makeRequest(
        group: MultiThreadedEventLoopGroup,
        url: URL,
        hostname: String,
        peer: OAuthIPAddress,
        port: Int,
        scheme: String,
        headers: [String: String],
        body: Data,
        timeout: TimeInterval,
        maximumResponseBodyBytes: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        let responsePromise = group.next().makePromise(of: OAuthRemoteHTTPResponse.self)
        let bootstrap = ClientBootstrap(group: group)
            .channelOption(ChannelOptions.connectTimeout, value: .milliseconds(Int64(timeout * 1_000)))
            .channelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)
            .channelInitializer { channel in
                do {
                    if scheme == "https" {
                        var tls = TLSConfiguration.makeClientConfiguration()
                        if let pem = configuration.additionalTrustRootsPEM {
                            tls.trustRoots = .certificates(try NIOSSLCertificate.fromPEMBytes([UInt8](pem)))
                        }
                        let context = try NIOSSLContext(configuration: tls)
                        let handler = try NIOSSLClientHandler(context: context, serverHostname: hostname)
                        // `channelInitializer` is already isolated to this
                        // event loop, so use NIO's synchronous pipeline view.
                        // This avoids claiming the legacy NIOSSL handler is
                        // Sendable while retaining NIO's one-event-loop
                        // ownership invariant for all handler state.
                        try channel.pipeline.syncOperations.addHandler(handler)
                    }
                    try channel.pipeline.syncOperations.addHTTPClientHandlers()
                    try channel.pipeline.syncOperations.addHandler(
                        PeerPinnedHTTPResponseHandler(
                            responsePromise: responsePromise,
                            expectedPeer: peer,
                            requestURL: url,
                            maximumResponseBodyBytes: maximumResponseBodyBytes,
                            timeout: timeout
                        )
                    )
                    return channel.eventLoop.makeSucceededFuture(())
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }

        let channel = try await bootstrap.connect(host: peer.description, port: port).get()
        do {
            guard socketPeerAddress(channel.remoteAddress) == peer else {
                throw SwanError.unauthorized("notification connected peer did not match its pin")
            }
            var requestHeaders = HTTPHeaders()
            requestHeaders.add(name: "host", value: hostHeader(hostname: hostname, port: port, scheme: scheme))
            requestHeaders.add(name: "content-length", value: String(body.count))
            requestHeaders.add(name: "connection", value: "close")
            for (name, value) in headers {
                let lower = name.lowercased()
                if lower != "host" && lower != "content-length" && lower != "connection" {
                    requestHeaders.add(name: name, value: value)
                }
            }
            let path: String = {
                let value = url.path.isEmpty ? "/" : url.path
                guard let query = url.query, !query.isEmpty else { return value }
                return "\(value)?\(query)"
            }()
            let head = HTTPRequestHead(version: .http1_1, method: .POST, uri: path, headers: requestHeaders)
            var buffer = channel.allocator.buffer(capacity: body.count)
            buffer.writeBytes(body)
            try await channel.writeAndFlush(HTTPClientRequestPart.head(head)).get()
            try await channel.writeAndFlush(HTTPClientRequestPart.body(.byteBuffer(buffer))).get()
            try await channel.writeAndFlush(HTTPClientRequestPart.end(nil)).get()
            let response = try await responsePromise.futureResult.get()
            try? await channel.close().get()
            return response
        } catch {
            try? await channel.close().get()
            throw error
        }
    }
}

private final class PeerPinnedHTTPResponseHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPClientResponsePart

    private let responsePromise: EventLoopPromise<OAuthRemoteHTTPResponse>
    private let expectedPeer: OAuthIPAddress
    private let requestURL: URL
    private let maximumResponseBodyBytes: Int
    private let timeout: TimeInterval
    private var head: HTTPResponseHead?
    private var body: ByteBuffer?
    private var timeoutTask: Scheduled<Void>?
    private var completed = false

    init(
        responsePromise: EventLoopPromise<OAuthRemoteHTTPResponse>,
        expectedPeer: OAuthIPAddress,
        requestURL: URL,
        maximumResponseBodyBytes: Int,
        timeout: TimeInterval
    ) {
        self.responsePromise = responsePromise
        self.expectedPeer = expectedPeer
        self.requestURL = requestURL
        self.maximumResponseBodyBytes = maximumResponseBodyBytes
        self.timeout = timeout
    }

    func handlerAdded(context: ChannelHandlerContext) {
        let promise = responsePromise
        timeoutTask = context.eventLoop.scheduleTask(in: .milliseconds(Int64(timeout * 1_000))) {
            promise.fail(SwanError.unavailable("notification request timed out"))
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case let .head(head):
            guard self.head == nil else {
                fail(context: context, error: SwanError.unauthorized("notification response was malformed"))
                return
            }
            self.head = head
        case let .body(part):
            guard head != nil else {
                fail(context: context, error: SwanError.unauthorized("notification response was malformed"))
                return
            }
            var aggregate = body ?? context.channel.allocator.buffer(capacity: part.readableBytes)
            var copy = part
            aggregate.writeBuffer(&copy)
            guard aggregate.readableBytes <= maximumResponseBodyBytes else {
                fail(context: context, error: SwanError.unauthorized("notification response exceeded its bound"))
                return
            }
            body = aggregate
        case .end:
            guard let head,
                  let peer = socketPeerAddress(context.channel.remoteAddress),
                  peer == expectedPeer else {
                fail(context: context, error: SwanError.unauthorized("notification connected peer did not match its pin"))
                return
            }
            timeoutTask?.cancel()
            completed = true
            let bytes = body.flatMap { buffer in
                buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes)
            } ?? []
            let headers = head.headers.reduce(into: [String: [String]]()) { output, header in
                output[header.name.lowercased(), default: []].append(header.value)
            }
            responsePromise.succeed(.init(
                status: Int(head.status.code),
                headers: headers,
                body: Data(bytes),
                responseURL: requestURL,
                redirectCount: 0,
                connectedPeerAddress: peer
            ))
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        fail(context: context, error: error)
    }

    func channelInactive(context: ChannelHandlerContext) {
        if !completed {
            fail(context: context, error: SwanError.unavailable("notification connection closed before response"))
        }
    }

    private func fail(context: ChannelHandlerContext, error: Error) {
        guard !completed else { return }
        completed = true
        timeoutTask?.cancel()
        responsePromise.fail(error)
        context.close(promise: nil)
    }
}

private func socketPeerAddress(_ address: SocketAddress?) -> OAuthIPAddress? {
    guard let ip = address?.ipAddress else { return nil }
    return OAuthIPAddress(literal: ip)
}

private func hostHeader(hostname: String, port: Int, scheme: String) -> String {
    let defaultPort = scheme == "https" ? 443 : 80
    return port == defaultPort ? hostname : "\(hostname):\(port)"
}
