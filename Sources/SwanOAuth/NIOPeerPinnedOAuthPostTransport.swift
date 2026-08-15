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
        /// Erratum 03: permits an endpoint with NO configured pin to connect
        /// to a member of the poster's policy-approved DNS answer set instead.
        /// This is not the AsyncHTTPClient escape hatch the adapter below
        /// warns about: the connect target is still a literal IP chosen
        /// BEFORE the socket opens, it must appear in both of the poster's
        /// approved answer sets, no second lookup ever happens, and TLS still
        /// verifies the URL hostname. What it gives up relative to an
        /// operator pin is only the operator's foreknowledge of the peer —
        /// which cannot exist for a subscriber endpoint learned at
        /// registration time from a DID document. Configured pins keep
        /// priority for their endpoints.
        public let allowsDynamicPeerSelection: Bool
        /// Optional PEM trust roots are only for a local interop lab. Normal
        /// construction leaves NIOSSL's platform/default trust policy intact.
        public let additionalTrustRootsPEM: Data?
        fileprivate let resources: OAuthPeerPinnedNIOClientResources

        public init(
            endpointPeers: [String: OAuthIPAddress],
            allowsDynamicPeerSelection: Bool = false,
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
            self.allowsDynamicPeerSelection = allowsDynamicPeerSelection
            self.additionalTrustRootsPEM = additionalTrustRootsPEM
            resources = try OAuthPeerPinnedNIOClientResources(
                additionalTrustRootsPEM: additionalTrustRootsPEM
            )
        }
    }

    private let configuration: Configuration

    public init(configuration: Configuration) {
        self.configuration = configuration
    }

    public func post(
        url: URL,
        approvedPeers: Set<OAuthIPAddress>,
        headers: [String: String],
        body: Data,
        timeout: TimeInterval,
        maximumResponseBodyBytes: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        guard body.count <= 64 * 1_024,
              (0 ... 1_048_576).contains(maximumResponseBodyBytes),
              timeout > 0,
              timeout <= 30,
              timeout.isFinite,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              let hostname = components.host,
              components.user == nil,
              components.password == nil,
              components.fragment == nil,
              !approvedPeers.isEmpty,
              approvedPeers.count <= 32,
              let peer = connectPeer(for: url, approvedPeers: approvedPeers) else {
            throw SwanError.unauthorized("notification endpoint is not peer-pinned")
        }
        guard scheme == "https" || (scheme == "http" && hostname == "localhost") else {
            throw SwanError.unauthorized("notification endpoint scheme is invalid")
        }
        let port = components.port ?? (scheme == "https" ? 443 : 80)
        guard (1 ... 65_535).contains(port) else {
            throw SwanError.malformed("notification endpoint port is invalid")
        }

        // Built before the socket is opened so a target that cannot be
        // expressed in origin form is rejected without any network contact.
        let target = try oauthOriginFormRequestTarget(
            components,
            failure: SwanError.malformed("notification request target is invalid")
        )

        return try await makeRequest(
            group: configuration.resources.eventLoopGroup,
            tlsContext: configuration.resources.tlsContext,
            target: target,
            hostname: hostname,
            peer: peer,
            port: port,
            scheme: scheme,
            headers: headers,
            body: body,
            timeout: timeout,
            maximumResponseBodyBytes: maximumResponseBodyBytes
        )
    }

    /// A configured pin wins and must be a member of the approved answers.
    /// With dynamic selection enabled, an unpinned endpoint connects to the
    /// canonically-smallest approved answer — a deterministic choice so a
    /// retry cannot be steered to a different member by response timing.
    private func connectPeer(
        for url: URL,
        approvedPeers: Set<OAuthIPAddress>
    ) -> OAuthIPAddress? {
        if let configured = configuredPeer(for: url) {
            return approvedPeers.contains(configured) ? configured : nil
        }
        guard configuration.allowsDynamicPeerSelection else { return nil }
        return approvedPeers.min { "\($0)" < "\($1)" }
    }

    private func configuredPeer(for url: URL) -> OAuthIPAddress? {
        if let exact = configuration.endpointPeers[url.absoluteString] {
            return exact
        }
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return nil
        }
        // Notification destinations are configured as service origins, while
        // the XRPC transport adds an absolute method path.  Preserve exact
        // path pins when present, then fall back only to that same origin
        // spelling; scheme, host, port, userinfo, and fragments remain bound
        // by the configuration key and cannot be selected by the request.
        components.path = ""
        components.query = nil
        components.fragment = nil
        guard let origin = components.url?.absoluteString else { return nil }
        return configuration.endpointPeers[origin]
    }

    private func makeRequest(
        group: MultiThreadedEventLoopGroup,
        tlsContext: NIOSSLContext,
        target: OAuthOriginFormRequestTarget,
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
                        let handler = try NIOSSLClientHandler(
                            context: tlsContext,
                            serverHostname: hostname
                        )
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
                            // The URL the emitted request target denotes, not
                            // the URL that was passed in. See
                            // `oauthOriginFormRequestTarget`.
                            requestURL: target.denotedURL,
                            maximumResponseBodyBytes: maximumResponseBodyBytes,
                            timeout: timeout
                        )
                    )
                    return channel.eventLoop.makeSucceededFuture(())
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }

        // If the connect fails, the response handler was never added to a live
        // pipeline, so nothing else will ever complete `responsePromise` and
        // NIO would trap on the leak in debug builds. Completing it here cannot
        // double-complete: the response handler is added last, so any
        // initializer failure happens before it exists, and a failure after it
        // exists would have gone through `handlerRemoved`.
        let channel: Channel
        do {
            channel = try await bootstrap.connect(host: peer.description, port: port).get()
        } catch {
            responsePromise.fail(error)
            throw error
        }
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
            let head = HTTPRequestHead(
                version: .http1_1, method: .POST, uri: target.uri, headers: requestHeaders
            )
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

final class PeerPinnedHTTPResponseHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
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
        let channel = context.channel
        timeoutTask = context.eventLoop.scheduleTask(
            in: .milliseconds(Int64(timeout * 1_000))
        ) { [weak self, channel] in
            self?.timeout(channel: channel)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !completed else { return }
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
            let bytes = body.flatMap { buffer in
                buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes)
            } ?? []
            let headers = head.headers.reduce(into: [String: [String]]()) { output, header in
                output[header.name.lowercased(), default: []].append(header.value)
            }
            succeed(.init(
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

    func handlerRemoved(context: ChannelHandlerContext) {
        if !completed {
            fail(context: context, error: SwanError.unavailable("notification response handler was removed before response"))
        }
    }

    private func fail(context: ChannelHandlerContext, error: Error) {
        guard !completed else { return }
        completed = true
        timeoutTask?.cancel()
        timeoutTask = nil
        responsePromise.fail(error)
        context.close(promise: nil)
    }

    private func timeout(channel: Channel) {
        guard !completed else { return }
        completed = true
        timeoutTask = nil
        responsePromise.fail(SwanError.unavailable("notification request timed out"))
        channel.close(promise: nil)
    }

    private func succeed(_ response: OAuthRemoteHTTPResponse) {
        guard !completed else { return }
        completed = true
        timeoutTask?.cancel()
        timeoutTask = nil
        responsePromise.succeed(response)
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
