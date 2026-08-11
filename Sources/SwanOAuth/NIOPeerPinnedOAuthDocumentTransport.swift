import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import SwanCore

/// GET transport for OAuth client metadata and JWKS documents.  DNS is
/// resolved and policy-checked by `OAuthRemoteDocumentFetcher`; this transport
/// receives those approved literals, picks one deterministically, and opens
/// the TCP socket to that literal.  TLS still validates the URL hostname via
/// SNI, so literal pinning cannot bypass certificate name verification.
public struct NIOPeerPinnedOAuthDocumentTransport: OAuthRemoteTransport {
    private let maximumTransportTimeout: TimeInterval
    private let resources: OAuthPeerPinnedNIOClientResources

    public init(
        maximumTransportTimeout: TimeInterval = 5,
        additionalTrustRootsPEM: Data? = nil
    ) throws {
        guard maximumTransportTimeout > 0, maximumTransportTimeout <= 30,
              maximumTransportTimeout.isFinite,
              additionalTrustRootsPEM.map({ !$0.isEmpty && $0.count <= 128 * 1_024 }) ?? true else {
            throw SwanError.malformed("peer-pinned OAuth document transport configuration is invalid")
        }
        self.maximumTransportTimeout = maximumTransportTimeout
        resources = try OAuthPeerPinnedNIOClientResources(
            additionalTrustRootsPEM: additionalTrustRootsPEM
        )
    }

    public func get(
        url: URL,
        approvedPeers: Set<OAuthIPAddress>,
        timeout: TimeInterval,
        maximumBodyBytes: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        guard timeout > 0, timeout <= maximumTransportTimeout, timeout.isFinite,
              (1 ... 1_048_576).contains(maximumBodyBytes),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              let hostname = components.host,
              components.user == nil, components.password == nil, components.fragment == nil,
              !approvedPeers.isEmpty, approvedPeers.count <= 32,
              let peer = approvedPeers.sorted(by: { $0.description < $1.description }).first else {
            throw SwanError.unauthorized("OAuth document request is not peer-pinned")
        }
        guard scheme == "https" || (scheme == "http" && hostname == "localhost") else {
            throw SwanError.unauthorized("OAuth document URL scheme is invalid")
        }
        let port = components.port ?? (scheme == "https" ? 443 : 80)
        guard (1 ... 65_535).contains(port) else {
            throw SwanError.malformed("OAuth document URL port is invalid")
        }

        return try await makeRequest(
            group: resources.eventLoopGroup,
            tlsContext: resources.tlsContext,
            url: url,
            hostname: hostname,
            peer: peer,
            port: port,
            scheme: scheme,
            timeout: timeout,
            maximumBodyBytes: maximumBodyBytes
        )
    }

    private func makeRequest(
        group: MultiThreadedEventLoopGroup,
        tlsContext: NIOSSLContext,
        url: URL,
        hostname: String,
        peer: OAuthIPAddress,
        port: Int,
        scheme: String,
        timeout: TimeInterval,
        maximumBodyBytes: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        let responsePromise = group.next().makePromise(of: OAuthRemoteHTTPResponse.self)
        let bootstrap = ClientBootstrap(group: group)
            .channelOption(ChannelOptions.connectTimeout, value: .milliseconds(Int64(timeout * 1_000)))
            .channelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)
            .channelInitializer { channel in
                do {
                    if scheme == "https" {
                        try channel.pipeline.syncOperations.addHandler(
                            try NIOSSLClientHandler(context: tlsContext, serverHostname: hostname)
                        )
                    }
                    try channel.pipeline.syncOperations.addHTTPClientHandlers()
                    try channel.pipeline.syncOperations.addHandler(
                        OAuthDocumentResponseHandler(
                            responsePromise: responsePromise,
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

        let channel = try await bootstrap.connect(host: peer.description, port: port).get()
        do {
            guard oauthDocumentSocketPeer(channel.remoteAddress) == peer else {
                throw SwanError.unauthorized("OAuth document connected peer did not match its pin")
            }
            var headers = HTTPHeaders()
            headers.add(name: "host", value: oauthDocumentHostHeader(hostname: hostname, port: port, scheme: scheme))
            headers.add(name: "accept", value: "application/json")
            headers.add(name: "connection", value: "close")
            let path: String = {
                let value = url.path.isEmpty ? "/" : url.path
                guard let query = url.query, !query.isEmpty else { return value }
                return "\(value)?\(query)"
            }()
            let head = HTTPRequestHead(version: .http1_1, method: .GET, uri: path, headers: headers)
            try await channel.writeAndFlush(HTTPClientRequestPart.head(head)).get()
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

/// Long-lived resources owned by a peer-pinned transport configuration. NIO's
/// event-loop group and SSL context are both safe to reuse across requests;
/// constructing either per request creates attacker-controlled thread and
/// blocking certificate-loading churn.
final class OAuthPeerPinnedNIOClientResources: @unchecked Sendable {
    let eventLoopGroup: MultiThreadedEventLoopGroup
    let tlsContext: NIOSSLContext

    init(additionalTrustRootsPEM: Data?) throws {
        var tls = TLSConfiguration.makeClientConfiguration()
        if let pem = additionalTrustRootsPEM {
            tls.trustRoots = .certificates(
                try NIOSSLCertificate.fromPEMBytes([UInt8](pem))
            )
        }
        tlsContext = try NIOSSLContext(configuration: tls)
        eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    }

    deinit {
        eventLoopGroup.shutdownGracefully { _ in }
    }
}

final class OAuthDocumentResponseHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = HTTPClientResponsePart

    private let responsePromise: EventLoopPromise<OAuthRemoteHTTPResponse>
    private let expectedPeer: OAuthIPAddress
    private let requestURL: URL
    private let maximumBodyBytes: Int
    private let timeout: TimeInterval
    /// Only prefixes the diagnostics. `SwanNIOPeerPinnedProxyTransport` reuses
    /// this handler verbatim rather than growing a third copy of the bounded,
    /// peer-verifying inbound path; the default keeps the OAuth document
    /// transport's messages byte-identical.
    private let label: String
    private var head: HTTPResponseHead?
    private var body: ByteBuffer?
    private var timeoutTask: Scheduled<Void>?
    private var completed = false

    init(
        responsePromise: EventLoopPromise<OAuthRemoteHTTPResponse>,
        expectedPeer: OAuthIPAddress,
        requestURL: URL,
        maximumBodyBytes: Int,
        timeout: TimeInterval,
        label: String = "OAuth document"
    ) {
        self.responsePromise = responsePromise
        self.expectedPeer = expectedPeer
        self.requestURL = requestURL
        self.maximumBodyBytes = maximumBodyBytes
        self.timeout = timeout
        self.label = label
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
                fail(context: context, error: SwanError.unauthorized("\(label) response was malformed"))
                return
            }
            self.head = head
        case let .body(part):
            guard head != nil else {
                fail(context: context, error: SwanError.unauthorized("\(label) response was malformed"))
                return
            }
            var aggregate = body ?? context.channel.allocator.buffer(capacity: part.readableBytes)
            var copy = part
            aggregate.writeBuffer(&copy)
            guard aggregate.readableBytes <= maximumBodyBytes else {
                fail(context: context, error: SwanError.unauthorized("\(label) response exceeded its bound"))
                return
            }
            body = aggregate
        case .end:
            guard let head,
                  let peer = oauthDocumentSocketPeer(context.channel.remoteAddress),
                  peer == expectedPeer else {
                fail(context: context, error: SwanError.unauthorized("\(label) connected peer did not match its pin"))
                return
            }
            let bytes = body.flatMap { buffer in
                buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes)
            } ?? []
            let headers = head.headers.reduce(into: [String: [String]]()) { output, header in
                output[header.name.lowercased(), default: []].append(header.value)
            }
            succeed(.init(
                status: Int(head.status.code), headers: headers, body: Data(bytes),
                responseURL: requestURL, redirectCount: 0, connectedPeerAddress: peer
            ))
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        fail(context: context, error: error)
    }

    func channelInactive(context: ChannelHandlerContext) {
        if !completed {
            fail(context: context, error: SwanError.unavailable("\(label) connection closed before response"))
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        if !completed {
            fail(context: context, error: SwanError.unavailable("\(label) response handler was removed before response"))
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
        responsePromise.fail(SwanError.unavailable("\(label) request timed out"))
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

private func oauthDocumentSocketPeer(_ address: SocketAddress?) -> OAuthIPAddress? {
    guard let ip = address?.ipAddress else { return nil }
    return OAuthIPAddress(literal: ip)
}

private func oauthDocumentHostHeader(hostname: String, port: Int, scheme: String) -> String {
    let defaultPort = scheme == "https" ? 443 : 80
    return port == defaultPort ? hostname : "\(hostname):\(port)"
}
