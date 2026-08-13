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

        // Built before the socket is opened so a target that cannot be
        // expressed in origin form is rejected without any network contact.
        let target = try oauthOriginFormRequestTarget(
            components,
            failure: SwanError.malformed("OAuth document request target is invalid")
        )

        return try await makeRequest(
            group: resources.eventLoopGroup,
            tlsContext: resources.tlsContext,
            target: target,
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
        target: OAuthOriginFormRequestTarget,
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
                            // The URL the emitted request target denotes, not
                            // the URL that was passed in. See
                            // `oauthOriginFormRequestTarget`.
                            requestURL: target.denotedURL,
                            maximumBodyBytes: maximumBodyBytes,
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
            guard oauthDocumentSocketPeer(channel.remoteAddress) == peer else {
                throw SwanError.unauthorized("OAuth document connected peer did not match its pin")
            }
            var headers = HTTPHeaders()
            headers.add(name: "host", value: oauthDocumentHostHeader(hostname: hostname, port: port, scheme: scheme))
            headers.add(name: "accept", value: "application/json")
            headers.add(name: "connection", value: "close")
            let head = HTTPRequestHead(version: .http1_1, method: .GET, uri: target.uri, headers: headers)
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

/// The origin-form request target actually written to the socket, together with
/// the URL that target denotes.
struct OAuthOriginFormRequestTarget: Sendable {
    /// The exact `request-target` bytes placed in the HTTP/1.1 request line.
    let uri: String
    /// The URL `uri` denotes when resolved against the request's origin. The
    /// transports report this as `OAuthRemoteHTTPResponse.responseURL`.
    let denotedURL: URL
}

/// Builds the origin-form request target for an outbound HTTP/1.1 request from
/// the **percent-encoded** URL components.
///
/// `URL.path` and `URL.query` percent-DECODE. Building the target from them
/// rewrites a path that legitimately contains `%2F`, `%3F`, `%23` or an encoded
/// space into a *different* resource than the one that was policy-checked and
/// peer-pinned a few lines earlier. `SwanProxyHTTPTransport` already builds its
/// target this way; this keeps the peer-pinned NIO transports consistent with
/// it.
///
/// `denotedURL` is re-parsed from the emitted target rather than echoed from
/// the request URL. Echoing the request URL makes the callers' exact-URL
/// comparison (`OAuthRemoteFetch`, `ATHandleVerification`) compare a value
/// against itself, which proves nothing. Re-parsing makes that comparison a
/// real check that the derivation below round-trips. The single normalization
/// is RFC 3986 §6.2.3: origin form requires at least `/`, and an empty path in
/// an http(s) URI denotes the same resource as `/`.
///
/// The `0x21 ... 0x7E` byte guard is defence in depth, kept for symmetry with
/// `SwanProxyHTTPTransport`. It is **not** the control that prevents
/// request-target header injection, and the CRLF-injection finding originally
/// filed as F22 was REFUTED — do not re-derive it from the presence of this
/// guard. Every one of these pipelines is built with
/// `syncOperations.addHTTPClientHandlers()`, which unconditionally installs
/// `NIOHTTPRequestHeadersValidator` (swift-nio 2.101.3,
/// `Sources/NIOHTTP1/HTTPPipelineSetup.swift` `_addHTTPClientHandlers`). That
/// handler runs before `HTTPRequestEncoder` on the outbound path and fails the
/// write with `HTTPParserError.invalidHeaderToken` for any URI byte outside the
/// RFC 9112 request-target grammar — CR, LF, NUL, SP, CTLs and non-ASCII all
/// included.
func oauthOriginFormRequestTarget(
    _ components: URLComponents,
    failure: SwanError
) throws -> OAuthOriginFormRequestTarget {
    let encodedPath = components.percentEncodedPath
    let path = encodedPath.isEmpty ? "/" : encodedPath
    guard path.hasPrefix("/") else { throw failure }
    let encodedQuery = components.percentEncodedQuery.flatMap { $0.isEmpty ? nil : $0 }
    let uri = encodedQuery.map { "\(path)?\($0)" } ?? path
    guard uri.utf8.allSatisfy({ (0x21 ... 0x7E).contains($0) }), uri.utf8.count <= 8_192 else {
        throw failure
    }

    // Split the emitted bytes back apart rather than reusing the inputs, so a
    // future edit to the derivation above that stops round-tripping is caught
    // by the callers' exact-URL comparison instead of passing silently.
    var denoted = components
    let separator = uri.firstIndex(of: "?")
    let emittedPath = separator.map { String(uri[uri.startIndex ..< $0]) } ?? uri
    denoted.percentEncodedPath = (encodedPath.isEmpty && emittedPath == "/") ? "" : emittedPath
    denoted.percentEncodedQuery = separator.map { String(uri[uri.index(after: $0)...]) }
    guard let denotedURL = denoted.url else { throw failure }
    return OAuthOriginFormRequestTarget(uri: uri, denotedURL: denotedURL)
}

private func oauthDocumentSocketPeer(_ address: SocketAddress?) -> OAuthIPAddress? {
    guard let ip = address?.ipAddress else { return nil }
    return OAuthIPAddress(literal: ip)
}

private func oauthDocumentHostHeader(hostname: String, port: Int, scheme: String) -> String {
    let defaultPort = scheme == "https" ? 443 : 80
    return port == defaultPort ? hostname : "\(hostname):\(port)"
}
