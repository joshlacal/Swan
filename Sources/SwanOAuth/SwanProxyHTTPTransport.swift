import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import SwanCore

public struct SwanProxyRequest: Sendable {
    public let method: String
    public let url: URL
    public let headers: [(name: String, value: String)]
    public let body: Data?

    public init(method: String, url: URL, headers: [(name: String, value: String)], body: Data?) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
    }
}

/// Opens the socket to an already-approved peer literal.
public protocol SwanProxyTransporting: Sendable {
    func send(
        _ request: SwanProxyRequest, approvedPeers: Set<OAuthIPAddress>,
        timeout: TimeInterval, maximumBodyBytes: Int
    ) async throws -> OAuthRemoteHTTPResponse
}

public protocol SwanProxySending: Sendable {
    func send(
        _ request: SwanProxyRequest, timeout: TimeInterval, maximumBodyBytes: Int
    ) async throws -> OAuthRemoteHTTPResponse
}

/// Validates the URL, resolves the host, policy-checks every resolved literal,
/// and pins the connection to them.
///
/// This is the same resolve → policy-check → pin discipline the OAuth document
/// fetcher uses. It is an SSRF and DNS-rebinding control, not a host
/// allow-list: arbitrary public hosts are permitted, which is what lets the
/// proxy reach any AppView, labeler, or feed service.
public struct SwanPeerPinnedProxySender: SwanProxySending {
    private static let permittedMethods: Set<String> = ["GET", "POST"]

    private let policy: OAuthRemoteFetchPolicy
    private let resolver: any OAuthHostnameResolving
    private let transport: any SwanProxyTransporting

    public init(
        policy: OAuthRemoteFetchPolicy,
        resolver: any OAuthHostnameResolving,
        transport: any SwanProxyTransporting
    ) {
        self.policy = policy
        self.resolver = resolver
        self.transport = transport
    }

    public func send(
        _ request: SwanProxyRequest, timeout: TimeInterval, maximumBodyBytes: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        guard Self.permittedMethods.contains(request.method) else {
            throw SwanError.malformed("proxied method is not permitted")
        }
        guard maximumBodyBytes > 0 else {
            throw SwanError.malformed("proxied response body bound must be positive")
        }
        let host = try policy.validateURL(request.url)
        let port = URLComponents(url: request.url, resolvingAgainstBaseURL: false)?.port
        // The caller holds a pipethrough lease across this call, and
        // `getaddrinfo` has no cancellation handle, so an attacker-selected
        // service hostname served by a blackholed nameserver would otherwise
        // hold that lease indefinitely. Bound resolution by the same policy
        // deadline the transport uses.
        let before = Set(try await resolveOAuthHostname(
            resolver, host: host, timeout: policy.timeout
        ))
        try policy.validateResolved(Array(before), host: host, port: port)
        let response = try await transport.send(
            request, approvedPeers: before, timeout: timeout,
            maximumBodyBytes: maximumBodyBytes
        )
        let after = Set(try await resolveOAuthHostname(
            resolver, host: host, timeout: policy.timeout
        ))
        try policy.validateResolved(Array(after), host: host, port: port)
        guard response.redirectCount == 0,
              response.responseURL.absoluteString == request.url.absoluteString,
              response.body.count <= maximumBodyBytes,
              let peer = response.connectedPeerAddress,
              before.contains(peer),
              after.contains(peer),
              policy.permits(peer, forHost: host, port: port) else {
            throw SwanError.unauthorized("proxied XRPC response failed peer or framing policy")
        }
        let normalizedHeaders = response.headers.reduce(into: [String: [String]]()) { output, item in
            output[item.key.lowercased(), default: []].append(contentsOf: item.value)
        }
        if let lengths = normalizedHeaders["content-length"] {
            guard lengths.count == 1,
                  !lengths[0].isEmpty,
                  lengths[0].utf8.allSatisfy({ (48 ... 57).contains($0) }),
                  let declared = Int(lengths[0]),
                  declared == response.body.count,
                  declared <= maximumBodyBytes else {
                throw SwanError.unauthorized("proxied XRPC response content length is invalid")
            }
        }
        return response
    }
}

/// Everything the transport decided *before* any byte left the process. It is
/// a separate value so the pin/SNI split — connect to an approved literal,
/// verify the certificate against the URL hostname — is directly testable
/// without standing up a TLS peer.
struct SwanProxyConnectionPlan: Sendable {
    /// The TCP connect target. Always an approved IP literal, never a hostname:
    /// re-resolving here would reopen the DNS-rebinding window that the
    /// sender's resolve → policy-check step just closed.
    let peer: OAuthIPAddress
    /// TLS SNI and certificate-name verification target. Pinning the socket to
    /// an IP must never weaken certificate validation, so this stays the URL's
    /// hostname.
    let sniHostname: String
    let port: Int
    let scheme: String
    let method: HTTPMethod
    let uri: String
    let headers: HTTPHeaders
    let body: Data
}

/// GET/POST transport for proxied XRPC traffic. DNS is resolved and
/// policy-checked by ``SwanPeerPinnedProxySender``; this transport receives
/// those approved literals, picks one deterministically, and opens the TCP
/// socket to that literal. TLS still validates the URL hostname via SNI, so
/// literal pinning cannot bypass certificate name verification.
///
/// Only the long-lived NIO resources and the inbound response handler are
/// shared with the OAuth transports (``OAuthPeerPinnedNIOClientResources`` and
/// ``OAuthDocumentResponseHandler``). The outbound request construction is not
/// shared: the OAuth document transport hardcodes GET with a fixed `accept`
/// header and no body, and the notification POST transport selects its peer
/// from an operator-configured pin table rather than from the approved DNS
/// answer set. Rewriting either to accept caller-supplied methods, bodies, and
/// arbitrary headers would change the behavior of security-reviewed code that
/// other call sites depend on, so the ~40 lines of request writing below are
/// deliberately kept local.
public struct SwanNIOPeerPinnedProxyTransport: SwanProxyTransporting {
    private static let permittedMethods: [String: HTTPMethod] = ["GET": .GET, "POST": .POST]

    /// Headers the caller may not set: they either frame the message (and so
    /// would enable request smuggling) or describe the hop rather than the
    /// request.
    private static let reservedHeaderNames: Set<String> = [
        "host", "content-length", "connection", "transfer-encoding",
        "proxy-connection", "keep-alive", "upgrade", "te", "trailer", "expect",
    ]

    private let maximumTransportTimeout: TimeInterval
    private let maximumRequestBodyBytes: Int
    private let resources: OAuthPeerPinnedNIOClientResources

    public init(
        maximumTransportTimeout: TimeInterval = 15,
        maximumRequestBodyBytes: Int = 1_048_576,
        additionalTrustRootsPEM: Data? = nil
    ) throws {
        guard maximumTransportTimeout > 0, maximumTransportTimeout <= 30,
              maximumTransportTimeout.isFinite,
              (1 ... 8 * 1_048_576).contains(maximumRequestBodyBytes),
              additionalTrustRootsPEM.map({ !$0.isEmpty && $0.count <= 128 * 1_024 }) ?? true else {
            throw SwanError.malformed("peer-pinned proxy transport configuration is invalid")
        }
        self.maximumTransportTimeout = maximumTransportTimeout
        self.maximumRequestBodyBytes = maximumRequestBodyBytes
        resources = try OAuthPeerPinnedNIOClientResources(
            additionalTrustRootsPEM: additionalTrustRootsPEM
        )
    }

    public func send(
        _ request: SwanProxyRequest,
        approvedPeers: Set<OAuthIPAddress>,
        timeout: TimeInterval,
        maximumBodyBytes: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        let plan = try Self.makeConnectionPlan(
            request: request,
            approvedPeers: approvedPeers,
            timeout: timeout,
            maximumTransportTimeout: maximumTransportTimeout,
            maximumRequestBodyBytes: maximumRequestBodyBytes,
            maximumBodyBytes: maximumBodyBytes
        )
        return try await makeRequest(
            group: resources.eventLoopGroup,
            tlsContext: resources.tlsContext,
            url: request.url,
            plan: plan,
            timeout: timeout,
            maximumBodyBytes: maximumBodyBytes
        )
    }

    /// Pure, synchronous derivation of the connection parameters. Every reason
    /// to refuse a proxied request is decided here, before a socket exists.
    static func makeConnectionPlan(
        request: SwanProxyRequest,
        approvedPeers: Set<OAuthIPAddress>,
        timeout: TimeInterval,
        maximumTransportTimeout: TimeInterval,
        maximumRequestBodyBytes: Int,
        maximumBodyBytes: Int
    ) throws -> SwanProxyConnectionPlan {
        guard let method = permittedMethods[request.method] else {
            throw SwanError.malformed("proxied method is not permitted")
        }
        guard timeout > 0, timeout <= maximumTransportTimeout, timeout.isFinite,
              (1 ... 16 * 1_048_576).contains(maximumBodyBytes),
              let components = URLComponents(url: request.url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              let hostname = components.host, !hostname.isEmpty,
              components.user == nil, components.password == nil, components.fragment == nil,
              !approvedPeers.isEmpty, approvedPeers.count <= 32,
              // Deterministic selection so a retried request reproduces the
              // same peer, and so no ordering nondeterminism enters the audit.
              let peer = approvedPeers.sorted(by: { $0.description < $1.description }).first else {
            throw SwanError.unauthorized("proxied XRPC request is not peer-pinned")
        }
        guard scheme == "https" || (scheme == "http" && hostname == "localhost") else {
            throw SwanError.unauthorized("proxied XRPC URL scheme is invalid")
        }
        let port = components.port ?? (scheme == "https" ? 443 : 80)
        guard (1 ... 65_535).contains(port) else {
            throw SwanError.malformed("proxied XRPC URL port is invalid")
        }

        let body = request.body ?? Data()
        switch method {
        case .GET:
            guard body.isEmpty else {
                throw SwanError.malformed("proxied GET must not carry a request body")
            }
        default:
            guard body.count <= maximumRequestBodyBytes else {
                throw SwanError.malformed("proxied request body exceeds its bound")
            }
        }

        // Keep the origin-form target byte-identical to what the client sent:
        // `URL.path` percent-decodes, which would silently rewrite an encoded
        // path segment on the way to the upstream service.
        let encodedPath = components.percentEncodedPath
        let path = encodedPath.isEmpty ? "/" : encodedPath
        guard path.hasPrefix("/") else {
            throw SwanError.malformed("proxied XRPC path is not origin-form")
        }
        let uri: String = {
            guard let query = components.percentEncodedQuery, !query.isEmpty else { return path }
            return "\(path)?\(query)"
        }()
        guard uri.utf8.allSatisfy({ (0x21 ... 0x7E).contains($0) }), uri.utf8.count <= 8_192 else {
            throw SwanError.malformed("proxied XRPC request target is invalid")
        }

        var headers = HTTPHeaders()
        headers.add(name: "host", value: proxyHostHeader(hostname: hostname, port: port, scheme: scheme))
        headers.add(name: "content-length", value: String(body.count))
        headers.add(name: "connection", value: "close")
        guard request.headers.count <= 64 else {
            throw SwanError.malformed("proxied XRPC request has too many headers")
        }
        for header in request.headers {
            guard isValidHeaderName(header.name), isValidHeaderValue(header.value) else {
                throw SwanError.malformed("proxied XRPC header is invalid")
            }
            guard !reservedHeaderNames.contains(header.name.lowercased()) else { continue }
            headers.add(name: header.name, value: header.value)
        }

        return SwanProxyConnectionPlan(
            peer: peer,
            sniHostname: hostname,
            port: port,
            scheme: scheme,
            method: method,
            uri: uri,
            headers: headers,
            body: body
        )
    }

    private func makeRequest(
        group: MultiThreadedEventLoopGroup,
        tlsContext: NIOSSLContext,
        url: URL,
        plan: SwanProxyConnectionPlan,
        timeout: TimeInterval,
        maximumBodyBytes: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        let responsePromise = group.next().makePromise(of: OAuthRemoteHTTPResponse.self)
        let peer = plan.peer
        let hostname = plan.sniHostname
        let scheme = plan.scheme
        let bootstrap = ClientBootstrap(group: group)
            .channelOption(ChannelOptions.connectTimeout, value: .milliseconds(Int64(timeout * 1_000)))
            .channelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)
            .channelInitializer { channel in
                do {
                    if scheme == "https" {
                        // SNI is the URL hostname even though the socket is
                        // pinned to `peer`, so BoringSSL still performs full
                        // certificate name verification against the host the
                        // caller asked for.
                        try channel.pipeline.syncOperations.addHandler(
                            NIOSSLClientHandler(context: tlsContext, serverHostname: hostname)
                        )
                    }
                    try channel.pipeline.syncOperations.addHTTPClientHandlers()
                    try channel.pipeline.syncOperations.addHandler(
                        OAuthDocumentResponseHandler(
                            responsePromise: responsePromise,
                            expectedPeer: peer,
                            requestURL: url,
                            maximumBodyBytes: maximumBodyBytes,
                            timeout: timeout,
                            label: "proxied XRPC"
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
            channel = try await bootstrap.connect(host: peer.description, port: plan.port).get()
        } catch {
            responsePromise.fail(error)
            throw error
        }
        do {
            guard proxySocketPeer(channel.remoteAddress) == peer else {
                throw SwanError.unauthorized("proxied XRPC connected peer did not match its pin")
            }
            let head = HTTPRequestHead(
                version: .http1_1, method: plan.method, uri: plan.uri, headers: plan.headers
            )
            try await channel.writeAndFlush(HTTPClientRequestPart.head(head)).get()
            if !plan.body.isEmpty {
                var buffer = channel.allocator.buffer(capacity: plan.body.count)
                buffer.writeBytes(plan.body)
                try await channel.writeAndFlush(HTTPClientRequestPart.body(.byteBuffer(buffer))).get()
            }
            try await channel.writeAndFlush(HTTPClientRequestPart.end(nil)).get()
            let response = try await responsePromise.futureResult.get()
            try? await channel.close().get()
            return response
        } catch {
            try? await channel.close().get()
            throw error
        }
    }

    /// RFC 9110 token characters. Anything else — including CR, LF, NUL, space,
    /// and separators — cannot become a header name.
    private static func isValidHeaderName(_ name: String) -> Bool {
        guard !name.isEmpty, name.utf8.count <= 256 else { return false }
        return name.utf8.allSatisfy { byte in
            switch byte {
            case 0x30 ... 0x39, 0x41 ... 0x5A, 0x61 ... 0x7A: true
            case UInt8(ascii: "!"), UInt8(ascii: "#"), UInt8(ascii: "$"), UInt8(ascii: "%"),
                 UInt8(ascii: "&"), UInt8(ascii: "'"), UInt8(ascii: "*"), UInt8(ascii: "+"),
                 UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "^"), UInt8(ascii: "_"),
                 UInt8(ascii: "`"), UInt8(ascii: "|"), UInt8(ascii: "~"): true
            default: false
            }
        }
    }

    /// Visible ASCII plus horizontal tab. This is what stops a caller-supplied
    /// value from injecting a CRLF and forging a second request or header.
    private static func isValidHeaderValue(_ value: String) -> Bool {
        guard value.utf8.count <= 8_192 else { return false }
        return value.utf8.allSatisfy { byte in
            byte == 0x09 || (0x20 ... 0x7E).contains(byte)
        }
    }
}

private func proxySocketPeer(_ address: SocketAddress?) -> OAuthIPAddress? {
    guard let ip = address?.ipAddress else { return nil }
    return OAuthIPAddress(literal: ip)
}

private func proxyHostHeader(hostname: String, port: Int, scheme: String) -> String {
    let defaultPort = scheme == "https" ? 443 : 80
    return port == defaultPort ? hostname : "\(hostname):\(port)"
}
