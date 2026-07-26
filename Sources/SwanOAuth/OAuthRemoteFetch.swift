import AsyncHTTPClient
import Foundation
import SwanCore

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// A parsed IP address used for DNS and final-peer policy enforcement. The
/// value keeps network-order bytes, avoiding string-prefix classification bugs.
public enum OAuthIPAddress: Hashable, Sendable, Equatable, CustomStringConvertible {
    case ipv4(UInt32)
    case ipv6(Data)

    public init?(literal: String) {
        let input = literal.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        var ipv4 = in_addr()
        if input.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            let bytes = [UInt8](Data(bytes: &ipv4, count: MemoryLayout<in_addr>.size))
            guard bytes.count == 4 else { return nil }
            self = .ipv4(
                (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16) |
                    (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
            )
        } else {
            var ipv6 = in6_addr()
            guard input.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 else { return nil }
            let bytes = Data(bytes: &ipv6, count: MemoryLayout<in6_addr>.size)
            guard bytes.count == 16 else { return nil }
            self = .ipv6(bytes)
        }
    }

    public var description: String {
        switch self {
        case let .ipv4(value):
            return "\((value >> 24) & 0xFF).\((value >> 16) & 0xFF).\((value >> 8) & 0xFF).\(value & 0xFF)"
        case let .ipv6(bytes):
            guard bytes.count == 16 else { return "[invalid IPv6]" }
            var raw = in6_addr()
            bytes.withUnsafeBytes { source in
                withUnsafeMutableBytes(of: &raw) { destination in destination.copyBytes(from: source) }
            }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &raw, &buffer, socklen_t(buffer.count)) != nil else {
                return "[invalid IPv6]"
            }
            return String(
                decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
                as: UTF8.self
            )
        }
    }

    fileprivate var isLoopback: Bool {
        switch self {
        case let .ipv4(value): (value >> 24) == 127
        case let .ipv6(bytes): bytes == Data(repeating: 0, count: 15) + Data([1])
        }
    }

    /// True only for globally routable addresses. The intentional deny list
    /// includes private, loopback, link-local, CGNAT, documentation, multicast,
    /// and other reserved/special-purpose ranges rather than merely RFC1918.
    fileprivate var isPublicInternetAddress: Bool {
        switch self {
        case let .ipv4(value):
            let first = UInt8((value >> 24) & 0xFF)
            let second = UInt8((value >> 16) & 0xFF)
            let third = UInt8((value >> 8) & 0xFF)
            if first == 0 || first == 10 || first == 127 || first >= 224 { return false }
            if first == 100 && (64 ... 127).contains(second) { return false }
            if first == 169 && second == 254 { return false }
            if first == 172 && (16 ... 31).contains(second) { return false }
            if first == 192 && second == 0 && third == 0 { return false }
            if first == 192 && second == 0 && third == 2 { return false }
            if first == 192 && second == 88 && third == 99 { return false }
            if first == 192 && second == 168 { return false }
            if first == 198 && (second == 18 || second == 19) { return false }
            if first == 198 && second == 51 && third == 100 { return false }
            if first == 203 && second == 0 && third == 113 { return false }
            return true
        case let .ipv6(bytes):
            guard bytes.count == 16 else { return false }
            // IPv4-mapped IPv6 inherits the IPv4 decision instead of creating
            // an alternate spelling for an unsafe peer.
            if bytes.prefix(10).allSatisfy({ $0 == 0 }), bytes[10] == 0xFF, bytes[11] == 0xFF {
                let value = (UInt32(bytes[12]) << 24) | (UInt32(bytes[13]) << 16) |
                    (UInt32(bytes[14]) << 8) | UInt32(bytes[15])
                return OAuthIPAddress.ipv4(value).isPublicInternetAddress
            }
            // Global unicast is 2000::/3. Everything else includes unspecified,
            // loopback, ULA, link-local, multicast, and reserved space.
            guard (bytes[0] & 0xE0) == 0x20 else { return false }
            // IETF protocol assignments and documentation prefixes are not
            // external destinations for OAuth metadata retrieval.
            if bytes[0] == 0x20, bytes[1] == 0x01, bytes[2] == 0x0D, bytes[3] == 0xB8 { return false }
            if bytes[0] == 0x20, bytes[1] == 0x01, bytes[2] == 0x00, bytes[3] < 0x20 { return false }
            return true
        }
    }
}

/// Explicit, exact lab-address escape hatch. It is configuration, not an
/// implicit `localhost`/private-network relaxation.
public struct OAuthRemoteNetworkAllowlist: Sendable, Equatable {
    public let addresses: Set<OAuthIPAddress>

    public init(addresses: Set<OAuthIPAddress> = []) {
        self.addresses = addresses
    }
}

public struct OAuthRemoteFetchPolicy: Sendable, Equatable {
    public let allowLocalhostDevelopment: Bool
    public let networkAllowlist: OAuthRemoteNetworkAllowlist
    public let maximumBodyBytes: Int
    public let timeout: TimeInterval

    public init(
        allowLocalhostDevelopment: Bool = false,
        networkAllowlist: OAuthRemoteNetworkAllowlist = .init(),
        maximumBodyBytes: Int = 256 * 1024,
        timeout: TimeInterval = 5
    ) throws {
        guard (1_024 ... 1_048_576).contains(maximumBodyBytes), timeout > 0, timeout <= 30, timeout.isFinite else {
            throw SwanError.malformed("OAuth remote fetch policy bounds are invalid")
        }
        self.allowLocalhostDevelopment = allowLocalhostDevelopment
        self.networkAllowlist = networkAllowlist
        self.maximumBodyBytes = maximumBodyBytes
        self.timeout = timeout
    }

    fileprivate func validateURL(_ url: URL) throws -> String {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(), let host = components.host,
              components.user == nil, components.password == nil, components.fragment == nil else {
            throw SwanError.unauthorized("OAuth remote URL is malformed")
        }
        let exactLocalhost = scheme == "http" && host == "localhost" &&
            components.port == nil && (components.path.isEmpty || components.path == "/")
        guard scheme == "https" || (allowLocalhostDevelopment && exactLocalhost) else {
            throw SwanError.unauthorized("OAuth remote URL must use HTTPS")
        }
        if let literal = OAuthIPAddress(literal: host) {
            guard permits(literal, forHost: host) else {
                throw SwanError.unauthorized("OAuth remote IP literal is not public")
            }
        }
        return host
    }

    fileprivate func validateResolved(_ addresses: [OAuthIPAddress], host: String) throws {
        guard !addresses.isEmpty, addresses.count <= 32,
              addresses.allSatisfy({ permits($0, forHost: host) }) else {
            throw SwanError.unauthorized("OAuth remote host resolved to a forbidden address")
        }
    }

    fileprivate func permits(_ address: OAuthIPAddress, forHost host: String) -> Bool {
        if networkAllowlist.addresses.contains(address) { return true }
        if allowLocalhostDevelopment && host == "localhost" && address.isLoopback { return true }
        return address.isPublicInternetAddress
    }
}

/// Compatibility surface for existing call sites. Unlike the old permissive
/// helper, `allowLoopbackDevelopment` only enables literal `http://localhost`
/// and never makes `127.0.0.1` or `::1` client metadata URLs acceptable.
public enum OAuthRemoteURLPolicy {
    public static func validate(_ url: URL, allowLoopbackDevelopment: Bool = false) throws {
        let policy = try OAuthRemoteFetchPolicy(allowLocalhostDevelopment: allowLoopbackDevelopment)
        _ = try policy.validateURL(url)
    }
}

public protocol OAuthHostnameResolving: Sendable {
    func resolve(host: String) async throws -> [OAuthIPAddress]
}

/// System DNS is kept behind this protocol so tests can simulate private A/AAAA
/// answers and a future hardened connector can share the exact resolution path.
public struct SystemOAuthHostnameResolver: OAuthHostnameResolving {
    private static let queue = DispatchQueue(label: "blue.catbird.swan.oauth-dns", qos: .utility)

    public init() {}

    public func resolve(host: String) async throws -> [OAuthIPAddress] {
        if let literal = OAuthIPAddress(literal: host) { return [literal] }
        return try await withCheckedThrowingContinuation { continuation in
            Self.queue.async {
                var hints = addrinfo()
                hints.ai_flags = AI_ADDRCONFIG
                hints.ai_family = AF_UNSPEC
                #if os(Linux)
                hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
                #else
                hints.ai_socktype = SOCK_STREAM
                #endif
                var result: UnsafeMutablePointer<addrinfo>?
                let status = getaddrinfo(host, nil, &hints, &result)
                guard status == 0, let result else {
                    continuation.resume(throwing: SwanError.unavailable("OAuth DNS resolution failed"))
                    return
                }
                defer { freeaddrinfo(result) }
                var values = Set<OAuthIPAddress>()
                var cursor: UnsafeMutablePointer<addrinfo>? = result
                while let current = cursor {
                    defer { cursor = current.pointee.ai_next }
                    guard let socketAddress = current.pointee.ai_addr else { continue }
                    switch Int32(current.pointee.ai_family) {
                    case AF_INET:
                        var address = socketAddress.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                        let bytes = [UInt8](Data(bytes: &address, count: MemoryLayout<in_addr>.size))
                        guard bytes.count == 4 else { continue }
                        values.insert(.ipv4(
                            (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16) |
                                (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
                        ))
                    case AF_INET6:
                        var address = socketAddress.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
                        let bytes = Data(bytes: &address, count: MemoryLayout<in6_addr>.size)
                        guard bytes.count == 16 else { continue }
                        values.insert(.ipv6(bytes))
                    default:
                        continue
                    }
                }
                continuation.resume(returning: values.sorted { $0.description < $1.description })
            }
        }
    }
}

public struct OAuthRemoteHTTPResponse: Sendable {
    public let status: Int
    /// Header names are lowercased by the AHC adapter. Fakes may provide any
    /// case; the fetcher canonicalizes them before validation.
    public let headers: [String: [String]]
    public let body: Data
    public let responseURL: URL
    public let redirectCount: Int
    /// A hardened connector should report the actual peer address here. AHC's
    /// high-level API currently cannot, so its adapter returns nil (documented
    /// in `AsyncHTTPClientOAuthTransport`).
    public let connectedPeerAddress: OAuthIPAddress?

    public init(
        status: Int,
        headers: [String: [String]],
        body: Data,
        responseURL: URL,
        redirectCount: Int = 0,
        connectedPeerAddress: OAuthIPAddress? = nil
    ) {
        self.status = status
        self.headers = headers
        self.body = body
        self.responseURL = responseURL
        self.redirectCount = redirectCount
        self.connectedPeerAddress = connectedPeerAddress
    }
}

public protocol OAuthRemoteTransport: Sendable {
    func get(url: URL, timeout: TimeInterval, maximumBodyBytes: Int) async throws -> OAuthRemoteHTTPResponse
}

/// AsyncHTTPClient adapter configured to disallow redirects and bound each
/// response body. It preflights and postflights DNS through
/// `OAuthRemoteDocumentFetcher`, but AHC does not expose the final connected
/// peer address (and Apple's Network.framework can resolve independently).
/// Therefore this adapter cannot by itself prove DNS re-resolution safety; a
/// deployment needing that guarantee must inject a transport that reports and
/// enforces `connectedPeerAddress` before sending HTTP bytes.
public final class AsyncHTTPClientOAuthTransport: OAuthRemoteTransport {
    private let client: HTTPClient
    private let maximumTransportTimeout: TimeInterval

    public init(maximumTransportTimeout: TimeInterval = 5) throws {
        guard maximumTransportTimeout > 0, maximumTransportTimeout <= 30, maximumTransportTimeout.isFinite else {
            throw SwanError.malformed("OAuth transport timeout is invalid")
        }
        self.maximumTransportTimeout = maximumTransportTimeout
        let timeout = HTTPClient.Configuration.Timeout(
            connect: .milliseconds(Int64(maximumTransportTimeout * 1_000)),
            read: .milliseconds(Int64(maximumTransportTimeout * 1_000))
        )
        client = HTTPClient(configuration: .init(
            redirectConfiguration: .disallow,
            timeout: timeout,
            decompression: .disabled
        ))
    }

    deinit {
        client.shutdown { _ in }
    }

    public func get(url: URL, timeout: TimeInterval, maximumBodyBytes: Int) async throws -> OAuthRemoteHTTPResponse {
        guard timeout <= maximumTransportTimeout else {
            throw SwanError.unavailable("OAuth fetch timeout exceeds transport policy")
        }
        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = .GET
        request.headers.add(name: "accept", value: "application/json")
        let response = try await client.execute(
            request,
            timeout: .milliseconds(Int64(timeout * 1_000))
        )
        let buffer = try await response.body.collect(upTo: maximumBodyBytes)
        let bytes = buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes) ?? []
        var headers: [String: [String]] = [:]
        for header in response.headers {
            headers[header.name.lowercased(), default: []].append(header.value)
        }
        return OAuthRemoteHTTPResponse(
            status: Int(response.status.code),
            headers: headers,
            body: Data(bytes),
            responseURL: response.url ?? url,
            redirectCount: max(0, response.history.count - 1),
            connectedPeerAddress: nil
        )
    }
}

/// Applies the complete local policy around a single GET. It intentionally has
/// no cache: only a domain loader can know that a fetched JSON body was fully
/// validated before retaining it.
public struct OAuthRemoteDocumentFetcher: Sendable {
    public let policy: OAuthRemoteFetchPolicy
    private let resolver: any OAuthHostnameResolving
    private let transport: any OAuthRemoteTransport

    public init(
        policy: OAuthRemoteFetchPolicy,
        resolver: any OAuthHostnameResolving = SystemOAuthHostnameResolver(),
        transport: any OAuthRemoteTransport
    ) {
        self.policy = policy
        self.resolver = resolver
        self.transport = transport
    }

    public func fetchJSON(from url: URL) async throws -> Data {
        let host = try policy.validateURL(url)
        try policy.validateResolved(try await resolver.resolve(host: host), host: host)
        let response: OAuthRemoteHTTPResponse
        do {
            response = try await transport.get(
                url: url,
                timeout: policy.timeout,
                maximumBodyBytes: policy.maximumBodyBytes
            )
        } catch let error as SwanError {
            throw error
        } catch {
            throw SwanError.unavailable("OAuth remote fetch failed")
        }
        // Resolve again after the request. This catches an answer which changed
        // during the operation; it is not a substitute for a peer-reporting
        // hardened connector (see AsyncHTTPClientOAuthTransport's doc comment).
        try policy.validateResolved(try await resolver.resolve(host: host), host: host)
        guard response.redirectCount == 0,
              response.responseURL.absoluteString == url.absoluteString,
              response.status == 200 else {
            throw SwanError.unauthorized("OAuth remote document did not return exact HTTP 200")
        }
        if let peer = response.connectedPeerAddress {
            guard policy.permits(peer, forHost: host) else {
                throw SwanError.unauthorized("OAuth remote peer address is forbidden")
            }
        }
        let headers = response.headers.reduce(into: [String: [String]]()) { output, item in
            output[item.key.lowercased(), default: []].append(contentsOf: item.value)
        }
        guard let contentType = headers["content-type"], contentType.count == 1,
              isJSONContentType(contentType[0]) else {
            throw SwanError.unauthorized("OAuth remote document has non-JSON content type")
        }
        if let lengths = headers["content-length"] {
            guard lengths.count == 1, let declared = strictDecimal(lengths[0]),
                  declared <= policy.maximumBodyBytes, declared == response.body.count else {
                throw SwanError.unauthorized("OAuth remote document content length is invalid")
            }
        }
        guard !response.body.isEmpty, response.body.count <= policy.maximumBodyBytes else {
            throw SwanError.unauthorized("OAuth remote document body is out of bounds")
        }
        // The duplicate-member scanner also verifies complete JSON syntax. Keep
        // the bytes unmodified so metadata/JWKS decoders see exactly what was
        // validated and any caller can bind an audit hash if needed.
        try StrictJSON.validate(response.body)
        return response.body
    }

    private func isJSONContentType(_ value: String) -> Bool {
        let mediaType = value.split(separator: ";", maxSplits: 1)[0].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return mediaType == "application/json"
    }

    private func strictDecimal(_ value: String) -> Int? {
        guard !value.isEmpty, value.utf8.allSatisfy({ (48 ... 57).contains($0) }) else { return nil }
        return Int(value)
    }
}
