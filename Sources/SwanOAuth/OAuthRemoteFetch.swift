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

    public var isLoopback: Bool {
        switch self {
        case let .ipv4(value): SwanPublicAddressPolicy.isLoopback(ipv4: value)
        case let .ipv6(bytes): SwanPublicAddressPolicy.isLoopback(ipv6: bytes)
        }
    }

    /// True only for globally routable addresses. The intentional deny list
    /// includes private, loopback, link-local, CGNAT, documentation, multicast,
    /// and other reserved/special-purpose ranges rather than merely RFC1918.
    ///
    /// The table itself lives in ``SwanPublicAddressPolicy`` because the AT
    /// handle verifier resolves attacker-selectable hostnames through the same
    /// boundary. Keeping two copies is how this one went on accepting 6to4
    /// after the handle copy stopped rejecting it in `b5f1610` (2026-07-27).
    public var isPublicInternetAddress: Bool {
        switch self {
        case let .ipv4(value):
            SwanPublicAddressPolicy.isPublicInternetAddress(ipv4: value)
        case let .ipv6(bytes):
            SwanPublicAddressPolicy.isPublicInternetAddress(ipv6: bytes)
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

    public func validateURL(_ url: URL) throws -> String {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(), let host = components.host,
              components.user == nil, components.password == nil, components.fragment == nil else {
            throw SwanError.unauthorized("OAuth remote URL is malformed")
        }
        // The localhost exception is an explicit development-only escape
        // hatch.  Local XRPC services commonly use a non-default port and a
        // method path; keeping the host literal still prevents it from
        // becoming a general private-network allowance.
        let localhostDevelopment = scheme == "http" && host == "localhost"
        guard scheme == "https" || (allowLocalhostDevelopment && localhostDevelopment) else {
            throw SwanError.unauthorized("OAuth remote URL must use HTTPS")
        }
        if let literal = OAuthIPAddress(literal: host) {
            guard permits(literal, forHost: host) else {
                throw SwanError.unauthorized("OAuth remote IP literal is not public")
            }
        }
        return host
    }

    public func validateResolved(_ addresses: [OAuthIPAddress], host: String) throws {
        guard !addresses.isEmpty, addresses.count <= 32,
              addresses.allSatisfy({ permits($0, forHost: host) }) else {
            throw SwanError.unauthorized("OAuth remote host resolved to a forbidden address")
        }
    }

    public func permits(_ address: OAuthIPAddress, forHost host: String) -> Bool {
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

/// Bounds blocking `getaddrinfo` work independently of async request
/// cancellation. A timed-out caller cannot cancel the libc call, so its lease
/// is released only when that blocking operation actually returns. This
/// prevents repeated DNS timeouts from accumulating an unbounded dispatch
/// backlog after the higher-level remote-fetch permit has been released.
final class OAuthBlockingDNSAdmission: @unchecked Sendable {
    static let shared = OAuthBlockingDNSAdmission(maximumOutstanding: 4)

    private let lock = NSLock()
    private let maximumOutstanding: Int
    private var outstanding = 0

    init(maximumOutstanding: Int) {
        precondition(maximumOutstanding > 0)
        self.maximumOutstanding = maximumOutstanding
    }

    func acquire() throws -> OAuthBlockingDNSLease {
        lock.lock()
        guard outstanding < maximumOutstanding else {
            lock.unlock()
            throw SwanError.unavailable(
                "OAuth DNS resolver capacity is exhausted"
            )
        }
        outstanding += 1
        lock.unlock()
        return OAuthBlockingDNSLease(admission: self)
    }

    fileprivate func release() {
        lock.lock()
        precondition(outstanding > 0)
        outstanding -= 1
        lock.unlock()
    }

    var outstandingCountForTesting: Int {
        lock.lock()
        defer { lock.unlock() }
        return outstanding
    }
}

final class OAuthBlockingDNSLease: @unchecked Sendable {
    private let lock = NSLock()
    private var admission: OAuthBlockingDNSAdmission?

    fileprivate init(admission: OAuthBlockingDNSAdmission) {
        self.admission = admission
    }

    func release() {
        lock.lock()
        let held = admission
        admission = nil
        lock.unlock()
        held?.release()
    }

    deinit {
        release()
    }
}

/// Races DNS resolution against the same deadline used by the transport.
/// `getaddrinfo` does not expose a cancellation handle on every supported
/// platform, so this intentionally does not await a cancelled resolver task:
/// an unresponsive resolver cannot hold the caller past policy.timeout before
/// any network connection is attempted. The completion box is lock-protected
/// because it bridges that detached resolver work back to structured async
/// code exactly once.
private final class OAuthDNSResolutionDeadline: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<[OAuthIPAddress], Error>?
    private var result: Result<[OAuthIPAddress], Error>?

    func install(_ continuation: CheckedContinuation<[OAuthIPAddress], Error>) {
        lock.lock()
        if let result {
            lock.unlock()
            resume(continuation, with: result)
        } else {
            self.continuation = continuation
            lock.unlock()
        }
    }

    func complete(_ result: Result<[OAuthIPAddress], Error>) {
        lock.lock()
        guard self.result == nil else {
            lock.unlock()
            return
        }
        self.result = result
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        if let continuation {
            resume(continuation, with: result)
        }
    }

    private func resume(
        _ continuation: CheckedContinuation<[OAuthIPAddress], Error>,
        with result: Result<[OAuthIPAddress], Error>
    ) {
        switch result {
        case let .success(addresses):
            continuation.resume(returning: addresses)
        case let .failure(error):
            continuation.resume(throwing: error)
        }
    }
}

/// Internal rather than file-private because every caller that holds a lease
/// or an admission permit across hostname resolution needs this deadline. The
/// authenticated pipethrough is one of them: it resolves a request-selected
/// service hostname while holding a proxy lease.
func resolveOAuthHostname(
    _ resolver: any OAuthHostnameResolving,
    host: String,
    timeout: TimeInterval
) async throws -> [OAuthIPAddress] {
    let completion = OAuthDNSResolutionDeadline()
    let resolutionTask = Task { @Sendable in
        do {
            completion.complete(.success(try await resolver.resolve(host: host)))
        } catch {
            completion.complete(.failure(error))
        }
    }
    let timeoutNanoseconds = UInt64((timeout * 1_000_000_000).rounded(.up))
    let timeoutTask = Task { @Sendable in
        do {
            try await Task.sleep(nanoseconds: timeoutNanoseconds)
        } catch {
            return
        }
        resolutionTask.cancel()
        completion.complete(.failure(SwanError.unavailable("OAuth DNS resolution timed out")))
    }
    defer {
        resolutionTask.cancel()
        timeoutTask.cancel()
    }
    return try await withTaskCancellationHandler(
        operation: {
            try await withCheckedThrowingContinuation { continuation in
                completion.install(continuation)
            }
        },
        onCancel: {
            resolutionTask.cancel()
            timeoutTask.cancel()
            completion.complete(.failure(CancellationError()))
        }
    )
}

/// System DNS is kept behind this protocol so tests can simulate private A/AAAA
/// answers and a future hardened connector can share the exact resolution path.
public struct SystemOAuthHostnameResolver: OAuthHostnameResolving {
    /// Concurrent, with ``OAuthBlockingDNSAdmission`` as the sole bound on how
    /// many blocking `getaddrinfo` calls may be outstanding. A serial queue
    /// made those four permits unreachable — three permit holders would sit
    /// behind one unresponsive lookup — so a single blackholed nameserver
    /// stalled every OAuth, did:web, and pipethrough resolution in the
    /// process. The worst case is now four blocked dispatch threads instead
    /// of one, which is exactly what the admission limit is sized for.
    private static let queue = DispatchQueue(
        label: "blue.catbird.swan.oauth-dns",
        qos: .utility,
        attributes: .concurrent
    )

    public init() {}

    public func resolve(host: String) async throws -> [OAuthIPAddress] {
        if let literal = OAuthIPAddress(literal: host) { return [literal] }
        let admission = try OAuthBlockingDNSAdmission.shared.acquire()
        return try await withCheckedThrowingContinuation { continuation in
            Self.queue.async {
                defer { admission.release() }
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
    /// `approvedPeers` is the exact, policy-checked result of the DNS lookup
    /// immediately preceding this request. A production transport must select
    /// a literal member of this set before any HTTP bytes are sent.
    func get(
        url: URL,
        approvedPeers: Set<OAuthIPAddress>,
        timeout: TimeInterval,
        maximumBodyBytes: Int
    ) async throws -> OAuthRemoteHTTPResponse
}

/// Legacy compatibility type. It is deliberately disabled: AsyncHTTPClient
/// cannot report the actual connected peer, so it cannot meet the metadata
/// fetcher's DNS-rebinding proof. Production server setup uses
/// `NIOPeerPinnedOAuthDocumentTransport`, which connects a policy-approved
/// literal IP and reports that peer.
public final class AsyncHTTPClientOAuthTransport: OAuthRemoteTransport {
    public init(maximumTransportTimeout: TimeInterval = 5) throws {
        guard maximumTransportTimeout > 0, maximumTransportTimeout <= 30, maximumTransportTimeout.isFinite else {
            throw SwanError.malformed("OAuth transport timeout is invalid")
        }
        throw SwanError.unavailable(
            "AsyncHTTPClient cannot prove an OAuth metadata peer; use NIOPeerPinnedOAuthDocumentTransport"
        )
    }

    public func get(
        url _: URL,
        approvedPeers _: Set<OAuthIPAddress>,
        timeout _: TimeInterval,
        maximumBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        throw SwanError.unavailable(
            "AsyncHTTPClient cannot prove an OAuth metadata peer; use NIOPeerPinnedOAuthDocumentTransport"
        )
    }
}

/// One process-wide budget covers every outbound OAuth document, including
/// metadata and a metadata document's remote JWKS. Admission is deliberately
/// non-queueing: an attacker controlling many distinct URLs cannot turn the
/// server into an unbounded waiter or connection factory.
///
/// The budget is split rather than enlarged. `generalLimit` of the `limit`
/// permits are all an anonymous caller can reach, so slow attacker-controlled
/// origins arriving through PAR can never take the last permits away from a
/// client the account still holds a live authorization for — that client's
/// token refresh and revocation both revalidate metadata with `bypassCache`,
/// and denying them is the real damage in this finding. Enlarging the pool
/// instead would just raise the attacker's cost linearly while multiplying
/// concurrent outbound sockets.
final class OAuthRemoteFetchAdmission: @unchecked Sendable {
    static let shared = OAuthRemoteFetchAdmission(limit: 8, generalLimit: 6)

    private let lock = NSLock()
    private let limit: Int
    private let generalLimit: Int
    private var active = 0
    private var generalActive = 0

    init(limit: Int, generalLimit: Int) {
        precondition(generalLimit > 0 && generalLimit <= limit)
        self.limit = limit
        self.generalLimit = generalLimit
    }

    /// `reserved` may be passed only after the caller has proven, against
    /// durable state, that the client is one the account currently authorizes.
    /// It is never derived from request-supplied values.
    func acquire(reserved: Bool) throws -> OAuthRemoteFetchAdmissionLease {
        lock.lock()
        guard active < limit, reserved || generalActive < generalLimit else {
            lock.unlock()
            throw SwanError.unavailable(
                "OAuth remote fetch admission capacity is exhausted"
            )
        }
        active += 1
        if !reserved { generalActive += 1 }
        lock.unlock()
        return OAuthRemoteFetchAdmissionLease(admission: self, reserved: reserved)
    }

    fileprivate func release(reserved: Bool) {
        lock.lock()
        precondition(active > 0)
        active -= 1
        if !reserved {
            precondition(generalActive > 0)
            generalActive -= 1
        }
        lock.unlock()
    }

    /// Advisory: true when a reserved acquisition could currently succeed. It
    /// exists so a caller can skip the durable read that proves reserved
    /// eligibility when there is no slot left to win. `acquire` remains the
    /// authority.
    var mayHaveReservedCapacity: Bool {
        lock.lock()
        defer { lock.unlock() }
        return active < limit
    }

    var activeCountForTesting: Int {
        lock.lock()
        defer { lock.unlock() }
        return active
    }
}

final class OAuthRemoteFetchAdmissionLease: @unchecked Sendable {
    private let lock = NSLock()
    private let reserved: Bool
    private var admission: OAuthRemoteFetchAdmission?

    fileprivate init(admission: OAuthRemoteFetchAdmission, reserved: Bool) {
        self.admission = admission
        self.reserved = reserved
    }

    func release() {
        lock.lock()
        let heldAdmission = admission
        admission = nil
        lock.unlock()
        heldAdmission?.release(reserved: reserved)
    }

    deinit {
        release()
    }
}

/// Capability handed only to code already holding the process-wide admission
/// lease. A metadata loader keeps one lease across the metadata document and
/// its optional remote JWKS, so the second fetch cannot bypass or deadlock
/// against the same budget.
struct OAuthAdmittedRemoteDocumentFetcher: Sendable {
    fileprivate let fetcher: OAuthRemoteDocumentFetcher

    func fetchJSON(from url: URL) async throws -> Data {
        try await fetchJSONWithHeaders(from: url).data
    }

    func fetchJSONWithHeaders(from url: URL) async throws -> (data: Data, headers: [String: [String]]) {
        try await fetcher.fetchJSONWithoutAdmissionWithHeaders(from: url)
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
        try await fetchJSONWithHeaders(from: url).data
    }

    public func fetchJSONWithHeaders(from url: URL) async throws -> (data: Data, headers: [String: [String]]) {
        _ = try policy.validateURL(url)
        return try await withAdmission { admittedFetcher in
            try await admittedFetcher.fetchJSONWithHeaders(from: url)
        }
    }

    /// `reservedCapacityCheck` is consulted only after the general tier is
    /// already full, so the durable read it performs costs nothing until the
    /// process is actually under contention. Returning false preserves the
    /// original typed rejection rather than substituting a different one.
    func withAdmission<T: Sendable>(
        reservedCapacityCheck: @escaping @Sendable () async -> Bool = { false },
        _ operation: @escaping @Sendable (
            OAuthAdmittedRemoteDocumentFetcher
        ) async throws -> T
    ) async throws -> T {
        try Task.checkCancellation()
        let admission: OAuthRemoteFetchAdmissionLease
        do {
            admission = try OAuthRemoteFetchAdmission.shared.acquire(
                reserved: false
            )
        } catch {
            guard OAuthRemoteFetchAdmission.shared.mayHaveReservedCapacity,
                  await reservedCapacityCheck() else { throw error }
            admission = try OAuthRemoteFetchAdmission.shared.acquire(
                reserved: true
            )
        }
        defer { admission.release() }
        return try await operation(
            OAuthAdmittedRemoteDocumentFetcher(fetcher: self)
        )
    }

    fileprivate func fetchJSONWithoutAdmission(from url: URL) async throws -> Data {
        try await fetchJSONWithoutAdmissionWithHeaders(from: url).data
    }

    fileprivate func fetchJSONWithoutAdmissionWithHeaders(from url: URL) async throws
        -> (data: Data, headers: [String: [String]])
    {
        let host = try policy.validateURL(url)
        let preflightPeers = Set(try await resolveOAuthHostname(
            resolver, host: host, timeout: policy.timeout
        ))
        try policy.validateResolved(Array(preflightPeers), host: host)
        let response: OAuthRemoteHTTPResponse
        do {
            response = try await transport.get(
                url: url,
                approvedPeers: preflightPeers,
                timeout: policy.timeout,
                maximumBodyBytes: policy.maximumBodyBytes
            )
        } catch let error as SwanError {
            throw error
        } catch {
            throw SwanError.unavailable("OAuth remote fetch failed")
        }
        // Resolve again after the request, then require the observed socket
        // peer to be in *both* answer sets. A transport without a peer proof
        // is not a valid remote-document transport.
        let postflightPeers = Set(try await resolveOAuthHostname(
            resolver, host: host, timeout: policy.timeout
        ))
        try policy.validateResolved(Array(postflightPeers), host: host)
        guard response.redirectCount == 0,
              response.responseURL.absoluteString == url.absoluteString,
              response.status == 200 else {
            throw SwanError.unauthorized("OAuth remote document did not return exact HTTP 200")
        }
        guard let peer = response.connectedPeerAddress,
              preflightPeers.contains(peer),
              postflightPeers.contains(peer),
              policy.permits(peer, forHost: host) else {
            throw SwanError.unauthorized("OAuth remote peer was not in both approved DNS answer sets")
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
        return (data: response.body, headers: headers)
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

/// A bounded POST transport for service-to-service control-plane traffic.
/// This is separate from `OAuthRemoteTransport` so existing metadata fetch
/// fakes cannot accidentally gain a request-body capability.
public protocol OAuthRemotePostTransport: Sendable {
    /// `approvedPeers` is the exact, policy-checked DNS answer set observed
    /// immediately before this request. A concrete transport must reject its
    /// configured literal pin unless it is a member of this set, before
    /// opening a connection or writing any request bytes.
    func post(
        url: URL,
        approvedPeers: Set<OAuthIPAddress>,
        headers: [String: String],
        body: Data,
        timeout: TimeInterval,
        maximumResponseBodyBytes: Int
    ) async throws -> OAuthRemoteHTTPResponse
}

/// Compatibility adapter for callers that need a bounded AsyncHTTPClient
/// request but do *not* require final-peer proof. It is deliberately
/// unavailable for notification delivery: AsyncHTTPClient's high-level API
/// cannot report the connected peer, so sending a service JWT through it
/// would create a DNS-rebinding escape hatch. Supply a transport that reports
/// a concrete connected peer to ``OAuthBoundedJSONPoster`` instead.
public final class AsyncHTTPClientOAuthPostTransport: OAuthRemotePostTransport {
    private let client: HTTPClient
    private let maximumTransportTimeout: TimeInterval

    public init(maximumTransportTimeout: TimeInterval = 5) throws {
        guard maximumTransportTimeout > 0,
              maximumTransportTimeout <= 30,
              maximumTransportTimeout.isFinite else {
            throw SwanError.malformed("OAuth POST transport timeout is invalid")
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

    public func post(
        url: URL,
        approvedPeers _: Set<OAuthIPAddress>,
        headers: [String: String],
        body: Data,
        timeout: TimeInterval,
        maximumResponseBodyBytes: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        guard timeout <= maximumTransportTimeout,
              body.count <= 64 * 1_024 else {
            throw SwanError.unavailable("OAuth POST transport bounds exceeded")
        }
        _ = (url, headers, body, maximumResponseBodyBytes)
        throw SwanError.unavailable(
            "AsyncHTTPClient notification transport cannot prove the final connected peer"
        )
    }
}

/// Applies the same URL, DNS re-resolution, peer-address, redirect, timeout,
/// and response-size policy as OAuth metadata discovery to a small JSON POST.
/// It intentionally does not inspect a success body: service notifications
/// have no response payload contract and must not become a data-fetch path.
public struct OAuthBoundedJSONPoster: Sendable {
    public let policy: OAuthRemoteFetchPolicy
    private let resolver: any OAuthHostnameResolving
    private let transport: any OAuthRemotePostTransport

    public init(
        policy: OAuthRemoteFetchPolicy,
        resolver: any OAuthHostnameResolving = SystemOAuthHostnameResolver(),
        transport: any OAuthRemotePostTransport
    ) {
        self.policy = policy
        self.resolver = resolver
        self.transport = transport
    }

    public func postJSON(
        to url: URL,
        headers: [String: String],
        body: Data
    ) async throws {
        guard !body.isEmpty, body.count <= min(policy.maximumBodyBytes, 64 * 1_024) else {
            throw SwanError.malformed("outbound JSON body is out of bounds")
        }
        let host = try policy.validateURL(url)
        let initialAddresses = Set(try await resolveOAuthHostname(
            resolver, host: host, timeout: policy.timeout
        ))
        try policy.validateResolved(Array(initialAddresses), host: host)
        let response: OAuthRemoteHTTPResponse
        do {
            response = try await transport.post(
                url: url,
                approvedPeers: initialAddresses,
                headers: headers,
                body: body,
                timeout: policy.timeout,
                maximumResponseBodyBytes: policy.maximumBodyBytes
            )
        } catch let error as SwanError {
            throw error
        } catch {
            throw SwanError.unavailable("outbound notification request failed")
        }
        // Re-resolve after the request and require the transport to prove the
        // actual peer belongs to *both* approved answer sets. A nil peer is
        // never a permissive fallback for service-to-service delivery.
        let finalAddresses = Set(try await resolveOAuthHostname(
            resolver, host: host, timeout: policy.timeout
        ))
        try policy.validateResolved(Array(finalAddresses), host: host)
        guard response.redirectCount == 0,
              response.responseURL.absoluteString == url.absoluteString,
              (200 ... 299).contains(response.status),
              response.body.count <= policy.maximumBodyBytes else {
            throw SwanError.unauthorized("outbound notification response is invalid")
        }
        guard let peer = response.connectedPeerAddress,
              initialAddresses.contains(peer),
              finalAddresses.contains(peer),
              policy.permits(peer, forHost: host) else {
            throw SwanError.unauthorized("outbound notification peer is forbidden")
        }
        let normalized = response.headers.reduce(into: [String: [String]]()) { output, item in
            output[item.key.lowercased(), default: []].append(contentsOf: item.value)
        }
        if let lengths = normalized["content-length"] {
            guard lengths.count == 1,
                  let declared = strictOutboundDecimal(lengths[0]),
                  declared == response.body.count,
                  declared <= policy.maximumBodyBytes else {
                throw SwanError.unauthorized("outbound notification response length is invalid")
            }
        }
    }
}

private func strictOutboundDecimal(_ value: String) -> Int? {
    guard !value.isEmpty,
          value.utf8.allSatisfy({ (48 ... 57).contains($0) }) else {
        return nil
    }
    return Int(value)
}
