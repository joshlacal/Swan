import CATHandleDNS
import Foundation
import SwanCore

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

public enum ATHandleVerificationError: Error, Sendable, Equatable {
    case verificationFailed
    case unavailable
}

public enum ATHandleIPAddress: Hashable, Sendable, Equatable, CustomStringConvertible {
    case ipv4(UInt32)
    case ipv6(Data)

    public init?(literal: String) {
        let input = literal.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        var ipv4 = in_addr()
        if input.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            let bytes = [UInt8](Data(bytes: &ipv4, count: MemoryLayout<in_addr>.size))
            guard bytes.count == 4 else { return nil }
            self = .ipv4(
                UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16
                    | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
            )
            return
        }
        var ipv6 = in6_addr()
        guard input.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 else {
            return nil
        }
        let bytes = Data(bytes: &ipv6, count: MemoryLayout<in6_addr>.size)
        guard bytes.count == 16 else { return nil }
        self = .ipv6(bytes)
    }

    public var description: String {
        switch self {
        case let .ipv4(value):
            return "\((value >> 24) & 0xff).\((value >> 16) & 0xff)."
                + "\((value >> 8) & 0xff).\(value & 0xff)"
        case let .ipv6(bytes):
            guard bytes.count == 16 else { return "[invalid]" }
            var raw = in6_addr()
            bytes.withUnsafeBytes { source in
                withUnsafeMutableBytes(of: &raw) { destination in
                    destination.copyBytes(from: source)
                }
            }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &raw, &buffer, socklen_t(buffer.count)) != nil else {
                return "[invalid]"
            }
            return String(
                decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
                as: UTF8.self
            )
        }
    }

    public var isLoopback: Bool {
        switch self {
        case let .ipv4(value):
            return value >> 24 == 127
        case let .ipv6(bytes):
            return bytes == Data(repeating: 0, count: 15) + Data([1])
        }
    }

    public var isPublicInternetAddress: Bool {
        switch self {
        case let .ipv4(value):
            let first = UInt8((value >> 24) & 0xff)
            let second = UInt8((value >> 16) & 0xff)
            let third = UInt8((value >> 8) & 0xff)
            if first == 0 || first == 10 || first == 127 || first >= 224 { return false }
            if first == 100, (64 ... 127).contains(second) { return false }
            if first == 169, second == 254 { return false }
            if first == 172, (16 ... 31).contains(second) { return false }
            if first == 192, second == 0, third == 0 { return false }
            if first == 192, second == 0, third == 2 { return false }
            if first == 192, second == 88, third == 99 { return false }
            if first == 192, second == 168 { return false }
            if first == 198, second == 18 || second == 19 { return false }
            if first == 198, second == 51, third == 100 { return false }
            if first == 203, second == 0, third == 113 { return false }
            return true
        case let .ipv6(bytes):
            guard bytes.count == 16 else { return false }
            if bytes.prefix(10).allSatisfy({ $0 == 0 }),
               bytes[10] == 0xff, bytes[11] == 0xff {
                let mapped = UInt32(bytes[12]) << 24 | UInt32(bytes[13]) << 16
                    | UInt32(bytes[14]) << 8 | UInt32(bytes[15])
                return Self.ipv4(mapped).isPublicInternetAddress
            }
            guard bytes[0] & 0xe0 == 0x20 else { return false }
            // IANA IPv6 Special-Purpose Address Registry, last updated
            // 2025-10-09. Swan deliberately rejects the whole 2001::/23
            // protocol-assignment umbrella instead of maintaining exceptions
            // for protocol anycast/tunneling ranges as fetch destinations.
            let deniedSpecialPurposePrefixes: [(Data, Int)] = [
                (Data([0x20, 0x01, 0x00]), 23),       // IETF assignments
                (Data([0x20, 0x01, 0x0d, 0xb8]), 32), // documentation
                (Data([0x20, 0x02]), 16),             // 6to4
                (Data([0x3f, 0xff, 0x00]), 20),       // documentation
            ]
            return !deniedSpecialPurposePrefixes.contains {
                Self.ipv6(bytes, hasPrefix: $0.0, bitCount: $0.1)
            }
        }
    }

    private static func ipv6(
        _ address: Data,
        hasPrefix prefix: Data,
        bitCount: Int
    ) -> Bool {
        guard address.count == 16, bitCount >= 0,
              bitCount <= prefix.count * 8 else {
            return false
        }
        let wholeBytes = bitCount / 8
        guard address.prefix(wholeBytes) == prefix.prefix(wholeBytes) else {
            return false
        }
        let remainingBits = bitCount % 8
        guard remainingBits > 0 else { return true }
        let mask = UInt8.max << (8 - remainingBits)
        return address[wholeBytes] & mask == prefix[wholeBytes] & mask
    }
}

public struct ATHandleTXTRecord: Sendable, Equatable {
    public let bytes: Data

    public init(bytes: Data) throws {
        guard bytes.count <= 4_096 else {
            throw ATHandleVerificationError.verificationFailed
        }
        self.bytes = bytes
    }
}

public protocol ATHandleDNSResolving: Sendable {
    func txtRecords(name: String) async throws -> [ATHandleTXTRecord]
    func addresses(host: String) async throws -> [ATHandleIPAddress]
}

public struct SystemATHandleDNSResolver: ATHandleDNSResolving {
    private static let queue = DispatchQueue(
        label: "blue.catbird.swan.handle-dns",
        qos: .utility
    )

    public init() {}

    public func txtRecords(name: String) async throws -> [ATHandleTXTRecord] {
        try await withCheckedThrowingContinuation { continuation in
            Self.queue.async {
                var output = [UInt8](repeating: 0, count: 64 * 1_024)
                let count = swan_at_handle_query_txt(
                    name,
                    &output,
                    output.count
                )
                guard count >= 0 else {
                    continuation.resume(
                        throwing: ATHandleVerificationError.unavailable
                    )
                    return
                }
                var records: [ATHandleTXTRecord] = []
                var offset = 0
                do {
                    while offset < count {
                        guard offset + 2 <= count else {
                            throw ATHandleVerificationError.verificationFailed
                        }
                        let length = Int(output[offset]) << 8 | Int(output[offset + 1])
                        offset += 2
                        guard offset + length <= count else {
                            throw ATHandleVerificationError.verificationFailed
                        }
                        records.append(try ATHandleTXTRecord(
                            bytes: Data(output[offset ..< offset + length])
                        ))
                        offset += length
                    }
                    continuation.resume(returning: records)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    public func addresses(host: String) async throws -> [ATHandleIPAddress] {
        if let literal = ATHandleIPAddress(literal: host) { return [literal] }
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
                    continuation.resume(
                        throwing: ATHandleVerificationError.unavailable
                    )
                    return
                }
                defer { freeaddrinfo(result) }
                var values = Set<ATHandleIPAddress>()
                var cursor: UnsafeMutablePointer<addrinfo>? = result
                while let current = cursor {
                    defer { cursor = current.pointee.ai_next }
                    guard let socket = current.pointee.ai_addr else { continue }
                    switch Int32(current.pointee.ai_family) {
                    case AF_INET:
                        var address = socket.withMemoryRebound(
                            to: sockaddr_in.self,
                            capacity: 1
                        ) { $0.pointee.sin_addr }
                        let bytes = [UInt8](Data(
                            bytes: &address,
                            count: MemoryLayout<in_addr>.size
                        ))
                        if bytes.count == 4 {
                            values.insert(.ipv4(
                                UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16
                                    | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
                            ))
                        }
                    case AF_INET6:
                        var address = socket.withMemoryRebound(
                            to: sockaddr_in6.self,
                            capacity: 1
                        ) { $0.pointee.sin6_addr }
                        values.insert(.ipv6(Data(
                            bytes: &address,
                            count: MemoryLayout<in6_addr>.size
                        )))
                    default:
                        break
                    }
                }
                continuation.resume(
                    returning: values.sorted { $0.description < $1.description }
                )
            }
        }
    }
}

public struct ATHandleHTTPResponse: Sendable {
    public let status: Int
    public let headers: [String: [String]]
    public let body: Data
    public let responseURL: URL
    public let connectedPeer: ATHandleIPAddress?

    public init(
        status: Int,
        headers: [String: [String]] = [:],
        body: Data,
        responseURL: URL,
        connectedPeer: ATHandleIPAddress?
    ) {
        self.status = status
        self.headers = headers
        self.body = body
        self.responseURL = responseURL
        self.connectedPeer = connectedPeer
    }
}

public protocol ATHandleHTTPFetching: Sendable {
    /// Implementations must connect directly to a member of `approvedPeers`,
    /// preserve the URL hostname for TLS SNI/certificate validation and the
    /// Host header, never follow redirects, and report the actual socket peer.
    func get(
        url: URL,
        approvedPeers: Set<ATHandleIPAddress>,
        timeout: TimeInterval,
        maximumBodyBytes: Int
    ) async throws -> ATHandleHTTPResponse
}

public struct ATHandleResolutionPolicy: Sendable, Equatable {
    public let laboratoryOrigin: URL?
    public let timeout: TimeInterval
    public let maximumBodyBytes: Int
    public let maximumRedirects: Int

    public static func production(
        timeout: TimeInterval = 5,
        maximumBodyBytes: Int = 2_048,
        maximumRedirects: Int = 3
    ) throws -> Self {
        try .init(
            laboratoryOrigin: nil,
            timeout: timeout,
            maximumBodyBytes: maximumBodyBytes,
            maximumRedirects: maximumRedirects
        )
    }

    public static func laboratory(
        origin: URL,
        timeout: TimeInterval = 5,
        maximumBodyBytes: Int = 2_048,
        maximumRedirects: Int = 0
    ) throws -> Self {
        try .init(
            laboratoryOrigin: origin,
            timeout: timeout,
            maximumBodyBytes: maximumBodyBytes,
            maximumRedirects: maximumRedirects
        )
    }

    private init(
        laboratoryOrigin: URL?,
        timeout: TimeInterval,
        maximumBodyBytes: Int,
        maximumRedirects: Int
    ) throws {
        guard timeout > 0, timeout <= 30, timeout.isFinite,
              (64 ... 16_384).contains(maximumBodyBytes),
              (0 ... 5).contains(maximumRedirects) else {
            throw ATHandleVerificationError.verificationFailed
        }
        if let laboratoryOrigin {
            guard let parts = URLComponents(
                url: laboratoryOrigin,
                resolvingAgainstBaseURL: false
            ), parts.scheme?.lowercased() == "http",
            let host = parts.host,
            let literal = ATHandleIPAddress(literal: host),
            literal.isLoopback,
            let port = parts.port, (1 ... 65_535).contains(port),
            parts.user == nil, parts.password == nil,
            parts.query == nil, parts.fragment == nil,
            parts.path.isEmpty || parts.path == "/" else {
                throw ATHandleVerificationError.verificationFailed
            }
        }
        self.laboratoryOrigin = laboratoryOrigin
        self.timeout = timeout
        self.maximumBodyBytes = maximumBodyBytes
        self.maximumRedirects = maximumRedirects
    }
}

public struct VerifiedATHandleIdentity: Sendable, Equatable {
    public let did: String
    public let canonicalHandle: String
    public let pdsOrigin: String
}

public protocol PLCHandleVerifying: Sendable {
    func verify(
        plcState: PLCDocumentData,
        expectedDID: String,
        handle: String,
        pdsOrigin: String
    ) async throws -> VerifiedATHandleIdentity
}

/// A deliberately explicit laboratory-only handle verifier. It authenticates
/// the PLC document's DID, handle, and PDS service binding but does not make a
/// DNS or HTTP ownership request. The disposable Compose bootstrap uses this
/// only while the account is being created before a public Swan listener can
/// answer the handle proof. Production activation always uses
/// ``ATProtocolHandleVerifier``.
public struct StaticLaboratoryHandleVerifier: PLCHandleVerifying, Sendable {
    public init() {}

    public func verify(
        plcState: PLCDocumentData,
        expectedDID: String,
        handle rawHandle: String,
        pdsOrigin: String
    ) async throws -> VerifiedATHandleIdentity {
        do {
            let did = try AccountIdentifiers.validateDID(expectedDID)
            let handle = try AccountIdentifiers.canonicalHandle(rawHandle)
            guard plcState.did == did,
                  plcState.alsoKnownAs == ["at://\(handle)"],
                  plcState.services == [
                      "atproto_pds": PLCService(
                          type: "AtprotoPersonalDataServer",
                          endpoint: pdsOrigin
                      ),
                  ] else {
                throw ATHandleVerificationError.verificationFailed
            }
            return .init(did: did, canonicalHandle: handle, pdsOrigin: pdsOrigin)
        } catch let error as ATHandleVerificationError {
            throw error
        } catch {
            throw ATHandleVerificationError.verificationFailed
        }
    }
}

public struct ATProtocolHandleVerifier: PLCHandleVerifying, Sendable {
    private static let reservedTLDs = Set([
        "alt", "arpa", "example", "internal", "invalid", "local",
        "localhost", "onion", "test",
    ])
    private let policy: ATHandleResolutionPolicy
    private let dns: any ATHandleDNSResolving
    private let http: any ATHandleHTTPFetching

    public init(
        policy: ATHandleResolutionPolicy,
        dns: any ATHandleDNSResolving = SystemATHandleDNSResolver(),
        http: any ATHandleHTTPFetching
    ) {
        self.policy = policy
        self.dns = dns
        self.http = http
    }

    public func verify(
        plcState: PLCDocumentData,
        expectedDID: String,
        handle rawHandle: String,
        pdsOrigin: String
    ) async throws -> VerifiedATHandleIdentity {
        do {
            let did = try AccountIdentifiers.validateDID(expectedDID)
            let handle = try AccountIdentifiers.canonicalHandle(rawHandle)
            try validateHandlePolicy(handle)
            guard plcState.did == did,
                  plcState.alsoKnownAs == ["at://\(handle)"],
                  plcState.services == [
                      "atproto_pds": PLCService(
                          type: "AtprotoPersonalDataServer",
                          endpoint: pdsOrigin
                      ),
                  ] else {
                throw ATHandleVerificationError.verificationFailed
            }

            let dnsResult: String?
            do {
                dnsResult = try await resolveTXT(handle: handle)
            } catch let error as ATHandleVerificationError
                where error == .verificationFailed {
                throw error
            } catch {
                dnsResult = nil
            }
            if let dnsResult {
                guard dnsResult == did else {
                    throw ATHandleVerificationError.verificationFailed
                }
            } else {
                let httpsResult = try await resolveHTTP(handle: handle)
                guard httpsResult == did else {
                    throw ATHandleVerificationError.verificationFailed
                }
            }
            return .init(
                did: did,
                canonicalHandle: handle,
                pdsOrigin: pdsOrigin
            )
        } catch let error as ATHandleVerificationError {
            throw error
        } catch {
            throw ATHandleVerificationError.verificationFailed
        }
    }

    private func validateHandlePolicy(_ handle: String) throws {
        guard let tld = handle.split(separator: ".").last.map(String.init) else {
            throw ATHandleVerificationError.verificationFailed
        }
        if policy.laboratoryOrigin != nil {
            guard tld == "test" else {
                throw ATHandleVerificationError.verificationFailed
            }
        } else if Self.reservedTLDs.contains(tld) {
            throw ATHandleVerificationError.verificationFailed
        }
    }

    private func resolveTXT(handle: String) async throws -> String? {
        let records = try await withDeadline {
            try await dns.txtRecords(name: "_atproto.\(handle)")
        }
        guard records.count <= 128 else {
            throw ATHandleVerificationError.verificationFailed
        }
        var usable = Set<String>()
        for record in records {
            guard record.bytes.starts(with: Data("did=".utf8)) else {
                continue
            }
            guard let text = String(data: record.bytes, encoding: .utf8) else {
                throw ATHandleVerificationError.verificationFailed
            }
            let value = String(text.dropFirst(4))
            guard (try? AccountIdentifiers.validateDID(value)) == value else {
                throw ATHandleVerificationError.verificationFailed
            }
            usable.insert(value)
        }
        guard usable.count <= 1 else {
            throw ATHandleVerificationError.verificationFailed
        }
        return usable.first
    }

    private func resolveHTTP(handle: String) async throws -> String {
        var current = try initialHTTPURL(handle: handle)
        for redirectCount in 0 ... policy.maximumRedirects {
            let response = try await fetchOne(current)
            if (200 ... 299).contains(response.status) {
                return try decodedDID(response.body)
            }
            guard redirectCount < policy.maximumRedirects,
                  [301, 302, 303, 307, 308].contains(response.status),
                  let location = singleHeader("location", response.headers),
                  let redirected = URL(string: location, relativeTo: current)?.absoluteURL else {
                throw ATHandleVerificationError.verificationFailed
            }
            try validateRedirect(redirected)
            current = redirected
        }
        throw ATHandleVerificationError.verificationFailed
    }

    private func fetchOne(_ url: URL) async throws -> ATHandleHTTPResponse {
        let host = try validatedHTTPURL(url)
        let preflight = Set(try await withDeadline {
            try await dns.addresses(host: host)
        })
        try validateAddresses(preflight, host: host)
        let response = try await withDeadline {
            try await http.get(
                url: url,
                approvedPeers: preflight,
                timeout: policy.timeout,
                maximumBodyBytes: policy.maximumBodyBytes
            )
        }
        let postflight = Set(try await withDeadline {
            try await dns.addresses(host: host)
        })
        try validateAddresses(postflight, host: host)
        guard response.responseURL.absoluteString == url.absoluteString,
              response.body.count <= policy.maximumBodyBytes,
              let peer = response.connectedPeer,
              preflight.contains(peer), postflight.contains(peer),
              permits(peer, host: host) else {
            throw ATHandleVerificationError.verificationFailed
        }
        if let lengths = canonicalHeaders(response.headers)["content-length"] {
            guard lengths.count == 1,
                  let length = Int(lengths[0]),
                  String(length) == lengths[0],
                  length == response.body.count,
                  length <= policy.maximumBodyBytes else {
                throw ATHandleVerificationError.verificationFailed
            }
        }
        return response
    }

    private func initialHTTPURL(handle: String) throws -> URL {
        if let origin = policy.laboratoryOrigin {
            return origin.appending(path: ".well-known/atproto-did")
        }
        var parts = URLComponents()
        parts.scheme = "https"
        parts.host = handle
        parts.path = "/.well-known/atproto-did"
        guard let url = parts.url else {
            throw ATHandleVerificationError.verificationFailed
        }
        return url
    }

    private func validateRedirect(_ url: URL) throws {
        _ = try validatedHTTPURL(url)
        if let laboratoryOrigin = policy.laboratoryOrigin {
            guard url.scheme?.lowercased() == "http",
                  url.host == laboratoryOrigin.host,
                  url.port == laboratoryOrigin.port else {
                throw ATHandleVerificationError.verificationFailed
            }
        }
    }

    private func validatedHTTPURL(_ url: URL) throws -> String {
        guard let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = parts.scheme?.lowercased(),
              let host = parts.host, !host.isEmpty,
              parts.user == nil, parts.password == nil,
              parts.fragment == nil else {
            throw ATHandleVerificationError.verificationFailed
        }
        if let laboratoryOrigin = policy.laboratoryOrigin {
            guard scheme == "http", host == laboratoryOrigin.host,
                  parts.port == laboratoryOrigin.port,
                  ATHandleIPAddress(literal: host)?.isLoopback == true else {
                throw ATHandleVerificationError.verificationFailed
            }
        } else {
            guard scheme == "https", parts.port == nil || parts.port == 443 else {
                throw ATHandleVerificationError.verificationFailed
            }
        }
        return host
    }

    private func validateAddresses(
        _ addresses: Set<ATHandleIPAddress>,
        host: String
    ) throws {
        guard !addresses.isEmpty, addresses.count <= 32,
              addresses.allSatisfy({ permits($0, host: host) }) else {
            throw ATHandleVerificationError.verificationFailed
        }
    }

    private func permits(_ address: ATHandleIPAddress, host: String) -> Bool {
        if policy.laboratoryOrigin != nil {
            return ATHandleIPAddress(literal: host) == address && address.isLoopback
        }
        return address.isPublicInternetAddress
    }

    private func decodedDID(_ body: Data) throws -> String {
        guard !body.isEmpty, body.count <= policy.maximumBodyBytes else {
            throw ATHandleVerificationError.verificationFailed
        }
        let whitespace: Set<UInt8> = [0x09, 0x0a, 0x0d, 0x20]
        let prefix = body.prefix { whitespace.contains($0) }.count
        let suffix = body.reversed().prefix { whitespace.contains($0) }.count
        guard prefix + suffix <= 64, prefix + suffix < body.count else {
            throw ATHandleVerificationError.verificationFailed
        }
        let trimmed = body.dropFirst(prefix).dropLast(suffix)
        guard let value = String(data: trimmed, encoding: .utf8),
              (try? AccountIdentifiers.validateDID(value)) == value else {
            throw ATHandleVerificationError.verificationFailed
        }
        return value
    }

    private func singleHeader(
        _ name: String,
        _ headers: [String: [String]]
    ) -> String? {
        let values = canonicalHeaders(headers)[name]
        return values?.count == 1 ? values?.first : nil
    }

    private func canonicalHeaders(
        _ headers: [String: [String]]
    ) -> [String: [String]] {
        headers.reduce(into: [:]) { result, item in
            result[item.key.lowercased(), default: []].append(contentsOf: item.value)
        }
    }

    private func withDeadline<T: Sendable>(
        _ operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        let completion = ATHandleDeadline<T>()
        let operationTask = Task {
            do {
                completion.complete(.success(try await operation()))
            } catch {
                completion.complete(.failure(error))
            }
        }
        let nanoseconds = UInt64(
            (policy.timeout * 1_000_000_000).rounded(.up)
        )
        let timeoutTask = Task {
            do {
                try await Task.sleep(nanoseconds: nanoseconds)
            } catch {
                return
            }
            operationTask.cancel()
            completion.complete(.failure(ATHandleVerificationError.unavailable))
        }
        defer {
            operationTask.cancel()
            timeoutTask.cancel()
        }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                completion.install(continuation)
            }
        } onCancel: {
            operationTask.cancel()
            timeoutTask.cancel()
            completion.complete(.failure(CancellationError()))
        }
    }
}

private final class ATHandleDeadline<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Error>?
    private var result: Result<Value, Error>?

    func install(_ continuation: CheckedContinuation<Value, Error>) {
        lock.lock()
        if let result {
            lock.unlock()
            resume(continuation, with: result)
        } else {
            self.continuation = continuation
            lock.unlock()
        }
    }

    func complete(_ result: Result<Value, Error>) {
        lock.lock()
        guard self.result == nil else {
            lock.unlock()
            return
        }
        self.result = result
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        if let continuation { resume(continuation, with: result) }
    }

    private func resume(
        _ continuation: CheckedContinuation<Value, Error>,
        with result: Result<Value, Error>
    ) {
        switch result {
        case let .success(value):
            continuation.resume(returning: value)
        case let .failure(error):
            continuation.resume(throwing: error)
        }
    }
}
