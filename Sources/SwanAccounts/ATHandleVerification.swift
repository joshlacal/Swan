import CATHandleDNS
import Foundation
import PetrelPLC
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

public enum ATHandleDNSAdmissionError: Error, Sendable, Equatable {
    case saturated
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
            return SwanPublicAddressPolicy.isLoopback(ipv4: value)
        case let .ipv6(bytes):
            return SwanPublicAddressPolicy.isLoopback(ipv6: bytes)
        }
    }

    /// Delegates to ``SwanPublicAddressPolicy``, which is shared with the
    /// OAuth/DID/pipethrough classifier so a range denied here can never be
    /// reached through those paths instead.
    public var isPublicInternetAddress: Bool {
        switch self {
        case let .ipv4(value):
            return SwanPublicAddressPolicy.isPublicInternetAddress(ipv4: value)
        case let .ipv6(bytes):
            return SwanPublicAddressPolicy.isPublicInternetAddress(ipv6: bytes)
        }
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

public final class HandleDNSAdmissionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var active: Int = 0
    private var queued: [(id: UUID, continuation: CheckedContinuation<Void, Error>)] = []
    public let maxActive: Int
    public let maxQueued: Int

    public init(maxActive: Int = 8, maxQueued: Int = 128) {
        self.maxActive = maxActive
        self.maxQueued = maxQueued
    }

    public var activeCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return active
    }

    public var queuedCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return queued.count
    }
    public func acquire() async throws {
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                lock.lock()
                if active < maxActive {
                    active += 1
                    lock.unlock()
                    continuation.resume()
                } else if queued.count < maxQueued {
                    if Task.isCancelled {
                        lock.unlock()
                        continuation.resume(throwing: CancellationError())
                    } else {
                        queued.append((id: id, continuation: continuation))
                        lock.unlock()
                    }
                } else {
                    lock.unlock()
                    continuation.resume(throwing: ATHandleDNSAdmissionError.saturated)
                }
            }
        } onCancel: {
            self.cancel(id: id)
        }
    }

    private func cancel(id: UUID) {
        lock.lock()
        let waiter: (id: UUID, continuation: CheckedContinuation<Void, Error>)?
        if let index = queued.firstIndex(where: { $0.id == id }) {
            waiter = queued.remove(at: index)
        } else {
            waiter = nil
        }
        lock.unlock()
        waiter?.continuation.resume(throwing: CancellationError())
    }

    public func release() {
        lock.lock()
        precondition(active > 0, "HandleDNSAdmissionGate released with active count 0")
        let next: (id: UUID, continuation: CheckedContinuation<Void, Error>)?
        if !queued.isEmpty {
            next = queued.removeFirst()
        } else {
            active -= 1
            next = nil
        }
        lock.unlock()
        next?.continuation.resume()
    }
}

public struct SystemATHandleDNSResolver: ATHandleDNSResolving {
    public static let defaultGate = HandleDNSAdmissionGate(maxActive: 8, maxQueued: 128)
    public let gate: HandleDNSAdmissionGate

    public init() {
        self.gate = Self.defaultGate
    }

    public init(gate: HandleDNSAdmissionGate) {
        self.gate = gate
    }
    public func txtRecords(name: String) async throws -> [ATHandleTXTRecord] {
        try await gate.acquire()
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                defer { self.gate.release() }
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
        try await gate.acquire()
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                defer { self.gate.release() }
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

    /// Resolves a handle this host does not own to whatever DID it claims,
    /// TXT first and `/.well-known/atproto-did` second — the same order, the
    /// same bounds, and the same pinned transport `verify` uses.
    ///
    /// `verify` asks "does this handle point at the DID I already expect"; this
    /// asks "what does this handle point at", which is what a PDS answering
    /// `com.atproto.identity.resolveHandle` for a handle it does not host has
    /// to do. A reference PDS answers those from its identity resolver, and
    /// refusing them made every handle-to-DID lookup a client sent this host
    /// fail with `InvalidRequest`.
    ///
    /// `nil` means the handle resolved to nothing usable. Reserved TLDs,
    /// malformed handles, and non-public addresses are refused before any
    /// lookup, so an anonymous caller cannot steer this at an internal host.
    public func resolve(handle rawHandle: String) async throws -> String? {
        do {
            let handle = try AccountIdentifiers.canonicalHandle(rawHandle)
            try validateHandlePolicy(handle)
            do {
                if let viaDNS = try await resolveTXT(handle: handle) {
                    return viaDNS
                }
            } catch let error as ATHandleVerificationError
                where error == .verificationFailed {
                // A malformed or ambiguous TXT answer is a fault in the record,
                // not a reason to fall through to a second source that could
                // disagree with it.
                throw error
            } catch {
                // Anything else — timeout, SERVFAIL, no record — is the
                // ordinary "no TXT" case the HTTPS leg exists for.
            }
            return try await resolveHTTP(handle: handle)
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
        try await swanRaceWithDeadline(
            seconds: policy.timeout,
            onExpiry: ATHandleVerificationError.unavailable,
            operation: operation
        )
    }
}
