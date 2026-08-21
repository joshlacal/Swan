import Foundation
import SwanCore

public struct SwanDIDDocumentFetchResult: Sendable {
    public let data: Data
    public let maxAge: TimeInterval?
    public let noStore: Bool

    public init(data: Data, maxAge: TimeInterval? = nil, noStore: Bool = false) {
        self.data = data
        self.maxAge = maxAge
        self.noStore = noStore
    }
}

/// Supplies a DID document as raw JSON. Implementations must fetch through
/// Swan's peer-pinned path; this protocol exists so resolution logic is
/// testable without a network.
public protocol SwanDIDDocumentFetching: Sendable {
    func documentJSON(forDID did: String) async throws -> Data
    func fetchDocument(forDID did: String) async throws -> SwanDIDDocumentFetchResult
}

extension SwanDIDDocumentFetching {
    public func fetchDocument(forDID did: String) async throws -> SwanDIDDocumentFetchResult {
        let data = try await documentJSON(forDID: did)
        return SwanDIDDocumentFetchResult(data: data)
    }
}

public enum SwanServiceResolutionFailure: Error, Sendable, Equatable {
    case unresolvableService
}

private enum DIDDocumentFlightWaitOutcome: Sendable {
    case completed(Result<SwanDIDDocumentResolutionPayload, Error>)
    case waiterCancelled
}

private struct SwanDIDDocumentResolutionPayload: Sendable {
    let document: SwanServiceEndpointResolver.Document
    let fetchResult: SwanDIDDocumentFetchResult
}

/// Bridges one caller to an independent shared task. Cancellation settles only
/// this bridge; it never propagates to the task that other exact-DID callers
/// are awaiting.
private final class DIDDocumentFlightWait: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<DIDDocumentFlightWaitOutcome, Never>?
    private var outcome: DIDDocumentFlightWaitOutcome?

    func install(_ continuation: CheckedContinuation<DIDDocumentFlightWaitOutcome, Never>) {
        lock.lock()
        if let outcome {
            lock.unlock()
            continuation.resume(returning: outcome)
            return
        }
        self.continuation = continuation
        lock.unlock()
    }

    func complete(_ outcome: DIDDocumentFlightWaitOutcome) {
        lock.lock()
        guard self.outcome == nil else {
            lock.unlock()
            return
        }
        self.outcome = outcome
        let continuation = continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(returning: outcome)
    }
}

/// Resolves a `did#fragment` service reference to its https endpoint.
///
/// Every failure collapses to `.unresolvableService`: the caller turns that
/// into a 400, and distinguishing "no such DID" from "no such fragment" would
/// leak remote lookup detail without helping a legitimate client.
public struct SwanServiceEndpointResolver: Sendable {
    public struct CacheConfiguration: Sendable, Equatable {
        public static let standard = CacheConfiguration(
            lifetime: 60,
            maximumEntries: 256
        )

        public let lifetime: TimeInterval
        public let maximumEntries: Int

        public init(
            lifetime: TimeInterval = 60,
            maximumEntries: Int = 256
        ) {
            self.lifetime = lifetime
            self.maximumEntries = maximumEntries
        }

        fileprivate func validate() throws {
            guard lifetime >= 5, lifetime <= 300, lifetime.isFinite,
                  (1 ... 1_024).contains(maximumEntries) else {
                throw SwanError.malformed("DID document resolver cache bounds are invalid")
            }
        }
    }

    /// Continuous monotonic time source for cache TTL.
    public struct MonotonicClock: Sendable {
        private let readInstant: @Sendable () -> ContinuousClock.Instant

        public init(
            nowInstant: @escaping @Sendable () -> ContinuousClock.Instant
        ) {
            readInstant = nowInstant
        }

        fileprivate static let continuous = MonotonicClock(
            nowInstant: {
                ContinuousClock.now
            }
        )

        fileprivate func now() -> ContinuousClock.Instant {
            readInstant()
        }
    }

    fileprivate struct Document: Decodable, Sendable {
        struct Service: Decodable, Sendable {
            let id: String
            let serviceEndpoint: String
        }

        /// The document's own subject. Optional only so a document that omits
        /// it decodes and is then *rejected* below with the same
        /// `.unresolvableService` as everything else, rather than failing
        /// decode and taking a different path to the same answer.
        let id: String?
        let service: [Service]?
    }

    private actor CacheActor {
        private struct CacheEntry: Sendable {
            let document: Document
            let expiresAt: ContinuousClock.Instant
        }

        private struct Flight: Sendable {
            let identity: UUID
            let task: Task<SwanDIDDocumentResolutionPayload, Error>
            var waiters: [DIDDocumentFlightWait]
            var waiterCount: Int { waiters.count }
        }

        private let documents: any SwanDIDDocumentFetching
        private let configuration: CacheConfiguration
        private let clock: MonotonicClock
        private var cache: [String: CacheEntry] = [:]
        private var inFlight: [String: Flight] = [:]

        init(
            documents: any SwanDIDDocumentFetching,
            configuration: CacheConfiguration,
            clock: MonotonicClock
        ) {
            self.documents = documents
            self.configuration = configuration
            self.clock = clock
        }

        func inFlightWaiterCount(for did: String) -> Int {
            inFlight[did]?.waiterCount ?? 0
        }

        func endpoint(did: String, fragment: String) async throws -> URL {
            try Task.checkCancellation()
            let now = clock.now()
            if let entry = cache[did] {
                if entry.expiresAt > now {
                    if let url = SwanServiceEndpointResolver.resolveEndpoint(
                        document: entry.document,
                        did: did,
                        fragment: fragment
                    ) {
                        return url
                    }
                    // The cached document does not resolve this fragment.
                    // Evict so semantic failures are not locked into the cache.
                    cache.removeValue(forKey: did)
                } else {
                    cache.removeValue(forKey: did)
                }
            }

            if var flight = inFlight[did] {
                let wait = DIDDocumentFlightWait()
                flight.waiters.append(wait)
                inFlight[did] = flight
                let payload = try await awaitFlight(wait)
                return try evaluateEndpoint(payload: payload, did: did, fragment: fragment, shouldCache: false)
            }

            let wait = DIDDocumentFlightWait()
            let identity = UUID()
            let documents = self.documents
            let priority = Task.currentPriority
            let task: Task<SwanDIDDocumentResolutionPayload, Error> = Task.detached(priority: priority) {
                let fetchResult = try await documents.fetchDocument(forDID: did)
                guard let document = try? JSONDecoder().decode(Document.self, from: fetchResult.data),
                      document.service != nil,
                      document.id == did
                else {
                    throw SwanServiceResolutionFailure.unresolvableService
                }
                return SwanDIDDocumentResolutionPayload(document: document, fetchResult: fetchResult)
            }

            let flight = Flight(
                identity: identity,
                task: task,
                waiters: [wait]
            )
            inFlight[did] = flight

            Task.detached { [weak self] in
                let result = await task.result
                await self?.finishFlight(identity: identity, for: did, result: result)
            }

            let payload = try await awaitFlight(wait)
            return try evaluateEndpoint(payload: payload, did: did, fragment: fragment, shouldCache: true)
        }

        private func evaluateEndpoint(
            payload: SwanDIDDocumentResolutionPayload,
            did: String,
            fragment: String,
            shouldCache: Bool
        ) throws -> URL {
            guard let url = SwanServiceEndpointResolver.resolveEndpoint(
                document: payload.document,
                did: did,
                fragment: fragment
            ) else {
                throw SwanServiceResolutionFailure.unresolvableService
            }
            if shouldCache && !payload.fetchResult.noStore {
                storeInCache(payload.document, fetchResult: payload.fetchResult, for: did)
            }
            return url
        }

        private func awaitFlight(_ wait: DIDDocumentFlightWait) async throws -> SwanDIDDocumentResolutionPayload {
            let outcome = await withTaskCancellationHandler(
                operation: {
                    await withCheckedContinuation { continuation in
                        wait.install(continuation)
                        if Task.isCancelled {
                            wait.complete(.waiterCancelled)
                        }
                    }
                },
                onCancel: {
                    wait.complete(.waiterCancelled)
                }
            )
            switch outcome {
            case let .completed(result):
                return try result.get()
            case .waiterCancelled:
                throw CancellationError()
            }
        }

        private func finishFlight(
            identity: UUID,
            for did: String,
            result: Result<SwanDIDDocumentResolutionPayload, Error>
        ) {
            guard let flight = inFlight[did], flight.identity == identity else {
                return
            }
            inFlight.removeValue(forKey: did)
            for waiter in flight.waiters {
                waiter.complete(.completed(result))
            }
        }

        private func storeInCache(
            _ document: Document,
            fetchResult: SwanDIDDocumentFetchResult,
            for did: String
        ) {
            let now = clock.now()
            let effectiveLifetime: TimeInterval
            if let maxAge = fetchResult.maxAge {
                effectiveLifetime = min(maxAge, configuration.lifetime)
            } else {
                effectiveLifetime = configuration.lifetime
            }
            guard effectiveLifetime > 0 else { return }
            let expiresAt = now.advanced(by: .seconds(effectiveLifetime))

            if cache.count >= configuration.maximumEntries {
                cache = cache.filter { $0.value.expiresAt > now }
                if cache.count >= configuration.maximumEntries {
                    if let oldest = cache.min(by: { $0.value.expiresAt < $1.value.expiresAt })?.key {
                        cache.removeValue(forKey: oldest)
                    }
                }
            }

            cache[did] = CacheEntry(
                document: document,
                expiresAt: expiresAt
            )
        }
    }

    private let cacheActor: CacheActor

    public init(
        documents: any SwanDIDDocumentFetching,
        cacheConfiguration: CacheConfiguration = .standard
    ) throws {
        try self.init(
            documents: documents,
            cacheConfiguration: cacheConfiguration,
            monotonicClock: .continuous
        )
    }

    public init(
        documents: any SwanDIDDocumentFetching,
        cacheConfiguration: CacheConfiguration = .standard,
        monotonicClock: MonotonicClock
    ) throws {
        try cacheConfiguration.validate()
        self.cacheActor = CacheActor(
            documents: documents,
            configuration: cacheConfiguration,
            clock: monotonicClock
        )
    }

    internal func inFlightWaiterCount(for did: String) async -> Int {
        await cacheActor.inFlightWaiterCount(for: did)
    }

    public func endpoint(did: String, fragment: String) async throws -> URL {
        do {
            return try await cacheActor.endpoint(did: did, fragment: fragment)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw SwanServiceResolutionFailure.unresolvableService
        }
    }

    fileprivate static func resolveEndpoint(
        document: Document,
        did: String,
        fragment: String
    ) -> URL? {
        guard document.id == did, let services = document.service else {
            return nil
        }
        let matches = services.filter {
            $0.id == "#\(fragment)" || $0.id == "\(did)#\(fragment)"
        }
        guard
            matches.count == 1,
            let match = matches.first,
            let url = URL(string: match.serviceEndpoint),
            url.scheme?.lowercased() == "https",
            let host = url.host, !host.isEmpty,
            url.user == nil, url.password == nil
        else { return nil }
        return url
    }
}

/// The production ``SwanDIDDocumentFetching`` conformer.
///
/// It deliberately owns no HTTP client of its own: every fetch goes through
/// ``OAuthRemoteDocumentFetcher``, which is the peer-pinned resolve →
/// policy-check → pin path already used for OAuth client metadata. A hostile
/// `did:web` host therefore cannot reach a private or loopback address, and a
/// DNS rebind between resolution and connection is rejected.
///
/// Only two DID methods are supported, and both are resolved from an operator
/// configured origin or from the DID itself — never from a redirect, and never
/// from a `Location` header (the fetcher requires `redirectCount == 0`).
public struct SwanPeerPinnedDIDDocumentFetcher: SwanDIDDocumentFetching {
    private let documents: OAuthRemoteDocumentFetcher
    private let plcOrigin: URL

    /// - Parameter plcOrigin: the PLC directory origin. Callers pass the
    ///   already-configured `PLCClientConfiguration.origin` so this type never
    ///   becomes a second, independently drifting copy of that setting.
    public init(documents: OAuthRemoteDocumentFetcher, plcOrigin: URL) throws {
        guard let components = URLComponents(url: plcOrigin, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              components.percentEncodedPath.isEmpty || components.percentEncodedPath == "/",
              scheme == "https" || (scheme == "http" && host == "localhost") else {
            throw SwanError.malformed("PLC directory origin for DID resolution is invalid")
        }
        self.documents = documents
        self.plcOrigin = plcOrigin
    }

    public func documentJSON(forDID did: String) async throws -> Data {
        let url = try Self.documentURL(forDID: did, plcOrigin: plcOrigin)
        return try await documents.fetchJSON(from: url)
    }

    public func fetchDocument(forDID did: String) async throws -> SwanDIDDocumentFetchResult {
        let url = try Self.documentURL(forDID: did, plcOrigin: plcOrigin)
        let (data, headers) = try await documents.fetchJSONWithHeaders(from: url)
        let (maxAge, noStore) = Self.parseCacheControl(headers: headers)
        return SwanDIDDocumentFetchResult(data: data, maxAge: maxAge, noStore: noStore)
    }

    private static func parseCacheControl(headers: [String: [String]]) -> (maxAge: TimeInterval?, noStore: Bool) {
        guard let values = headers["cache-control"] else { return (nil, false) }
        var noStore = false
        var maxAge: TimeInterval?
        for value in values {
            let directives = value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            for directive in directives {
                if directive == "no-store" || directive == "no-cache" {
                    noStore = true
                } else if directive.hasPrefix("max-age=") {
                    let numberPart = directive.dropFirst("max-age=".count).trimmingCharacters(in: .whitespacesAndNewlines)
                    if let seconds = Double(numberPart), seconds >= 0, seconds.isFinite {
                        maxAge = seconds
                    }
                }
            }
        }
        return (maxAge, noStore)
    }
    /// Pure, synchronous DID → document URL derivation, so the whole grammar is
    /// testable without a network.
    static func documentURL(forDID did: String, plcOrigin: URL) throws -> URL {
        guard did.utf8.count <= 512,
              did.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }) else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        if let identifier = did.dropPrefixIfPresent("did:plc:") {
            // PLC identifiers are lowercase base32-sortable. Anything else is
            // refused rather than concatenated into the directory's path.
            guard !identifier.isEmpty, identifier.utf8.count <= 64,
                  identifier.utf8.allSatisfy({
                      ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z"))
                          || ($0 >= UInt8(ascii: "2") && $0 <= UInt8(ascii: "7"))
                  }) else {
                throw SwanServiceResolutionFailure.unresolvableService
            }
            return try url(origin: plcOrigin, percentEncodedPath: "/\(did)")
        }
        if let methodSpecific = did.dropPrefixIfPresent("did:web:") {
            return try webDocumentURL(methodSpecificID: methodSpecific)
        }
        throw SwanServiceResolutionFailure.unresolvableService
    }

    /// `did:web:host` → `https://host/.well-known/did.json`;
    /// `did:web:host:a:b` → `https://host/a/b/did.json`.
    private static func webDocumentURL(methodSpecificID: String) throws -> URL {
        let segments = methodSpecificID.split(separator: ":", omittingEmptySubsequences: false)
        guard let rawHost = segments.first, !rawHost.isEmpty else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        // A port is the one place the method-specific id may carry a percent
        // escape (`%3A`). Nothing else is decoded: leaving other escapes
        // intact is what stops `..%2F` from climbing out of the path.
        let host = rawHost
            .replacingOccurrences(of: "%3A", with: ":")
            .replacingOccurrences(of: "%3a", with: ":")
        guard isValidWebAuthority(host) else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        let pathSegments = segments.dropFirst().map(String.init)
        guard pathSegments.allSatisfy(isValidWebPathSegment) else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        let path = pathSegments.isEmpty
            ? "/.well-known/did.json"
            : "/\(pathSegments.joined(separator: "/"))/did.json"
        guard let origin = URL(string: "https://\(host)") else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        return try url(origin: origin, percentEncodedPath: path)
    }

    private static func isValidWebAuthority(_ value: String) -> Bool {
        let parts = value.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2 else { return false }
        let host = parts[0]
        guard !host.isEmpty, host.utf8.count <= 253, !host.hasPrefix("."), !host.hasSuffix("."),
              !host.contains(".."),
              host.utf8.allSatisfy({
                  ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z"))
                      || ($0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z"))
                      || ($0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9"))
                      || $0 == UInt8(ascii: "-") || $0 == UInt8(ascii: ".")
              }) else {
            return false
        }
        guard parts.count == 2 else { return true }
        let port = parts[1]
        guard (1 ... 5).contains(port.utf8.count),
              port.utf8.allSatisfy({ $0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9") }),
              let value = Int(port), (1 ... 65_535).contains(value) else {
            return false
        }
        return true
    }

    /// Unreserved characters only. `%`, `/`, and `.`-only segments are refused,
    /// so no encoded traversal or empty segment can enter the path.
    private static func isValidWebPathSegment(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 128, value != ".", value != ".." else {
            return false
        }
        return value.utf8.allSatisfy {
            ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z"))
                || ($0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z"))
                || ($0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9"))
                || $0 == UInt8(ascii: "-") || $0 == UInt8(ascii: ".")
                || $0 == UInt8(ascii: "_") || $0 == UInt8(ascii: "~")
        }
    }

    private static func url(origin: URL, percentEncodedPath: String) throws -> URL {
        guard var components = URLComponents(url: origin, resolvingAgainstBaseURL: false) else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        components.percentEncodedPath = percentEncodedPath
        components.percentEncodedQuery = nil
        components.fragment = nil
        guard let url = components.url else {
            throw SwanServiceResolutionFailure.unresolvableService
        }
        return url
    }
}

private extension String {
    func dropPrefixIfPresent(_ prefix: String) -> String? {
        hasPrefix(prefix) ? String(dropFirst(prefix.count)) : nil
    }
}
