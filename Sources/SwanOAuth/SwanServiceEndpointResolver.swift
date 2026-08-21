import Foundation
import SwanCore

/// Supplies a DID document as raw JSON. Implementations must fetch through
/// Swan's peer-pinned path; this protocol exists so resolution logic is
/// testable without a network.
public protocol SwanDIDDocumentFetching: Sendable {
    func documentJSON(forDID did: String) async throws -> Data
}

public enum SwanServiceResolutionFailure: Error, Sendable, Equatable {
    case unresolvableService
}

private enum DIDDocumentFlightWaitOutcome: Sendable {
    case completed(Result<SwanServiceEndpointResolver.Document, Error>)
    case waiterCancelled
}

/// Bridges one caller to an independent shared task. Cancellation settles only
/// this bridge; it never propagates to the task that other exact-DID callers
/// are awaiting.
private final class DIDDocumentFlightWait: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<DIDDocumentFlightWaitOutcome, Never>?
    private var outcome: DIDDocumentFlightWaitOutcome?

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        if case .waiterCancelled? = outcome {
            return true
        }
        return false
    }

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

/// Resolves a `did#fragment` service reference to its https endpoint with
/// single-flight coalescing for concurrent lookups of the same DID.
///
/// Every failure collapses to `.unresolvableService`: the caller turns that
/// into a 400, and distinguishing "no such DID" from "no such fragment" would
/// leak remote lookup detail without helping a legitimate client.
public struct SwanServiceEndpointResolver: Sendable {
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

    private actor ResolverActor {
        private struct Flight: Sendable {
            let identity: UUID
            let task: Task<Document, Error>
            var waiters: [DIDDocumentFlightWait]
            var waiterCount: Int { waiters.count }
        }

        private let documents: any SwanDIDDocumentFetching
        private var inFlight: [String: Flight] = [:]

        init(documents: any SwanDIDDocumentFetching) {
            self.documents = documents
        }

        func inFlightWaiterCount(for did: String) -> Int {
            inFlight[did]?.waiterCount ?? 0
        }

        func document(forDID did: String) async throws -> Document {
            try Task.checkCancellation()

            let wait = DIDDocumentFlightWait()

            if var flight = inFlight[did] {
                flight.waiters.append(wait)
                inFlight[did] = flight
            } else {
                let identity = UUID()
                let documents = self.documents
                let priority = Task.currentPriority
                let task: Task<Document, Error> = Task.detached(priority: priority) {
                    let data = try await documents.documentJSON(forDID: did)
                    guard let document = try? JSONDecoder().decode(Document.self, from: data),
                          document.service != nil,
                          document.id == did
                    else {
                        throw SwanServiceResolutionFailure.unresolvableService
                    }
                    return document
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
            }

            let document = try await awaitFlight(wait)
            return document
        }

        func endpoint(did: String, fragment: String) async throws -> URL {
            let document = try await self.document(forDID: did)
            guard let url = SwanServiceEndpointResolver.resolveEndpoint(
                document: document,
                did: did,
                fragment: fragment
            ) else {
                throw SwanServiceResolutionFailure.unresolvableService
            }
            return url
        }

        func endpoint(serviceIdentifier: String) async throws -> URL {
            guard !serviceIdentifier.isEmpty, serviceIdentifier.utf8.count <= 1_024 else {
                throw SwanServiceResolutionFailure.unresolvableService
            }
            if let separator = serviceIdentifier.firstIndex(of: "#") {
                let did = String(serviceIdentifier[..<separator])
                let fragment = String(serviceIdentifier[serviceIdentifier.index(after: separator)...])
                guard !did.isEmpty, !fragment.isEmpty, !fragment.contains("#") else {
                    throw SwanServiceResolutionFailure.unresolvableService
                }
                return try await endpoint(did: did, fragment: fragment)
            }
            let did = serviceIdentifier
            let document = try await self.document(forDID: did)
            guard let services = document.service,
                  services.count == 1,
                  let only = services.first,
                  let url = URL(string: only.serviceEndpoint),
                  url.scheme?.lowercased() == "https",
                  let host = url.host, !host.isEmpty,
                  url.user == nil, url.password == nil
            else { throw SwanServiceResolutionFailure.unresolvableService }
            return url
        }

        private func awaitFlight(_ wait: DIDDocumentFlightWait) async throws -> Document {
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
            result: Result<Document, Error>
        ) {
            guard let flight = inFlight[did], flight.identity == identity else {
                return
            }
            inFlight.removeValue(forKey: did)
            for waiter in flight.waiters {
                waiter.complete(.completed(result))
            }
        }
    }

    private let resolverActor: ResolverActor

    public init(documents: any SwanDIDDocumentFetching) {
        self.resolverActor = ResolverActor(documents: documents)
    }

    internal func inFlightWaiterCount(for did: String) async -> Int {
        await resolverActor.inFlightWaiterCount(for: did)
    }

    public func endpoint(did: String, fragment: String) async throws -> URL {
        do {
            return try await resolverActor.endpoint(did: did, fragment: fragment)
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

    /// Resolves a whole service identifier — `did` or `did#fragment` — as the
    /// spaces `registerNotify` contract names its subscriber (the reference
    /// implementation's `resolve_service_endpoint`).
    ///
    /// With a fragment this is exactly ``endpoint(did:fragment:)``. Without
    /// one, the reference selects the document's FIRST service entry; Swan
    /// keeps its refuse-ambiguity posture instead: a fragment-less identifier
    /// resolves only when the document declares exactly one service entry, so
    /// the answer can never depend on entry ordering. A subscriber whose
    /// document has several services must name one with a fragment.
    ///
    /// The endpoint checks (https, host, no credentials) are identical to the
    /// fragment form — a DID document is not this server's to trust either.
    public func endpoint(serviceIdentifier: String) async throws -> URL {
        do {
            return try await resolverActor.endpoint(serviceIdentifier: serviceIdentifier)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw SwanServiceResolutionFailure.unresolvableService
        }
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
