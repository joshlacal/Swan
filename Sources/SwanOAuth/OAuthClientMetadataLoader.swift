import Foundation
import SwanCore
import SwanStorage

public struct OAuthResolvedClientMetadata: Sendable, Equatable {
    public let metadata: OAuthClientMetadata
    /// Present only for confidential clients, after inline or remote JWKS
    /// material has been parsed and validated.
    public let keySet: OAuthJSONWebKeySet?

    public init(metadata: OAuthClientMetadata, keySet: OAuthJSONWebKeySet?) {
        self.metadata = metadata
        self.keySet = keySet
    }
}

private enum OAuthMetadataFlightWaitOutcome: Sendable {
    case completed(Result<OAuthResolvedClientMetadata, Error>)
    case waiterCancelled
}

/// Bridges one caller to an independent shared task. Cancellation settles only
/// this bridge; it never propagates to the task that other exact-URL callers
/// are awaiting.
private final class OAuthMetadataFlightWait: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation:
        CheckedContinuation<OAuthMetadataFlightWaitOutcome, Never>?
    private var outcome: OAuthMetadataFlightWaitOutcome?

    func install(
        _ continuation:
            CheckedContinuation<OAuthMetadataFlightWaitOutcome, Never>
    ) {
        lock.lock()
        if let outcome {
            lock.unlock()
            continuation.resume(returning: outcome)
            return
        }
        self.continuation = continuation
        lock.unlock()
    }

    func complete(_ outcome: OAuthMetadataFlightWaitOutcome) {
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

/// Loads client metadata and its optional JWKS with a small explicit cache.
/// Entries are retained only after the metadata identity, all profile fields,
/// and any referenced JWKS have validated. `revalidate(clientID:)` is an
/// intentional rotation hook for a later session manager; this task does not
/// claim to revalidate already-active sessions automatically.
public actor OAuthClientMetadataLoader {
    private struct CachedDocument: Codable, Sendable {
        let metadata: OAuthClientMetadata
        let keySet: OAuthJSONWebKeySet?
    }

    private enum LoadMode: Hashable, Sendable {
        case cached
        case revalidation
    }

    private struct FlightKey: Hashable, Sendable {
        let clientID: String
        let mode: LoadMode
    }

    private struct Flight: Sendable {
        let identity: UUID
        let task: Task<OAuthResolvedClientMetadata, Error>
        var waiterCount: Int
    }

    private static let maximumConcurrentFlights = 8
    private static let maximumWaitersPerFlight = 64
    private let fetcher: OAuthRemoteDocumentFetcher
    private let controlStore: any OAuthControlStore
    private let cacheLifetime: TimeInterval
    private var inFlight: [FlightKey: Flight] = [:]
    /// Immutable construction evidence for HTTP assembly. It is safe to read
    /// without entering the actor because the value-type policy never changes
    /// after initialization; the loader remains the fetch capability.
    public nonisolated let fetchPolicy: OAuthRemoteFetchPolicy

    public init(
        fetcher: OAuthRemoteDocumentFetcher,
        controlStore: any OAuthControlStore,
        cacheLifetime: TimeInterval = 300
    ) throws {
        guard cacheLifetime >= 5, cacheLifetime <= 900, cacheLifetime.isFinite else {
            throw SwanError.malformed("OAuth metadata cache lifetime is out of bounds")
        }
        self.fetcher = fetcher
        self.controlStore = controlStore
        self.cacheLifetime = cacheLifetime
        fetchPolicy = fetcher.policy
    }

    public func load(clientID: URL, now: Date = Date()) async throws -> OAuthResolvedClientMetadata {
        try await load(clientID: clientID, now: now, bypassCache: false)
    }

    private func load(clientID: URL, now: Date, bypassCache: Bool) async throws -> OAuthResolvedClientMetadata {
        try Task.checkCancellation()
        let key = clientID.absoluteString
        if OAuthClientMetadata.isExactLocalhostDevelopmentClientID(clientID) {
            guard fetcher.policy.allowLocalhostDevelopment else {
                throw SwanError.unauthorized("localhost OAuth development client is disabled")
            }
            // The profile defines a virtual document; do not make an SSRF-prone
            // loopback fetch for it and do not treat it as a cached response.
            return OAuthResolvedClientMetadata(
                metadata: try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: clientID),
                keySet: nil
            )
        }
        try OAuthClientMetadata.validateStandardClientID(clientID)
        let flightKey = FlightKey(
            clientID: key,
            mode: bypassCache ? .revalidation : .cached
        )
        if let flight = inFlight[flightKey] {
            return try await finish(flight, for: flightKey)
        }
        guard inFlight.count < Self.maximumConcurrentFlights else {
            throw SwanError.unavailable(
                "OAuth metadata flight capacity is exhausted"
            )
        }

        let fetcher = self.fetcher
        let controlStore = self.controlStore
        let cacheLifetime = self.cacheLifetime
        let priority = Task.currentPriority
        // This is intentionally independent of the initiating waiter. Exact
        // URL peers share its result, and cancelling any one waiter must not
        // cancel DNS resolution or the peer-pinned transport underneath it.
        let task: Task<OAuthResolvedClientMetadata, Error> = Task.detached(
            priority: priority
        ) {
            try await Self.loadAndCache(
                clientID: clientID,
                key: key,
                now: now,
                bypassCache: bypassCache,
                fetcher: fetcher,
                controlStore: controlStore,
                cacheLifetime: cacheLifetime
            )
        }
        let flight = Flight(identity: UUID(), task: task, waiterCount: 0)
        inFlight[flightKey] = flight
        // A caller may cancel without cancelling `task`. This observer removes
        // a completed flight even when no waiter remains to re-enter the actor.
        _ = Task.detached { [weak self] in
            _ = await task.result
            await self?.removeFlight(
                identity: flight.identity,
                for: flightKey
            )
        }
        return try await finish(flight, for: flightKey)
    }

    private func finish(
        _ flight: Flight,
        for key: FlightKey
    ) async throws -> OAuthResolvedClientMetadata {
        guard var admittedFlight = inFlight[key],
              admittedFlight.identity == flight.identity,
              admittedFlight.waiterCount < Self.maximumWaitersPerFlight else {
            throw SwanError.unavailable(
                "OAuth metadata waiter capacity is exhausted"
            )
        }
        admittedFlight.waiterCount += 1
        inFlight[key] = admittedFlight
        defer {
            releaseWaiter(identity: flight.identity, for: key)
        }
        let wait = OAuthMetadataFlightWait()
        _ = Task.detached {
            wait.complete(.completed(await flight.task.result))
        }
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
            removeFlight(identity: flight.identity, for: key)
            return try result.get()
        case .waiterCancelled:
            throw CancellationError()
        }
    }

    private func removeFlight(identity: UUID, for key: FlightKey) {
        if inFlight[key]?.identity == identity {
            inFlight.removeValue(forKey: key)
        }
    }

    private func releaseWaiter(identity: UUID, for key: FlightKey) {
        guard var flight = inFlight[key],
              flight.identity == identity,
              flight.waiterCount > 0 else {
            return
        }
        flight.waiterCount -= 1
        inFlight[key] = flight
    }

    private static func loadAndCache(
        clientID: URL,
        key: String,
        now: Date,
        bypassCache: Bool,
        fetcher: OAuthRemoteDocumentFetcher,
        controlStore: any OAuthControlStore,
        cacheLifetime: TimeInterval
    ) async throws -> OAuthResolvedClientMetadata {
        if !bypassCache {
            do {
                if let cached = try await controlStore.cachedClientMetadata(
                    clientID: key,
                    now: now
                ) {
                    guard cached.expiresAt <=
                        now.addingTimeInterval(cacheLifetime),
                        cached.clientID == key else {
                        throw SwanError.unavailable(
                            "OAuth metadata cache record exceeded policy"
                        )
                    }
                    let cachedDocument = try StrictJSON.decode(
                        CachedDocument.self,
                        from: cached.document
                    )
                    guard cachedDocument.metadata.clientID.absoluteString ==
                        key,
                        !cachedDocument.metadata
                            .isLocalhostDevelopmentClient else {
                        throw SwanError.unavailable(
                            "OAuth metadata cache record is malformed"
                        )
                    }
                    return OAuthResolvedClientMetadata(
                        metadata: cachedDocument.metadata,
                        keySet: cachedDocument.keySet
                    )
                }
            } catch let error as SwanError {
                throw error
            } catch {
                throw SwanError.unavailable(
                    "OAuth metadata cache unavailable"
                )
            }
        }

        return try await fetcher.withAdmission { admittedFetcher in
            let ticket: OAuthClientMetadataFetchTicket
            do {
                ticket = try await controlStore.beginClientMetadataFetch(
                    clientID: key,
                    now: now
                )
            } catch {
                throw SwanError.unavailable(
                    "OAuth metadata cache unavailable"
                )
            }

            let metadataData = try await admittedFetcher.fetchJSON(
                from: clientID
            )
            let metadata = try OAuthClientMetadata.decodeValidated(
                metadataData,
                responseURL: clientID
            )
            let keySet: OAuthJSONWebKeySet?
            if let inline = metadata.jwks {
                keySet = inline
            } else if let jwksURI = metadata.jwksURI {
                keySet = try OAuthJSONWebKeySet.decodeValidated(
                    try await admittedFetcher.fetchJSON(from: jwksURI)
                )
            } else {
                keySet = nil
            }
            let resolved = OAuthResolvedClientMetadata(
                metadata: metadata,
                keySet: keySet
            )
            do {
                let document = try JSONEncoder().encode(
                    CachedDocument(metadata: metadata, keySet: keySet)
                )
                let published = try await controlStore.publishClientMetadata(
                    OAuthCachedClientMetadata(
                        clientID: key,
                        document: document,
                        expiresAt: now.addingTimeInterval(cacheLifetime)
                    ),
                    using: ticket,
                    now: now
                )
                guard published else {
                    throw SwanError.unavailable(
                        "OAuth metadata was superseded during validation"
                    )
                }
            } catch {
                if let error = error as? SwanError {
                    throw error
                }
                throw SwanError.unavailable(
                    "OAuth metadata cache unavailable"
                )
            }
            return resolved
        }
    }

    /// Forces a fresh validation pass for confidential-key rotation callers.
    /// Callers decide how a missing previously-bound key affects their session.
    public func revalidate(clientID: URL, now: Date = Date()) async throws -> OAuthResolvedClientMetadata {
        return try await load(clientID: clientID, now: now, bypassCache: true)
    }
}
