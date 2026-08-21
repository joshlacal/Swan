import Foundation
@testable import SwanOAuth
import XCTest

private struct StubDocuments: SwanDIDDocumentFetching {
    let json: String
    func documentJSON(forDID _: String) async throws -> Data {
        Data(json.utf8)
    }
}

private struct FailingDocuments: SwanDIDDocumentFetching {
    struct Boom: Error {}
    func documentJSON(forDID _: String) async throws -> Data {
        throw Boom()
    }
}
private actor ControllableDocuments: SwanDIDDocumentFetching {
    private var json: String
    private var maxAge: TimeInterval?
    private var noStore: Bool
    private var count = 0
    private var releaseContinuations: [CheckedContinuation<Void, Never>] = []
    private var gated = false

    init(json: String, maxAge: TimeInterval? = nil, noStore: Bool = false, gated: Bool = false) {
        self.json = json
        self.maxAge = maxAge
        self.noStore = noStore
        self.gated = gated
    }

    func setJSON(_ json: String, maxAge: TimeInterval? = nil, noStore: Bool = false) {
        self.json = json
        self.maxAge = maxAge
        self.noStore = noStore
    }
    var fetchCount: Int {
        count
    }


    func releaseAll() {
        gated = false
        let conts = releaseContinuations
        releaseContinuations.removeAll()
        for cont in conts {
            cont.resume()
        }
    }

    func documentJSON(forDID did: String) async throws -> Data {
        let res = try await fetchDocument(forDID: did)
        return res.data
    }

    func fetchDocument(forDID _: String) async throws -> SwanDIDDocumentFetchResult {
        count += 1
        if gated {
            await withCheckedContinuation { continuation in
                if !gated {
                    continuation.resume()
                } else {
                    releaseContinuations.append(continuation)
                }
            }
            return SwanDIDDocumentFetchResult(data: Data(json.utf8), maxAge: maxAge, noStore: noStore)
        } else {
            return SwanDIDDocumentFetchResult(data: Data(json.utf8), maxAge: maxAge, noStore: noStore)
        }
    }
}

private final class TestMonotonicClock: @unchecked Sendable {
    private let lock = NSLock()
    private var currentInstant: ContinuousClock.Instant = .now

    var clock: SwanServiceEndpointResolver.MonotonicClock {
        SwanServiceEndpointResolver.MonotonicClock { [weak self] in
            self?.now() ?? .now
        }
    }

    func now() -> ContinuousClock.Instant {
        lock.withLock { currentInstant }
    }

    func advance(by seconds: TimeInterval) {
        lock.withLock {
            currentInstant = currentInstant.advanced(by: .seconds(seconds))
        }
    }
}

final class SwanServiceEndpointResolverTests: XCTestCase {
    private func resolver(_ json: String) throws -> SwanServiceEndpointResolver {
        try SwanServiceEndpointResolver(documents: StubDocuments(json: json))
    }

    private let document = """
    {"id":"did:web:api.bsky.app","service":[
      {"id":"#bsky_appview","type":"BskyAppView","serviceEndpoint":"https://api.bsky.app"},
      {"id":"#other","type":"Other","serviceEndpoint":"https://other.example"}]}
    """

    func testSelectsServiceByFragment() async throws {
        let url = try await resolver(document).endpoint(
            did: "did:web:api.bsky.app", fragment: "bsky_appview"
        )
        XCTAssertEqual(url, URL(string: "https://api.bsky.app"))
    }

    func testAcceptsFullyQualifiedServiceID() async throws {
        let json = """
        {"id":"did:web:x.example","service":[
          {"id":"did:web:x.example#bsky_appview","type":"BskyAppView",
           "serviceEndpoint":"https://x.example"}]}
        """
        let url = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
        XCTAssertEqual(url, URL(string: "https://x.example"))
    }

    func testMissingFragmentIsUnresolvable() async {
        do {
            _ = try await resolver(document).endpoint(
                did: "did:web:api.bsky.app", fragment: "nope"
            )
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    func testNonHTTPSEndpointIsRejected() async {
        let json = """
        {"id":"did:web:x.example","service":[
          {"id":"#bsky_appview","type":"BskyAppView","serviceEndpoint":"http://x.example"}]}
        """
        do {
            _ = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    func testMalformedDocumentIsUnresolvable() async {
        for json in ["{}", "not json", #"{"service":[]}"#, #"{"service":"nope"}"#] {
            do {
                _ = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
                XCTFail("expected failure for \(json)")
            } catch {
                XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
            }
        }
    }

    // MARK: Subject binding (F07)

    /// The fetch path proves *where* the document came from, not *whose* it is.
    /// A document that names a different subject is refused even though it is
    /// otherwise well formed and its endpoint is a perfectly good https URL.
    func testDocumentForADifferentSubjectIsRejected() async {
        let json = """
        {"id":"did:web:evil.example","service":[
          {"id":"#bsky_appview","type":"BskyAppView",
           "serviceEndpoint":"https://evil.example"}]}
        """
        do {
            _ = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    /// The comparison is byte-exact against the DID as received. `did:web` ids
    /// carry `%3A` for a port, and the fetcher's URL derivation is the only
    /// place that decoding happens; re-normalising here would be a second,
    /// weaker grammar. So a `%3A`-bearing DID resolves only against a document
    /// whose `id` is spelled the same way.
    func testPercentEncodedPortDIDMatchesExactly() async throws {
        let json = """
        {"id":"did:web:x.example%3A8443","service":[
          {"id":"#bsky_appview","type":"BskyAppView",
           "serviceEndpoint":"https://x.example:8443"}]}
        """
        let url = try await resolver(json).endpoint(
            did: "did:web:x.example%3A8443", fragment: "bsky_appview"
        )
        XCTAssertEqual(url, URL(string: "https://x.example:8443"))
    }

    /// ...and the decoded spelling of the same authority is a different string,
    /// so it does not match. This is the deliberate consequence of refusing to
    /// normalise, asserted so a later "helpful" normalisation fails loudly.
    func testDecodedPortSpellingDoesNotMatchEncodedDocumentID() async {
        let json = """
        {"id":"did:web:x.example%3A8443","service":[
          {"id":"#bsky_appview","type":"BskyAppView",
           "serviceEndpoint":"https://x.example:8443"}]}
        """
        do {
            _ = try await resolver(json).endpoint(
                did: "did:web:x.example:8443", fragment: "bsky_appview"
            )
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    /// Host case is the other spelling that names the same subject and is not
    /// the same string. DNS is case-insensitive, so the document fetch itself
    /// would have succeeded; binding still refuses, because accepting it means
    /// choosing a case-folding rule here that the fetcher's URL derivation
    /// does not share. Declared as a behaviour change, not discovered as one:
    /// a caller that spells the DID in a different case than the document does
    /// gets `.unresolvableService` where it used to get the endpoint.
    func testHostCaseDifferenceDoesNotMatchDocumentID() async {
        let json = """
        {"id":"did:web:x.example","service":[
          {"id":"#bsky_appview","type":"BskyAppView",
           "serviceEndpoint":"https://x.example"}]}
        """
        do {
            _ = try await resolver(json).endpoint(
                did: "did:web:X.Example", fragment: "bsky_appview"
            )
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    /// A document with no `id` cannot be bound to the DID that was asked for.
    /// `id` is required by DID Core, so an absent one is a malformed document,
    /// not a permissive one — it is rejected rather than waved through.
    func testDocumentWithoutAnIDIsRejected() async {
        let json = """
        {"service":[
          {"id":"#bsky_appview","type":"BskyAppView",
           "serviceEndpoint":"https://x.example"}]}
        """
        do {
            _ = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    // MARK: Duplicate service ids (F07)

    /// Two entries with the same id: taking the first makes the answer depend
    /// on array order, so an appended duplicate would silently shadow — or be
    /// shadowed by — the real entry. The ambiguity is refused instead.
    func testDuplicateServiceIDsAreRejected() async {
        let json = """
        {"id":"did:web:x.example","service":[
          {"id":"#bsky_appview","type":"BskyAppView","serviceEndpoint":"https://x.example"},
          {"id":"#bsky_appview","type":"BskyAppView","serviceEndpoint":"https://evil.example"}]}
        """
        do {
            _ = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    /// The same fragment written both ways ("#frag" and "did:...#frag") is the
    /// same service id, so it is the same ambiguity and is refused too.
    func testFragmentDeclaredBothShortAndFullyQualifiedIsRejected() async {
        let json = """
        {"id":"did:web:x.example","service":[
          {"id":"#bsky_appview","type":"BskyAppView","serviceEndpoint":"https://x.example"},
          {"id":"did:web:x.example#bsky_appview","type":"BskyAppView",
           "serviceEndpoint":"https://evil.example"}]}
        """
        do {
            _ = try await resolver(json).endpoint(did: "did:web:x.example", fragment: "bsky_appview")
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    /// A duplicate on some *other* fragment does not make the requested one
    /// ambiguous. Scoping the rejection to the selection keeps a single
    /// malformed unrelated entry from denying every service in the document.
    func testDuplicateOnAnUnrelatedFragmentStillResolves() async throws {
        let json = """
        {"id":"did:web:x.example","service":[
          {"id":"#other","type":"Other","serviceEndpoint":"https://a.example"},
          {"id":"#other","type":"Other","serviceEndpoint":"https://b.example"},
          {"id":"#bsky_appview","type":"BskyAppView","serviceEndpoint":"https://x.example"}]}
        """
        let url = try await resolver(json).endpoint(
            did: "did:web:x.example", fragment: "bsky_appview"
        )
        XCTAssertEqual(url, URL(string: "https://x.example"))
    }

    func testFetchFailureIsUnresolvable() async {
        do {
            _ = try await SwanServiceEndpointResolver(documents: FailingDocuments())
                .endpoint(did: "did:web:x.example", fragment: "bsky_appview")
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
    }

    // MARK: Single-flight coalescing and caching

    func testConcurrentResolutionsOfSameDIDCoalesceToOneUpstreamFetch() async throws {
        let docs = ControllableDocuments(json: document, gated: true)
        let resolver = try SwanServiceEndpointResolver(documents: docs)

        let tasks = (0 ..< 10).map { _ in
            Task {
                try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
            }
        }

        // Wait until all 10 callers have joined the single in-flight flight
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(3))
        while (await resolver.inFlightWaiterCount(for: "did:web:api.bsky.app") < 10) && clock.now < deadline {
            await Task.yield()
        }
        let inFlightCount = await resolver.inFlightWaiterCount(for: "did:web:api.bsky.app")
        XCTAssertEqual(inFlightCount, 10, "all 10 concurrent requests must be registered in the flight")

        // Release the single gated upstream fetch
        await docs.releaseAll()

        for task in tasks {
            let url = try await task.value
            XCTAssertEqual(url, URL(string: "https://api.bsky.app"))
        }

        let count = await docs.fetchCount
        XCTAssertEqual(count, 1, "all 10 concurrent resolutions must coalesce to exactly one upstream fetch")
    }

    func testPositiveCacheServesWithinLifetimeAndRefetchesAfterExpiry() async throws {
        let clock = TestMonotonicClock()
        let docs = ControllableDocuments(json: document)
        let resolver = try SwanServiceEndpointResolver(
            documents: docs,
            cacheConfiguration: .init(lifetime: 60, maximumEntries: 256),
            monotonicClock: clock.clock
        )

        let first = try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
        XCTAssertEqual(first, URL(string: "https://api.bsky.app"))
        var count = await docs.fetchCount
        XCTAssertEqual(count, 1)

        // Within TTL (30s < 60s)
        clock.advance(by: 30)
        let cached = try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
        XCTAssertEqual(cached, URL(string: "https://api.bsky.app"))
        count = await docs.fetchCount
        XCTAssertEqual(count, 1)

        // Different fragment on same cached document also hits cache
        let cachedOther = try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "other")
        XCTAssertEqual(cachedOther, URL(string: "https://other.example"))
        count = await docs.fetchCount
        XCTAssertEqual(count, 1)

        // Past TTL (30s + 31s = 61s > 60s)
        clock.advance(by: 31)
        let refetched = try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
        XCTAssertEqual(refetched, URL(string: "https://api.bsky.app"))
        count = await docs.fetchCount
        XCTAssertEqual(count, 2, "must refetch after cache lifetime expires")
    }

    func testCancellingOneWaiterDoesNotCancelSharedFetchForOtherWaiters() async throws {
        let docs = ControllableDocuments(json: document, gated: true)
        let resolver = try SwanServiceEndpointResolver(documents: docs)

        let waiter1 = Task {
            try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
        }

        // Wait until waiter1 is in flight
        let clock = ContinuousClock()
        let deadline1 = clock.now.advanced(by: .seconds(5))
        while (await resolver.inFlightWaiterCount(for: "did:web:api.bsky.app") < 1) && clock.now < deadline1 {
            await Task.yield()
        }
        let count1 = await resolver.inFlightWaiterCount(for: "did:web:api.bsky.app")
        XCTAssertEqual(count1, 1)
        let waiter2 = Task {
            try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
        }

        // Explicit acknowledgement: wait until waiter2 has registered on the existing in-flight flight
        let deadline2 = clock.now.advanced(by: .seconds(5))
        while (await resolver.inFlightWaiterCount(for: "did:web:api.bsky.app") < 2) && clock.now < deadline2 {
            await Task.yield()
        }
        let count2 = await resolver.inFlightWaiterCount(for: "did:web:api.bsky.app")
        XCTAssertEqual(count2, 2)
        // Cancel waiter1
        waiter1.cancel()

        // Waiter1 must fail immediately with CancellationError while fetch is still gated
        do {
            _ = try await waiter1.value
            XCTFail("waiter1 should have thrown CancellationError")
        } catch is CancellationError {
            // Expected immediate cancellation
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        // Release the gated fetch
        await docs.releaseAll()

        // Waiter2 must succeed with the resolved URL
        let result2 = try await waiter2.value
        XCTAssertEqual(result2, URL(string: "https://api.bsky.app"))
        let count = await docs.fetchCount
        XCTAssertEqual(count, 1, "exactly one fetch should have run")
    }

    func testFetchFailureIsNotCachedAndDeliveredToAllWaiters() async throws {
        let docs = ControllableDocuments(json: "invalid json", gated: true)
        let resolver = try SwanServiceEndpointResolver(documents: docs)

        let waiter1 = Task {
            try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
        }
        let waiter2 = Task {
            try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
        }
        let waiter3 = Task {
            try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
        }

        // Wait until all 3 waiters are registered in flight
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(3))
        while (await resolver.inFlightWaiterCount(for: "did:web:api.bsky.app") < 3) && clock.now < deadline {
            await Task.yield()
        }
        let failureCount = await resolver.inFlightWaiterCount(for: "did:web:api.bsky.app")
        XCTAssertEqual(failureCount, 3)
        // Release the gated failing fetch
        await docs.releaseAll()

        for waiter in [waiter1, waiter2, waiter3] {
            do {
                _ = try await waiter.value
                XCTFail("expected failure")
            } catch {
                XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
            }
        }
        var count = await docs.fetchCount
        XCTAssertEqual(count, 1, "all 3 concurrent waiters must share the 1 failed fetch")

        // Fix document JSON; next call should fetch immediately (not negatively cached)
        await docs.setJSON(document)
        let recovered = try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
        XCTAssertEqual(recovered, URL(string: "https://api.bsky.app"))
        count = await docs.fetchCount
        XCTAssertEqual(count, 2, "must fetch again after failure repair")
    }

    func testCacheCapacityEviction() async throws {
        let clock = TestMonotonicClock()
        let docs = ControllableDocuments(json: document)
        let resolver = try SwanServiceEndpointResolver(
            documents: docs,
            cacheConfiguration: .init(lifetime: 60, maximumEntries: 2),
            monotonicClock: clock.clock
        )

        let doc1 = """
        {"id":"did:web:one.example","service":[{"id":"#svc","type":"S","serviceEndpoint":"https://one.example"}]}
        """
        let doc2 = """
        {"id":"did:web:two.example","service":[{"id":"#svc","type":"S","serviceEndpoint":"https://two.example"}]}
        """
        let doc3 = """
        {"id":"did:web:three.example","service":[{"id":"#svc","type":"S","serviceEndpoint":"https://three.example"}]}
        """

        await docs.setJSON(doc1)
        _ = try await resolver.endpoint(did: "did:web:one.example", fragment: "svc")
        var count = await docs.fetchCount
        XCTAssertEqual(count, 1)

        // Advance 10s (doc1 expires at t=60)
        clock.advance(by: 10)
        await docs.setJSON(doc2)
        _ = try await resolver.endpoint(did: "did:web:two.example", fragment: "svc")
        count = await docs.fetchCount
        XCTAssertEqual(count, 2)

        // Advance 10s to t=20. BOTH doc1 (expires at 60) and doc2 (expires at 70) are LIVE!
        clock.advance(by: 10)

        // Insert doc3 at t=20; capacity is 2; both entries are live, so oldest entry (doc1) is evicted
        await docs.setJSON(doc3)
        _ = try await resolver.endpoint(did: "did:web:three.example", fragment: "svc")
        count = await docs.fetchCount
        XCTAssertEqual(count, 3)

        // doc2 is still live and cached
        await docs.setJSON(doc2)
        let url2 = try await resolver.endpoint(did: "did:web:two.example", fragment: "svc")
        XCTAssertEqual(url2, URL(string: "https://two.example"))
        count = await docs.fetchCount
        XCTAssertEqual(count, 3, "doc2 should still be cached")

        // doc3 is still live and cached
        await docs.setJSON(doc3)
        let url3 = try await resolver.endpoint(did: "did:web:three.example", fragment: "svc")
        XCTAssertEqual(url3, URL(string: "https://three.example"))
        count = await docs.fetchCount
        XCTAssertEqual(count, 3, "doc3 should still be cached")

        // Query doc1: doc1 was evicted to make room for doc3, so it MUST trigger an upstream fetch!
        await docs.setJSON(doc1)
        let url1 = try await resolver.endpoint(did: "did:web:one.example", fragment: "svc")
        XCTAssertEqual(url1, URL(string: "https://one.example"))
        count = await docs.fetchCount
        XCTAssertEqual(count, 4, "evicted doc1 must trigger a new upstream fetch")
    }

    func testRespectsSourceFreshnessAndNoStoreDirectives() async throws {
        let clock = TestMonotonicClock()
        let docs = ControllableDocuments(json: document, noStore: true)
        let resolver = try SwanServiceEndpointResolver(
            documents: docs,
            cacheConfiguration: .init(lifetime: 60, maximumEntries: 256),
            monotonicClock: clock.clock
        )

        // no-store document should resolve successfully
        let first = try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
        XCTAssertEqual(first, URL(string: "https://api.bsky.app"))
        var count = await docs.fetchCount
        XCTAssertEqual(count, 1)

        // Second request immediately after must fetch again (not cached due to no-store)
        let second = try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
        XCTAssertEqual(second, URL(string: "https://api.bsky.app"))
        count = await docs.fetchCount
        XCTAssertEqual(count, 2, "no-store response must not be cached")

        // max-age=10 document should expire at 10s even though local cap is 60s
        await docs.setJSON(document, maxAge: 10, noStore: false)
        let third = try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
        XCTAssertEqual(third, URL(string: "https://api.bsky.app"))
        count = await docs.fetchCount
        XCTAssertEqual(count, 3)

        // Within max-age (5s < 10s)
        clock.advance(by: 5)
        let thirdCached = try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
        XCTAssertEqual(thirdCached, URL(string: "https://api.bsky.app"))
        count = await docs.fetchCount
        XCTAssertEqual(count, 3)

        // Past max-age (5s + 6s = 11s > 10s)
        clock.advance(by: 6)
        let fourth = try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
        XCTAssertEqual(fourth, URL(string: "https://api.bsky.app"))
        count = await docs.fetchCount
        XCTAssertEqual(count, 4, "source max-age must take precedence when shorter than local lifetime")
    }

    func testSemanticFailureIsNotCachedAndAllowsImmediateSourceRepair() async throws {
        let docs = ControllableDocuments(json: #"{"id":"did:web:x.example","service":[]}"#)
        let resolver = try SwanServiceEndpointResolver(documents: docs)

        // Empty services -> semantic failure
        do {
            _ = try await resolver.endpoint(did: "did:web:x.example", fragment: "bsky_appview")
            XCTFail("expected failure")
        } catch {
            XCTAssertEqual(error as? SwanServiceResolutionFailure, .unresolvableService)
        }
        var count = await docs.fetchCount
        XCTAssertEqual(count, 1)

        // Remote source repairs document by adding the service
        let repaired = """
        {"id":"did:web:x.example","service":[
          {"id":"#bsky_appview","type":"BskyAppView","serviceEndpoint":"https://x.example"}]}
        """
        await docs.setJSON(repaired)

        // Next request immediately fetches and succeeds (semantic failure was not cached)
        let url = try await resolver.endpoint(did: "did:web:x.example", fragment: "bsky_appview")
        XCTAssertEqual(url, URL(string: "https://x.example"))
        count = await docs.fetchCount
        XCTAssertEqual(count, 2, "semantic failure must not be cached")
    }

    func testInvalidConfigurationIsRejectedAtConstruction() {
        let docs = StubDocuments(json: document)
        XCTAssertThrowsError(try SwanServiceEndpointResolver(
            documents: docs,
            cacheConfiguration: .init(lifetime: 4)
        ))
        XCTAssertThrowsError(try SwanServiceEndpointResolver(
            documents: docs,
            cacheConfiguration: .init(lifetime: 301)
        ))
        XCTAssertThrowsError(try SwanServiceEndpointResolver(
            documents: docs,
            cacheConfiguration: .init(lifetime: .nan)
        ))
        XCTAssertThrowsError(try SwanServiceEndpointResolver(
            documents: docs,
            cacheConfiguration: .init(maximumEntries: 0)
        ))
        XCTAssertThrowsError(try SwanServiceEndpointResolver(
            documents: docs,
            cacheConfiguration: .init(maximumEntries: 1025)
        ))
    }
}
