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
    private var count = 0
    private var nextContinuationID = 0
    private var releaseContinuations: [Int: CheckedContinuation<Void, Error>] = [:]
    private var gated = false

    init(json: String, gated: Bool = false) {
        self.json = json
        self.gated = gated
    }

    func setJSON(_ json: String) {
        self.json = json
    }

    var fetchCount: Int {
        count
    }

    func releaseAll() {
        gated = false
        let conts = Array(releaseContinuations.values)
        releaseContinuations.removeAll()
        for cont in conts {
            cont.resume()
        }
    }

    private func cancelContinuation(id: Int) {
        if let cont = releaseContinuations.removeValue(forKey: id) {
            cont.resume(throwing: CancellationError())
        }
    }

    func documentJSON(forDID did: String) async throws -> Data {
        count += 1
        try Task.checkCancellation()
        if gated {
            let id = nextContinuationID
            nextContinuationID += 1
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    if !gated {
                        continuation.resume()
                    } else {
                        releaseContinuations[id] = continuation
                    }
                }
            } onCancel: {
                Task { [weak self] in
                    await self?.cancelContinuation(id: id)
                }
            }
        }
        try Task.checkCancellation()
        return Data(json.utf8)
    }
}

private struct TestAcknowledgementTimeoutError: Error, Sendable {}

private actor TestAcknowledgement {
    private var signaled = false
    private var waiters: [CheckedContinuation<Void, Error>] = []

    func signal() {
        signaled = true
        let continuations = waiters
        waiters.removeAll()
        for cont in continuations {
            cont.resume()
        }
    }

    func wait(timeoutSeconds: TimeInterval = 3) async throws {
        if signaled { return }
        let timer = Task { [weak self] in
            try await Task.sleep(for: .seconds(timeoutSeconds))
            await self?.timeout()
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            if signaled {
                continuation.resume()
            } else {
                waiters.append(continuation)
            }
        }
        timer.cancel()
    }

    private func timeout() {
        guard !signaled else { return }
        let continuations = waiters
        waiters.removeAll()
        for cont in continuations {
            cont.resume(throwing: TestAcknowledgementTimeoutError())
        }
    }
}
private struct TestTimeoutError: Error, Sendable {}
private struct TestStateError: Error, Sendable {}

private final class BoundedJoinState<R: Sendable>: @unchecked Sendable {
    private enum State {
        case idle
        case waiting(CheckedContinuation<R, Error>)
        case completed(Result<R, Error>)
    }

    private let lock = NSLock()
    private var state: State = .idle

    init() {}

    func install(_ cont: CheckedContinuation<R, Error>) {
        lock.lock()
        switch state {
        case .idle:
            state = .waiting(cont)
            lock.unlock()
        case .waiting:
            lock.unlock()
            preconditionFailure("BoundedJoinState: continuation installed more than once")
        case let .completed(result):
            lock.unlock()
            cont.resume(with: result)
        }
    }

    func complete(with result: Result<R, Error>) {
        lock.lock()
        switch state {
        case .idle:
            state = .completed(result)
            lock.unlock()
        case let .waiting(cont):
            state = .completed(result)
            lock.unlock()
            cont.resume(with: result)
        case .completed:
            lock.unlock()
        }
    }
}

private func boundedJoin<T: Sendable>(
    _ task: Task<T, Error>,
    timeoutSeconds: TimeInterval = 3,
    onInstalled: (@Sendable () async -> Void)? = nil
) async throws -> T {
    let state = BoundedJoinState<T>()
    return try await withTaskCancellationHandler(
        operation: {
            let timer = Task {
                try await Task.sleep(for: .seconds(timeoutSeconds))
                state.complete(with: .failure(TestTimeoutError()))
                task.cancel()
            }
            _ = Task {
                do {
                    let val = try await task.value
                    timer.cancel()
                    state.complete(with: .success(val))
                } catch {
                    timer.cancel()
                    state.complete(with: .failure(error))
                }
            }
            return try await withCheckedThrowingContinuation { cont in
                state.install(cont)
                if let onInstalled {
                    Task {
                        await onInstalled()
                    }
                }
            }
        },
        onCancel: {
            task.cancel()
            state.complete(with: .failure(CancellationError()))
        }
    )
}

final class SwanServiceEndpointResolverTests: XCTestCase {
    private func resolver(_ json: String) -> SwanServiceEndpointResolver {
        SwanServiceEndpointResolver(documents: StubDocuments(json: json))
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
        let resolver = SwanServiceEndpointResolver(documents: docs)

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
            let url = try await boundedJoin(task)
            XCTAssertEqual(url, URL(string: "https://api.bsky.app"))
        }

        let count = await docs.fetchCount
        XCTAssertEqual(count, 1, "all 10 concurrent resolutions must coalesce to exactly one upstream fetch")
    }
    func testCoalescedWaitersWithDifferentFragmentsDoNotStarveOnCreatorFailure() async throws {
        let docs = ControllableDocuments(json: document, gated: true)
        let resolver = SwanServiceEndpointResolver(documents: docs)

        // Creator requests non-existent fragment `#nonexistent`
        let creator = Task {
            try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "nonexistent")
        }
        let clock = ContinuousClock()
        let deadline1 = clock.now.advanced(by: .seconds(3))
        while (await resolver.inFlightWaiterCount(for: "did:web:api.bsky.app") < 1) && clock.now < deadline1 {
            await Task.yield()
        }
        let count1 = await resolver.inFlightWaiterCount(for: "did:web:api.bsky.app")
        XCTAssertEqual(count1, 1)

        // Joined caller requests valid fragment `#bsky_appview`
        let joined = Task {
            try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
        }
        let deadline2 = clock.now.advanced(by: .seconds(3))
        while (await resolver.inFlightWaiterCount(for: "did:web:api.bsky.app") < 2) && clock.now < deadline2 {
            await Task.yield()
        }
        let count2 = await resolver.inFlightWaiterCount(for: "did:web:api.bsky.app")
        XCTAssertEqual(count2, 2)

        // Release the shared upstream fetch
        await docs.releaseAll()

        // Creator fails with unresolvableService
        do {
            _ = try await boundedJoin(creator)
            XCTFail("creator should have failed with unresolvableService")
        } catch let error as SwanServiceResolutionFailure {
            XCTAssertEqual(error, .unresolvableService)
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        // Joined caller succeeds with the resolved URL
        let result = try await boundedJoin(joined)
        XCTAssertEqual(result, URL(string: "https://api.bsky.app"))

        let count = await docs.fetchCount
        XCTAssertEqual(count, 1, "both callers must share exactly 1 upstream fetch")
    }


    func testCancellingOneWaiterDoesNotCancelSharedFetchForOtherWaiters() async throws {
        let docs = ControllableDocuments(json: document, gated: true)
        let resolver = SwanServiceEndpointResolver(documents: docs)

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
            _ = try await boundedJoin(waiter1)
            XCTFail("waiter1 should have thrown CancellationError")
        } catch is CancellationError {
            // Expected immediate cancellation
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        // Release the gated fetch
        await docs.releaseAll()

        // Waiter2 must succeed with the resolved URL
        let result2 = try await boundedJoin(waiter2)
        XCTAssertEqual(result2, URL(string: "https://api.bsky.app"))
        let count = await docs.fetchCount
        XCTAssertEqual(count, 1, "exactly one fetch should have run")
    }

    func testFetchFailureIsNotCachedAndDeliveredToAllWaiters() async throws {
        let docs = ControllableDocuments(json: "invalid json", gated: true)
        let resolver = SwanServiceEndpointResolver(documents: docs)

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
                _ = try await boundedJoin(waiter)
                XCTFail("expected failure")
            } catch let error as SwanServiceResolutionFailure {
                XCTAssertEqual(error, .unresolvableService)
            } catch {
                XCTFail("unexpected error: \(error)")
            }
        }
        var count = await docs.fetchCount
        XCTAssertEqual(count, 1, "all 3 concurrent waiters must share the 1 failed fetch")

        // Fix document JSON; next call should fetch immediately (not negatively cached)
        await docs.setJSON(document)
        let recoveryTask = Task {
            try await resolver.endpoint(did: "did:web:api.bsky.app", fragment: "bsky_appview")
        }
        let recovered = try await boundedJoin(recoveryTask)
        XCTAssertEqual(recovered, URL(string: "https://api.bsky.app"))
        count = await docs.fetchCount
        XCTAssertEqual(count, 2, "must fetch again after failure repair")
    }

    func testSemanticFailureIsNotCachedAndAllowsImmediateSourceRepair() async throws {
        let docs = ControllableDocuments(json: #"{"id":"did:web:x.example","service":[]}"#)
        let resolver = SwanServiceEndpointResolver(documents: docs)

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

    func testBoundedJoinStateCompleteBeforeInstall() async throws {
        let state = BoundedJoinState<Int>()
        state.complete(with: .success(42))
        // Duplicate completion must be ignored
        state.complete(with: .success(99))
        let task = Task {
            try await withCheckedThrowingContinuation { cont in
                state.install(cont)
            }
        }
        let result = try await boundedJoin(task)
        XCTAssertEqual(result, 42)
    }

    func testBoundedJoinStateInstallBeforeComplete() async throws {
        let state = BoundedJoinState<Int>()
        let installed = TestAcknowledgement()
        let task = Task {
            try await withCheckedThrowingContinuation { cont in
                state.install(cont)
                Task {
                    await installed.signal()
                }
            }
        }
        try await installed.wait()
        state.complete(with: .success(100))
        // Duplicate completion ignored
        state.complete(with: .success(200))
        let result = try await boundedJoin(task)
        XCTAssertEqual(result, 100)
    }

    func testBoundedJoinStateTimeoutResumesContinuationOnce() async throws {
        let state = BoundedJoinState<Int>()
        let installed = TestAcknowledgement()
        let task = Task {
            try await withCheckedThrowingContinuation { cont in
                state.install(cont)
                Task {
                    await installed.signal()
                }
            }
        }
        try await installed.wait()
        state.complete(with: .failure(TestStateError()))
        // Subsequent completion ignored
        state.complete(with: .success(42))
        do {
            _ = try await boundedJoin(task)
            XCTFail("should have failed with TestStateError")
        } catch is TestStateError {
            // Expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testBoundedJoinStateCancellationResumesContinuationOnce() async throws {
        let state = BoundedJoinState<Int>()
        let installed = TestAcknowledgement()
        let task = Task {
            try await withCheckedThrowingContinuation { cont in
                state.install(cont)
                Task {
                    await installed.signal()
                }
            }
        }
        try await installed.wait()
        state.complete(with: .failure(CancellationError()))
        // Subsequent completion ignored
        state.complete(with: .success(42))
        do {
            _ = try await boundedJoin(task)
            XCTFail("should have failed with CancellationError")
        } catch is CancellationError {
            // Expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testBoundedJoinWhenTaskCompletes() async throws {
        let task: Task<Int, Error> = Task {
            return 42
        }
        let result = try await boundedJoin(task, timeoutSeconds: 3)
        XCTAssertEqual(result, 42)
    }

    func testBoundedJoinWhenTaskTimesOut() async throws {
        let task: Task<Int, Error> = Task {
            try await Task.sleep(for: .seconds(10))
            return 42
        }
        do {
            _ = try await boundedJoin(task, timeoutSeconds: 0.1)
            XCTFail("should have timed out")
        } catch is TestTimeoutError {
            // Expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testBoundedJoinWhenTaskCancelled() async throws {
        let installed = TestAcknowledgement()
        let callerTask = Task {
            let task: Task<Int, Error> = Task {
                try await Task.sleep(for: .seconds(10))
                return 42
            }
            return try await boundedJoin(task, timeoutSeconds: 3, onInstalled: {
                await installed.signal()
            })
        }
        try await installed.wait()
        callerTask.cancel()
        do {
            _ = try await callerTask.value
            XCTFail("should have thrown CancellationError")
        } catch is CancellationError {
            // Expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }
}
