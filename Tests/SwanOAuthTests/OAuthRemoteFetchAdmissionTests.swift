import Crypto
import Foundation
@testable import SwanOAuth
import SwanCore
import SwanSQLite
import SwanStorage
import XCTest

final class OAuthRemoteFetchAdmissionTests: XCTestCase, @unchecked Sendable {
    private let now = Date(timeIntervalSince1970: 1_775_001_600)

    func testBlockingDNSAdmissionRetainsTimedOutWorkUntilLibcCompletion()
        throws
    {
        let admission = OAuthBlockingDNSAdmission(maximumOutstanding: 2)
        let first = try admission.acquire()
        let second = try admission.acquire()
        XCTAssertEqual(admission.outstandingCountForTesting, 2)
        XCTAssertThrowsError(try admission.acquire()) { error in
            guard let swanError = error as? SwanError,
                  case .unavailable = swanError else {
                return XCTFail("expected typed unavailable, got \(error)")
            }
        }
        first.release()
        XCTAssertEqual(admission.outstandingCountForTesting, 1)
        let replacement = try admission.acquire()
        XCTAssertEqual(admission.outstandingCountForTesting, 2)
        second.release()
        replacement.release()
        XCTAssertEqual(admission.outstandingCountForTesting, 0)
    }

    func testNewerStartedFetchDoesNotStarveOlderValidPublication()
        async throws
    {
        let fixture = try await OAuthRemoteFetchAdmissionFixture()
        addTeardownBlock {
            try? await fixture.database.close()
            fixture.cleanup()
        }
        let clientID = fixture.clientID.absoluteString
        let first = try await fixture.database.beginClientMetadataFetch(
            clientID: clientID,
            now: now
        )
        let second = try await fixture.database.beginClientMetadataFetch(
            clientID: clientID,
            now: now.addingTimeInterval(1)
        )

        let firstPublished = try await fixture.database.publishClientMetadata(
            OAuthCachedClientMetadata(
                clientID: clientID,
                document: Data("first-valid".utf8),
                expiresAt: now.addingTimeInterval(300)
            ),
            using: first,
            now: now.addingTimeInterval(2)
        )
        XCTAssertTrue(
            firstPublished,
            "a newer fetch that has not successfully published must not starve an older valid response"
        )

        let secondPublished = try await fixture.database.publishClientMetadata(
            OAuthCachedClientMetadata(
                clientID: clientID,
                document: Data("second-valid".utf8),
                expiresAt: now.addingTimeInterval(301)
            ),
            using: second,
            now: now.addingTimeInterval(3)
        )
        XCTAssertTrue(secondPublished)
        let cached = try await fixture.database.cachedClientMetadata(
            clientID: clientID,
            now: now.addingTimeInterval(4)
        )
        XCTAssertEqual(cached?.document, Data("second-valid".utf8))
    }

    func testConcurrentExactURLMetadataLoadsShareOneTransportFlightAndReturnEveryResult()
        async throws
    {
        let fixture = try await OAuthRemoteFetchAdmissionFixture()
        addTeardownBlock {
            try? await fixture.database.close()
            fixture.cleanup()
        }
        let callerBarrier = OAuthMetadataCallerBarrier(participantCount: 8)
        let completions = OAuthMetadataLoadProbe()

        let waiters = (0 ..< 8).map { index in
            Task {
                await callerBarrier.arriveAndWait()
                await completions.record(
                    await oauthMetadataLoadOutcome {
                        try await fixture.loader.load(
                            clientID: fixture.clientID,
                            now: self.now
                        )
                    },
                    at: index
                )
            }
        }
        defer {
            waiters.forEach { $0.cancel() }
            Task {
                await callerBarrier.release()
                await fixture.transport.releaseAll()
            }
        }

        let allCallersArrived = await oauthEventually(within: .seconds(1)) {
            await callerBarrier.arrivalCount() == 8
        }
        XCTAssertTrue(
            allCallersArrived,
            "all callers must reach the closed start gate"
        )
        await callerBarrier.release()
        let sharedRequestStarted = await oauthEventually(
            within: .seconds(1)
        ) {
            await fixture.transport.requestCount() >= 1
        }
        XCTAssertTrue(
            sharedRequestStarted,
            "the shared metadata request never reached the transport"
        )
        let secondRequestStarted = await oauthEventually(
            within: .milliseconds(400)
        ) {
            await fixture.transport.requestCount() >= 2
        }
        XCTAssertFalse(
            secondRequestStarted,
            "a second exact-URL transport request escaped singleflight"
        )
        let activeBlockedRequests =
            await fixture.transport.activeBlockedRequestCount()
        XCTAssertEqual(
            activeBlockedRequests,
            1,
            "the one shared transport request must remain blocked"
        )
        let prematureCompletions = await completions.count()
        XCTAssertEqual(
            prematureCompletions,
            0,
            "no metadata caller may fabricate a result before transport release"
        )
        await fixture.transport.releaseAll()

        let allCallersCompleted = await completions.waitUntilCount(
            8,
            within: .seconds(2)
        )
        XCTAssertTrue(
            allCallersCompleted,
            "all joined metadata callers must complete after release"
        )
        let outcomes = await completions.allOutcomes()
        XCTAssertEqual(outcomes.count, 8)
        for outcome in outcomes {
            guard case let .success(result) = outcome else {
                XCTFail("every joined metadata caller must succeed: \(outcome)")
                continue
            }
            XCTAssertEqual(
                result.metadata.clientID.absoluteString,
                "https://client.example/oauth/client-metadata.json"
            )
            XCTAssertEqual(
                result.metadata.clientName,
                "Admission test client"
            )
            XCTAssertTrue(result.metadata.dpopBoundAccessTokens)
        }
        let requestCount = await fixture.transport.requestCount()
        XCTAssertEqual(
            requestCount,
            1,
            "exact-URL cache misses must join one outbound metadata request"
        )
    }

    func testCancellingOneWaiterDoesNotCancelExactURLSharedTransportFlight()
        async throws
    {
        let fixture = try await OAuthRemoteFetchAdmissionFixture()
        addTeardownBlock {
            try? await fixture.database.close()
            fixture.cleanup()
        }
        let completions = OAuthMetadataLoadProbe()

        let survivingWaiter = Task {
            await completions.record(
                await oauthMetadataLoadOutcome {
                    try await fixture.loader.load(
                        clientID: fixture.clientID,
                        now: self.now
                    )
                },
                at: 0
            )
        }
        defer {
            survivingWaiter.cancel()
            Task { await fixture.transport.releaseAll() }
        }
        let initiatingRequestStarted = await oauthEventually(
            within: .seconds(1)
        ) {
            await fixture.transport.requestCount() == 1
        }
        XCTAssertTrue(
            initiatingRequestStarted,
            "the initiating shared request never reached the transport"
        )

        let cancelledWaiter = Task {
            await completions.record(
                await oauthMetadataLoadOutcome {
                    try await fixture.loader.load(
                        clientID: fixture.clientID,
                        now: self.now
                    )
                },
                at: 1
            )
        }
        defer { cancelledWaiter.cancel() }
        let duplicateRequestStarted = await oauthEventually(
            within: .milliseconds(200)
        ) {
            await fixture.transport.requestCount() >= 2
        }
        XCTAssertFalse(
            duplicateRequestStarted,
            "the second exact-URL waiter must join the blocked shared flight"
        )

        cancelledWaiter.cancel()
        let cancelledPromptly = await completions.waitUntilIndex(
            1,
            within: .milliseconds(250)
        )
        XCTAssertTrue(
            cancelledPromptly,
            "a cancelled waiter must finish promptly while the shared transport remains blocked"
        )
        if let outcome = await completions.outcome(at: 1) {
            XCTAssertEqual(
                outcome,
                .cancellation,
                "the cancelled waiter must observe CancellationError"
            )
        }
        let completionsBeforeRelease = await completions.count()
        XCTAssertEqual(
            completionsBeforeRelease,
            cancelledPromptly ? 1 : 0,
            "the surviving waiter must remain blocked"
        )
        let activeBlockedRequests =
            await fixture.transport.activeBlockedRequestCount()
        XCTAssertEqual(
            activeBlockedRequests,
            1,
            "waiter cancellation must not release the shared transport"
        )
        let cancelledTransportRequests =
            await fixture.transport.cancelledRequestCount()
        XCTAssertEqual(
            cancelledTransportRequests,
            0,
            "cancelling a waiter must not propagate into the shared transport"
        )

        await fixture.transport.releaseAll()
        let bothWaitersCompleted = await completions.waitUntilCount(
            2,
            within: .seconds(2)
        )
        XCTAssertTrue(
            bothWaitersCompleted,
            "both waiters must settle after the shared transport is released"
        )
        guard case let .success(result) =
            await completions.outcome(at: 0) else {
            XCTFail("the surviving metadata waiter must succeed")
            return
        }
        XCTAssertEqual(
            result.metadata.clientID.absoluteString,
            "https://client.example/oauth/client-metadata.json"
        )
        XCTAssertEqual(result.metadata.clientName, "Admission test client")
        let requestCount = await fixture.transport.requestCount()
        XCTAssertEqual(
            requestCount,
            1,
            "the surviving waiter must reuse the exact-URL shared flight"
        )
    }

    func testExactURLSingleflightHasBoundedPromptWaiterAdmission()
        async throws
    {
        let fixture = try await OAuthRemoteFetchAdmissionFixture()
        addTeardownBlock {
            try? await fixture.database.close()
            fixture.cleanup()
        }
        let waiterCount = 96
        let callerBarrier = OAuthMetadataCallerBarrier(
            participantCount: waiterCount
        )
        let completions = OAuthMetadataLoadProbe()
        let tasks = (0 ..< waiterCount).map { index in
            Task {
                await callerBarrier.arriveAndWait()
                await completions.record(
                    await oauthMetadataLoadOutcome {
                        try await fixture.loader.load(
                            clientID: fixture.clientID,
                            now: self.now
                        )
                    },
                    at: index
                )
            }
        }
        defer {
            tasks.forEach { $0.cancel() }
            Task {
                await callerBarrier.release()
                await fixture.transport.releaseAll()
            }
        }

        let allCallersArrived = await oauthEventually(within: .seconds(1)) {
            await callerBarrier.arrivalCount() == waiterCount
        }
        XCTAssertTrue(allCallersArrived)
        await callerBarrier.release()
        let sharedRequestStarted = await oauthEventually(within: .seconds(1)) {
            await fixture.transport.requestCount() == 1
        }
        XCTAssertTrue(sharedRequestStarted)
        let excessRejectedPromptly = await oauthEventually(
            within: .seconds(1)
        ) {
            await completions.count() >= waiterCount - 64
        }
        XCTAssertTrue(
            excessRejectedPromptly,
            "same-URL callers beyond the bounded waiter set must not allocate unbounded observers"
        )
        let premature = await completions.allOutcomes()
        XCTAssertTrue(
            premature.allSatisfy(\.isUnavailable),
            "only typed admission failures may settle before transport release"
        )
        let blockedRequestCount = await fixture.transport.requestCount()
        XCTAssertEqual(blockedRequestCount, 1)

        await fixture.transport.releaseAll()
        let allSettled = await completions.waitUntilCount(
            waiterCount,
            within: .seconds(3)
        )
        XCTAssertTrue(allSettled)
        let outcomes = await completions.allOutcomes()
        XCTAssertLessThanOrEqual(outcomes.filter(\.isSuccess).count, 64)
        XCTAssertGreaterThanOrEqual(
            outcomes.filter(\.isUnavailable).count,
            waiterCount - 64
        )
        XCTAssertEqual(
            outcomes.filter(\.isSuccess).count
                + outcomes.filter(\.isUnavailable).count,
            waiterCount
        )
        let finalRequestCount = await fixture.transport.requestCount()
        XCTAssertEqual(finalRequestCount, 1)
    }

    func testDistinctMetadataCacheMissesAreGloballyBoundedAndExcessLoadsFailPromptly()
        async throws
    {
        let peer = try XCTUnwrap(
            OAuthIPAddress(literal: "93.184.216.34")
        )
        let transport = OAuthMetadataBarrierTransport(
            shouldBlock: { _ in true },
            responder: { url, _ in
                oauthPublicMetadataResponse(for: url, peer: peer)
            }
        )
        let fixture = try await OAuthRemoteFetchAdmissionFixture(
            transport: transport
        )
        addTeardownBlock {
            try? await fixture.database.close()
            fixture.cleanup()
        }
        let clientIDs = try (0 ..< 24).map { index in
            try XCTUnwrap(URL(
                string:
                    "https://metadata-\(index).example/oauth/client.json"
            ))
        }
        let callerBarrier = OAuthMetadataCallerBarrier(
            participantCount: clientIDs.count
        )
        let completions = OAuthMetadataLoadProbe()
        let tasks = clientIDs.enumerated().map { index, clientID in
            Task {
                await callerBarrier.arriveAndWait()
                await completions.record(
                    await oauthMetadataLoadOutcome {
                        try await fixture.loader.load(
                            clientID: clientID,
                            now: self.now
                        )
                    },
                    at: index
                )
            }
        }
        defer {
            tasks.forEach { $0.cancel() }
            Task {
                await callerBarrier.release()
                await transport.releaseAll()
            }
        }

        let allCallersArrived = await oauthEventually(within: .seconds(1)) {
            await callerBarrier.arrivalCount() == clientIDs.count
        }
        XCTAssertTrue(
            allCallersArrived,
            "all distinct metadata callers must reach the closed gate"
        )
        await callerBarrier.release()
        let ninthRequestWasAdmitted = await oauthEventually(
            within: .milliseconds(750)
        ) {
            await transport.blockedRequestCount() >= 9
        }
        XCTAssertFalse(
            ninthRequestWasAdmitted,
            "the process must admit at most eight distinct remote metadata flights"
        )
        let activeBlockedRequests =
            await transport.activeBlockedRequestCount()
        XCTAssertLessThanOrEqual(
            activeBlockedRequests,
            8,
            "distinct client IDs must share one bounded admission budget"
        )

        await transport.releaseAll()
        let allCallersSettled = await completions.waitUntilCount(
            clientIDs.count,
            within: .seconds(3)
        )
        XCTAssertTrue(
            allCallersSettled,
            "admitted and rejected metadata callers must all settle"
        )
        let outcomes = await completions.allOutcomes()
        let successes = outcomes.filter(\.isSuccess).count
        let unavailable = outcomes.filter(\.isUnavailable).count
        XCTAssertGreaterThanOrEqual(
            successes,
            1,
            "global admission must still make forward progress"
        )
        XCTAssertLessThanOrEqual(
            successes,
            8,
            "only the bounded admitted set may reach the remote transport"
        )
        XCTAssertGreaterThanOrEqual(
            unavailable,
            clientIDs.count - 8,
            "excess distinct metadata loads must fail closed instead of queueing without bound"
        )
        XCTAssertEqual(
            successes + unavailable,
            clientIDs.count,
            "global admission rejection must use the typed unavailable path"
        )
    }

    func testDistinctRemoteJWKSFetchesShareGlobalAdmissionBudgetAndExcessLoadsFailPromptly()
        async throws
    {
        let peer = try XCTUnwrap(
            OAuthIPAddress(literal: "93.184.216.34")
        )
        let keySet = try OAuthJSONWebKeySet(keys: [
            oauthTestJWK(keyID: "admission-key"),
        ])
        let encodedKeySet = try JSONEncoder().encode(keySet)
        let transport = OAuthMetadataBarrierTransport(
            shouldBlock: { url in
                url.path.hasSuffix("/jwks.json")
            },
            responder: { url, _ in
                if url.path.hasSuffix("/jwks.json") {
                    return oauthJSONResponse(
                        body: encodedKeySet,
                        url: url,
                        peer: peer
                    )
                }
                let jwksURL = url.deletingLastPathComponent()
                    .appending(path: "jwks.json")
                return oauthJSONResponse(
                    body: oauthRemoteJWKSMetadataBody(
                        clientID: url,
                        jwksURL: jwksURL
                    ),
                    url: url,
                    peer: peer
                )
            }
        )
        let fixture = try await OAuthRemoteFetchAdmissionFixture(
            transport: transport
        )
        addTeardownBlock {
            try? await fixture.database.close()
            fixture.cleanup()
        }
        let clientIDs = try (0 ..< 24).map { index in
            try XCTUnwrap(URL(
                string:
                    "https://jwks-\(index).example/oauth/client.json"
            ))
        }
        let callerBarrier = OAuthMetadataCallerBarrier(
            participantCount: clientIDs.count
        )
        let completions = OAuthMetadataLoadProbe()
        let tasks = clientIDs.enumerated().map { index, clientID in
            Task {
                await callerBarrier.arriveAndWait()
                await completions.record(
                    await oauthMetadataLoadOutcome {
                        try await fixture.loader.load(
                            clientID: clientID,
                            now: self.now
                        )
                    },
                    at: index
                )
            }
        }
        defer {
            tasks.forEach { $0.cancel() }
            Task {
                await callerBarrier.release()
                await transport.releaseAll()
            }
        }

        let allCallersArrived = await oauthEventually(within: .seconds(1)) {
            await callerBarrier.arrivalCount() == clientIDs.count
        }
        XCTAssertTrue(
            allCallersArrived,
            "all remote-JWKS callers must reach the closed gate"
        )
        await callerBarrier.release()
        let ninthJWKSRequestWasAdmitted = await oauthEventually(
            within: .milliseconds(750)
        ) {
            await transport.blockedRequestCount() >= 9
        }
        XCTAssertFalse(
            ninthJWKSRequestWasAdmitted,
            "remote JWKS requests must not bypass metadata admission"
        )
        let activeBlockedRequests =
            await transport.activeBlockedRequestCount()
        XCTAssertLessThanOrEqual(
            activeBlockedRequests,
            8,
            "metadata and remote JWKS must share one bounded remote-fetch budget"
        )

        await transport.releaseAll()
        let allCallersSettled = await completions.waitUntilCount(
            clientIDs.count,
            within: .seconds(3)
        )
        XCTAssertTrue(
            allCallersSettled,
            "admitted and rejected remote-JWKS callers must all settle"
        )
        let outcomes = await completions.allOutcomes()
        let successes = outcomes.filter(\.isSuccess).count
        let unavailable = outcomes.filter(\.isUnavailable).count
        XCTAssertGreaterThanOrEqual(successes, 1)
        XCTAssertLessThanOrEqual(
            successes,
            8,
            "only the bounded admitted set may complete its JWKS fetch"
        )
        XCTAssertGreaterThanOrEqual(
            unavailable,
            clientIDs.count - 8,
            "excess JWKS fetches must be rejected promptly"
        )
        XCTAssertEqual(successes + unavailable, clientIDs.count)
    }

    func testDelayedCacheMissCannotOverwriteNewerJWKSRevalidation()
        async throws
    {
        let peer = try XCTUnwrap(
            OAuthIPAddress(literal: "93.184.216.34")
        )
        let oldKeySet = try OAuthJSONWebKeySet(keys: [
            oauthTestJWK(keyID: "rotating-key"),
        ])
        let newKeySet = try OAuthJSONWebKeySet(keys: [
            oauthTestJWK(keyID: "rotating-key"),
        ])
        XCTAssertNotEqual(
            oldKeySet.keys[0].thumbprint(),
            newKeySet.keys[0].thumbprint()
        )
        let clientID = try XCTUnwrap(URL(
            string: "https://client.example/oauth/client-metadata.json"
        ))
        let oldBody = try oauthInlineJWKSMetadataBody(
            clientID: clientID,
            keySet: oldKeySet,
            clientName: "old metadata"
        )
        let newBody = try oauthInlineJWKSMetadataBody(
            clientID: clientID,
            keySet: newKeySet,
            clientName: "rotated metadata"
        )
        let transport = OAuthMetadataBarrierTransport(
            shouldBlock: { _ in true },
            responder: { url, ordinal in
                oauthJSONResponse(
                    body: ordinal == 1 ? oldBody : newBody,
                    url: url,
                    peer: peer
                )
            }
        )
        let fixture = try await OAuthRemoteFetchAdmissionFixture(
            transport: transport
        )
        addTeardownBlock {
            try? await fixture.database.close()
            fixture.cleanup()
        }
        let completions = OAuthMetadataLoadProbe()
        let staleLoad = Task {
            await completions.record(
                await oauthMetadataLoadOutcome {
                    try await fixture.loader.load(
                        clientID: clientID,
                        now: self.now
                    )
                },
                at: 0
            )
        }
        defer {
            staleLoad.cancel()
            Task { await transport.releaseAll() }
        }
        let staleRequestStarted = await oauthEventually(
            within: .seconds(1)
        ) {
            await transport.requestCount() == 1
        }
        XCTAssertTrue(
            staleRequestStarted,
            "the stale cache-miss request never reached the transport"
        )

        let revalidation = Task {
            await completions.record(
                await oauthMetadataLoadOutcome {
                    try await fixture.loader.revalidate(
                        clientID: clientID,
                        now: self.now.addingTimeInterval(1)
                    )
                },
                at: 1
            )
        }
        defer { revalidation.cancel() }
        let revalidationRequestStarted = await oauthEventually(
            within: .seconds(1)
        ) {
            await transport.requestCount() == 2
        }
        XCTAssertTrue(
            revalidationRequestStarted,
            "cache miss and revalidation must be independently observable flights"
        )
        let releasedRevalidation =
            await transport.releaseRequest(ordinal: 2)
        XCTAssertTrue(
            releasedRevalidation,
            "the newer revalidation request must be pending"
        )
        let revalidationCompleted = await completions.waitUntilIndex(
            1,
            within: .seconds(1)
        )
        XCTAssertTrue(
            revalidationCompleted,
            "the released revalidation must persist before the stale request"
        )
        guard case let .success(rotated) =
            await completions.outcome(at: 1) else {
            XCTFail("the newer JWKS revalidation must succeed")
            await transport.releaseAll()
            return
        }
        XCTAssertEqual(rotated.keySet, newKeySet)

        let releasedStaleRequest =
            await transport.releaseRequest(ordinal: 1)
        XCTAssertTrue(
            releasedStaleRequest,
            "the stale cache-miss request must remain pending"
        )
        let staleRequestCompleted = await completions.waitUntilIndex(
            0,
            within: .seconds(1)
        )
        XCTAssertTrue(
            staleRequestCompleted,
            "the stale cache-miss request must settle after release"
        )
        guard let staleOutcome = await completions.outcome(at: 0) else {
            return XCTFail("the older in-flight metadata read did not settle")
        }
        XCTAssertTrue(
            staleOutcome.isUnavailable,
            "a superseded metadata response must not authorize with stale JWKS: \(staleOutcome)"
        )

        let cached = try await fixture.loader.load(
            clientID: clientID,
            now: self.now.addingTimeInterval(2)
        )
        XCTAssertEqual(
            cached.keySet,
            newKeySet,
            "a delayed old cache miss must not roll durable JWKS state backward"
        )
        XCTAssertEqual(
            cached.metadata.clientName,
            "rotated metadata",
            "the JWKS generation and its validated metadata must advance atomically"
        )
        let requestCount = await transport.requestCount()
        XCTAssertEqual(
            requestCount,
            2,
            "the final read must come from the non-regressed durable cache"
        )
    }

    func testFailedExactURLFlightIsRemovedBeforeRetryAndSuccessfulRetryIsCached()
        async throws
    {
        let peer = try XCTUnwrap(
            OAuthIPAddress(literal: "93.184.216.34")
        )
        let transport = OAuthMetadataBarrierTransport(
            shouldBlock: { _ in false },
            responder: { url, ordinal in
                if ordinal == 1 {
                    throw SwanError.unavailable(
                        "scripted first metadata failure"
                    )
                }
                return oauthPublicMetadataResponse(
                    for: url,
                    peer: peer,
                    clientName: "retry succeeded"
                )
            }
        )
        let fixture = try await OAuthRemoteFetchAdmissionFixture(
            transport: transport
        )
        addTeardownBlock {
            try? await fixture.database.close()
            fixture.cleanup()
        }
        defer { Task { await transport.releaseAll() } }

        do {
            _ = try await fixture.loader.load(
                clientID: fixture.clientID,
                now: now
            )
            XCTFail("the scripted first metadata flight must fail")
        } catch let error as SwanError {
            guard case .unavailable = error else {
                XCTFail("the first flight must preserve unavailable, got \(error)")
                return
            }
        } catch {
            XCTFail("the first flight returned an unexpected error: \(error)")
        }
        let failedRequestCount = await transport.requestCount()
        XCTAssertEqual(failedRequestCount, 1)

        let retried = try await fixture.loader.load(
            clientID: fixture.clientID,
            now: now.addingTimeInterval(1)
        )
        XCTAssertEqual(retried.metadata.clientName, "retry succeeded")
        let retriedRequestCount = await transport.requestCount()
        XCTAssertEqual(
            retriedRequestCount,
            2,
            "retry must create a fresh transport flight after failure"
        )

        let cached = try await fixture.loader.load(
            clientID: fixture.clientID,
            now: now.addingTimeInterval(2)
        )
        XCTAssertEqual(cached, retried)
        let cachedRequestCount = await transport.requestCount()
        XCTAssertEqual(
            cachedRequestCount,
            2,
            "the successful retry, rather than the failed task, must occupy the cache"
        )
    }
}

private struct OAuthRemoteFetchAdmissionFixture: Sendable {
    let root: URL
    let database: SQLiteControlDatabase
    let loader: OAuthClientMetadataLoader
    let transport: OAuthMetadataBarrierTransport
    let clientID: URL

    init(
        transport suppliedTransport: OAuthMetadataBarrierTransport? = nil
    ) async throws {
        let fixtureRoot = FileManager.default.temporaryDirectory.appending(
            path: "SwanOAuthRemoteFetchAdmissionTests-\(UUID().uuidString)"
        )
        try FileManager.default.createDirectory(
            at: fixtureRoot,
            withIntermediateDirectories: true
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: fixtureRoot.path
        )

        guard let fixtureClientID = URL(
            string: "https://client.example/oauth/client-metadata.json"
        ), let peer = OAuthIPAddress(literal: "93.184.216.34") else {
            try? FileManager.default.removeItem(at: fixtureRoot)
            throw SwanError.malformed("OAuth admission test fixture is invalid")
        }
        let fixtureTransport = suppliedTransport ??
            OAuthMetadataBarrierTransport(
                shouldBlock: { _ in true },
                responder: { url, _ in
                    oauthPublicMetadataResponse(
                        for: url,
                        peer: peer,
                        clientName: "Admission test client"
                    )
                }
            )
        do {
            let fixtureDatabase = try await SQLiteControlDatabase(
                dataDirectory: fixtureRoot
            )
            let fixtureLoader = try OAuthClientMetadataLoader(
                fetcher: OAuthRemoteDocumentFetcher(
                    policy: try OAuthRemoteFetchPolicy(),
                    resolver: OAuthMetadataStaticResolver(peer: peer),
                    transport: fixtureTransport
                ),
                controlStore: fixtureDatabase,
                cacheLifetime: 60
            )
            root = fixtureRoot
            database = fixtureDatabase
            loader = fixtureLoader
            transport = fixtureTransport
            clientID = fixtureClientID
        } catch {
            try? FileManager.default.removeItem(at: fixtureRoot)
            throw error
        }
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }
}

private actor OAuthMetadataCallerBarrier {
    private var arrivals = 0
    private var isReleased = false
    private var waiters = [CheckedContinuation<Void, Never>]()

    init(participantCount: Int) {
        precondition(participantCount > 0)
    }

    func arriveAndWait() async {
        arrivals += 1
        if isReleased {
            return
        }
        await withCheckedContinuation { continuation in
            if isReleased {
                continuation.resume()
            } else {
                waiters.append(continuation)
            }
        }
    }

    func arrivalCount() -> Int {
        arrivals
    }

    func release() {
        guard !isReleased else { return }
        isReleased = true
        let arrived = waiters
        waiters.removeAll(keepingCapacity: false)
        for waiter in arrived {
            waiter.resume()
        }
    }
}

private struct OAuthMetadataStaticResolver: OAuthHostnameResolving {
    let peer: OAuthIPAddress

    func resolve(host _: String) async throws -> [OAuthIPAddress] {
        [peer]
    }
}

private actor OAuthMetadataBarrierTransport: OAuthRemoteTransport {
    private struct PendingRequest {
        let id: UUID
        let ordinal: Int
        let continuation: CheckedContinuation<Void, Error>
    }

    private let shouldBlock: @Sendable (URL) -> Bool
    private let responder:
        @Sendable (URL, Int) throws -> OAuthRemoteHTTPResponse
    private var requests = 0
    private var blockedRequests = 0
    private var activeBlockedRequests = 0
    private var cancelledRequests = 0
    private var isReleased = false
    private var pending = [PendingRequest]()

    init(
        shouldBlock: @escaping @Sendable (URL) -> Bool,
        responder: @escaping @Sendable (
            URL,
            Int
        ) throws -> OAuthRemoteHTTPResponse
    ) {
        self.shouldBlock = shouldBlock
        self.responder = responder
    }

    func get(
        url: URL,
        approvedPeers _: Set<OAuthIPAddress>,
        timeout _: TimeInterval,
        maximumBodyBytes _: Int
    ) async throws -> OAuthRemoteHTTPResponse {
        requests += 1
        let ordinal = requests
        if shouldBlock(url), !isReleased {
            blockedRequests += 1
            activeBlockedRequests += 1
            defer { activeBlockedRequests -= 1 }
            let id = UUID()
            try await withTaskCancellationHandler(
                operation: { [self] in
                    try await suspendRequest(
                        id: id,
                        ordinal: ordinal
                    )
                },
                onCancel: {
                    Task { await self.cancelRequest(id: id) }
                }
            )
        }
        return try responder(url, ordinal)
    }

    func releaseAll() {
        isReleased = true
        let requestsToRelease = pending
        pending.removeAll(keepingCapacity: false)
        for request in requestsToRelease {
            request.continuation.resume()
        }
    }

    func releaseRequest(ordinal: Int) -> Bool {
        guard let index = pending.firstIndex(where: {
            $0.ordinal == ordinal
        }) else {
            return false
        }
        let request = pending.remove(at: index)
        request.continuation.resume()
        return true
    }

    func requestCount() -> Int {
        requests
    }

    func blockedRequestCount() -> Int {
        blockedRequests
    }

    func activeBlockedRequestCount() -> Int {
        activeBlockedRequests
    }

    func cancelledRequestCount() -> Int {
        cancelledRequests
    }

    private func suspendRequest(
        id: UUID,
        ordinal: Int
    ) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            guard !Task.isCancelled else {
                continuation.resume(throwing: CancellationError())
                return
            }
            if isReleased {
                continuation.resume()
            } else {
                pending.append(PendingRequest(
                    id: id,
                    ordinal: ordinal,
                    continuation: continuation
                ))
            }
        }
    }

    private func cancelRequest(id: UUID) {
        guard let index = pending.firstIndex(where: { $0.id == id }) else {
            return
        }
        let request = pending.remove(at: index)
        cancelledRequests += 1
        request.continuation.resume(throwing: CancellationError())
    }
}

private enum OAuthMetadataLoadOutcome: Sendable, Equatable,
    CustomStringConvertible
{
    case success(OAuthResolvedClientMetadata)
    case cancellation
    case swanError(SwanError)
    case unexpectedError(String)

    var isSuccess: Bool {
        if case .success = self { return true }
        return false
    }

    var isUnavailable: Bool {
        if case let .swanError(error) = self,
           case .unavailable = error {
            return true
        }
        return false
    }

    var description: String {
        switch self {
        case let .success(metadata):
            "success(\(metadata.metadata.clientID.absoluteString))"
        case .cancellation:
            "cancellation"
        case let .swanError(error):
            "swanError(\(error))"
        case let .unexpectedError(error):
            "unexpectedError(\(error))"
        }
    }
}

private actor OAuthMetadataLoadProbe {
    private var outcomes = [Int: OAuthMetadataLoadOutcome]()

    func record(_ outcome: OAuthMetadataLoadOutcome, at index: Int) {
        outcomes[index] = outcome
    }

    func count() -> Int {
        outcomes.count
    }

    func outcome(at index: Int) -> OAuthMetadataLoadOutcome? {
        outcomes[index]
    }

    func allOutcomes() -> [OAuthMetadataLoadOutcome] {
        outcomes.keys.sorted().compactMap { outcomes[$0] }
    }

    func waitUntilCount(
        _ expected: Int,
        within timeout: Duration
    ) async -> Bool {
        await oauthEventually(within: timeout) {
            await self.count() >= expected
        }
    }

    func waitUntilIndex(
        _ index: Int,
        within timeout: Duration
    ) async -> Bool {
        await oauthEventually(within: timeout) {
            await self.outcome(at: index) != nil
        }
    }
}

private func oauthMetadataLoadOutcome(
    _ operation: @escaping @Sendable () async throws
        -> OAuthResolvedClientMetadata
) async -> OAuthMetadataLoadOutcome {
    do {
        return .success(try await operation())
    } catch is CancellationError {
        return .cancellation
    } catch let error as SwanError {
        return .swanError(error)
    } catch {
        return .unexpectedError(String(describing: error))
    }
}

private func oauthEventually(
    within timeout: Duration,
    pollEvery pollInterval: Duration = .milliseconds(2),
    _ predicate: @escaping @Sendable () async -> Bool
) async -> Bool {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: timeout)
    while clock.now < deadline {
        if await predicate() {
            return true
        }
        try? await Task.sleep(for: pollInterval)
    }
    return await predicate()
}

private func oauthPublicMetadataResponse(
    for clientID: URL,
    peer: OAuthIPAddress,
    clientName: String = "Admission test client"
) -> OAuthRemoteHTTPResponse {
    oauthJSONResponse(
        body: Data(
            """
            {
              "client_id": "\(clientID.absoluteString)",
              "application_type": "web",
              "redirect_uris": ["https://\(clientID.host ?? "client.example")/oauth/callback"],
              "grant_types": ["authorization_code", "refresh_token"],
              "response_types": ["code"],
              "scope": "atproto",
              "token_endpoint_auth_method": "none",
              "dpop_bound_access_tokens": true,
              "client_name": "\(clientName)"
            }
            """.utf8
        ),
        url: clientID,
        peer: peer
    )
}

private func oauthRemoteJWKSMetadataBody(
    clientID: URL,
    jwksURL: URL
) -> Data {
    Data(
        """
        {
          "client_id": "\(clientID.absoluteString)",
          "application_type": "web",
          "redirect_uris": ["https://\(clientID.host ?? "client.example")/oauth/callback"],
          "grant_types": ["authorization_code", "refresh_token"],
          "response_types": ["code"],
          "scope": "atproto",
          "token_endpoint_auth_method": "private_key_jwt",
          "token_endpoint_auth_signing_alg": "ES256",
          "dpop_bound_access_tokens": true,
          "jwks_uri": "\(jwksURL.absoluteString)"
        }
        """.utf8
    )
}

private func oauthInlineJWKSMetadataBody(
    clientID: URL,
    keySet: OAuthJSONWebKeySet,
    clientName: String
) throws -> Data {
    let encodedKeySet = try JSONEncoder().encode(keySet)
    let keySetJSON = String(decoding: encodedKeySet, as: UTF8.self)
    return Data(
        """
        {
          "client_id": "\(clientID.absoluteString)",
          "application_type": "web",
          "redirect_uris": ["https://\(clientID.host ?? "client.example")/oauth/callback"],
          "grant_types": ["authorization_code", "refresh_token"],
          "response_types": ["code"],
          "scope": "atproto",
          "token_endpoint_auth_method": "private_key_jwt",
          "token_endpoint_auth_signing_alg": "ES256",
          "dpop_bound_access_tokens": true,
          "jwks": \(keySetJSON),
          "client_name": "\(clientName)"
        }
        """.utf8
    )
}

private func oauthJSONResponse(
    body: Data,
    url: URL,
    peer: OAuthIPAddress
) -> OAuthRemoteHTTPResponse {
    OAuthRemoteHTTPResponse(
        status: 200,
        headers: ["content-type": ["application/json"]],
        body: body,
        responseURL: url,
        connectedPeerAddress: peer
    )
}

private func oauthTestJWK(keyID: String) throws -> OAuthJSONWebKey {
    let publicBytes = P256.Signing.PrivateKey()
        .publicKey.x963Representation
    return try OAuthJSONWebKey(
        x: Data(publicBytes.dropFirst().prefix(32))
            .base64URLEncodedString(),
        y: Data(publicBytes.dropFirst(33).prefix(32))
            .base64URLEncodedString(),
        keyID: keyID
    )
}
