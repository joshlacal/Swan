import Crypto
import Foundation
import PetrelCrypto
import PetrelPLC
@testable import SwanAccounts
@testable import SwanOAuth
import SwanCore
import SwanStorage
import XCTest

final class PLCSpaceCredentialSingleFlightTests: XCTestCase, @unchecked Sendable {
    private let issuer = "did:plc:abcdefghijklmnopqrstuvwx"
    private let signingKey = P256.Signing.PrivateKey()

    func testStaleGenerationCannotRemoveReplacementFlight() {
        var registry = PLCResolverFlightRegistry<Int>()
        let generationA = registry.install(1, for: issuer)

        XCTAssertEqual(
            registry.remove(for: issuer, ifOwnedBy: generationA),
            1
        )

        let generationB = registry.install(2, for: issuer)

        XCTAssertNil(
            registry.remove(for: issuer, ifOwnedBy: generationA),
            "a waiter for completed flight A must not remove replacement B"
        )
        XCTAssertEqual(registry.entry(for: issuer)?.generation, generationB)
        XCTAssertEqual(registry.entry(for: issuer)?.value, 2)
    }

    func testWithinDeadlineReturnsPromptlyWhenBodyIgnoresCancellation() async {
        let fixture = SingleFlightNonCooperativeBody()
        let safetyRelease = Task {
            await fixture.waitUntilEntered()
            try? await Task.sleep(for: .seconds(1))
            await fixture.release()
        }
        let clock = ContinuousClock()
        let startedAt = clock.now

        do {
            _ = try await withinDeadline(
                0.05,
                reportTimeout: false
            ) {
                await fixture.waitUntilReleased()
            }
            XCTFail("expected the controlled body to exceed its deadline")
        } catch SingleFlightTestTimeout.taskValue {
            // Expected: the deadline owns completion while the body remains
            // deliberately suspended and ignores cancellation.
        } catch {
            XCTFail("unexpected deadline error: \(error)")
        }

        let elapsed = startedAt.duration(to: clock.now)
        XCTAssertLessThan(
            elapsed,
            .milliseconds(200),
            "the helper must return without awaiting a noncooperative child"
        )

        await fixture.release()
        await fixture.waitUntilFinished()
        safetyRelease.cancel()
        _ = await safetyRelease.result
    }

    func testDeadlineRaceAcceptsExactlyOneCompletionBeforeWaiterInstallation() async {
        let race = SingleFlightDeadlineRace<Int>()
        let barrier = SingleFlightCompetitionBarrier(participants: 3)
        let body = Task {
            await barrier.arriveAndWait()
            return race.resolveBodyForTesting(.success(7))
        }
        let timer = Task {
            await barrier.arriveAndWait()
            return race.resolveTimeoutForTesting()
        }
        let cancellation = Task {
            await barrier.arriveAndWait()
            return race.resolveCancellationForTesting()
        }

        let bodyWon = await body.value
        let timerWon = await timer.value
        let cancellationWon = await cancellation.value
        XCTAssertEqual(
            [bodyWon, timerWon, cancellationWon].filter { $0 }.count,
            1,
            "body, timer, and caller cancellation must share one terminal slot"
        )
        XCTAssertEqual(race.completionCountForTesting(), 1)

        do {
            let value = try await race.value()
            XCTAssertTrue(bodyWon)
            XCTAssertEqual(value, 7)
        } catch SingleFlightDeadlineRaceError.timeout {
            XCTAssertTrue(timerWon)
        } catch is CancellationError {
            XCTAssertTrue(cancellationWon)
        } catch {
            XCTFail("unexpected race completion: \(error)")
        }
    }

    func testWithinDeadlineCallerCancellationReturnsPromptly() async {
        let fixture = SingleFlightNonCooperativeBody()
        let caller = Task {
            try await withinDeadline(
                10,
                reportTimeout: false
            ) {
                await fixture.waitUntilReleased()
            }
        }
        await fixture.waitUntilEntered()
        let clock = ContinuousClock()
        let cancelledAt = clock.now
        caller.cancel()

        do {
            _ = try await caller.value
            XCTFail("expected caller cancellation")
        } catch is CancellationError {
            // Expected: caller cancellation owns the terminal slot and does
            // not wait for the noncooperative body.
        } catch {
            XCTFail("unexpected caller-cancellation error: \(error)")
        }
        XCTAssertLessThan(
            cancelledAt.duration(to: clock.now),
            .milliseconds(200)
        )

        await fixture.release()
        await fixture.waitUntilFinished()
    }

    func testWithheldLookupReportsPhasesAndCleansUpAfterRelease() async throws {
        let lookupIndex = 1
        let recorder = SingleFlightPhaseRecorder()
        let checkpointStore = SingleFlightCheckpointStore(
            phaseRecorder: recorder
        )
        let plc = try controlledPLC(
            for: [issuer],
            phaseRecorder: recorder
        )
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: checkpointStore
        )
        let lookup = Task {
            await recorder.record(.lookupStarted(
                index: lookupIndex,
                issuer: self.issuer
            ))
            do {
                let key = try await resolver.publicKey(
                    for: self.issuer,
                    keyID: PermissionedDataJWT.spaceCredentialKeyID
                )
                await recorder.record(.lookupOutcomeReturned(
                    index: lookupIndex,
                    issuer: self.issuer,
                    succeeded: true
                ))
                return key
            } catch {
                await recorder.record(.lookupOutcomeReturned(
                    index: lookupIndex,
                    issuer: self.issuer,
                    succeeded: false
                ))
                throw error
            }
        }
        try await waitForFetchCount(lookupIndex, from: plc)

        let losingBodyFinished = SingleFlightOneShotSignal()
        let clock = ContinuousClock()
        let startedAt = clock.now
        do {
            _ = try await withinDeadline(
                0.05,
                reportTimeout: false
            ) {
                do {
                    let value = try await lookup.value
                    await losingBodyFinished.signal()
                    return value
                } catch {
                    await losingBodyFinished.signal()
                    throw error
                }
            }
            XCTFail("expected the controlled state fetch to remain withheld")
        } catch SingleFlightTestTimeout.taskValue {
            // Expected while the PLC fixture owns the release continuation.
        }
        XCTAssertLessThan(
            startedAt.duration(to: clock.now),
            .milliseconds(200)
        )

        let pending = try await singleFlightDiagnostic(
            lookupIndex: lookupIndex,
            issuer: issuer,
            plc: plc,
            checkpointStore: checkpointStore,
            recorder: recorder
        )
        XCTAssertEqual(pending.lookupIndex, lookupIndex)
        XCTAssertEqual(pending.issuer, issuer)
        XCTAssertEqual(pending.controlledFetchState, .pending)
        XCTAssertEqual(pending.checkpointState, .absent)
        XCTAssertEqual(pending.lookupOutcomeState, .pending)
        XCTAssertEqual(
            pending.processPermitStateInference,
            .heldInferredFromStateFetchBoundary
        )
        XCTAssertEqual(
            pending.lastPhase,
            .stateFetchEntered(index: lookupIndex, issuer: issuer)
        )

        await plc.releaseNext(with: .success)
        let key = try await withinDeadline { try await lookup.value }
        XCTAssertNotNil(key)
        await losingBodyFinished.wait()

        let completed = try await singleFlightDiagnostic(
            lookupIndex: lookupIndex,
            issuer: issuer,
            plc: plc,
            checkpointStore: checkpointStore,
            recorder: recorder
        )
        XCTAssertEqual(completed.controlledFetchState, .released)
        guard case .present = completed.checkpointState else {
            return XCTFail("expected a durable continuity checkpoint")
        }
        XCTAssertEqual(completed.lookupOutcomeState, .returned(success: true))
        XCTAssertEqual(
            completed.processPermitStateInference,
            .releasedInferredFromLookupOutcome
        )
        XCTAssertEqual(
            completed.lastPhase,
            .lookupOutcomeReturned(
                index: lookupIndex,
                issuer: issuer,
                succeeded: true
            )
        )
        XCTAssertEqual(
            completed.phases.map(\.kind),
            [
                .lookupStarted,
                .stateFetchEntered,
                .stateFetchReleased,
                .auditReturned,
                .continuityAdvanceEntered,
                .continuityAdvanceCompleted,
                .lookupOutcomeReturned,
            ]
        )
    }

    func testPositiveCacheLifetimeStartsWhenRefreshCompletes() async throws {
        let clock = ResolverMonotonicTestClock()
        let plc = try controlledPLC(for: [issuer])
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: SingleFlightCheckpointStore(),
            cacheConfiguration: .init(lifetime: 10),
            monotonicClock: clock.resolverClock
        )

        let first = Task {
            try await resolver.publicKey(
                for: self.issuer,
                keyID: PermissionedDataJWT.spaceCredentialKeyID
            )
        }
        try await waitForFetchCount(1, from: plc)
        clock.advance(seconds: 30)
        await plc.releaseNext(with: .success)
        let firstKey = try await withinDeadline { try await first.value }
        XCTAssertNotNil(firstKey)

        let immediatelyCached = try await resolver.publicKey(
            for: issuer,
            keyID: PermissionedDataJWT.spaceCredentialKeyID
        )
        XCTAssertNotNil(immediatelyCached)
        let immediateFetchCount = await plc.fetchCount()
        XCTAssertEqual(immediateFetchCount, 1)

        clock.advance(seconds: 9)
        let stillCached = try await resolver.publicKey(
            for: issuer,
            keyID: PermissionedDataJWT.spaceCredentialKeyID
        )
        XCTAssertNotNil(stillCached)
        let cachedFetchCount = await plc.fetchCount()
        XCTAssertEqual(cachedFetchCount, 1)

        clock.advance(seconds: 2)
        let refresh = Task {
            try await resolver.publicKey(
                for: self.issuer,
                keyID: PermissionedDataJWT.spaceCredentialKeyID
            )
        }
        try await waitForFetchCount(2, from: plc)
        await plc.releaseNext(with: .success)
        let refreshedKey = try await withinDeadline { try await refresh.value }
        XCTAssertNotNil(refreshedKey)
    }

    func testNegativeCacheLifetimeStartsWhenFailureCompletes() async throws {
        let clock = ResolverMonotonicTestClock()
        let plc = try controlledPLC(for: [issuer])
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: SingleFlightCheckpointStore(),
            cacheConfiguration: .init(negativeLifetime: 10),
            monotonicClock: clock.resolverClock
        )

        let first = Task {
            try await resolver.publicKey(
                for: self.issuer,
                keyID: PermissionedDataJWT.spaceCredentialKeyID
            )
        }
        try await waitForFetchCount(1, from: plc)
        clock.advance(seconds: 30)
        await plc.releaseNext(with: .failure)
        await XCTAssertThrowsSingleFlightError(try await withinDeadline { try await first.value })

        await XCTAssertThrowsSingleFlightError(try await resolver.publicKey(
            for: issuer,
            keyID: PermissionedDataJWT.spaceCredentialKeyID
        ))
        let immediateFetchCount = await plc.fetchCount()
        XCTAssertEqual(immediateFetchCount, 1)

        clock.advance(seconds: 9)
        await XCTAssertThrowsSingleFlightError(try await resolver.publicKey(
            for: issuer,
            keyID: PermissionedDataJWT.spaceCredentialKeyID
        ))
        let cachedFailureFetchCount = await plc.fetchCount()
        XCTAssertEqual(cachedFailureFetchCount, 1)

        clock.advance(seconds: 2)
        let retry = Task {
            try await resolver.publicKey(
                for: self.issuer,
                keyID: PermissionedDataJWT.spaceCredentialKeyID
            )
        }
        try await waitForFetchCount(2, from: plc)
        await plc.releaseNext(with: .success)
        let retriedKey = try await withinDeadline { try await retry.value }
        XCTAssertNotNil(retriedKey)
    }

    func testRefreshFailureNeverRevivesExpiredKeyMaterial() async throws {
        let clock = ResolverMonotonicTestClock()
        let plc = try controlledPLC(for: [issuer])
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: SingleFlightCheckpointStore(),
            cacheConfiguration: .init(
                lifetime: 1,
                negativeLifetime: 1
            ),
            monotonicClock: clock.resolverClock
        )

        let initial = Task {
            try await resolver.publicKey(
                for: self.issuer,
                keyID: PermissionedDataJWT.spaceCredentialKeyID
            )
        }
        try await waitForFetchCount(1, from: plc)
        await plc.releaseNext(with: .success)
        let initialKey = try await withinDeadline { try await initial.value }
        XCTAssertNotNil(initialKey)

        clock.advance(seconds: 2)
        let failedRefresh = Task {
            try await resolver.publicKey(
                for: self.issuer,
                keyID: PermissionedDataJWT.spaceCredentialKeyID
            )
        }
        try await waitForFetchCount(2, from: plc)
        await plc.releaseNext(with: .failure)
        await XCTAssertThrowsSingleFlightError(try await withinDeadline { try await failedRefresh.value })

        await XCTAssertThrowsSingleFlightError(try await resolver.publicKey(
            for: issuer,
            keyID: PermissionedDataJWT.spaceCredentialKeyID
        ))
        let failedFetchCount = await plc.fetchCount()
        XCTAssertEqual(
            failedFetchCount,
            2,
            "the failed refresh must neither serve nor retry stale key material"
        )
    }

    func testCancellingInitiatingWaiterDoesNotCancelSharedRefresh() async throws {
        let plc = try controlledPLC(for: [issuer])
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: SingleFlightCheckpointStore()
        )

        let initiatingWaiter = Task {
            try await resolver.publicKey(
                for: self.issuer,
                keyID: PermissionedDataJWT.spaceCredentialKeyID
            )
        }
        try await waitForFetchCount(1, from: plc)

        let survivingWaiter = Task {
            try await resolver.publicKey(
                for: self.issuer,
                keyID: PermissionedDataJWT.spaceCredentialKeyID
            )
        }
        await Task.yield()
        initiatingWaiter.cancel()
        await plc.releaseNext(with: .success)

        await XCTAssertThrowsSingleFlightError(try await withinDeadline { try await initiatingWaiter.value })
        let survivingKey = try await withinDeadline { try await survivingWaiter.value }
        XCTAssertNotNil(survivingKey)
        let fetchCount = await plc.fetchCount()
        let peakFetchCount = await plc.peakConcurrentFetchCount()
        XCTAssertEqual(fetchCount, 1)
        XCTAssertEqual(peakFetchCount, 1)
    }

    func testConfiguredPerResolverConcurrencyLimitRemainsEnforced() async throws {
        let issuers = Array(Self.validIssuers.prefix(4))
        let plc = try controlledPLC(for: issuers)
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: SingleFlightCheckpointStore(),
            cacheConfiguration: .init(maximumConcurrentLookups: 2)
        )

        let lookups = issuers.map { issuer in
            Task {
                do {
                    return try await resolver.publicKey(
                        for: issuer,
                        keyID: PermissionedDataJWT.spaceCredentialKeyID
                    ) != nil
                } catch {
                    return false
                }
            }
        }

        try await waitForFetchCount(2, from: plc)
        await plc.releaseNext(with: .success)
        await plc.releaseNext(with: .success)
        var successes = 0
        for lookup in lookups {
            let succeeded = try await withinDeadline { await lookup.value }
            if succeeded {
                successes += 1
            }
        }

        let fetchCount = await plc.fetchCount()
        let peakFetchCount = await plc.peakConcurrentFetchCount()
        XCTAssertEqual(successes, 2)
        XCTAssertEqual(fetchCount, 2)
        XCTAssertEqual(peakFetchCount, 2)
    }

    func testProcessWideConcurrencyNeverExceedsHardCeilingAcrossResolvers()
        async throws
    {
        let issuers = Self.validIssuers
        let phaseRecorder = SingleFlightPhaseRecorder()
        let checkpointStore = SingleFlightCheckpointStore(
            phaseRecorder: phaseRecorder
        )
        let outcomeRecorder = SingleFlightLookupOutcomeRecorder()
        let startBarrier = SingleFlightCompetitionBarrier(
            participants: issuers.count
        )
        let plc = try controlledPLC(
            for: issuers,
            phaseRecorder: phaseRecorder
        )
        let firstResolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: checkpointStore,
            cacheConfiguration: .init(maximumConcurrentLookups: 8)
        )
        let secondResolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: checkpointStore,
            cacheConfiguration: .init(maximumConcurrentLookups: 8)
        )

        let lookups = issuers.enumerated().map { index, issuer in
            let lookupIndex = index + 1
            let resolver = index.isMultiple(of: 2)
                ? firstResolver
                : secondResolver
            return Task {
                await phaseRecorder.record(.lookupStarted(
                    index: lookupIndex,
                    issuer: issuer
                ))
                await startBarrier.arriveAndWait()
                let succeeded: Bool
                do {
                    succeeded = try await resolver.publicKey(
                        for: issuer,
                        keyID: PermissionedDataJWT.spaceCredentialKeyID
                    ) != nil
                } catch {
                    succeeded = false
                }
                await phaseRecorder.record(.lookupOutcomeReturned(
                    index: lookupIndex,
                    issuer: issuer,
                    succeeded: succeeded
                ))
                await outcomeRecorder.record(
                    lookupIndex: lookupIndex,
                    succeeded: succeeded
                )
                return succeeded
            }
        }

        do {
            try await waitForFetchCount(8, from: plc)
            // Eight withheld fetches hold the process permits. Waiting for
            // the other two registered contenders to return before draining
            // removes scheduler timing from the expected hard-ceiling result.
            try await waitForLookupCompletionCount(
                2,
                from: outcomeRecorder
            )
            try await drainControlledFetches(
                plc: plc,
                untilCompletionCount: issuers.count,
                from: outcomeRecorder
            )
        } catch {
            let beforeCleanup = await singleFlightBatchDiagnostic(
                issuers: issuers,
                plc: plc,
                checkpointStore: checkpointStore,
                phaseRecorder: phaseRecorder,
                outcomeRecorder: outcomeRecorder
            )
            // This actor transition covers both already-pending continuations
            // and fetches that enter after the failure path starts.
            await plc.enableAutomaticRelease(with: .success)
            var acknowledged = [Bool]()
            for lookup in lookups {
                acknowledged.append(await lookup.value)
            }
            let afterCleanup = await singleFlightBatchDiagnostic(
                issuers: issuers,
                plc: plc,
                checkpointStore: checkpointStore,
                phaseRecorder: phaseRecorder,
                outcomeRecorder: outcomeRecorder
            )
            XCTFail(
                "process-wide fixture failed: \(error)\n" +
                    "before cleanup:\n\(beforeCleanup)\n" +
                    "after cleanup:\n\(afterCleanup)\n" +
                    "acknowledged outcomes=\(acknowledged)"
            )
            return
        }

        var acknowledged = [Bool]()
        for lookup in lookups {
            acknowledged.append(await lookup.value)
        }
        let successes = acknowledged.filter { $0 }.count

        let fetchCount = await plc.fetchCount()
        let peakFetchCount = await plc.peakConcurrentFetchCount()
        XCTAssertEqual(successes, 8)
        XCTAssertEqual(fetchCount, 8)
        XCTAssertEqual(peakFetchCount, 8)
    }

    func testControlledPLCDrainReleasesLateContenderAfterFirstRelease()
        async throws
    {
        let issuers = Array(Self.validIssuers.prefix(2))
        let plc = try controlledPLC(for: issuers)
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: SingleFlightCheckpointStore()
        )
        let lateStart = SingleFlightOneShotSignal()

        let first = Task {
            try await resolver.publicKey(
                for: issuers[0],
                keyID: PermissionedDataJWT.spaceCredentialKeyID
            )
        }
        let late = Task {
            await lateStart.wait()
            return try await resolver.publicKey(
                for: issuers[1],
                keyID: PermissionedDataJWT.spaceCredentialKeyID
            )
        }

        try await waitForFetchCount(1, from: plc)
        await plc.enableAutomaticRelease(with: .success)
        let firstKey = try await withinDeadline { try await first.value }
        XCTAssertNotNil(firstKey)

        await lateStart.signal()
        try await waitForFetchCount(2, from: plc)
        let losingBodyFinished = SingleFlightOneShotSignal()
        do {
            _ = try await withinDeadline(
                0.05,
                reportTimeout: false
            ) {
                do {
                    let key = try await late.value
                    await losingBodyFinished.signal()
                    return key
                } catch {
                    await losingBodyFinished.signal()
                    throw error
                }
            }
        } catch SingleFlightTestTimeout.taskValue {
            let fetchState = await plc.controlledFetchState(for: 2)
            await plc.releaseNext(with: .success)
            _ = try await late.value
            await losingBodyFinished.wait()
            XCTFail(
                "late contender remained \(fetchState) after the first release"
            )
            return
        }

        let finalFetchState = await plc.controlledFetchState(for: 2)
        let finalFetchCount = await plc.fetchCount()
        let finalPeakFetchCount = await plc.peakConcurrentFetchCount()
        let finalFixture = await plc.diagnosticDescription()
        XCTAssertEqual(finalFetchState, .released)
        XCTAssertEqual(finalFetchCount, 2)
        XCTAssertEqual(finalPeakFetchCount, 1)
        XCTAssertTrue(finalFixture.contains("pending=[]"), finalFixture)
        XCTAssertTrue(finalFixture.contains("automatic=true"), finalFixture)
    }

    private func controlledPLC(
        for issuers: [String],
        phaseRecorder: SingleFlightPhaseRecorder? = nil
    ) throws -> SingleFlightControlledPLC {
        let verificationKey = P256.Signing.PrivateKey().publicKey
        let method = P256DIDKey(publicKey: verificationKey).value
        var snapshots = [String: SingleFlightPLCSnapshot]()
        for issuer in issuers {
            snapshots[issuer] = try snapshot(
                issuer: issuer,
                methods: ["atproto_space": method]
            )
        }
        return SingleFlightControlledPLC(
            snapshots: snapshots,
            phaseRecorder: phaseRecorder
        )
    }

    private func snapshot(
        issuer: String,
        methods: [String: String]
    ) throws -> SingleFlightPLCSnapshot {
        let rotationKey = P256DIDKey(publicKey: signingKey.publicKey).value
        let unsigned = try PLCUnsignedRegularOperation(
            rotationKeys: [rotationKey],
            verificationMethods: methods,
            alsoKnownAs: [],
            services: [:],
            prev: nil
        )
        let operation = try PLCOperationCodec.sign(
            .regular(unsigned),
            using: signingKey
        )
        let entry = PLCAuditEntry(
            did: issuer,
            operation: operation,
            cid: try operation.cid.string,
            nullified: false,
            createdAt: "2026-07-30T00:00:00.000Z"
        )
        return SingleFlightPLCSnapshot(
            state: PLCDocumentData(
                did: issuer,
                rotationKeys: unsigned.rotationKeys,
                verificationMethods: methods,
                alsoKnownAs: unsigned.alsoKnownAs,
                services: unsigned.services
            ),
            audit: [entry]
        )
    }

    private static let validIssuers = [
        "did:plc:abcdefghijklmnopqrstuvw2",
        "did:plc:abcdefghijklmnopqrstuvw3",
        "did:plc:abcdefghijklmnopqrstuvw4",
        "did:plc:abcdefghijklmnopqrstuvw5",
        "did:plc:abcdefghijklmnopqrstuvw6",
        "did:plc:abcdefghijklmnopqrstuvw7",
        "did:plc:bcdefghijklmnopqrstuvwxy",
        "did:plc:cdefghijklmnopqrstuvwxyz",
        "did:plc:defghijklmnopqrstuvwxyza",
        "did:plc:efghijklmnopqrstuvwxyzab",
    ]
}

private final class ResolverMonotonicTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var nanoseconds: UInt64 = 0

    var resolverClock:
        PLCSpaceCredentialPublicKeyResolver.MonotonicClock
    {
        .init(nowNanoseconds: { [weak self] in
            guard let self else { return 0 }
            return self.now()
        })
    }

    func advance(seconds: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        nanoseconds += seconds * 1_000_000_000
    }

    private func now() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return nanoseconds
    }
}

private struct SingleFlightPLCSnapshot: Sendable {
    let state: PLCDocumentData
    let audit: [PLCAuditEntry]
}

private enum SingleFlightPhaseKind: Sendable, Equatable {
    case lookupStarted
    case stateFetchEntered
    case stateFetchReleased
    case auditReturned
    case continuityAdvanceEntered
    case continuityAdvanceCompleted
    case lookupOutcomeReturned
}

private enum SingleFlightPhase: Sendable, Equatable {
    case lookupStarted(index: Int, issuer: String)
    case stateFetchEntered(index: Int, issuer: String)
    case stateFetchReleased(index: Int, issuer: String)
    case auditReturned(index: Int, issuer: String)
    case continuityAdvanceEntered(index: Int, issuer: String)
    case continuityAdvanceCompleted(index: Int, issuer: String)
    case lookupOutcomeReturned(
        index: Int,
        issuer: String,
        succeeded: Bool
    )

    var kind: SingleFlightPhaseKind {
        switch self {
        case .lookupStarted: .lookupStarted
        case .stateFetchEntered: .stateFetchEntered
        case .stateFetchReleased: .stateFetchReleased
        case .auditReturned: .auditReturned
        case .continuityAdvanceEntered: .continuityAdvanceEntered
        case .continuityAdvanceCompleted: .continuityAdvanceCompleted
        case .lookupOutcomeReturned: .lookupOutcomeReturned
        }
    }

    var lookupIndex: Int {
        switch self {
        case let .lookupStarted(index, _),
             let .stateFetchEntered(index, _),
             let .stateFetchReleased(index, _),
             let .auditReturned(index, _),
             let .continuityAdvanceEntered(index, _),
             let .continuityAdvanceCompleted(index, _),
             let .lookupOutcomeReturned(index, _, _):
            index
        }
    }

    var issuer: String {
        switch self {
        case let .lookupStarted(_, issuer),
             let .stateFetchEntered(_, issuer),
             let .stateFetchReleased(_, issuer),
             let .auditReturned(_, issuer),
             let .continuityAdvanceEntered(_, issuer),
             let .continuityAdvanceCompleted(_, issuer),
             let .lookupOutcomeReturned(_, issuer, _):
            issuer
        }
    }
}

private actor SingleFlightPhaseRecorder {
    private var recordedPhases = [SingleFlightPhase]()

    func record(_ phase: SingleFlightPhase) {
        recordedPhases.append(phase)
    }

    func phases(
        for lookupIndex: Int,
        issuer: String
    ) -> [SingleFlightPhase] {
        recordedPhases.filter {
            $0.lookupIndex == lookupIndex && $0.issuer == issuer
        }
    }

    func phases(for issuer: String) -> [SingleFlightPhase] {
        recordedPhases.filter { $0.issuer == issuer }
    }

    func latestLookupIndex(for issuer: String) -> Int? {
        recordedPhases.reversed().first(where: {
            $0.issuer == issuer
        })?.lookupIndex
    }
}

private actor SingleFlightLookupOutcomeRecorder {
    private var outcomes = [Int: Bool]()

    func record(
        lookupIndex: Int,
        succeeded: Bool
    ) {
        precondition(outcomes[lookupIndex] == nil)
        outcomes[lookupIndex] = succeeded
    }

    func completionCount() -> Int { outcomes.count }

    func outcome(for lookupIndex: Int) -> SingleFlightLookupOutcomeState {
        outcomes[lookupIndex].map {
            .returned(success: $0)
        } ?? .pending
    }
}

private enum SingleFlightControlledFetchState: Sendable, Equatable {
    case notStarted
    case pending
    case released
}

private enum SingleFlightCheckpointState: Sendable, Equatable {
    case absent
    case present(terminalCID: String)
}

private enum SingleFlightLookupOutcomeState: Sendable, Equatable {
    case pending
    case returned(success: Bool)
}

private enum SingleFlightProcessPermitStateInference: Sendable, Equatable {
    case unknown
    case heldInferredFromStateFetchBoundary
    case releasedInferredFromLookupOutcome
}

private struct SingleFlightLookupDiagnostic: Sendable, Equatable {
    let lookupIndex: Int
    let issuer: String
    let controlledFetchState: SingleFlightControlledFetchState
    let checkpointState: SingleFlightCheckpointState
    let lookupOutcomeState: SingleFlightLookupOutcomeState
    let processPermitStateInference: SingleFlightProcessPermitStateInference
    let lastPhase: SingleFlightPhase?
    let phases: [SingleFlightPhase]
}

private actor SingleFlightControlledPLC: PLCClient {
    enum Outcome: Sendable, Equatable {
        case success
        case failure
    }

    private struct PendingFetch {
        let continuation: CheckedContinuation<Outcome, Never>
        let did: String
        let index: Int
    }

    private let snapshots: [String: SingleFlightPLCSnapshot]
    private let phaseRecorder: SingleFlightPhaseRecorder?
    private var pending = [PendingFetch]()
    private var releasedFetches = Set<Int>()
    private var fetchIssuers = [Int: String]()
    private var automaticOutcome: Outcome?
    private var fetches = 0
    private var activeFetches = 0
    private var peakActiveFetches = 0

    init(
        snapshots: [String: SingleFlightPLCSnapshot],
        phaseRecorder: SingleFlightPhaseRecorder? = nil
    ) {
        self.snapshots = snapshots
        self.phaseRecorder = phaseRecorder
    }

    func submit(did _: String, operation _: PLCSignedOperation) async throws {
        throw SwanError.unavailable("controlled PLC does not accept writes")
    }

    func fetchState(did: String) async throws -> PLCDocumentData {
        fetches += 1
        let lookupIndex = fetches
        fetchIssuers[lookupIndex] = did
        activeFetches += 1
        peakActiveFetches = max(peakActiveFetches, activeFetches)
        if let phaseRecorder {
            await phaseRecorder.record(.stateFetchEntered(
                index: lookupIndex,
                issuer: did
            ))
        }
        let outcome: Outcome
        if let automaticOutcome {
            releasedFetches.insert(lookupIndex)
            if let phaseRecorder {
                await phaseRecorder.record(.stateFetchReleased(
                    index: lookupIndex,
                    issuer: did
                ))
            }
            outcome = automaticOutcome
        } else {
            // Re-checking the actor-owned automatic outcome immediately
            // before continuation installation is what makes the transition
            // race-free: no await can interleave between this branch and the
            // synchronous continuation closure below.
            outcome = await withCheckedContinuation {
                (continuation: CheckedContinuation<Outcome, Never>) in
                pending.append(PendingFetch(
                    continuation: continuation,
                    did: did,
                    index: lookupIndex
                ))
            }
        }
        activeFetches -= 1
        guard outcome == .success,
              let snapshot = snapshots[did] else {
            throw SwanError.unavailable("controlled PLC fetch failed")
        }
        return snapshot.state
    }

    func fetchAudit(did: String) async throws -> [PLCAuditEntry] {
        guard let snapshot = snapshots[did] else {
            throw SwanError.unavailable("controlled PLC has no such DID")
        }
        if let phaseRecorder {
            await phaseRecorder.record(.auditReturned(
                index: fetches,
                issuer: did
            ))
        }
        return snapshot.audit
    }

    func fetchAuditIfPresent(did: String) async throws -> [PLCAuditEntry]? {
        snapshots[did]?.audit
    }

    @discardableResult
    func releaseNext(with outcome: Outcome) async -> Bool {
        guard !pending.isEmpty else { return false }
        let fetch = pending.removeFirst()
        releasedFetches.insert(fetch.index)
        if let phaseRecorder {
            await phaseRecorder.record(.stateFetchReleased(
                index: fetch.index,
                issuer: fetch.did
            ))
        }
        fetch.continuation.resume(returning: outcome)
        return true
    }

    func enableAutomaticRelease(with outcome: Outcome) async {
        automaticOutcome = outcome
        let currentFetches = pending
        pending.removeAll(keepingCapacity: true)
        for fetch in currentFetches {
            releasedFetches.insert(fetch.index)
            if let phaseRecorder {
                await phaseRecorder.record(.stateFetchReleased(
                    index: fetch.index,
                    issuer: fetch.did
                ))
            }
            fetch.continuation.resume(returning: outcome)
        }
    }

    func fetchCount() -> Int { fetches }
    func peakConcurrentFetchCount() -> Int { peakActiveFetches }

    func controlledFetchState(
        for lookupIndex: Int
    ) -> SingleFlightControlledFetchState {
        if releasedFetches.contains(lookupIndex) {
            return .released
        }
        if pending.contains(where: { $0.index == lookupIndex }) {
            return .pending
        }
        return .notStarted
    }

    func controlledFetchState(
        for issuer: String
    ) -> SingleFlightControlledFetchState {
        guard let lookupIndex = fetchIssuers.first(where: {
            $0.value == issuer
        })?.key else {
            return .notStarted
        }
        return controlledFetchState(for: lookupIndex)
    }

    func diagnosticDescription() -> String {
        let pendingDescription = pending.map {
            "\($0.index):\($0.did)"
        }.joined(separator: ",")
        let releasedDescription = releasedFetches.sorted().map(String.init)
            .joined(separator: ",")
        return "fetches=\(fetches) active=\(activeFetches) " +
            "peak=\(peakActiveFetches) pending=[\(pendingDescription)] " +
            "released=[\(releasedDescription)] " +
            "automatic=\(automaticOutcome != nil)"
    }
}

private actor SingleFlightCheckpointStore:
    PLCCredentialKeyContinuityStore
{
    private let phaseRecorder: SingleFlightPhaseRecorder?
    private var checkpoints =
        [String: PLCCredentialKeyContinuityCheckpoint]()

    init(phaseRecorder: SingleFlightPhaseRecorder? = nil) {
        self.phaseRecorder = phaseRecorder
    }

    func advancePLCCredentialKeyContinuity(
        _ advance: PLCCredentialKeyContinuityAdvance
    ) async throws -> PLCCredentialKeyContinuityCheckpoint {
        if let phaseRecorder {
            let lookupIndex = await phaseRecorder.latestLookupIndex(
                for: advance.checkpoint.issuer
            ) ?? 0
            await phaseRecorder.record(.continuityAdvanceEntered(
                index: lookupIndex,
                issuer: advance.checkpoint.issuer
            ))
        }
        if let current = checkpoints[advance.checkpoint.issuer],
           current.terminalCID != advance.checkpoint.terminalCID,
           !advance.auditCIDs.contains(current.terminalCID) {
            throw PLCCredentialKeyContinuityStoreError.continuityViolation
        }
        checkpoints[advance.checkpoint.issuer] = advance.checkpoint
        if let phaseRecorder {
            let lookupIndex = await phaseRecorder.latestLookupIndex(
                for: advance.checkpoint.issuer
            ) ?? 0
            await phaseRecorder.record(.continuityAdvanceCompleted(
                index: lookupIndex,
                issuer: advance.checkpoint.issuer
            ))
        }
        return advance.checkpoint
    }

    func plcCredentialKeyContinuityCheckpoint(
        for issuer: String
    ) async throws -> PLCCredentialKeyContinuityCheckpoint? {
        checkpoints[issuer]
    }
}

private actor SingleFlightOneShotSignal {
    private var didSignal = false
    private var waiters = [CheckedContinuation<Void, Never>]()

    func signal() {
        guard !didSignal else { return }
        didSignal = true
        let currentWaiters = waiters
        waiters.removeAll(keepingCapacity: true)
        for waiter in currentWaiters {
            waiter.resume()
        }
    }

    func wait() async {
        guard !didSignal else { return }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }
}

private func singleFlightDiagnostic(
    lookupIndex: Int,
    issuer: String,
    plc: SingleFlightControlledPLC,
    checkpointStore: SingleFlightCheckpointStore,
    recorder: SingleFlightPhaseRecorder
) async throws -> SingleFlightLookupDiagnostic {
    let phases = await recorder.phases(
        for: lookupIndex,
        issuer: issuer
    )
    let controlledFetchState = await plc.controlledFetchState(
        for: lookupIndex
    )
    let checkpoint = try await checkpointStore
        .plcCredentialKeyContinuityCheckpoint(for: issuer)
    let checkpointState: SingleFlightCheckpointState = checkpoint.map {
        .present(terminalCID: $0.terminalCID)
    } ?? .absent
    let lookupOutcomeState: SingleFlightLookupOutcomeState
    if let outcome = phases.reversed().first(where: {
        $0.kind == .lookupOutcomeReturned
    }), case let .lookupOutcomeReturned(_, _, succeeded) = outcome {
        lookupOutcomeState = .returned(success: succeeded)
    } else {
        lookupOutcomeState = .pending
    }

    // These are deliberately labelled as inferences. The production permit
    // is private and gets no test hook: reaching fetchState is only possible
    // after acquisition, while a returned resolver outcome occurs only after
    // the detached refresh has released its permit.
    let permitInference: SingleFlightProcessPermitStateInference
    if case .returned = lookupOutcomeState {
        permitInference = .releasedInferredFromLookupOutcome
    } else if phases.contains(where: { $0.kind == .stateFetchEntered }) {
        permitInference = .heldInferredFromStateFetchBoundary
    } else {
        permitInference = .unknown
    }

    return SingleFlightLookupDiagnostic(
        lookupIndex: lookupIndex,
        issuer: issuer,
        controlledFetchState: controlledFetchState,
        checkpointState: checkpointState,
        lookupOutcomeState: lookupOutcomeState,
        processPermitStateInference: permitInference,
        lastPhase: phases.last,
        phases: phases
    )
}

private actor SingleFlightNonCooperativeBody {
    private var didEnter = false
    private var didRelease = false
    private var didFinish = false
    private var entryWaiters = [CheckedContinuation<Void, Never>]()
    private var releaseContinuation: CheckedContinuation<Void, Never>?
    private var finishWaiters = [CheckedContinuation<Void, Never>]()

    func waitUntilReleased() async {
        didEnter = true
        let waiters = entryWaiters
        entryWaiters.removeAll(keepingCapacity: true)
        for waiter in waiters {
            waiter.resume()
        }

        if !didRelease {
            await withCheckedContinuation { continuation in
                releaseContinuation = continuation
            }
        }

        didFinish = true
        let finishingWaiters = finishWaiters
        finishWaiters.removeAll(keepingCapacity: true)
        for waiter in finishingWaiters {
            waiter.resume()
        }
    }

    func waitUntilEntered() async {
        guard !didEnter else { return }
        await withCheckedContinuation { continuation in
            entryWaiters.append(continuation)
        }
    }

    func release() {
        guard !didRelease else { return }
        didRelease = true
        let continuation = releaseContinuation
        releaseContinuation = nil
        continuation?.resume()
    }

    func waitUntilFinished() async {
        guard !didFinish else { return }
        await withCheckedContinuation { continuation in
            finishWaiters.append(continuation)
        }
    }
}

private actor SingleFlightCompetitionBarrier {
    private let participants: Int
    private var arrivals = 0
    private var waiters = [CheckedContinuation<Void, Never>]()

    init(participants: Int) {
        precondition(participants > 0)
        self.participants = participants
    }

    func arriveAndWait() async {
        arrivals += 1
        if arrivals == participants {
            let currentWaiters = waiters
            waiters.removeAll(keepingCapacity: true)
            for waiter in currentWaiters {
                waiter.resume()
            }
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }
}

private enum SingleFlightDeadlineRaceError: Error {
    case timeout
}

/// A test-owned deadline race whose terminal slot is independent of Swift's
/// structured task-group teardown. Cancellation is only a request, so a body
/// suspended on a continuation can ignore it indefinitely. The caller must
/// still receive the timeout while a controlled fixture remains responsible
/// for releasing and acknowledging the losing work.
private final class SingleFlightDeadlineRace<Value: Sendable>:
    @unchecked Sendable
{
    private enum Source: Equatable {
        case body
        case timer
        case callerCancellation
    }

    private enum Completion {
        case body(Result<Value, any Error>)
        case timeout
        case callerCancellation

        var source: Source {
            switch self {
            case .body: .body
            case .timeout: .timer
            case .callerCancellation: .callerCancellation
            }
        }
    }

    private let lock = NSLock()
    private var completion: Completion?
    private var continuation: CheckedContinuation<Completion, Never>?
    private var bodyTask: Task<Void, Never>?
    private var timerTask: Task<Void, Never>?
    private var acceptedCompletions = 0

    func start(
        seconds: Double,
        body: @escaping @Sendable () async throws -> Value
    ) {
        precondition(seconds > 0 && seconds.isFinite)

        let bodyTask = Task { [self] in
            do {
                _ = resolve(.body(.success(try await body())))
            } catch {
                _ = resolve(.body(.failure(error)))
            }
        }
        install(bodyTask, as: .body)

        let timerTask = Task { [self] in
            do {
                try await Task.sleep(
                    nanoseconds: UInt64(seconds * 1_000_000_000)
                )
            } catch {
                return
            }
            _ = resolve(.timeout)
        }
        install(timerTask, as: .timer)
    }

    func value() async throws -> Value {
        let terminal = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                install(continuation)
            }
        } onCancel: { [self] in
            _ = resolve(.callerCancellation)
        }

        switch terminal {
        case let .body(result):
            return try result.get()
        case .timeout:
            throw SingleFlightDeadlineRaceError.timeout
        case .callerCancellation:
            throw CancellationError()
        }
    }

    @discardableResult
    func resolveBodyForTesting(
        _ result: Result<Value, any Error>
    ) -> Bool {
        resolve(.body(result))
    }

    @discardableResult
    func resolveTimeoutForTesting() -> Bool {
        resolve(.timeout)
    }

    @discardableResult
    func resolveCancellationForTesting() -> Bool {
        resolve(.callerCancellation)
    }

    func completionCountForTesting() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return acceptedCompletions
    }

    private func install(
        _ task: Task<Void, Never>,
        as source: Source
    ) {
        let shouldCancel: Bool
        lock.lock()
        if let completion {
            shouldCancel = completion.source != source
        } else {
            switch source {
            case .body:
                precondition(bodyTask == nil)
                bodyTask = task
            case .timer:
                precondition(timerTask == nil)
                timerTask = task
            case .callerCancellation:
                preconditionFailure("caller cancellation has no task handle")
            }
            shouldCancel = false
        }
        lock.unlock()

        if shouldCancel {
            task.cancel()
        }
    }

    private func install(
        _ installedContinuation: CheckedContinuation<Completion, Never>
    ) {
        let terminal: Completion?
        lock.lock()
        if let completion {
            terminal = completion
        } else {
            precondition(continuation == nil)
            continuation = installedContinuation
            terminal = nil
        }
        lock.unlock()

        if let terminal {
            installedContinuation.resume(returning: terminal)
        }
    }

    @discardableResult
    private func resolve(_ proposed: Completion) -> Bool {
        let installedContinuation: CheckedContinuation<Completion, Never>?
        let tasksToCancel: [Task<Void, Never>]

        lock.lock()
        guard completion == nil else {
            lock.unlock()
            return false
        }
        completion = proposed
        acceptedCompletions += 1
        installedContinuation = continuation
        continuation = nil

        switch proposed.source {
        case .body:
            tasksToCancel = timerTask.map { [$0] } ?? []
        case .timer:
            tasksToCancel = bodyTask.map { [$0] } ?? []
        case .callerCancellation:
            tasksToCancel = [bodyTask, timerTask].compactMap { $0 }
        }
        bodyTask = nil
        timerTask = nil
        lock.unlock()

        for task in tasksToCancel {
            task.cancel()
        }
        installedContinuation?.resume(returning: proposed)
        return true
    }
}

private enum SingleFlightTestTimeout: Error {
    case fetchCount(Int)
    case lookupCompletionCount(expected: Int, actual: Int)
    case taskValue
}

private func waitForFetchCount(
    _ expected: Int,
    from plc: SingleFlightControlledPLC
) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while await plc.fetchCount() < expected {
        guard clock.now < deadline else {
            throw SingleFlightTestTimeout.fetchCount(expected)
        }
        await Task.yield()
    }
}

private func waitForLookupCompletionCount(
    _ expected: Int,
    from recorder: SingleFlightLookupOutcomeRecorder
) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while await recorder.completionCount() < expected {
        guard clock.now < deadline else {
            throw SingleFlightTestTimeout.lookupCompletionCount(
                expected: expected,
                actual: await recorder.completionCount()
            )
        }
        await Task.yield()
    }
}

private func drainControlledFetches(
    plc: SingleFlightControlledPLC,
    untilCompletionCount expected: Int,
    from recorder: SingleFlightLookupOutcomeRecorder
) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(2))
    while await recorder.completionCount() < expected {
        if await plc.releaseNext(with: .success) {
            continue
        }
        guard clock.now < deadline else {
            throw SingleFlightTestTimeout.lookupCompletionCount(
                expected: expected,
                actual: await recorder.completionCount()
            )
        }
        await Task.yield()
    }
}

private func singleFlightBatchDiagnostic(
    issuers: [String],
    plc: SingleFlightControlledPLC,
    checkpointStore: SingleFlightCheckpointStore,
    phaseRecorder: SingleFlightPhaseRecorder,
    outcomeRecorder: SingleFlightLookupOutcomeRecorder
) async -> String {
    var lines = [await plc.diagnosticDescription()]
    for (index, issuer) in issuers.enumerated() {
        let lookupIndex = index + 1
        let phases = await phaseRecorder.phases(for: issuer)
        let checkpoint = try? await checkpointStore
            .plcCredentialKeyContinuityCheckpoint(for: issuer)
        let checkpointDescription = checkpoint.map {
            "present(terminalCID: \($0.terminalCID))"
        } ?? "absent"
        let fetchState = await plc.controlledFetchState(for: issuer)
        let outcome = await outcomeRecorder.outcome(for: lookupIndex)
        lines.append(
            "lookup=\(lookupIndex) issuer=\(issuer) " +
                "fetch=\(fetchState) checkpoint=\(checkpointDescription) " +
                "outcome=\(outcome) lastPhase=\(String(describing: phases.last)) " +
                "phases=\(phases)"
        )
    }
    return lines.joined(separator: "\n")
}

private func XCTAssertThrowsSingleFlightError<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected an error", file: file, line: line)
    } catch {}
}

/// Awaits `body` with a deadline, failing rather than parking forever.
///
/// corelibs-xctest bridges an `async` test body through an expectation with no
/// timeout, so one release that never arrives suspends the whole suite instead
/// of failing it: two amd64 gate runs stalled for forty minutes each inside
/// this file, and neither reported which test was stuck — that had to be
/// recovered with lldb. Every task await here goes through this helper so the
/// same situation costs seconds and names itself.
///
/// The bound is deliberately loose. It is not a performance assertion; it is
/// the difference between a diagnosable failure and a hung gate.
private func withinDeadline<T: Sendable>(
    _ seconds: Double = 10,
    reportTimeout: Bool = true,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: @escaping @Sendable () async throws -> T
) async throws -> T {
    let race = SingleFlightDeadlineRace<T>()
    race.start(seconds: seconds, body: body)
    do {
        return try await race.value()
    } catch SingleFlightDeadlineRaceError.timeout {
        if reportTimeout {
            XCTFail(
                "timed out after \(seconds)s waiting for a task to finish",
                file: file,
                line: line
            )
        }
        throw SingleFlightTestTimeout.taskValue
    }
}
