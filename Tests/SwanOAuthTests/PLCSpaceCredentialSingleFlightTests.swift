import Crypto
import Foundation
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
        let firstKey = try await first.value
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
        let refreshedKey = try await refresh.value
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
        await XCTAssertThrowsSingleFlightError(try await first.value)

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
        let retriedKey = try await retry.value
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
        let initialKey = try await initial.value
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
        await XCTAssertThrowsSingleFlightError(try await failedRefresh.value)

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

        await XCTAssertThrowsSingleFlightError(try await initiatingWaiter.value)
        let survivingKey = try await survivingWaiter.value
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
        await plc.releaseAll(with: .success)
        var successes = 0
        for lookup in lookups {
            if await lookup.value {
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
        let plc = try controlledPLC(for: issuers)
        let firstResolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: SingleFlightCheckpointStore(),
            cacheConfiguration: .init(maximumConcurrentLookups: 8)
        )
        let secondResolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: SingleFlightCheckpointStore(),
            cacheConfiguration: .init(maximumConcurrentLookups: 8)
        )

        let lookups = issuers.enumerated().map { index, issuer in
            let resolver = index.isMultiple(of: 2)
                ? firstResolver
                : secondResolver
            return Task {
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

        try await waitForFetchCount(8, from: plc)
        await plc.releaseAll(with: .success)
        var successes = 0
        for lookup in lookups {
            if await lookup.value {
                successes += 1
            }
        }

        let fetchCount = await plc.fetchCount()
        let peakFetchCount = await plc.peakConcurrentFetchCount()
        XCTAssertEqual(successes, 8)
        XCTAssertEqual(fetchCount, 8)
        XCTAssertEqual(peakFetchCount, 8)
    }

    private func controlledPLC(
        for issuers: [String]
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
        return SingleFlightControlledPLC(snapshots: snapshots)
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

private actor SingleFlightControlledPLC: PLCClient {
    enum Outcome: Sendable, Equatable {
        case success
        case failure
    }

    private struct PendingFetch {
        let continuation: CheckedContinuation<Outcome, Never>
        let did: String
    }

    private let snapshots: [String: SingleFlightPLCSnapshot]
    private var pending = [PendingFetch]()
    private var fetches = 0
    private var activeFetches = 0
    private var peakActiveFetches = 0

    init(snapshots: [String: SingleFlightPLCSnapshot]) {
        self.snapshots = snapshots
    }

    func submit(did _: String, operation _: PLCSignedOperation) async throws {
        throw SwanError.unavailable("controlled PLC does not accept writes")
    }

    func fetchState(did: String) async throws -> PLCDocumentData {
        fetches += 1
        activeFetches += 1
        peakActiveFetches = max(peakActiveFetches, activeFetches)
        let outcome = await withCheckedContinuation {
            (continuation: CheckedContinuation<Outcome, Never>) in
            pending.append(PendingFetch(
                continuation: continuation,
                did: did
            ))
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
        return snapshot.audit
    }

    func fetchAuditIfPresent(did: String) async throws -> [PLCAuditEntry]? {
        snapshots[did]?.audit
    }

    func releaseNext(with outcome: Outcome) {
        guard !pending.isEmpty else { return }
        let fetch = pending.removeFirst()
        fetch.continuation.resume(returning: outcome)
    }

    func releaseAll(with outcome: Outcome) {
        let fetches = pending
        pending.removeAll(keepingCapacity: true)
        for fetch in fetches {
            fetch.continuation.resume(returning: outcome)
        }
    }

    func fetchCount() -> Int { fetches }
    func peakConcurrentFetchCount() -> Int { peakActiveFetches }
}

private actor SingleFlightCheckpointStore:
    PLCCredentialKeyContinuityStore
{
    private var checkpoints =
        [String: PLCCredentialKeyContinuityCheckpoint]()

    func advancePLCCredentialKeyContinuity(
        _ advance: PLCCredentialKeyContinuityAdvance
    ) async throws -> PLCCredentialKeyContinuityCheckpoint {
        if let current = checkpoints[advance.checkpoint.issuer],
           current.terminalCID != advance.checkpoint.terminalCID,
           !advance.auditCIDs.contains(current.terminalCID) {
            throw PLCCredentialKeyContinuityStoreError.continuityViolation
        }
        checkpoints[advance.checkpoint.issuer] = advance.checkpoint
        return advance.checkpoint
    }

    func plcCredentialKeyContinuityCheckpoint(
        for issuer: String
    ) async throws -> PLCCredentialKeyContinuityCheckpoint? {
        checkpoints[issuer]
    }
}

private enum SingleFlightTestTimeout: Error {
    case fetchCount(Int)
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
