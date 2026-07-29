import Foundation
import SQLiteNIO
import SwanCore
import SwanStorage
import XCTest

@testable import SwanSQLite

final class ControlSQLiteConnectionGateTests: XCTestCase, @unchecked Sendable {
    func testCapacityAndCancellationAreBoundedAndRecoverable() async throws {
        let gate = ControlSQLiteConnectionGate(maximumQueuedWaiters: 2)
        try await gate.acquire()

        let first = Task {
            try await gate.acquire()
            await gate.release()
        }
        let second = Task {
            try await gate.acquire()
            await gate.release()
        }
        try await waitForGate(gate) {
            $0.isHeld && $0.queuedWaiters == 2
        }

        await assertUnavailable(try await gate.acquire())

        first.cancel()
        second.cancel()
        await assertCancellation(first)
        await assertCancellation(second)
        try await waitForGate(gate) {
            $0.isHeld && $0.queuedWaiters == 0
        }

        await gate.release()
        let releasedSnapshot = await gate.admissionSnapshotForTesting()
        XCTAssertEqual(
            releasedSnapshot,
            .init(isHeld: false, queuedWaiters: 0)
        )
        try await gate.acquire()
        await gate.release()
    }

    func testCanceledWaiterRacingHandoffCannotLeakOwnership() async throws {
        let gate = ControlSQLiteConnectionGate(maximumQueuedWaiters: 1)
        try await gate.acquire()
        let waiter = Task {
            try await gate.acquire()
            await gate.release()
        }
        try await waitForGate(gate) {
            $0.isHeld && $0.queuedWaiters == 1
        }

        // `cancel()` sets the Task flag synchronously. The cancellation
        // handler's actor hop and this release may arrive in either order; in
        // both orders the canceled waiter must finish without retaining the
        // handed-off lease.
        waiter.cancel()
        await gate.release()
        await assertCancellation(waiter)
        try await waitForGate(gate) {
            !$0.isHeld && $0.queuedWaiters == 0
        }

        try await gate.acquire()
        await gate.release()
    }

    func testSuccessfulHandoffTransfersExactlyOneLease() async throws {
        let gate = ControlSQLiteConnectionGate(maximumQueuedWaiters: 1)
        let recorder = GateHandoffRecorder()
        try await gate.acquire()
        let waiter = Task {
            try await gate.acquire()
            await recorder.recordAcquisition()
            await gate.release()
        }
        try await waitForGate(gate) {
            $0.isHeld && $0.queuedWaiters == 1
        }

        await gate.release()
        try await waiter.value
        let acquisitions = await recorder.acquisitions
        let releasedSnapshot = await gate.admissionSnapshotForTesting()
        XCTAssertEqual(acquisitions, 1)
        XCTAssertEqual(
            releasedSnapshot,
            .init(isHeld: false, queuedWaiters: 0)
        )
    }

    private func waitForGate(
        _ gate: ControlSQLiteConnectionGate,
        predicate: (ControlSQLiteConnectionGate.AdmissionSnapshot) -> Bool
    ) async throws {
        for _ in 0 ..< 10_000 {
            if predicate(await gate.admissionSnapshotForTesting()) {
                return
            }
            await Task.yield()
        }
        throw OAuthControlHardeningTestError.conditionNotReached
    }

    private func assertCancellation(
        _ task: Task<Void, Error>,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            try await task.value
            XCTFail("expected cancellation", file: file, line: line)
        } catch is CancellationError {
            return
        } catch {
            XCTFail("expected CancellationError, got \(error)", file: file, line: line)
        }
    }
}

final class OAuthControlStorageHardeningTests: XCTestCase, @unchecked Sendable {
    private let now = Date(timeIntervalSince1970: 1_775_001_600)

    func testHardCapsRejectNewMetadataPARAndReplayRows() async throws {
        let fixture = try await makeFixture()
        addTeardownBlock { await fixture.close() }
        await fixture.database.configureOAuthControlStorageLimitsForTesting(
            .init(
                clientMetadata: 2,
                clientMetadataFreshness: 4,
                pushedAuthorizationRequests: 2,
                pushedAuthorizationStateReplays: 2,
                dpopReplays: 2,
                clientAssertionReplays: 2,
                spaceDelegationReplays: 2,
                spaceClientAttestationReplays: 2
            )
        )

        for index in 0 ..< 2 {
            try await fixture.database.cacheClientMetadata(
                metadata(index),
                now: now
            )
        }
        await assertUnavailable(
            try await fixture.database.cacheClientMetadata(
                metadata(2),
                now: now
            )
        )
        _ = try await fixture.database.beginClientMetadataFetch(
            clientID: metadataClientID(2),
            now: now
        )
        _ = try await fixture.database.beginClientMetadataFetch(
            clientID: metadataClientID(3),
            now: now
        )
        await assertUnavailable(
            try await fixture.database.beginClientMetadataFetch(
                clientID: metadataClientID(4),
                now: now
            )
        )

        for index in 0 ..< 2 {
            try await fixture.database.storePushedAuthorizationRequest(
                pushedRequest(index),
                now: now
            )
        }
        await assertUnavailable(
            try await fixture.database.storePushedAuthorizationRequest(
                pushedRequest(2),
                now: now
            )
        )
        _ = try await fixture.database.connection.query(
            "DELETE FROM oauth_control_par_requests"
        )
        await assertUnavailable(
            try await fixture.database.storePushedAuthorizationRequest(
                pushedRequest(2),
                now: now
            )
        )

        for index in 0 ..< 2 {
            let dpopClaimed = try await fixture.database.claimDPoPReplay(
                digest: digest(index),
                expiresAt: now.addingTimeInterval(300),
                now: now
            )
            let assertionClaimed =
                try await fixture.database.claimClientAssertion(
                digest: digest(index + 10),
                clientID: "https://client.example/\(index)",
                expiresAt: now.addingTimeInterval(300),
                now: now
            )
            let delegationClaimed =
                try await fixture.database.claimSpaceDelegation(
                digest: digest(index + 20),
                expiresAt: now.addingTimeInterval(300),
                now: now
            )
            let attestationClaimed =
                try await fixture.database.claimSpaceClientAttestation(
                digest: digest(index + 30),
                expiresAt: now.addingTimeInterval(300),
                now: now
            )
            XCTAssertTrue(dpopClaimed)
            XCTAssertTrue(assertionClaimed)
            XCTAssertTrue(delegationClaimed)
            XCTAssertTrue(attestationClaimed)
        }
        await assertUnavailable(try await fixture.database.claimDPoPReplay(
            digest: digest(2),
            expiresAt: now.addingTimeInterval(300),
            now: now
        ))
        await assertUnavailable(try await fixture.database.claimClientAssertion(
            digest: digest(12),
            clientID: "https://client.example/2",
            expiresAt: now.addingTimeInterval(300),
            now: now
        ))
        await assertUnavailable(try await fixture.database.claimSpaceDelegation(
            digest: digest(22),
            expiresAt: now.addingTimeInterval(300),
            now: now
        ))
        await assertUnavailable(
            try await fixture.database.claimSpaceClientAttestation(
                digest: digest(32),
                expiresAt: now.addingTimeInterval(300),
                now: now
            )
        )
    }

    func testHardCapsRejectLiveAuthorizationAndTokenRows() async throws {
        let fixture = try await makeFixture()
        addTeardownBlock { await fixture.close() }
        await fixture.database.configureOAuthControlStorageLimitsForTesting(
            .init(
                clientMetadata: 8,
                clientMetadataFreshness: 8,
                pushedAuthorizationRequests: 8,
                pushedAuthorizationStateReplays: 8,
                dpopReplays: 8,
                clientAssertionReplays: 8,
                spaceDelegationReplays: 8,
                spaceClientAttestationReplays: 8,
                authorizationCodes: 2,
                tokenFamilies: 8,
                accessTokens: 2,
                refreshTokens: 2
            )
        )

        for index in 0 ..< 2 {
            let family = tokenFamily(index)
            try await fixture.database.issueTokenPair(
                family: family,
                tokens: tokenPair(familyID: family.familyID, index: index),
                now: now
            )
        }
        let thirdFamily = tokenFamily(2)
        await assertUnavailable(
            try await fixture.database.issueTokenPair(
                family: thirdFamily,
                tokens: tokenPair(familyID: thirdFamily.familyID, index: 2),
                now: now
            )
        )

        for index in 0 ..< 2 {
            let family = tokenFamily(index + 10)
            try await fixture.database.storeAuthorizationCode(
                OAuthAuthorizationCode(
                    codeDigest: digest(index + 60),
                    familyID: family.familyID,
                    subject: family.subject,
                    binding: family.binding,
                    codeChallengeS256:
                        "E9Melhoa2OwvFrEMTJguCHaoeK1f7p_wW1gFWFOEjXk",
                    expiresAt: now.addingTimeInterval(300),
                    familyExpiresAt: family.expiresAt
                ),
                now: now
            )
        }
        let thirdCodeFamily = tokenFamily(12)
        await assertUnavailable(
            try await fixture.database.storeAuthorizationCode(
                OAuthAuthorizationCode(
                    codeDigest: digest(62),
                    familyID: thirdCodeFamily.familyID,
                    subject: thirdCodeFamily.subject,
                    binding: thirdCodeFamily.binding,
                    codeChallengeS256:
                        "E9Melhoa2OwvFrEMTJguCHaoeK1f7p_wW1gFWFOEjXk",
                    expiresAt: now.addingTimeInterval(300),
                    familyExpiresAt: thirdCodeFamily.expiresAt
                ),
                now: now
            )
        )
    }

    func testOnePurgePassDeletesAtMostOneIndexedBatch() async throws {
        let fixture = try await makeFixture()
        addTeardownBlock { await fixture.close() }
        _ = try await fixture.database.connection.query(
            """
            WITH RECURSIVE rows(value) AS (
                VALUES(1)
                UNION ALL
                SELECT value + 1 FROM rows WHERE value < 513
            )
            INSERT INTO oauth_control_dpop_replays(jti_digest, expires_at)
            SELECT CAST(printf('%032d', value) AS BLOB), 1 FROM rows
            """
        )

        try await fixture.database.purgeExpiredOAuthControlState(now: now)

        let rows = try await fixture.database.connection.query(
            "SELECT COUNT(*) AS row_count FROM oauth_control_dpop_replays"
        )
        XCTAssertEqual(rows.first?.column("row_count")?.integer, 1)
        let plan = try await fixture.database.connection.query(
            """
            EXPLAIN QUERY PLAN
            SELECT jti_digest
            FROM oauth_control_dpop_replays
            WHERE expires_at <= ?
            ORDER BY expires_at, jti_digest
            LIMIT ?
            """,
            [.integer(Int.max), .integer(512)]
        )
        let details = plan.compactMap {
            $0.column("detail")?.string?.uppercased()
        }
        XCTAssertTrue(details.contains {
            $0.contains("OAUTH_CONTROL_DPOP_REPLAY_CLEANUP")
        }, "expiry cleanup must use its bounded composite index: \(details)")
        XCTAssertFalse(details.contains { $0.contains("USE TEMP B-TREE") })
    }

    func testFreshnessCleanupCannotCreateGenerationABA() async throws {
        let fixture = try await makeFixture()
        addTeardownBlock { await fixture.close() }
        let clientID = "https://client.example/aba"
        let staleTicket = try await fixture.database.beginClientMetadataFetch(
            clientID: clientID,
            now: now
        )
        _ = try await fixture.database.connection.query(
            """
            UPDATE oauth_control_client_metadata_freshness
            SET retain_until = 0
            WHERE client_id = ?
            """,
            [.text(clientID)]
        )
        try await fixture.database.purgeExpiredOAuthControlState(
            now: now.addingTimeInterval(3_601)
        )
        let removed = try await fixture.database.connection.query(
            """
            SELECT 1 FROM oauth_control_client_metadata_freshness
            WHERE client_id = ?
            """,
            [.text(clientID)]
        )
        XCTAssertTrue(removed.isEmpty)

        let currentTicket = try await fixture.database.beginClientMetadataFetch(
            clientID: clientID,
            now: now.addingTimeInterval(3_602)
        )
        XCTAssertGreaterThan(currentTicket.generation, staleTicket.generation)
        let stalePublished = try await fixture.database.publishClientMetadata(
            .init(
                clientID: clientID,
                document: Data("stale".utf8),
                expiresAt: now.addingTimeInterval(7_200)
            ),
            using: staleTicket,
            now: now.addingTimeInterval(3_603)
        )
        XCTAssertFalse(stalePublished)
        let currentPublished = try await fixture.database.publishClientMetadata(
            .init(
                clientID: clientID,
                document: Data("current".utf8),
                expiresAt: now.addingTimeInterval(7_200)
            ),
            using: currentTicket,
            now: now.addingTimeInterval(3_603)
        )
        XCTAssertTrue(currentPublished)
    }

    private func metadata(_ index: Int) -> OAuthCachedClientMetadata {
        .init(
            clientID: metadataClientID(index),
            document: Data("{\"client\":\(index)}".utf8),
            expiresAt: now.addingTimeInterval(300)
        )
    }

    private func metadataClientID(_ index: Int) -> String {
        "https://metadata\(index).client.example/document"
    }

    private func pushedRequest(
        _ index: Int
    ) -> OAuthPushedAuthorizationRequest {
        .init(
            requestDigest: digest(index + 40),
            binding: .init(
                issuer: "https://swan.example",
                clientID: "https://client.example/metadata",
                redirectURI: "https://client.example/callback",
                scopes: ["atproto"],
                dpopJKT: String(repeating: "K", count: 43)
            ),
            state: "state-\(index)",
            stateDigest: digest(index + 50),
            codeChallengeS256:
                "E9Melhoa2OwvFrEMTJguCHaoeK1f7p_wW1gFWFOEjXk",
            expiresAt: now.addingTimeInterval(300)
        )
    }

    private func tokenFamily(_ index: Int) -> OAuthTokenFamily {
        OAuthTokenFamily(
            familyID: UUID(uuidString: String(format: "00000000-0000-4000-8000-%012d", index))!,
            subject: "did:plc:alice",
            binding: .init(
                issuer: "https://swan.example",
                clientID: "https://client.example/(index)",
                redirectURI: "https://client.example/callback",
                scopes: ["atproto"],
                dpopJKT: String(repeating: "D", count: 43)
            ),
            expiresAt: now.addingTimeInterval(600)
        )
    }

    private func tokenPair(familyID: UUID, index: Int) -> OAuthIssuedTokenDigests {
        OAuthIssuedTokenDigests(
            familyID: familyID,
            accessTokenDigest: digest(index + 100),
            refreshTokenDigest: digest(index + 200),
            accessExpiresAt: now.addingTimeInterval(300),
            refreshExpiresAt: now.addingTimeInterval(600)
        )
    }

    private func digest(_ value: Int) -> Data {
        var bytes = Data(repeating: 0, count: 32)
        bytes[28] = UInt8((value >> 24) & 0xff)
        bytes[29] = UInt8((value >> 16) & 0xff)
        bytes[30] = UInt8((value >> 8) & 0xff)
        bytes[31] = UInt8(value & 0xff)
        return bytes
    }

    private func makeFixture() async throws -> OAuthControlHardeningFixture {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "SwanOAuthControlHardening-\(UUID().uuidString)"
        )
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        return OAuthControlHardeningFixture(
            root: root,
            database: database
        )
    }
}

private actor GateHandoffRecorder {
    private(set) var acquisitions = 0

    func recordAcquisition() {
        acquisitions += 1
    }
}

private struct OAuthControlHardeningFixture: Sendable {
    let root: URL
    let database: SQLiteControlDatabase

    func close() async {
        try? await database.close()
        try? FileManager.default.removeItem(at: root)
    }
}

private enum OAuthControlHardeningTestError: Error {
    case conditionNotReached
}

private func assertUnavailable<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected typed unavailable", file: file, line: line)
    } catch let error as SwanError {
        guard case .unavailable = error else {
            return XCTFail(
                "expected unavailable, got \(error)",
                file: file,
                line: line
            )
        }
    } catch {
        XCTFail("expected SwanError.unavailable, got \(error)", file: file, line: line)
    }
}
