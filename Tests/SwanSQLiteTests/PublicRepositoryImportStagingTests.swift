import Crypto
import Foundation
import Petrel
import SQLiteNIO
import SwanPublicRepository
import SwanStorage
@testable import SwanSQLite
import XCTest
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

final class PublicRepositoryImportStagingTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let genesisRevision = "3jzfcijpj2z2a"

    func testPinnedTypeScriptMultiLayerShuffledDuplicateExtraPublishesExactProjection() async throws {
        let fixtureURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent(
                "fixtures/permissioned-data-0016-2026-07-03/public-repository-nonempty-car.json"
            )
        let object = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL))
                as? [String: Any]
        )
        let fixtureDID = try XCTUnwrap(object["did"] as? String)
        let multi = try XCTUnwrap(object["multiLayer"] as? [String: Any])
        let car = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(multi["carBase64"] as? String)))
        let rootCID = try CID.parse(try XCTUnwrap(multi["commitCID"] as? String))
        let records = try XCTUnwrap(multi["records"] as? [[String: String]])
        let key = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 1, count: 32)
        )

        let parsedSink = CollectingFrameSink()
        _ = try await PublicRepositoryCAR.parseIncrementally(
            from: InstrumentedCARSource(data: car, chunkBytes: 113),
            to: parsedSink
        )
        var frames = await parsedSink.blocks
        frames.reverse()
        frames.append(frames[0])
        let extra = try DAGCBOR.encodeValue(Data(repeating: 0x5a, count: 128 * 1_024))
        let extraCID = CID.fromDAGCBOR(extra)
        frames.insert(.init(cid: extraCID, bytes: extra), at: 2)
        let shuffled = try await encodeCAR(root: rootCID, frames: frames)

        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: fixtureDID)
        do {
        let genesis = try PublicRepositoryGenesisCodec.create(
            did: fixtureDID, revision: "3jzfcijpj2z22", signingKey: key
        )
        _ = try await database.installPublicRepositoryGenesis(
            genesis, signingPublicKey: key.publicKey,
            installedAt: Date(timeIntervalSince1970: 1)
        )
        let binding = try PublicRepositoryImportBinding(
            requestID: "pinned-typescript-multilayer",
            requestDigest: Data(repeating: 0x71, count: 32),
            accountDID: fixtureDID,
            expectedBaseCommitCID: genesis.commitCID,
            verifierIdentity: P256PublicRepositoryCommitVerifier(
                publicKey: key.publicKey
            ).verificationIdentity,
            policy: .init(limits: .standard)
        )
        let result = try await testCoordinator(database)
            .importRepository(
                from: InstrumentedCARSource(data: shuffled, chunkBytes: 4_111),
                binding: binding,
                verifier: P256PublicRepositoryCommitVerifier(publicKey: key.publicKey),
                createdAt: 100, expiresAt: 200
            )
        XCTAssertEqual(result.state.commitCID, rootCID)
        XCTAssertEqual(result.recordCount, 8)
        let storedExtra = try await database.block(for: extraCID)
        XCTAssertNil(storedExtra)
        for record in records {
            let path = try PublicRepositoryPath(
                collection: try XCTUnwrap(record["collection"]),
                recordKey: try XCTUnwrap(record["rkey"])
            )
            let cid = try await database.publicRepositoryRecordCID(for: path)
            XCTAssertNotNil(cid)
        }
        try await database.verifyPublicRepositoryProjection()
        try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testShuffledDuplicateExtraCARPublishesReachableTruthAndReplaysResult() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let extraBytes = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "$type", value: "app.bsky.feed.post"),
            (key: "text", value: "unlinked private extra"),
        ]))
        let extraCID = CID.fromDAGCBOR(extraBytes)
        var frames = try await fixture.blocks()
        frames.reverse()
        frames.append(frames[0])
        frames.insert(.init(cid: extraCID, bytes: extraBytes), at: 1)
        let car = try await encodeCAR(root: fixture.prepared.state.commitCID, frames: frames)
        let source = InstrumentedCARSource(data: car, chunkBytes: 4_097)
        let binding = try binding(
            requestID: "import-success",
            baseCID: fixture.initial.commitCID
        )
        let coordinator = testCoordinator(fixture.database)
        let result = try await coordinator.importRepository(
            from: source,
            binding: binding,
            verifier: P256PublicRepositoryCommitVerifier(publicKey: fixture.key.publicKey),
            createdAt: 100,
            expiresAt: 200
        )

        XCTAssertEqual(result.state, fixture.prepared.state)
        let storedState = try await fixture.database.loadPublicRepositoryState()
        XCTAssertEqual(storedState, fixture.prepared.state)
        let storedRecord = try await fixture.database.publicRepositoryRecordCID(for: fixture.path)
        XCTAssertEqual(
            storedRecord,
            fixture.prepared.recordResults[0].recordCID
        )
        let extraBlock = try await fixture.database.block(for: extraCID)
        XCTAssertNil(extraBlock)
        let maximumReturnedBytes = await source.maximumReturnedBytes
        XCTAssertLessThanOrEqual(maximumReturnedBytes, 4_097)
        let replay = try await coordinator.importRepository(
            from: InstrumentedCARSource(data: Data(), chunkBytes: 1),
            binding: binding,
            verifier: P256PublicRepositoryCommitVerifier(publicKey: fixture.key.publicKey),
            createdAt: 101,
            expiresAt: 201
        )
        XCTAssertEqual(replay, result)

        let raw = try await openRaw(fixture.root)
        let childCounts = try await raw.query(
            """
            SELECT
              (SELECT COUNT(*) FROM public_repository_import_blocks) AS blocks,
              (SELECT COUNT(*) FROM public_repository_import_reachable) AS reachable,
              (SELECT COUNT(*) FROM public_repository_import_record_index) AS records
            """
        )
        XCTAssertEqual(childCounts.first?.column("blocks")?.integer, 0)
        XCTAssertEqual(childCounts.first?.column("reachable")?.integer, 0)
        XCTAssertEqual(childCounts.first?.column("records")?.integer, 0)
        try await raw.close()
        try await fixture.database.close()
    }

    func testSameRequestCannotAcquireTwoReceivingAttemptsAndExpiryRecovers() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let binding = try binding(requestID: "same-request", baseCID: fixture.initial.commitCID)

        let outcomes = await withTaskGroup(of: Result<PublicRepositoryImportStartOutcome, Error>.self) {
            group in
            for _ in 0 ..< 2 {
                group.addTask {
                    do {
                        return .success(try await fixture.database.createPublicRepositoryImportSession(
                            binding: binding, createdAt: 10, expiresAt: 20, now: 10
                        ))
                    } catch {
                        return .failure(error)
                    }
                }
            }
            var values: [Result<PublicRepositoryImportStartOutcome, Error>] = []
            for await value in group { values.append(value) }
            return values
        }
        XCTAssertEqual(outcomes.filter {
            if case .success(.staged) = $0 { return true }
            return false
        }.count, 1)
        XCTAssertEqual(outcomes.filter {
            guard case let .failure(error) = $0 else { return false }
            return error as? PublicRepositoryImportStagingError == .importInProgress
        }.count, 1)
        try await fixture.database.close()
        let reopened = try await SQLiteAccountDatabase(dataDirectory: fixture.root, did: did)
        let expired = try await reopened
            .recoverExpiredPublicRepositoryImportSessions(now: 21)
        XCTAssertEqual(expired, 0, "startup recovery should remove the expired attempt")
        if case .staged = try await reopened.createPublicRepositoryImportSession(
            binding: binding, createdAt: 22, expiresAt: 30, now: 22
        ) {} else {
            XCTFail("expired attempt was not recoverable")
        }
        try await reopened.close()
    }

    func testInvalidSignaturePublishesNothingAndCleansStaging() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let car = try await encodeCAR(
            root: fixture.prepared.state.commitCID,
            frames: try await fixture.blocks()
        )
        let wrongKey = P256.Signing.PrivateKey()
        let coordinator = testCoordinator(fixture.database)

        do {
            _ = try await coordinator.importRepository(
                from: InstrumentedCARSource(data: car, chunkBytes: 17),
                binding: try binding(
                    requestID: "bad-signature", baseCID: fixture.initial.commitCID,
                    verifierIdentity: P256PublicRepositoryCommitVerifier(
                        publicKey: wrongKey.publicKey
                    ).verificationIdentity
                ),
                verifier: P256PublicRepositoryCommitVerifier(publicKey: wrongKey.publicKey),
                createdAt: 100,
                expiresAt: 200
            )
            XCTFail("corrupt signature published")
        } catch {
            XCTAssertEqual(
                error as? PublicRepositoryCARError,
                .commit(.invalidSignature)
            )
        }
        let unchanged = try await fixture.database.loadPublicRepositoryState()
        XCTAssertEqual(unchanged, fixture.initial)
        let raw = try await openRaw(fixture.root)
        let rows = try await raw.query(
            """
            SELECT
              (SELECT COUNT(*) FROM public_repository_import_sessions) AS sessions,
              (SELECT COUNT(*) FROM public_repository_import_blocks) AS blocks,
              (SELECT COUNT(*) FROM public_repository_import_reachable) AS reachable,
              (SELECT COUNT(*) FROM public_repository_import_record_index) AS indexes,
              (SELECT COUNT(*) FROM public_repository_import_results) AS results
            """
        )
        for column in ["sessions", "blocks", "reachable", "indexes", "results"] {
            XCTAssertEqual(rows.first?.column(column)?.integer, 0, column)
        }
        try await raw.close()
        try await fixture.database.close()
    }

    func testVerifierIdentityMismatchReadsNothingAndCreatesNoSession() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let source = InstrumentedCARSource(data: Data([0]), chunkBytes: 1)
        let verifier = P256PublicRepositoryCommitVerifier(publicKey: fixture.key.publicKey)
        let mismatched = try PublicRepositoryImportBinding(
            requestID: "identity-mismatch",
            requestDigest: Data(repeating: 0x91, count: 32),
            accountDID: did,
            expectedBaseCommitCID: fixture.initial.commitCID,
            verifierIdentity: "p256-sha256:\(String(repeating: "0", count: 64))",
            policy: .init(limits: .standard)
        )
        do {
            _ = try await testCoordinator(fixture.database).importRepository(
                from: source,
                binding: mismatched,
                verifier: verifier,
                createdAt: 100,
                expiresAt: 200
            )
            XCTFail("mismatched verifier identity accepted")
        } catch {
            XCTAssertEqual(
                error as? PublicRepositoryImportStagingError, .bindingMismatch
            )
        }
        let reads = await source.readCount()
        XCTAssertEqual(reads, 0)
        try await assertInitialAndNoStaging(fixture)
        try await fixture.database.close()
    }

    func testPublishRejectsEveryProjectionAndCommitTamperAtomically() async throws {
        for tamper in StagingTamper.allCases {
            let fixture = try await makeFixture()
            defer { try? FileManager.default.removeItem(at: fixture.root) }
            let extraBytes = try DAGCBOR.encodeValue(Data("unlinked".utf8))
            let extraCID = CID.fromDAGCBOR(extraBytes)
            var frames = try await fixture.blocks()
            frames.append(.init(cid: extraCID, bytes: extraBytes))
            let car = try await encodeCAR(
                root: fixture.prepared.state.commitCID, frames: frames
            )
            let databasePath = SQLiteLayout.accountDatabase(
                in: fixture.root, did: did
            ).path
            let coordinator = SQLitePublicRepositoryImportCoordinator(
                database: fixture.database,
                beforePublish: {
                    let raw = try await SQLiteConnection.open(
                        storage: .file(path: databasePath)
                    )
                    try await tamper.apply(to: raw, extraCID: extraCID)
                    try await raw.close()
                },
                now: { 100 }
            )
            do {
                _ = try await coordinator.importRepository(
                    from: InstrumentedCARSource(data: car, chunkBytes: 127),
                    binding: try binding(
                        requestID: "tamper-\(tamper.rawValue)",
                        baseCID: fixture.initial.commitCID
                    ),
                    verifier: P256PublicRepositoryCommitVerifier(
                        publicKey: fixture.key.publicKey
                    ),
                    createdAt: 100,
                    expiresAt: 200
                )
                XCTFail("\(tamper.rawValue) published")
            } catch {
                XCTAssertEqual(
                    error as? PublicRepositoryImportStagingError, .corruptStaging
                )
            }
            try await assertInitialAndNoStaging(fixture)
            try await fixture.database.close()
        }
    }

    func testExpiryIsExclusiveAndEnforcedDuringReceiveVerifyAndPublish() async throws {
        let boundary = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: boundary.root) }
        let boundaryBinding = try binding(
            requestID: "expiry-boundary", baseCID: boundary.initial.commitCID
        )
        if case .staged = try await boundary.database.createPublicRepositoryImportSession(
            binding: boundaryBinding, createdAt: 10, expiresAt: 12, now: 11
        ) {} else {
            XCTFail("one tick before expiry was rejected")
        }
        let beforeExpiry = try await boundary.database
            .recoverExpiredPublicRepositoryImportSessions(now: 11)
        XCTAssertEqual(beforeExpiry, 0)
        let atExpiry = try await boundary.database
            .recoverExpiredPublicRepositoryImportSessions(now: 12)
        XCTAssertEqual(atExpiry, 1)
        for now in [12, 13] {
            do {
                _ = try await boundary.database.createPublicRepositoryImportSession(
                    binding: boundaryBinding, createdAt: 10, expiresAt: 12, now: Int64(now)
                )
                XCTFail("now \(now) accepted")
            } catch {
                XCTAssertEqual(
                    error as? PublicRepositoryImportStagingError, .expiredSession
                )
            }
        }
        do {
            _ = try await boundary.database.createPublicRepositoryImportSession(
                binding: boundaryBinding, createdAt: 12, expiresAt: 12, now: 11
            )
            XCTFail("zero lifetime accepted")
        } catch {
            XCTAssertEqual(
                error as? PublicRepositoryImportStagingError, .invalidTimestamp
            )
        }
        try await boundary.database.close()

        for phase in ExpiryPhase.allCases {
            let fixture = try await makeFixture()
            defer { try? FileManager.default.removeItem(at: fixture.root) }
            let car = try await encodeCAR(
                root: fixture.prepared.state.commitCID,
                frames: try await fixture.blocks()
            )
            let clock = TestImportClock(10)
            let baseVerifier = P256PublicRepositoryCommitVerifier(
                publicKey: fixture.key.publicKey
            )
            let verifier: any PublicRepositoryCommitVerifier = phase == .verification
                ? ExpiringVerifier(base: baseVerifier, clock: clock, expiry: 12)
                : baseVerifier
            let source: any PublicRepositoryCARByteSource = phase == .receive
                ? ExpiringCARSource(data: car, clock: clock, expiry: 12)
                : InstrumentedCARSource(data: car, chunkBytes: 127)
            let beforePublish: (@Sendable () async throws -> Void)? =
                phase == .publish ? { @Sendable in await clock.set(12) } : nil
            let coordinator = SQLitePublicRepositoryImportCoordinator(
                database: fixture.database,
                beforePublish: beforePublish,
                now: { await clock.now() }
            )
            do {
                _ = try await coordinator.importRepository(
                    from: source,
                    binding: try binding(
                        requestID: "expiry-\(phase.rawValue)",
                        baseCID: fixture.initial.commitCID,
                        verifierIdentity: verifier.verificationIdentity
                    ),
                    verifier: verifier,
                    createdAt: 10,
                    expiresAt: 12
                )
                XCTFail("\(phase.rawValue) crossed expiry")
            } catch {
                XCTAssertEqual(
                    error as? PublicRepositoryImportStagingError, .expiredSession
                )
            }
            try await assertInitialAndNoStaging(fixture)
            try await fixture.database.close()
        }
    }

    func testTamperedCommittedResultFailsReplayClosed() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let binding = try binding(requestID: "tamper-result", baseCID: fixture.initial.commitCID)
        let car = try await encodeCAR(
            root: fixture.prepared.state.commitCID,
            frames: try await fixture.blocks()
        )
        let coordinator = testCoordinator(fixture.database)
        _ = try await coordinator.importRepository(
            from: InstrumentedCARSource(data: car, chunkBytes: 257),
            binding: binding,
            verifier: P256PublicRepositoryCommitVerifier(publicKey: fixture.key.publicKey),
            createdAt: 100,
            expiresAt: 200
        )
        try await fixture.database.close()
        let raw = try await openRaw(fixture.root)
        _ = try await raw.query(
            """
            UPDATE public_repository_import_results SET record_count = record_count + 1
            WHERE request_id = ?
            """,
            [.text(binding.requestID)]
        )
        try await raw.close()
        let reopened = try await SQLiteAccountDatabase(dataDirectory: fixture.root, did: did)
        do {
            _ = try await testCoordinator(reopened, now: 201)
                .importRepository(
                    from: InstrumentedCARSource(data: Data(), chunkBytes: 1),
                    binding: binding,
                    verifier: P256PublicRepositoryCommitVerifier(publicKey: fixture.key.publicKey),
                    createdAt: 201,
                    expiresAt: 202
                )
            XCTFail("tampered result replayed")
        } catch {
            XCTAssertEqual(
                error as? PublicRepositoryImportStagingError, .corruptStaging
            )
        }
        try await reopened.close()
    }

    func testCancellationAcrossFramingVerificationAndPrePublishLeavesNoLiveChange() async throws {
        // Canonical header ends at byte 59. The first frame then has a
        // multi-byte length prefix, a 36-byte CID, and a commit body.
        for (index, cancellationOffset) in [0, 1, 20, 59, 60, 75, 100, 150].enumerated() {
            let fixture = try await makeFixture()
            defer { try? FileManager.default.removeItem(at: fixture.root) }
            let car = try await encodeCAR(
                root: fixture.prepared.state.commitCID,
                frames: try await fixture.blocks()
            )
            do {
                _ = try await testCoordinator(fixture.database)
                    .importRepository(
                        from: CancellingCARSource(data: car, cancellationOffset: cancellationOffset),
                        binding: try binding(
                            requestID: "cancel-frame-\(index)",
                            baseCID: fixture.initial.commitCID
                        ),
                        verifier: P256PublicRepositoryCommitVerifier(publicKey: fixture.key.publicKey),
                        createdAt: 100, expiresAt: 200
                    )
                XCTFail("framing cancellation published")
            } catch {
                XCTAssertTrue(error is CancellationError)
            }
            try await assertInitialAndNoStaging(fixture)
            try await fixture.database.close()
        }

        let verificationFixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: verificationFixture.root) }
        let verificationCAR = try await encodeCAR(
            root: verificationFixture.prepared.state.commitCID,
            frames: try await verificationFixture.blocks()
        )
        do {
            _ = try await testCoordinator(verificationFixture.database).importRepository(
                from: InstrumentedCARSource(data: verificationCAR, chunkBytes: 31),
                binding: try binding(
                    requestID: "cancel-verification",
                    baseCID: verificationFixture.initial.commitCID,
                    verifierIdentity: CancellingVerifier().verificationIdentity
                ),
                verifier: CancellingVerifier(),
                createdAt: 100, expiresAt: 200
            )
            XCTFail("verification cancellation published")
        } catch {
            XCTAssertTrue(error is CancellationError)
        }
        try await assertInitialAndNoStaging(verificationFixture)
        try await verificationFixture.database.close()

        let publishFixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: publishFixture.root) }
        let publishCAR = try await encodeCAR(
            root: publishFixture.prepared.state.commitCID,
            frames: try await publishFixture.blocks()
        )
        do {
            _ = try await testCoordinator(
                publishFixture.database,
                beforePublish: { throw CancellationError() }
            ).importRepository(
                from: InstrumentedCARSource(data: publishCAR, chunkBytes: 31),
                binding: try binding(
                    requestID: "cancel-prepublish",
                    baseCID: publishFixture.initial.commitCID
                ),
                verifier: P256PublicRepositoryCommitVerifier(
                    publicKey: publishFixture.key.publicKey
                ),
                createdAt: 100, expiresAt: 200
            )
            XCTFail("pre-publish cancellation published")
        } catch {
            XCTAssertTrue(error is CancellationError)
        }
        try await assertInitialAndNoStaging(publishFixture)
        try await publishFixture.database.close()

        let timeoutFixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: timeoutFixture.root) }
        do {
            _ = try await testCoordinator(timeoutFixture.database).importRepository(
                from: TimeoutCARSource(),
                binding: try binding(
                    requestID: "transport-timeout",
                    baseCID: timeoutFixture.initial.commitCID
                ),
                verifier: P256PublicRepositoryCommitVerifier(
                    publicKey: timeoutFixture.key.publicKey
                ),
                createdAt: 100, expiresAt: 200
            )
            XCTFail("timeout published")
        } catch {
            XCTAssertTrue(error is ImportTestTimeout)
        }
        try await assertInitialAndNoStaging(timeoutFixture)
        try await timeoutFixture.database.close()
    }

    func testTwoDifferentImportsFromSameBaseHaveOneCASWinner() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let alternative = try await prepareAlternative(fixture)
        let firstFrames = try await fixture.blocks()
        let secondFrames = try await blocks(alternative)
        let cars = [
            try await encodeCAR(
                root: fixture.prepared.state.commitCID, frames: firstFrames
            ),
            try await encodeCAR(
                root: alternative.state.commitCID, frames: secondFrames
            ),
        ]
        let prepared = [fixture.prepared, alternative]
        let raceBindings = try (0 ..< 2).map {
            try binding(
                requestID: "base-race-\($0)",
                baseCID: fixture.initial.commitCID
            )
        }
        let coordinator = testCoordinator(fixture.database)
        let outcomes = await withTaskGroup(
            of: (Int, Result<CommittedPublicRepositoryImport, Error>).self
        ) { group in
            for index in 0 ..< 2 {
                group.addTask {
                    do {
                        return (index, .success(
                            try await coordinator.importRepository(
                                from: InstrumentedCARSource(
                                    data: cars[index], chunkBytes: 37
                                ),
                                binding: raceBindings[index],
                                verifier: P256PublicRepositoryCommitVerifier(
                                    publicKey: fixture.key.publicKey
                                ),
                                createdAt: 100, expiresAt: 200
                            )
                        ))
                    } catch {
                        return (index, .failure(error))
                    }
                }
            }
            var results: [(Int, Result<CommittedPublicRepositoryImport, Error>)] = []
            for await result in group { results.append(result) }
            return results
        }
        let winners = outcomes.compactMap { index, result -> Int? in
            if case .success = result { return index }
            return nil
        }
        XCTAssertEqual(winners.count, 1)
        XCTAssertEqual(outcomes.filter {
            guard case let .failure(error) = $0.1 else { return false }
            return error as? PublicRepositoryImportStagingError == .commitCASConflict
        }.count, 1)
        let winner = try XCTUnwrap(winners.first)
        let loser = 1 - winner
        let finalState = try await fixture.database.loadPublicRepositoryState()
        XCTAssertEqual(finalState, prepared[winner].state)
        try await fixture.database.verifyPublicRepositoryProjection()
        let winnerCIDs = prepared[winner].newBlocks.cids
        for cid in prepared[loser].newBlocks.cids.subtracting(winnerCIDs) {
            let loserOnlyBlock = try await fixture.database.block(for: cid)
            XCTAssertNil(loserOnlyBlock, "loser-only block became live: \(cid)")
        }
        let raw = try await openRaw(fixture.root)
        let residue = try await raw.query(
            """
            SELECT COUNT(*) AS count FROM public_repository_import_sessions
            WHERE status != 'consumed'
            """
        )
        XCTAssertEqual(residue.first?.column("count")?.integer, 0)
        try await raw.close()
        try await fixture.database.close()
    }

    func testMalformedAndCorruptCARCasesPublishNothing() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let valid = try await encodeCAR(
            root: fixture.prepared.state.commitCID,
            frames: try await fixture.blocks()
        )
        var malformedCID = valid
        malformedCID[61] ^= 0x7f
        var corruptBody = valid
        corruptBody[corruptBody.count - 1] ^= 1
        let cases = [
            Data(),
            Data(valid.prefix(1)),
            Data(valid.prefix(20)),
            Data(valid.prefix(59)),
            Data(valid.dropLast()),
            malformedCID,
            corruptBody,
        ]
        for (index, bytes) in cases.enumerated() {
            do {
                _ = try await testCoordinator(fixture.database).importRepository(
                    from: InstrumentedCARSource(data: bytes, chunkBytes: 7),
                    binding: try binding(
                        requestID: "corrupt-\(index)",
                        baseCID: fixture.initial.commitCID
                    ),
                    verifier: P256PublicRepositoryCommitVerifier(
                        publicKey: fixture.key.publicKey
                    ),
                    createdAt: 100, expiresAt: 200
                )
                XCTFail("corrupt case \(index) published")
            } catch {
                XCTAssertNotNil(error as? PublicRepositoryCARError)
            }
            try await assertInitialAndNoStaging(fixture)
        }
        try await fixture.database.close()
    }

    func testMultiMegabyteUnlinkedPayloadUsesBoundedReadChunksAndOneBlock() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        var frames = try await fixture.blocks()
        for index in 0 ..< 8 {
            var payload = Data("extra-\(index)-".utf8)
            payload.append(Data(repeating: UInt8(index), count: 512 * 1_024))
            let bytes = try DAGCBOR.encodeValue(payload)
            frames.append(.init(cid: CID.fromDAGCBOR(bytes), bytes: bytes))
        }
        let car = try await encodeCAR(root: fixture.prepared.state.commitCID, frames: frames)
        let source = InstrumentedCARSource(data: car, chunkBytes: 32 * 1_024)
        _ = try await testCoordinator(fixture.database)
            .importRepository(
                from: source,
                binding: try binding(
                    requestID: "bounded-multimegabyte",
                    baseCID: fixture.initial.commitCID
                ),
                verifier: P256PublicRepositoryCommitVerifier(publicKey: fixture.key.publicKey),
                createdAt: 100, expiresAt: 200
            )
        let maximumReturned = await source.maximumReturned()
        let maximumRequested = await source.maximumRequested()
        XCTAssertLessThanOrEqual(maximumReturned, 32 * 1_024)
        XCTAssertLessThanOrEqual(
            maximumRequested,
            PublicRepositoryLimits.standard.maximumRecordBlockBytes
        )
        try await fixture.database.close()
    }

    func testExactBlockBodyLimitsAndValidCIDSemanticCorruptionPublishNothing() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let normalCAR = try await encodeCAR(
            root: fixture.prepared.state.commitCID,
            frames: try await fixture.blocks()
        )
        let oneBlockLimit = try PublicRepositoryLimits(
            maximumRecordBlockBytes: 1_000_000,
            maximumCARBytes: PublicRepositoryLimits.standard.maximumCARBytes,
            maximumCARBlocks: 1,
            maximumMSTNodes: 1,
            maximumMSTEntriesPerNode: 4_096,
            maximumCBORNestingDepth: 64
        )
        try await assertRejected(
            car: normalCAR, requestID: "limit-blocks",
            limits: oneBlockLimit, fixture: fixture,
            expected: .blockLimitExceeded
        )
        let oneByteBody = try PublicRepositoryLimits(
            maximumRecordBlockBytes: 1,
            maximumCARBytes: PublicRepositoryLimits.standard.maximumCARBytes,
            maximumCARBlocks: 1_000_000,
            maximumMSTNodes: 500_000,
            maximumMSTEntriesPerNode: 4_096,
            maximumCBORNestingDepth: 64
        )
        try await assertRejected(
            car: normalCAR, requestID: "limit-body",
            limits: oneByteBody, fixture: fixture,
            expected: .blockBodyLimitExceeded
        )

        let malformedMST = Data([0xa0])
        let malformedMSTCID = CID.fromDAGCBOR(malformedMST)
        let malformedCommit = try await PublicRepositoryCommitCodec.prepare(
            did: did,
            revision: fixture.prepared.state.revision,
            dataCID: malformedMSTCID,
            currentRevision: fixture.initial.revision,
            signer: P256PublicRepositoryCommitSigner(privateKey: fixture.key)
        )
        let malformedCAR = try await encodeCAR(
            root: malformedCommit.commitCID,
            frames: [
                .init(cid: malformedCommit.commitCID, bytes: malformedCommit.signedCommitBytes),
                .init(cid: malformedMSTCID, bytes: malformedMST),
            ]
        )
        try await assertRejected(
            car: malformedCAR, requestID: "bad-topology",
            limits: .standard, fixture: fixture,
            expected: .repository(.invalidNodeSchema)
        )

        let path = try PublicRepositoryPath(
            collection: "app.bsky.feed.post", recordKey: "wrong-type"
        )
        let wrongRecord = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "$type", value: "com.example.wrong"),
            (key: "text", value: "wrong type"),
        ]))
        let wrongRecordCID = CID.fromDAGCBOR(wrongRecord)
        let tree = try await RepositoryMST.empty()
            .adding(path: path, recordCID: wrongRecordCID)
        let materialized = try await tree.materialized()
        let wrongCommit = try await PublicRepositoryCommitCodec.prepare(
            did: did,
            revision: fixture.prepared.state.revision,
            dataCID: materialized.rootCID,
            currentRevision: fixture.initial.revision,
            signer: P256PublicRepositoryCommitSigner(privateKey: fixture.key)
        )
        var wrongFrames = [
            PublicRepositoryBlock(
                cid: wrongCommit.commitCID, bytes: wrongCommit.signedCommitBytes
            ),
            PublicRepositoryBlock(cid: wrongRecordCID, bytes: wrongRecord),
        ]
        for cid in materialized.newBlocks.cids {
            let maybeBytes = try await materialized.newBlocks.block(for: cid)
            wrongFrames.append(.init(
                cid: cid,
                bytes: try XCTUnwrap(maybeBytes)
            ))
        }
        let wrongCAR = try await encodeCAR(root: wrongCommit.commitCID, frames: wrongFrames)
        try await assertRejected(
            car: wrongCAR, requestID: "wrong-record-type",
            limits: .standard, fixture: fixture,
            expected: .repository(.invalidRecordBlock)
        )
        try await fixture.database.close()
    }

    func testEveryPersistedTopologyLimitAtAndOnePastStagingBoundary() async throws {
        let probe = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: probe.root) }
        let prepared = try await prepareWideRepository(probe)
        let frames = try await blocks(prepared)
        let validated = try await RepositoryMSTValidation.validate(
            rootCID: prepared.state.dataCID, blocks: prepared.newBlocks
        )
        let maximumEntries = try validated.reachableMSTBlocks.values.map {
            try RepositoryMSTCodec.decode($0).entries.count
        }.max() ?? 0
        let maximumBody = try XCTUnwrap(frames.map(\.bytes.count).max())
        let minimumDepth = try await minimumAcceptedDepth(
            root: prepared.state.dataCID, blocks: prepared.newBlocks
        )
        let dimensions: [LimitDimension] = [
            .blocks(frames.count),
            .body(maximumBody),
            .nodes(validated.reachableMSTBlocks.count),
            .entries(maximumEntries),
            .depth(minimumDepth),
        ]
        try await probe.database.close()

        for dimension in dimensions {
            for delta in -1 ... 1 {
                let fixture = try await makeFixture()
                defer { try? FileManager.default.removeItem(at: fixture.root) }
                let wide = try await prepareWideRepository(fixture)
                let wideCAR = try await encodeCAR(
                    root: wide.state.commitCID, frames: try await blocks(wide)
                )
                let limits = try dimension.policy(delta: delta, baseline: (
                    body: maximumBody,
                    blocks: frames.count,
                    nodes: validated.reachableMSTBlocks.count,
                    entries: maximumEntries,
                    depth: minimumDepth
                ))
                if delta == -1 {
                    try await assertRejected(
                        car: wideCAR,
                        requestID: "limit-\(dimension.name)-below",
                        limits: limits,
                        fixture: fixture,
                        expected: dimension.expectedFailure
                    )
                } else {
                    let result = try await testCoordinator(fixture.database)
                        .importRepository(
                            from: InstrumentedCARSource(data: wideCAR, chunkBytes: 257),
                            binding: try PublicRepositoryImportBinding(
                                requestID: "limit-\(dimension.name)-\(delta)",
                                requestDigest: Data(
                                    SHA256.hash(
                                        data: Data("limit-\(dimension.name)-\(delta)".utf8)
                                    )
                                ),
                                accountDID: did,
                                expectedBaseCommitCID: fixture.initial.commitCID,
                                verifierIdentity: P256PublicRepositoryCommitVerifier(
                                    publicKey: fixture.key.publicKey
                                ).verificationIdentity,
                                policy: .init(limits: limits)
                            ),
                            verifier: P256PublicRepositoryCommitVerifier(
                                publicKey: fixture.key.publicKey
                            ),
                            createdAt: 100,
                            expiresAt: 200
                        )
                    XCTAssertEqual(result.state, wide.state)
                }
                try await fixture.database.close()
            }
        }
    }

    func testOptIn256MiBStagedCAR() async throws {
        guard ProcessInfo.processInfo.environment["SWAN_RUN_256MIB_CAR_STAGING"] == "1" else {
            throw XCTSkip("set SWAN_RUN_256MIB_CAR_STAGING=1 for the 256 MiB acceptance run")
        }
        let baselineHWM = peakResidentBytes()
        var exactCARURL: URL?
        for delta in [-1, 0] {
            let fixture = try await makeFixture()
            defer { try? FileManager.default.removeItem(at: fixture.root) }
            let carURL = fixture.root.appending(path: "streaming-256mib-\(delta).car")
            let sink = try FileCARByteSink(url: carURL)
            let blockStream = try ExactSizedCARBlockStream(
                required: try await fixture.blocks(),
                targetCARBytes: PublicRepositoryLimits.requiredStreamingCARBytes + delta
            )
            _ = try await PublicRepositoryCAR.write(
                rootCID: fixture.prepared.state.commitCID,
                blocks: blockStream,
                to: sink
            )
            try await sink.close()
            let carBytes = try XCTUnwrap(
                try FileManager.default.attributesOfItem(atPath: carURL.path)[.size]
                    as? NSNumber
            ).intValue
            XCTAssertEqual(
                carBytes, PublicRepositoryLimits.requiredStreamingCARBytes + delta
            )
            let source = try FileCARByteSource(
                url: carURL, chunkBytes: 64 * 1_024
            )
            let limits = try PublicRepositoryLimits(
                maximumRecordBlockBytes: 1_000_000,
                maximumCARBytes: PublicRepositoryLimits.requiredStreamingCARBytes,
                maximumCARBlocks: 1_000_000,
                maximumMSTNodes: 500_000,
                maximumMSTEntriesPerNode: 4_096,
                maximumCBORNestingDepth: 64
            )
            let requestID = "opt-in-256mib-\(delta)"
            _ = try await testCoordinator(fixture.database).importRepository(
                from: source,
                binding: try PublicRepositoryImportBinding(
                    requestID: requestID,
                    requestDigest: Data(SHA256.hash(data: Data(requestID.utf8))),
                    accountDID: did,
                    expectedBaseCommitCID: fixture.initial.commitCID,
                    verifierIdentity: P256PublicRepositoryCommitVerifier(
                        publicKey: fixture.key.publicKey
                    ).verificationIdentity,
                    policy: .init(limits: limits)
                ),
                verifier: P256PublicRepositoryCommitVerifier(
                    publicKey: fixture.key.publicKey
                ),
                createdAt: 100,
                expiresAt: 200
            )
            let maximumReturned = await source.maximumReturned()
            XCTAssertLessThanOrEqual(maximumReturned, 64 * 1_024)
            let maximumGeneratedBody = await blockStream.maximumGeneratedBody()
            XCTAssertLessThanOrEqual(maximumGeneratedBody, 1_000_000)
            try await source.close()
            try await fixture.database.close()
            if delta == 0 {
                let retained = FileManager.default.temporaryDirectory
                    .appending(path: "swan-task42-exact-\(UUID().uuidString).car")
                try FileManager.default.copyItem(at: carURL, to: retained)
                exactCARURL = retained
            }
        }

        let overFixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: overFixture.root) }
        let retainedExact = try XCTUnwrap(exactCARURL)
        defer { try? FileManager.default.removeItem(at: retainedExact) }
        let exactSource = try FileCARByteSource(
            url: retainedExact, chunkBytes: 64 * 1_024
        )
        let overSource = AppendingByteCARSource(source: exactSource)
        let exactLimit = try PublicRepositoryLimits(
            maximumRecordBlockBytes: 1_000_000,
            maximumCARBytes: PublicRepositoryLimits.requiredStreamingCARBytes,
            maximumCARBlocks: 1_000_000,
            maximumMSTNodes: 500_000,
            maximumMSTEntriesPerNode: 4_096,
            maximumCBORNestingDepth: 64
        )
        do {
            _ = try await testCoordinator(overFixture.database).importRepository(
                from: overSource,
                binding: try PublicRepositoryImportBinding(
                    requestID: "opt-in-256mib-over",
                    requestDigest: Data(repeating: 0xa4, count: 32),
                    accountDID: did,
                    expectedBaseCommitCID: overFixture.initial.commitCID,
                    verifierIdentity: P256PublicRepositoryCommitVerifier(
                        publicKey: overFixture.key.publicKey
                    ).verificationIdentity,
                    policy: .init(limits: exactLimit)
                ),
                verifier: P256PublicRepositoryCommitVerifier(
                    publicKey: overFixture.key.publicKey
                ),
                createdAt: 100,
                expiresAt: 200
            )
            XCTFail("one byte over maximum CAR bytes published")
        } catch {
            XCTAssertEqual(error as? PublicRepositoryCARError, .byteLimitExceeded)
        }
        try await assertInitialAndNoStaging(overFixture)
        try await exactSource.close()
        try await overFixture.database.close()
        let finalHWM = peakResidentBytes()
        XCTAssertLessThan(
            finalHWM - baselineHWM,
            128 * 1_024 * 1_024,
            "streamed generation/import must not retain a payload-sized representation"
        )
        XCTAssertLessThan(finalHWM, 512 * 1_024 * 1_024)
    }

    private func makeFixture() async throws -> ImportFixture {
        let root = try temporaryDirectory()
        let key = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 1, count: 32)
        )
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let genesis = try PublicRepositoryGenesisCodec.create(
            did: did, revision: genesisRevision, signingKey: key
        )
        _ = try await database.installPublicRepositoryGenesis(
            genesis, signingPublicKey: key.publicKey,
            installedAt: Date(timeIntervalSince1970: 1)
        )
        let loadedInitial = try await database.loadPublicRepositoryState()
        let initial = try XCTUnwrap(loadedInitial)
        let request = try PublicRepositoryMutationRequest(
            id: UUID().uuidString,
            canonicalDigest: Data(repeating: 0x33, count: 32),
            baseCommitCID: initial.commitCID
        )
        guard case let .reserved(reservation) =
            try await database.reservePublicRepositoryRevision(
                request, wallClockMicroseconds: 1_750_000_000_000_000
            ) else {
            throw PublicRepositoryImportStagingError.corruptRepository
        }
        let path = try PublicRepositoryPath(
            collection: "app.bsky.feed.post", recordKey: "imported"
        )
        let batch = try PublicRepositoryWriteBatch(
            writes: [.create(
                path: path,
                record: PublicRecord([
                    "$type": .string("app.bsky.feed.post"),
                    "text": .string("hello from staged CAR"),
                ])
            )],
            expectedCommitCID: initial.commitCID
        )
        let prepared = try await PublicRepositoryEngine.apply(
            repositoryDID: did, currentState: initial, blocks: database,
            revision: reservation.nextRevision, batch: batch,
            signer: P256PublicRepositoryCommitSigner(privateKey: key)
        )
        return ImportFixture(
            root: root, database: database, key: key, initial: initial,
            prepared: prepared, path: path
        )
    }

    private func prepareAlternative(
        _ fixture: ImportFixture
    ) async throws -> PreparedPublicRepositoryMutation {
        let path = try PublicRepositoryPath(
            collection: "app.bsky.feed.post", recordKey: "alternative"
        )
        return try await PublicRepositoryEngine.apply(
            repositoryDID: did,
            currentState: fixture.initial,
            blocks: fixture.database,
            revision: fixture.prepared.state.revision,
            batch: try PublicRepositoryWriteBatch(
                writes: [.create(
                    path: path,
                    record: PublicRecord([
                        "$type": .string("app.bsky.feed.post"),
                        "text": .string("loser unique"),
                    ])
                )],
                expectedCommitCID: fixture.initial.commitCID
            ),
            signer: P256PublicRepositoryCommitSigner(privateKey: fixture.key)
        )
    }

    private func prepareWideRepository(
        _ fixture: ImportFixture
    ) async throws -> PreparedPublicRepositoryMutation {
        let writes: [PublicRepositoryWrite] = try (0 ..< 96).map { index in
            .create(
                path: try PublicRepositoryPath(
                    collection: "com.example.record",
                    recordKey: String(format: "wide-%03d", index)
                ),
                record: PublicRecord([
                    "$type": .string("com.example.record"),
                    "value": .integer(index),
                ])
            )
        }
        return try await PublicRepositoryEngine.apply(
            repositoryDID: did,
            currentState: fixture.initial,
            blocks: fixture.database,
            revision: fixture.prepared.state.revision,
            batch: try PublicRepositoryWriteBatch(
                writes: writes,
                expectedCommitCID: fixture.initial.commitCID
            ),
            signer: P256PublicRepositoryCommitSigner(privateKey: fixture.key)
        )
    }

    private func minimumAcceptedDepth(
        root: CID,
        blocks: any PublicRepositoryBlockSource
    ) async throws -> Int {
        for depth in 1 ... PublicRepositoryLimits.maximumPermittedCBORNestingDepth {
            let limits = try PublicRepositoryLimits(
                maximumRecordBlockBytes: 1_000_000,
                maximumCARBytes: PublicRepositoryLimits.requiredStreamingCARBytes,
                maximumCARBlocks: 1_000,
                maximumMSTNodes: 1_000,
                maximumMSTEntriesPerNode: 4_096,
                maximumCBORNestingDepth: depth
            )
            if (try? await RepositoryMSTValidation.validate(
                rootCID: root, blocks: blocks, limits: limits
            )) != nil {
                return depth
            }
        }
        throw PublicRepositoryImportStagingError.corruptRepository
    }

    private func blocks(
        _ prepared: PreparedPublicRepositoryMutation
    ) async throws -> [PublicRepositoryBlock] {
        var result: [PublicRepositoryBlock] = []
        for cid in prepared.newBlocks.cids {
            guard let bytes = try await prepared.newBlocks.block(for: cid) else {
                throw PublicRepositoryImportStagingError.corruptRepository
            }
            result.append(.init(cid: cid, bytes: bytes))
        }
        return result
    }

    private func assertInitialAndNoStaging(_ fixture: ImportFixture) async throws {
        let state = try await fixture.database.loadPublicRepositoryState()
        XCTAssertEqual(state, fixture.initial)
        let raw = try await openRaw(fixture.root)
        let rows = try await raw.query(
            "SELECT COUNT(*) AS count FROM public_repository_import_sessions"
        )
        XCTAssertEqual(rows.first?.column("count")?.integer, 0)
        try await raw.close()
    }

    private func assertRejected(
        car: Data,
        requestID: String,
        limits: PublicRepositoryLimits,
        fixture: ImportFixture,
        expected: PublicRepositoryCARError
    ) async throws {
        do {
            _ = try await testCoordinator(fixture.database)
                .importRepository(
                    from: InstrumentedCARSource(data: car, chunkBytes: 29),
                    binding: try PublicRepositoryImportBinding(
                        requestID: requestID,
                        requestDigest: Data(SHA256.hash(data: Data(requestID.utf8))),
                        accountDID: did,
                        expectedBaseCommitCID: fixture.initial.commitCID,
                        verifierIdentity: P256PublicRepositoryCommitVerifier(
                            publicKey: fixture.key.publicKey
                        ).verificationIdentity,
                        policy: .init(limits: limits)
                    ),
                    verifier: P256PublicRepositoryCommitVerifier(
                        publicKey: fixture.key.publicKey
                    ),
                    createdAt: 100, expiresAt: 200
                )
            XCTFail("\(requestID) published")
        } catch {
            XCTAssertEqual(error as? PublicRepositoryCARError, expected)
        }
        try await assertInitialAndNoStaging(fixture)
    }

    private func binding(
        requestID: String,
        baseCID: CID,
        verifierIdentity: String? = nil
    ) throws
        -> PublicRepositoryImportBinding {
        try PublicRepositoryImportBinding(
            requestID: requestID,
            requestDigest: Data(SHA256.hash(data: Data(requestID.utf8))),
            accountDID: did,
            expectedBaseCommitCID: baseCID,
            verifierIdentity: verifierIdentity ?? P256PublicRepositoryCommitVerifier(
                publicKey: try P256.Signing.PrivateKey(
                    rawRepresentation: Data(repeating: 1, count: 32)
                ).publicKey
            ).verificationIdentity,
            policy: .init(limits: .standard)
        )
    }

    private func testCoordinator(
        _ database: SQLiteAccountDatabase,
        now: Int64 = 100,
        beforePublish: (@Sendable () async throws -> Void)? = nil
    ) -> SQLitePublicRepositoryImportCoordinator {
        SQLitePublicRepositoryImportCoordinator(
            database: database,
            beforePublish: beforePublish,
            now: { now }
        )
    }

    private func encodeCAR(
        root: CID,
        frames: [PublicRepositoryBlock]
    ) async throws -> Data {
        let sink = DataCARSink()
        _ = try await PublicRepositoryCAR.write(
            rootCID: root, blocks: ArrayCARBlockStream(frames), to: sink
        )
        return await sink.data
    }

    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("swan-import-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: NSNumber(value: 0o700)]
        )
        return url
    }

    private func openRaw(_ root: URL) async throws -> SQLiteConnection {
        try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(in: root, did: did).path)
        )
    }
}

private struct ImportFixture {
    let root: URL
    let database: SQLiteAccountDatabase
    let key: P256.Signing.PrivateKey
    let initial: PublicRepositoryState
    let prepared: PreparedPublicRepositoryMutation
    let path: PublicRepositoryPath

    func blocks() async throws -> [PublicRepositoryBlock] {
        var values: [PublicRepositoryBlock] = []
        for cid in prepared.newBlocks.cids {
            guard let bytes = try await prepared.newBlocks.block(for: cid) else {
                throw PublicRepositoryImportStagingError.corruptRepository
            }
            values.append(.init(cid: cid, bytes: bytes))
        }
        return values
    }
}

private enum StagingTamper: String, CaseIterable, Sendable {
    case addReachable
    case dropReachable
    case changeReachableKind
    case addIndex
    case dropIndex
    case changeIndex
    case changeCommitBody

    func apply(to connection: SQLiteConnection, extraCID: CID) async throws {
        switch self {
        case .addReachable:
            _ = try await connection.query(
                """
                INSERT INTO public_repository_import_reachable(session_id, cid, kind)
                SELECT session_id, ?, 'record'
                FROM public_repository_import_sessions
                """,
                [.text(extraCID.string)]
            )
        case .dropReachable:
            _ = try await connection.query(
                """
                DELETE FROM public_repository_import_reachable
                WHERE rowid = (
                    SELECT rowid FROM public_repository_import_reachable
                    WHERE kind = 'record' ORDER BY cid LIMIT 1
                )
                """
            )
        case .changeReachableKind:
            _ = try await connection.query(
                """
                UPDATE public_repository_import_reachable SET kind = 'record'
                WHERE rowid = (
                    SELECT rowid FROM public_repository_import_reachable
                    WHERE kind = 'mst' ORDER BY cid LIMIT 1
                )
                """
            )
        case .addIndex:
            _ = try await connection.query(
                """
                INSERT INTO public_repository_import_record_index(
                    session_id, collection, rkey, record_cid
                )
                SELECT session_id, 'app.bsky.feed.post', 'tampered', ?
                FROM public_repository_import_sessions
                """,
                [.text(extraCID.string)]
            )
        case .dropIndex:
            _ = try await connection.query(
                """
                DELETE FROM public_repository_import_record_index
                WHERE rowid = (
                    SELECT rowid FROM public_repository_import_record_index
                    ORDER BY collection, rkey LIMIT 1
                )
                """
            )
        case .changeIndex:
            _ = try await connection.query(
                """
                UPDATE public_repository_import_record_index SET record_cid = ?
                WHERE rowid = (
                    SELECT rowid FROM public_repository_import_record_index
                    ORDER BY collection, rkey LIMIT 1
                )
                """,
                [.text(extraCID.string)]
            )
        case .changeCommitBody:
            _ = try await connection.query(
                """
                UPDATE public_repository_import_blocks SET bytes = X'00'
                WHERE cid = (
                    SELECT root_cid FROM public_repository_import_sessions LIMIT 1
                )
                """
            )
        }
    }
}

private enum LimitDimension: Sendable {
    case blocks(Int)
    case body(Int)
    case nodes(Int)
    case entries(Int)
    case depth(Int)

    var name: String {
        switch self {
        case .blocks: "blocks"
        case .body: "body"
        case .nodes: "nodes"
        case .entries: "entries"
        case .depth: "depth"
        }
    }

    var expectedFailure: PublicRepositoryCARError {
        switch self {
        case .blocks: .blockLimitExceeded
        case .body: .blockBodyLimitExceeded
        case .nodes: .repository(.nodeLimitExceeded)
        case .entries: .repository(.entryLimitExceeded)
        case .depth: .repository(.cborDepthLimitExceeded)
        }
    }

    func policy(
        delta: Int,
        baseline: (body: Int, blocks: Int, nodes: Int, entries: Int, depth: Int)
    ) throws -> PublicRepositoryLimits {
        var body = baseline.body + 1
        var blocks = baseline.blocks + 1
        var nodes = baseline.nodes + 1
        var entries = baseline.entries + 1
        var depth = baseline.depth + 1
        switch self {
        case let .body(value): body = value + delta
        case let .blocks(value): blocks = value + delta
        case let .nodes(value): nodes = value + delta
        case let .entries(value): entries = value + delta
        case let .depth(value): depth = value + delta
        }
        return try PublicRepositoryLimits(
            maximumRecordBlockBytes: body,
            maximumCARBytes: PublicRepositoryLimits.requiredStreamingCARBytes,
            maximumCARBlocks: blocks,
            maximumMSTNodes: min(nodes, blocks),
            maximumMSTEntriesPerNode: entries,
            maximumCBORNestingDepth: depth
        )
    }
}

private enum ExpiryPhase: String, CaseIterable, Sendable {
    case receive
    case verification
    case publish
}

private actor TestImportClock {
    private var value: Int64
    init(_ value: Int64) { self.value = value }
    func now() -> Int64 { value }
    func set(_ value: Int64) { self.value = value }
}

private struct ExpiringVerifier: PublicRepositoryCommitVerifier {
    let base: P256PublicRepositoryCommitVerifier
    let clock: TestImportClock
    let expiry: Int64
    var signingAlgorithm: PublicRepositorySigningAlgorithm { base.signingAlgorithm }
    var verificationIdentity: String { base.verificationIdentity }

    func verify(signature: Data, unsignedCommitBytes: Data, did: String) async throws {
        try await base.verify(
            signature: signature, unsignedCommitBytes: unsignedCommitBytes, did: did
        )
        await clock.set(expiry)
    }
}

private actor ExpiringCARSource: PublicRepositoryCARByteSource {
    private let data: Data
    private let clock: TestImportClock
    private let expiry: Int64
    private var offset = 0

    init(data: Data, clock: TestImportClock, expiry: Int64) {
        self.data = data
        self.clock = clock
        self.expiry = expiry
    }

    func read(maximumBytes: Int) async throws -> Data? {
        guard offset < data.count else { return nil }
        let count = min(maximumBytes, 64, data.count - offset)
        let result = Data(data[offset ..< offset + count])
        offset += count
        await clock.set(expiry)
        return result
    }
}

private actor DataCARSink: PublicRepositoryCARByteSink {
    private(set) var data = Data()
    func write(_ bytes: Data) async throws { data.append(bytes) }
}

private actor FileCARByteSink: PublicRepositoryCARByteSink {
    private let handle: FileHandle

    init(url: URL) throws {
        _ = FileManager.default.createFile(atPath: url.path, contents: nil)
        handle = try FileHandle(forWritingTo: url)
    }

    func write(_ bytes: Data) async throws {
        try handle.write(contentsOf: bytes)
    }

    func close() throws {
        try handle.close()
    }
}

private actor FileCARByteSource: PublicRepositoryCARByteSource {
    private let handle: FileHandle
    private let chunkBytes: Int
    private var maximumReturnedBytes = 0

    init(url: URL, chunkBytes: Int) throws {
        handle = try FileHandle(forReadingFrom: url)
        self.chunkBytes = chunkBytes
    }

    func read(maximumBytes: Int) async throws -> Data? {
        let bytes = try handle.read(upToCount: min(maximumBytes, chunkBytes))
        guard let bytes, !bytes.isEmpty else { return nil }
        maximumReturnedBytes = max(maximumReturnedBytes, bytes.count)
        return bytes
    }

    func maximumReturned() -> Int { maximumReturnedBytes }
    func close() throws { try handle.close() }
}

private actor AppendingByteCARSource: PublicRepositoryCARByteSource {
    private let source: FileCARByteSource
    private var appended = false

    init(source: FileCARByteSource) {
        self.source = source
    }

    func read(maximumBytes: Int) async throws -> Data? {
        if let bytes = try await source.read(maximumBytes: maximumBytes) {
            return bytes
        }
        guard !appended else { return nil }
        appended = true
        return Data([0])
    }
}

private actor ExactSizedCARBlockStream: PublicRepositoryCARBlockStream {
    private let required: [PublicRepositoryBlock]
    private let extraBodyLengths: [Int]
    private var index = 0
    private var maximumBody = 0

    init(required: [PublicRepositoryBlock], targetCARBytes: Int) throws {
        self.required = required
        var remaining = targetCARBytes - 59
        for block in required {
            remaining -= Self.frameByteCount(bodyBytes: block.bytes.count)
        }
        guard remaining >= 0 else {
            throw PublicRepositoryImportStagingError.corruptRepository
        }
        let maximumFrame = Self.frameByteCount(bodyBytes: 1_000_000)
        var bodies: [Int] = []
        while remaining > maximumFrame * 2 {
            bodies.append(1_000_000)
            remaining -= maximumFrame
        }
        if remaining > 0 {
            if let body = Self.bodyLength(forExactFrameBytes: remaining) {
                bodies.append(body)
            } else {
                var pair: (Int, Int)?
                for first in stride(from: min(1_000_000, remaining), through: 1, by: -1)
                where Self.isCanonicalByteStringLength(first) {
                    let rest = remaining - Self.frameByteCount(bodyBytes: first)
                    guard rest > 0,
                          let second = Self.bodyLength(forExactFrameBytes: rest)
                    else { continue }
                    pair = (first, second)
                    break
                }
                guard let pair else {
                    throw PublicRepositoryImportStagingError.corruptRepository
                }
                bodies.append(pair.0)
                bodies.append(pair.1)
            }
        }
        extraBodyLengths = bodies
    }

    func nextBlock() async throws -> PublicRepositoryBlock? {
        if index < required.count {
            defer { index += 1 }
            return required[index]
        }
        let extraIndex = index - required.count
        guard extraIndex < extraBodyLengths.count else { return nil }
        index += 1
        let bytes = Self.canonicalByteString(
            totalBytes: extraBodyLengths[extraIndex],
            fill: UInt8(truncatingIfNeeded: extraIndex)
        )
        maximumBody = max(maximumBody, bytes.count)
        return PublicRepositoryBlock(cid: CID.fromDAGCBOR(bytes), bytes: bytes)
    }

    func maximumGeneratedBody() -> Int { maximumBody }

    private static func frameByteCount(bodyBytes: Int) -> Int {
        let frameLength = 36 + bodyBytes
        return canonicalVarintByteCount(UInt64(frameLength)) + frameLength
    }

    private static func bodyLength(forExactFrameBytes bytes: Int) -> Int? {
        for varintBytes in 1 ... 10 {
            let body = bytes - 36 - varintBytes
            guard body > 0, body <= 1_000_000,
                  isCanonicalByteStringLength(body),
                  canonicalVarintByteCount(UInt64(36 + body)) == varintBytes
            else { continue }
            return body
        }
        return nil
    }

    private static func canonicalVarintByteCount(_ value: UInt64) -> Int {
        var value = value
        var count = 1
        while value >= 0x80 {
            value >>= 7
            count += 1
        }
        return count
    }

    private static func isCanonicalByteStringLength(_ total: Int) -> Bool {
        (1 ... 24).contains(total)
            || (26 ... 257).contains(total)
            || (259 ... 65_538).contains(total)
            || (65_541 ... 1_000_000).contains(total)
    }

    private static func canonicalByteString(totalBytes: Int, fill: UInt8) -> Data {
        precondition(isCanonicalByteStringLength(totalBytes))
        var result = Data()
        let payloadBytes: Int
        switch totalBytes {
        case 1 ... 24:
            payloadBytes = totalBytes - 1
            result.append(0x40 | UInt8(payloadBytes))
        case 26 ... 257:
            payloadBytes = totalBytes - 2
            result.append(0x58)
            result.append(UInt8(payloadBytes))
        case 259 ... 65_538:
            payloadBytes = totalBytes - 3
            result.append(0x59)
            var value = UInt16(payloadBytes).bigEndian
            withUnsafeBytes(of: &value) { result.append(contentsOf: $0) }
        default:
            payloadBytes = totalBytes - 5
            result.append(0x5a)
            var value = UInt32(payloadBytes).bigEndian
            withUnsafeBytes(of: &value) { result.append(contentsOf: $0) }
        }
        result.append(Data(repeating: fill, count: payloadBytes))
        return result
    }
}

private func peakResidentBytes() -> Int {
    var usage = rusage()
    guard getrusage(RUSAGE_SELF, &usage) == 0 else { return 0 }
    #if os(Linux)
    return Int(usage.ru_maxrss) * 1_024
    #else
    return Int(usage.ru_maxrss)
    #endif
}

private actor ArrayCARBlockStream: PublicRepositoryCARBlockStream {
    private let blocks: [PublicRepositoryBlock]
    private var index = 0
    init(_ blocks: [PublicRepositoryBlock]) { self.blocks = blocks }
    func nextBlock() async throws -> PublicRepositoryBlock? {
        guard index < blocks.count else { return nil }
        defer { index += 1 }
        return blocks[index]
    }
}

private actor InstrumentedCARSource: PublicRepositoryCARByteSource {
    private let data: Data
    private let chunkBytes: Int
    private var offset = 0
    private(set) var maximumReturnedBytes = 0
    private var maximumRequestedBytes = 0
    private var reads = 0

    init(data: Data, chunkBytes: Int) {
        self.data = data
        self.chunkBytes = chunkBytes
    }

    func read(maximumBytes: Int) async throws -> Data? {
        reads += 1
        maximumRequestedBytes = max(maximumRequestedBytes, maximumBytes)
        guard offset < data.count else { return nil }
        let count = min(maximumBytes, chunkBytes, data.count - offset)
        let result = Data(data[offset ..< offset + count])
        offset += count
        maximumReturnedBytes = max(maximumReturnedBytes, result.count)
        return result
    }

    func maximumReturned() -> Int { maximumReturnedBytes }
    func maximumRequested() -> Int { maximumRequestedBytes }
    func readCount() -> Int { reads }
}

private actor CollectingFrameSink: PublicRepositoryCARFrameSink {
    private(set) var blocks: [PublicRepositoryBlock] = []
    func receiveHeader(rootCID _: CID, receivedByteCount _: Int) async throws {}
    func receiveBlock(
        _ block: PublicRepositoryBlock,
        receivedByteCount _: Int,
        frameCount _: Int
    ) async throws {
        blocks.append(block)
    }
}

private actor CancellingCARSource: PublicRepositoryCARByteSource {
    private let data: Data
    private let cancellationOffset: Int
    private var offset = 0

    init(data: Data, cancellationOffset: Int) {
        self.data = data
        self.cancellationOffset = cancellationOffset
    }

    func read(maximumBytes: Int) async throws -> Data? {
        if offset >= cancellationOffset {
            throw CancellationError()
        }
        guard offset < data.count else { return nil }
        let count = min(
            maximumBytes,
            cancellationOffset - offset,
            data.count - offset
        )
        guard count > 0 else { throw CancellationError() }
        let result = Data(data[offset ..< offset + count])
        offset += count
        return result
    }
}

private struct CancellingVerifier: PublicRepositoryCommitVerifier {
    let signingAlgorithm: PublicRepositorySigningAlgorithm = .p256
    let verificationIdentity = "test:cancelling"
    func verify(
        signature _: Data,
        unsignedCommitBytes _: Data,
        did _: String
    ) async throws {
        throw CancellationError()
    }
}

private struct ImportTestTimeout: Error {}

private struct TimeoutCARSource: PublicRepositoryCARByteSource {
    func read(maximumBytes _: Int) async throws -> Data? {
        throw ImportTestTimeout()
    }
}
