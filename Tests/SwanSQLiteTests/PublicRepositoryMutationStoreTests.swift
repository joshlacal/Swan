import Crypto
import Foundation
import Petrel
import SQLiteNIO
import SwanPublicRepository
import SwanStorage
@testable import SwanSQLite
import XCTest

final class PublicRepositoryMutationStoreTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let genesisRevision = "3jzfcijpj2z2a"

    func testGenesisBecomesRepositoryTruthAndPreparedCreateSurvivesReopen() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let genesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: genesisRevision,
            signingKey: key
        )
        _ = try await database.installPublicRepositoryGenesis(
            genesis,
            signingPublicKey: key.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_750_000_000)
        )

        let maybeInitial = try await database.loadPublicRepositoryState()
        let initial = try XCTUnwrap(maybeInitial)
        XCTAssertEqual(initial.did, did)
        XCTAssertEqual(initial.revision, genesisRevision)
        XCTAssertEqual(initial.commitCID, genesis.commitCID)
        let storedCommit = try await database.block(for: genesis.commitCID)
        let storedMST = try await database.block(for: genesis.emptyMSTCID)
        XCTAssertEqual(storedCommit, genesis.signedCommit)
        XCTAssertEqual(storedMST, genesis.emptyMST)

        let request = try PublicRepositoryMutationRequest(
            id: "create-1",
            canonicalDigest: Data(repeating: 0x41, count: 32),
            baseCommitCID: initial.commitCID
        )
        let reservation: PublicRepositoryMutationReservation
        switch try await database.reservePublicRepositoryRevision(
            request,
            wallClockMicroseconds: 1_750_000_000_000_000
        ) {
        case let .reserved(value):
            reservation = value
        case .committed:
            return XCTFail("new request unexpectedly replayed")
        }
        let path = try PublicRepositoryPath(
            collection: "app.bsky.feed.post",
            recordKey: "first"
        )
        let batch = try PublicRepositoryWriteBatch(
            writes: [
                .create(
                    path: path,
                    record: PublicRecord([
                        "$type": .string("app.bsky.feed.post"),
                        "text": .string("hello"),
                    ])
                ),
            ],
            expectedCommitCID: initial.commitCID
        )
        let prepared = try await PublicRepositoryEngine.apply(
            repositoryDID: did,
            currentState: initial,
            blocks: database,
            revision: reservation.nextRevision,
            batch: batch,
            signer: P256PublicRepositoryCommitSigner(privateKey: key)
        )
        let committed = try await database.applyPublicRepositoryMutation(
            reservation: reservation,
            prepared: prepared
        )
        let repeatedGenesis = try await database.installPublicRepositoryGenesis(
            genesis,
            signingPublicKey: key.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_750_000_100)
        )
        XCTAssertTrue(repeatedGenesis.wasAlreadyInstalled)
        let stateAfterGenesisReplay = try await database.loadPublicRepositoryState()
        XCTAssertEqual(stateAfterGenesisReplay, prepared.state)
        XCTAssertEqual(committed.state, prepared.state)
        let indexed = try await database.publicRepositoryRecordCID(for: path)
        XCTAssertEqual(indexed, prepared.recordResults[0].recordCID)
        try await database.close()

        let reopened = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let reopenedState = try await reopened.loadPublicRepositoryState()
        XCTAssertEqual(reopenedState, prepared.state)
        let validated = try await RepositoryMSTValidation.validate(
            rootCID: prepared.state.dataCID,
            blocks: reopened
        )
        XCTAssertEqual(validated.leaves.count, 1)
        let reopenedIndexed = try await reopened.publicRepositoryRecordCID(for: path)
        XCTAssertEqual(reopenedIndexed, prepared.recordResults[0].recordCID)
        switch try await reopened.reservePublicRepositoryRevision(
            request,
            wallClockMicroseconds: 1
        ) {
        case .reserved:
            XCTFail("committed request was reserved again")
        case let .committed(replayed):
            XCTAssertEqual(replayed, committed)
        }
        try await reopened.close()

        let raw = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(in: root, did: did).path)
        )
        _ = try await raw.query(
            """
            UPDATE public_repository_mutation_requests
            SET committed_projection = ? WHERE request_id = ?
            """,
            [Data([0x00]).sqliteData!, .text(request.id)]
        )
        try await raw.close()
        let corruptedReplay = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: did
        )
        await XCTAssertThrowsAsync(
            try await corruptedReplay.reservePublicRepositoryRevision(
                request,
                wallClockMicroseconds: 1
            )
        ) {
            XCTAssertEqual(
                $0 as? PublicRepositoryMutationStoreError,
                .corruptRepository
            )
        }
        try await corruptedReplay.close()
    }

    func testReservationsAreMonotonicAcrossBurstRestartAndClockRollback() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        var database = try await installedDatabase(root: root, key: key)
        let maybeState = try await database.loadPublicRepositoryState()
        let state = try XCTUnwrap(maybeState)
        let pendingRequest = try PublicRepositoryMutationRequest(
            id: "pending-restart",
            canonicalDigest: Data(repeating: 0x29, count: 32),
            baseCommitCID: state.commitCID
        )
        guard case let .reserved(pendingReservation) = try await database.reservePublicRepositoryRevision(
            pendingRequest,
            wallClockMicroseconds: 1_750_000_000_000_000
        ) else {
            return XCTFail("new pending request replayed")
        }
        var revisions: [PublicRepositoryTID] = []
        for index in 0..<1_030 {
            let request = try PublicRepositoryMutationRequest(
                id: "burst-\(index)",
                canonicalDigest: Data(SHA256.hash(data: Data("burst-\(index)".utf8))),
                baseCommitCID: state.commitCID
            )
            guard case let .reserved(reservation) = try await database.reservePublicRepositoryRevision(
                request,
                wallClockMicroseconds: 1_750_000_000_000_000
            ) else {
                return XCTFail("new request replayed")
            }
            revisions.append(try PublicRepositoryTID(reservation.nextRevision))
        }
        XCTAssertEqual(revisions, revisions.sorted())
        XCTAssertEqual(Set(revisions).count, revisions.count)
        try await database.close()

        database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        guard case let .reserved(replayedPending) = try await database.reservePublicRepositoryRevision(
            pendingRequest,
            wallClockMicroseconds: 1
        ) else {
            return XCTFail("uncommitted reservation became committed")
        }
        XCTAssertEqual(replayedPending, pendingReservation)
        let rollbackRequest = try PublicRepositoryMutationRequest(
            id: "after-restart",
            canonicalDigest: Data(repeating: 0x88, count: 32),
            baseCommitCID: state.commitCID
        )
        guard case let .reserved(afterRestart) = try await database.reservePublicRepositoryRevision(
            rollbackRequest,
            wallClockMicroseconds: 1
        ) else {
            return XCTFail("new request replayed")
        }
        XCTAssertLessThan(revisions.last!, try PublicRepositoryTID(afterRestart.nextRevision))
        try await database.close()
    }

    func testRequestReuseWithDifferentDigestFailsClosed() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        let database = try await installedDatabase(root: root, key: key)
        let maybeState = try await database.loadPublicRepositoryState()
        let state = try XCTUnwrap(maybeState)
        let first = try PublicRepositoryMutationRequest(
            id: "same",
            canonicalDigest: Data(repeating: 0x11, count: 32),
            baseCommitCID: state.commitCID
        )
        _ = try await database.reservePublicRepositoryRevision(
            first,
            wallClockMicroseconds: 10
        )
        let conflicting = try PublicRepositoryMutationRequest(
            id: "same",
            canonicalDigest: Data(repeating: 0x22, count: 32),
            baseCommitCID: state.commitCID
        )
        await XCTAssertThrowsAsync(
            try await database.reservePublicRepositoryRevision(
                conflicting,
                wallClockMicroseconds: 10
            )
        ) { error in
            XCTAssertEqual(error as? PublicRepositoryMutationStoreError, .conflictingRequestReuse)
        }
        try await database.close()
    }

    func testTwoConnectionsRaceFromOneBaseWithExactlyOneAtomicWinner() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        let first = try await installedDatabase(root: root, key: key)
        let second = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let maybeInitial = try await first.loadPublicRepositoryState()
        let initial = try XCTUnwrap(maybeInitial)
        let left = try await prepareCreate(
            database: first,
            state: initial,
            key: key,
            requestID: "race-left",
            digestByte: 0x31,
            rkey: "left",
            clock: 1_750_000_000_000_000
        )
        let right = try await prepareCreate(
            database: second,
            state: initial,
            key: key,
            requestID: "race-right",
            digestByte: 0x32,
            rkey: "right",
            clock: 1_750_000_000_000_000
        )
        let outcomes = await withTaskGroup(
            of: Result<CommittedPublicRepositoryMutation, any Error>.self
        ) { group in
            group.addTask {
                do {
                    return .success(try await first.applyPublicRepositoryMutation(
                        reservation: left.reservation,
                        prepared: left.prepared
                    ))
                } catch { return .failure(error) }
            }
            group.addTask {
                do {
                    return .success(try await second.applyPublicRepositoryMutation(
                        reservation: right.reservation,
                        prepared: right.prepared
                    ))
                } catch { return .failure(error) }
            }
            return await group.reduce(into: []) { $0.append($1) }
        }
        XCTAssertEqual(outcomes.compactMap { try? $0.get() }.count, 1)
        let failures = outcomes.compactMap { result -> (any Error)? in
            guard case let .failure(error) = result else { return nil }
            return error
        }
        XCTAssertEqual(failures.count, 1)
        XCTAssertEqual(
            failures.first as? PublicRepositoryMutationStoreError,
            .commitCASConflict
        )
        let maybeFinalState = try await first.loadPublicRepositoryState()
        let finalState = try XCTUnwrap(maybeFinalState)
        let leftWon = finalState.commitCID == left.prepared.state.commitCID
        let loser = leftWon ? right : left
        let winner = leftWon ? left : right
        XCTAssertEqual(finalState, winner.prepared.state)
        let loserBlock = try await first.block(for: loser.prepared.state.commitCID)
        let loserIndex = try await first.publicRepositoryRecordCID(for: loser.path)
        let winnerIndex = try await first.publicRepositoryRecordCID(for: winner.path)
        XCTAssertNil(loserBlock)
        XCTAssertNil(loserIndex)
        XCTAssertEqual(winnerIndex, winner.prepared.recordResults[0].recordCID)
        try await first.close()
        try await second.close()
    }

    func testInjectedFailureRollsBackBlocksIndexStateAndReservationStatus() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        let database = try await installedDatabase(root: root, key: key)
        let maybeInitial = try await database.loadPublicRepositoryState()
        let initial = try XCTUnwrap(maybeInitial)
        let candidate = try await prepareCreate(
            database: database,
            state: initial,
            key: key,
            requestID: "rollback",
            digestByte: 0x44,
            rkey: "rollback",
            clock: 1_750_000_000_000_000
        )
        await database.installTestingHooks(SQLiteTestingHooks(
            beforePublicRepositoryCommit: { throw InjectedFailure.expected }
        ))
        await XCTAssertThrowsAsync(
            try await database.applyPublicRepositoryMutation(
                reservation: candidate.reservation,
                prepared: candidate.prepared
            )
        ) { error in
            XCTAssertEqual(error as? InjectedFailure, .expected)
        }
        await database.installTestingHooks(SQLiteTestingHooks())

        let stateAfterFailure = try await database.loadPublicRepositoryState()
        let blockAfterFailure = try await database.block(for: candidate.prepared.state.commitCID)
        let indexAfterFailure = try await database.publicRepositoryRecordCID(for: candidate.path)
        XCTAssertEqual(stateAfterFailure, initial)
        XCTAssertNil(blockAfterFailure)
        XCTAssertNil(indexAfterFailure)
        guard case .reserved = try await database.reservePublicRepositoryRevision(
            candidate.reservation.request,
            wallClockMicroseconds: 1
        ) else {
            return XCTFail("rolled-back request was falsely committed")
        }
        try await database.close()
    }

    func testInvalidRequestsAndOutOfAllocatableRangeFailTyped() async throws {
        let genesisCID = try CID.parse(PublicRepositoryGenesisCodec.canonicalEmptyMSTCID)
        XCTAssertThrowsError(try PublicRepositoryMutationRequest(
            id: "",
            canonicalDigest: Data(repeating: 0, count: 32),
            baseCommitCID: genesisCID
        )) {
            XCTAssertEqual($0 as? PublicRepositoryMutationStoreError, .invalidRequest)
        }
        XCTAssertThrowsError(try PublicRepositoryMutationRequest(
            id: "bad-digest",
            canonicalDigest: Data(repeating: 0, count: 31),
            baseCommitCID: genesisCID
        )) {
            XCTAssertEqual($0 as? PublicRepositoryMutationStoreError, .invalidRequestDigest)
        }

        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        let database = try await installedDatabase(root: root, key: key)
        let maybeState = try await database.loadPublicRepositoryState()
        let state = try XCTUnwrap(maybeState)
        let wrongBase = try PublicRepositoryMutationRequest(
            id: "wrong-base",
            canonicalDigest: Data(repeating: 0x66, count: 32),
            baseCommitCID: genesisCID
        )
        await XCTAssertThrowsAsync(
            try await database.reservePublicRepositoryRevision(
                wrongBase,
                wallClockMicroseconds: 1
            )
        ) {
            XCTAssertEqual(
                $0 as? PublicRepositoryMutationStoreError,
                .commitCASConflict
            )
        }
        try await database.close()
        let raw = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(in: root, did: did).path)
        )
        _ = try await raw.query(
            "UPDATE public_repository_state SET revision = 'jzzzzzzzzzzzz'"
        )
        try await raw.close()
        let reopened = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let request = try PublicRepositoryMutationRequest(
            id: "exhausted",
            canonicalDigest: Data(repeating: 0x77, count: 32),
            baseCommitCID: state.commitCID
        )
        await XCTAssertThrowsAsync(
            try await reopened.reservePublicRepositoryRevision(
                request,
                wallClockMicroseconds: 1
            )
        ) {
            XCTAssertEqual($0 as? PublicRepositoryMutationStoreError, .revisionExhausted)
        }
        try await reopened.close()
    }

    func testMixedUpdateDeleteProjectionSurvivesReopenAndCorruptionFailsClosed() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        let database = try await installedDatabase(root: root, key: key)
        let maybeInitial = try await database.loadPublicRepositoryState()
        let initial = try XCTUnwrap(maybeInitial)
        let firstPath = try PublicRepositoryPath(
            collection: "app.bsky.feed.post",
            recordKey: "update-me"
        )
        let secondPath = try PublicRepositoryPath(
            collection: "app.bsky.feed.post",
            recordKey: "delete-me"
        )
        let createRequest = try PublicRepositoryMutationRequest(
            id: "mixed-create",
            canonicalDigest: Data(repeating: 0x51, count: 32),
            baseCommitCID: initial.commitCID
        )
        guard case let .reserved(createReservation) = try await database.reservePublicRepositoryRevision(
            createRequest,
            wallClockMicroseconds: 1_750_000_000_000_000
        ) else { return XCTFail("unexpected replay") }
        let creates = try PublicRepositoryWriteBatch(
            writes: [
                .create(path: firstPath, record: [
                    "$type": .string("app.bsky.feed.post"),
                    "text": .string("before"),
                ]),
                .create(path: secondPath, record: [
                    "$type": .string("app.bsky.feed.post"),
                    "text": .string("delete"),
                ]),
            ],
            expectedCommitCID: initial.commitCID
        )
        let created = try await PublicRepositoryEngine.apply(
            repositoryDID: did,
            currentState: initial,
            blocks: database,
            revision: createReservation.nextRevision,
            batch: creates,
            signer: P256PublicRepositoryCommitSigner(privateKey: key)
        )
        _ = try await database.applyPublicRepositoryMutation(
            reservation: createReservation,
            prepared: created
        )

        let updateRequest = try PublicRepositoryMutationRequest(
            id: "mixed-change",
            canonicalDigest: Data(repeating: 0x52, count: 32),
            baseCommitCID: created.state.commitCID
        )
        guard case let .reserved(updateReservation) = try await database.reservePublicRepositoryRevision(
            updateRequest,
            wallClockMicroseconds: 1
        ) else { return XCTFail("unexpected replay") }
        let changed = try await PublicRepositoryEngine.apply(
            repositoryDID: did,
            currentState: created.state,
            blocks: database,
            revision: updateReservation.nextRevision,
            batch: try PublicRepositoryWriteBatch(
                writes: [
                    .update(
                        path: firstPath,
                        record: [
                            "$type": .string("app.bsky.feed.post"),
                            "text": .string("after"),
                        ],
                        expectedRecordCID: created.recordResults[0].recordCID
                    ),
                    .delete(
                        path: secondPath,
                        expectedRecordCID: created.recordResults[1].recordCID
                    ),
                ],
                expectedCommitCID: created.state.commitCID
            ),
            signer: P256PublicRepositoryCommitSigner(privateKey: key)
        )
        _ = try await database.applyPublicRepositoryMutation(
            reservation: updateReservation,
            prepared: changed
        )
        try await database.close()

        let reopened = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let updatedCID = try await reopened.publicRepositoryRecordCID(for: firstPath)
        let deletedCID = try await reopened.publicRepositoryRecordCID(for: secondPath)
        XCTAssertEqual(updatedCID, changed.recordResults[0].recordCID)
        XCTAssertNil(deletedCID)
        try await reopened.close()

        let raw = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(in: root, did: did).path)
        )
        _ = try await raw.query(
            """
            UPDATE public_repository_record_index SET record_cid = ?
            WHERE collection = ? AND rkey = ?
            """,
            [
                .text(PublicRepositoryGenesisCodec.canonicalEmptyMSTCID),
                .text(firstPath.collection),
                .text(firstPath.recordKey),
            ]
        )
        try await raw.close()
        let corrupted = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        await XCTAssertThrowsAsync(
            try await corrupted.publicRepositoryRecordCID(for: firstPath)
        ) {
            XCTAssertEqual(
                $0 as? PublicRepositoryMutationStoreError,
                .corruptRepository
            )
        }
        await XCTAssertThrowsAsync(try await corrupted.verifyPublicRepositoryProjection()) {
            XCTAssertEqual(
                $0 as? PublicRepositoryMutationStoreError,
                .corruptRepository
            )
        }
        try await corrupted.close()
    }

    func testRepositoryTruthUsesAccountWALAndNeverControlDatabase() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        let account = try await installedDatabase(root: root, key: key)
        let expectedPath = SQLiteLayout.accountDatabase(in: root, did: did)
        XCTAssertTrue(FileManager.default.fileExists(atPath: expectedPath.path))
        try await account.close()
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        try await control.close()

        let accountRaw = try await SQLiteConnection.open(
            storage: .file(path: expectedPath.path)
        )
        let journal = try await accountRaw.query("PRAGMA journal_mode")
        XCTAssertEqual(journal.first?.column("journal_mode")?.string?.lowercased(), "wal")
        let accountTables = try await accountRaw.query(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name LIKE 'public_repository_%'
            """
        )
        XCTAssertGreaterThanOrEqual(accountTables.count, 5)
        try await accountRaw.close()

        let controlRaw = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.controlDatabase(in: root).path)
        )
        let leakedTables = try await controlRaw.query(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name LIKE 'public_repository_%'
            """
        )
        XCTAssertTrue(leakedTables.isEmpty)
        try await controlRaw.close()
    }

    private func installedDatabase(
        root: URL,
        key: P256.Signing.PrivateKey
    ) async throws -> SQLiteAccountDatabase {
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let genesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: genesisRevision,
            signingKey: key
        )
        _ = try await database.installPublicRepositoryGenesis(
            genesis,
            signingPublicKey: key.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
        return database
    }

    private struct PreparedCandidate {
        let reservation: PublicRepositoryMutationReservation
        let prepared: PreparedPublicRepositoryMutation
        let path: PublicRepositoryPath
    }

    private func prepareCreate(
        database: SQLiteAccountDatabase,
        state: PublicRepositoryState,
        key: P256.Signing.PrivateKey,
        requestID: String,
        digestByte: UInt8,
        rkey: String,
        clock: UInt64
    ) async throws -> PreparedCandidate {
        let request = try PublicRepositoryMutationRequest(
            id: requestID,
            canonicalDigest: Data(repeating: digestByte, count: 32),
            baseCommitCID: state.commitCID
        )
        guard case let .reserved(reservation) = try await database.reservePublicRepositoryRevision(
            request,
            wallClockMicroseconds: clock
        ) else {
            throw PublicRepositoryMutationStoreError.conflictingRequestReuse
        }
        let path = try PublicRepositoryPath(
            collection: "app.bsky.feed.post",
            recordKey: rkey
        )
        let batch = try PublicRepositoryWriteBatch(
            writes: [.create(
                path: path,
                record: [
                    "$type": .string("app.bsky.feed.post"),
                    "text": .string(rkey),
                ]
            )],
            expectedCommitCID: state.commitCID
        )
        return PreparedCandidate(
            reservation: reservation,
            prepared: try await PublicRepositoryEngine.apply(
                repositoryDID: did,
                currentState: state,
                blocks: database,
                revision: reservation.nextRevision,
                batch: batch,
                signer: P256PublicRepositoryCommitSigner(privateKey: key)
            ),
            path: path
        )
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPublicRepositoryMutationStoreTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        return root
    }
}

private enum InjectedFailure: Error, Equatable {
    case expected
}

private func XCTAssertThrowsAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ handler: (any Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("expected error", file: file, line: line)
    } catch {
        handler(error)
    }
}
