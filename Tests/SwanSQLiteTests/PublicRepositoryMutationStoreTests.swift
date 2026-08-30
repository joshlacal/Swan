import Crypto
import Foundation
import Petrel
import SQLiteNIO
import PetrelRepo
import SwanStorage
@testable import SwanSQLite
import XCTest

final class PublicRepositoryMutationStoreTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let genesisRevision = "3jzfcijpj2z2a"

    func testCommitRechecksPublicBlobReachabilityInsideTransaction() async throws {
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

        let payload = Data("public-reference-fence".utf8)
        let publicReference = try await database.putBlob(
            payload,
            namespace: .public,
            mimeType: "application/octet-stream"
        )
        let loadedInitial = try await database.loadPublicRepositoryState()
        let initial = try XCTUnwrap(loadedInitial)
        let request = try PublicRepositoryMutationRequest(
            id: "public-blob-fence",
            canonicalDigest: Data(repeating: 0x52, count: 32),
            baseCommitCID: initial.commitCID
        )
        let reservation: PublicRepositoryMutationReservation
        switch try await database.reservePublicRepositoryRevision(
            request,
            wallClockMicroseconds: 1_750_000_000_000_000
        ) {
        case let .reserved(value): reservation = value
        case .committed: return XCTFail("public request unexpectedly replayed")
        }
        let path = try PublicRepositoryPath(
            collection: "app.bsky.feed.post",
            recordKey: "blob-fence"
        )
        let blobCID = try CID.parse(publicReference.cid)
        let prepared = try await PublicRepositoryEngine.apply(
            repositoryDID: did,
            currentState: initial,
            blocks: database,
            revision: reservation.nextRevision,
            batch: try PublicRepositoryWriteBatch(
                writes: [.create(
                    path: path,
                    record: PublicRecord([
                        "$type": .string("app.bsky.feed.post"),
                        "blob": .link(blobCID),
                    ])
                )],
                expectedCommitCID: initial.commitCID
            ),
            signer: P256PublicRepositoryCommitSigner(privateKey: key)
        )

        try await database.remove(publicReference)
        var failure: Error?
        do {
            _ = try await database.applyPublicRepositoryMutation(
                reservation: reservation,
                prepared: prepared
            )
        } catch {
            failure = error
        }
        XCTAssertEqual(
            failure as? PublicRepositoryMutationStoreError,
            .publicBlobNotReachable
        )
        let indexed = try await database.publicRepositoryRecordCID(for: path)
        XCTAssertNil(indexed)
        try await database.close()
    }

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
        let nowMicros = UInt64(Date().timeIntervalSince1970 * 1_000_000)
        switch try await database.reservePublicRepositoryRevision(
            request,
            wallClockMicroseconds: nowMicros
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
            wallClockMicroseconds: nowMicros
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
                wallClockMicroseconds: nowMicros
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

    func testAbandonReservationRejectsMalformedPersistedDigest() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        let database = try await installedDatabase(root: root, key: key)
        let maybeState = try await database.loadPublicRepositoryState()
        let state = try XCTUnwrap(maybeState)
        let request = try PublicRepositoryMutationRequest(
            id: "malformed-abandon-digest",
            canonicalDigest: Data(repeating: 0x71, count: 32),
            baseCommitCID: state.commitCID
        )
        guard case let .reserved(reservation) = try await database
            .reservePublicRepositoryRevision(request, wallClockMicroseconds: 1)
        else {
            return XCTFail("new request unexpectedly replayed")
        }
        let raw = try await openRawAccountDatabase(root: root)
        _ = try await raw.query("PRAGMA ignore_check_constraints = ON")
        _ = try await raw.query(
            "UPDATE public_repository_mutation_requests SET request_digest = zeroblob(0) WHERE request_id = ?",
            [.text(request.id)]
        )
        try await raw.close()

        await XCTAssertThrowsAsync(
            try await database.abandonPublicRepositoryReservation(reservation)
        ) { error in
            XCTAssertEqual(
                error as? PublicRepositoryMutationStoreError,
                .corruptRepository
            )
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
        for target in 1...7 {
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
                requestID: "rollback-\(target)",
                digestByte: UInt8(0x40 + target),
                rkey: "rollback-\(target)",
                clock: 1_750_000_000_000_000
            )
            XCTAssertEqual(candidate.prepared.newBlocks.count + 4, 7)
            await database.installTestingHooks(SQLiteTestingHooks(
                afterPublicRepositoryMutatingSQL: { index in
                    if index == target { throw InjectedFailure.expected }
                }
            ))
            await XCTAssertThrowsAsync(
                try await database.applyPublicRepositoryMutation(
                    reservation: candidate.reservation,
                    prepared: candidate.prepared,
                    firehose: .init(lifecycleGeneration: 0)
                )
            ) { error in
                XCTAssertEqual(error as? InjectedFailure, .expected)
            }
            try await database.close()

            let reopened = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
            let stateAfterFailure = try await reopened.loadPublicRepositoryState()
            XCTAssertEqual(stateAfterFailure, initial)
            for cid in candidate.prepared.newBlocks.cids {
                let stored = try await reopened.block(for: cid)
                XCTAssertNil(stored)
            }
            let indexed = try await reopened.publicRepositoryRecordCID(
                for: candidate.path
            )
            XCTAssertNil(indexed)
            let outboxAfterFailure = try await reopened.pendingPublicFirehoseOutbox()
            XCTAssertTrue(
                outboxAfterFailure.isEmpty,
                "failure after SQL boundary \(target) persisted an outbox row"
            )
            guard case .reserved = try await reopened.reservePublicRepositoryRevision(
                candidate.reservation.request,
                wallClockMicroseconds: 1
            ) else {
                return XCTFail("rolled-back request was falsely committed")
            }
            try await reopened.close()
        }
    }

    func testReservationFailpointsRollbackAllocatorAndRequestTogether() async throws {
        for target in 1...2 {
            let root = try temporaryDirectory()
            defer { try? FileManager.default.removeItem(at: root) }
            let key = P256.Signing.PrivateKey()
            let database = try await installedDatabase(root: root, key: key)
            let maybeState = try await database.loadPublicRepositoryState()
            let state = try XCTUnwrap(maybeState)
            let request = try PublicRepositoryMutationRequest(
                id: "reserve-failure-\(target)",
                canonicalDigest: Data(repeating: UInt8(target), count: 32),
                baseCommitCID: state.commitCID
            )
            let clock: UInt64 = 1_750_000_000_000_000
            let beforeRaw = try await openRawAccountDatabase(root: root)
            let beforeRequests = try await beforeRaw.query(
                """
                SELECT request_id FROM public_repository_mutation_requests
                WHERE request_id = ?
                """,
                [.text(request.id)]
            )
            XCTAssertTrue(beforeRequests.isEmpty)
            let beforeAllocator = try await beforeRaw.query(
                """
                SELECT highest_value FROM public_repository_revision_allocator
                WHERE singleton = 1
                """
            )
            XCTAssertTrue(beforeAllocator.isEmpty)
            try await beforeRaw.close()
            await database.installTestingHooks(SQLiteTestingHooks(
                afterPublicRepositoryMutatingSQL: { index in
                    if index == target { throw InjectedFailure.expected }
                }
            ))
            await XCTAssertThrowsAsync(
                try await database.reservePublicRepositoryRevision(
                    request,
                    wallClockMicroseconds: clock
                )
            ) {
                XCTAssertEqual($0 as? InjectedFailure, .expected)
            }
            try await database.close()

            let afterRaw = try await openRawAccountDatabase(root: root)
            let afterRequests = try await afterRaw.query(
                """
                SELECT request_id FROM public_repository_mutation_requests
                WHERE request_id = ?
                """,
                [.text(request.id)]
            )
            XCTAssertTrue(
                afterRequests.isEmpty,
                "failure after SQL boundary \(target) persisted the request"
            )
            let afterAllocator = try await afterRaw.query(
                """
                SELECT highest_value FROM public_repository_revision_allocator
                WHERE singleton = 1
                """
            )
            XCTAssertTrue(
                afterAllocator.isEmpty,
                "failure after SQL boundary \(target) persisted the allocator"
            )
            try await afterRaw.close()

            let reopened = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
            guard case let .reserved(reservation) =
                try await reopened.reservePublicRepositoryRevision(
                request,
                wallClockMicroseconds: clock
            ) else {
                return XCTFail("rolled-back reservation persisted")
            }
            XCTAssertEqual(
                reservation.nextRevision,
                expectedRevision(clock << 10)
            )
            try await reopened.close()
        }
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
            """
            INSERT INTO public_repository_revision_allocator(singleton, highest_value)
            VALUES (1, ?)
            ON CONFLICT(singleton) DO UPDATE SET highest_value = excluded.highest_value
            """,
            [.integer(Int.max)]
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

    func testValidMetadataSubstitutionsFailClosedAcrossStateReservationAndReplay() async throws {
        enum StateField {
            case revision
            case commitCID
            case dataCID
        }
        for field in [StateField.revision, .commitCID, .dataCID] {
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
                requestID: "state-substitution",
                digestByte: 0x91,
                rkey: "state-substitution",
                clock: 1_750_000_000_000_000
            )
            _ = try await database.applyPublicRepositoryMutation(
                reservation: candidate.reservation,
                prepared: candidate.prepared
            )
            try await database.close()

            let raw = try await openRawAccountDatabase(root: root)
            switch field {
            case .revision:
                _ = try await raw.query(
                    "UPDATE public_repository_state SET revision = ?",
                    [.text(initial.revision)]
                )
            case .commitCID:
                _ = try await raw.query(
                    "UPDATE public_repository_state SET commit_cid = ?",
                    [.text(candidate.prepared.state.dataCID.string)]
                )
            case .dataCID:
                _ = try await raw.query(
                    "UPDATE public_repository_state SET data_cid = ?",
                    [.text(initial.dataCID.string)]
                )
            }
            try await raw.close()

            let corrupted = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
            await XCTAssertThrowsAsync(
                try await corrupted.loadPublicRepositoryState()
            ) {
                XCTAssertEqual(
                    $0 as? PublicRepositoryMutationStoreError,
                    .corruptRepository
                )
            }
            try await corrupted.close()
        }

        let reservationRoot = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: reservationRoot) }
        let reservationKey = P256.Signing.PrivateKey()
        let reservationDatabase = try await installedDatabase(
            root: reservationRoot,
            key: reservationKey
        )
        let maybeReservationState = try await reservationDatabase
            .loadPublicRepositoryState()
        let reservationState = try XCTUnwrap(maybeReservationState)
        let reservationRequest = try PublicRepositoryMutationRequest(
            id: "reserved-next-substitution",
            canonicalDigest: Data(repeating: 0x92, count: 32),
            baseCommitCID: reservationState.commitCID
        )
        _ = try await reservationDatabase.reservePublicRepositoryRevision(
            reservationRequest,
            wallClockMicroseconds: 1_750_000_000_000_000
        )
        try await reservationDatabase.close()
        let reservationRaw = try await openRawAccountDatabase(root: reservationRoot)
        _ = try await reservationRaw.query(
            """
            UPDATE public_repository_mutation_requests
            SET next_revision = ? WHERE request_id = ?
            """,
            [.text(genesisRevision), .text(reservationRequest.id)]
        )
        try await reservationRaw.close()
        let corruptedReservation = try await SQLiteAccountDatabase(
            dataDirectory: reservationRoot,
            did: did
        )
        await XCTAssertThrowsAsync(
            try await corruptedReservation.reservePublicRepositoryRevision(
                reservationRequest,
                wallClockMicroseconds: 1
            )
        ) {
            XCTAssertEqual(
                $0 as? PublicRepositoryMutationStoreError,
                .corruptRepository
            )
        }
        try await corruptedReservation.close()

        for column in [
            "committed_commit_cid",
            "committed_data_cid",
            "committed_projection",
        ] {
            let root = try temporaryDirectory()
            defer { try? FileManager.default.removeItem(at: root) }
            let key = P256.Signing.PrivateKey()
            let nowMicros = UInt64(Date().timeIntervalSince1970 * 1_000_000)
            let database = try await installedDatabase(root: root, key: key)
            let maybeState = try await database.loadPublicRepositoryState()
            let state = try XCTUnwrap(maybeState)
            let candidate = try await prepareCreate(
                database: database,
                state: state,
                key: key,
                requestID: "replay-\(column)",
                digestByte: 0x93,
                rkey: "replay-\(column)",
                clock: nowMicros
            )
            _ = try await database.applyPublicRepositoryMutation(
                reservation: candidate.reservation,
                prepared: candidate.prepared
            )
            try await database.close()
            let raw = try await openRawAccountDatabase(root: root)
            if column == "committed_projection" {
                let substituted = Data("[]".utf8)
                _ = try await raw.query(
                    """
                    UPDATE public_repository_mutation_requests
                    SET committed_projection = ?, committed_projection_digest = ?
                    WHERE request_id = ?
                    """,
                    [
                        substituted.sqliteData!,
                        Data(SHA256.hash(data: substituted)).sqliteData!,
                        .text(candidate.reservation.request.id),
                    ]
                )
            } else {
                let substituted = column == "committed_commit_cid"
                    ? candidate.prepared.state.dataCID.string
                    : candidate.prepared.state.commitCID.string
                _ = try await raw.query(
                    """
                    UPDATE public_repository_mutation_requests
                    SET \(column) = ? WHERE request_id = ?
                    """,
                    [.text(substituted), .text(candidate.reservation.request.id)]
                )
            }
            try await raw.close()
            let corrupted = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
            await XCTAssertThrowsAsync(
                try await corrupted.reservePublicRepositoryRevision(
                    candidate.reservation.request,
                    wallClockMicroseconds: nowMicros
                )
            ) {
                XCTAssertEqual(
                    $0 as? PublicRepositoryMutationStoreError,
                    .corruptRepository
                )
            }
            try await corrupted.close()
        }
    }

    func testLegacyRequestTableUpgradeIsEmptyOnlyAndFailsClosedWithRows() async throws {
        let emptyRoot = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: emptyRoot) }
        let emptyKey = P256.Signing.PrivateKey()
        let emptyDatabase = try await installedDatabase(root: emptyRoot, key: emptyKey)
        try await emptyDatabase.close()
        let emptyRaw = try await openRawAccountDatabase(root: emptyRoot)
        try await replaceRequestTableWithLegacySchema(connection: emptyRaw)
        try await emptyRaw.close()

        let upgraded = try await SQLiteAccountDatabase(dataDirectory: emptyRoot, did: did)
        let maybeState = try await upgraded.loadPublicRepositoryState()
        let state = try XCTUnwrap(maybeState)
        let request = try PublicRepositoryMutationRequest(
            id: "after-empty-upgrade",
            canonicalDigest: Data(repeating: 0xa1, count: 32),
            baseCommitCID: state.commitCID
        )
        guard case .reserved = try await upgraded.reservePublicRepositoryRevision(
            request,
            wallClockMicroseconds: 1
        ) else {
            try await upgraded.close()
            return XCTFail("empty legacy request table did not upgrade")
        }
        try await upgraded.close()

        let occupiedRoot = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: occupiedRoot) }
        let occupiedKey = P256.Signing.PrivateKey()
        let occupiedDatabase = try await installedDatabase(
            root: occupiedRoot,
            key: occupiedKey
        )
        let maybeOccupiedState = try await occupiedDatabase.loadPublicRepositoryState()
        let occupiedState = try XCTUnwrap(maybeOccupiedState)
        try await occupiedDatabase.close()
        let occupiedRaw = try await openRawAccountDatabase(root: occupiedRoot)
        try await replaceRequestTableWithLegacySchema(connection: occupiedRaw)
        _ = try await occupiedRaw.query(
            """
            INSERT INTO public_repository_mutation_requests(
                request_id, request_digest, base_commit_cid, base_revision,
                next_revision, status
            ) VALUES (?, ?, ?, ?, ?, 'reserved')
            """,
            [
                .text("legacy-row"),
                Data(repeating: 0xa2, count: 32).sqliteData!,
                .text(occupiedState.commitCID.string),
                .text(occupiedState.revision),
                .text("3jzfcijpj2z2b"),
            ]
        )
        try await occupiedRaw.close()
        await XCTAssertThrowsAsync(
            try await SQLiteAccountDatabase(dataDirectory: occupiedRoot, did: did)
        ) {
            XCTAssertEqual(
                $0 as? SQLiteRepositoryError,
                .corruptDatabase(
                    "legacy public repository request rows require offline recovery"
                )
            )
        }
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

    private func openRawAccountDatabase(root: URL) async throws -> SQLiteConnection {
        try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(in: root, did: did).path)
        )
    }

    private func expectedRevision(_ raw: UInt64) -> String {
        let alphabet = Array("234567abcdefghijklmnopqrstuvwxyz".utf8)
        var value = raw
        var bytes = Array(repeating: UInt8(ascii: "2"), count: 13)
        for index in stride(from: 12, through: 0, by: -1) {
            bytes[index] = alphabet[Int(value & 31)]
            value >>= 5
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    private func replaceRequestTableWithLegacySchema(
        connection: SQLiteConnection
    ) async throws {
        _ = try await connection.query(
            "DROP TABLE public_repository_mutation_requests"
        )
        _ = try await connection.query(
            """
            CREATE TABLE public_repository_mutation_requests (
                request_id TEXT PRIMARY KEY,
                request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
                base_commit_cid TEXT NOT NULL,
                base_revision TEXT NOT NULL,
                next_revision TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL CHECK(status IN ('reserved', 'committed')),
                committed_commit_cid TEXT,
                committed_data_cid TEXT,
                committed_projection BLOB,
                committed_projection_digest BLOB CHECK(
                    committed_projection_digest IS NULL
                    OR length(committed_projection_digest) = 32
                ),
                CHECK(
                    (status = 'reserved' AND committed_commit_cid IS NULL
                        AND committed_data_cid IS NULL AND committed_projection IS NULL
                        AND committed_projection_digest IS NULL)
                    OR
                    (status = 'committed' AND committed_commit_cid IS NOT NULL
                        AND committed_data_cid IS NOT NULL AND committed_projection IS NOT NULL
                        AND committed_projection_digest IS NOT NULL)
                )
            )
            """
        )
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "PublicRepositoryMutationStoreTests-\(UUID().uuidString)")
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
