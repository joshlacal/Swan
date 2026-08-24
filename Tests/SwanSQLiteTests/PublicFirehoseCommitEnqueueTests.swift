import Crypto
import Foundation
import Petrel
import PetrelFirehose
import PetrelRepo
import SwanStorage
import XCTest
@testable import SwanSQLite

final class PublicFirehoseCommitEnqueueTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let genesisRevision = "3jzfcijpj2z2a"

    private struct PreparedCandidate {
        let reservation: PublicRepositoryMutationReservation
        let prepared: PreparedPublicRepositoryMutation
        let paths: [PublicRepositoryPath]
    }

    func testOrdinaryWriteEnqueuesOneCommitEventWithFinalMaterial() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        let database = try await installedDatabase(root: root, key: key)
        defer { Task { try? await database.close() } }
        let loadedState = try await database.loadPublicRepositoryState()
        let initial = try XCTUnwrap(loadedState)

        let candidate = try await prepareWrites(
            database: database,
            state: initial,
            key: key,
            requestID: "commit-enqueue-1",
            digestByte: 0x10,
            clock: 1_750_000_000_000_000,
            writes: [
                .create(
                    path: try PublicRepositoryPath(
                        collection: "app.bsky.feed.post",
                        recordKey: "first"
                    ),
                    record: record("first")
                ),
            ]
        )
        _ = try await database.applyPublicRepositoryMutation(
            reservation: candidate.reservation,
            prepared: candidate.prepared,
            firehose: .init(lifecycleGeneration: 0)
        )

        let pending = try await database.pendingPublicFirehoseOutbox()
        XCTAssertEqual(pending.count, 1)
        let row = try XCTUnwrap(pending.first)
        XCTAssertEqual(row.kind, .commit)
        XCTAssertEqual(row.lifecycleGeneration, 0)
        XCTAssertEqual(
            row.sourceKey,
            PublicFirehoseSourceKey.commit(
                did: did,
                commitCID: candidate.prepared.state.commitCID.string
            )
        )
        XCTAssertFalse(row.carBytes.isEmpty)

        let material = try JSONDecoder().decode(
            PublicFirehoseCommitMaterial.self,
            from: row.payload
        )
        XCTAssertEqual(material.did, did)
        XCTAssertEqual(material.rev, candidate.prepared.state.revision)
        XCTAssertEqual(material.since, initial.revision)
        XCTAssertEqual(material.commitCID, candidate.prepared.state.commitCID.string)
        XCTAssertEqual(material.prevDataCID, initial.dataCID.string)
        XCTAssertEqual(material.ops.count, 1)
        XCTAssertEqual(material.ops[0].action, .create)
        XCTAssertEqual(material.ops[0].path, "app.bsky.feed.post/first")
        XCTAssertNotNil(material.ops[0].cid)
        XCTAssertNil(material.ops[0].prev)
    }

    func testRepeatedRequestReplayKeepsExactlyOneSourceRow() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        let database = try await installedDatabase(root: root, key: key)
        defer { Task { try? await database.close() } }
        let loadedState = try await database.loadPublicRepositoryState()
        let initial = try XCTUnwrap(loadedState)
        let candidate = try await prepareWrites(
            database: database,
            state: initial,
            key: key,
            requestID: "commit-replay-1",
            digestByte: 0x11,
            clock: 1_750_000_000_000_000,
            writes: [
                .create(
                    path: try PublicRepositoryPath(
                        collection: "app.bsky.feed.post",
                        recordKey: "replay"
                    ),
                    record: record("replay")
                ),
            ]
        )
        let first = try await database.applyPublicRepositoryMutation(
            reservation: candidate.reservation,
            prepared: candidate.prepared,
            firehose: .init(lifecycleGeneration: 0)
        )
        let replayed = try await database.applyPublicRepositoryMutation(
            reservation: candidate.reservation,
            prepared: candidate.prepared,
            firehose: .init(lifecycleGeneration: 0)
        )
        XCTAssertEqual(replayed, first)
        let pending = try await database.pendingPublicFirehoseOutbox()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending.first?.kind, .commit)
    }

    func testMultiOpBatchMapsActionsByExplicitSwitch() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        let database = try await installedDatabase(root: root, key: key)
        defer { Task { try? await database.close() } }
        let loadedState = try await database.loadPublicRepositoryState()
        let initial = try XCTUnwrap(loadedState)

        let createPathA = try PublicRepositoryPath(
            collection: "app.bsky.feed.post",
            recordKey: "aaa"
        )
        let createPathB = try PublicRepositoryPath(
            collection: "app.bsky.feed.post",
            recordKey: "bbb"
        )
        let create = try await prepareWrites(
            database: database,
            state: initial,
            key: key,
            requestID: "multi-op-create",
            digestByte: 0x12,
            clock: 1_750_000_000_000_000,
            writes: [
                .create(path: createPathA, record: record("aaa")),
                .create(path: createPathB, record: record("bbb")),
            ]
        )
        _ = try await database.applyPublicRepositoryMutation(
            reservation: create.reservation,
            prepared: create.prepared,
            firehose: .init(lifecycleGeneration: 0)
        )
        let loadedCreated = try await database.loadPublicRepositoryState()
        let createdState = try XCTUnwrap(loadedCreated)
        let loadedRecordCIDA = try await database.publicRepositoryRecordCID(for: createPathA)
        let loadedRecordCIDB = try await database.publicRepositoryRecordCID(for: createPathB)
        let recordCIDA = try XCTUnwrap(loadedRecordCIDA)
        let recordCIDB = try XCTUnwrap(loadedRecordCIDB)

        let updateDelete = try await prepareWrites(
            database: database,
            state: createdState,
            key: key,
            requestID: "multi-op-update-delete",
            digestByte: 0x13,
            clock: 1_750_000_000_000_001,
            writes: [
                .update(path: createPathA, record: record("aaa-updated"), expectedRecordCID: recordCIDA),
                .delete(path: createPathB, expectedRecordCID: recordCIDB),
            ]
        )
        _ = try await database.applyPublicRepositoryMutation(
            reservation: updateDelete.reservation,
            prepared: updateDelete.prepared,
            firehose: .init(lifecycleGeneration: 0)
        )

        let pending = try await database.pendingPublicFirehoseOutbox()
        XCTAssertEqual(pending.count, 2)
        let second = try XCTUnwrap(pending.last)
        let material = try JSONDecoder().decode(
            PublicFirehoseCommitMaterial.self,
            from: second.payload
        )
        XCTAssertEqual(material.ops.count, 2)
        XCTAssertEqual(material.ops[0].action, .update)
        XCTAssertEqual(material.ops[0].path, "app.bsky.feed.post/aaa")
        XCTAssertNotNil(material.ops[0].cid)
        XCTAssertEqual(material.ops[0].prev, recordCIDA.string)
        XCTAssertEqual(material.ops[1].action, .delete)
        XCTAssertEqual(material.ops[1].path, "app.bsky.feed.post/bbb")
        XCTAssertNil(material.ops[1].cid)
        XCTAssertEqual(material.ops[1].prev, recordCIDB.string)
    }

    func testOutboxConflictRollsBackTheWholeRepositoryTransaction() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        let database = try await installedDatabase(root: root, key: key)
        defer { Task { try? await database.close() } }
        let loadedInitial = try await database.loadPublicRepositoryState()
        let initial = try XCTUnwrap(loadedInitial)
        let candidate = try await prepareWrites(
            database: database,
            state: initial,
            key: key,
            requestID: "conflict-rollback",
            digestByte: 0x14,
            clock: 1_750_000_000_000_000,
            writes: [
                .create(
                    path: try PublicRepositoryPath(
                        collection: "app.bsky.feed.post",
                        recordKey: "conflict"
                    ),
                    record: record("conflict")
                ),
            ]
        )
        let conflictingKey = PublicFirehoseSourceKey.commit(
            did: did,
            commitCID: candidate.prepared.state.commitCID.string
        )
        let conflictingPayload = try JSONEncoder().encode(
            PublicFirehoseCommitMaterial(
                did: did,
                rev: "3different",
                since: nil,
                commitCID: candidate.prepared.state.commitCID.string,
                prevDataCID: nil,
                ops: [],
                time: "2026-08-04T12:00:00.000Z"
            )
        )
        let conflictingCAR = try await PublicFirehoseDiffCAR.commitOnly(
            commitCID: candidate.prepared.state.commitCID,
            commitBytes: candidate.prepared.signedCommit.signedCommitBytes
        )
        _ = try await database.enqueuePublicFirehoseEvent(
            sourceKey: conflictingKey,
            kind: .commit,
            lifecycleGeneration: 0,
            payload: conflictingPayload,
            carBytes: conflictingCAR,
            now: Date(timeIntervalSince1970: 1_785_844_800)
        )

        do {
            _ = try await database.applyPublicRepositoryMutation(
                reservation: candidate.reservation,
                prepared: candidate.prepared,
                firehose: .init(lifecycleGeneration: 0)
            )
            XCTFail("expected conflictingPublicFirehoseSourceKey")
        } catch let error as SQLiteRepositoryError {
            XCTAssertEqual(
                error,
                .conflictingPublicFirehoseSourceKey(conflictingKey)
            )
        }

        let head = try await database.loadPublicRepositoryState()
        XCTAssertEqual(head, initial)
        let indexed = try await database.publicRepositoryRecordCID(
            for: candidate.paths[0]
        )
        XCTAssertNil(indexed)
        guard case .reserved = try await database.reservePublicRepositoryRevision(
            candidate.reservation.request,
            wallClockMicroseconds: 1
        ) else {
            return XCTFail("rolled-back request was falsely committed")
        }
        let outbox = try await database.pendingPublicFirehoseOutbox()
        XCTAssertEqual(outbox.count, 1)
        XCTAssertEqual(outbox.first?.sourceKey, conflictingKey)
        XCTAssertEqual(outbox.first?.payload, conflictingPayload)
    }

    func testMutationWithoutFirehoseContextEnqueuesNoOutboxRow() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        let database = try await installedDatabase(root: root, key: key)
        defer { Task { try? await database.close() } }
        let loadedState = try await database.loadPublicRepositoryState()
        let initial = try XCTUnwrap(loadedState)
        let candidate = try await prepareWrites(
            database: database,
            state: initial,
            key: key,
            requestID: "no-firehose-context",
            digestByte: 0x20,
            clock: 1_750_000_000_000_000,
            writes: [
                .create(
                    path: try PublicRepositoryPath(
                        collection: "app.bsky.feed.post",
                        recordKey: "no-firehose"
                    ),
                    record: record("no-firehose")
                ),
            ]
        )
        _ = try await database.applyPublicRepositoryMutation(
            reservation: candidate.reservation,
            prepared: candidate.prepared
        )
        let pending = try await database.pendingPublicFirehoseOutbox()
        XCTAssertTrue(
            pending.isEmpty,
            "a mutation without a firehose context must not enqueue an outbox row"
        )
    }

    func testMutationWithFirehoseContextStampsItsGeneration() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        let database = try await installedDatabase(root: root, key: key)
        defer { Task { try? await database.close() } }
        let loadedState = try await database.loadPublicRepositoryState()
        let initial = try XCTUnwrap(loadedState)
        let candidate = try await prepareWrites(
            database: database,
            state: initial,
            key: key,
            requestID: "firehose-context-stamp",
            digestByte: 0x21,
            clock: 1_750_000_000_000_000,
            writes: [
                .create(
                    path: try PublicRepositoryPath(
                        collection: "app.bsky.feed.post",
                        recordKey: "firehose-stamp"
                    ),
                    record: record("firehose-stamp")
                ),
            ]
        )
        _ = try await database.applyPublicRepositoryMutation(
            reservation: candidate.reservation,
            prepared: candidate.prepared,
            firehose: .init(lifecycleGeneration: 7)
        )
        let pending = try await database.pendingPublicFirehoseOutbox()
        let row = try XCTUnwrap(pending.first)
        XCTAssertEqual(row.lifecycleGeneration, 7)
    }

    func testDecisionMakerFallsBackToSyncForOversizeCommitFrame() async throws {
        let commitCID = CID.fromDAGCBOR(Data([0x01, 0x02, 0x03]))
        let time = "2026-08-04T12:00:00.000Z"
        let manyOps = (0 ..< 201).map { index in
            PublicFirehoseRepoOp(
                action: .create,
                path: "app.bsky.feed.post/op-\(index)",
                cid: CID.fromDAGCBOR(Data([0x10, 0x20, UInt8(index % 256)])).string,
                prev: nil
            )
        }
        let commitMaterial = PublicFirehoseCommitMaterial(
            did: did,
            rev: "3kabc",
            since: nil,
            commitCID: commitCID.string,
            prevDataCID: nil,
            ops: manyOps,
            time: time
        )
        let syncMaterial = PublicFirehoseSyncMaterial(
            did: did,
            rev: "3kabc",
            commitCID: commitCID.string,
            time: time
        )
        let diffCAR = try await PublicFirehoseDiffCAR.commitOnly(commitCID: commitCID, commitBytes: Data([0x01, 0x02, 0x03]))
        let decision = try PublicFirehoseSourceDecisionMaker.decide(
            accountDID: did,
            commitCID: commitCID,
            commitMaterial: commitMaterial,
            syncMaterial: syncMaterial,
            diffCAR: diffCAR,
            commitOnlyCAR: diffCAR
        )
        guard case let .sync(payload, car, sourceKey) = decision else {
            return XCTFail("expected sync fallback")
        }
        XCTAssertEqual(sourceKey, PublicFirehoseSourceKey.syncOversize(did: did, commitCID: commitCID.string))
        XCTAssertEqual(car, diffCAR)
        let decoded = try JSONDecoder().decode(PublicFirehoseSyncMaterial.self, from: payload)
        XCTAssertEqual(decoded.did, did)
        XCTAssertEqual(decoded.commitCID, commitCID.string)
    }

    func testDecisionMakerFallsBackToSyncForOversizedCAR() async throws {
        let commitCID = CID.fromDAGCBOR(Data([0x01, 0x02, 0x03]))
        let time = "2026-08-04T12:00:00.000Z"
        let commitMaterial = PublicFirehoseCommitMaterial(
            did: did,
            rev: "3kabc",
            since: nil,
            commitCID: commitCID.string,
            prevDataCID: nil,
            ops: [],
            time: time
        )
        let syncMaterial = PublicFirehoseSyncMaterial(
            did: did,
            rev: "3kabc",
            commitCID: commitCID.string,
            time: time
        )
        let diffCAR = Data(repeating: 0, count: 2_000_001)
        let smallCAR = try await PublicFirehoseDiffCAR.commitOnly(commitCID: commitCID, commitBytes: Data([0x01, 0x02, 0x03]))
        let decision = try PublicFirehoseSourceDecisionMaker.decide(
            accountDID: did,
            commitCID: commitCID,
            commitMaterial: commitMaterial,
            syncMaterial: syncMaterial,
            diffCAR: diffCAR,
            commitOnlyCAR: smallCAR
        )
        guard case let .sync(_, car, sourceKey) = decision else {
            return XCTFail("expected sync fallback")
        }
        XCTAssertEqual(car, smallCAR)
        XCTAssertEqual(sourceKey, PublicFirehoseSourceKey.syncOversize(did: did, commitCID: commitCID.string))
    }

    func testDecisionMakerRejectsMalformedMaterialAsCorruption() throws {
        let commitCID = CID.fromDAGCBOR(Data([0x01, 0x02, 0x03]))
        let time = "2026-08-04T12:00:00.000Z"
        let invalidMaterial = PublicFirehoseCommitMaterial(
            did: did,
            rev: "3kabc",
            since: nil,
            commitCID: "not-a-cid",
            prevDataCID: nil,
            ops: [],
            time: time
        )
        let syncMaterial = PublicFirehoseSyncMaterial(
            did: did,
            rev: "3kabc",
            commitCID: commitCID.string,
            time: time
        )
        XCTAssertThrowsError(
            try PublicFirehoseSourceDecisionMaker.decide(
                accountDID: did,
                commitCID: commitCID,
                commitMaterial: invalidMaterial,
                syncMaterial: syncMaterial,
                diffCAR: Data(),
                commitOnlyCAR: Data()
            )
        ) { error in
            XCTAssertEqual(
                error as? PublicRepositoryMutationStoreError,
                .corruptRepository
            )
        }
    }

    func testDecisionIsDeterministicAcrossReplays() async throws {
        let commitCID = CID.fromDAGCBOR(Data([0x01, 0x02, 0x03]))
        let time = "2026-08-04T12:00:00.000Z"
        let op = PublicFirehoseRepoOp(
            action: .create,
            path: "app.bsky.feed.post/one",
            cid: CID.fromDAGCBOR(Data([0x10])).string,
            prev: nil
        )
        let commitMaterial = PublicFirehoseCommitMaterial(
            did: did,
            rev: "3kabc",
            since: "3jzzz",
            commitCID: commitCID.string,
            prevDataCID: CID.fromDAGCBOR(Data([0x20])).string,
            ops: [op],
            time: time
        )
        let syncMaterial = PublicFirehoseSyncMaterial(
            did: did,
            rev: "3kabc",
            commitCID: commitCID.string,
            time: time
        )
        let diffCAR = try await PublicFirehoseDiffCAR.commitOnly(commitCID: commitCID, commitBytes: Data([0x01, 0x02, 0x03]))
        let first = try PublicFirehoseSourceDecisionMaker.decide(
            accountDID: did,
            commitCID: commitCID,
            commitMaterial: commitMaterial,
            syncMaterial: syncMaterial,
            diffCAR: diffCAR,
            commitOnlyCAR: diffCAR
        )
        let second = try PublicFirehoseSourceDecisionMaker.decide(
            accountDID: did,
            commitCID: commitCID,
            commitMaterial: commitMaterial,
            syncMaterial: syncMaterial,
            diffCAR: diffCAR,
            commitOnlyCAR: diffCAR
        )
        XCTAssertEqual(first, second)
        XCTAssertEqual(first.kind, .commit)
    }

    private func record(_ text: String) -> PublicRecord {
        [
            "$type": .string("app.bsky.feed.post"),
            "text": .string(text),
        ]
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

    private func prepareWrites(
        database: SQLiteAccountDatabase,
        state: PublicRepositoryState,
        key: P256.Signing.PrivateKey,
        requestID: String,
        digestByte: UInt8,
        clock: UInt64,
        writes: [PublicRepositoryWrite]
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
        let batch = try PublicRepositoryWriteBatch(
            writes: writes,
            expectedCommitCID: state.commitCID
        )
        let prepared = try await PublicRepositoryEngine.apply(
            repositoryDID: did,
            currentState: state,
            blocks: database,
            revision: reservation.nextRevision,
            batch: batch,
            signer: P256PublicRepositoryCommitSigner(privateKey: key)
        )
        return PreparedCandidate(
            reservation: reservation,
            prepared: prepared,
            paths: writes.map { $0.path }
        )
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "swan-firehose-commit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }
}

private extension PublicRepositoryWrite {
    var path: PublicRepositoryPath {
        switch self {
        case let .create(path, _), let .update(path, _, _), let .delete(path, _):
            path
        }
    }
}
