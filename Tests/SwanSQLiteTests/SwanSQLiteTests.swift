import Foundation
import Petrel
import SQLiteNIO
import SwanCore
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class SwanSQLiteTests: XCTestCase {
    func testRestartPreservesRepositoryRecordsOplogAndPendingOutbox() async throws {
        let fixture = try Fixture()
        var database: SQLiteAccountDatabase? = try await fixture.open()

        let result = try await database!.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 0,
            requestID: UUID(uuidString: "10000000-0000-0000-0000-000000000001")!,
            wireRevision: try fixture.tid(0),
            writes: [.put(uri: fixture.first, value: fixture.firstValue, cid: "cid:first")],
            commit: Data([0x00, 0xff, 0x42]),
            notificationPayload: Data([0xff, 0x00, 0x01]),
            eventID: UUID(uuidString: "20000000-0000-0000-0000-000000000001")!
        )
        XCTAssertEqual(result.state.revision, 1)
        try await database!.close()
        database = nil

        let reopened = try await fixture.open()
        defer { Task { try? await reopened.close() } }

        let loadedSnapshot = try await reopened.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        let snapshot = try XCTUnwrap(loadedSnapshot)
        XCTAssertEqual(snapshot.state.revision, 1)
        XCTAssertEqual(snapshot.state.ltHash.count, LtHash.byteCount)
        XCTAssertEqual(snapshot.state.commit, Data([0x00, 0xff, 0x42]))
        XCTAssertEqual(snapshot.records.map(\.value), [fixture.firstValue])
        XCTAssertEqual(snapshot.records.map(\.cid), ["cid:first"])

        let oplog = try await reopened.spaceOplog(
            space: fixture.space,
            author: fixture.author,
            since: 0
        )
        guard case let .incremental(entries) = oplog else {
            return XCTFail("revision zero should still be inside retention")
        }
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries.first?.revision, 1)

        let pending = try await reopened.pendingOutbox()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending.first?.payload, Data([0xff, 0x00, 0x01]))
        XCTAssertEqual(pending.first?.author, fixture.author)
    }

    func testCASFailureAndInvalidBatchRollBackEveryFact() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }

        _ = try await fixture.commitFirst(on: database)

        await XCTAssertThrowsErrorAsync(
            try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try fixture.tid(1),
                writes: [.put(uri: fixture.second, value: fixture.secondValue, cid: "cid:wrong-cas")],
                commit: Data("wrong-cas".utf8),
                notificationPayload: Data("wrong-cas".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? SwanError, .conflict(expected: 0, actual: 1))
        }

        await XCTAssertThrowsErrorAsync(
            try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 1,
                requestID: UUID(),
                wireRevision: try fixture.tid(1),
                writes: [
                    .put(uri: fixture.second, value: fixture.secondValue, cid: "cid:second"),
                    .delete(uri: fixture.missing),
                ],
                commit: Data("invalid-batch".utf8),
                notificationPayload: Data("invalid-batch".utf8)
            )
        )

        let loadedSnapshot = try await database.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        let snapshot = try XCTUnwrap(loadedSnapshot)
        XCTAssertEqual(snapshot.state.revision, 1)
        XCTAssertEqual(snapshot.records.map(\.uri), [fixture.first])
        let secondRecord = try await database.spaceRecord(fixture.second)
        XCTAssertNil(secondRecord)

        guard case let .incremental(entries) = try await database.spaceOplog(
            space: fixture.space,
            author: fixture.author,
            since: 0
        ) else {
            return XCTFail("unexpected retention gap")
        }
        XCTAssertEqual(entries.count, 1)
        let pending = try await database.pendingOutbox()
        XCTAssertEqual(pending.count, 1)
    }

    func testDuplicateRequestIDCannotCreateASecondCommit() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        let requestID = UUID(uuidString: "10000000-0000-0000-0000-000000000099")!

        _ = try await database.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 0,
            requestID: requestID,
            wireRevision: try fixture.tid(0),
            writes: [.put(uri: fixture.first, value: fixture.firstValue, cid: "cid:first")],
            commit: Data("first".utf8),
            notificationPayload: Data("first".utf8)
        )

        await XCTAssertThrowsErrorAsync(
            try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 1,
                requestID: requestID,
                wireRevision: try fixture.tid(1),
                writes: [.put(uri: fixture.second, value: fixture.secondValue, cid: "cid:second")],
                commit: Data("second".utf8),
                notificationPayload: Data("second".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? SQLiteRepositoryError, .duplicateRequest(requestID))
        }

        let loadedSnapshot = try await database.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        let snapshot = try XCTUnwrap(loadedSnapshot)
        XCTAssertEqual(snapshot.state.revision, 1)
        XCTAssertEqual(snapshot.records.map(\.uri), [fixture.first])
        let pending = try await database.pendingOutbox()
        XCTAssertEqual(pending.count, 1)
    }

    func testSeparateConnectionsRaceThroughSQLiteCAS() async throws {
        let fixture = try Fixture()
        let firstDatabase = try await fixture.open()
        let secondDatabase = try await fixture.open()
        defer {
            Task {
                try? await firstDatabase.close()
                try? await secondDatabase.close()
            }
        }

        let outcomes = await withTaskGroup(
            of: Result<PersistedRepositoryCommit, any Error>.self,
            returning: [Result<PersistedRepositoryCommit, any Error>].self
        ) { group in
            group.addTask {
                do {
                    return .success(
                        try await firstDatabase.apply(
                            space: fixture.space,
                            author: fixture.author,
                            expectedRevision: 0,
                            requestID: UUID(),
                            wireRevision: try fixture.tid(0),
                            writes: [
                                .put(
                                    uri: fixture.first,
                                    value: fixture.firstValue,
                                    cid: "cid:first"
                                )
                            ],
                            commit: Data("first-racer".utf8),
                            notificationPayload: Data("first-racer".utf8)
                        )
                    )
                } catch {
                    return .failure(error)
                }
            }
            group.addTask {
                do {
                    return .success(
                        try await secondDatabase.apply(
                            space: fixture.space,
                            author: fixture.author,
                            expectedRevision: 0,
                            requestID: UUID(),
                            wireRevision: try fixture.tid(0),
                            writes: [
                                .put(
                                    uri: fixture.second,
                                    value: fixture.secondValue,
                                    cid: "cid:second"
                                )
                            ],
                            commit: Data("second-racer".utf8),
                            notificationPayload: Data("second-racer".utf8)
                        )
                    )
                } catch {
                    return .failure(error)
                }
            }
            return await group.reduce(into: []) { $0.append($1) }
        }

        let successes = outcomes.compactMap { try? $0.get() }
        let failures = outcomes.compactMap { result -> (any Error)? in
            guard case let .failure(error) = result else { return nil }
            return error
        }
        XCTAssertEqual(successes.count, 1)
        XCTAssertEqual(failures.count, 1)
        XCTAssertEqual(
            failures.first as? SwanError,
            .conflict(expected: 0, actual: 1)
        )

        let loadedSnapshot = try await firstDatabase.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        let snapshot = try XCTUnwrap(loadedSnapshot)
        XCTAssertEqual(snapshot.state.revision, 1)
        XCTAssertEqual(snapshot.records.count, 1)
        let pending = try await firstDatabase.pendingOutbox()
        XCTAssertEqual(pending.count, 1)
    }

    func testSameInstanceGateHidesRolledBackOutboxAndPreventsNestedTransaction() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        let barrier = FailingApplyBarrier()
        await database.installTestingHooks(
            SQLiteTestingHooks(beforeApplyCommit: { try await barrier.pauseThenFailOnce() })
        )
        defer { Task { try? await database.close() } }

        let failingApply = Task {
            try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try fixture.tid(0),
                writes: [
                    .put(uri: fixture.first, value: fixture.firstValue, cid: "cid:first")
                ],
                commit: Data("rolled-back".utf8),
                notificationPayload: Data("rolled-back".utf8)
            )
        }
        await barrier.waitUntilPaused()

        let pollStarted = AsyncSignal()
        let pendingPoll = Task {
            await pollStarted.signal()
            return try await database.pendingOutbox()
        }
        await pollStarted.wait()
        for _ in 0..<20 { await Task.yield() }

        let succeedingApply = Task {
            try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try fixture.tid(1),
                writes: [
                    .put(uri: fixture.second, value: fixture.secondValue, cid: "cid:second")
                ],
                commit: Data("committed".utf8),
                notificationPayload: Data("committed".utf8)
            )
        }

        await barrier.release()
        do {
            _ = try await failingApply.value
            XCTFail("the injected transaction failure should roll back")
        } catch {
            XCTAssertTrue(error is InjectedTransactionFailure)
        }

        let eventsDuringFailure = try await pendingPoll.value
        XCTAssertEqual(eventsDuringFailure, [])
        let committed = try await succeedingApply.value
        XCTAssertEqual(committed.state.revision, 1)
        let finalPending = try await database.pendingOutbox()
        XCTAssertEqual(finalPending.count, 1)
    }

    func testSnapshotUsesOneStableSQLiteReadTransaction() async throws {
        let fixture = try Fixture()
        let reader = try await fixture.open()
        let writer = try await fixture.open()
        defer {
            Task {
                try? await reader.close()
                try? await writer.close()
            }
        }
        _ = try await fixture.commitFirst(on: reader)

        let barrier = SnapshotReadBarrier()
        await reader.installTestingHooks(
            SQLiteTestingHooks(afterSnapshotStateRead: { await barrier.pause() })
        )
        let snapshotTask = Task {
            try await reader.repositorySnapshot(
                space: fixture.space,
                author: fixture.author
            )
        }
        await barrier.waitUntilPaused()

        _ = try await writer.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 1,
            requestID: UUID(),
            wireRevision: try fixture.tid(1),
            writes: [
                .put(uri: fixture.second, value: fixture.secondValue, cid: "cid:second")
            ],
            commit: Data("second".utf8),
            notificationPayload: Data("second".utf8)
        )
        await barrier.release()

        let loadedSnapshot = try await snapshotTask.value
        let snapshot = try XCTUnwrap(loadedSnapshot)
        XCTAssertEqual(snapshot.state.revision, 1)
        XCTAssertEqual(snapshot.records.map(\.uri), [fixture.first])

        let current = try await reader.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        XCTAssertEqual(current?.state.revision, 2)
        XCTAssertEqual(current?.records.count, 2)
    }

    func testOplogPreservesWireRevisionActionAndPreviousCID() async throws {
        let fixture = try Fixture()
        var database: SQLiteAccountDatabase? = try await fixture.open()
        let createRevision = try fixture.tid(0)
        let updateRevision = try fixture.tid(1)
        let deleteRevision = try fixture.tid(2)

        _ = try await database!.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: createRevision,
            writes: [
                .put(uri: fixture.first, value: fixture.firstValue, cid: "cid:first")
            ],
            commit: Data("create".utf8),
            notificationPayload: Data("create".utf8)
        )
        _ = try await database!.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 1,
            requestID: UUID(),
            wireRevision: updateRevision,
            writes: [
                .put(uri: fixture.first, value: fixture.secondValue, cid: "cid:updated")
            ],
            commit: Data("update".utf8),
            notificationPayload: Data("update".utf8)
        )
        _ = try await database!.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 2,
            requestID: UUID(),
            wireRevision: deleteRevision,
            writes: [.delete(uri: fixture.first)],
            commit: Data("delete".utf8),
            notificationPayload: Data("delete".utf8)
        )

        try await database!.close()
        database = nil
        let reopened = try await fixture.open()
        defer { Task { try? await reopened.close() } }

        guard case let .incremental(entries) = try await reopened.spaceOplog(
            space: fixture.space,
            author: fixture.author,
            since: 0
        ) else {
            return XCTFail("all three commits should be retained")
        }
        XCTAssertEqual(entries.map(\.wireRevision), [
            createRevision, updateRevision, deleteRevision,
        ])
        XCTAssertEqual(entries.map(\.action), [.create, .update, .delete])
        XCTAssertEqual(entries.map(\.previousCID), [nil, "cid:first", "cid:updated"])
        XCTAssertEqual(entries.map(\.cid), ["cid:first", "cid:updated", nil])
        let snapshot = try await reopened.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        XCTAssertEqual(snapshot?.state.wireRevision, deleteRevision)
    }

    func testAccountDIDRejectsCrossAccountPublicAndPermissionedFacts() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        let otherAuthor = "did:plc:bob"
        let otherRecord = try SpaceRecordURI(
            space: fixture.space,
            author: otherAuthor,
            collection: "app.bsky.feed.post",
            rkey: "other"
        )

        await XCTAssertThrowsErrorAsync(
            try await database.apply(
                space: fixture.space,
                author: otherAuthor,
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try fixture.tid(0),
                writes: [.put(uri: otherRecord, value: fixture.firstValue, cid: "cid:other")],
                commit: Data("other".utf8),
                notificationPayload: Data("other".utf8)
            )
        ) { error in
            guard case .unauthorized = error as? SwanError else {
                return XCTFail("cross-account author must be unauthorized")
            }
        }

        let otherPublic = try PublicRecordURI(
            "at://did:plc:bob/app.bsky.feed.post/other"
        )
        await XCTAssertThrowsErrorAsync(
            try await database.putPublicRecord(
                uri: otherPublic,
                value: fixture.firstValue,
                cid: "cid:other",
                revision: 1
            )
        ) { error in
            guard case .unauthorized = error as? SwanError else {
                return XCTFail("cross-account public record must be unauthorized")
            }
        }
        await XCTAssertThrowsErrorAsync(
            try await database.publicRecord(otherPublic)
        )
        await XCTAssertThrowsErrorAsync(
            try await database.repositorySnapshot(
                space: fixture.space,
                author: otherAuthor
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await database.spaceRecord(otherRecord)
        )

        XCTAssertThrowsError(
            try PublicRecordURI("at://not-a-did/app.bsky.feed.post/one")
        )
        XCTAssertThrowsError(
            try PublicRecordURI("at://did:plc:alice/not-an-nsid/one")
        )
        XCTAssertThrowsError(
            try PublicRecordURI("at://did:plc:alice/app.bsky.feed.post/bad/key")
        )
    }

    func testDurableBlobPayloadAndNamespaceReferencesSurviveRestart() async throws {
        let fixture = try Fixture()
        var database: SQLiteAccountDatabase? = try await fixture.open()
        let payload = Data([0x00, 0xff, 0x42, 0x01])
        let spaceReference = try await database!.putBlob(
            payload,
            namespace: .space(fixture.space)
        )
        let privateAsPublic = try await database!.publicBlobData(
            cid: spaceReference.cid
        )
        XCTAssertNil(privateAsPublic)
        try await database!.close()
        database = nil

        let reopened = try await fixture.open()
        defer { Task { try? await reopened.close() } }
        let blobStore: any BlobStore = reopened
        let reopenedPrivate = try await blobStore.data(for: spaceReference)
        XCTAssertEqual(reopenedPrivate, payload)
        let otherSpace = try SpaceURI(
            authority: fixture.author,
            spaceType: "app.bsky.bookmarks",
            skey: "other"
        )
        let wrongSpaceReference = BlobReference(
            cid: spaceReference.cid,
            namespace: .space(otherSpace)
        )
        await XCTAssertThrowsErrorAsync(
            try await blobStore.data(for: wrongSpaceReference)
        )

        let publicReference = try await blobStore.put(
            payload,
            namespace: .public
        )
        XCTAssertEqual(publicReference.cid, spaceReference.cid)
        let reopenedPublic = try await blobStore.publicData(
            cid: publicReference.cid
        )
        XCTAssertEqual(reopenedPublic, payload)

        try await blobStore.remove(publicReference)
        let removedPublic = try await blobStore.publicData(
            cid: publicReference.cid
        )
        XCTAssertNil(removedPublic)
        let retainedPrivate = try await blobStore.data(for: spaceReference)
        XCTAssertEqual(retainedPrivate, payload)
    }

    func testAtomicBatchUsesOneRevisionAndOrderedOperationIndexes() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }

        let result = try await database.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try fixture.tid(0),
            writes: [
                .put(uri: fixture.first, value: fixture.firstValue, cid: "cid:first"),
                .put(uri: fixture.second, value: fixture.secondValue, cid: "cid:second"),
            ],
            commit: Data("batch".utf8),
            notificationPayload: Data("batch".utf8)
        )

        XCTAssertEqual(result.state.revision, 1)
        XCTAssertEqual(
            result.entries.map(\.cursor),
            [
                PersistedOplogCursor(revision: 1, index: 0),
                PersistedOplogCursor(revision: 1, index: 1),
            ]
        )
        guard case let .incremental(remainingEntries) = try await database.spaceOplog(
            space: fixture.space,
            author: fixture.author,
            after: PersistedOplogCursor(revision: 1, index: 0)
        ) else {
            return XCTFail("cursor inside the current commit should stay incremental")
        }
        XCTAssertEqual(
            remainingEntries.map(\.cursor),
            [PersistedOplogCursor(revision: 1, index: 1)]
        )
        let loadedSnapshot = try await database.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        let snapshot = try XCTUnwrap(loadedSnapshot)
        XCTAssertEqual(snapshot.records.map(\.revision), [1, 1])
    }

    func testRetentionReportsFullRecoveryGapAndReturnsNormalIncrementalRange() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open(retention: 2)
        defer { Task { try? await database.close() } }

        _ = try await fixture.commitFirst(on: database)
        _ = try await database.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 1,
            requestID: UUID(),
            wireRevision: try fixture.tid(1),
            writes: [.put(uri: fixture.second, value: fixture.secondValue, cid: "cid:second")],
            commit: Data("second".utf8),
            notificationPayload: Data("second".utf8)
        )
        _ = try await database.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 2,
            requestID: UUID(),
            wireRevision: try fixture.tid(2),
            writes: [.put(uri: fixture.third, value: fixture.thirdValue, cid: "cid:third")],
            commit: Data("third".utf8),
            notificationPayload: Data("third".utf8)
        )

        guard case let .fullRecoveryRequired(snapshot) = try await database.spaceOplog(
            space: fixture.space,
            author: fixture.author,
            since: 0
        ) else {
            return XCTFail("cursor before retained revision must require a full CAR recovery")
        }
        XCTAssertEqual(snapshot.state.revision, 3)
        XCTAssertEqual(snapshot.records.count, 3)

        guard case let .incremental(entries) = try await database.spaceOplog(
            space: fixture.space,
            author: fixture.author,
            since: 1
        ) else {
            return XCTFail("cursor directly before the retained range should be incremental")
        }
        XCTAssertEqual(entries.map(\.revision), [2, 3])
    }

    func testPublicAndPermissionedNamespaceAPIsCannotCrossRead() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        let privateOnly = try PublicRecordURI(
            "at://did:plc:alice/app.bsky.feed.post/private-only"
        )
        let publicOnlySpaceURI = try SpaceRecordURI(
            space: fixture.space,
            author: fixture.author,
            collection: "app.bsky.feed.post",
            rkey: "public-only"
        )
        let publicOnly = try PublicRecordURI(
            "at://did:plc:alice/app.bsky.feed.post/public-only"
        )

        _ = try await fixture.commitFirst(on: database)
        try await database.putPublicRecord(
            uri: publicOnly,
            value: Data("public".utf8),
            cid: "cid:public",
            revision: 7
        )

        let privateAsPublic = try await database.publicRecord(privateOnly)
        let publicAsPrivate = try await database.spaceRecord(publicOnlySpaceURI)
        let publicRecord = try await database.publicRecord(publicOnly)
        let privateRecord = try await database.spaceRecord(fixture.first)
        XCTAssertNil(privateAsPublic)
        XCTAssertNil(publicAsPrivate)
        XCTAssertEqual(publicRecord?.value, Data("public".utf8))
        XCTAssertEqual(privateRecord?.value, fixture.firstValue)
    }

    func testControlStorePersistsReplayStateAndPurgesExpiredMetadata() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanControlStoreTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let binding = OAuthClientBinding(
            issuer: "https://swan.example",
            clientID: "https://client.example/metadata",
            redirectURI: "https://client.example/callback",
            scopes: ["atproto"],
            dpopJKT: String(repeating: "C", count: 43)
        )
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let metadata = OAuthCachedClientMetadata(
            clientID: binding.clientID,
            document: Data("{\"client_id\":\"example\"}".utf8),
            expiresAt: now.addingTimeInterval(1)
        )
        try await database.cacheClientMetadata(metadata, now: now)
        let cachedMetadata = try await database.cachedClientMetadata(
            clientID: binding.clientID,
            now: now
        )
        XCTAssertEqual(cachedMetadata, metadata)

        let request = OAuthPushedAuthorizationRequest(
            requestDigest: Data(repeating: 0x11, count: 32),
            binding: binding,
            state: "state=must-round-trip",
            stateDigest: Data(repeating: 0x22, count: 32),
            codeChallengeS256: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            expiresAt: now.addingTimeInterval(30)
        )
        try await database.storePushedAuthorizationRequest(request, now: now)
        let consumed = try await database.consumePushedAuthorizationRequest(
            requestDigest: request.requestDigest,
            binding: binding,
            now: now
        )
        XCTAssertEqual(consumed.state, "state=must-round-trip")
        let duplicateState = OAuthPushedAuthorizationRequest(
            requestDigest: Data(repeating: 0x33, count: 32),
            binding: binding,
            state: request.state,
            stateDigest: request.stateDigest,
            codeChallengeS256: request.codeChallengeS256,
            expiresAt: request.expiresAt
        )
        await XCTAssertThrowsErrorAsync(
            try await database.storePushedAuthorizationRequest(duplicateState, now: now)
        ) { error in
            XCTAssertEqual(error as? OAuthControlStoreError, .replayDetected)
        }
        let expiredMetadata = try await database.cachedClientMetadata(
            clientID: binding.clientID,
            now: now.addingTimeInterval(2)
        )
        XCTAssertNil(expiredMetadata)
        let firstReplayClaim = try await database.claimDPoPReplay(
            digest: Data(repeating: 0x44, count: 32),
            expiresAt: now.addingTimeInterval(30),
            now: now
        )
        XCTAssertTrue(firstReplayClaim)
        try await database.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        let secondReplayClaim = try await reopened.claimDPoPReplay(
            digest: Data(repeating: 0x44, count: 32),
            expiresAt: now.addingTimeInterval(30),
            now: now.addingTimeInterval(1)
        )
        XCTAssertFalse(secondReplayClaim)
        let reclaimedReplay = try await reopened.claimDPoPReplay(
            digest: Data(repeating: 0x44, count: 32),
            expiresAt: now.addingTimeInterval(60),
            now: now.addingTimeInterval(31)
        )
        XCTAssertTrue(reclaimedReplay)
        try await reopened.close()
    }

    func testControlStoreRejectsUnboundOrMismatchedFamiliesAndFailsClosedForCorruptBindings() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanControlStoreBindingsTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let familyID = UUID()
        let binding = OAuthClientBinding(
            issuer: "https://swan.example",
            clientID: "https://client.example/metadata",
            redirectURI: "https://client.example/callback",
            scopes: ["atproto"],
            dpopJKT: String(repeating: "D", count: 43)
        )
        let family = OAuthTokenFamily(
            familyID: familyID,
            subject: "did:plc:alice",
            binding: binding,
            expiresAt: now.addingTimeInterval(600)
        )
        let tokens = OAuthIssuedTokenDigests(
            familyID: familyID,
            accessTokenDigest: Data(repeating: 0xA1, count: 32),
            refreshTokenDigest: Data(repeating: 0xB2, count: 32),
            accessExpiresAt: now.addingTimeInterval(60),
            refreshExpiresAt: now.addingTimeInterval(600)
        )
        let database = try await SQLiteControlDatabase(dataDirectory: root)

        for invalidJKT in [nil, "", "not-a-jkt"] as [String?] {
            let invalidFamily = OAuthTokenFamily(
                familyID: UUID(),
                subject: "did:plc:alice",
                binding: OAuthClientBinding(
                    issuer: binding.issuer,
                    clientID: binding.clientID,
                    redirectURI: binding.redirectURI,
                    scopes: binding.scopes,
                    dpopJKT: invalidJKT
                ),
                expiresAt: family.expiresAt
            )
            let invalidTokens = OAuthIssuedTokenDigests(
                familyID: invalidFamily.familyID,
                accessTokenDigest: Data(repeating: UInt8(0xC0 + (invalidJKT?.count ?? 0)), count: 32),
                refreshTokenDigest: Data(repeating: UInt8(0xD0 + (invalidJKT?.count ?? 0)), count: 32),
                accessExpiresAt: tokens.accessExpiresAt,
                refreshExpiresAt: tokens.refreshExpiresAt
            )
            await XCTAssertThrowsErrorAsync(
                try await database.issueTokenPair(
                    family: invalidFamily,
                    tokens: invalidTokens,
                    now: now
                )
            ) { error in
                XCTAssertEqual(error as? OAuthControlStoreError, .invalidInput)
            }
        }

        let mismatchedTokens = OAuthIssuedTokenDigests(
            familyID: UUID(),
            accessTokenDigest: tokens.accessTokenDigest,
            refreshTokenDigest: tokens.refreshTokenDigest,
            accessExpiresAt: tokens.accessExpiresAt,
            refreshExpiresAt: tokens.refreshExpiresAt
        )
        await XCTAssertThrowsErrorAsync(
            try await database.issueTokenPair(family: family, tokens: mismatchedTokens, now: now)
        ) { error in
            XCTAssertEqual(error as? OAuthControlStoreError, .invalidInput)
        }
        let revokedFamily = OAuthTokenFamily(
            familyID: UUID(),
            subject: family.subject,
            binding: binding,
            expiresAt: family.expiresAt,
            revokedAt: now
        )
        let revokedTokens = OAuthIssuedTokenDigests(
            familyID: revokedFamily.familyID,
            accessTokenDigest: Data(repeating: 0xE1, count: 32),
            refreshTokenDigest: Data(repeating: 0xF2, count: 32),
            accessExpiresAt: tokens.accessExpiresAt,
            refreshExpiresAt: tokens.refreshExpiresAt
        )
        await XCTAssertThrowsErrorAsync(
            try await database.issueTokenPair(family: revokedFamily, tokens: revokedTokens, now: now)
        ) { error in
            XCTAssertEqual(error as? OAuthControlStoreError, .invalidInput)
        }

        try await database.issueTokenPair(family: family, tokens: tokens, now: now)
        let codeDigest = Data(repeating: 0xC3, count: 32)
        let code = OAuthAuthorizationCode(
            codeDigest: codeDigest,
            familyID: UUID(),
            subject: family.subject,
            binding: binding,
            codeChallengeS256: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            expiresAt: now.addingTimeInterval(60),
            familyExpiresAt: family.expiresAt
        )
        try await database.storeAuthorizationCode(code, now: now)
        try await database.close()

        let direct = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.controlDatabase(in: root).path)
        )
        _ = try await direct.query(
            "UPDATE oauth_control_token_families SET dpop_jkt = NULL"
        )
        try await direct.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        await XCTAssertThrowsErrorAsync(
            try await reopened.validatedAccessToken(
                accessTokenDigest: tokens.accessTokenDigest,
                now: now
            )
        ) { error in
            XCTAssertEqual(error as? OAuthControlStoreError, .malformedRecord)
        }
        await XCTAssertThrowsErrorAsync(
            try await reopened.refreshTokenFamily(
                refreshTokenDigest: tokens.refreshTokenDigest,
                now: now
            )
        ) { error in
            XCTAssertEqual(error as? OAuthControlStoreError, .malformedRecord)
        }
        await XCTAssertThrowsErrorAsync(
            try await reopened.authorizationCode(codeDigest: codeDigest, now: now)
        ) { error in
            XCTAssertEqual(error as? OAuthControlStoreError, .malformedRecord)
        }
        try await reopened.close()
    }
}

private struct Fixture {
    let root: URL
    let author = "did:plc:alice"
    let space: SpaceURI
    let first: SpaceRecordURI
    let second: SpaceRecordURI
    let third: SpaceRecordURI
    let missing: SpaceRecordURI
    let firstValue = Data([0xa1, 0x61, 0x61, 0x01])
    let secondValue = Data([0xa1, 0x61, 0x62, 0x02])
    let thirdValue = Data([0xa1, 0x61, 0x63, 0x03])

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSQLiteTests-\(UUID().uuidString)")
        space = try SpaceURI(
            authority: "did:plc:alice",
            spaceType: "app.bsky.bookmarks",
            skey: "self"
        )
        first = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.bsky.feed.post",
            rkey: "first"
        )
        second = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.bsky.feed.post",
            rkey: "second"
        )
        third = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.bsky.feed.post",
            rkey: "third"
        )
        missing = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.bsky.feed.post",
            rkey: "missing"
        )
    }

    func open(retention: Int = 10_000) async throws -> SQLiteAccountDatabase {
        try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: author,
            oplogRetention: retention
        )
    }

    func commitFirst(on database: SQLiteAccountDatabase) async throws -> PersistedRepositoryCommit {
        try await database.apply(
            space: space,
            author: author,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try tid(0),
            writes: [.put(uri: first, value: firstValue, cid: "cid:first")],
            commit: Data("first".utf8),
            notificationPayload: Data("first".utf8)
        )
    }

    func tid(_ offset: Int) throws -> TID {
        let alphabet = Array("234567abcdefghijklmnopqrstuvwxyz")
        return try TID(tidString: "222222222222\(alphabet[offset])")
    }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ errorHandler: (any Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("expected error", file: file, line: line)
    } catch {
        errorHandler(error)
    }
}

private struct InjectedTransactionFailure: Error {}

private actor FailingApplyBarrier {
    private var hasFailed = false
    private var isPaused = false
    private var pauseWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseContinuation: CheckedContinuation<Void, Never>?

    func pauseThenFailOnce() async throws {
        guard !hasFailed else { return }
        hasFailed = true
        isPaused = true
        pauseWaiters.forEach { $0.resume() }
        pauseWaiters.removeAll()
        await withCheckedContinuation { releaseContinuation = $0 }
        throw InjectedTransactionFailure()
    }

    func waitUntilPaused() async {
        guard !isPaused else { return }
        await withCheckedContinuation { pauseWaiters.append($0) }
    }

    func release() {
        releaseContinuation?.resume()
        releaseContinuation = nil
    }
}

private actor SnapshotReadBarrier {
    private var isPaused = false
    private var pauseWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseContinuation: CheckedContinuation<Void, Never>?

    func pause() async {
        guard !isPaused else { return }
        isPaused = true
        pauseWaiters.forEach { $0.resume() }
        pauseWaiters.removeAll()
        await withCheckedContinuation { releaseContinuation = $0 }
    }

    func waitUntilPaused() async {
        guard !isPaused else { return }
        await withCheckedContinuation { pauseWaiters.append($0) }
    }

    func release() {
        releaseContinuation?.resume()
        releaseContinuation = nil
    }
}

private actor AsyncSignal {
    private var signaled = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func signal() {
        signaled = true
        waiters.forEach { $0.resume() }
        waiters.removeAll()
    }

    func wait() async {
        guard !signaled else { return }
        await withCheckedContinuation { waiters.append($0) }
    }
}
