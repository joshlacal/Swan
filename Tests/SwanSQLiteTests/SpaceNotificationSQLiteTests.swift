import Foundation
import Petrel
import SQLiteNIO
import SwanCore
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class SpaceNotificationSQLiteTests: XCTestCase {
    /// The request receipt is a replay reservation, not the state guard: the
    /// revision CAS is what refuses a stale write. Retaining receipts to the
    /// same depth as the oplog therefore only changes a duplicate rejection
    /// into a conflict rejection once a request is older than the window.
    func testRequestReceiptsPruneToRetentionDepthAndStaleReplayBecomesAConflict() async throws {
        let fixture = try NotificationFixture()
        let database = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root,
            did: fixture.writer,
            oplogRetention: 3
        )
        defer { Task { try? await database.close() } }

        let uri = try SpaceRecordURI(
            space: fixture.space,
            author: fixture.writer,
            collection: "app.bsky.feed.post",
            rkey: "ledger"
        )
        var requestIDs: [UUID] = []
        for index in 1 ... 6 {
            let requestID = UUID()
            requestIDs.append(requestID)
            let value = Data([0xA1, 0x61, 0x61, UInt8(index)])
            _ = try await database.apply(
                space: fixture.space,
                author: fixture.writer,
                expectedRevision: UInt64(index - 1),
                requestID: requestID,
                wireRevision: try fixture.tid(index),
                writes: [
                    .put(
                        uri: uri,
                        value: value,
                        cid: CID.fromDAGCBOR(value).string
                    ),
                ]
            )
        }

        let retained = try await database.connection.query(
            """
            SELECT request_id, created_at
            FROM permissioned_space_requests
            WHERE space_uri = ? AND author_did = ?
            ORDER BY final_revision
            """,
            [.text(fixture.space.rawValue), .text(fixture.writer)]
        )
        XCTAssertEqual(retained.count, 3)
        XCTAssertEqual(
            retained.compactMap { $0.column("request_id")?.string },
            requestIDs.suffix(3).map(\.uuidString)
        )
        XCTAssertTrue(
            retained.allSatisfy { ($0.column("created_at")?.integer ?? 0) > 0 }
        )

        // A retained receipt still answers a replay as a duplicate, before the
        // revision CAS is consulted.
        let duplicateValue = Data([0xA1, 0x61, 0x61, 0x07])
        do {
            _ = try await database.apply(
                space: fixture.space,
                author: fixture.writer,
                expectedRevision: 5,
                requestID: try XCTUnwrap(requestIDs.last),
                wireRevision: try fixture.tid(7),
                writes: [
                    .put(
                        uri: uri,
                        value: duplicateValue,
                        cid: CID.fromDAGCBOR(duplicateValue).string
                    ),
                ]
            )
            XCTFail("a retained receipt must reject its replay as a duplicate")
        } catch {
            XCTAssertEqual(
                error as? SQLiteRepositoryError,
                .duplicateRequest(try XCTUnwrap(requestIDs.last))
            )
        }

        // A pruned receipt no longer recognises the request, and the revision
        // CAS refuses the same stale replay instead.
        do {
            _ = try await database.apply(
                space: fixture.space,
                author: fixture.writer,
                expectedRevision: 0,
                requestID: try XCTUnwrap(requestIDs.first),
                wireRevision: try fixture.tid(7),
                writes: [
                    .put(
                        uri: uri,
                        value: duplicateValue,
                        cid: CID.fromDAGCBOR(duplicateValue).string
                    ),
                ]
            )
            XCTFail("a pruned receipt must not admit its stale replay")
        } catch {
            guard case let .conflict(expected, actual) = error as? SwanError else {
                XCTFail("expected a revision conflict, got \(error)")
                return
            }
            XCTAssertEqual(expected, 0)
            XCTAssertEqual(actual, 6)
        }
    }
    /// Reopening a database with a substantially lower oplog retention
    /// must prune the excess oplog entries and request receipts down to the new
    /// retention limit on the next commit without performing an unbounded scan.
    func testLoweringOplogRetentionPrunesToNewDepthAndReplaysOlderReceiptsAsConflicts() async throws {
        let fixture = try NotificationFixture()
        let highRetentionDatabase = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root,
            did: fixture.writer,
            oplogRetention: 20
        )

        let uri = try SpaceRecordURI(
            space: fixture.space,
            author: fixture.writer,
            collection: "app.bsky.feed.post",
            rkey: "retention-reduction"
        )
        var requestIDs: [UUID] = []
        for index in 1 ... 15 {
            let requestID = UUID()
            requestIDs.append(requestID)
            let value1 = Data([0xA1, 0x61, 0x61, UInt8(index)])
            let value2 = Data([0xA1, 0x61, 0x62, UInt8(index)])
            let uri2 = try SpaceRecordURI(
                space: fixture.space,
                author: fixture.writer,
                collection: "app.bsky.feed.post",
                rkey: "retention-reduction-\(index)"
            )
            _ = try await highRetentionDatabase.apply(
                space: fixture.space,
                author: fixture.writer,
                expectedRevision: UInt64(index - 1),
                requestID: requestID,
                wireRevision: try fixture.tid(index),
                writes: [
                    .put(
                        uri: uri,
                        value: value1,
                        cid: CID.fromDAGCBOR(value1).string
                    ),
                    .put(
                        uri: uri2,
                        value: value2,
                        cid: CID.fromDAGCBOR(value2).string
                    ),
                ]
            )
        }

        let initialRequests = try await highRetentionDatabase.connection.query(
            "SELECT COUNT(*) AS count FROM permissioned_space_requests WHERE space_uri = ? AND author_did = ?",
            [.text(fixture.space.rawValue), .text(fixture.writer)]
        )
        XCTAssertEqual(initialRequests.first?.column("count")?.integer, 15)

        let initialOplog = try await highRetentionDatabase.connection.query(
            "SELECT COUNT(*) AS count FROM permissioned_space_oplog WHERE space_uri = ? AND author_did = ?",
            [.text(fixture.space.rawValue), .text(fixture.writer)]
        )
        XCTAssertEqual(initialOplog.first?.column("count")?.integer, 20)
        try await highRetentionDatabase.close()

        // Reopen with oplogRetention lowered to 4
        let lowRetentionDatabase = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root,
            did: fixture.writer,
            oplogRetention: 4
        )
        defer { Task { try? await lowRetentionDatabase.close() } }

        // Commit revision 16 under the new low retention limit
        let nextRequestID = UUID()
        let nextValue = Data([0xA1, 0x61, 0x61, 0x10])
        _ = try await lowRetentionDatabase.apply(
            space: fixture.space,
            author: fixture.writer,
            expectedRevision: 15,
            requestID: nextRequestID,
            wireRevision: try fixture.tid(16),
            writes: [
                .put(
                    uri: uri,
                    value: nextValue,
                    cid: CID.fromDAGCBOR(nextValue).string
                ),
            ]
        )

        // Requests should now be pruned to exactly 4 (revisions 13, 14, 15, 16)
        let retainedRequests = try await lowRetentionDatabase.connection.query(
            """
            SELECT request_id, final_revision
            FROM permissioned_space_requests
            WHERE space_uri = ? AND author_did = ?
            ORDER BY final_revision ASC
            """,
            [.text(fixture.space.rawValue), .text(fixture.writer)]
        )
        XCTAssertEqual(retainedRequests.count, 4)
        XCTAssertEqual(
            retainedRequests.compactMap { $0.column("final_revision")?.integer },
            [13, 14, 15, 16]
        )

        // Oplog entries should be pruned down to the retention window (revisions >= 15)
        let retainedOplog = try await lowRetentionDatabase.connection.query(
            """
            SELECT revision, operation_index
            FROM permissioned_space_oplog
            WHERE space_uri = ? AND author_did = ?
            ORDER BY revision ASC, operation_index ASC
            """,
            [.text(fixture.space.rawValue), .text(fixture.writer)]
        )
        let retainedEntries = retainedOplog.compactMap { row -> String? in
            guard let rev = row.column("revision")?.integer,
                  let idx = row.column("operation_index")?.integer else { return nil }
            return "\(rev):\(idx)"
        }
        XCTAssertEqual(
            retainedEntries,
            ["14:0", "14:1", "15:0", "15:1", "16:0"]
        )

        // Replay of an evicted request (e.g. revision 1) must be refused as a revision conflict
        let duplicateValue = Data([0xA1, 0x61, 0x61, 0x01])
        do {
            _ = try await lowRetentionDatabase.apply(
                space: fixture.space,
                author: fixture.writer,
                expectedRevision: 0,
                requestID: try XCTUnwrap(requestIDs.first),
                wireRevision: try fixture.tid(17),
                writes: [
                    .put(
                        uri: uri,
                        value: duplicateValue,
                        cid: CID.fromDAGCBOR(duplicateValue).string
                    ),
                ]
            )
            XCTFail("a pruned receipt must not admit its stale replay")
        } catch {
            guard case let .conflict(expected, actual) = error as? SwanError else {
                XCTFail("expected a revision conflict, got \(error)")
                return
            }
            XCTAssertEqual(expected, 0)
            XCTAssertEqual(actual, 16)
        }

        // Replay of a retained request (revision 16) must be refused as a duplicate
        do {
            _ = try await lowRetentionDatabase.apply(
                space: fixture.space,
                author: fixture.writer,
                expectedRevision: 16,
                requestID: nextRequestID,
                wireRevision: try fixture.tid(17),
                writes: [
                    .put(
                        uri: uri,
                        value: duplicateValue,
                        cid: CID.fromDAGCBOR(duplicateValue).string
                    ),
                ]
            )
            XCTFail("a retained receipt must reject its replay as a duplicate")
        } catch {
            XCTAssertEqual(
                error as? SQLiteRepositoryError,
                .duplicateRequest(nextRequestID)
            )
        }
    }
    /// A repository with many operations per revision must prune to the exact
    /// composite retention boundary and use covering index seeks without full-table scans.
    func testHighOperationsPerRevisionRetentionPrunesToExactOplogBoundaryAndAvoidsFullTableScan() async throws {
        let fixture = try NotificationFixture()
        let database = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root,
            did: fixture.writer,
            oplogRetention: 35
        )
        defer { Task { try? await database.close() } }

        // Apply 10 commits with 10 writes each = 100 total operations across revisions 1...10
        for revision in 1 ... 10 {
            let requestID = UUID()
            var writes: [SQLiteSpaceWrite] = []
            for op in 0 ..< 10 {
                let uri = try SpaceRecordURI(
                    space: fixture.space,
                    author: fixture.writer,
                    collection: "app.bsky.feed.post",
                    rkey: "rkey-rev\(revision)-op\(op)"
                )
                let value = Data([0xA1, 0x61, 0x61, UInt8(revision)])
                writes.append(.put(
                    uri: uri,
                    value: value,
                    cid: CID.fromDAGCBOR(value).string
                ))
            }
            _ = try await database.apply(
                space: fixture.space,
                author: fixture.writer,
                expectedRevision: UInt64(revision - 1),
                requestID: requestID,
                wireRevision: try fixture.tid(revision),
                writes: writes
            )
        }

        // With oplogRetention = 35:
        // Revisions 10 (10 ops), 9 (10 ops), 8 (10 ops) = 30 ops.
        // The 35th newest entry falls in Revision 7.
        // Whole commits are retained -> revisions 7, 8, 9, 10 are retained (40 total ops).
        // Commits 1...6 (60 ops) are pruned.
        let retainedOplog = try await database.connection.query(
            """
            SELECT revision, operation_index
            FROM permissioned_space_oplog
            WHERE space_uri = ? AND author_did = ?
            ORDER BY revision ASC, operation_index ASC
            """,
            [.text(fixture.space.rawValue), .text(fixture.writer)]
        )
        XCTAssertEqual(retainedOplog.count, 40)
        let retainedEntries = retainedOplog.compactMap { row -> String? in
            guard let rev = row.column("revision")?.integer,
                  let idx = row.column("operation_index")?.integer else { return nil }
            return "\(rev):\(idx)"
        }
        var expectedEntries: [String] = []
        for rev in 7 ... 10 {
            for idx in 0 ..< 10 {
                expectedEntries.append("\(rev):\(idx)")
            }
        }
        XCTAssertEqual(retainedEntries, expectedEntries)
        // Requests ledger retains all 10 receipts since 10 <= 35
        let retainedRequests = try await database.connection.query(
            """
            SELECT final_revision
            FROM permissioned_space_requests
            WHERE space_uri = ? AND author_did = ?
            ORDER BY final_revision ASC
            """,
            [.text(fixture.space.rawValue), .text(fixture.writer)]
        )
        XCTAssertEqual(retainedRequests.count, 10)
        XCTAssertEqual(
            retainedRequests.compactMap { $0.column("final_revision")?.integer },
            Array(1 ... 10)
        )

    }



    /// Receipts written before the retention column exists carry no timestamp.
    /// They must survive the upgrade and prune first, never win retention over
    /// a stamped row.
    func testRequestReceiptMigrationStampsExistingRowsAsOldest() async throws {
        let fixture = try NotificationFixture()
        let database = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root,
            did: fixture.writer,
            oplogRetention: 2
        )
        let uri = try SpaceRecordURI(
            space: fixture.space,
            author: fixture.writer,
            collection: "app.bsky.feed.post",
            rkey: "migrated"
        )
        let legacyValue = Data([0xA1, 0x61, 0x61, 0x01])
        let legacyRequestID = UUID()
        _ = try await database.apply(
            space: fixture.space,
            author: fixture.writer,
            expectedRevision: 0,
            requestID: legacyRequestID,
            wireRevision: try fixture.tid(1),
            writes: [
                .put(
                    uri: uri,
                    value: legacyValue,
                    cid: CID.fromDAGCBOR(legacyValue).string
                ),
            ]
        )
        try await database.close()

        let databasePath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.writer
        ).path
        let legacy = try await SQLiteConnection.open(
            storage: .file(path: databasePath)
        )
        do {
            _ = try await legacy.query(
                "DELETE FROM permissioned_repository_migrations WHERE version = 16"
            )
            _ = try await legacy.query(
                "ALTER TABLE permissioned_space_requests DROP COLUMN created_at"
            )
            let preUpgradeColumns = try await legacy.query(
                "PRAGMA table_info(permissioned_space_requests)"
            )
            XCTAssertFalse(
                preUpgradeColumns.contains { $0.column("name")?.string == "created_at" }
            )
        } catch {
            // An unclosed connection traps in `deinit` and would truncate the
            // whole target's run, hiding this failure.
            try? await legacy.close()
            throw error
        }
        try await legacy.close()

        let reopened = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root,
            did: fixture.writer,
            oplogRetention: 2
        )
        defer { Task { try? await reopened.close() } }
        let migrated = try await reopened.connection.query(
            """
            SELECT request_id, created_at
            FROM permissioned_space_requests
            """
        )
        XCTAssertEqual(migrated.count, 1)
        XCTAssertEqual(
            migrated.first?.column("request_id")?.string,
            legacyRequestID.uuidString
        )
        XCTAssertEqual(migrated.first?.column("created_at")?.integer, 0)

        // Two stamped writes must evict the unstamped legacy row first.
        for index in 2 ... 3 {
            let value = Data([0xA1, 0x61, 0x61, UInt8(index)])
            _ = try await reopened.apply(
                space: fixture.space,
                author: fixture.writer,
                expectedRevision: UInt64(index - 1),
                requestID: UUID(),
                wireRevision: try fixture.tid(index),
                writes: [
                    .put(
                        uri: uri,
                        value: value,
                        cid: CID.fromDAGCBOR(value).string
                    ),
                ]
            )
        }
        let remaining = try await reopened.connection.query(
            "SELECT request_id FROM permissioned_space_requests"
        )
        XCTAssertEqual(remaining.count, 2)
        XCTAssertFalse(
            remaining.contains { $0.column("request_id")?.string == legacyRequestID.uuidString }
        )
    }

    func testDeletedAndRecreatedSpaceAcceptsWriterNotificationAtPreviouslySeenRevision() async throws {
        let fixture = try NotificationFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        do {
            try await fixture.createAuthorityState(on: database)

            let revision = try fixture.tid(1)
            let writeNotification1 = fixture.writeNotification(
                eventID: "event-1",
                revision: revision,
                commitmentByte: 0xaa
            )
            try await database.receiveSpaceWriteNotification(
                writeNotification1,
                now: Date()
            )

            let writersBefore = try await database.spaceWriters(
                space: fixture.space,
                limit: 100,
                cursor: nil,
                authorization: fixture.readCredential()
            )
            XCTAssertEqual(writersBefore.count, 1)

            let authority = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
            _ = try await authority.delete(
                space: fixture.space,
                authorization: .accountOAuthForTesting(subject: fixture.authority, scopes: ["atproto"])
            )
            do {
                _ = try await database.spaceWriters(
                    space: fixture.space,
                    limit: 100,
                    cursor: nil,
                    authorization: fixture.readCredential()
                )
                XCTFail("deleted space must return not found")
            } catch let error as AuthorizedSimpleSpaceLifecycleError {
                XCTAssertEqual(error, .notFound)
            }

            _ = try await authority.create(
                space: fixture.space,
                owner: fixture.authority,
                configuration: try SimpleSpaceConfiguration(readPolicy: .memberList, writePolicy: .memberList, appAccess: .open),
                authorization: .accountOAuthForTesting(subject: fixture.authority, scopes: ["atproto"])
            )
            _ = try await authority.putMembers(
                space: fixture.space,
                members: [.init(did: fixture.writer, read: true, write: true)],
                authorization: .accountOAuthForTesting(subject: fixture.authority, scopes: ["atproto"])
            )

            let writeNotification2 = fixture.writeNotification(
                eventID: "event-2",
                revision: revision,
                commitmentByte: 0xbb
            )
            try await database.receiveSpaceWriteNotification(
                writeNotification2,
                now: Date()
            )
            try await database.close()
        } catch {
            print("DELETE_RECREATE_ERROR: \(error)")
            try? await database.close()
            throw error
        }
    }

    func testWriterForeignKeyMigrationRebuildsTableAndDropsConstraintWhilePreservingRows() async throws {
        let fixture = try NotificationFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        try await fixture.createAuthorityState(on: database)
        try await database.close()

        let databasePath = SQLiteLayout.accountDatabase(in: fixture.root, did: fixture.authority).path
        let legacy = try await SQLiteConnection.open(storage: .file(path: databasePath))

        _ = try await legacy.query(
            "DELETE FROM permissioned_repository_migrations WHERE version = 21"
        )
        _ = try await legacy.query("DROP TABLE IF EXISTS permissioned_space_writers")
        _ = try await legacy.query(
            """
            CREATE TABLE permissioned_space_writers (
                space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
                repo_did TEXT NOT NULL,
                wire_revision TEXT NOT NULL,
                commitment BLOB NOT NULL CHECK(length(commitment) = 32),
                updated_at INTEGER NOT NULL CHECK(updated_at >= 0),
                PRIMARY KEY(space_uri, repo_did)
            )
            """
        )
        let commitment = Data(repeating: 0x42, count: 32)
        let revision1 = try fixture.tid(1).toString()
        _ = try await legacy.query(
            """
            INSERT INTO permissioned_space_writers (space_uri, repo_did, wire_revision, commitment, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                .text(fixture.space.rawValue),
                .text(fixture.writer),
                .text(revision1),
                .blob(ByteBuffer(data: commitment)),
                .integer(1_000_000)
            ]
        )
        let fkListBefore = try await legacy.query("PRAGMA foreign_key_list(permissioned_space_writers)")
        XCTAssertFalse(fkListBefore.isEmpty, "legacy table must have foreign key constraint")
        try await legacy.close()

        let reopened = try await fixture.open()
        try await reopened.close()
        let raw = try await SQLiteConnection.open(storage: .file(path: databasePath))
        let fkListAfter = try await raw.query("PRAGMA foreign_key_list(permissioned_space_writers)")
        XCTAssertTrue(fkListAfter.isEmpty, "migrated table must have no foreign key constraint")

        let migratedRows = try await raw.query(
            "SELECT space_uri, repo_did, wire_revision, commitment FROM permissioned_space_writers"
        )
        XCTAssertEqual(migratedRows.count, 1)
        XCTAssertEqual(migratedRows.first?.column("space_uri")?.string, fixture.space.rawValue)
        XCTAssertEqual(migratedRows.first?.column("repo_did")?.string, fixture.writer)
        XCTAssertEqual(migratedRows.first?.column("commitment")?.blob.map { Data($0.readableBytesView) }, commitment)
        try await raw.close()

        let database2 = try await fixture.open()
        let externalSpace = try SpaceURI(authority: "did:plc:external", spaceType: "app.bsky.bookmarks", skey: "ext")
        let revision2 = try fixture.tid(2).toString()
        _ = try await database2.advanceWriterHighWaterWithoutGate(
            space: externalSpace,
            repository: "did:plc:external-writer",
            wireRevision: revision2,
            commitment: commitment,
            updatedAt: 2_000_000
        )
        try await database2.close()
    }






    func testSpaceDeleteAndRecreateRemovesWriterHighWaterAndAdmitsLiveNotificationAndRecovery() async throws {
        let fixture = try NotificationFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)
        let now = Date()
        try await database.putSpaceSyncRegistration(.init(
            space: fixture.space,
            endpoint: "https://recreated-syncer.example",
            token: "recreated-token",
            expiresAt: now.addingTimeInterval(600)
        ))

        let eventID1 = "writer-event-rev1"
        let rev1 = try fixture.tid(1)
        let notification1 = fixture.writeNotification(
            eventID: eventID1,
            revision: rev1,
            commitmentByte: 0x42,
            space: fixture.space
        )
        try await database.receiveSpaceWriteNotification(notification1)

        // Verify permissioned_space_writers contains the writer high-water row
        let writersBeforeDelete = try await database.connection.query(
            "SELECT space_uri, repo_did, wire_revision FROM permissioned_space_writers WHERE space_uri = ?",
            [.text(fixture.space.rawValue)]
        )
        XCTAssertEqual(writersBeforeDelete.count, 1)
        XCTAssertEqual(writersBeforeDelete.first?.column("repo_did")?.string, fixture.writer)
        XCTAssertEqual(writersBeforeDelete.first?.column("wire_revision")?.string, rev1.toString())

        // Delete the space
        let authContext = AuthorizationContext.accountOAuthForTesting(subject: fixture.authority, scopes: ["atproto"])
        _ = try await database.deleteSimpleSpace(space: fixture.space, authorization: authContext)
        let queuedDeletion = try await database.pendingSpaceSyncNotifications()
        XCTAssertEqual(queuedDeletion.map(\.kind), [.spaceDeleted])

        // Verify permissioned_space_writers is empty immediately after delete
        let writersAfterDelete = try await database.connection.query(
            "SELECT space_uri, repo_did FROM permissioned_space_writers WHERE space_uri = ?",
            [.text(fixture.space.rawValue)]
        )
        XCTAssertTrue(writersAfterDelete.isEmpty, "permissioned_space_writers must be empty immediately after delete")

        // Recreate the space through createSimpleSpace
        let authority = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
        _ = try await authority.create(
            space: fixture.space,
            owner: fixture.authority,
            configuration: try SimpleSpaceConfiguration(readPolicy: .memberList, writePolicy: .memberList, appAccess: .open),
            authorization: authContext
        )
        _ = try await authority.putMembers(
            space: fixture.space,
            members: [.init(did: fixture.writer, read: true, write: true)],
            authorization: authContext
        )
        let queuedAfterRevival = try await database.pendingSpaceSyncNotifications()
        XCTAssertTrue(
            queuedAfterRevival.isEmpty,
            "a revived space must not inherit its deletion notice"
        )

        // Submit a notification at the same wire revision/commitment as before
        let eventID2 = "writer-event-revived"
        let notificationRecreate = fixture.writeNotification(
            eventID: eventID2,
            revision: rev1,
            commitmentByte: 0x42,
            space: fixture.space
        )
        try await database.receiveSpaceWriteNotification(notificationRecreate)

        // Verify writer high-water row is recorded for the recreated space
        let writersAfterRecreate = try await database.connection.query(
            "SELECT space_uri, repo_did, wire_revision FROM permissioned_space_writers WHERE space_uri = ?",
            [.text(fixture.space.rawValue)]
        )
        XCTAssertEqual(writersAfterRecreate.count, 1)
        XCTAssertEqual(writersAfterRecreate.first?.column("wire_revision")?.string, rev1.toString())
    }

    func testSequencedWriteAndRemovalQueueContinuousUpdates() async throws {
        let fixture = try NotificationFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)
        let now = Date()
        try await database.putSpaceSyncRegistration(
            .init(
                space: fixture.space,
                endpoint: "https://syncer.example",
                token: "write-token",
                expiresAt: now.addingTimeInterval(600)
            )
        )

        try await database.receiveSpaceWriteNotification(
            fixture.writeNotification(
                eventID: "continuous-write",
                revision: try fixture.tid(1),
                commitmentByte: 0x42
            ),
            now: now
        )
        try await database.removeSpaceWriter(
            space: fixture.space,
            writer: fixture.writer,
            authorization: .accountOAuthForTesting(
                subject: fixture.authority,
                scopes: ["atproto"]
            )
        )

        let pending = try await database.pendingSpaceSyncNotifications()
        XCTAssertEqual(pending.map(\.kind), [.repoWrite, .repoRemoved])
        XCTAssertEqual(pending.map(\.repository), [fixture.writer, fixture.writer])
        XCTAssertEqual(pending[0].wireRevision, try fixture.tid(1).toString())
        XCTAssertEqual(pending[0].commitment, Data(repeating: 0x42, count: 32))
        XCTAssertNil(pending[0].previousSpaceRevision)
        XCTAssertEqual(
            pending[1].previousSpaceRevision,
            pending[0].spaceRevision
        )
    }

    func testBatchMemberChangesQueueOnlyRemovedWriterTombstones() async throws {
        let fixture = try NotificationFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)
        let authority = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
        let authorization = AuthorizationContext.accountOAuthForTesting(
            subject: fixture.authority,
            scopes: ["atproto"]
        )
        let now = Date()
        try await database.putSpaceSyncRegistration(.init(
            space: fixture.space,
            endpoint: "https://syncer.example",
            token: "batch-token",
            expiresAt: now.addingTimeInterval(600)
        ))
        try await database.receiveSpaceWriteNotification(
            fixture.writeNotification(
                eventID: "batch-write-1",
                revision: try fixture.tid(1),
                commitmentByte: 1
            ),
            now: now
        )
        _ = try await database.connection.query(
            "DELETE FROM permissioned_space_sync_notifications"
        )

        _ = try await authority.putMembers(
            space: fixture.space,
            members: [
                .init(did: fixture.writer, read: true, write: false),
                .init(did: fixture.reader, read: true, write: false),
            ],
            authorization: authorization,
            now: now
        )
        var pending = try await database.pendingSpaceSyncNotifications()
        XCTAssertEqual(pending.map(\.kind), [.repoRemoved])
        XCTAssertEqual(pending.map(\.repository), [fixture.writer])

        _ = try await authority.putMembers(
            space: fixture.space,
            members: [.init(did: fixture.writer, read: true, write: true)],
            authorization: authorization,
            now: now
        )
        try await database.receiveSpaceWriteNotification(
            fixture.writeNotification(
                eventID: "batch-write-2",
                revision: try fixture.tid(2),
                commitmentByte: 2
            ),
            now: now
        )
        _ = try await database.connection.query(
            "DELETE FROM permissioned_space_sync_notifications"
        )
        _ = try await authority.removeMembers(
            space: fixture.space,
            members: [
                fixture.authority,
                fixture.writer,
                fixture.reader,
                "did:plc:not-a-member",
            ],
            authorization: authorization,
            now: now
        )
        pending = try await database.pendingSpaceSyncNotifications()
        XCTAssertEqual(pending.map(\.kind), [.repoRemoved])
        XCTAssertEqual(pending.map(\.repository), [fixture.writer])
    }

    func testLapsedRegistrationGetsOneExpiryAndThenSilence() async throws {
        let fixture = try NotificationFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)
        let now = Date()
        try await database.putSpaceSyncRegistration(
            .init(
                space: fixture.space,
                endpoint: "https://syncer.example",
                token: "lapsed-token",
                expiresAt: now.addingTimeInterval(-1)
            )
        )

        for index in 1 ... 2 {
            try await database.receiveSpaceWriteNotification(
                fixture.writeNotification(
                    eventID: "lapsed-write-\(index)",
                    revision: try fixture.tid(index),
                    commitmentByte: UInt8(index)
                ),
                now: now.addingTimeInterval(TimeInterval(index))
            )
        }

        let pending = try await database.pendingSpaceSyncNotifications()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending.first?.kind, .registrationExpired)
        let expiredAt = try XCTUnwrap(pending.first?.registrationExpiredAt)
        XCTAssertEqual(
            expiredAt.timeIntervalSince1970,
            now.addingTimeInterval(-1).timeIntervalSince1970,
            accuracy: 0.000_001
        )
        let registration = try await database.spaceSyncRegistration(
            space: fixture.space,
            endpoint: "https://syncer.example",
            token: "lapsed-token"
        )
        XCTAssertEqual(registration?.expiryNotified, true)
    }

    func testReliableExpiryBackoffAndRejectionDropRegistration() async throws {
        let fixture = try NotificationFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)
        let start = Date()
        let endpoint = "https://syncer.example"
        try await database.putSpaceSyncRegistration(
            .init(
                space: fixture.space,
                endpoint: endpoint,
                token: "retry-token",
                expiresAt: start.addingTimeInterval(-1)
            )
        )
        try await database.receiveSpaceWriteNotification(
            fixture.writeNotification(
                eventID: "retry-write",
                revision: try fixture.tid(1),
                commitmentByte: 1
            ),
            now: start
        )
        let retrying = RecordingSpaceSyncTransport(.retryableFailure)
        let retryWorker = PermissionedSpaceSyncNotificationDeliveryWorker(
            database: database,
            transport: retrying
        )
        let queuedForRetry = try await database.pendingSpaceSyncNotifications()
        let retryEventID = try XCTUnwrap(queuedForRetry.first?.id)
        var attemptAt = start
        for (index, delay) in [60, 600, 3_600, 21_600, 43_200].enumerated() {
            let result = try await retryWorker.deliverNext(now: attemptAt)
            XCTAssertEqual(
                result,
                .failed(eventID: retryEventID, attempts: index + 1)
            )
            let available = try await database.connection.query(
                """
                SELECT available_at FROM permissioned_space_sync_notifications
                WHERE token = 'retry-token'
                """
            ).first?.column("available_at")?.integer
            XCTAssertEqual(
                available,
                Int(attemptAt.addingTimeInterval(TimeInterval(delay))
                    .timeIntervalSince1970 * 1_000_000)
            )
            attemptAt = attemptAt.addingTimeInterval(TimeInterval(delay))
        }
        guard case .dropped = try await retryWorker.deliverNext(
            now: start.addingTimeInterval(72 * 60 * 60 + 1)
        ) else {
            return XCTFail("retry exhaustion must drop the registration")
        }
        let exhaustedRegistration = try await database.spaceSyncRegistration(
            space: fixture.space,
            endpoint: endpoint,
            token: "retry-token"
        )
        XCTAssertNil(exhaustedRegistration)

        let rejectedAt = start.addingTimeInterval(72 * 60 * 60 + 1)
        try await database.putSpaceSyncRegistration(
            .init(
                space: fixture.space,
                endpoint: endpoint,
                token: "rejected-token",
                expiresAt: rejectedAt.addingTimeInterval(-1)
            )
        )
        try await database.receiveSpaceWriteNotification(
            fixture.writeNotification(
                eventID: "rejected-write",
                revision: try fixture.tid(2),
                commitmentByte: 2
            ),
            now: rejectedAt
        )
        let rejectedWorker = PermissionedSpaceSyncNotificationDeliveryWorker(
            database: database,
            transport: RecordingSpaceSyncTransport(.rejected)
        )
        guard case .dropped = try await rejectedWorker.deliverNext(now: rejectedAt)
        else {
            return XCTFail("a permanent rejection must drop the registration")
        }
        let rejectedRegistration = try await database.spaceSyncRegistration(
            space: fixture.space,
            endpoint: endpoint,
            token: "rejected-token"
        )
        XCTAssertNil(rejectedRegistration)
    }

    func testDeletionQueuesActiveAndLapsedRegistrations() async throws {
        let fixture = try NotificationFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)
        let now = Date()
        for (token, offset) in [("active-token", 600.0), ("lapsed-token", -1.0)] {
            try await database.putSpaceSyncRegistration(
                .init(
                    space: fixture.space,
                    endpoint: "https://\(token).example",
                    token: token,
                    expiresAt: now.addingTimeInterval(offset)
                )
            )
        }
        _ = try await database.deleteSimpleSpace(
            space: fixture.space,
            authorization: .accountOAuthForTesting(
                subject: fixture.authority,
                scopes: ["atproto"]
            ),
            now: now
        )

        let pending = try await database.pendingSpaceSyncNotifications()
        XCTAssertEqual(pending.count, 2)
        XCTAssertTrue(pending.allSatisfy { $0.kind == .spaceDeleted })
        XCTAssertEqual(Set(pending.map(\.token)), ["active-token", "lapsed-token"])
        let registrations = try await database.connection.query(
            "SELECT 1 FROM permissioned_space_sync_registrations"
        )
        XCTAssertTrue(registrations.isEmpty)

        let transport = RecordingSpaceSyncTransport(.delivered)
        let worker = PermissionedSpaceSyncNotificationDeliveryWorker(
            database: database,
            transport: transport
        )
        for _ in 0 ..< 2 {
            guard case .delivered = try await worker.deliverNext(now: now) else {
                return XCTFail("deletion delivery must drain reliably")
            }
        }
        let deliveredEvents = await transport.events()
        XCTAssertEqual(deliveredEvents.count, 2)
    }

    func testInvalidStoredEndpointIsDroppedBeforeTheNextDelivery() async throws {
        let fixture = try NotificationFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)
        let now = Date()
        do {
            try await database.putSpaceSyncRegistration(.init(
                space: fixture.space,
                endpoint: "https://exa\u{200b}mple.com",
                token: "poison",
                expiresAt: now.addingTimeInterval(600)
            ))
            XCTFail("persistence must reject a non-ASCII endpoint")
        } catch {}
        try await database.putSpaceSyncRegistration(.init(
            space: fixture.space,
            endpoint: "https://healthy.example",
            token: "healthy",
            expiresAt: now.addingTimeInterval(600)
        ))
        try await database.receiveSpaceWriteNotification(
            fixture.writeNotification(
                eventID: "healthy-write",
                revision: try fixture.tid(1),
                commitmentByte: 1
            ),
            now: now
        )
        let poisonID = UUID().uuidString
        _ = try await database.connection.query(
            """
            INSERT INTO permissioned_space_sync_notifications(
                id, kind, space_uri, endpoint, token, repo_did, repo_revision,
                commitment, space_revision, previous_space_revision,
                registration_expires_at, attempts, created_at, available_at,
                retry_expires_at, lease_token, lease_expires_at
            )
            SELECT ?, kind, space_uri, ?, ?, repo_did, repo_revision,
                   commitment, space_revision, previous_space_revision,
                   registration_expires_at, attempts, created_at - 1000000,
                   available_at - 1000000, retry_expires_at, NULL, NULL
            FROM permissioned_space_sync_notifications
            LIMIT 1
            """,
            [
                .text(poisonID),
                .text("https://exa\u{200b}mple.com"),
                .text("poison"),
            ]
        )
        let transport = RecordingSpaceSyncTransport(.delivered)
        let worker = PermissionedSpaceSyncNotificationDeliveryWorker(
            database: database,
            transport: transport
        )
        guard case .delivered = try await worker.deliverNext(
            now: now.addingTimeInterval(2)
        ) else {
            return XCTFail("the valid row after poison must be delivered")
        }
        let delivered = await transport.events()
        XCTAssertEqual(delivered.map(\.endpoint), ["https://healthy.example"])
        let pendingAfterPoison = try await database.pendingSpaceSyncNotifications()
        XCTAssertTrue(pendingAfterPoison.isEmpty)
    }

    func testReliableRowsPrecedeFreshBestEffortAndOldBestEffortExpires() async throws {
        let fixture = try NotificationFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        try await database.putSpaceSyncRegistration(.init(
            space: fixture.space,
            endpoint: "https://active.example",
            token: "active",
            expiresAt: start.addingTimeInterval(600)
        ))
        try await database.receiveSpaceWriteNotification(
            fixture.writeNotification(
                eventID: "fresh-write-1",
                revision: try fixture.tid(1),
                commitmentByte: 1
            ),
            now: start
        )
        try await database.putSpaceSyncRegistration(.init(
            space: fixture.space,
            endpoint: "https://lapsed.example",
            token: "lapsed",
            expiresAt: start.addingTimeInterval(-1)
        ))
        try await database.receiveSpaceWriteNotification(
            fixture.writeNotification(
                eventID: "fresh-write-2",
                revision: try fixture.tid(2),
                commitmentByte: 2
            ),
            now: start.addingTimeInterval(1)
        )
        let transport = RecordingSpaceSyncTransport(.delivered)
        let worker = PermissionedSpaceSyncNotificationDeliveryWorker(
            database: database,
            transport: transport
        )
        guard case .delivered = try await worker.deliverNext(
            now: start.addingTimeInterval(2)
        ) else {
            return XCTFail("the reliable row must be leased first")
        }
        let firstEvents = await transport.events()
        XCTAssertEqual(firstEvents.map(\.kind), [.registrationExpired])
        let afterExpiry = try await worker.deliverNext(
            now: start.addingTimeInterval(63)
        )
        XCTAssertEqual(afterExpiry, .idle)
        let pending = try await database.pendingSpaceSyncNotifications()
        XCTAssertTrue(pending.isEmpty)
    }

    func testRegistrationCapacityEvictsOldestNotifiedLapse() async throws {
        let fixture = try NotificationFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)
        _ = try await database.connection.query(
            """
            WITH RECURSIVE registrations(n) AS (
                VALUES(0) UNION ALL SELECT n + 1 FROM registrations WHERE n < 1023
            )
            INSERT INTO permissioned_space_sync_registrations(
                space_uri, endpoint, token, expires_at, expiry_notified, updated_at
            )
            SELECT ?, 'https://syncer-' || n || '.example', 'token-' || n,
                   1, CASE WHEN n < 2 THEN 1 ELSE 0 END, n + 1
            FROM registrations
            """,
            [.text(fixture.space.rawValue)]
        )
        let now = Date()
        try await database.putSpaceSyncRegistration(.init(
            space: fixture.space,
            endpoint: "https://new-syncer.example",
            token: "new-token",
            expiresAt: now.addingTimeInterval(600)
        ))
        let rows = try await database.connection.query(
            """
            SELECT endpoint, token
            FROM permissioned_space_sync_registrations
            WHERE space_uri = ?
            """,
            [.text(fixture.space.rawValue)]
        )
        XCTAssertEqual(rows.count, 1_024)
        XCTAssertFalse(rows.contains {
            $0.column("endpoint")?.string == "https://syncer-0.example"
        })
        XCTAssertTrue(rows.contains {
            $0.column("endpoint")?.string == "https://new-syncer.example"
                && $0.column("token")?.string == "new-token"
        })
    }
}

private struct NotificationFixture {
    let root: URL
    let authority = "did:plc:alice"
    let writer = "did:plc:bob"
    let reader = "did:plc:reader"
    let space: SpaceURI
    let secondarySpace: SpaceURI

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSpaceNotificationTests-\(UUID().uuidString)")
        space = try SpaceURI(
            authority: authority,
            spaceType: "app.bsky.bookmarks",
            skey: "notifications"
        )
        secondarySpace = try SpaceURI(
            authority: authority,
            spaceType: "app.bsky.bookmarks",
            skey: "notifications-secondary"
        )
    }

    func open() async throws -> SQLiteAccountDatabase {
        try await SQLiteAccountDatabase(dataDirectory: root, did: authority)
    }

    func createAuthorityState(on database: SQLiteAccountDatabase) async throws {
        let authority = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
        _ = try await authority.create(
            space: space,
            owner: self.authority,
            configuration: try SimpleSpaceConfiguration(readPolicy: .memberList, writePolicy: .memberList, appAccess: .open),
            authorization: .accountOAuthForTesting(subject: self.authority, scopes: ["atproto"])
        )
        _ = try await authority.putMembers(
            space: space,
            members: [.init(did: writer, read: true, write: true)],
            authorization: .accountOAuthForTesting(subject: self.authority, scopes: ["atproto"])
        )
    }

    func createSecondaryAuthorityState(on database: SQLiteAccountDatabase) async throws {
        let authority = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
        _ = try await authority.create(
            space: secondarySpace,
            owner: self.authority,
            configuration: try SimpleSpaceConfiguration(readPolicy: .memberList, writePolicy: .memberList, appAccess: .open),
            authorization: .accountOAuthForTesting(subject: self.authority, scopes: ["atproto"])
        )
        _ = try await authority.putMembers(
            space: secondarySpace,
            members: [.init(did: writer, read: true, write: true)],
            authorization: .accountOAuthForTesting(subject: self.authority, scopes: ["atproto"])
        )
    }

    func readCredential(for space: SpaceURI? = nil) -> AuthorizationContext {
        let space = space ?? self.space
        return .spaceCredential(.init(
            subject: reader,
            space: space,
            permissions: [.read],
            expiresAt: Date(timeIntervalSinceNow: 3_600)
        ))
    }


    func writeNotification(
        eventID: String,
        revision: TID,
        commitmentByte: UInt8,
        space: SpaceURI? = nil
    ) -> AuthorizedSpaceWriteNotification {
        let space = space ?? self.space
        let commitment = Data(repeating: commitmentByte, count: 32)
        return AuthorizedSpaceWriteNotification(
            eventID: eventID,
            space: space,
            repository: writer,
            wireRevision: revision.toString(),
            commitment: commitment,
            issuer: writer,
            audience: authority,
            requestBodyDigest: SpaceNotificationRequestDigest.write(
                space: space,
                repository: writer,
                wireRevision: revision.toString(),
                commitment: commitment
            )
        )
    }

    func tid(_ offset: Int) throws -> TID {
        let alphabet = Array("234567abcdefghijklmnopqrstuvwxyz")
        return try TID(tidString: "222222222222\(alphabet[offset])")
    }

}

private actor RecordingSpaceSyncTransport:
    PermissionedSpaceSyncNotificationTransport
{
    private let disposition: PermissionedSpaceSyncNotificationDisposition
    private var deliveredEvents: [PersistedSpaceSyncNotification] = []

    init(_ disposition: PermissionedSpaceSyncNotificationDisposition) {
        self.disposition = disposition
    }

    func deliver(
        _ notification: PersistedSpaceSyncNotification
    ) async -> PermissionedSpaceSyncNotificationDisposition {
        deliveredEvents.append(notification)
        return disposition
    }

    func events() -> [PersistedSpaceSyncNotification] {
        deliveredEvents
    }
}



