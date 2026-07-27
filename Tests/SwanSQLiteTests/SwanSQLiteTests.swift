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
            eventID: UUID(uuidString: "20000000-0000-0000-0000-000000000001")!
        )
        XCTAssertEqual(result.state.revision, 1)
        XCTAssertEqual(
            result.outbox.payload,
            Data(result.outbox.id.uuidString.lowercased().utf8)
        )
        XCTAssertNil(result.outbox.payload.range(of: fixture.firstValue))
        try await database!.close()
        database = nil

        let reopened = try await fixture.open()
        try await withClosedAccountDatabase(reopened) { reopened in
            let loadedSnapshot = try await reopened.repositorySnapshot(
                space: fixture.space,
                author: fixture.author
            )
            let snapshot = try XCTUnwrap(loadedSnapshot)
            XCTAssertEqual(snapshot.state.revision, 1)
            XCTAssertEqual(snapshot.state.ltHash.count, LtHash.byteCount)
            XCTAssertEqual(snapshot.state.commit, result.state.commit)
            XCTAssertNotEqual(snapshot.state.commit, Data([0x00, 0xff, 0x42]))
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
            XCTAssertEqual(pending, [result.outbox])
        }
    }

    func testOutboxWorkerDeliversOnceWithOpaquePayloadOutsideSQLiteTransaction() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        try await withClosedAccountDatabase(database) { database in
            let committed = try await fixture.commitFirst(on: database)
            let transport = RecordingOutboxTransport(database: database)
            let worker = PermissionedSpaceOutboxDeliveryWorker(
                database: database,
                transport: transport,
                configuration: try outboxConfiguration()
            )
            let now = Date(timeIntervalSinceNow: 60)

            let result = try await worker.deliverNext(now: now)
            XCTAssertEqual(result, .delivered(eventID: committed.outbox.id))
            let pending = try await database.pendingOutbox()
            let followUp = try await worker.deliverNext(now: now)
            XCTAssertEqual(pending, [])
            XCTAssertEqual(followUp, .idle)

            let delivered = await transport.notifications()
            XCTAssertEqual(delivered.count, 1)
            XCTAssertEqual(delivered.first?.id, committed.outbox.id)
            XCTAssertEqual(delivered.first?.payload, Data(committed.outbox.id.uuidString.lowercased().utf8))
            XCTAssertNil(delivered.first?.payload.range(of: fixture.firstValue))
            XCTAssertNil(delivered.first?.payload.range(of: Data("cid:first".utf8)))
            let transactionStates = await transport.observedWriteTransactions()
            XCTAssertEqual(transactionStates, [false])
        }
    }

    func testOutboxWorkerFailureIncrementsAttemptsAndUsesBoundedRetryDeadline() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        try await withClosedAccountDatabase(database) { database in
            let committed = try await fixture.commitFirst(on: database)
            let transport = RecordingOutboxTransport(database: database, failuresRemaining: 1)
            let configuration = try outboxConfiguration(
                initialFailureBackoff: 3,
                maximumFailureBackoff: 4
            )
            let worker = PermissionedSpaceOutboxDeliveryWorker(
                database: database,
                transport: transport,
                configuration: configuration
            )
            let now = Date(timeIntervalSinceNow: 60)

            let firstResult = try await worker.deliverNext(now: now)
            let pending = try await database.pendingOutbox()
            let beforeRetry = try await worker.deliverNext(now: now.addingTimeInterval(2.9))
            let retryResult = try await worker.deliverNext(now: now.addingTimeInterval(3))
            let deliveredIDs = (await transport.notifications()).map(\.id)
            let transactionStates = await transport.observedWriteTransactions()
            XCTAssertEqual(firstResult, .failed(eventID: committed.outbox.id, attempts: 1))
            XCTAssertEqual(pending.first?.attempts, 1)
            XCTAssertEqual(beforeRetry, .idle)
            XCTAssertEqual(retryResult, .delivered(eventID: committed.outbox.id))
            XCTAssertEqual(deliveredIDs, [committed.outbox.id, committed.outbox.id])
            XCTAssertEqual(transactionStates, [false, false])
        }
    }

    func testOutboxWorkerFailsClosedBeforeMaximumAttemptArithmetic() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        let committed = try await fixture.commitFirst(on: database)
        try await database.close()

        let databasePath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        ).path
        let rawConnection = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await rawConnection.query(
            "UPDATE permissioned_space_outbox SET attempts = ? WHERE id = ?",
            [.integer(Int.max), .text(committed.outbox.id.uuidString)]
        )
        try await rawConnection.close()

        let reopened = try await fixture.open()
        try await withClosedAccountDatabase(reopened) { reopened in
            let transport = RecordingOutboxTransport(database: reopened, failuresRemaining: 1)
            let worker = PermissionedSpaceOutboxDeliveryWorker(
                database: reopened,
                transport: transport,
                configuration: try outboxConfiguration()
            )

            await XCTAssertThrowsErrorAsync(
                try await worker.deliverNext(now: Date(timeIntervalSinceNow: 60))
            ) { error in
                XCTAssertEqual(
                    error as? SQLiteRepositoryError,
                    .corruptDatabase("outbox attempts overflow")
                )
            }
            let delivered = await transport.notifications()
            XCTAssertEqual(delivered, [])
        }
    }

    func testExpiredLeaseIsRecoveredAfterDatabaseRestartAndStaleTokenCannotAcknowledge() async throws {
        let fixture = try Fixture()
        var database: SQLiteAccountDatabase? = try await fixture.open()
        let committed = try await fixture.commitFirst(on: database!)
        let now = Date(timeIntervalSinceNow: 60)
        let maybeFirstLease = try await database!.leaseNextOutbox(
            now: now,
            leaseDuration: 2
        )
        let firstLease = try XCTUnwrap(maybeFirstLease)
        try await database!.close()
        database = nil

        let reopened = try await fixture.open()
        try await withClosedAccountDatabase(reopened) { reopened in
            let beforeExpiry = try await reopened.leaseNextOutbox(
                now: now.addingTimeInterval(1),
                leaseDuration: 2
            )
            let maybeRecovered = try await reopened.leaseNextOutbox(
                now: now.addingTimeInterval(3),
                leaseDuration: 2
            )
            XCTAssertNil(beforeExpiry)
            let recovered = try XCTUnwrap(maybeRecovered)
            XCTAssertEqual(recovered.event.id, committed.outbox.id)
            XCTAssertNotEqual(recovered.token, firstLease.token)
            let staleCompletion = try await reopened.completeOutboxLease(
                eventID: committed.outbox.id,
                token: firstLease.token
            )
            let recoveredCompletion = try await reopened.completeOutboxLease(
                eventID: committed.outbox.id,
                token: recovered.token
            )
            let pending = try await reopened.pendingOutbox()
            XCTAssertFalse(staleCompletion)
            XCTAssertTrue(recoveredCompletion)
            XCTAssertEqual(pending, [])
        }
    }

    func testOutboxLeaseMigrationUpgradesVersionOneRowsWithoutExposingPayload() async throws {
        let fixture = try Fixture()
        let databaseURL = SQLiteLayout.accountDatabase(in: fixture.root, did: fixture.author)
        try FileManager.default.createDirectory(
            at: databaseURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let eventID = UUID(uuidString: "20000000-0000-0000-0000-000000000099")!
        let createdAt = Int(Date().timeIntervalSince1970 * 1_000_000)
        let raw = try await SQLiteConnection.open(storage: .file(path: databaseURL.path))
        _ = try await raw.query(
            """
            CREATE TABLE permissioned_repository_migrations (
                version INTEGER PRIMARY KEY CHECK(version > 0),
                applied_at INTEGER NOT NULL CHECK(applied_at >= 0)
            )
            """
        )
        _ = try await raw.query(
            """
            CREATE TABLE permissioned_space_outbox (
                id TEXT PRIMARY KEY,
                space_uri TEXT NOT NULL,
                author_did TEXT NOT NULL,
                revision INTEGER NOT NULL,
                payload BLOB NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            )
            """
        )
        _ = try await raw.query(
            "INSERT INTO permissioned_repository_migrations(version, applied_at) VALUES (1, ?)",
            [.integer(createdAt)]
        )
        _ = try await raw.query(
            """
            INSERT INTO permissioned_space_outbox(
                id, space_uri, author_did, revision, payload, attempts, created_at
            ) VALUES (?, ?, ?, 1, ?, 0, ?)
            """,
            [
                .text(eventID.uuidString), .text(fixture.space.rawValue),
                .text(fixture.author),
                Data(eventID.uuidString.lowercased().utf8).sqliteData!,
                .integer(createdAt),
            ]
        )
        try await raw.close()
        try lockDownLegacySQLiteDatabase(databaseURL, dataDirectory: fixture.root)

        let migrated = try await fixture.open()
        try await withClosedAccountDatabase(migrated) { migrated in
            let pending = try await migrated.pendingOutbox()
            XCTAssertEqual(pending.map(\.id), [eventID])
            XCTAssertEqual(pending.first?.payload, Data(eventID.uuidString.lowercased().utf8))
            XCTAssertNil(pending.first?.payload.range(of: fixture.firstValue))
            let lease = try await migrated.leaseNextOutbox(
                now: Date(timeIntervalSince1970: Double(createdAt) / 1_000_000 + 1),
                leaseDuration: 5
            )
            XCTAssertEqual(lease?.event.id, eventID)
        }
    }

    func testConcurrentWorkersHaveOneActiveLeaseAndAtLeastOnceIdempotencyKey() async throws {
        let fixture = try Fixture()
        let firstDatabase = try await fixture.open()
        let secondDatabase = try await fixture.open()
        try await withClosedAccountDatabases(firstDatabase, secondDatabase) {
            firstDatabase, secondDatabase in
            let committed = try await fixture.commitFirst(on: firstDatabase)
            let barrier = OutboxDeliveryBarrier()
            let firstTransport = BlockingOutboxTransport(barrier: barrier)
            let firstWorker = PermissionedSpaceOutboxDeliveryWorker(
                database: firstDatabase,
                transport: firstTransport,
                configuration: try outboxConfiguration()
            )
            let secondTransport = RecordingOutboxTransport(database: secondDatabase)
            let secondWorker = PermissionedSpaceOutboxDeliveryWorker(
                database: secondDatabase,
                transport: secondTransport,
                configuration: try outboxConfiguration()
            )
            let now = Date(timeIntervalSinceNow: 60)

            let firstTask = Task { try await firstWorker.deliverNext(now: now) }
            await barrier.waitUntilStarted()
            let secondResult = try await secondWorker.deliverNext(now: now)
            let secondNotifications = await secondTransport.notifications()
            await barrier.release()
            let firstResult = try await firstTask.value
            let firstNotifications = (await firstTransport.notifications()).map(\.id)
            let pending = try await firstDatabase.pendingOutbox()
            XCTAssertEqual(secondResult, .idle)
            XCTAssertEqual(secondNotifications, [])
            XCTAssertEqual(firstResult, .delivered(eventID: committed.outbox.id))
            XCTAssertEqual(firstNotifications, [committed.outbox.id])
            XCTAssertEqual(pending, [])
        }
    }

    func testRepositoryStateMarkerRejectsTamperedReaderEnvelopeAfterReopen() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        _ = try await fixture.commitFirst(on: database)
        try await database.close()

        let readerSpecificBytes = Data(
            "ikm=reader-secret&contextSignature=signature&contentBinding=binding".utf8
        )
        let databasePath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        ).path
        let rawConnection = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await rawConnection.query(
            """
            UPDATE permissioned_repository_state
            SET current_commit = ?
            WHERE space_uri = ? AND author_did = ?
            """,
            [
                readerSpecificBytes.sqliteData!,
                .text(fixture.space.rawValue),
                .text(fixture.author),
            ]
        )
        try await rawConnection.close()

        let reopened = try await fixture.open()
        defer { Task { try? await reopened.close() } }
        await XCTAssertThrowsErrorAsync(
            try await reopened.repositorySnapshot(
                space: fixture.space,
                author: fixture.author
            )
        ) { error in
            XCTAssertEqual(
                error as? SQLiteRepositoryError,
                .corruptDatabase("invalid deterministic repository state marker")
            )
        }
        await XCTAssertThrowsErrorAsync(
            try await reopened.spaceRecord(fixture.first)
        )
    }

    func testOutboxRejectsTamperedPayloadAfterReopen() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        let committed = try await fixture.commitFirst(on: database)
        try await database.close()

        let readerSpecificPayload = Data(
            "private-record-bytes-and-cid-must-not-be-a-notification".utf8
        )
        let databasePath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        ).path
        let rawConnection = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await rawConnection.query(
            "UPDATE permissioned_space_outbox SET payload = ? WHERE id = ?",
            [readerSpecificPayload.sqliteData!, .text(committed.outbox.id.uuidString)]
        )
        try await rawConnection.close()

        let reopened = try await fixture.open()
        do {
            _ = try await reopened.pendingOutbox()
            XCTFail("tampered outbox payload must fail closed")
        } catch {
            XCTAssertEqual(
                error as? SQLiteRepositoryError,
                .corruptDatabase("invalid opaque notification payload")
            )
        }
        try await reopened.close()
    }

    func testPendingOutboxRejectsMalformedLeasePairAfterReopen() async throws {
        let fixture = try Fixture()
        let databaseURL = SQLiteLayout.accountDatabase(in: fixture.root, did: fixture.author)
        try FileManager.default.createDirectory(
            at: databaseURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let eventID = UUID(uuidString: "20000000-0000-0000-0000-000000000098")!
        let timestamp = Int(Date().timeIntervalSince1970 * 1_000_000)
        let rawConnection = try await SQLiteConnection.open(storage: .file(path: databaseURL.path))
        do {
            _ = try await rawConnection.query(
                """
                CREATE TABLE permissioned_repository_migrations (
                    version INTEGER PRIMARY KEY CHECK(version > 0),
                    applied_at INTEGER NOT NULL CHECK(applied_at >= 0)
                )
                """
            )
            _ = try await rawConnection.query(
                """
                CREATE TABLE permissioned_space_outbox (
                    id TEXT PRIMARY KEY,
                    space_uri TEXT NOT NULL,
                    author_did TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    payload BLOB NOT NULL,
                    attempts INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
            _ = try await rawConnection.query(
                "INSERT INTO permissioned_repository_migrations(version, applied_at) VALUES (1, ?)",
                [.integer(timestamp)]
            )
            _ = try await rawConnection.query(
                """
                INSERT INTO permissioned_space_outbox(
                    id, space_uri, author_did, revision, payload, attempts, created_at
                ) VALUES (?, ?, ?, 1, ?, 0, ?)
                """,
                [
                    .text(eventID.uuidString), .text(fixture.space.rawValue),
                    .text(fixture.author),
                    Data(eventID.uuidString.lowercased().utf8).sqliteData!,
                    .integer(timestamp),
                ]
            )
            try await rawConnection.close()
        } catch {
            try? await rawConnection.close()
            throw error
        }
        try lockDownLegacySQLiteDatabase(databaseURL, dataDirectory: fixture.root)

        // This is the actual upgrade sequence for an old table: the additive
        // migration adds columns but SQLite cannot retroactively add the new
        // lease-pair CHECK constraint. A later corrupted legacy row must still
        // be rejected by `pendingOutbox`'s decoder.
        let upgraded = try await fixture.open()
        try await upgraded.close()
        let corruptingConnection = try await SQLiteConnection.open(
            storage: .file(path: databaseURL.path)
        )
        do {
            _ = try await corruptingConnection.query(
                "UPDATE permissioned_space_outbox SET lease_token = ?, lease_expires_at = NULL WHERE id = ?",
                [.text(UUID().uuidString), .text(eventID.uuidString)]
            )
            try await corruptingConnection.close()
        } catch {
            try? await corruptingConnection.close()
            throw error
        }

        let reopened = try await fixture.open()
        do {
            _ = try await reopened.pendingOutbox()
            XCTFail("malformed outbox lease must fail closed")
        } catch {
            XCTAssertEqual(
                error as? SQLiteRepositoryError,
                .corruptDatabase("invalid outbox lease")
            )
        }
        try await reopened.close()
    }

    func testPermissionedStorageMigrationUpgradesLegacyRowsBeforeRecordingSentinel() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        let committed = try await fixture.commitFirst(on: database)
        try await database.close()

        let legacyCommit = Data(
            "ikm=legacy-reader-secret&contextSignature=legacy-signature".utf8
        )
        let legacyPayload = Data(
            "legacy-private-record-bytes-and-cid".utf8
        )
        let databasePath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        ).path
        let rawConnection = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await rawConnection.query(
            "DELETE FROM permissioned_repository_migrations WHERE version = 1"
        )
        _ = try await rawConnection.query(
            """
            UPDATE permissioned_repository_state
            SET current_commit = ?
            WHERE space_uri = ? AND author_did = ?
            """,
            [
                legacyCommit.sqliteData!, .text(fixture.space.rawValue),
                .text(fixture.author),
            ]
        )
        _ = try await rawConnection.query(
            "UPDATE permissioned_space_outbox SET payload = ? WHERE id = ?",
            [legacyPayload.sqliteData!, .text(committed.outbox.id.uuidString)]
        )
        try await rawConnection.close()

        let migrated = try await fixture.open()
        let migratedSnapshot = try await migrated.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        let snapshot = try XCTUnwrap(migratedSnapshot)
        XCTAssertNotEqual(snapshot.state.commit, legacyCommit)
        XCTAssertEqual(snapshot.records.map(\.value), [fixture.firstValue])
        let pending = try await migrated.pendingOutbox()
        XCTAssertEqual(
            pending,
            [
                PersistedOutboxEvent(
                    id: committed.outbox.id,
                    space: fixture.space,
                    author: fixture.author,
                    revision: 1,
                    payload: Data(committed.outbox.id.uuidString.lowercased().utf8),
                    attempts: 0
                ),
            ]
        )
        try await migrated.close()

        let inspected = try await SQLiteConnection.open(storage: .file(path: databasePath))
        let sentinelRows = try await inspected.query(
            "SELECT version FROM permissioned_repository_migrations WHERE version = 1"
        )
        XCTAssertEqual(sentinelRows.count, 1)
        XCTAssertEqual(sentinelRows.first?.column("version")?.integer, 1)
        try await inspected.close()
    }

    func testPermissionedStorageMigrationPreservesForeignAuthoritySharedSpace() async throws {
        let fixture = try Fixture()
        let sharedSpace = try SpaceURI(
            authority: "did:plc:bob",
            spaceType: "app.bsky.bookmarks",
            skey: "shared"
        )
        let sharedRecord = try SpaceRecordURI(
            space: sharedSpace,
            author: fixture.author,
            collection: "app.bsky.feed.post",
            rkey: "shared-first"
        )
        let database = try await fixture.open()
        let committed = try await database.apply(
            space: sharedSpace,
            author: fixture.author,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try fixture.tid(0),
            writes: [
                .put(
                    uri: sharedRecord,
                    value: fixture.firstValue,
                    cid: "cid:shared-first"
                ),
            ]
        )
        try await database.close()

        let databasePath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        ).path
        let rawConnection = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await rawConnection.query(
            "DELETE FROM permissioned_repository_migrations WHERE version = 1"
        )
        _ = try await rawConnection.query(
            """
            UPDATE permissioned_repository_state
            SET current_commit = ?
            WHERE space_uri = ? AND author_did = ?
            """,
            [
                Data("legacy-shared-space-commit".utf8).sqliteData!,
                .text(sharedSpace.rawValue),
                .text(fixture.author),
            ]
        )
        _ = try await rawConnection.query(
            "UPDATE permissioned_space_outbox SET payload = ? WHERE id = ?",
            [
                Data("legacy-shared-space-payload".utf8).sqliteData!,
                .text(committed.outbox.id.uuidString),
            ]
        )
        try await rawConnection.close()

        let migrated = try await fixture.open()
        let migratedSnapshot = try await migrated.repositorySnapshot(
            space: sharedSpace,
            author: fixture.author
        )
        let snapshot = try XCTUnwrap(migratedSnapshot)
        XCTAssertEqual(snapshot.state.revision, 1)
        XCTAssertEqual(snapshot.records.map(\.uri), [sharedRecord])
        let pending = try await migrated.pendingOutbox()
        XCTAssertEqual(pending.first?.space, sharedSpace)
        XCTAssertEqual(pending.first?.author, fixture.author)
        XCTAssertEqual(
            pending.first?.payload,
            Data(committed.outbox.id.uuidString.lowercased().utf8)
        )
        let next = try await migrated.apply(
            space: sharedSpace,
            author: fixture.author,
            expectedRevision: 1,
            requestID: UUID(),
            wireRevision: try fixture.tid(1),
            writes: [
                .put(
                    uri: sharedRecord,
                    value: fixture.secondValue,
                    cid: "cid:shared-second"
                ),
            ]
        )
        XCTAssertEqual(next.state.revision, 2)
        try await migrated.close()
    }

    func testPermissionedStorageMigrationRollsBackWithoutSentinelForMalformedLegacyRows() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        let committed = try await fixture.commitFirst(on: database)
        try await database.close()

        let legacyCommit = Data("legacy-raw-commit".utf8)
        let databasePath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        ).path
        let rawConnection = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await rawConnection.query(
            "DELETE FROM permissioned_repository_migrations WHERE version = 1"
        )
        _ = try await rawConnection.query(
            """
            UPDATE permissioned_repository_state
            SET current_commit = ?
            WHERE space_uri = ? AND author_did = ?
            """,
            [
                legacyCommit.sqliteData!, .text(fixture.space.rawValue),
                .text(fixture.author),
            ]
        )
        _ = try await rawConnection.query(
            "UPDATE permissioned_space_outbox SET id = ? WHERE id = ?",
            [.text("not-a-uuid"), .text(committed.outbox.id.uuidString)]
        )
        try await rawConnection.close()

        await XCTAssertThrowsErrorAsync(
            try await fixture.open()
        ) { error in
            XCTAssertEqual(
                error as? SQLiteRepositoryError,
                .corruptDatabase("invalid outbox id")
            )
        }

        let inspected = try await SQLiteConnection.open(storage: .file(path: databasePath))
        let stateRows = try await inspected.query(
            """
            SELECT current_commit
            FROM permissioned_repository_state
            WHERE space_uri = ? AND author_did = ?
            """,
            [.text(fixture.space.rawValue), .text(fixture.author)]
        )
        let stateRow = try XCTUnwrap(stateRows.first)
        let currentCommit = try XCTUnwrap(
            Data(sqliteData: try XCTUnwrap(stateRow.column("current_commit")))
        )
        XCTAssertEqual(currentCommit, legacyCommit)
        let sentinelRows = try await inspected.query(
            "SELECT version FROM permissioned_repository_migrations WHERE version = 1"
        )
        XCTAssertTrue(sentinelRows.isEmpty)
        try await inspected.close()
    }

    func testPermissionedStorageMigrationRejectsCrossAccountLegacyStateRow() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        _ = try await fixture.commitFirst(on: database)
        try await database.close()

        let databasePath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        ).path
        let rawConnection = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await rawConnection.query(
            "DELETE FROM permissioned_repository_migrations WHERE version = 1"
        )
        _ = try await rawConnection.query(
            """
            UPDATE permissioned_repository_state
            SET author_did = ?
            WHERE space_uri = ? AND author_did = ?
            """,
            [
                .text("did:plc:mallory"), .text(fixture.space.rawValue),
                .text(fixture.author),
            ]
        )
        try await rawConnection.close()

        await XCTAssertThrowsErrorAsync(
            try await fixture.open()
        ) { error in
            XCTAssertEqual(
                error as? SQLiteRepositoryError,
                .corruptDatabase("invalid permissioned repository state ownership")
            )
        }

        let inspected = try await SQLiteConnection.open(storage: .file(path: databasePath))
        let sentinelRows = try await inspected.query(
            "SELECT version FROM permissioned_repository_migrations WHERE version = 1"
        )
        XCTAssertTrue(sentinelRows.isEmpty)
        try await inspected.close()
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
        )

        await XCTAssertThrowsErrorAsync(
            try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 1,
                requestID: requestID,
                wireRevision: try fixture.tid(1),
                writes: [.put(uri: fixture.second, value: fixture.secondValue, cid: "cid:second")],
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
        )
        _ = try await database!.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 2,
            requestID: UUID(),
            wireRevision: deleteRevision,
            writes: [.delete(uri: fixture.first)],
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
        )
        _ = try await database.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 2,
            requestID: UUID(),
            wireRevision: try fixture.tid(2),
            writes: [.put(uri: fixture.third, value: fixture.thirdValue, cid: "cid:third")],
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

    func testControlStoreAddsCompleteConfidentialKeyColumnsToExistingDatabase() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanControlStoreMigrationTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o700)],
            ofItemAtPath: root.path
        )
        let path = SQLiteLayout.controlDatabase(in: root).path
        let legacy = try await SQLiteConnection.open(storage: .file(path: path))
        _ = try await legacy.query(
            """
            CREATE TABLE oauth_control_token_families (
                family_id TEXT PRIMARY KEY, subject TEXT NOT NULL,
                issuer TEXT NOT NULL, client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL, scopes BLOB NOT NULL,
                dpop_jkt TEXT, client_assertion_key_id TEXT,
                expires_at INTEGER NOT NULL, revoked_at INTEGER
            )
            """
        )
        _ = try await legacy.query(
            """
            CREATE TABLE oauth_control_par_requests (
                request_digest BLOB PRIMARY KEY, issuer TEXT NOT NULL,
                client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
                scopes BLOB NOT NULL, dpop_jkt TEXT,
                client_assertion_key_id TEXT, state TEXT NOT NULL,
                state_digest BLOB NOT NULL, code_challenge_method TEXT NOT NULL,
                code_challenge_s256 TEXT NOT NULL, expires_at INTEGER NOT NULL,
                consumed_at INTEGER
            )
            """
        )
        try await legacy.close()
        try lockDownLegacySQLiteDatabase(URL(fileURLWithPath: path), dataDirectory: root)

        let migrated = try await SQLiteControlDatabase(dataDirectory: root)
        try await migrated.close()
        let inspected = try await SQLiteConnection.open(storage: .file(path: path))
        for table in ["oauth_control_token_families", "oauth_control_par_requests"] {
            let columns = try await inspected.query("PRAGMA table_info(\(table))")
                .compactMap { $0.column("name")?.string }
            XCTAssertTrue(columns.contains("client_assertion_algorithm"))
            XCTAssertTrue(columns.contains("client_assertion_jkt"))
        }
        try await inspected.close()
    }

    func testAccountControlRestartPersistsRegistryButLookupExcludesVerifier() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        var database: SQLiteControlDatabase? = try await SQLiteControlDatabase(dataDirectory: root)
        let registration = try controlRegistration(
            did: "did:plc:abcdefghijklmnopqrstuvwx",
            handle: "alice.example.com",
            createdAt: now
        )
        let created = try await database!.createAccount(registration)
        XCTAssertEqual(created.did, registration.did)
        XCTAssertEqual(created.canonicalHandle, registration.canonicalHandle)
        XCTAssertEqual(created.status, .active)
        XCTAssertEqual(created.credentialState, .configured)
        XCTAssertEqual(created.signingKey?.generation, 1)
        XCTAssertEqual(created.rotationKey?.reference, "account-rotation:1")
        XCTAssertFalse(String(describing: created).contains(registration.passwordVerifier))
        try await database!.close()
        database = nil

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        let byDIDResult = try await reopened.account(did: registration.did)
        let byHandleResult = try await reopened.account(canonicalHandle: registration.canonicalHandle)
        let byDID = try XCTUnwrap(byDIDResult)
        let byHandle = try XCTUnwrap(byHandleResult)
        XCTAssertEqual(byDID, byHandle)
        XCTAssertEqual(byDID.createdAt, now)
        XCTAssertEqual(byDID.updatedAt, now)
        let credential = try await reopened.credential(did: registration.did)
        XCTAssertEqual(credential?.verifier, registration.passwordVerifier)
        try await reopened.close()
    }

    func testAccountControlDuplicateDIDAndHandleRacesAreTypedAndAtomic() async throws {
        let handleRoot = try controlRoot()
        defer { try? FileManager.default.removeItem(at: handleRoot) }
        let handleFirst = try await SQLiteControlDatabase(dataDirectory: handleRoot)
        let handleSecond = try await SQLiteControlDatabase(dataDirectory: handleRoot)
        defer {
            Task {
                try? await handleFirst.close()
                try? await handleSecond.close()
            }
        }
        let handleResults = await controlCreateRace(
            first: handleFirst,
            second: handleSecond,
            firstRegistration: try controlRegistration(
                did: "did:plc:abcdefghijklmnopqrstuvwx",
                handle: "race.example.com"
            ),
            secondRegistration: try controlRegistration(
                did: "did:plc:bcdefghijklmnopqrstuvwxy",
                handle: "race.example.com"
            )
        )
        XCTAssertEqual(handleResults.successes, 1)
        XCTAssertEqual(handleResults.errors, [.duplicateHandle])

        let didRoot = try controlRoot()
        defer { try? FileManager.default.removeItem(at: didRoot) }
        let didFirst = try await SQLiteControlDatabase(dataDirectory: didRoot)
        let didSecond = try await SQLiteControlDatabase(dataDirectory: didRoot)
        defer {
            Task {
                try? await didFirst.close()
                try? await didSecond.close()
            }
        }
        let didResults = await controlCreateRace(
            first: didFirst,
            second: didSecond,
            firstRegistration: try controlRegistration(
                did: "did:plc:abcdefghijklmnopqrstuvwx",
                handle: "alice-one.example.com"
            ),
            secondRegistration: try controlRegistration(
                did: "did:plc:abcdefghijklmnopqrstuvwx",
                handle: "alice-two.example.com"
            )
        )
        XCTAssertEqual(didResults.successes, 1)
        XCTAssertEqual(didResults.errors, [.duplicateDID])
    }

    func testAccountControlMigrationMakesLegacyAccountsExplicitlyCredentialless() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let path = SQLiteLayout.controlDatabase(in: root).path
        let legacy = try await SQLiteConnection.open(storage: .file(path: path))
        _ = try await legacy.query(
            """
            CREATE TABLE accounts (
                did TEXT PRIMARY KEY,
                handle TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        _ = try await legacy.query(
            "INSERT INTO accounts(did, handle, status, created_at) VALUES (?, ?, ?, ?)",
            [
                .text("did:plc:abcdefghijklmnopqrstuvwx"),
                .text("Alice.Example.COM"),
                .text("active"),
                .integer(1_750_000_000_000_000),
            ]
        )
        try await legacy.close()
        try lockDownLegacySQLiteDatabase(URL(fileURLWithPath: path), dataDirectory: root)

        let migrated = try await SQLiteControlDatabase(dataDirectory: root)
        let migratedAccount = try await migrated.account(did: "did:plc:abcdefghijklmnopqrstuvwx")
        let account = try XCTUnwrap(migratedAccount)
        XCTAssertEqual(account.canonicalHandle, "alice.example.com")
        XCTAssertEqual(account.credentialState, .missing)
        XCTAssertNil(account.signingKey)
        XCTAssertNil(account.rotationKey)
        let legacyCredential = try await migrated.credential(did: account.did)
        XCTAssertNil(legacyCredential)
        try await migrated.close()
    }

    func testAccountControlRejectsInvalidInputsAndStoresNoRawPasswordOrPrivateKeyBytes() async throws {
        XCTAssertThrowsError(try AccountControlStatus(rawValue: "Active"))
        XCTAssertThrowsError(try AccountControlStatus(rawValue: "future status"))
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        await XCTAssertThrowsErrorAsync(
            try await database.account(canonicalHandle: "Alice.Example.COM")
        ) { error in
            XCTAssertEqual(error as? AccountControlStoreError, .invalidInput)
        }
        await XCTAssertThrowsErrorAsync(
            try await database.createAccount(
                AccountControlRegistration(
                    did: "did:key:abcdefghijklmnopqrstuvwx",
                    canonicalHandle: "invalid.example.com",
                    passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                    signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
                    rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1)
                )
            )
        ) { error in
            XCTAssertEqual(error as? AccountControlStoreError, .invalidInput)
        }
        let directStatusWrite = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.controlDatabase(in: root).path)
        )
        await XCTAssertThrowsErrorAsync(
            try await directStatusWrite.query(
                "INSERT INTO accounts(did, handle, status, created_at) VALUES (?, ?, ?, ?)",
                [
                    .text("did:plc:bcdefghijklmnopqrstuvwxy"),
                    .text("status.example.com"),
                    .text("invalid status"),
                    .integer(1_750_000_000_000_000),
                ]
            )
        )
        try await directStatusWrite.close()
        let registration = try controlRegistration(
            did: "did:plc:abcdefghijklmnopqrstuvwx",
            handle: "alice.example.com"
        )
        _ = try await database.createAccount(registration)
        try await database.close()

        let bytes = try Data(contentsOf: SQLiteLayout.controlDatabase(in: root))
        let databaseText = String(decoding: bytes, as: UTF8.self)
        XCTAssertFalse(databaseText.contains("raw-password-never-stored"))
        XCTAssertFalse(databaseText.contains("\u{01}\u{02}\u{03}\u{04}"))
        XCTAssertFalse(databaseText.contains("private-key-export-envelope"))
        let direct = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.controlDatabase(in: root).path)
        )
        let columns = try await direct.query("PRAGMA table_info(accounts)")
            .compactMap { $0.column("name")?.string }
        XCTAssertFalse(columns.contains(where: { $0.contains("private") || $0.contains("key_bytes") }))
        try await direct.close()
    }

    func testAccountControlRejectsUnknownAliasesForEveryKnownStatusToken() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }
        let registration = try controlRegistration(
            did: "did:plc:abcdefghijklmnopqrstuvwx",
            handle: "aliases.example.com"
        )
        let account = try await database.createAccount(registration)
        let knownStatuses: [AccountControlStatus] = [
            .active, .deactivated, .deleted, .takendown, .suspended,
            .desynchronized, .throttled,
        ]

        for known in knownStatuses {
            let alias = AccountControlStatus.unknown(known.rawValue)
            XCTAssertFalse(alias.isCanonicalValue, "unknown alias for \(known.rawValue)")
            XCTAssertFalse(AccountStatusTransitionPolicy.standard.permits(from: .deactivated, to: alias))
            XCTAssertThrowsError(
                try AccountStatusTransitionPolicy.standard.validate(from: .deactivated, to: alias)
            ) { error in
                XCTAssertEqual(error as? AccountControlStoreError, .invalidStatus)
            }
            XCTAssertThrowsError(
                try AccountControlAccount(
                    did: account.did,
                    canonicalHandle: account.canonicalHandle,
                    status: alias,
                    createdAt: account.createdAt,
                    updatedAt: account.updatedAt,
                    credentialState: account.credentialState,
                    signingKey: account.signingKey,
                    rotationKey: account.rotationKey
                )
            ) { error in
                XCTAssertEqual(error as? AccountControlStoreError, .invalidStatus)
            }
            await XCTAssertThrowsErrorAsync(
                try await database.transitionStatus(
                    did: account.did,
                    to: alias,
                    declaration: .init(),
                    now: account.updatedAt.addingTimeInterval(1)
                )
            ) { error in
                XCTAssertEqual(error as? AccountControlStoreError, .invalidStatus)
            }
        }

        let reloaded = try await database.account(did: account.did)
        XCTAssertEqual(reloaded?.status, .active)
    }

    func testAccountControlKeyReferencesRejectDecodedSecretsAndMismatchedGenerations() async throws {
        let secretSentinel = "injected-private-key-bytes-never-persist"
        let injectedReference = """
        {"purpose":"account-signing","generation":1,"reference":"\(secretSentinel)"}
        """
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                AccountControlKeyReference.self,
                from: Data(injectedReference.utf8)
            )
        )
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                AccountControlKeyReference.self,
                from: Data(#"{"purpose":"account-signing","generation":1,"reference":"account-rotation:1"}"#.utf8)
            )
        )

        let signing = try AccountControlKeyReference(purpose: .signing, generation: 1)
        let mismatchedRotation = try AccountControlKeyReference(purpose: .rotation, generation: 2)
        XCTAssertThrowsError(
            try AccountControlRegistration(
                did: "did:plc:abcdefghijklmnopqrstuvwx",
                canonicalHandle: "mismatch.example.com",
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: signing,
                rotationKey: mismatchedRotation
            )
        ) { error in
            XCTAssertEqual(error as? AccountControlStoreError, .invalidInput)
        }
        XCTAssertThrowsError(
            try AccountControlAccount(
                did: "did:plc:abcdefghijklmnopqrstuvwx",
                canonicalHandle: "mismatch.example.com",
                status: .active,
                createdAt: Date(timeIntervalSince1970: 1_750_000_000),
                updatedAt: Date(timeIntervalSince1970: 1_750_000_000),
                credentialState: .configured,
                signingKey: signing,
                rotationKey: mismatchedRotation
            )
        ) { error in
            XCTAssertEqual(error as? AccountControlStoreError, .invalidInput)
        }

        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await database.createAccount(
            controlRegistration(
                did: "did:plc:abcdefghijklmnopqrstuvwx",
                handle: "references.example.com"
            )
        )
        try await database.close()
        let controlBytes = try Data(contentsOf: SQLiteLayout.controlDatabase(in: root))
        XCTAssertFalse(String(decoding: controlBytes, as: UTF8.self).contains(secretSentinel))
    }

    func testAccountControlExportMetadataOnlyPersistsCanonicalManifestDigests() async throws {
        let secretSentinel = "recovery phrase private key export payload"
        let validDigest = "sha256:" + String(repeating: "a", count: 64)
        let invalidReferences = [
            secretSentinel,
            "c2VlZC1waHJhc2U=",
            "sha256:" + String(repeating: "A", count: 64),
            "sha256:" + String(repeating: "a", count: 63),
        ]
        for reference in invalidReferences {
            XCTAssertThrowsError(try AccountExportMetadata(reference: reference))
            let encoded = "{\"declaredAt\":0,\"reference\":\"\(reference)\"}"
            XCTAssertThrowsError(
                try JSONDecoder().decode(AccountExportMetadata.self, from: Data(encoded.utf8))
            )
        }
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                AccountTombstoneMetadata.self,
                from: Data(#"{"declaredAt":-1000000000,"reason":"invalid"}"#.utf8)
            )
        )
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                AccountTombstoneMetadata.self,
                from: Data(#"{"declaredAt":0,"reason":"operator\ntext"}"#.utf8)
            )
        )

        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let registration = try controlRegistration(
            did: "did:plc:abcdefghijklmnopqrstuvwx",
            handle: "exports.example.com",
            createdAt: now
        )
        _ = try await database.createAccount(registration)
        let transitioned = try await database.transitionStatus(
            did: registration.did,
            to: .active,
            declaration: AccountLifecycleDeclaration(
                export: try AccountExportMetadata(declaredAt: now, reference: validDigest)
            ),
            now: now.addingTimeInterval(1)
        )
        XCTAssertEqual(transitioned.export?.reference, validDigest)
        try await database.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        let persisted = try await reopened.account(did: registration.did)
        XCTAssertEqual(persisted?.export?.reference, validDigest)
        try await reopened.close()

        let controlBytes = try Data(contentsOf: SQLiteLayout.controlDatabase(in: root))
        let controlText = String(decoding: controlBytes, as: UTF8.self)
        XCTAssertTrue(controlText.contains(validDigest))
        XCTAssertFalse(controlText.contains(secretSentinel))
        XCTAssertFalse(controlText.contains("c2VlZC1waHJhc2U="))
    }

    func testAccountControlConcurrentLegacyOpenSerializesMigration() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let path = SQLiteLayout.controlDatabase(in: root).path
        let legacy = try await SQLiteConnection.open(storage: .file(path: path))
        _ = try await legacy.query(
            """
            CREATE TABLE accounts (
                did TEXT PRIMARY KEY,
                handle TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        _ = try await legacy.query(
            "INSERT INTO accounts(did, handle, status, created_at) VALUES (?, ?, ?, ?)",
            [
                .text("did:plc:abcdefghijklmnopqrstuvwx"),
                .text("Alice.Example.COM"),
                .text("active"),
                .integer(1_750_000_000_000_000),
            ]
        )
        try await legacy.close()
        try lockDownLegacySQLiteDatabase(URL(fileURLWithPath: path), dataDirectory: root)

        // A successfully opened database owns an SQLiteNIO connection until
        // `close()` completes. Do not make it a result of a throwing group:
        // if its peer throws, `withThrowingTaskGroup` discards unretrieved
        // successful results while unwinding, which deinitializes that live
        // connection before this test can close it. Keep every outcome first,
        // then close successes on either path.
        let concurrentOpenCount = 8
        let openResults = await withTaskGroup(
            of: Result<SQLiteControlDatabase, any Error>.self,
            returning: [Result<SQLiteControlDatabase, any Error>].self
        ) { group in
            for _ in 0 ..< concurrentOpenCount {
                group.addTask {
                    do {
                        return .success(try await SQLiteControlDatabase(dataDirectory: root))
                    } catch {
                        return .failure(error)
                    }
                }
            }
            return await group.reduce(into: []) { $0.append($1) }
        }
        var databases: [SQLiteControlDatabase] = []
        var openingErrors: [any Error] = []
        for result in openResults {
            switch result {
            case let .success(database):
                databases.append(database)
            case let .failure(error):
                openingErrors.append(error)
            }
        }
        if !openingErrors.isEmpty {
            for database in databases {
                try? await database.close()
            }
            XCTFail("concurrent legacy opens failed: \(openingErrors.map { String(reflecting: $0) })")
            return
        }
        XCTAssertEqual(databases.count, concurrentOpenCount)
        let migratedAccount = try await databases[0].account(
            did: "did:plc:abcdefghijklmnopqrstuvwx"
        )
        XCTAssertEqual(migratedAccount?.canonicalHandle, "alice.example.com")
        XCTAssertEqual(migratedAccount?.credentialState, .missing)
        for database in databases {
            try await database.close()
        }

        let inspected = try await SQLiteConnection.open(storage: .file(path: path))
        let columns = try await inspected.query("PRAGMA table_info(accounts)")
            .compactMap { $0.column("name")?.string }
        XCTAssertTrue(columns.contains("password_verifier"))
        XCTAssertTrue(columns.contains("signing_key_generation"))
        XCTAssertTrue(columns.contains("export_reference"))
        try await inspected.close()
    }
    func testSimpleSpaceAuthorityRejectsTamperedPersistedFacts() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSQLiteAuthorityTamperTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let did = "did:plc:alice"
        let space = try SpaceURI(
            authority: did,
            spaceType: "app.bsky.bookmarks",
            skey: "tamper"
        )
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let authority = try DurableSimpleSpaceAuthority(
            database: database,
            credentialSecret: Data(repeating: 7, count: 32)
        )
        _ = try await authority.create(
            space: space,
            owner: did,
            configuration: try SimpleSpaceConfiguration(policy: .memberList),
            authorization: .accountOAuth(subject: did, scopes: ["atproto"])
        )
        try await database.close()

        let databasePath = SQLiteLayout.accountDatabase(in: root, did: did).path
        let raw = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await raw.query(
            "DELETE FROM permissioned_simple_space_members WHERE space_uri = ? AND member_did = ?",
            [.text(space.rawValue), .text(did)]
        )
        _ = try await raw.query(
            "INSERT INTO permissioned_simple_space_managing_app_decisions(space_uri, user_did) VALUES (?, ?)",
            [.text(space.rawValue), .text("did:plc:bob")]
        )
        try await raw.close()

        let reopened = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        await XCTAssertThrowsErrorAsync(
            try await reopened.simpleSpace(
                space,
                authorization: .accountOAuth(subject: did, scopes: ["atproto"])
            )
        ) { error in
            guard case .corruptDatabase = error as? SQLiteRepositoryError else {
                return XCTFail("expected a fail-closed corruption error, got \(error)")
            }
        }
        let reopenedAuthority = try DurableSimpleSpaceAuthority(
            database: reopened,
            credentialSecret: Data(repeating: 7, count: 32)
        )
        await XCTAssertThrowsErrorAsync(
            try await reopenedAuthority.issueReadCredential(
                space: space,
                user: "did:plc:bob",
                clientID: nil,
                authorization: .accountOAuth(
                    subject: "did:plc:bob",
                    scopes: ["atproto"]
                )
            )
        )
        try await reopened.close()
    }

    func testSQLiteCreatesOwnerOnlyRootDirectoriesAndDatabaseFiles() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSQLiteProtectedPathsTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let did = "did:plc:abcdefghijklmnopqrstuvwx"

        let control = try await SQLiteControlDatabase(dataDirectory: root)
        let account = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        defer {
            Task {
                try? await control.close()
                try? await account.close()
            }
        }

        let accountDatabase = SQLiteLayout.accountDatabase(in: root, did: did)
        XCTAssertEqual(try permissions(of: root), 0o700)
        XCTAssertEqual(try permissions(of: root.appending(path: "actors")), 0o700)
        XCTAssertEqual(try permissions(of: accountDatabase.deletingLastPathComponent()), 0o700)
        XCTAssertEqual(try permissions(of: SQLiteLayout.controlDatabase(in: root)), 0o600)
        XCTAssertEqual(try permissions(of: accountDatabase), 0o600)

        for database in [SQLiteLayout.controlDatabase(in: root), accountDatabase] {
            for suffix in ["-wal", "-shm"] {
                let sidecar = URL(fileURLWithPath: database.path + suffix)
                if FileManager.default.fileExists(atPath: sidecar.path) {
                    XCTAssertEqual(try permissions(of: sidecar), 0o600)
                }
            }
        }
    }

    func testSQLiteRejectsUnsafeOrSymlinkDataRootBeforeOpeningDatabases() async throws {
        let base = FileManager.default.temporaryDirectory
            .appending(path: "SwanSQLiteUnsafeRootTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: base) }
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o755)],
            ofItemAtPath: base.path
        )

        await XCTAssertThrowsErrorAsync(
            try await SQLiteControlDatabase(dataDirectory: base)
        ) { error in
            XCTAssertEqual(error as? SwanError, .unavailable("SQLite data directory is unavailable"))
        }
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: SQLiteLayout.controlDatabase(in: base).path
        ))

        let target = FileManager.default.temporaryDirectory
            .appending(path: "SwanSQLiteUnsafeRootTarget-\(UUID().uuidString)")
        let link = FileManager.default.temporaryDirectory
            .appending(path: "SwanSQLiteUnsafeRootLink-\(UUID().uuidString)")
        defer {
            try? FileManager.default.removeItem(at: target)
            try? FileManager.default.removeItem(at: link)
        }
        try FileManager.default.createDirectory(
            at: target,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: NSNumber(value: 0o700)]
        )
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        await XCTAssertThrowsErrorAsync(
            try await SQLiteControlDatabase(dataDirectory: link)
        ) { error in
            XCTAssertEqual(error as? SwanError, .unavailable("SQLite data directory is unavailable"))
        }
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: SQLiteLayout.controlDatabase(in: target).path
        ))
    }
}

private extension SwanSQLiteTests {
    func controlRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanAccountControlTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o700)],
            ofItemAtPath: root.path
        )
        return root
    }

    func permissions(of url: URL) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        let mode = try XCTUnwrap(attributes[.posixPermissions] as? NSNumber)
        return mode.intValue & 0o777
    }

    func lockDownLegacySQLiteDatabase(
        _ database: URL,
        dataDirectory: URL
    ) throws {
        let root = dataDirectory.standardizedFileURL
        var directory = database.deletingLastPathComponent().standardizedFileURL
        while true {
            try FileManager.default.setAttributes(
                [.posixPermissions: NSNumber(value: 0o700)],
                ofItemAtPath: directory.path
            )
            if directory == root { break }
            let parent = directory.deletingLastPathComponent().standardizedFileURL
            guard parent.path.hasPrefix(root.path) else {
                throw SwanError.unavailable("test database escaped its root")
            }
            directory = parent
        }
        for suffix in ["", "-wal", "-shm"] {
            let file = URL(fileURLWithPath: database.path + suffix)
            guard FileManager.default.fileExists(atPath: file.path) else { continue }
            try FileManager.default.setAttributes(
                [.posixPermissions: NSNumber(value: 0o600)],
                ofItemAtPath: file.path
            )
        }
    }

    func controlRegistration(
        did: String,
        handle: String,
        createdAt: Date = Date(timeIntervalSince1970: 1_750_000_000)
    ) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
            rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
            createdAt: createdAt
        )
    }

    func controlCreateRace(
        first: SQLiteControlDatabase,
        second: SQLiteControlDatabase,
        firstRegistration: AccountControlRegistration,
        secondRegistration: AccountControlRegistration
    ) async -> (successes: Int, errors: [AccountControlStoreError]) {
        await withTaskGroup(
            of: Result<AccountControlAccount, any Error>.self,
            returning: (Int, [AccountControlStoreError]).self
        ) { group in
            group.addTask {
                do {
                    return .success(try await first.createAccount(firstRegistration))
                } catch {
                    return .failure(error)
                }
            }
            group.addTask {
                do {
                    return .success(try await second.createAccount(secondRegistration))
                } catch {
                    return .failure(error)
                }
            }
            let outcomes = await group.reduce(into: [Result<AccountControlAccount, any Error>]()) {
                $0.append($1)
            }
            return (
                outcomes.compactMap { try? $0.get() }.count,
                outcomes.compactMap { result in
                    guard case let .failure(error) = result else { return nil }
                    return error as? AccountControlStoreError
                }
            )
        }
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

private func withClosedAccountDatabase<T>(
    _ database: SQLiteAccountDatabase,
    body: (SQLiteAccountDatabase) async throws -> T
) async throws -> T {
    do {
        let value = try await body(database)
        try await database.close()
        return value
    } catch {
        try? await database.close()
        throw error
    }
}

private func withClosedAccountDatabases<T>(
    _ first: SQLiteAccountDatabase,
    _ second: SQLiteAccountDatabase,
    body: (SQLiteAccountDatabase, SQLiteAccountDatabase) async throws -> T
) async throws -> T {
    do {
        let value = try await body(first, second)
        try await first.close()
        try await second.close()
        return value
    } catch {
        try? await first.close()
        try? await second.close()
        throw error
    }
}

private struct InjectedTransactionFailure: Error {}
private struct InjectedOutboxTransportFailure: Error {}

private func outboxConfiguration(
    leaseDuration: TimeInterval = 10,
    idlePollInterval: TimeInterval = 1,
    initialFailureBackoff: TimeInterval = 1,
    maximumFailureBackoff: TimeInterval = 8
) throws -> PermissionedSpaceOutboxDeliveryConfiguration {
    try PermissionedSpaceOutboxDeliveryConfiguration(
        leaseDuration: leaseDuration,
        idlePollInterval: idlePollInterval,
        initialFailureBackoff: initialFailureBackoff,
        maximumFailureBackoff: maximumFailureBackoff
    )
}

private actor RecordingOutboxTransport: PermissionedSpaceOutboxTransport {
    private let database: SQLiteAccountDatabase?
    private var failuresRemaining: Int
    private var delivered: [PermissionedSpaceOutboxNotification] = []
    private var writeTransactionStates: [Bool] = []

    init(
        database: SQLiteAccountDatabase?,
        failuresRemaining: Int = 0
    ) {
        self.database = database
        self.failuresRemaining = failuresRemaining
    }

    func deliver(_ notification: PermissionedSpaceOutboxNotification) async throws {
        if let database {
            writeTransactionStates.append(await database.hasActiveWriteTransactionForTesting())
        }
        delivered.append(notification)
        if failuresRemaining > 0 {
            failuresRemaining -= 1
            throw InjectedOutboxTransportFailure()
        }
    }

    func notifications() -> [PermissionedSpaceOutboxNotification] { delivered }

    func observedWriteTransactions() -> [Bool] { writeTransactionStates }
}

private actor BlockingOutboxTransport: PermissionedSpaceOutboxTransport {
    private let barrier: OutboxDeliveryBarrier
    private var delivered: [PermissionedSpaceOutboxNotification] = []

    init(barrier: OutboxDeliveryBarrier) {
        self.barrier = barrier
    }

    func deliver(_ notification: PermissionedSpaceOutboxNotification) async throws {
        delivered.append(notification)
        await barrier.started()
        await barrier.waitForRelease()
    }

    func notifications() -> [PermissionedSpaceOutboxNotification] { delivered }
}

private actor OutboxDeliveryBarrier {
    private var didStart = false
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseContinuation: CheckedContinuation<Void, Never>?

    func started() {
        didStart = true
        startWaiters.forEach { $0.resume() }
        startWaiters.removeAll()
    }

    func waitUntilStarted() async {
        guard !didStart else { return }
        await withCheckedContinuation { startWaiters.append($0) }
    }

    func waitForRelease() async {
        await withCheckedContinuation { releaseContinuation = $0 }
    }

    func release() {
        releaseContinuation?.resume()
        releaseContinuation = nil
    }
}

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
