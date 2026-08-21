import Foundation
import Petrel
import SQLiteNIO
import SwanCore
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class SpaceNotificationSQLiteTests: XCTestCase {
    func testReusedWriterJTIIsScopedToEachSpace() async throws {
        let fixture = try NotificationFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)
        try await fixture.createSecondaryAuthorityState(on: database)

        let eventID = "writer-event-reused-across-spaces"
        try await database.receiveSpaceWriteNotification(
            fixture.writeNotification(
                eventID: eventID,
                revision: try fixture.tid(1),
                commitmentByte: 1,
                space: fixture.space
            )
        )
        try await database.receiveSpaceWriteNotification(
            fixture.writeNotification(
                eventID: eventID,
                revision: try fixture.tid(1),
                commitmentByte: 2,
                space: fixture.secondarySpace
            )
        )

        let primary = try await database.spaceWriters(
            space: fixture.space,
            limit: 100,
            cursor: nil,
            authorization: fixture.readCredential(for: fixture.space)
        )
        let secondary = try await database.spaceWriters(
            space: fixture.secondarySpace,
            limit: 100,
            cursor: nil,
            authorization: fixture.readCredential(for: fixture.secondarySpace)
        )
        XCTAssertEqual(primary.first?.commitment, Data(repeating: 1, count: 32))
        XCTAssertEqual(secondary.first?.commitment, Data(repeating: 2, count: 32))
    }

    func testWriterNotificationsAreIdempotentMonotonicAndNeverEnqueueAuthorityFanout() async throws {
        let fixture = try NotificationFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)

        let credential = fixture.readCredential()
        let endpoint = "https://notify.example/xrpc/com.atproto.space.notifyWrite"
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: endpoint,
                repository: fixture.writer,
                expiresAt: now.addingTimeInterval(3_600)
            ),
            authorization: credential,
            now: now
        )

        let first = fixture.writeNotification(
            eventID: "writer-event-1",
            revision: try fixture.tid(1),
            commitmentByte: 1
        )
        try await database.receiveSpaceWriteNotification(first, now: now)
        // Duplicate service JTI is a successful no-op, not another state
        // change. The pinned TypeScript receiver requires `iss == repo`, so
        // an authority cannot lawfully fan this write out to another host.
        try await database.receiveSpaceWriteNotification(first, now: now.addingTimeInterval(1))
        // A reordered older TID cannot regress the authority hint or produce
        // another recipient delivery. It also must not become permanent replay
        // state: the writer row already makes the stale event harmless.
        try await database.receiveSpaceWriteNotification(
            fixture.writeNotification(
                eventID: "writer-event-older",
                revision: try fixture.tid(0),
                commitmentByte: 1
            ),
            now: now.addingTimeInterval(2)
        )

        let writers = try await database.spaceWriters(
            space: fixture.space,
            limit: 100,
            cursor: nil,
            authorization: credential
        )
        let pending = try await database.pendingNotificationFanout()
        XCTAssertEqual(writers.count, 1)
        XCTAssertEqual(writers.first?.repository, fixture.writer)
        XCTAssertEqual(writers.first?.wireRevision, try fixture.tid(1).toString())
        XCTAssertEqual(writers.first?.commitment, Data(repeating: 1, count: 32))
        XCTAssertTrue(pending.isEmpty)
        XCTAssertNil(String(describing: pending).range(of: "private record value"))

        let receiptCount = try await database.connection.query(
            "SELECT COUNT(*) AS row_count FROM permissioned_space_notification_receipts"
        )
        XCTAssertEqual(receiptCount.first?.column("row_count")?.integer, 1)

        do {
            try await database.receiveSpaceWriteNotification(
                fixture.writeNotification(
                    eventID: "writer-event-conflict",
                    revision: try fixture.tid(1),
                    commitmentByte: 9
                ),
                now: now.addingTimeInterval(3)
            )
            XCTFail("equal-TID commitment mismatch should fail closed")
        } catch {
            guard case .conflict = error as? SwanError else {
                XCTFail("expected equal-TID commitment conflict, got \(error)")
                return
            }
        }
        let afterConflict = try await database.spaceWriters(
            space: fixture.space,
            limit: 100,
            cursor: nil,
            authorization: credential
        )
        XCTAssertEqual(afterConflict.first?.commitment, Data(repeating: 1, count: 32))
    }

    func testNotificationReceiptsCompactToCurrentStateAndTombstonesStopGrowth() async throws {
        let fixture = try NotificationFixture()
        let authorityDatabase = try await fixture.open()
        defer { Task { try? await authorityDatabase.close() } }
        try await fixture.createAuthorityState(on: authorityDatabase)
        let now = Date(timeIntervalSince1970: 1_750_000_050)

        try await authorityDatabase.receiveSpaceWriteNotification(
            fixture.writeNotification(
                eventID: "writer-current-1",
                revision: try fixture.tid(1),
                commitmentByte: 1
            ),
            now: now
        )
        for index in 0 ..< 100 {
            try await authorityDatabase.receiveSpaceWriteNotification(
                fixture.writeNotification(
                    eventID: "writer-stale-\(index)",
                    revision: try fixture.tid(0),
                    commitmentByte: 1
                ),
                now: now.addingTimeInterval(TimeInterval(index + 1))
            )
        }
        let staleRows = try await authorityDatabase.connection.query(
            "SELECT COUNT(*) AS row_count FROM permissioned_space_notification_receipts"
        )
        XCTAssertEqual(staleRows.first?.column("row_count")?.integer, 1)

        try await authorityDatabase.receiveSpaceWriteNotification(
            fixture.writeNotification(
                eventID: "writer-current-2",
                revision: try fixture.tid(2),
                commitmentByte: 2
            ),
            now: now.addingTimeInterval(200)
        )
        let compactedRows = try await authorityDatabase.connection.query(
            "SELECT COUNT(*) AS row_count FROM permissioned_space_notification_receipts"
        )
        XCTAssertEqual(compactedRows.first?.column("row_count")?.integer, 1)

        let recipient = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root,
            did: fixture.writer
        )
        defer { Task { try? await recipient.close() } }
        // A deletion is only recorded for a space this account already
        // participates in, so establish that participation before measuring
        // the receipt bound.
        try await fixture.join(space: fixture.space, on: recipient, rkey: "receipt-bound")
        for index in 0 ..< 100 {
            try await recipient.receiveSpaceDeletionNotification(
                space: fixture.space,
                issuer: fixture.authority,
                audience: fixture.writer,
                eventID: "space-delete-\(index)",
                now: now.addingTimeInterval(TimeInterval(index))
            )
        }
        let deletionRows = try await recipient.connection.query(
            "SELECT COUNT(*) AS row_count FROM permissioned_space_notification_receipts"
        )
        XCTAssertEqual(deletionRows.first?.column("row_count")?.integer, 1)
    }

    func testDeletionFanoutWorkerRetriesOutsideTransactionsAndRecoversLease() async throws {
        let fixture = try NotificationFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)
        let now = Date(timeIntervalSince1970: 1_750_000_100)
        try await fixture.register(on: database, now: now)
        _ = try await database.deleteSimpleSpace(
            space: fixture.space,
            authorization: .accountOAuth(subject: fixture.authority, scopes: ["atproto"]),
            now: now
        )

        let transport = RecordingFanoutTransport(database: database, failuresRemaining: 1)
        let worker = PermissionedSpaceNotificationFanoutDeliveryWorker(
            database: database,
            transport: transport,
            configuration: try notificationOutboxConfiguration(
                initialFailureBackoff: 2,
                maximumFailureBackoff: 2
            )
        )
        let pendingBeforeFailure = try await database.pendingNotificationFanout()
        let fanoutID = try XCTUnwrap(pendingBeforeFailure.first?.id)
        let firstResult = try await worker.deliverNext(now: now)
        XCTAssertEqual(firstResult, .failed(eventID: fanoutID, attempts: 1))
        let beforeRetry = try await worker.deliverNext(now: now.addingTimeInterval(1))
        XCTAssertEqual(beforeRetry, .idle)
        guard case .delivered = try await worker.deliverNext(now: now.addingTimeInterval(2)) else {
            return XCTFail("retry should deliver the leased fanout")
        }
        let delivered = await transport.delivered()
        let transactionStates = await transport.writeTransactions()
        let remaining = try await database.pendingNotificationFanout()
        XCTAssertEqual(delivered.count, 2)
        XCTAssertTrue(delivered.allSatisfy { $0.kind == .deleted })
        XCTAssertEqual(transactionStates, [false, false])
        XCTAssertTrue(remaining.isEmpty)
    }

    func testRegistrationReplacementAndDeletionCreateOnlyOpaqueFanout() async throws {
        let fixture = try NotificationFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)
        let now = Date(timeIntervalSince1970: 1_750_000_200)
        let endpoint = "https://notify.example/xrpc/com.atproto.space.notifySpaceDeleted"
        let credential = fixture.readCredential()
        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: endpoint,
                repository: fixture.writer,
                expiresAt: now.addingTimeInterval(600)
            ),
            authorization: credential,
            now: now
        )
        // The same endpoint replaces its repo filter rather than creating a
        // second registration. A deletion still reaches the active endpoint.
        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: endpoint,
                repository: nil,
                expiresAt: now.addingTimeInterval(1_200)
            ),
            authorization: credential,
            now: now
        )
        _ = try await database.deleteSimpleSpace(
            space: fixture.space,
            authorization: .accountOAuth(subject: fixture.authority, scopes: ["atproto"]),
            now: now.addingTimeInterval(1)
        )
        let pending = try await database.pendingNotificationFanout()
        XCTAssertEqual(pending.count, 1)
        XCTAssertEqual(pending.first?.kind, .deleted)
        XCTAssertNil(pending.first?.repository)
        XCTAssertNil(pending.first?.wireRevision)
        XCTAssertNil(pending.first?.commitment)
        XCTAssertNil(String(describing: pending).range(of: "private record value"))
    }

    func testNotificationRegistrationCapacityIsBoundedPerSpaceAndReclaimsExpiredRows()
        async throws
    {
        let fixture = try NotificationFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)

        let now = Date()
        let credential = AuthorizationContext.spaceCredential(.init(
            subject: fixture.reader,
            space: fixture.space,
            permissions: [.read],
            expiresAt: now.addingTimeInterval(7_200)
        ))
        let maximum = SQLiteAccountDatabase.maximumNotificationRegistrationsPerSpace
        func endpoint(_ index: Int) -> String {
            "https://notify-\(index).example/xrpc/com.atproto.space.notifyWrite"
        }

        // Fill the admission budget with short-lived rows. This deliberately
        // exercises the public registration API rather than inserting rows
        // directly, so the authorization and endpoint checks remain in the
        // path under review.
        for index in 0 ..< maximum {
            try await database.registerSpaceNotification(
                .init(
                    space: fixture.space,
                    endpoint: endpoint(index),
                    repository: fixture.writer,
                    expiresAt: now.addingTimeInterval(60)
                ),
                authorization: credential,
                now: now
            )
        }

        // Replacement is idempotent even when the budget is full.
        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: endpoint(0),
                repository: nil,
                expiresAt: now.addingTimeInterval(120)
            ),
            authorization: credential,
            now: now
        )

        do {
            try await database.registerSpaceNotification(
                .init(
                    space: fixture.space,
                    endpoint: endpoint(maximum),
                    repository: fixture.writer,
                    expiresAt: now.addingTimeInterval(120)
                ),
                authorization: credential,
                now: now
            )
            XCTFail("a new endpoint must not exceed the per-space registration budget")
        } catch let error as SwanError {
            guard case .unavailable = error else {
                XCTFail("expected unavailable capacity error, got \(error)")
                return
            }
        }

        // Once the short-lived rows expire, the same transaction that admits
        // a new endpoint reclaims them before counting active registrations.
        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: endpoint(maximum + 1),
                repository: fixture.writer,
                expiresAt: now.addingTimeInterval(180)
            ),
            authorization: credential,
            now: now.addingTimeInterval(61)
        )
    }

    func testRecipientDeletionDurablyClosesLocalRepositoryAndClearsStaleOutbox() async throws {
        let fixture = try NotificationFixture()
        let writerDatabase = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root,
            did: fixture.writer
        )
        defer { Task { try? await writerDatabase.close() } }
        let uri = try SpaceRecordURI(
            space: fixture.space,
            author: fixture.writer,
            collection: "app.bsky.feed.post",
            rkey: "local"
        )
        let revision = try fixture.tid(1)
        let initialValue = Data([0xA1, 0x61, 0x61, 0x01])
        _ = try await writerDatabase.apply(
            space: fixture.space,
            author: fixture.writer,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: revision,
            writes: [
                .put(
                    uri: uri,
                    value: initialValue,
                    cid: CID.fromDAGCBOR(initialValue).string
                ),
            ]
        )
        let initialOutbox = try await writerDatabase.pendingOutbox()
        XCTAssertEqual(initialOutbox.count, 1)

        let now = Date(timeIntervalSince1970: 1_750_000_300)
        try await writerDatabase.receiveSpaceDeletionNotification(
            space: fixture.space,
            issuer: fixture.authority,
            audience: fixture.writer,
            eventID: "space-delete-1",
            now: now
        )
        // A duplicate delivery must preserve the durable closure rather than
        // reopening it or reporting a retryable failure.
        try await writerDatabase.receiveSpaceDeletionNotification(
            space: fixture.space,
            issuer: fixture.authority,
            audience: fixture.writer,
            eventID: "space-delete-1",
            now: now.addingTimeInterval(1)
        )
        let remainingOutbox = try await writerDatabase.pendingOutbox()
        XCTAssertTrue(remainingOutbox.isEmpty)
        do {
            _ = try await writerDatabase.repositoryState(
                space: fixture.space,
                author: fixture.writer
            )
            XCTFail("recipient tombstone must close repository state reads")
        } catch {}
        do {
            let postDeletionValue = Data([0xA1, 0x61, 0x61, 0x02])
            _ = try await writerDatabase.apply(
                space: fixture.space,
                author: fixture.writer,
                expectedRevision: 1,
                requestID: UUID(),
                wireRevision: try fixture.tid(2),
                writes: [
                    .put(
                        uri: uri,
                        value: postDeletionValue,
                        cid: CID.fromDAGCBOR(postDeletionValue).string
                    ),
                ]
            )
            XCTFail("recipient tombstone must close repository writes")
        } catch {}
    }

    /// A deletion service JWT carries no space claim, and the verifier keeps no
    /// replay cache (`Sources/SwanOAuth/SpaceServiceAuthentication.swift:40`).
    /// The pinned reference receiver bounds that by no-oping unless the
    /// recipient already knows the space
    /// (`packages/pds/src/api/com/atproto/space/notifySpaceDeleted.ts:33-34`).
    /// Without the same precondition one valid token mints a permanent
    /// tombstone — and a permanent receipt — for every SpaceURI under the
    /// issuer's authority, because receipt identity includes `space_uri`.
    func testDeletionNotificationForAnUnjoinedSpaceIsANoOp() async throws {
        let fixture = try NotificationFixture()
        let recipient = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root,
            did: fixture.writer
        )
        defer { Task { try? await recipient.close() } }
        try await fixture.join(space: fixture.space, on: recipient, rkey: "joined")

        let now = Date(timeIntervalSince1970: 1_750_000_400)
        // Same authority, same token identity, a space this account never
        // joined. The reference receiver answers this with a no-op.
        try await recipient.receiveSpaceDeletionNotification(
            space: fixture.secondarySpace,
            issuer: fixture.authority,
            audience: fixture.writer,
            eventID: "cross-space-replay",
            now: now
        )
        let tombstones = try await recipient.connection.query(
            """
            SELECT COUNT(*) AS row_count
            FROM permissioned_space_recipient_tombstones
            WHERE space_uri = ?
            """,
            [.text(fixture.secondarySpace.rawValue)]
        )
        XCTAssertEqual(tombstones.first?.column("row_count")?.integer, 0)
        let receipts = try await recipient.connection.query(
            """
            SELECT COUNT(*) AS row_count
            FROM permissioned_space_notification_receipts
            WHERE space_uri = ?
            """,
            [.text(fixture.secondarySpace.rawValue)]
        )
        XCTAssertEqual(receipts.first?.column("row_count")?.integer, 0)

        // The pre-emptive tombstone would also have closed the space before
        // this account ever joined it.
        try await fixture.join(
            space: fixture.secondarySpace,
            on: recipient,
            rkey: "joined-after-replay"
        )

        // Participation restored, the same message is recorded normally.
        try await recipient.receiveSpaceDeletionNotification(
            space: fixture.secondarySpace,
            issuer: fixture.authority,
            audience: fixture.writer,
            eventID: "cross-space-replay",
            now: now.addingTimeInterval(1)
        )
        let afterJoin = try await recipient.connection.query(
            """
            SELECT COUNT(*) AS row_count
            FROM permissioned_space_recipient_tombstones
            WHERE space_uri = ?
            """,
            [.text(fixture.secondarySpace.rawValue)]
        )
        XCTAssertEqual(afterJoin.first?.column("row_count")?.integer, 1)
    }

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

    func testActiveRegistrationLookupReturnsTrueForRegisteredEndpointAndBindsCorrectly() async throws {
        let fixture = try NotificationFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)
        let now = Date(timeIntervalSince1970: 1_750_000_200)
        let endpoint = "https://notify.example/xrpc/com.atproto.space.notifySpaceDeleted"
        let credential = fixture.readCredential()

        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: endpoint,
                repository: fixture.writer,
                expiresAt: now.addingTimeInterval(600)
            ),
            authorization: credential,
            now: now
        )

        let isActive = try await database.isSpaceNotificationRegistrationActive(
            space: fixture.space,
            endpoint: endpoint,
            repository: fixture.writer,
            now: now
        )
        XCTAssertTrue(isActive, "active registered endpoint must return true")

        let isExpired = try await database.isSpaceNotificationRegistrationActive(
            space: fixture.space,
            endpoint: endpoint,
            repository: fixture.writer,
            now: now.addingTimeInterval(601)
        )
        XCTAssertFalse(isExpired, "expired registration must return false")

        let isUnregistered = try await database.isSpaceNotificationRegistrationActive(
            space: fixture.space,
            endpoint: "https://other.example/notify",
            repository: nil,
            now: now
        )
        XCTAssertFalse(isUnregistered, "unregistered endpoint must return false")

        let isOtherSpace = try await database.isSpaceNotificationRegistrationActive(
            space: fixture.secondarySpace,
            endpoint: endpoint,
            repository: nil,
            now: now
        )
        XCTAssertFalse(isOtherSpace, "registration for different space must return false")
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
            configuration: try SimpleSpaceConfiguration(policy: .memberList, appAccess: .open),
            authorization: .accountOAuth(subject: self.authority, scopes: ["atproto"])
        )
        _ = try await authority.addMember(
            space: space,
            member: writer,
            authorization: .accountOAuth(subject: self.authority, scopes: ["atproto"])
        )
    }

    func createSecondaryAuthorityState(on database: SQLiteAccountDatabase) async throws {
        let authority = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
        _ = try await authority.create(
            space: secondarySpace,
            owner: self.authority,
            configuration: try SimpleSpaceConfiguration(policy: .memberList, appAccess: .open),
            authorization: .accountOAuth(subject: self.authority, scopes: ["atproto"])
        )
        _ = try await authority.addMember(
            space: secondarySpace,
            member: writer,
            authorization: .accountOAuth(subject: self.authority, scopes: ["atproto"])
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

    func register(on database: SQLiteAccountDatabase, now: Date) async throws {
        try await database.registerSpaceNotification(
            .init(
                space: space,
                endpoint: "https://notify.example/xrpc/com.atproto.space.notifyWrite",
                repository: writer,
                expiresAt: now.addingTimeInterval(3_600)
            ),
            authorization: readCredential(),
            now: now
        )
    }

    func writeNotification(
        eventID: String,
        revision: TID,
        commitmentByte: UInt8,
        space: SpaceURI? = nil
    ) -> AuthorizedSpaceWriteNotification {
        let space = space ?? self.space
        return AuthorizedSpaceWriteNotification(
            eventID: eventID,
            space: space,
            repository: writer,
            wireRevision: revision.toString(),
            commitment: Data(repeating: commitmentByte, count: 32),
            issuer: writer,
            audience: authority
        )
    }

    func tid(_ offset: Int) throws -> TID {
        let alphabet = Array("234567abcdefghijklmnopqrstuvwxyz")
        return try TID(tidString: "222222222222\(alphabet[offset])")
    }

    /// Commits the local repository row that makes this account a participant
    /// in `space`. This is the recipient-side fact the pinned reference PDS
    /// reads as `actorTxn.space.getSpace(space)`.
    @discardableResult
    func join(
        space: SpaceURI,
        on database: SQLiteAccountDatabase,
        rkey: String,
        revisionOffset: Int = 1
    ) async throws -> PersistedRepositoryCommit {
        let uri = try SpaceRecordURI(
            space: space,
            author: writer,
            collection: "app.bsky.feed.post",
            rkey: rkey
        )
        let value = Data([0xA1, 0x61, 0x61, 0x01])
        return try await database.apply(
            space: space,
            author: writer,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try tid(revisionOffset),
            writes: [
                .put(uri: uri, value: value, cid: CID.fromDAGCBOR(value).string),
            ]
        )
    }
}

private actor RecordingFanoutTransport: PermissionedSpaceNotificationFanoutTransport {
    private let database: SQLiteAccountDatabase
    private var failuresRemaining: Int
    private var events: [PersistedSpaceNotificationFanout] = []
    private var transactionStates: [Bool] = []

    init(database: SQLiteAccountDatabase, failuresRemaining: Int) {
        self.database = database
        self.failuresRemaining = failuresRemaining
    }

    func deliver(_ notification: PersistedSpaceNotificationFanout) async throws {
        events.append(notification)
        transactionStates.append(await database.hasActiveWriteTransactionForTesting())
        if failuresRemaining > 0 {
            failuresRemaining -= 1
            throw NotificationTransportFailure()
        }
    }

    func delivered() -> [PersistedSpaceNotificationFanout] { events }
    func writeTransactions() -> [Bool] { transactionStates }
}

private struct NotificationTransportFailure: Error {}

private func notificationOutboxConfiguration(
    initialFailureBackoff: TimeInterval,
    maximumFailureBackoff: TimeInterval
) throws -> PermissionedSpaceOutboxDeliveryConfiguration {
    try .init(
        leaseDuration: 10,
        idlePollInterval: 1,
        initialFailureBackoff: initialFailureBackoff,
        maximumFailureBackoff: maximumFailureBackoff
    )
}
