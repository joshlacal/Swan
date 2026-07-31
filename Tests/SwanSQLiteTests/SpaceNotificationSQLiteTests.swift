import Foundation
import Petrel
import SwanCore
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class SpaceNotificationSQLiteTests: XCTestCase {
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
        // A reordered older TID records its receipt but cannot regress the
        // authority hint or produce another recipient delivery.
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
}

private struct NotificationFixture {
    let root: URL
    let authority = "did:plc:alice"
    let writer = "did:plc:bob"
    let reader = "did:plc:reader"
    let space: SpaceURI

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSpaceNotificationTests-\(UUID().uuidString)")
        space = try SpaceURI(
            authority: authority,
            spaceType: "app.bsky.bookmarks",
            skey: "notifications"
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

    func readCredential() -> AuthorizationContext {
        .spaceCredential(.init(
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
        commitmentByte: UInt8
    ) -> AuthorizedSpaceWriteNotification {
        .init(
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
