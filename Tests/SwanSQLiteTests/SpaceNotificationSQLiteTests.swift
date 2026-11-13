import Foundation
import Petrel
import SQLiteNIO
import SwanCore
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class SpaceNotificationSQLiteTests: XCTestCase {
    func testGlobalIssuerEventConflictsAndIdenticalReplay() async throws {
        let fixture = try NotificationFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)
        try await fixture.createSecondaryAuthorityState(on: database)

        let eventID = "writer-event-global-replay"
        let initial = fixture.writeNotification(
            eventID: eventID,
            revision: try fixture.tid(1),
            commitmentByte: 1,
            space: fixture.space
        )
        try await database.receiveSpaceWriteNotification(initial)

        // Identical replay succeeds idempotently
        try await database.receiveSpaceWriteNotification(initial)

        // Cross-space reuse fails
        do {
            try await database.receiveSpaceWriteNotification(
                fixture.writeNotification(
                    eventID: eventID,
                    revision: try fixture.tid(1),
                    commitmentByte: 1,
                    space: fixture.secondarySpace
                )
            )
            XCTFail("cross-space JTI reuse must fail")
        } catch let error as SwanError {
            guard case .unauthorized = error else {
                XCTFail("expected unauthorized error, got \(error)")
                return
            }
        }

        // Cross-action reuse fails: authority announces write, then tries to reuse same eventID for deletion
        let authEventID = "authority-event-cross-action"
        let authCommitment = Data(repeating: 3, count: 32)
        let authWrite = AuthorizedSpaceWriteNotification(
            eventID: authEventID,
            space: fixture.space,
            repository: fixture.authority,
            wireRevision: try fixture.tid(3).toString(),
            commitment: authCommitment,
            issuer: fixture.authority,
            audience: fixture.authority,
            requestBodyDigest: SpaceNotificationRequestDigest.write(
                space: fixture.space,
                repository: fixture.authority,
                wireRevision: try fixture.tid(3).toString(),
                commitment: authCommitment
            )
        )
        try await database.receiveSpaceWriteNotification(authWrite)
        do {
            try await database.receiveSpaceDeletionNotification(
                space: fixture.space,
                issuer: fixture.authority,
                audience: fixture.authority,
                eventID: authEventID,
                requestBodyDigest: SpaceNotificationRequestDigest.deletion(space: fixture.space)
            )
            XCTFail("cross-action JTI reuse must fail at receipt check")
        } catch let error as SwanError {
            guard case .unauthorized = error else {
                XCTFail("expected unauthorized error, got \(error)")
                return
            }
        }

        // Body conflict fails
        do {
            try await database.receiveSpaceWriteNotification(
                fixture.writeNotification(
                    eventID: eventID,
                    revision: try fixture.tid(1),
                    commitmentByte: 2,
                    space: fixture.space
                )
            )
            XCTFail("same JTI with different commitment must fail")
        } catch let error as SwanError {
            guard case .unauthorized = error else {
                XCTFail("expected unauthorized error, got \(error)")
                return
            }
        }

        let primary = try await database.spaceWriters(
            space: fixture.space,
            limit: 100,
            cursor: nil,
            authorization: fixture.readCredential(for: fixture.space)
        )
        let writerRow = primary.first { $0.repository == fixture.writer }
        XCTAssertEqual(writerRow?.commitment, Data(repeating: 1, count: 32))
    }

    func testWriterNotificationsAreIdempotentMonotonicAndNeverEnqueueAuthorityFanout() async throws {
        let fixture = try NotificationFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)

        let credential = fixture.readCredential()
        let endpoint = "https://notify.example/xrpc/com.atproto.space.notifyRepoUpdate"
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: endpoint,
                repository: "did:plc:other-writer",
                expiresAt: now.addingTimeInterval(3_600),
                service: "did:web:notify.example#service",
                serviceDID: "did:web:notify.example"
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
        // change. The registration above is LEGACY (endpoint-only, no service
        // identity), so Erratum 03's write fanout does not fire either: with
        // no service identity there is no audience a receiver could verify.
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

    /// SW-C: a writer signs each notifyWrite attempt with a fresh jti, so a
    /// retry after a lost acknowledgement arrives under a new event ID. The
    /// authority must recognize it by revision: no second receipt, no second
    /// forward to a service-named subscriber, and no space revision bump.
    func testRetriedWriterNotificationUnderAFreshEventIDIsANoOp() async throws {
        let fixture = try NotificationFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)
        let now = Date()
        try await fixture.register(on: database, now: now)

        for (eventID, offset) in [("first-attempt", 0.0), ("retry-attempt", 1.0)] {
            try await database.receiveSpaceWriteNotification(
                fixture.writeNotification(eventID: eventID, revision: try fixture.tid(1), commitmentByte: 4),
                now: now.addingTimeInterval(offset)
            )
        }
        let fanout = try await database.pendingNotificationFanout()
        XCTAssertEqual(fanout.count, 1)
        XCTAssertEqual(fanout.first?.sourceEventID, "first-attempt")
        let receipts = try await database.connection.query(
            "SELECT event_id FROM permissioned_space_notification_receipts WHERE space_uri = ?",
            [.text(fixture.space.rawValue)]
        )
        XCTAssertEqual(receipts.map { $0.column("event_id")?.string }, ["first-attempt"])
        let writers = try await database.spaceWriters(
            space: fixture.space, limit: 10, cursor: nil, authorization: fixture.readCredential()
        )
        XCTAssertEqual(writers.map(\.wireRevision), [try fixture.tid(1).toString()])
    }

    /// Erratum 03: write fanout fires for SERVICE-NAMED registrations only,
    /// from both write paths — a member's announced write and a local apply —
    /// carrying the writer/revision/commitment the `notifyWrite` body needs.
    /// Legacy endpoint-only rows enqueue nothing, an expired service row stops
    /// matching, and the service-identity accessor answers per registration.
    func testWriteFanoutEnqueuesOnlyForServiceNamedRegistrations() async throws {
        let fixture = try NotificationFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)

        let credential = fixture.readCredential()
        // Wall-clock, deliberately: the LOCAL apply path stamps its fanout
        // rows with real time, so a fixed past epoch would silently expire
        // every registration for that path.
        let now = Date()
        let legacyEndpoint = "https://legacy.example/xrpc/com.atproto.space.notifyRepoUpdate"
        let serviceEndpoint = "https://events.bulleted.example"
        let serviceIdentity = "did:web:events.bulleted.example#bulleted_events"
        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: legacyEndpoint,
                repository: nil,
                expiresAt: now.addingTimeInterval(3_600),
                service: nil,
                serviceDID: "did:plc:serviceabcdefghijklmnop"
            ),
            authorization: credential,
            now: now
        )
        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: serviceEndpoint,
                repository: nil,
                expiresAt: now.addingTimeInterval(3_600),
                service: serviceIdentity
            ),
            serviceDID: "did:plc:serviceabcdefghijklmnop",
            authorization: credential,
            now: now
        )

        // Path 1: a LOCAL apply by the authority's own account enqueues
        // in-transaction (the authority is its own hosted writer here).
        let localURI = try SpaceRecordURI(
            space: fixture.space,
            author: fixture.authority,
            collection: "app.bsky.feed.post",
            rkey: "erratum03-local"
        )
        let localValue = Data([0xA1, 0x61, 0x61, 0x01])
        _ = try await database.apply(
            space: fixture.space,
            author: fixture.authority,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try fixture.tid(1),
            writes: [
                .put(
                    uri: localURI,
                    value: localValue,
                    cid: CID.fromDAGCBOR(localValue).string
                ),
            ]
        )
        let afterLocal = try await database.pendingNotificationFanout()
        XCTAssertEqual(afterLocal.count, 1, "only the service registration enqueues")
        let localRow = try XCTUnwrap(afterLocal.first)
        XCTAssertEqual(localRow.kind, .write)
        XCTAssertEqual(localRow.endpoint, serviceEndpoint)
        XCTAssertEqual(localRow.repository, fixture.authority)
        XCTAssertEqual(localRow.wireRevision, try fixture.tid(1).toString())
        XCTAssertNotNil(localRow.commitment)
        XCTAssertEqual(localRow.sourceIssuer, fixture.authority)

        // Path 2: a member's announced write fans out the same way.
        try await database.receiveSpaceWriteNotification(
            fixture.writeNotification(
                eventID: "erratum03-announced",
                revision: try fixture.tid(2),
                commitmentByte: 7
            ),
            now: now
        )
        let afterAnnounce = try await database.pendingNotificationFanout()
        XCTAssertEqual(afterAnnounce.count, 2)
        let announced = try XCTUnwrap(
            afterAnnounce.first { $0.wireRevision == (try? fixture.tid(2).toString()) }
        )
        XCTAssertEqual(announced.kind, .write)
        XCTAssertEqual(announced.endpoint, serviceEndpoint)
        XCTAssertEqual(announced.commitment, Data(repeating: 7, count: 32))

        // The identity accessor: the delivery worker's source of the JWT
        // audience. Legacy rows answer nil; an inactive row answers nil.
        let identity = try await database.spaceNotificationRegistrationService(
            space: fixture.space,
            endpoint: serviceEndpoint,
            repository: fixture.writer,
            now: now
        )
        XCTAssertEqual(identity, serviceIdentity)
        let legacyIdentity = try await database.spaceNotificationRegistrationService(
            space: fixture.space,
            endpoint: legacyEndpoint,
            repository: nil,
            now: now
        )
        XCTAssertNil(legacyIdentity, "endpoint-only registration must have nil delivery service")
        let expiredIdentity = try await database.spaceNotificationRegistrationService(
            space: fixture.space,
            endpoint: serviceEndpoint,
            repository: fixture.writer,
            now: now.addingTimeInterval(4_000)
        )
        XCTAssertNil(expiredIdentity)

        // An expired service registration stops enqueueing.
        try await database.receiveSpaceWriteNotification(
            fixture.writeNotification(
                eventID: "erratum03-after-expiry",
                revision: try fixture.tid(3),
                commitmentByte: 8
            ),
            now: now.addingTimeInterval(4_000)
        )
        let afterExpiry = try await database.pendingNotificationFanout()
        XCTAssertEqual(afterExpiry.count, 2, "an expired service registration enqueues nothing")
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
        XCTAssertEqual(compactedRows.first?.column("row_count")?.integer, 2)

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
                requestBodyDigest: SpaceNotificationRequestDigest.deletion(space: fixture.space),
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
            authorization: .accountOAuthForTesting(subject: fixture.authority, scopes: ["atproto"]),
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
            serviceDID: "did:plc:serviceabcdefghijklmnop",
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
            serviceDID: "did:plc:serviceabcdefghijklmnop",
            authorization: credential,
            now: now
        )
        _ = try await database.deleteSimpleSpace(
            space: fixture.space,
            authorization: .accountOAuthForTesting(subject: fixture.authority, scopes: ["atproto"]),
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
            "https://notify-\(index).example/xrpc/com.atproto.space.notifyRepoUpdate"
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
            serviceDID: "did:plc:serviceabcdefghijklmnop",
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
            serviceDID: "did:plc:serviceabcdefghijklmnop",
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
            serviceDID: "did:plc:serviceabcdefghijklmnop",
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
            serviceDID: "did:plc:serviceabcdefghijklmnop",
            authorization: credential,
            now: now.addingTimeInterval(61)
        )
    }

    func testRecipientDeletionLeavesAuthoredRepositoryOpenAndClearsOnlyItsStaleOutbox() async throws {
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
        let blobBytes = Data([0x31, 0x32, 0x33])
        let blob = try await writerDatabase.putBlob(blobBytes, namespace: .space(fixture.space))
        try await fixture.join(space: fixture.secondarySpace, on: writerDatabase, rkey: "other-space")
        let repository = try DurableSpaceRepository(
            database: writerDatabase, space: fixture.space, author: fixture.writer
        )
        let sharedCredential = fixture.readCredential()
        let sharedReadBeforeNotice = try await repository.record(uri, authorization: sharedCredential)
        XCTAssertEqual(sharedReadBeforeNotice?.value, initialValue)

        let now = Date(timeIntervalSince1970: 1_750_000_300)
        try await writerDatabase.receiveSpaceDeletionNotification(
            space: fixture.space,
            issuer: fixture.authority,
            audience: fixture.writer,
            eventID: "space-delete-1",
            requestBodyDigest: SpaceNotificationRequestDigest.deletion(space: fixture.space),
            now: now
        )
        // A duplicate delivery preserves the sync deletion signal without
        // taking ownership of the member's authored repository.
        try await writerDatabase.receiveSpaceDeletionNotification(
            space: fixture.space,
            issuer: fixture.authority,
            audience: fixture.writer,
            eventID: "space-delete-1",
            requestBodyDigest: SpaceNotificationRequestDigest.deletion(space: fixture.space),
            now: now.addingTimeInterval(1)
        )
        let remainingOutbox = try await writerDatabase.pendingOutbox()
        XCTAssertEqual(remainingOutbox.map(\.space), [fixture.secondarySpace])
        let selfRead = AuthorizationContext.accountOAuthForTesting(
            subject: fixture.writer,
            scopes: ["space:\(fixture.space.spaceType)?authority=\(fixture.space.authority)&skey=\(fixture.space.skey)&action=read_self"]
        )
        let record = try await repository.record(uri, authorization: selfRead)
        XCTAssertEqual(record?.value, initialValue)
        let blobMetadata = try await repository.permissionedBlobMetadata(cid: blob.cid, authorization: selfRead)
        XCTAssertEqual(blobMetadata?.size, blobBytes.count)
        let retainedBlob = try await writerDatabase.blobData(for: blob)
        XCTAssertEqual(retainedBlob, blobBytes)
        let spaces = try await writerDatabase.hostedSpaces(
            spaceType: nil, authority: nil, cursor: nil, limit: 100
        )
        XCTAssertEqual(Set(spaces.map(\.space)), Set([fixture.space, fixture.secondarySpace]))
        let receiptRows = try await writerDatabase.connection.query(
            "SELECT COUNT(*) AS row_count FROM permissioned_space_notification_receipts WHERE space_uri = ?",
            [.text(fixture.space.rawValue)]
        )
        XCTAssertEqual(receiptRows.first?.column("row_count")?.integer, 1)

        // SWAN-SYNC-1: the recipient tombstone closes replicated and derived
        // state only. The member's own repository stays readable through
        // every shared facade, as upstream leaves member repositories
        // untouched and a recreated space must be able to read them again
        // (October 22 section 6).
        for authorization in [
            sharedCredential,
            AuthorizationContext.service(subject: fixture.reader, audience: fixture.authority),
        ] {
            let sharedReads: [(String, @Sendable () async throws -> Void)] = [
                ("record", { _ = try await repository.record(uri, authorization: authorization) }),
                ("listRecords", {
                    _ = try await repository.listRecords(
                        collection: nil, limit: 10, cursor: nil, reverse: false, authorization: authorization
                    )
                }),
                ("listBlobs", {
                    _ = try await repository.listBlobCIDs(since: nil, cursor: nil, limit: 10, authorization: authorization)
                }),
                ("blobMetadata", {
                    _ = try await repository.permissionedBlobMetadata(cid: blob.cid, authorization: authorization)
                }),
                ("commitState", { _ = try await repository.currentCommitState(authorization: authorization) }),
                ("snapshot", { _ = try await repository.snapshot(authorization: authorization) }),
                ("CAR", {
                    let snapshot = try await repository.prepareCARSnapshot(authorization: authorization)
                    snapshot?.spool.cleanup()
                }),
                ("oplog", {
                    _ = try await repository.incrementalOplog(since: nil, limit: 10, includeValues: true, authorization: authorization)
                }),
            ]
            for (name, read) in sharedReads {
                do {
                    try await read()
                } catch {
                    XCTFail("\(name) closed the member's own repository after a recipient deletion: \(error)")
                }
            }
        }

        let postDeletionValue = Data([0xA1, 0x61, 0x61, 0x02])
        _ = try await writerDatabase.apply(
            space: fixture.space,
            author: fixture.writer,
            expectedRevision: 1,
            requestID: UUID(),
            wireRevision: try fixture.tid(2),
            writes: [.put(uri: uri, value: postDeletionValue, cid: CID.fromDAGCBOR(postDeletionValue).string)]
        )
        let updated = try await repository.record(uri, authorization: selfRead)
        XCTAssertEqual(updated?.value, postDeletionValue)
        let sibling = try await writerDatabase.repositoryState(space: fixture.secondarySpace, author: fixture.writer)
        XCTAssertEqual(sibling?.revision, 1)
        // A post-deletion write still announces itself to the authority, so
        // a recreated space learns of the member's new state.
        let outboxAfterWrite = try await writerDatabase.pendingOutbox()
        XCTAssertEqual(Set(outboxAfterWrite.map(\.space)), [fixture.space, fixture.secondarySpace])
        XCTAssertEqual(outboxAfterWrite.filter { $0.space == fixture.space }.map(\.revision), [2])

        try await writerDatabase.close()
        let reopened = try await SQLiteAccountDatabase(dataDirectory: fixture.root, did: fixture.writer)
        do {
            let retained = try await reopened.repositoryState(space: fixture.space, author: fixture.writer)
            XCTAssertEqual(retained?.revision, 2)
            let reopenedBlob = try await reopened.blobData(for: blob)
            XCTAssertEqual(reopenedBlob, blobBytes)
            try await reopened.close()
        } catch {
            try? await reopened.close()
            throw error
        }
    }

    /// A deletion service JWT carries no space claim, and the verifier keeps no
    /// replay cache (`Sources/SwanOAuth/SpaceServiceAuthentication.swift:40`).
    /// Only spaces known through authored or synchronized state need a
    /// deletion marker. Unknown spaces must not allocate permanent receipts
    /// or markers, and a marker must never close the member's own repository.
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
            requestBodyDigest: SpaceNotificationRequestDigest.deletion(space: fixture.secondarySpace),
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

        // An ignored signal does not prevent the member from writing its own
        // repository in this space later.
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
            eventID: "space-delete-joined",
            requestBodyDigest: SpaceNotificationRequestDigest.deletion(space: fixture.secondarySpace),
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
            serviceDID: "did:plc:serviceabcdefghijklmnop",
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

    func testForeignRegistrationOverwriteIsForbidden() async throws {
        let fixture = try NotificationFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)

        let now = Date()
        let endpoint = "https://receiver.example/notify"
        let credential = fixture.readCredential()

        // Service A registers endpoint
        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: endpoint,
                repository: fixture.writer,
                expiresAt: now.addingTimeInterval(3600),
                service: "did:web:service-a.example#srv",
                serviceDID: "did:web:service-a.example"
            ),
            authorization: credential,
            now: now
        )

        // Service B claiming Service A's service identity -> fails
        do {
            try await database.registerSpaceNotification(
                .init(
                    space: fixture.space,
                    endpoint: endpoint,
                    repository: fixture.writer,
                    expiresAt: now.addingTimeInterval(3600),
                    service: "did:web:service-a.example#srv",
                    serviceDID: "did:web:service-b.example"
                ),
                authorization: credential,
                now: now
            )
            XCTFail("foreign registration overwrite must fail")
        } catch let error as SwanError {
            guard case .unauthorized = error else {
                XCTFail("expected unauthorized error, got \(error)")
                return
            }
        }

        // SWAN-SYNC-4: Service B registering its own identity behind the same
        // endpoint is accepted, as the reference keys (space, serviceDid),
        // and leaves Service A's registration untouched.
        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: endpoint,
                repository: nil,
                expiresAt: now.addingTimeInterval(1800),
                service: "did:web:service-b.example#srv",
                serviceDID: "did:web:service-b.example"
            ),
            authorization: credential,
            now: now
        )
        let shared = try await database.connection.query(
            """
            SELECT service_key, owner_service_did, repo_did
            FROM permissioned_space_notification_registrations
            WHERE space_uri = ? AND endpoint = ? ORDER BY service_key
            """,
            [.text(fixture.space.rawValue), .text(endpoint)]
        )
        XCTAssertEqual(shared.compactMap { $0.column("service_key")?.string },
                       ["did:web:service-a.example#srv", "did:web:service-b.example#srv"])
        XCTAssertEqual(shared.first?.column("owner_service_did")?.string, "did:web:service-a.example")
        XCTAssertEqual(shared.first?.column("repo_did")?.string, fixture.writer)

        // Service A re-registering its own endpoint succeeds
        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: endpoint,
                repository: nil,
                expiresAt: now.addingTimeInterval(7200),
                service: "did:web:service-a.example#srv",
                serviceDID: "did:web:service-a.example"
            ),
            authorization: credential,
            now: now
        )
    }

    func testForeignRegistrationDeleteIsForbidden() async throws {
        let fixture = try NotificationFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)

        let now = Date()
        let endpoint = "https://receiver.example/notify"
        let credential = fixture.readCredential()

        // Service A registers endpoint
        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: endpoint,
                repository: fixture.writer,
                expiresAt: now.addingTimeInterval(3600),
                service: "did:web:service-a.example#srv",
                serviceDID: "did:web:service-a.example"
            ),
            authorization: credential,
            now: now
        )

        // Service B unregisters its own identity (which has no rows)
        try await database.unregisterSpaceNotification(
            space: fixture.space,
            service: "did:web:service-b.example",
            authorization: credential
        )

        // Service A's registration is still active
        let active = try await database.isSpaceNotificationRegistrationActive(
            space: fixture.space,
            endpoint: endpoint,
            repository: fixture.writer,
            now: now
        )
        XCTAssertTrue(active, "foreign delete must not delete service A's registration")

        // Service A unregisters
        try await database.unregisterSpaceNotification(
            space: fixture.space,
            service: "did:web:service-a.example#srv",
            authorization: credential
        )
        let activeAfter = try await database.isSpaceNotificationRegistrationActive(
            space: fixture.space,
            endpoint: endpoint,
            repository: fixture.writer,
            now: now
        )
        XCTAssertFalse(activeAfter, "own unregister must remove registration")
    }

    func testExactNotificationServiceUnregisterLeavesSiblingFragmentsAndEndpointOnly() async throws {
        let fixture = try NotificationFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)

        let now = Date()
        let credential = fixture.readCredential()
        let owner = "did:web:subscriber.example"
        let serviceA = "did:web:subscriber.example#a"
        let serviceB = "did:web:subscriber.example#b"
        let endpointA = "https://a.example/notify"
        let endpointB = "https://b.example/notify"
        let endpointOnly = "https://endpoint-only.example/notify"

        // Register #a for owner
        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: endpointA,
                repository: fixture.writer,
                expiresAt: now.addingTimeInterval(3600),
                service: serviceA,
                serviceDID: owner
            ),
            authorization: credential,
            now: now
        )

        // Register #b for same owner
        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: endpointB,
                repository: fixture.writer,
                expiresAt: now.addingTimeInterval(3600),
                service: serviceB,
                serviceDID: owner
            ),
            authorization: credential,
            now: now
        )

        // Register endpoint-only for same owner
        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: endpointOnly,
                repository: fixture.writer,
                expiresAt: now.addingTimeInterval(3600),
                service: nil,
                serviceDID: owner
            ),
            authorization: credential,
            now: now
        )

        let activeA = try await database.isSpaceNotificationRegistrationActive(space: fixture.space, endpoint: endpointA, repository: fixture.writer, now: now)
        let activeB = try await database.isSpaceNotificationRegistrationActive(space: fixture.space, endpoint: endpointB, repository: fixture.writer, now: now)
        let activeOnly = try await database.isSpaceNotificationRegistrationActive(space: fixture.space, endpoint: endpointOnly, repository: fixture.writer, now: now)
        XCTAssertTrue(activeA)
        XCTAssertTrue(activeB)
        XCTAssertTrue(activeOnly)

        // Unregister specific service #a only
        try await database.unregisterSpaceNotification(
            space: fixture.space,
            ownerServiceDID: owner,
            deliveryServiceDID: serviceA,
            authorization: credential
        )

        let activeA2 = try await database.isSpaceNotificationRegistrationActive(space: fixture.space, endpoint: endpointA, repository: fixture.writer, now: now)
        let activeB2 = try await database.isSpaceNotificationRegistrationActive(space: fixture.space, endpoint: endpointB, repository: fixture.writer, now: now)
        let activeOnly2 = try await database.isSpaceNotificationRegistrationActive(space: fixture.space, endpoint: endpointOnly, repository: fixture.writer, now: now)
        XCTAssertFalse(activeA2, "exact unregister of #a must remove #a")
        XCTAssertTrue(activeB2, "exact unregister of #a must leave #b untouched")
        XCTAssertTrue(activeOnly2, "exact unregister of #a must leave endpoint-only untouched")

        // Unregister owner base DID (without fragment) -> removes all registrations under owner including endpoint-only
        try await database.unregisterSpaceNotification(
            space: fixture.space,
            ownerServiceDID: owner,
            deliveryServiceDID: nil,
            authorization: credential
        )

        let activeOnly3 = try await database.isSpaceNotificationRegistrationActive(space: fixture.space, endpoint: endpointOnly, repository: fixture.writer, now: now)
        XCTAssertFalse(activeOnly3, "base DID unregister must remove endpoint-only registration")

        // Finally unregister #b
        try await database.unregisterSpaceNotification(
            space: fixture.space,
            ownerServiceDID: owner,
            deliveryServiceDID: serviceB,
            authorization: credential
        )
        let activeB3 = try await database.isSpaceNotificationRegistrationActive(space: fixture.space, endpoint: endpointB, repository: fixture.writer, now: now)
        XCTAssertFalse(activeB3)
    }

    func testEndpointOnlyRegistrationDoesNotEnqueueDynamicFanoutAndReturnsNilService() async throws {
        let fixture = try NotificationFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)

        let endpoint = "https://legacy-endpoint.example/sink"
        let credential = fixture.readCredential()
        let now = Date()

        // Register endpoint-only (service is nil, serviceDID is authenticated owner)
        try await database.registerSpaceNotification(
            .init(
                space: fixture.space,
                endpoint: endpoint,
                repository: fixture.writer,
                expiresAt: now.addingTimeInterval(3600),
                service: nil,
                serviceDID: fixture.reader
            ),
            authorization: credential,
            now: now
        )

        // spaceNotificationRegistrationService must return nil for endpoint-only row
        let svc = try await database.spaceNotificationRegistrationService(
            space: fixture.space,
            endpoint: endpoint,
            repository: fixture.writer,
            now: now
        )
        XCTAssertNil(svc, "endpoint-only registration must return nil service identity")

        // Receive write notification -> verify no dynamic fanout row is enqueued
        let notification = fixture.writeNotification(
            eventID: "write-event-legacy-check",
            revision: try fixture.tid(1),
            commitmentByte: 1
        )
        try await database.receiveSpaceWriteNotification(notification, now: now)

        let pendingFanouts = try await database.pendingNotificationFanout()
        XCTAssertTrue(pendingFanouts.isEmpty, "endpoint-only registration must never enqueue dynamic fanout")
    }

    func testSpaceNotificationOwnershipMigrationClearsLegacyRowsAndRebuildsTable() async throws {
        let fixture = try NotificationFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        try await fixture.createAuthorityState(on: database)
        try await database.close()

        let databasePath = SQLiteLayout.accountDatabase(in: fixture.root, did: fixture.authority).path
        let raw = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await raw.query("DELETE FROM permissioned_repository_migrations WHERE version = 22")
        _ = try await raw.query("DROP TABLE IF EXISTS permissioned_space_notification_registrations")
        _ = try await raw.query("""
            CREATE TABLE permissioned_space_notification_registrations (
                space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
                endpoint TEXT NOT NULL,
                repo_did TEXT,
                expires_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                service_did TEXT,
                PRIMARY KEY(space_uri, endpoint)
            )
        """)
        _ = try await raw.query("""
            INSERT INTO permissioned_space_notification_registrations(
                space_uri, endpoint, repo_did, expires_at, updated_at, service_did
            ) VALUES
                ('\(fixture.space.rawValue)', 'https://legacy.example/sink', NULL, 1800000000, 1700000000, NULL),
                ('\(fixture.space.rawValue)', 'https://valid.example/sink', NULL, 1800000000, 1700000000, 'did:web:valid.example')
        """)
        try await raw.close()

        // Open via SQLiteAccountDatabase which runs migrations
        let reopened = try await fixture.open()
        defer { Task { try? await reopened.close() } }

        // Verify schema is NOT NULL
        let columns = try await reopened.connection.query("PRAGMA table_info(permissioned_space_notification_registrations)")
        let serviceCol = columns.first { $0.column("name")?.string == "owner_service_did" }
        XCTAssertEqual(serviceCol?.column("notnull")?.integer, 1, "owner_service_did must be NOT NULL after migration")

        // Verify zero survivors: all pre-fix rows must be deleted
        let rows = try await reopened.connection.query("SELECT endpoint, owner_service_did FROM permissioned_space_notification_registrations")
        XCTAssertEqual(rows.count, 0, "legacy rows must be discarded during migration")
    }

    func testSpaceDeleteAndRecreateRemovesWriterHighWaterAndAdmitsLiveNotificationAndRecovery() async throws {
        let fixture = try NotificationFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        try await fixture.createAuthorityState(on: database)

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

    func register(on database: SQLiteAccountDatabase, now: Date, service: String = "did:web:notify.example#service") async throws {
        try await database.registerSpaceNotification(
            .init(
                space: space,
                endpoint: "https://notify.example/xrpc/com.atproto.space.notifyRepoUpdate",
                repository: writer,
                expiresAt: now.addingTimeInterval(3_600),
                service: service,
                serviceDID: service
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
