import Foundation
import Petrel
import SQLiteNIO
import SwanCore
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class ConversationSpaceAuthorityStoreTests: XCTestCase {
    func testActiveRegistrySupportsDiscoveryAndNotificationsWithoutSimplePolicyAndDeletionClosesLeasedWrites() async throws {
        let fixture = try ConversationAuthorityFixture()
        let database = try await fixture.open()
        do {
            try await database.registerKnownConversationSpace(space: fixture.space, now: fixture.now)
            try await database.registerKnownConversationSpace(space: fixture.space, now: fixture.now)
            try await fixture.register(on: database, endpoint: fixture.endpoint, repository: nil)
            let policy = try await database.connection.query("SELECT 1 FROM permissioned_simple_space_authorities WHERE space_uri = ?", [.text(fixture.space.rawValue)])
            XCTAssertTrue(policy.isEmpty, "conversation membership must never be represented as synthetic simple-space policy")
            let hosted = try await database.hostedSpaceURIs(spaceType: fixture.space.spaceType, authority: fixture.owner, cursor: nil, limit: 100)
            XCTAssertEqual(hosted, [fixture.space])
            let write = try fixture.notification()
            do {
                try await database.receiveSpaceWriteNotification(write, now: fixture.now)
                XCTFail("ordinary notification path must not bypass the live membership boundary")
            } catch let error as SwanError { guard case .unauthorized = error else { throw error } }
            try await database.receiveMembershipVerifiedConversationSpaceWriteNotification(write, now: fixture.now)
            let writers = try await database.spaceWriters(space: fixture.space, limit: 10, cursor: nil, authorization: fixture.credential)
            XCTAssertEqual(writers.map(\.repository), [fixture.writer])
            let pendingLease = try await database.leaseNextNotificationFanout(now: fixture.now, leaseDuration: 60)
            let leased = try XCTUnwrap(pendingLease)
            XCTAssertEqual(leased.event.kind, .write)
            let deletion = try await database.beginConversationSpaceDeletion(space: fixture.space, authorization: fixture.ownerAuthorization, now: fixture.now)
            let repeated = try await database.beginConversationSpaceDeletion(space: fixture.space, authorization: fixture.ownerAuthorization, now: fixture.now)
            XCTAssertEqual(deletion, repeated)
            let queued = try await database.pendingNotificationFanout()
            XCTAssertTrue(queued.isEmpty, "beginning deletion must not publish a deletion before DS confirmation")
            let active = try await database.isSpaceNotificationRegistrationActive(space: fixture.space, endpoint: fixture.endpoint, repository: fixture.writer, now: fixture.now)
            let dynamic = try await database.spaceNotificationRegistrationService(space: fixture.space, endpoint: fixture.endpoint, repository: fixture.writer, now: fixture.now)
            XCTAssertFalse(active)
            XCTAssertNil(dynamic)
            let acknowledged = try await database.completeNotificationFanoutLease(eventID: leased.event.id, token: leased.token)
            XCTAssertFalse(acknowledged)
            for operation in 0..<4 {
                do {
                    switch operation {
                    case 0: try await database.registerKnownConversationSpace(space: fixture.space, now: fixture.now)
                    case 1: try await fixture.register(on: database, endpoint: fixture.endpoint, repository: nil)
                    case 2: try await database.receiveMembershipVerifiedConversationSpaceWriteNotification(write, now: fixture.now)
                    default: _ = try await database.spaceWriters(space: fixture.space, limit: 10, cursor: nil, authorization: fixture.credential)
                    }
                    XCTFail("closed conversation generation was accepted by operation \(operation)")
                } catch let error as AuthorizedSimpleSpaceLifecycleError { XCTAssertEqual(error, .deleted) }
            }
            let visibleAfterBegin = try await database.hostedSpaceURIs(spaceType: fixture.space.spaceType, authority: fixture.owner, cursor: nil, limit: 100)
            XCTAssertTrue(visibleAfterBegin.isEmpty)
            try await database.close()
        } catch { try? await database.close(); throw error }
    }

    func testDeletionIntentSurvivesRestartAndFinishesOnceForEveryRecipientThenDrains() async throws {
        let fixture = try ConversationAuthorityFixture()
        let database = try await fixture.open()
        let deletion: ConversationSpaceDeletion
        do {
            try await database.registerKnownConversationSpace(space: fixture.space, now: fixture.now)
            try await fixture.register(on: database, endpoint: fixture.endpoint, repository: nil)
            try await fixture.register(on: database, endpoint: "https://second.example/events", repository: "did:plc:other-writer")
            try await fixture.write(on: database)
            deletion = try await database.beginConversationSpaceDeletion(space: fixture.space, authorization: fixture.ownerAuthorization, now: fixture.now)
            do {
                try await fixture.write(on: database)
                XCTFail("local writes must close while DS deletion remains pending")
            } catch let error as SwanError { guard case .unauthorized = error else { throw error } }
            try await database.close()
        } catch { try? await database.close(); throw error }
        let reopened = try await fixture.open()
        do {
            let pending = try await reopened.pendingConversationSpaceDeletions(authority: fixture.owner)
            XCTAssertEqual(pending, [deletion])
            do {
                try await reopened.finishConversationSpaceDeletion(.init(space: fixture.space, eventID: UUID().uuidString.lowercased()), now: fixture.now)
                XCTFail("an unrelated event cannot complete durable deletion intent")
            } catch let error as SwanError { guard case .unauthorized = error else { throw error } }
            try await reopened.finishConversationSpaceDeletion(deletion, now: fixture.now)
            try await reopened.finishConversationSpaceDeletion(deletion, now: fixture.now)
            let noPending = try await reopened.pendingConversationSpaceDeletions(authority: fixture.owner)
            XCTAssertTrue(noPending.isEmpty)
            let fanout = try await reopened.pendingNotificationFanout()
            XCTAssertEqual(fanout.count, 2)
            XCTAssertEqual(Set(fanout.map(\.sourceEventID)), [deletion.eventID])
            XCTAssertTrue(fanout.allSatisfy { $0.kind == .deleted && $0.repository == nil })
            let records = try await reopened.connection.query("SELECT 1 FROM permissioned_space_records WHERE space_uri = ?", [.text(fixture.space.rawValue)])
            XCTAssertTrue(records.isEmpty)
            for _ in 0..<2 {
                let pendingLease = try await reopened.leaseNextNotificationFanout(now: fixture.now, leaseDuration: 60)
                let leased = try XCTUnwrap(pendingLease)
                let registration = try await reopened.currentSpaceDeletionDeliveryRegistration(for: leased.event, now: fixture.now)
                XCTAssertNotNil(registration)
                let completed = try await reopened.completeNotificationFanoutLease(eventID: leased.event.id, token: leased.token)
                XCTAssertTrue(completed, "SQLite fanout UUID spelling must round-trip through its lease")
            }
            try await reopened.finishConversationSpaceDeletion(deletion, now: fixture.now)
            let drained = try await reopened.pendingNotificationFanout()
            let registrations = try await reopened.connection.query("SELECT 1 FROM permissioned_space_notification_registrations WHERE space_uri = ?", [.text(fixture.space.rawValue)])
            XCTAssertTrue(drained.isEmpty, "repeated completion cannot create another deletion delivery")
            XCTAssertTrue(registrations.isEmpty)
            do {
                try await reopened.registerKnownConversationSpace(space: fixture.space, now: fixture.now)
                XCTFail("a deleted immutable generation must never reopen")
            } catch let error as AuthorizedSimpleSpaceLifecycleError { XCTAssertEqual(error, .deleted) }
            try await reopened.close()
        } catch { try? await reopened.close(); throw error }
    }

    /// SWAN-SYNC-3: owed recipients survive a delivery-service outage,
    /// restart and partial drain, but only until their own registration
    /// expires (October 22 section 6), mirroring simple spaces.
    func testOwedRecipientsSurviveOutageRestartAndPartialDrainUntilRegistrationExpiry() async throws {
        let fixture = try ConversationAuthorityFixture()
        let start = Date(timeIntervalSince1970: 100)
        let expiry = Date(timeIntervalSince1970: 300)
        let delayed = Date(timeIntervalSince1970: 200)
        let lapsed = Date(timeIntervalSince1970: 301)
        let database = try await fixture.open()
        let deletion: ConversationSpaceDeletion
        do {
            try await database.registerKnownConversationSpace(space: fixture.space, now: Date(timeIntervalSince1970: 98))
            for (endpoint, expires) in [(fixture.endpoint, expiry), ("https://second.example/events", expiry),
                                        ("https://expired.example/events", Date(timeIntervalSince1970: 99))] {
                try await database.registerSpaceNotification(.init(space: fixture.space, endpoint: endpoint, repository: nil,
                    expiresAt: expires, ownerServiceDID: fixture.service, deliveryServiceDID: fixture.service),
                    authorization: fixture.credential, now: Date(timeIntervalSince1970: 98))
            }
            deletion = try await database.beginConversationSpaceDeletion(space: fixture.space, authorization: fixture.ownerAuthorization, now: start)
            let owed = try await database.connection.query("SELECT endpoint, registration_expires_at FROM conversation_space_deletion_recipients WHERE space_uri = ?", [.text(fixture.space.rawValue)])
            XCTAssertEqual(owed.count, 2, "only recipients authenticated and active at deletion begin are owed the terminal signal")
            XCTAssertTrue(owed.allSatisfy { $0.column("registration_expires_at")?.integer == 300_000_000 })
            try await database.deferConversationSpaceDeletion(deletion, now: Date(timeIntervalSince1970: 150))
            try await database.close()
        } catch { try? await database.close(); throw error }
        let reopened = try await fixture.open()
        do {
            try await reopened.finishConversationSpaceDeletion(deletion, now: delayed)
            let fanout = try await reopened.pendingNotificationFanout()
            XCTAssertEqual(fanout.count, 2)
            for event in fanout {
                let destination = try await reopened.currentSpaceDeletionDeliveryRegistration(for: event, now: delayed)
                XCTAssertEqual(destination?.serviceIdentity, fixture.service)
            }
            let originalExpiry = try await reopened.connection.query("SELECT expires_at FROM permissioned_space_notification_registrations WHERE space_uri = ? AND endpoint = ?", [.text(fixture.space.rawValue), .text(fixture.endpoint)])
            XCTAssertEqual(originalExpiry.first?.column("expires_at")?.integer, 300_000_000, "a terminal obligation must never synthesize a renewed registration")
            let firstLease = try await reopened.leaseNextNotificationFanout(now: delayed, leaseDuration: 30)
            let first = try XCTUnwrap(firstLease)
            let failed = try await reopened.failNotificationFanoutLease(eventID: first.event.id, token: first.token, retryAt: delayed.addingTimeInterval(1))
            XCTAssertEqual(failed, 1)
            let retryDestination = try await reopened.currentSpaceDeletionDeliveryRegistration(for: first.event, now: delayed.addingTimeInterval(1))
            XCTAssertNotNil(retryDestination)
            let secondLease = try await reopened.leaseNextNotificationFanout(now: delayed, leaseDuration: 30)
            let second = try XCTUnwrap(secondLease)
            let firstAcknowledged = try await reopened.completeNotificationFanoutLease(eventID: second.event.id, token: second.token)
            XCTAssertTrue(firstAcknowledged)
            let retained = try await reopened.connection.query("SELECT 1 FROM conversation_space_deletion_recipients WHERE space_uri = ?", [.text(fixture.space.rawValue)])
            XCTAssertEqual(retained.count, 2, "partial completion retains the immutable recipient snapshot")
            // Retries stop once that recipient's registration has expired:
            // the transport treats a nil registration as a delivered no-op.
            let retriedLease = try await reopened.leaseNextNotificationFanout(now: lapsed, leaseDuration: 30)
            let retried = try XCTUnwrap(retriedLease)
            XCTAssertEqual(retried.event.id, first.event.id)
            let expiredDestination = try await reopened.currentSpaceDeletionDeliveryRegistration(for: retried.event, now: lapsed)
            XCTAssertNil(expiredDestination, "an expired registration is no longer owed the deletion")
            let finalAcknowledged = try await reopened.completeNotificationFanoutLease(eventID: retried.event.id, token: retried.token)
            XCTAssertTrue(finalAcknowledged)
            let drained = try await reopened.connection.query("SELECT 1 FROM conversation_space_deletion_recipients WHERE space_uri = ?", [.text(fixture.space.rawValue)])
            let registrations = try await reopened.connection.query("SELECT 1 FROM permissioned_space_notification_registrations WHERE space_uri = ?", [.text(fixture.space.rawValue)])
            XCTAssertTrue(drained.isEmpty)
            XCTAssertTrue(registrations.isEmpty)
            try await reopened.finishConversationSpaceDeletion(deletion, now: delayed.addingTimeInterval(2))
            let noDuplicate = try await reopened.pendingNotificationFanout()
            XCTAssertTrue(noDuplicate.isEmpty)
            try await reopened.close()
        } catch { try? await reopened.close(); throw error }
    }

    func testFailedPendingBatchRotatesSoLaterGenerationCannotStarve() async throws {
        let fixture = try ConversationAuthorityFixture()
        let database = try await fixture.open()
        do {
            var intents: [ConversationSpaceDeletion] = []
            for index in 0..<257 {
                let space = try SpaceURI(authority: fixture.owner, spaceType: fixture.space.spaceType, skey: UUID().uuidString.lowercased())
                intents.append(try await database.beginConversationSpaceDeletion(space: space,
                    authorization: fixture.ownerAuthorization, now: Date(timeIntervalSince1970: Double(100 + index))))
            }
            let initial = try await database.pendingConversationSpaceDeletions(authority: fixture.owner)
            XCTAssertEqual(initial, Array(intents.prefix(256)))
            for intent in initial {
                try await database.deferConversationSpaceDeletion(intent, now: Date(timeIntervalSince1970: 1000))
            }
            let next = try await database.pendingConversationSpaceDeletions(authority: fixture.owner)
            XCTAssertEqual(next.count, 256)
            XCTAssertEqual(next.first, intents.last, "the generation behind a full failed batch must be attempted next")
            let mismatched = try ConversationSpaceDeletion(space: intents[256].space, eventID: UUID().uuidString.lowercased())
            try await database.deferConversationSpaceDeletion(mismatched, now: Date(timeIntervalSince1970: 2000))
            let unchanged = try await database.pendingConversationSpaceDeletions(authority: fixture.owner)
            XCTAssertEqual(unchanged.first, intents.last, "a stale event cannot reschedule another deletion")
            do {
                try await database.requireConversationSpaceActive(space: intents[0].space)
                XCTFail("retry scheduling must never reopen a generation")
            } catch let error as AuthorizedSimpleSpaceLifecycleError { XCTAssertEqual(error, .deleted) }
            try await database.close()
        } catch { try? await database.close(); throw error }
    }

    func testDeletionOfUnknownGenerationRequiresExactAuthorityOAuthAndCanonicalUUID() async throws {
        let fixture = try ConversationAuthorityFixture()
        let database = try await fixture.open()
        do {
            for authorization in [fixture.credential, AuthorizationContext.accountOAuthForTesting(subject: fixture.writer, scopes: ["atproto"])] {
                do {
                    _ = try await database.beginConversationSpaceDeletion(space: fixture.space, authorization: authorization, now: fixture.now)
                    XCTFail("only the exact authority's OAuth may start lifecycle deletion")
                } catch let error as SwanError { guard case .unauthorized = error else { throw error } }
            }
            let before = try await database.pendingConversationSpaceDeletions(authority: fixture.owner)
            XCTAssertTrue(before.isEmpty)
            let malformed = try SpaceURI(authority: fixture.owner, spaceType: fixture.space.spaceType, skey: "not-a-generation")
            do {
                try await database.registerKnownConversationSpace(space: malformed, now: fixture.now)
                XCTFail("generation must be a canonical UUID")
            } catch let error as SwanError { guard case .unauthorized = error else { throw error } }
            let intent = try await database.beginConversationSpaceDeletion(space: fixture.space, authorization: fixture.ownerAuthorization, now: fixture.now)
            try await database.finishConversationSpaceDeletion(intent, now: fixture.now)
            try await database.close()
        } catch { try? await database.close(); throw error }
    }

    func testRegistrationForeignKeyMigrationPreservesAuthenticatedSimpleSpaceRecipients() async throws {
        let fixture = try ConversationAuthorityFixture()
        let database = try await fixture.open()
        let simple = try SpaceURI(authority: fixture.owner, spaceType: "app.bsky.bookmarks", skey: "existing")
        do {
            _ = try await database.createSimpleSpace(space: simple, owner: fixture.owner, configuration: .init(), authorization: fixture.ownerAuthorization, now: fixture.now)
            // Reconstruct the prior authenticated schema, which excluded all
            // non-simple authority kinds through its foreign key.
            _ = try await database.connection.query("ALTER TABLE permissioned_space_notification_registrations RENAME TO registration_before_fixture")
            _ = try await database.connection.query("""
                CREATE TABLE permissioned_space_notification_registrations (
                    space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
                    endpoint TEXT NOT NULL, repo_did TEXT, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                    owner_service_did TEXT NOT NULL, delivery_service_did TEXT, PRIMARY KEY(space_uri, endpoint))
                """)
            try await database.registerSpaceNotification(.init(space: simple, endpoint: fixture.endpoint, repository: fixture.writer,
                expiresAt: fixture.now.addingTimeInterval(3600), ownerServiceDID: fixture.service, deliveryServiceDID: fixture.service),
                authorization: fixture.credential(for: simple), now: fixture.now)
            try await database.close()
        } catch { try? await database.close(); throw error }
        let reopened = try await fixture.open()
        do {
            let rows = try await reopened.connection.query("SELECT owner_service_did, delivery_service_did, repo_did FROM permissioned_space_notification_registrations WHERE space_uri = ?", [.text(simple.rawValue)])
            XCTAssertEqual(rows.count, 1)
            XCTAssertEqual(rows.first?.column("owner_service_did")?.string, fixture.service)
            XCTAssertEqual(rows.first?.column("delivery_service_did")?.string, fixture.service)
            XCTAssertEqual(rows.first?.column("repo_did")?.string, fixture.writer)
            let foreignKeys = try await reopened.connection.query("PRAGMA foreign_key_list(permissioned_space_notification_registrations)")
            XCTAssertTrue(foreignKeys.isEmpty)
            try await reopened.registerKnownConversationSpace(space: fixture.space, now: fixture.now)
            try await fixture.register(on: reopened, endpoint: fixture.endpoint, repository: nil)
            try await reopened.close()
        } catch { try? await reopened.close(); throw error }
    }
}

private struct ConversationAuthorityFixture {
    let root = FileManager.default.temporaryDirectory.appending(path: "SwanConversationAuthority-\(UUID().uuidString)")
    let owner = "did:plc:alice"
    let writer = "did:plc:bob"
    let endpoint = "https://notify.example/events"
    let service = "did:web:notify.example#atproto_pds"
    let now = Date()
    let space: SpaceURI
    init() throws {
        space = try SpaceURI(authority: owner, spaceType: "blue.catbird.labyrinth.conversation", skey: UUID().uuidString.lowercased())
    }
    var ownerAuthorization: AuthorizationContext { .accountOAuthForTesting(subject: owner, scopes: ["atproto"]) }
    var credential: AuthorizationContext { credential(for: space) }
    func credential(for space: SpaceURI) -> AuthorizationContext {
        .spaceCredential(.init(subject: writer, space: space, permissions: [.read], expiresAt: now.addingTimeInterval(3600)))
    }
    func open() async throws -> SQLiteAccountDatabase { try await SQLiteAccountDatabase(dataDirectory: root, did: owner) }
    func register(on database: SQLiteAccountDatabase, endpoint: String, repository: String?) async throws {
        try await database.registerSpaceNotification(.init(space: space, endpoint: endpoint, repository: repository,
            expiresAt: now.addingTimeInterval(3600), ownerServiceDID: service, deliveryServiceDID: service),
            authorization: credential, now: now)
    }
    func notification() throws -> AuthorizedSpaceWriteNotification {
        let revision = try TID(tidString: "2222222222223").toString()
        let commitment = Data(repeating: 1, count: 32)
        return .init(eventID: "writer-event", space: space, repository: writer, wireRevision: revision,
            commitment: commitment, issuer: writer, audience: owner,
            requestBodyDigest: SpaceNotificationRequestDigest.write(space: space, repository: writer, wireRevision: revision, commitment: commitment))
    }
    func write(on database: SQLiteAccountDatabase) async throws {
        let value = Data([0xa1, 0x61, 0x61, 0x01])
        let uri = try SpaceRecordURI(space: space, author: owner, collection: "app.bsky.feed.post", rkey: "record")
        _ = try await database.apply(space: space, author: owner, expectedRevision: 0, requestID: UUID(),
            wireRevision: TID(tidString: "2222222222222"), writes: [.put(uri: uri, value: value, cid: CID.fromDAGCBOR(value).string)])
    }
}
