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
            let hosted = try await database.hostedSpaces(spaceType: fixture.space.spaceType, authority: fixture.owner, cursor: nil, limit: 100)
            XCTAssertEqual(hosted.map(\.space), [fixture.space])
            let write = try fixture.notification()
            do {
                try await database.receiveSpaceWriteNotification(write, now: fixture.now)
                XCTFail("ordinary notification path must not bypass the live membership boundary")
            } catch let error as SwanError { guard case .unauthorized = error else { throw error } }
            try await database.receiveMembershipVerifiedConversationSpaceWriteNotification(write, now: fixture.now)
            let writers = try await database.spaceWriters(space: fixture.space, limit: 10, cursor: nil, authorization: fixture.credential)
            XCTAssertEqual(writers.map(\.repository), [fixture.writer])
            let pendingLease = try await database.leaseNextSpaceSyncNotification(
                now: fixture.now,
                leaseDuration: 60
            )
            let leased = try XCTUnwrap(pendingLease)
            XCTAssertEqual(leased.event.kind, .repoWrite)
            let deletion = try await database.beginConversationSpaceDeletion(space: fixture.space, authorization: fixture.ownerAuthorization, now: fixture.now)
            let repeated = try await database.beginConversationSpaceDeletion(space: fixture.space, authorization: fixture.ownerAuthorization, now: fixture.now)
            XCTAssertEqual(deletion, repeated)
            let queued = try await database.pendingSpaceSyncNotifications()
            XCTAssertTrue(queued.isEmpty, "beginning deletion must not publish a deletion before DS confirmation")
            let registrations = try await database.connection.query(
                "SELECT 1 FROM permissioned_space_sync_registrations WHERE space_uri = ?",
                [.text(fixture.space.rawValue)]
            )
            XCTAssertEqual(registrations.count, 1, "the registration is retained until DS confirms deletion")
            let acknowledged = try await database.completeSpaceSyncNotificationLease(eventID: leased.event.id, token: leased.token)
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
            let visibleAfterBegin = try await database.hostedSpaces(spaceType: fixture.space.spaceType, authority: fixture.owner, cursor: nil, limit: 100)
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
            let fanout = try await reopened.pendingSpaceSyncNotifications()
            XCTAssertEqual(fanout.count, 2)
            XCTAssertTrue(fanout.allSatisfy { $0.kind == .spaceDeleted })
            XCTAssertEqual(
                Set(fanout.map(\.token)),
                Set([
                    fixture.token(for: fixture.endpoint),
                    fixture.token(for: "https://second.example/events"),
                ])
            )
            let records = try await reopened.connection.query("SELECT 1 FROM permissioned_space_records WHERE space_uri = ?", [.text(fixture.space.rawValue)])
            XCTAssertTrue(records.isEmpty)
            for _ in 0 ..< 2 {
                let pendingLease = try await reopened.leaseNextSpaceSyncNotification(now: fixture.now, leaseDuration: 60)
                let leased = try XCTUnwrap(pendingLease)
                let completed = try await reopened.completeSpaceSyncNotificationLease(eventID: leased.event.id, token: leased.token)
                XCTAssertTrue(completed, "SQLite sync UUID spelling must round-trip through its lease")
            }
            try await reopened.finishConversationSpaceDeletion(deletion, now: fixture.now)
            let drained = try await reopened.pendingSpaceSyncNotifications()
            let registrations = try await reopened.connection.query("SELECT 1 FROM permissioned_space_sync_registrations WHERE space_uri = ?", [.text(fixture.space.rawValue)])
            XCTAssertTrue(drained.isEmpty, "repeated completion cannot create another deletion delivery")
            XCTAssertTrue(registrations.isEmpty)
            do {
                try await reopened.registerKnownConversationSpace(space: fixture.space, now: fixture.now)
                XCTFail("a deleted immutable generation must never reopen")
            } catch let error as AuthorizedSimpleSpaceLifecycleError { XCTAssertEqual(error, .deleted) }
            try await reopened.close()
        } catch { try? await reopened.close(); throw error }
    }

    /// Nov-12 sync registrations survive a delivery-service outage and
    /// restart while deletion is pending. DS confirmation then replaces all
    /// work with one reliable terminal notice for each active or lapsed token.
    func testRegistrationsSurviveRestartUntilDeletionConfirmationThenDrain() async throws {
        let fixture = try ConversationAuthorityFixture()
        let start = Date(timeIntervalSince1970: 100)
        let delayed = Date(timeIntervalSince1970: 200)
        let database = try await fixture.open()
        let deletion: ConversationSpaceDeletion
        do {
            try await database.registerKnownConversationSpace(
                space: fixture.space,
                now: Date(timeIntervalSince1970: 98)
            )
            for (endpoint, token, expiresAt) in [
                (fixture.endpoint, "active-token", Date(timeIntervalSince1970: 300)),
                ("https://second.example/events", "second-token", Date(timeIntervalSince1970: 300)),
                ("https://expired.example/events", "lapsed-token", Date(timeIntervalSince1970: 99)),
            ] {
                try await database.putSpaceSyncRegistration(
                    .init(
                        space: fixture.space,
                        endpoint: endpoint,
                        token: token,
                        expiresAt: expiresAt
                    )
                )
            }
            deletion = try await database.beginConversationSpaceDeletion(
                space: fixture.space,
                authorization: fixture.ownerAuthorization,
                now: start
            )
            let registered = try await database.connection.query(
                "SELECT 1 FROM permissioned_space_sync_registrations WHERE space_uri = ?",
                [.text(fixture.space.rawValue)]
            )
            XCTAssertEqual(registered.count, 3)
            try await database.deferConversationSpaceDeletion(
                deletion,
                now: Date(timeIntervalSince1970: 150)
            )
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }

        let reopened = try await fixture.open()
        do {
            let pendingDeletions = try await reopened.pendingConversationSpaceDeletions(
                authority: fixture.owner
            )
            XCTAssertEqual(pendingDeletions, [deletion])
            try await reopened.finishConversationSpaceDeletion(deletion, now: delayed)
            let fanout = try await reopened.pendingSpaceSyncNotifications()
            XCTAssertEqual(fanout.count, 3)
            XCTAssertTrue(fanout.allSatisfy { $0.kind == .spaceDeleted })
            XCTAssertEqual(
                Set(fanout.map(\.token)),
                ["active-token", "second-token", "lapsed-token"]
            )
            let registrations = try await reopened.connection.query(
                "SELECT 1 FROM permissioned_space_sync_registrations WHERE space_uri = ?",
                [.text(fixture.space.rawValue)]
            )
            XCTAssertTrue(registrations.isEmpty)
            var delivered = 0
            while let lease = try await reopened.leaseNextSpaceSyncNotification(
                now: delayed,
                leaseDuration: 30
            ) {
                let completed = try await reopened.completeSpaceSyncNotificationLease(
                    eventID: lease.event.id,
                    token: lease.token
                )
                XCTAssertTrue(completed)
                delivered += 1
            }
            XCTAssertEqual(delivered, 3)
            try await reopened.finishConversationSpaceDeletion(
                deletion,
                now: delayed.addingTimeInterval(2)
            )
            let remaining = try await reopened.pendingSpaceSyncNotifications()
            XCTAssertTrue(remaining.isEmpty)
            try await reopened.close()
        } catch {
            try? await reopened.close()
            throw error
        }
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

}

private struct ConversationAuthorityFixture {
    let root = FileManager.default.temporaryDirectory.appending(path: "SwanConversationAuthority-\(UUID().uuidString)")
    let owner = "did:plc:alice"
    let writer = "did:plc:bob"
    let endpoint = "https://notify.example/events"
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
    func token(for endpoint: String) -> String {
        URL(string: endpoint)?.host ?? endpoint
    }
    func register(
        on database: SQLiteAccountDatabase,
        endpoint: String,
        repository _: String?
    ) async throws {
        try await database.putSpaceSyncRegistration(
            .init(
                space: space,
                endpoint: endpoint,
                token: token(for: endpoint),
                expiresAt: now.addingTimeInterval(3_600)
            )
        )
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
