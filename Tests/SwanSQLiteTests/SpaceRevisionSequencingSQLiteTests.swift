import Foundation
import Petrel
import SQLiteNIO
import SwanCore
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

/// atproto#5574 space-host sequencing: the space host alone assigns a
/// strictly increasing `spaceRev` to each accepted writer update, forwards it
/// with the preceding one, and pages `listRepos` by it.
final class SpaceRevisionSequencingSQLiteTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_790_000_000)

    func testAcceptedWritesAllocateIncreasingRevisionsAndChainForwards() async throws {
        let fixture = try SequencingFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close(); fixture.cleanup() } }
        try await fixture.createSpace(on: database)
        try await fixture.registerService(on: database, now: now)

        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.bob, event: "b1", revision: 1), now: now
        )
        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.dan, event: "d1", revision: 1), now: now
        )
        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.bob, event: "b2", revision: 2), now: now
        )

        let listed = try await fixture.list(database)
        XCTAssertEqual(listed.map(\.repository), [fixture.dan, fixture.bob])
        XCTAssertEqual(listed.map(\.wireRevision), [try fixture.tid(1), try fixture.tid(2)])

        // One forward per accepted update, chained: the first omits
        // prevSpaceRev and each later one names its predecessor.
        let forwards = try await database.pendingNotificationFanout()
            .sorted { ($0.spaceRevision ?? "") < ($1.spaceRevision ?? "") }
        XCTAssertEqual(forwards.count, 3)
        let revisions = forwards.compactMap(\.spaceRevision)
        XCTAssertEqual(revisions.count, 3)
        XCTAssertEqual(revisions, revisions.sorted())
        XCTAssertEqual(Set(revisions).count, 3, "space revisions are strictly increasing")
        XCTAssertNil(forwards[0].previousSpaceRevision)
        XCTAssertEqual(forwards[1].previousSpaceRevision, revisions[0])
        XCTAssertEqual(forwards[2].previousSpaceRevision, revisions[1])
        XCTAssertEqual(forwards.map(\.repository), [fixture.bob, fixture.dan, fixture.bob])
        // The listing's last entry is the newest accepted update.
        XCTAssertEqual(listed.last?.spaceRevision, revisions[2])
        XCTAssertEqual(listed.first?.spaceRevision, revisions[1])
        for revision in revisions {
            XCTAssertNoThrow(try TID(tidString: revision))
        }
    }

    func testDuplicateAndOlderRevisionsAreIgnoredWithoutResequencingOrForwarding() async throws {
        let fixture = try SequencingFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close(); fixture.cleanup() } }
        try await fixture.createSpace(on: database)
        try await fixture.registerService(on: database, now: now)
        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.bob, event: "b1", revision: 1), now: now
        )
        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.bob, event: "b2", revision: 2), now: now
        )
        let before = try await fixture.list(database)
        let forwardsBefore = try await database.pendingNotificationFanout().count

        // An older revision and the same revision under a fresh event ID.
        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.bob, event: "b1-late", revision: 1), now: now
        )
        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.bob, event: "b2-again", revision: 2), now: now
        )
        let after = try await fixture.list(database)
        XCTAssertEqual(after, before, "no new space revision for a repoRev <= the last accepted")
        let forwardsAfter = try await database.pendingNotificationFanout().count
        XCTAssertEqual(forwardsAfter, forwardsBefore, "ignored updates are never forwarded")
    }

    func testFutureRepoRevisionIsRefusedWhileSmallClockSkewIsAccepted() async throws {
        let fixture = try SequencingFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close(); fixture.cleanup() } }
        try await fixture.createSpace(on: database)

        let tenMinutes = SpaceRevisionSequence.string(
            SpaceRevisionSequence.value(at: now.addingTimeInterval(600))
        )
        do {
            try await database.receiveSpaceWriteNotification(
                fixture.write(fixture.bob, event: "future", wireRevision: tenMinutes), now: now
            )
            XCTFail("a repoRev ten minutes ahead must be FutureRev")
        } catch let error as AuthorizedSpaceWriteNotificationError {
            XCTAssertEqual(error, .futureRevision)
        }
        let afterFuture = try await fixture.list(database)
        XCTAssertTrue(afterFuture.isEmpty, "a refused update records nothing")

        // Positive control: one minute ahead is inside the allowance.
        let oneMinute = SpaceRevisionSequence.string(
            SpaceRevisionSequence.value(at: now.addingTimeInterval(60))
        )
        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.bob, event: "near", wireRevision: oneMinute), now: now
        )
        let accepted = try await fixture.list(database)
        XCTAssertEqual(accepted.map(\.repository), [fixture.bob])
    }

    func testUnknownAndDeletedSpacesAreSpaceNotFound() async throws {
        let fixture = try SequencingFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close(); fixture.cleanup() } }
        do {
            try await database.receiveSpaceWriteNotification(
                fixture.write(fixture.bob, event: "unknown", revision: 1), now: now
            )
            XCTFail("an unknown space must be SpaceNotFound")
        } catch let error as AuthorizedSimpleSpaceLifecycleError {
            XCTAssertEqual(error, .notFound)
        }
        try await fixture.createSpace(on: database)
        _ = try await DurableSimpleSpaceAuthority(lifecycleDatabase: database).delete(
            space: fixture.space,
            authorization: fixture.ownerAuthorization
        )
        do {
            try await database.receiveSpaceWriteNotification(
                fixture.write(fixture.bob, event: "deleted", revision: 1), now: now
            )
            XCTFail("a deleted space must be SpaceNotFound")
        } catch let error as AuthorizedSimpleSpaceLifecycleError {
            XCTAssertEqual(error, .notFound)
        }
    }

    /// The reference's catch-up scenario: an exclusive checkpoint, short
    /// pages that still return a cursor, a repo that reappears because it was
    /// updated mid-listing, and an empty page at the end.
    func testPaginationIsExclusiveAndAnUpdatedRepoReappears() async throws {
        let fixture = try SequencingFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close(); fixture.cleanup() } }
        try await fixture.createSpace(on: database)
        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.bob, event: "b1", revision: 1), now: now
        )
        let initial = try await fixture.list(database)
        let checkpoint = try XCTUnwrap(initial.last?.spaceRevision)
        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.dan, event: "d1", revision: 1), now: now
        )
        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.bob, event: "b2", revision: 2), now: now
        )

        let first = try await fixture.list(database, cursor: checkpoint, limit: 1)
        XCTAssertEqual(first.map(\.repository), [fixture.dan])
        // Dan moves forward while the caller paginates.
        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.dan, event: "d2", revision: 2), now: now
        )
        let second = try await fixture.list(database, cursor: first.last?.spaceRevision, limit: 1)
        XCTAssertEqual(second.map(\.repository), [fixture.bob])
        let third = try await fixture.list(database, cursor: second.last?.spaceRevision, limit: 1)
        XCTAssertEqual(third.map(\.repository), [fixture.dan], "an updated repo reappears")
        XCTAssertEqual(third.first?.wireRevision, try fixture.tid(2))
        let caughtUp = try await fixture.list(database, cursor: third.last?.spaceRevision)
        XCTAssertTrue(caughtUp.isEmpty)
    }

    func testCursorsAreOpaqueStringsAndLegacyDIDCursorsRelistFromTheStart() async throws {
        let fixture = try SequencingFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close(); fixture.cleanup() } }
        try await fixture.createSpace(on: database)
        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.bob, event: "b1", revision: 1), now: now
        )
        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.dan, event: "d1", revision: 1), now: now
        )
        // As in the reference: any string compares lexically.
        let fromZero = try await fixture.list(database, cursor: "0")
        XCTAssertEqual(fromZero.count, 2)
        let pastEnd = try await fixture.list(database, cursor: "not-a-tid")
        XCTAssertTrue(pastEnd.isEmpty)
        // Swan's pre-5574 listing returned writer DIDs as cursors. Compared
        // lexically they would end the listing early; they re-list instead.
        let legacy = try await fixture.list(database, cursor: fixture.bob)
        XCTAssertEqual(legacy.map(\.repository), [fixture.bob, fixture.dan])
        let empty = try await fixture.list(database, cursor: "")
        XCTAssertEqual(empty.count, 2)
    }

    func testRemovalIsSequencedRetainedAndReaddedByANewerWrite() async throws {
        let fixture = try SequencingFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close(); fixture.cleanup() } }
        try await fixture.createSpace(on: database)
        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.bob, event: "b1", revision: 1), now: now
        )
        let writtenRows = try await fixture.list(database)
        let written = try XCTUnwrap(writtenRows.first)

        try await database.removeSpaceWriter(
            space: fixture.space,
            writer: fixture.bob,
            authorization: fixture.ownerAuthorization
        )
        let removedRows = try await fixture.list(database)
        let removed = try XCTUnwrap(removedRows.first)
        XCTAssertTrue(removed.isRemoved)
        XCTAssertEqual(removed.repository, fixture.bob)
        XCTAssertGreaterThan(try XCTUnwrap(removed.spaceRevision), try XCTUnwrap(written.spaceRevision))
        let exported = try await database.exportSpaceMeta(
            space: fixture.space,
            authorization: fixture.ownerAuthorization
        )
        XCTAssertTrue(exported.writers.isEmpty, "space-meta never exports writer tombstones")

        try await database.removeSpaceWriter(
            space: fixture.space,
            writer: fixture.bob,
            authorization: fixture.ownerAuthorization
        )
        let afterDuplicateRemoval = try await fixture.list(database)
        XCTAssertEqual(afterDuplicateRemoval, [removed], "removal is idempotent")

        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.bob, event: "b2", revision: 2), now: now
        )
        let readdedRows = try await fixture.list(database)
        let readded = try XCTUnwrap(readdedRows.first)
        XCTAssertFalse(readded.isRemoved)
        XCTAssertEqual(readded.wireRevision, try fixture.tid(2))
        XCTAssertGreaterThan(try XCTUnwrap(readded.spaceRevision), try XCTUnwrap(removed.spaceRevision))
    }

    func testLocalAuthorityWriteIsSequencedAndItsSelfNotificationIsIgnored() async throws {
        let fixture = try SequencingFixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close(); fixture.cleanup() } }
        try await fixture.createSpace(on: database)
        try await fixture.registerService(on: database, now: Date())
        let commit = try await fixture.applyAsAuthority(on: database, revision: 1)

        let listed = try await fixture.list(database)
        XCTAssertEqual(listed.map(\.repository), [fixture.authority])
        let forwards = try await database.pendingNotificationFanout()
        XCTAssertEqual(forwards.count, 1)
        XCTAssertEqual(forwards.first?.spaceRevision, listed.first?.spaceRevision)
        XCTAssertNil(forwards.first?.previousSpaceRevision)

        // The outbox later announces the same commit to this authority.
        let selfAnnouncement = AuthorizedSpaceWriteNotification(
            eventID: "self-announcement",
            space: fixture.space,
            repository: fixture.authority,
            wireRevision: try fixture.tid(1),
            commitment: commit.state.commitment,
            issuer: fixture.authority,
            audience: fixture.authority,
            requestBodyDigest: SpaceNotificationRequestDigest.write(
                space: fixture.space,
                repository: fixture.authority,
                wireRevision: try fixture.tid(1),
                commitment: commit.state.commitment
            )
        )
        try await database.receiveSpaceWriteNotification(selfAnnouncement)
        let afterSelf = try await fixture.list(database)
        XCTAssertEqual(afterSelf, listed)
        let forwardsAfterSelf = try await database.pendingNotificationFanout()
        XCTAssertEqual(forwardsAfterSelf.count, 1)
    }

    /// v24 backfills writer rows recorded before space revisions existed:
    /// `(repoRev, did)` order, repoRev reused when it keeps the sequence
    /// strictly increasing, predecessor + 1 otherwise, far-future repoRevs
    /// clamped to the FutureRev horizon.
    func testMigrationBackfillsLegacyWriterRowsDeterministically() async throws {
        let fixture = try SequencingFixture()
        let database = try await fixture.open()
        try await fixture.createSpace(on: database)
        try await database.close()

        let path = SQLiteLayout.accountDatabase(in: fixture.root, did: fixture.authority).path
        let legacy = try await SQLiteConnection.open(storage: .file(path: path))
        _ = try await legacy.query("DROP INDEX permissioned_space_writers_space_rev")
        _ = try await legacy.query("ALTER TABLE permissioned_space_writers DROP COLUMN space_rev")
        _ = try await legacy.query(
            "DELETE FROM permissioned_repository_migrations WHERE version = 24"
        )
        let farFuture = "7zzzzzzzzzzzz"
        for (did, revision) in [
            (fixture.bob, try fixture.tid(5)),
            (fixture.dan, try fixture.tid(5)),
            (fixture.carol, try fixture.tid(3)),
            ("did:plc:eve", farFuture),
        ] {
            _ = try await legacy.query(
                """
                INSERT INTO permissioned_space_writers
                    (space_uri, repo_did, wire_revision, commitment, updated_at)
                VALUES (?, ?, ?, ?, 1)
                """,
                [
                    .text(fixture.space.rawValue), .text(did), .text(revision),
                    .blob(ByteBuffer(data: Data(repeating: 0x42, count: 32))),
                ]
            )
        }
        try await legacy.close()

        let migrationTime = Date()
        let reopened = try await fixture.open()
        defer { Task { try? await reopened.close(); fixture.cleanup() } }
        let listed = try await fixture.list(reopened)
        XCTAssertEqual(listed.map(\.repository), [fixture.carol, fixture.bob, fixture.dan, "did:plc:eve"])
        XCTAssertEqual(listed[0].spaceRevision, try fixture.tid(3))
        XCTAssertEqual(listed[1].spaceRevision, try fixture.tid(5))
        XCTAssertEqual(listed[2].spaceRevision, try fixture.tid(6), "a collision takes predecessor + 1")
        let clamped = try XCTUnwrap(listed[3].spaceRevision.flatMap(SpaceRevisionSequence.value(of:)))
        XCTAssertLessThan(clamped, try XCTUnwrap(SpaceRevisionSequence.value(of: farFuture)))
        XCTAssertGreaterThanOrEqual(
            clamped,
            SpaceRevisionSequence.value(at: migrationTime.addingTimeInterval(299))
        )

        let markers = try await reopened.connection.query(
            "SELECT version FROM permissioned_repository_migrations WHERE version = 24"
        )
        XCTAssertEqual(markers.count, 1)
        let index = try await reopened.connection.query(
            "SELECT \"unique\" FROM pragma_index_list('permissioned_space_writers') WHERE name = 'permissioned_space_writers_space_rev'"
        )
        XCTAssertEqual(index.first?.column("unique")?.integer, 1)

        // The next accepted update sorts after every backfilled revision.
        try await reopened.receiveSpaceWriteNotification(
            fixture.write(fixture.carol, event: "c-next", revision: 4), now: now
        )
        let after = try await fixture.list(reopened)
        XCTAssertEqual(after.last?.repository, fixture.carol)
        let newest = try XCTUnwrap(after.last?.spaceRevision.flatMap(SpaceRevisionSequence.value(of:)))
        XCTAssertGreaterThan(newest, clamped)
    }

    func testV29FixtureMigratesToV30WithoutRetargetingForeignKeys() async throws {
        let fixture = try SequencingFixture()
        let database = try await fixture.open()
        try await fixture.createSpace(on: database)
        try await database.receiveSpaceWriteNotification(
            fixture.write(fixture.bob, event: "v29-writer", revision: 1), now: now
        )
        try await database.close()

        let path = SQLiteLayout.accountDatabase(in: fixture.root, did: fixture.authority).path
        let v29 = try await SQLiteConnection.open(storage: .file(path: path))
        do {
            _ = try await v29.query(
                """
                INSERT INTO permissioned_space_notification_registrations(
                    space_uri, service_key, endpoint, repo_did, expires_at, updated_at,
                    owner_service_did, delivery_service_did
                ) VALUES (?, ?, ?, NULL, ?, ?, ?, NULL)
                """,
                [
                    .text(fixture.space.rawValue),
                    .text("endpoint:https://retired.example"),
                    .text("https://retired.example"),
                    .integer(2_000_000),
                    .integer(1_000_000),
                    .text(fixture.authority),
                ]
            )
            _ = try await v29.query(
                "DELETE FROM permissioned_repository_migrations WHERE version = 30"
            )
            _ = try await v29.query(
                "ALTER TABLE permissioned_space_writers DROP COLUMN removed_at"
            )
            _ = try await v29.query(
                "DROP TABLE permissioned_space_sync_registrations"
            )
            try await v29.close()
        } catch {
            try? await v29.close()
            throw error
        }

        let reopened = try await fixture.open()
        defer { Task { try? await reopened.close(); fixture.cleanup() } }
        let columns = try await reopened.connection.query(
            "PRAGMA table_info(permissioned_space_writers)"
        )
        XCTAssertTrue(columns.contains { $0.column("name")?.string == "removed_at" })
        let listed = try await fixture.list(reopened)
        XCTAssertEqual(listed.map(\.isRemoved), [false])
        let markers = try await reopened.connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = 30"
        )
        XCTAssertEqual(markers.count, 1)
        let registrationColumns = try await reopened.connection.query(
            "PRAGMA table_info(permissioned_space_sync_registrations)"
        )
        XCTAssertEqual(
            Set(registrationColumns.compactMap { $0.column("name")?.string }),
            ["space_uri", "endpoint", "token", "expires_at", "expiry_notified", "updated_at"]
        )
        let retiredRows = try await reopened.connection.query(
            "SELECT 1 FROM permissioned_space_notification_registrations"
        )
        XCTAssertTrue(retiredRows.isEmpty)
        let integrity = try await reopened.connection.query("PRAGMA integrity_check")
        XCTAssertEqual(integrity.first?.column("integrity_check")?.string, "ok")
        let foreignKeyViolations = try await reopened.connection.query(
            "PRAGMA foreign_key_check"
        )
        XCTAssertTrue(foreignKeyViolations.isEmpty)
    }

    func testRevisionArithmeticRoundTripsAndNeverGoesBackwards() throws {
        let tid = "3l72c4e2y2222"
        let value = try XCTUnwrap(SpaceRevisionSequence.value(of: tid))
        XCTAssertEqual(SpaceRevisionSequence.string(value), tid)
        XCTAssertNil(SpaceRevisionSequence.value(of: "did:plc:bob"))
        XCTAssertNil(SpaceRevisionSequence.value(of: "jzzzzzzzzzzzz"), "outside Petrel's TID range")
        XCTAssertNil(SpaceRevisionSequence.value(of: "k222222222222"), "a high leading digit must not wrap")
        XCTAssertEqual(SpaceRevisionSequence.value(of: "7zzzzzzzzzzzz"), SpaceRevisionSequence.maximumValue)
        // A stored revision ahead of the clock still advances by one.
        let ahead = SpaceRevisionSequence.string(SpaceRevisionSequence.value(at: now) + 5_000)
        let next = try SpaceRevisionSequence.next(after: ahead, now: now)
        XCTAssertEqual(SpaceRevisionSequence.value(of: next), SpaceRevisionSequence.value(of: ahead)! + 1)
        // Otherwise the clock decides.
        let fromClock = try SpaceRevisionSequence.next(after: tid, now: now)
        XCTAssertEqual(SpaceRevisionSequence.value(of: fromClock), SpaceRevisionSequence.value(at: now))
        XCTAssertNoThrow(try TID(tidString: fromClock))
    }
}

private struct SequencingFixture {
    let root: URL
    let authority = "did:plc:alice"
    let bob = "did:plc:bob"
    let dan = "did:plc:dan"
    let carol = "did:plc:carol"
    let space: SpaceURI

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSpaceRevisionTests-\(UUID().uuidString)")
        space = try SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "sequencing")
    }

    var ownerAuthorization: AuthorizationContext {
        .accountOAuthForTesting(subject: authority, scopes: ["atproto"])
    }

    func open() async throws -> SQLiteAccountDatabase {
        try await SQLiteAccountDatabase(dataDirectory: root, did: authority)
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }

    func createSpace(on database: SQLiteAccountDatabase) async throws {
        let lifecycle = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
        _ = try await lifecycle.create(
            space: space,
            owner: authority,
            configuration: try SimpleSpaceConfiguration(
                readPolicy: .memberList, writePolicy: .memberList, appAccess: .open
            ),
            authorization: ownerAuthorization
        )
        _ = try await lifecycle.putMembers(
            space: space,
            members: [bob, dan, carol].map { .init(did: $0, read: true, write: true) },
            authorization: ownerAuthorization
        )
    }

    func registerService(on database: SQLiteAccountDatabase, now: Date) async throws {
        try await database.registerSpaceNotification(
            .init(
                space: space,
                endpoint: "https://syncer.example",
                repository: nil,
                expiresAt: now.addingTimeInterval(3_600),
                service: "did:web:syncer.example#atproto_space_syncer"
            ),
            serviceDID: "did:web:syncer.example",
            authorization: readCredential,
            now: now
        )
    }

    var readCredential: AuthorizationContext {
        .spaceCredential(.init(
            subject: "did:plc:reader",
            space: space,
            permissions: [.read],
            expiresAt: Date(timeIntervalSinceNow: 3_600)
        ))
    }

    func list(
        _ database: SQLiteAccountDatabase,
        cursor: String? = nil,
        limit: Int = 100
    ) async throws -> [AuthorizedSpaceWriter] {
        try await database.spaceWriters(
            space: space, limit: limit, cursor: cursor, authorization: readCredential
        )
    }

    func write(_ repository: String, event: String, revision: Int) throws -> AuthorizedSpaceWriteNotification {
        write(repository, event: event, wireRevision: try tid(revision))
    }

    func write(_ repository: String, event: String, wireRevision: String) -> AuthorizedSpaceWriteNotification {
        let commitment = Data(repeating: UInt8(truncatingIfNeeded: wireRevision.hashValue), count: 32)
        return AuthorizedSpaceWriteNotification(
            eventID: event,
            space: space,
            repository: repository,
            wireRevision: wireRevision,
            commitment: commitment,
            issuer: repository,
            audience: authority,
            requestBodyDigest: SpaceNotificationRequestDigest.write(
                space: space,
                repository: repository,
                wireRevision: wireRevision,
                commitment: commitment
            )
        )
    }

    func tid(_ offset: Int) throws -> String {
        let alphabet = Array("234567abcdefghijklmnopqrstuvwxyz")
        return try TID(tidString: "222222222222\(alphabet[offset])").toString()
    }

    @discardableResult
    func applyAsAuthority(
        on database: SQLiteAccountDatabase,
        revision: Int
    ) async throws -> PersistedRepositoryCommit {
        let uri = try SpaceRecordURI(
            space: space, author: authority, collection: "app.bsky.feed.post", rkey: "local"
        )
        let value = Data([0xA1, 0x61, 0x61, 0x01])
        return try await database.apply(
            space: space,
            author: authority,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try TID(tidString: try tid(revision)),
            writes: [.put(uri: uri, value: value, cid: CID.fromDAGCBOR(value).string)]
        )
    }
}
