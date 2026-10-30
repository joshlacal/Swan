import Crypto
import Foundation
import Petrel
import PetrelCrypto
import SQLiteNIO
import SwanCore
import SwanSpaces
import SwanStorage
import XCTest
@testable import SwanSQLite

/// X2: a Swan authority signs every delivery attempt of a forwarded
/// notifySpaceDeleted with a fresh jti, so a retry reaches Swan's own
/// receiver under a new event ID. The repeat must leave exactly the state the
/// first notice produced, and adoption must still name the first notice.
final class SpaceDeletionNotificationRetryTests: XCTestCase {
    private let receiver = "did:plc:receiverabcdefghijkl"

    func testRepeatedDeletionUnderAFreshEventIDIsIdempotent() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "SwanDeletionRetry-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let space = try SpaceURI("at://did:plc:authorityabcdefghijk/space/app.swan.test/retry")
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: receiver)
        do {
            try await stageReplicaImport(database, space: space)
            for (eventID, time) in [("attempt-1", 110.0), ("attempt-2", 111.0)] {
                try await database.receiveSpaceDeletionNotification(
                    space: space, issuer: space.authority, audience: receiver, eventID: eventID,
                    requestBodyDigest: SpaceNotificationRequestDigest.deletion(space: space),
                    now: Date(timeIntervalSince1970: time)
                )
            }
            let tombstones = try await database.connection.query(
                "SELECT deletion_event_id FROM permissioned_space_recipient_tombstones WHERE space_uri = ?",
                [.text(space.rawValue)]
            )
            XCTAssertEqual(tombstones.map { $0.column("deletion_event_id")?.string }, ["attempt-1"])
            let receipts = try await database.connection.query(
                "SELECT event_id FROM permissioned_space_notification_receipts WHERE space_uri = ?",
                [.text(space.rawValue)]
            )
            XCTAssertEqual(receipts.map { $0.column("event_id")?.string }, ["attempt-1"])
            let sessions = try await database.connection.query(
                "SELECT COUNT(*) AS count FROM permissioned_remote_replica_import_sessions WHERE space_uri = ?",
                [.text(space.rawValue)]
            )
            XCTAssertEqual(sessions.first?.column("count")?.integer, 0)

            try await database.adoptRecreatedRemoteSpace(
                space, expectedDeletionEventID: "attempt-1",
                authorization: .spaceCredential(SpaceGrant(
                    subject: space.authority, space: space, permissions: [.read],
                    expiresAt: Date(timeIntervalSince1970: 300)
                )),
                credentialIssuedAt: Date(timeIntervalSince1970: 112),
                credentialDigest: Data(repeating: 0x5a, count: 32),
                now: Date(timeIntervalSince1970: 120)
            )
            let reopened = try await database.connection.query(
                "SELECT COUNT(*) AS count FROM permissioned_space_recipient_tombstones WHERE space_uri = ?",
                [.text(space.rawValue)]
            )
            XCTAssertEqual(reopened.first?.column("count")?.integer, 0)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    /// SW-A: a repeated notice (here a retry under a fresh jti) finds the
    /// first tombstone. It must keep the notifyWrite row a later write of the
    /// account's own repository queued, and must not rename the retired event.
    func testRepeatedDeletionKeepsOutboxRowsQueuedAfterTheFirstNotice() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "SwanDeletionRepeat-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let space = try SpaceURI("at://did:plc:authorityabcdefghijk/space/app.swan.test/repeat")
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: receiver)
        do {
            try await writeOwnRecord(database, space: space, revision: 1)
            try await deliverDeletion(database, space: space, eventID: "attempt-1", issuedAt: 100, now: 110)
            let afterFirst = try await database.pendingOutbox()
            XCTAssertTrue(afterFirst.filter { $0.space == space }.isEmpty, "the first notice drops the deleted lifecycle's rows")

            try await writeOwnRecord(database, space: space, revision: 2)
            try await deliverDeletion(database, space: space, eventID: "attempt-2", issuedAt: 101, now: 111)
            let afterRepeat = try await database.pendingOutbox()
            XCTAssertEqual(afterRepeat.filter { $0.space == space }.map(\.revision), [2])
            let retained = try await tombstoneEventID(database, space: space)
            XCTAssertEqual(retained, "attempt-1")
            let lifecycle = try await database.connection.query(
                "SELECT retired_event_id FROM permissioned_remote_replica_lifecycles WHERE space_uri = ?",
                [.text(space.rawValue)]
            )
            XCTAssertEqual(lifecycle.first?.column("retired_event_id")?.string, "attempt-1")
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    /// SW-A: after an operator adopts a recreated space, a delayed retry of
    /// the old deletion under a fresh jti must not close it again. The
    /// retry's iat predates the adopting credential's iat, both signed by the
    /// authority. A deletion signed after that credential still closes it.
    func testStaleRetryAfterAdoptionKeepsTheSpaceOpenButANewerDeletionClosesIt() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "SwanDeletionStale-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let space = try SpaceURI("at://did:plc:authorityabcdefghijk/space/app.swan.test/stale")
        let target = try PermissionedRemoteReplicaTarget(
            receiverDID: receiver, space: space, repositoryDID: "did:plc:repositoryabcdefghij"
        )
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: receiver)
        do {
            try await writeOwnRecord(database, space: space, revision: 1)
            try await deliverDeletion(database, space: space, eventID: "deletion-1", issuedAt: 100, now: 110)
            try await adopt(database, space: space, eventID: "deletion-1", credentialIssuedAt: 200, now: 210)
            try await writeOwnRecord(database, space: space, revision: 2)

            try await deliverDeletion(database, space: space, eventID: "late-retry", issuedAt: 150, now: 220)
            let afterStale = try await tombstoneEventID(database, space: space)
            XCTAssertNil(afterStale, "a stale retry re-closed the adopted space")
            let head = try await database.permissionedRemoteReplicaHead(target: target)
            XCTAssertNil(head)
            let outbox = try await database.pendingOutbox()
            XCTAssertEqual(outbox.filter { $0.space == space }.map(\.revision), [2])

            try await deliverDeletion(database, space: space, eventID: "deletion-2", issuedAt: 250, now: 260)
            let afterNewer = try await tombstoneEventID(database, space: space)
            XCTAssertEqual(afterNewer, "deletion-2")
            do {
                _ = try await database.permissionedRemoteReplicaHead(target: target)
                XCTFail("a deletion signed after the adopting credential must close the space")
            } catch let error as SwanError {
                XCTAssertEqual(error, .unauthorized("permissioned space is closed"))
            }
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    /// SW-A: a notice retained while the space is closed may name a newer
    /// deletion than the tombstone's first event. Adoption must then require
    /// a credential issued after that newest notice.
    func testAdoptionRequiresACredentialNewerThanTheNewestDeletionNotice() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "SwanDeletionFence-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let space = try SpaceURI("at://did:plc:authorityabcdefghijk/space/app.swan.test/fence")
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: receiver)
        do {
            try await writeOwnRecord(database, space: space, revision: 1)
            try await deliverDeletion(database, space: space, eventID: "deletion-1", issuedAt: 100, now: 110)
            try await deliverDeletion(database, space: space, eventID: "deletion-2", issuedAt: 300, now: 310)
            do {
                try await adopt(database, space: space, eventID: "deletion-1", credentialIssuedAt: 200, now: 320)
                XCTFail("adopted with a credential older than the newest deletion notice")
            } catch let error as SwanError {
                guard case .unauthorized = error else { throw error }
            }
            let refused = try await tombstoneEventID(database, space: space)
            XCTAssertEqual(refused, "deletion-1")
            try await adopt(database, space: space, eventID: "deletion-1", credentialIssuedAt: 301, now: 320)
            let adopted = try await tombstoneEventID(database, space: space)
            XCTAssertNil(adopted)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    /// Account-schema v28 adds the fence column to a database that predates
    /// it and keeps existing lifecycle rows with no fence.
    func testLifecycleFenceMigrationAddsTheColumnToAnExistingDatabase() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "SwanDeletionFenceMigration-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let space = try SpaceURI("at://did:plc:authorityabcdefghijk/space/app.swan.test/migration")
        let legacy = try await SQLiteAccountDatabase(dataDirectory: root, did: receiver)
        do {
            _ = try await legacy.connection.query(
                "ALTER TABLE permissioned_remote_replica_lifecycles DROP COLUMN authority_fence_at"
            )
            _ = try await legacy.connection.query(
                "DELETE FROM permissioned_repository_migrations WHERE version = ?",
                [.integer(SQLiteAccountDatabase.remoteReplicaLifecycleFenceMigrationVersion)]
            )
            _ = try await legacy.connection.query(
                """
                INSERT INTO permissioned_remote_replica_lifecycles(space_uri, generation_floor, retired_event_id, adopted_at)
                VALUES (?, 3, 'legacy-event', 5)
                """,
                [.text(space.rawValue)]
            )
            try await legacy.close()
        } catch {
            try? await legacy.close()
            throw error
        }
        let upgraded = try await SQLiteAccountDatabase(dataDirectory: root, did: receiver)
        do {
            let rows = try await upgraded.connection.query(
                "SELECT generation_floor, authority_fence_at FROM permissioned_remote_replica_lifecycles WHERE space_uri = ?",
                [.text(space.rawValue)]
            )
            XCTAssertEqual(rows.first?.column("generation_floor")?.integer, 3)
            XCTAssertEqual(rows.first?.column("authority_fence_at")?.isNull, true)
            let marker = try await upgraded.connection.query(
                "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
                [.integer(SQLiteAccountDatabase.remoteReplicaLifecycleFenceMigrationVersion)]
            )
            XCTAssertEqual(marker.count, 1)
            try await upgraded.close()
        } catch {
            try? await upgraded.close()
            throw error
        }
    }

    private func writeOwnRecord(_ database: SQLiteAccountDatabase, space: SpaceURI, revision: UInt64) async throws {
        let value = Data([0xA1, 0x61, 0x61, UInt8(revision)])
        let uri = try SpaceRecordURI(space: space, author: receiver, collection: "app.bsky.feed.post", rkey: "own")
        _ = try await database.apply(
            space: space, author: receiver, expectedRevision: revision - 1, requestID: UUID(),
            wireRevision: try TID(tidString: "222222222222\(revision + 1)"),
            writes: [.put(uri: uri, value: value, cid: CID.fromDAGCBOR(value).string)]
        )
    }

    private func deliverDeletion(
        _ database: SQLiteAccountDatabase, space: SpaceURI, eventID: String,
        issuedAt: TimeInterval, now: TimeInterval
    ) async throws {
        try await database.receiveSpaceDeletionNotification(
            space: space, issuer: space.authority, audience: receiver, eventID: eventID,
            requestBodyDigest: SpaceNotificationRequestDigest.deletion(space: space),
            issuedAt: Date(timeIntervalSince1970: issuedAt),
            now: Date(timeIntervalSince1970: now)
        )
    }

    private func adopt(
        _ database: SQLiteAccountDatabase, space: SpaceURI, eventID: String,
        credentialIssuedAt: TimeInterval, now: TimeInterval
    ) async throws {
        try await database.adoptRecreatedRemoteSpace(
            space, expectedDeletionEventID: eventID,
            authorization: .spaceCredential(SpaceGrant(
                subject: space.authority, space: space, permissions: [.read],
                expiresAt: Date(timeIntervalSince1970: now + 300)
            )),
            credentialIssuedAt: Date(timeIntervalSince1970: credentialIssuedAt),
            credentialDigest: Data(repeating: 0x5a, count: 32),
            now: Date(timeIntervalSince1970: now)
        )
    }

    private func tombstoneEventID(_ database: SQLiteAccountDatabase, space: SpaceURI) async throws -> String? {
        try await database.recipientSpaceDeletionTombstone(space)?.deletionEventID
    }

    /// A staged replica import is enough participation for the receiver to
    /// act on a deletion notice.
    private func stageReplicaImport(_ database: SQLiteAccountDatabase, space: SpaceURI) async throws {
        let target = try PermissionedRemoteReplicaTarget(
            receiverDID: receiver, space: space, repositoryDID: "did:plc:repositoryabcdefghij"
        )
        let binding = try PermissionedRemoteReplicaImportBinding(
            requestID: "retry", requestDigest: Data(SHA256.hash(data: Data("retry".utf8))),
            source: PermissionedRemoteReplicaSourceIdentity(
                origin: URL(string: "https://writer.example")!, repositoryDID: target.repositoryDID,
                verifierIdentity: "key-sha256:" + String(repeating: "a", count: 64)
            ),
            target: target, expectedBase: nil,
            freshnessWitness: PermissionedRemoteReplicaFreshnessWitness(
                wireRevision: try TID(tidString: "222222222222a"), commitment: LtHash().commitment
            ),
            profileID: "permissioned-data-0016-2026-10-22"
        )
        let outcome = try await database.createPermissionedRemoteReplicaImportSession(
            binding: binding, createdAt: 100, expiresAt: 200, now: 101
        )
        guard case .staged = outcome else { throw SwanError.malformed("unexpected staged import outcome") }
    }
}
