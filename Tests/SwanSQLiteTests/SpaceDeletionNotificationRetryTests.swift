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
