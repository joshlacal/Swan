import Crypto
import Foundation
import Petrel
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanSQLite
import SwanStorage
import XCTest
@testable import swan

/// SWAN-SYNC-1: the operator adoption path verifies the presented credential
/// with configured trust material and reopens replication only for a
/// credential the authority issued after the retained deletion.
final class RecreatedSpaceAdoptionTests: XCTestCase {
    private let receiver = "did:plc:receiverabcdefghijkl"
    private let authority = "did:plc:authorityabcdefghijklmno"

    func testAdoptionRequiresVerifiedPostDeletionCredentialAndResyncsFromScratch() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanRecreatedAdoption-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let space = try SpaceURI(authority: authority, spaceType: "com.example.forum", skey: "abc")
        let other = try SpaceURI(authority: authority, spaceType: "com.example.forum", skey: "other")
        let target = try PermissionedRemoteReplicaTarget(
            receiverDID: receiver, space: space, repositoryDID: "did:plc:repositoryabcdefghij"
        )
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: receiver)
        do {
            // Participation through the receiver's own authored repository,
            // the failure scenario in the finding.
            let value = Data([0xA1, 0x61, 0x61, 0x01])
            let uri = try SpaceRecordURI(space: space, author: receiver, collection: "app.bsky.feed.post", rkey: "own")
            _ = try await database.apply(
                space: space, author: receiver, expectedRevision: 0, requestID: UUID(),
                wireRevision: TID(tidString: "2222222222222"),
                writes: [.put(uri: uri, value: value, cid: CID.fromDAGCBOR(value).string)]
            )
            let deletedAt = Date(timeIntervalSince1970: 1_800_000_000)
            try await database.receiveSpaceDeletionNotification(
                space: space, issuer: authority, audience: receiver, eventID: "deletion-1",
                requestBodyDigest: SpaceNotificationRequestDigest.deletion(space: space), now: deletedAt
            )
            let tombstone = try await database.recipientSpaceDeletionTombstone(space)
            XCTAssertEqual(tombstone?.deletionEventID, "deletion-1")
            do {
                _ = try await database.permissionedRemoteReplicaHead(target: target)
                XCTFail("a recipient tombstone must close replicated state before adoption")
            } catch let error as SwanError {
                XCTAssertEqual(error, .unauthorized("permissioned space is closed"))
            }

            let authorityKey = P256.Signing.PrivateKey()
            let publicKeys = try PinnedSpaceCredentialPublicKeyResolver(pins: [
                .init(authority: authority, generation: 1, publicKey: authorityKey.publicKey),
            ])
            let holder = SpaceHTTPSignature.keyID(for: P256.Signing.PrivateKey())
            func credential(
                signedBy signer: P256.Signing.PrivateKey? = nil,
                for selected: SpaceURI? = nil,
                issuedAt: Date
            ) throws -> String {
                let selected = selected ?? space
                return try PermissionedDataJWT.createSpaceCredential(
                    issuer: selected.authority, space: selected, key: signer ?? authorityKey,
                    confirmationKeyID: holder, now: issuedAt
                )
            }
            let now = deletedAt.addingTimeInterval(120)
            let refused: [(String, String, String?)] = [
                ("issued before the deletion", try credential(issuedAt: deletedAt.addingTimeInterval(-30)), nil),
                ("issued in the deletion second", try credential(issuedAt: deletedAt), nil),
                ("signed by an untrusted key", try credential(signedBy: P256.Signing.PrivateKey(), issuedAt: now), nil),
                ("issued for another space", try credential(for: other, issuedAt: now), nil),
                ("naming another deletion", try credential(issuedAt: now), "another-deletion"),
            ]
            for (name, token, event) in refused {
                do {
                    _ = try await RecreatedSpaceAdoption.adopt(
                        credential: token, space: space, deletionEventID: event,
                        database: database, publicKeys: publicKeys, now: now
                    )
                    XCTFail("adoption accepted a credential \(name)")
                } catch let error as SwanError {
                    guard case .unauthorized = error else { throw error }
                }
                let retained = try await database.recipientSpaceDeletionTombstone(space)
                XCTAssertEqual(retained?.deletionEventID, "deletion-1", name)
            }

            let outcome = try await RecreatedSpaceAdoption.adopt(
                credential: try credential(issuedAt: deletedAt.addingTimeInterval(60)),
                space: space, deletionEventID: nil,
                database: database, publicKeys: publicKeys, now: now
            )
            XCTAssertEqual(outcome.deletionEventID, "deletion-1")
            XCTAssertTrue(outcome.adopted)
            let cleared = try await database.recipientSpaceDeletionTombstone(space)
            XCTAssertNil(cleared)
            let head = try await database.permissionedRemoteReplicaHead(target: target)
            XCTAssertNil(head, "adoption resyncs from scratch; it never revives the old projection")
            do {
                _ = try await RecreatedSpaceAdoption.adopt(
                    credential: try credential(issuedAt: deletedAt.addingTimeInterval(90)),
                    space: space, deletionEventID: nil,
                    database: database, publicKeys: publicKeys, now: now
                )
                XCTFail("adoption without a retained deletion was accepted")
            } catch let error as SwanError {
                guard case .unauthorized = error else { throw error }
            }
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }
}
