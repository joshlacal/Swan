import Foundation
import Petrel
import SQLiteNIO
import SwanCore
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class SimpleSpaceDeletionTests: XCTestCase {
    func testDeletionRemovesOnlyAuthorityRepositoryAndRetainsDurableCredentialSignal() async throws {
        let fixture = try DeletionFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let authority = try await fixture.open(fixture.owner)
        let member = try await fixture.open(fixture.member)
        do {
            _ = try await authority.createSimpleSpace(
                space: fixture.space,
                owner: fixture.owner,
                configuration: .init(),
                authorization: fixture.authorization
            )
            try await fixture.write(on: authority, author: fixture.owner, space: fixture.space)
            try await fixture.write(on: authority, author: fixture.owner, space: fixture.otherSpace)
            try await fixture.write(on: member, author: fixture.member, space: fixture.space)

            let exclusive = try await authority.putBlob(
                Data([1, 2, 3]), namespace: .space(fixture.space)
            )
            let sharedBytes = Data([4, 5, 6])
            let shared = try await authority.putBlob(
                sharedBytes, namespace: .space(fixture.space)
            )
            let publicReference = try await authority.putBlob(sharedBytes, namespace: .public)
            let otherReference = try await authority.putBlob(
                sharedBytes, namespace: .space(fixture.otherSpace)
            )

            let deleted = try await authority.deleteSimpleSpace(
                space: fixture.space,
                authorization: fixture.authorization
            )
            XCTAssertTrue(deleted.space.isDeleted)
            do {
                _ = try await authority.repositorySnapshot(
                    space: fixture.space, author: fixture.owner
                )
                XCTFail("deleted authority repository must stay closed")
            } catch let error as SwanError {
                guard case .unauthorized = error else { throw error }
            }
            do {
                try await fixture.write(on: authority, author: fixture.owner, space: fixture.space)
                XCTFail("a late write must not recreate the deleted authority repository")
            } catch let error as SwanError {
                guard case .unauthorized = error else { throw error }
            }
            do {
                _ = try await authority.putBlob(Data([9, 9, 9]), namespace: .space(fixture.space))
                XCTFail("a late blob write must not recreate the deleted space namespace")
            } catch let error as SwanError {
                guard case .unauthorized = error else { throw error }
            }
            let otherSnapshot = try await authority.repositorySnapshot(
                space: fixture.otherSpace, author: fixture.owner
            )
            XCTAssertEqual(otherSnapshot?.records.count, 1)
            let memberSnapshot = try await member.repositorySnapshot(
                space: fixture.space, author: fixture.member
            )
            XCTAssertEqual(memberSnapshot?.records.count, 1)
            // The remote authority cannot close a member's own write surface.
            try await fixture.write(
                on: member, author: fixture.member, space: fixture.space, expectedRevision: 1
            )
            let advancedMember = try await member.repositorySnapshot(
                space: fixture.space, author: fixture.member
            )
            XCTAssertEqual(advancedMember?.state.revision, 2)
            let publicBytes = try await authority.blobData(for: publicReference)
            let otherBytes = try await authority.blobData(for: otherReference)
            XCTAssertEqual(publicBytes, sharedBytes)
            XCTAssertEqual(otherBytes, sharedBytes)

            for table in [
                "permissioned_repository_state", "permissioned_space_records",
                "permissioned_space_record_blobs", "permissioned_space_oplog",
                "permissioned_space_requests", "permissioned_space_outbox",
            ] {
                let rows = try await authority.connection.query(
                    "SELECT 1 FROM \(table) WHERE space_uri = ? AND author_did = ?",
                    [.text(fixture.space.rawValue), .text(fixture.owner)]
                )
                XCTAssertTrue(rows.isEmpty, "authority repository residue in \(table)")
            }
            let spaceEdges = try await authority.connection.query(
                "SELECT 1 FROM blob_namespace_references WHERE namespace_kind = 'space' AND space_uri = ?",
                [.text(fixture.space.rawValue)]
            )
            XCTAssertTrue(spaceEdges.isEmpty)
            let exclusivePayload = try await authority.connection.query(
                "SELECT 1 FROM blob_payloads WHERE cid = ?", [.text(exclusive.cid)]
            )
            XCTAssertTrue(exclusivePayload.isEmpty)
            let sharedPayload = try await authority.connection.query(
                "SELECT 1 FROM blob_payloads WHERE cid = ?", [.text(shared.cid)]
            )
            XCTAssertEqual(sharedPayload.count, 1)
            let reclamation = try await authority.connection.query(
                "SELECT 1 FROM blob_cas_lifecycle WHERE state = 'reclaiming'"
            )
            XCTAssertTrue(reclamation.isEmpty)
            try await assertCredentialFailure(.deleted, database: authority, fixture: fixture)

            // A missing space remains distinct from a durable deletion.
            do {
                try await authority.authorizeSimpleSpaceRead(
                    space: fixture.otherSpace,
                    user: fixture.owner,
                    clientID: nil,
                    authorization: fixture.authorization
                )
                XCTFail("missing authority configuration must not authorize a credential")
            } catch let error as AuthorizedSimpleSpaceLifecycleError {
                XCTAssertEqual(error, .notFound)
            }
            try await member.close()
            try await authority.close()
        } catch {
            try? await member.close()
            try? await authority.close()
            throw error
        }

        let reopened = try await fixture.open(fixture.owner)
        do {
            try await assertCredentialFailure(.deleted, database: reopened, fixture: fixture)
            _ = try await reopened.createSimpleSpace(
                space: fixture.space,
                owner: fixture.owner,
                configuration: .init(),
                authorization: fixture.authorization
            )
            let snapshot = try await reopened.repositorySnapshot(
                space: fixture.space, author: fixture.owner
            )
            XCTAssertNil(snapshot, "recreating a space must not revive its old authority records")
            try await fixture.write(on: reopened, author: fixture.owner, space: fixture.space)
            let freshSnapshot = try await reopened.repositorySnapshot(
                space: fixture.space, author: fixture.owner
            )
            XCTAssertEqual(freshSnapshot?.state.revision, 1)
            try await reopened.close()
        } catch {
            try? await reopened.close()
            throw error
        }
    }

    func testOldTombstonesAreCleanedByRepeatedDeleteAndBeforeRecreation() async throws {
        for repeatDeletion in [true, false] {
            let fixture = try DeletionFixture()
            defer { try? FileManager.default.removeItem(at: fixture.root) }
            let database = try await fixture.open(fixture.owner)
            do {
                _ = try await database.createSimpleSpace(
                    space: fixture.space, owner: fixture.owner,
                    configuration: .init(), authorization: fixture.authorization
                )
                try await fixture.write(on: database, author: fixture.owner, space: fixture.space)
                let reference = try await database.putBlob(Data([7, 8, 9]), namespace: .space(fixture.space))
                _ = try await database.appendOplogAndOutbox(
                    space: fixture.space, revision: 1,
                    operation: Data([1]), commitment: Data(repeating: 0, count: 32)
                )
                _ = try await database.connection.query(
                    "INSERT INTO space_records(space_uri, uri, value, revision) VALUES (?, ?, ?, 1)",
                    [.text(fixture.space.rawValue), .text("legacy-record"), Data([1]).sqliteData!]
                )
                // Model an old-version deletion, which wrote a tombstone but
                // retained repository content and namespace edges.
                _ = try await database.connection.query(
                    "UPDATE permissioned_simple_space_authorities SET is_deleted = 1 WHERE space_uri = ?",
                    [.text(fixture.space.rawValue)]
                )
                if repeatDeletion {
                    _ = try await database.deleteSimpleSpace(
                        space: fixture.space, authorization: fixture.authorization
                    )
                    try await assertCredentialFailure(.deleted, database: database, fixture: fixture)
                    _ = try await database.deleteSimpleSpace(
                        space: fixture.space, authorization: fixture.authorization
                    )
                } else {
                    _ = try await database.createSimpleSpace(
                        space: fixture.space, owner: fixture.owner,
                        configuration: .init(), authorization: fixture.authorization
                    )
                    let snapshot = try await database.repositorySnapshot(
                        space: fixture.space, author: fixture.owner
                    )
                    XCTAssertNil(snapshot)
                }
                let retainedRecords = try await database.connection.query(
                    "SELECT 1 FROM permissioned_space_records WHERE space_uri = ?",
                    [.text(fixture.space.rawValue)]
                )
                let retainedPayload = try await database.connection.query(
                    "SELECT 1 FROM blob_payloads WHERE cid = ?", [.text(reference.cid)]
                )
                XCTAssertTrue(retainedRecords.isEmpty)
                XCTAssertTrue(retainedPayload.isEmpty)
                for table in ["space_records", "space_oplog"] {
                    let legacy = try await database.connection.query(
                        "SELECT 1 FROM \(table) WHERE space_uri = ?",
                        [.text(fixture.space.rawValue)]
                    )
                    XCTAssertTrue(legacy.isEmpty)
                }
                try await database.close()
            } catch {
                try? await database.close()
                throw error
            }
        }
    }

    private func assertCredentialFailure(
        _ expected: AuthorizedSimpleSpaceLifecycleError,
        database: SQLiteAccountDatabase,
        fixture: DeletionFixture
    ) async throws {
        do {
            try await database.authorizeSimpleSpaceRead(
                space: fixture.space,
                user: fixture.owner,
                clientID: nil,
                authorization: fixture.authorization
            )
            XCTFail("deleted space must not mint a credential")
        } catch let error as AuthorizedSimpleSpaceLifecycleError {
            XCTAssertEqual(error, expected)
        }
    }
}

private struct DeletionFixture {
    let root = FileManager.default.temporaryDirectory
        .appending(path: "SwanSimpleSpaceDeletion-\(UUID().uuidString)")
    let owner = "did:plc:alice"
    let member = "did:plc:bob"
    let space: SpaceURI
    let otherSpace: SpaceURI

    init() throws {
        space = try SpaceURI(authority: owner, spaceType: "app.bsky.bookmarks", skey: "deleted")
        otherSpace = try SpaceURI(authority: owner, spaceType: "app.bsky.bookmarks", skey: "retained")
    }

    var authorization: AuthorizationContext {
        .accountOAuthForTesting(subject: owner, scopes: ["atproto"])
    }

    func open(_ did: String) async throws -> SQLiteAccountDatabase {
        try await SQLiteAccountDatabase(dataDirectory: root, did: did)
    }

    func write(
        on database: SQLiteAccountDatabase,
        author: String,
        space: SpaceURI,
        expectedRevision: UInt64 = 0
    ) async throws {
        let value = Data([0xa1, 0x61, 0x61, 0x01])
        let uri = try SpaceRecordURI(
            space: space, author: author, collection: "app.bsky.feed.post", rkey: "record"
        )
        _ = try await database.apply(
            space: space,
            author: author,
            expectedRevision: expectedRevision,
            requestID: UUID(),
            wireRevision: try TID(tidString: expectedRevision == 0 ? "2222222222222" : "2222222222223"),
            writes: [.put(uri: uri, value: value, cid: CID.fromDAGCBOR(value).string)]
        )
    }
}
