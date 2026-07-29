import Foundation
import Petrel
import SwanCore
@_spi(PortableRestore) @testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class PermissionedBlobRepositoryReachabilityTests: XCTestCase {
    func testPortableRestoreRejectsSpaceBlobWithoutMatchingRepositoryStateAndLeavesNoReference()
        async throws
    {
        let fixture = try PermissionedBlobReachabilityFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        try await fixture.withDatabase { database in
            let payload = Data("orphaned portable space blob".utf8)
            let cid = CID.fromBlob(payload).string
            var rejected = false

            do {
                _ = try await database.restorePortableBlob(
                    payload,
                    expectedCID: cid,
                    namespace: .space(fixture.space)
                )
            } catch {
                rejected = true
            }

            XCTAssertTrue(
                rejected,
                "portable restore must reject a space blob when the account has no matching repository state"
            )
            let inventory = try await database.portableExportInventory()
            XCTAssertFalse(
                inventory.blobs.contains(
                    BlobReference(cid: cid, namespace: .space(fixture.space))
                ),
                "a rejected portable space blob must not leave a namespace reference"
            )
        }
    }

    func testUploadedSpaceBlobWithoutRepositoryStateIsNotReadable() async throws {
        let fixture = try PermissionedBlobReachabilityFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        try await fixture.withDatabase { database in
            let payload = Data("staged orphaned space blob".utf8)
            let reference = try await database.putBlob(
                payload,
                namespace: .space(fixture.space)
            )

            try await assertPermissionedBlobIsUnreadable(
                database,
                fixture: fixture,
                cid: reference.cid
            )
        }
    }

    func testUploadedSpaceBlobWithActiveRepositoryStateRemainsReadable() async throws {
        let fixture = try PermissionedBlobReachabilityFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        try await fixture.withDatabase { database in
            let recordValue = Data([0xa1, 0x61, 0x61, 0x01])
            let recordCID = CID.fromDAGCBOR(recordValue).string
            _ = try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222222"),
                writes: [
                    .create(
                        uri: fixture.record,
                        value: recordValue,
                        cid: recordCID
                    ),
                ]
            )

            let payload = Data("repository-reachable space blob".utf8)
            let reference = try await database.putBlob(
                payload,
                namespace: .space(fixture.space)
            )
            let maybeAuthorized = try await database.permissionedBlob(
                space: fixture.space,
                author: fixture.author,
                cid: reference.cid
            )
            let authorized = try XCTUnwrap(maybeAuthorized)
            var received = Data()
            try await authorized.body.streamBody(maximumChunkBytes: 7) { chunk in
                received.append(chunk)
            }
            XCTAssertEqual(received, payload)
        }
    }
}

private struct PermissionedBlobReachabilityFixture {
    let root: URL
    let author = "did:plc:alice"
    let space: SpaceURI
    let record: SpaceRecordURI

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "PermissionedBlobReachability-\(UUID().uuidString)")
        space = try SpaceURI(
            authority: author,
            spaceType: "app.bsky.bookmarks",
            skey: "self"
        )
        record = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.bsky.feed.post",
            rkey: "repository-state"
        )
    }

    func withDatabase<T>(
        _ body: (SQLiteAccountDatabase) async throws -> T
    ) async throws -> T {
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: author
        )
        do {
            let result = try await body(database)
            try await database.close()
            return result
        } catch {
            try? await database.close()
            throw error
        }
    }
}

private func assertPermissionedBlobIsUnreadable(
    _ database: SQLiteAccountDatabase,
    fixture: PermissionedBlobReachabilityFixture,
    cid: String,
    file: StaticString = #filePath,
    line: UInt = #line
) async throws {
    do {
        let blob = try await database.permissionedBlob(
            space: fixture.space,
            author: fixture.author,
            cid: cid
        )
        XCTAssertNil(
            blob,
            "a staged space blob must not be readable before its repository exists",
            file: file,
            line: line
        )
    } catch {
        guard case .unauthorized = error as? SwanError else {
            throw error
        }
    }
}
