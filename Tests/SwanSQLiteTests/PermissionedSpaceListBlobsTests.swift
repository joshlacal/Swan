import Foundation
import Crypto
import Petrel
import SQLiteNIO
import SwanCore
@testable import SwanSQLite
import PetrelRepo
import SwanSpaces
import SwanStorage
import XCTest

/// `com.atproto.space.listBlobs` (live lexicon at bddc99fb): the distinct blob
/// CIDs an account's records reference within one space, ascending, with a
/// `since` filter on the referencing record's last-write TID and a last-CID
/// cursor. Pins the durable record→blob edge index the write path maintains,
/// and the one-shot backfill for pre-index databases.
final class PermissionedSpaceListBlobsTests: XCTestCase {
    private let author = "did:plc:alice"

    func testWritePathMaintainsEdgeIndexAndPageObeysSinceCursorAndDelete() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "PermissionedSpaceListBlobs-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let space = try SpaceURI(authority: author, spaceType: "app.bsky.bookmarks", skey: "self")
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: author)
        do {
            let payloads = (1 ... 3).map { Data("blob-\($0)".utf8) }
            var cids: [CID] = []
            for payload in payloads {
                let reference = try await database.putBlob(payload, namespace: .public, mimeType: "application/octet-stream")
                cids.append(try CID.parse(reference.cid))
            }
            let sorted = cids.map(\.string).sorted()

            // Record A references blobs 0 and 1 at rev …2; record B references
            // blob 1 (shared) and blob 2 at rev …3.
            let recordA = try SpaceRecordURI(space: space, author: author, collection: "app.bsky.feed.post", rkey: "a")
            let recordB = try SpaceRecordURI(space: space, author: author, collection: "app.bsky.feed.post", rkey: "b")
            let valueA = try Self.record(text: "a", blobs: [cids[0], cids[1]], sizes: [payloads[0].count, payloads[1].count])
            let valueB = try Self.record(text: "b", blobs: [cids[1], cids[2]], sizes: [payloads[1].count, payloads[2].count])
            _ = try await database.apply(
                space: space, author: author, expectedRevision: 0, requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222222"),
                writes: [.create(uri: recordA, value: valueA, cid: CID.fromDAGCBOR(valueA).string)]
            )
            _ = try await database.apply(
                space: space, author: author, expectedRevision: 1, requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222223"),
                writes: [.create(uri: recordB, value: valueB, cid: CID.fromDAGCBOR(valueB).string)]
            )

            // Full page: every distinct blob once, ascending.
            let all = try await database.spaceRecordBlobCIDPage(space: space, author: author, since: nil, cursor: nil, limit: 500)
            XCTAssertEqual(all, sorted)

            // since=…2 excludes the record last written at …2 (A's exclusive
            // blob 0) but keeps the shared blob 1 through B, and blob 2.
            let sinceA = try await database.spaceRecordBlobCIDPage(space: space, author: author, since: "2222222222222", cursor: nil, limit: 500)
            XCTAssertEqual(Set(sinceA), Set([cids[1].string, cids[2].string]))
            let sinceB = try await database.spaceRecordBlobCIDPage(space: space, author: author, since: "2222222222223", cursor: nil, limit: 500)
            XCTAssertEqual(sinceB, [])

            // Cursor is the last CID of the previous page.
            let page1 = try await database.spaceRecordBlobCIDPage(space: space, author: author, since: nil, cursor: nil, limit: 2)
            XCTAssertEqual(page1, Array(sorted.prefix(2)))
            let page2 = try await database.spaceRecordBlobCIDPage(space: space, author: author, since: nil, cursor: page1.last, limit: 2)
            XCTAssertEqual(page2, Array(sorted.dropFirst(2)))

            // Another author's view of the same space is empty: the index is
            // per (space, author), like every other permissioned projection.
            let other = try await database.spaceRecordBlobCIDPage(space: space, author: author, since: nil, cursor: sorted.last, limit: 500)
            XCTAssertEqual(other, [])

            // Deleting A drops its exclusive edge; the shared blob survives
            // through B.
            _ = try await database.apply(
                space: space, author: author, expectedRevision: 2, requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222224"),
                writes: [.delete(uri: recordA)]
            )
            let afterDelete = try await database.spaceRecordBlobCIDPage(space: space, author: author, since: nil, cursor: nil, limit: 500)
            XCTAssertEqual(Set(afterDelete), Set([cids[1].string, cids[2].string]))

            // Updating B to drop blob 2 removes it from the index.
            let valueB2 = try Self.record(text: "b2", blobs: [cids[1]], sizes: [payloads[1].count])
            _ = try await database.apply(
                space: space, author: author, expectedRevision: 3, requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222225"),
                writes: [.update(uri: recordB, value: valueB2, cid: CID.fromDAGCBOR(valueB2).string)]
            )
            let afterUpdate = try await database.spaceRecordBlobCIDPage(space: space, author: author, since: nil, cursor: nil, limit: 500)
            XCTAssertEqual(afterUpdate, [cids[1].string])

            // Collection filters constrain writes, never space reads; blob
            // enumeration is available to both read grant shapes.
            let repository = try DurableSpaceRepository(database: database, space: space, author: author)
            let admitted = try await repository.listBlobCIDs(
                since: nil, cursor: nil, limit: 100,
                authorization: .accountOAuthForTesting(
                    subject: author,
                    scopes: ["space:app.bsky.bookmarks?authority=\(author)&skey=self&action=read"]
                )
            )
            XCTAssertEqual(admitted, [cids[1].string])
            let collectionQualified = try await repository.listBlobCIDs(
                since: nil, cursor: nil, limit: 100,
                authorization: .accountOAuthForTesting(
                    subject: author,
                    scopes: ["space:app.bsky.bookmarks?authority=\(author)&skey=self&collection=app.bsky.feed.post&action=read"]
                )
            )
            XCTAssertEqual(collectionQualified, admitted)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testBackfillIndexesRecordsWrittenBeforeTheEdgeTableExisted() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "PermissionedSpaceListBlobsBackfill-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let space = try SpaceURI(authority: author, spaceType: "app.bsky.bookmarks", skey: "self")
        let record = try SpaceRecordURI(space: space, author: author, collection: "app.bsky.feed.post", rkey: "old")

        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: author)
        let cid: String
        do {
            let payload = Data("pre-index blob".utf8)
            let reference = try await database.putBlob(payload, namespace: .public, mimeType: "application/octet-stream")
            cid = reference.cid
            let value = try Self.record(text: "old", blobs: [try CID.parse(cid)], sizes: [payload.count])
            _ = try await database.apply(
                space: space, author: author, expectedRevision: 0, requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222222"),
                writes: [.create(uri: record, value: value, cid: CID.fromDAGCBOR(value).string)]
            )
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }

        // Simulate a pre-v17 database: drop the edge table and its migration
        // row, as if the record had been written before the index existed.
        let raw = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(in: root, did: author).path)
        )
        _ = try await raw.query("DROP TABLE permissioned_space_record_blobs")
        _ = try await raw.query("DELETE FROM permissioned_repository_migrations WHERE version = 17")
        try await raw.close()

        let reopened = try await SQLiteAccountDatabase(dataDirectory: root, did: author)
        do {
            let page = try await reopened.spaceRecordBlobCIDPage(space: space, author: author, since: nil, cursor: nil, limit: 500)
            XCTAssertEqual(page, [cid], "the backfill must index a pre-existing record's blob links on reopen")
            // Backfilled edges carry the repository's current wire revision,
            // so a `since` at exactly that revision excludes them (they are
            // not newer than it) — over-inclusive under an older `since`,
            // never under-inclusive.
            let sinceCurrent = try await reopened.spaceRecordBlobCIDPage(space: space, author: author, since: "2222222222222", cursor: nil, limit: 500)
            XCTAssertEqual(sinceCurrent, [])
            let sinceOlder = try await reopened.spaceRecordBlobCIDPage(space: space, author: author, since: "2222222222221", cursor: nil, limit: 500)
            XCTAssertEqual(sinceOlder, [cid])
            try await reopened.close()
        } catch {
            try? await reopened.close()
            throw error
        }
    }

    private static func record(text: String, blobs: [CID], sizes: [Int]) throws -> Data {
        var entries: [(key: String, value: Any)] = [
            (key: "$type", value: "app.bsky.feed.post"),
            (key: "text", value: text),
        ]
        for (index, blob) in blobs.enumerated() {
            entries.append((key: "blob\(index)", value: OrderedCBORMap(entries: [
                (key: "$type", value: "blob"),
                (key: "ref", value: ATProtoLink(cid: blob)),
                (key: "mimeType", value: "application/octet-stream"),
                (key: "size", value: sizes[index]),
            ])))
        }
        return try DAGCBOR.encodeValue(OrderedCBORMap(entries: entries))
    }
}
