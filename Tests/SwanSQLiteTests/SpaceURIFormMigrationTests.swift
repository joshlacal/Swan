import Foundation
import Petrel
import SQLiteNIO
import SwanCore
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

/// Account-schema v32: stored space URIs move from the spaces alpha form
/// `at://{spaceDid}/space/...` to `at:space/{spaceDid}/...`, in place and
/// idempotently, and the repository-state marker that binds the URI follows.
final class SpaceURIFormMigrationTests: XCTestCase {
    func testMigrationRewritesAlphaFormSpaceURIsAndIsIdempotent() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSpaceURIForm-\(UUID().uuidString)")
        let author = "did:plc:writerabcdefghijklmn"
        let space = try SpaceURI(
            authority: "did:plc:authorityabcdefghijk", spaceType: "com.example.forum", skey: "one"
        )
        let legacySpace = "at://did:plc:authorityabcdefghijk/space/com.example.forum/one"
        XCTAssertEqual(space.rawValue, "at:space/did:plc:authorityabcdefghijk/com.example.forum/one")
        XCTAssertEqual(SpaceURI.fromLegacySpaceURI(legacySpace), space.rawValue)

        func open() async throws -> SQLiteAccountDatabase {
            try await SQLiteAccountDatabase(dataDirectory: root, did: author)
        }

        let database = try await open()
        do {
            let value = Data([0xA1, 0x61, 0x61, 0x01])
            let uri = try SpaceRecordURI(space: space, author: author, collection: "app.bsky.feed.post", rkey: "r1")
            _ = try await database.apply(
                space: space, author: author, expectedRevision: 0, requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222223"),
                writes: [.put(uri: uri, value: value, cid: CID.fromDAGCBOR(value).string)]
            )
            _ = try await database.connection.query(
                "INSERT INTO space_records(space_uri, uri, value, revision) VALUES (?, ?, ?, 1)",
                [.text(space.rawValue), .text(uri.rawValue), value.sqliteData!]
            )
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }

        // Put this database back into the alpha form, as a pre-v32 host left it.
        let legacy = try await open()
        do {
            _ = try await legacy.connection.query("BEGIN IMMEDIATE")
            _ = try await legacy.connection.query("PRAGMA defer_foreign_keys = ON")
            for (table, column) in SQLiteAccountDatabase.spaceURIColumns {
                _ = try await legacy.connection.query(
                    """
                    UPDATE \(table)
                    SET \(column) = 'at://' || substr(\(column), 10, instr(substr(\(column), 10), '/') - 1)
                        || '/space/' || substr(\(column), instr(substr(\(column), 10), '/') + 10)
                    WHERE substr(\(column), 1, 9) = 'at:space/'
                      AND instr(substr(\(column), 10), '/') > 0
                    """
                )
            }
            _ = try await legacy.connection.query(
                "DELETE FROM permissioned_repository_migrations WHERE version = ?",
                [.integer(SQLiteAccountDatabase.spaceURIFormMigrationVersion)]
            )
            _ = try await legacy.connection.query("COMMIT")
            let rows = try await legacy.connection.query(
                "SELECT space_uri FROM permissioned_space_records"
            )
            XCTAssertEqual(rows.compactMap { $0.column("space_uri")?.string }, [legacySpace])
            try await legacy.close()
        } catch {
            try? await legacy.close()
            throw error
        }

        // The upgrade, then a forced re-run, leave the same current-form state.
        for pass in 1 ... 2 {
            let migrated = try await open()
            do {
                for (table, column) in SQLiteAccountDatabase.spaceURIColumns {
                    let remaining = try await migrated.connection.query(
                        "SELECT COUNT(*) AS count FROM \(table) WHERE \(SQLiteAccountDatabase.legacySpaceURIPredicate(column))"
                    )
                    XCTAssertEqual(remaining.first?.column("count")?.integer, 0, "\(table).\(column), pass \(pass)")
                }
                let records = try await migrated.connection.query(
                    "SELECT space_uri FROM permissioned_space_records"
                )
                XCTAssertEqual(records.compactMap { $0.column("space_uri")?.string }, [space.rawValue])
                let sketch = try await migrated.connection.query("SELECT uri FROM space_records")
                XCTAssertEqual(
                    sketch.compactMap { $0.column("uri")?.string },
                    ["\(space.rawValue)/\(author)/app.bsky.feed.post/r1"]
                )
                // Reading the state verifies the marker, which binds the URI.
                let state = try await migrated.repositoryState(space: space, author: author)
                XCTAssertEqual(state?.revision, 1)
                _ = try await migrated.connection.query(
                    "DELETE FROM permissioned_repository_migrations WHERE version = ?",
                    [.integer(SQLiteAccountDatabase.spaceURIFormMigrationVersion)]
                )
                try await migrated.close()
            } catch {
                try? await migrated.close()
                throw error
            }
        }
    }
}
