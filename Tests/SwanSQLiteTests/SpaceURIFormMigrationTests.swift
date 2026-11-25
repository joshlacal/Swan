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
    /// Puts every stored space URI back into the alpha form and drops the v32
    /// sentinel, as a pre-v32 host left the database. Call inside a write
    /// transaction.
    static func revertToAlphaForm(_ connection: SQLiteConnection) async throws {
        _ = try await connection.query("PRAGMA defer_foreign_keys = ON")
        for (table, column) in SQLiteAccountDatabase.spaceURIColumns {
            _ = try await connection.query(
                """
                UPDATE \(table)
                SET \(column) = 'at://' || substr(\(column), 10, instr(substr(\(column), 10), '/') - 1)
                    || '/space/' || substr(\(column), instr(substr(\(column), 10), '/') + 10)
                WHERE substr(\(column), 1, 9) = 'at:space/'
                  AND instr(substr(\(column), 10), '/') > 0
                """
            )
        }
        _ = try await connection.query(
            "DELETE FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(SQLiteAccountDatabase.spaceURIFormMigrationVersion)]
        )
    }

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
            try await Self.revertToAlphaForm(legacy.connection)
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

    /// A database that predates permissioned-storage migration v1 as well as
    /// v32: v1 runs first in the same open and must read the alpha-form
    /// `space_uri` rather than report the rows as corrupt.
    func testPreV1DatabaseWithAlphaFormSpaceURIsOpens() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSpaceURIFormPreV1-\(UUID().uuidString)")
        let author = "did:plc:writerabcdefghijklmn"
        let space = try SpaceURI(
            authority: "did:plc:authorityabcdefghijk", spaceType: "com.example.forum", skey: "one"
        )
        let legacySpace = "at://did:plc:authorityabcdefghijk/space/com.example.forum/one"
        let value = Data([0xA1, 0x61, 0x61, 0x01])

        func open() async throws -> SQLiteAccountDatabase {
            try await SQLiteAccountDatabase(dataDirectory: root, did: author)
        }

        let database = try await open()
        do {
            let uri = try SpaceRecordURI(space: space, author: author, collection: "app.bsky.feed.post", rkey: "r1")
            _ = try await database.apply(
                space: space, author: author, expectedRevision: 0, requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222223"),
                writes: [.put(uri: uri, value: value, cid: CID.fromDAGCBOR(value).string)]
            )
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }

        // Alpha-form URIs, no v1 or v32 sentinel, and a pre-v1 state commit
        // and outbox payload.
        let legacy = try await open()
        do {
            _ = try await legacy.connection.query("BEGIN IMMEDIATE")
            try await Self.revertToAlphaForm(legacy.connection)
            _ = try await legacy.connection.query(
                "DELETE FROM permissioned_repository_migrations WHERE version = 1"
            )
            _ = try await legacy.connection.query(
                "UPDATE permissioned_repository_state SET current_commit = ?",
                [Data("legacy-commit-bytes".utf8).sqliteData!]
            )
            _ = try await legacy.connection.query(
                "UPDATE permissioned_space_outbox SET payload = ?",
                [Data("legacy-outbox-payload".utf8).sqliteData!]
            )
            _ = try await legacy.connection.query("COMMIT")
            let rows = try await legacy.connection.query(
                "SELECT space_uri FROM permissioned_repository_state"
            )
            XCTAssertEqual(rows.compactMap { $0.column("space_uri")?.string }, [legacySpace])
            try await legacy.close()
        } catch {
            try? await legacy.close()
            throw error
        }

        // Opening runs v1 then v32; a second open re-validates the result.
        for pass in 1 ... 2 {
            let migrated = try await open()
            do {
                for (table, column) in SQLiteAccountDatabase.spaceURIColumns {
                    let remaining = try await migrated.connection.query(
                        "SELECT COUNT(*) AS count FROM \(table) WHERE \(SQLiteAccountDatabase.legacySpaceURIPredicate(column))"
                    )
                    XCTAssertEqual(remaining.first?.column("count")?.integer, 0, "\(table).\(column), pass \(pass)")
                }
                let sentinels = try await migrated.connection.query(
                    "SELECT version FROM permissioned_repository_migrations WHERE version IN (1, ?) ORDER BY version",
                    [.integer(SQLiteAccountDatabase.spaceURIFormMigrationVersion)]
                )
                XCTAssertEqual(
                    sentinels.compactMap { $0.column("version")?.integer },
                    [1, SQLiteAccountDatabase.spaceURIFormMigrationVersion]
                )
                // Reading the snapshot verifies the marker v1 and v32 wrote.
                let snapshot = try await migrated.repositorySnapshot(space: space, author: author)
                XCTAssertEqual(snapshot?.state.revision, 1)
                XCTAssertEqual(snapshot?.records.map(\.value), [value])
                let pending = try await migrated.pendingOutbox()
                XCTAssertEqual(pending.map(\.space), [space])
                try await migrated.close()
            } catch {
                try? await migrated.close()
                throw error
            }
        }
    }
}
