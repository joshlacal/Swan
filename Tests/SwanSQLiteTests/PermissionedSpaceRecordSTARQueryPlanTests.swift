import Foundation
import Petrel
import SQLiteNIO
import SwanCore
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

/// SWAN-SYNC-5: each STAR export keyset step must seek the v26 path index
/// instead of sorting the whole repository into a temporary B-tree, while
/// keeping strict bytewise path order (October 22 section 5).
final class PermissionedSpaceRecordSTARQueryPlanTests: XCTestCase {
    private let author = "did:plc:writerabcdefghijklmn"

    func testSTARKeysetStepUsesPathIndexWithoutTemporarySort() async throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: author)
        do {
            try await assertIndexedPlan(database)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testMigrationInstallsPathIndexOnExistingDatabase() async throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let legacy = try await SQLiteAccountDatabase(dataDirectory: root, did: author)
        do {
            _ = try await legacy.connection.query("DROP INDEX permissioned_space_records_star_path")
            _ = try await legacy.connection.query(
                "DELETE FROM permissioned_repository_migrations WHERE version = ?",
                [.integer(SQLiteAccountDatabase.permissionedSpaceRecordPathIndexMigrationVersion)]
            )
            let plan = try await planDetails(legacy)
            XCTAssertTrue(plan.contains { $0.contains("USE TEMP B-TREE") }, "control: without the index each step sorts: \(plan)")
            try await legacy.close()
        } catch {
            try? await legacy.close()
            throw error
        }
        let migrated = try await SQLiteAccountDatabase(dataDirectory: root, did: author)
        do {
            try await assertIndexedPlan(migrated)
            let marker = try await migrated.connection.query(
                "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
                [.integer(SQLiteAccountDatabase.permissionedSpaceRecordPathIndexMigrationVersion)]
            )
            XCTAssertEqual(marker.count, 1)
            try await migrated.close()
        } catch {
            try? await migrated.close()
            throw error
        }
    }

    func testIndexedKeysetWalkKeepsStrictBytewisePathOrder() async throws {
        let root = try makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: author)
        do {
            let space = try SpaceURI(authority: "did:plc:authorityabcdefghijk", spaceType: "com.example.forum", skey: "star")
            // Collection order differs from path byte order here: '.' (0x2E)
            // sorts before '/' (0x2F), so "app.a.b/…" precedes "app.a/…".
            let paths: [(String, String)] = [
                ("app.a", "x"), ("app.a.b", "y"), ("app.a", "a"), ("app.ab", "z"), ("app.a.b", "b"),
            ]
            for (index, path) in paths.enumerated() {
                let value = Data([0xA1, 0x61, 0x61, UInt8(index)])
                _ = try await database.connection.query(
                    """
                    INSERT INTO permissioned_space_records(
                        space_uri, author_did, collection, rkey, value, cid, revision
                    ) VALUES (?, ?, ?, ?, ?, ?, 1)
                    """,
                    [
                        .text(space.rawValue), .text(author), .text(path.0), .text(path.1),
                        value.sqliteData!, .text(try CID.fromDAGCBOR(value).string),
                    ]
                )
            }
            var cursor = Data()
            var walked: [String] = []
            while let row = try await database.connection.query(
                SQLiteAccountDatabase.repositorySTARNextRecordSQL,
                [.text(space.rawValue), .text(author), cursor.sqliteData!]
            ).first {
                let path = "\(row.column("collection")?.string ?? "")/\(row.column("rkey")?.string ?? "")"
                walked.append(path)
                cursor = Data(path.utf8)
            }
            let expected = paths.map { "\($0.0)/\($0.1)" }.sorted { Data($0.utf8).lexicographicallyPrecedes(Data($1.utf8)) }
            XCTAssertEqual(walked, expected)
            XCTAssertEqual(walked.first, "app.a.b/b")
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    private func makeRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSTARPathPlan-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
        )
        return root
    }

    private func planDetails(_ database: SQLiteAccountDatabase) async throws -> [String] {
        let plan = try await database.connection.query(
            "EXPLAIN QUERY PLAN " + SQLiteAccountDatabase.repositorySTARNextRecordSQL,
            [
                .text("at://did:plc:authority/com.example.space/lab"),
                .text(author),
                Data("app.example.record/after".utf8).sqliteData!,
            ]
        )
        return plan.compactMap { $0.column("detail")?.string?.uppercased() }
    }

    private func assertIndexedPlan(_ database: SQLiteAccountDatabase) async throws {
        let details = try await planDetails(database)
        XCTAssertTrue(
            details.contains { $0.contains("PERMISSIONED_SPACE_RECORDS_STAR_PATH") },
            "the STAR keyset step must seek the path index: \(details)"
        )
        XCTAssertFalse(
            details.contains { $0.contains("USE TEMP B-TREE") },
            "the STAR keyset step must not sort per step: \(details)"
        )
    }
}
