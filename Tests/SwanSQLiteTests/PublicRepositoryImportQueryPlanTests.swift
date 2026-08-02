import Foundation
import XCTest

@testable import SwanSQLite

final class PublicRepositoryImportQueryPlanTests: XCTestCase {
    func testReachableProjectionPagesUseCIDPrimaryKeyWithoutTemporarySort() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "SwanPublicImportPlan-\(UUID().uuidString)"
            )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: "did:plc:abcdefghijklmnopqrstuvwx"
        )
        defer { Task { try? await database.close() } }

        let plan = try await database.connection.query(
            """
            EXPLAIN QUERY PLAN
            SELECT cid, kind
            FROM public_repository_import_reachable
            WHERE session_id = ? AND kind = ? AND cid > ?
            ORDER BY cid
            LIMIT ?
            """,
            [
                .text("session"), .text("record"), .text(""), .integer(256),
            ]
        )
        let details = plan.compactMap {
            $0.column("detail")?.string?.uppercased()
        }
        XCTAssertFalse(
            details.contains { $0.contains("USE TEMP B-TREE") },
            "reachable projection pagination must not sort a full staging page: \(details)"
        )
        XCTAssertTrue(
            details.contains { $0.contains("PRIMARY KEY") || $0.contains("INDEX") },
            "reachable projection pagination must advance through the CID key: \(details)"
        )
    }

    func testRecordIndexPagesUseCompositePrimaryKeyWithoutTemporarySort() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "SwanPublicImportRecordPlan-\(UUID().uuidString)"
            )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: "did:plc:abcdefghijklmnopqrstuvwx"
        )
        defer { Task { try? await database.close() } }

        let plan = try await database.connection.query(
            """
            EXPLAIN QUERY PLAN
            SELECT collection, rkey, record_cid
            FROM public_repository_import_record_index
            WHERE session_id = ? AND (collection, rkey) > (?, ?)
            ORDER BY collection, rkey
            LIMIT ?
            """,
            [
                .text("session"), .text("app.example.record"),
                .text("after"), .integer(256),
            ]
        )
        let details = plan.compactMap {
            $0.column("detail")?.string?.uppercased()
        }
        XCTAssertFalse(
            details.contains { $0.contains("USE TEMP B-TREE") },
            "record-index pagination must not sort a full staging page: \(details)"
        )
        XCTAssertTrue(
            details.contains {
                $0.contains("PUBLIC_REPOSITORY_IMPORT_RECORD_INDEX")
                    && ($0.contains("PRIMARY KEY") || $0.contains("INDEX"))
            },
            "record-index pagination must use the session/collection/rkey key: \(details)"
        )
    }
}
