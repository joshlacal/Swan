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
    func testReachableProjectionPagesWithBlockJoinUseCIDPrimaryKeyWithoutTemporarySort() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "SwanPublicImportJoinPlan-\(UUID().uuidString)"
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
            SELECT r.cid, r.kind, length(b.bytes) AS byte_count
            FROM public_repository_import_reachable r
            LEFT JOIN public_repository_import_blocks b
              ON b.session_id = r.session_id AND b.cid = r.cid
            WHERE r.session_id = ? AND r.kind = ? AND EXISTS (
                SELECT 1 FROM public_repository_import_sessions
                WHERE session_id = ? AND expires_at > ?
            ) AND r.cid > ?
            ORDER BY r.cid
            LIMIT ?
            """,
            [
                .text("session"), .text("record"),
                .text("session"), .integer(100),
                .text(""), .integer(256),
            ]
        )

        let blockPlan = try await database.connection.query(
            """
            EXPLAIN QUERY PLAN
            SELECT cid, bytes
            FROM public_repository_import_blocks
            WHERE session_id = ? AND cid IN (?, ?, ?)
            """,
            [
                .text("session"), .text("c1"), .text("c2"), .text("c3")
            ]
        )
        let details = plan.compactMap {
            $0.column("detail")?.string?.uppercased()
        }
        XCTAssertFalse(
            details.contains { $0.contains("USE TEMP B-TREE") },
            "reachable projection join pagination must not sort a full staging page: \(details)"
        )
        XCTAssertTrue(
            details.contains { $0.contains("PUBLIC_REPOSITORY_IMPORT_REACHABLE") || $0.contains("PRIMARY KEY") || $0.contains("INDEX") },
            "reachable projection join pagination must advance through the CID key: \(details)"
        )
        let blockDetails = blockPlan.compactMap {
            $0.column("detail")?.string?.uppercased()
        }
        XCTAssertFalse(
            blockDetails.contains { $0.contains("USE TEMP B-TREE") },
            "block batch query must not sort: \(blockDetails)"
        )
        XCTAssertTrue(
            blockDetails.contains { $0.contains("PRIMARY KEY") || $0.contains("INDEX") },
            "block batch query must use primary key index: \(blockDetails)"
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
