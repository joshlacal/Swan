import Foundation
import SQLiteNIO
import XCTest

@testable import SwanSQLite

final class PermissionedRemoteReplicaRecoveryQueryPlanTests:
    XCTestCase
{
    func testContinuationPageUsesCanonicalIndexWithoutTemporarySort()
        async throws
    {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "SwanRemoteReplicaPlan-\(UUID().uuidString)"
            )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: "did:plc:remote-replica-plan"
        )
        defer { Task { try? await database.close() } }

        let consumptionPlan = try await database.connection.query(
            """
            EXPLAIN QUERY PLAN
            SELECT path, cid
            FROM permissioned_remote_replica_import_index
            WHERE session_id = ? AND consumed = 0
            ORDER BY length(path), path
            LIMIT 1
            """,
            [.text("canonical-consumption")]
        )
        let consumptionDetails = consumptionPlan.compactMap {
            $0.column("detail")?.string?.uppercased()
        }
        XCTAssertTrue(consumptionDetails.contains {
            $0.contains("PERMISSIONED_REMOTE_REPLICA_IMPORT_INDEX_UNCONSUMED_CANONICAL")
        }, "record consumption must use the unconsumed canonical index: \(consumptionDetails)")
        XCTAssertFalse(consumptionDetails.contains { $0.contains("USE TEMP B-TREE") })

        let plan = try await database.connection.query(
            """
            EXPLAIN QUERY PLAN
            SELECT collection, rkey, cid,
                   CAST(collection || '/' || rkey AS BLOB) AS path
            FROM permissioned_remote_replica_records
            WHERE space_uri = ? AND repository_did = ?
              AND generation = ?
              AND (
                length(CAST(collection || '/' || rkey AS BLOB)),
                CAST(collection || '/' || rkey AS BLOB)
              ) > (?, ?)
            ORDER BY
              length(CAST(collection || '/' || rkey AS BLOB)),
              CAST(collection || '/' || rkey AS BLOB)
            LIMIT ?
            """,
            [
                .text("at://did:plc:authority/com.example.space/lab"),
                .text("did:plc:writer"),
                .integer(7),
                .integer(24),
                Data("app.example.record/after".utf8).sqliteData!,
                .integer(128),
            ]
        )
        let details = plan.compactMap {
            $0.column("detail")?.string?.uppercased()
        }
        XCTAssertTrue(
            details.contains {
                $0.contains(
                    "PERMISSIONED_REMOTE_REPLICA_RECORDS_CANONICAL_PAGE"
                )
            },
            "continuation page must use the canonical expression index: \(details)"
        )
        XCTAssertFalse(
            details.contains { $0.contains("USE TEMP B-TREE") },
            "continuation page must not materialize an ORDER BY: \(details)"
        )
        XCTAssertFalse(
            details.contains {
                $0.contains("SCAN PERMISSIONED_REMOTE_REPLICA_RECORDS")
                    && !$0.contains("USING INDEX")
            },
            "continuation page must not full-scan the live generation: \(details)"
        )
    }
}
