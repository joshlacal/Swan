import Crypto
import Foundation
import Petrel
import SQLiteNIO
import PetrelRepo
import SwanCore
import SwanStorage
@testable import SwanSQLite
import XCTest

final class PublicRepositoryReceiptRetentionTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let genesisRevision = "3jzfcijpj2z2a"

    func testTerminalReceiptsPruneOlderThanTwentyFourHoursWhileRetainingReserved() async throws {
        let fixture = try await makeRepository()
        defer { fixture.cleanUp() }

        let nowMicros: UInt64 = 2_000_000_000_000_000
        let oldMicros: UInt64 = nowMicros - (25 * 3600 * 1_000_000)
        let recentMicros: UInt64 = nowMicros - (1 * 3600 * 1_000_000)

        try await withRawConnection(root: fixture.root) { conn in
            // Old abandoned receipt 1 (should be pruned)
            _ = try await conn.query(
                """
                INSERT INTO public_repository_mutation_requests
                    (request_id, request_digest, base_commit_cid, base_revision, next_revision, status, integrity_digest, created_at)
                VALUES ('old-abandoned-1', x'0101010101010101010101010101010101010101010101010101010101010101', 'bafybase1', 'rev1', 'next1', 'abandoned', x'0101010101010101010101010101010101010101010101010101010101010101', ?)
                """,
                [.integer(Int(oldMicros))]
            )
            // Old abandoned receipt 2 (should be pruned)
            _ = try await conn.query(
                """
                INSERT INTO public_repository_mutation_requests
                    (request_id, request_digest, base_commit_cid, base_revision, next_revision, status, integrity_digest, created_at)
                VALUES ('old-abandoned-2', x'0202020202020202020202020202020202020202020202020202020202020202', 'bafybase2', 'rev2', 'next2', 'abandoned', x'0202020202020202020202020202020202020202020202020202020202020202', ?)
                """,
                [.integer(Int(oldMicros))]
            )
            // Old reserved receipt (must NEVER be pruned)
            _ = try await conn.query(
                """
                INSERT INTO public_repository_mutation_requests
                    (request_id, request_digest, base_commit_cid, base_revision, next_revision, status, integrity_digest, created_at)
                VALUES ('old-reserved', x'0303030303030303030303030303030303030303030303030303030303030303', 'bafybase3', 'rev3', 'next3', 'reserved', x'0303030303030303030303030303030303030303030303030303030303030303', ?)
                """,
                [.integer(Int(oldMicros))]
            )
            // Recent abandoned receipt (should be retained)
            _ = try await conn.query(
                """
                INSERT INTO public_repository_mutation_requests
                    (request_id, request_digest, base_commit_cid, base_revision, next_revision, status, integrity_digest, created_at)
                VALUES ('recent-abandoned', x'0404040404040404040404040404040404040404040404040404040404040404', 'bafybase4', 'rev4', 'next4', 'abandoned', x'0404040404040404040404040404040404040404040404040404040404040404', ?)
                """,
                [.integer(Int(recentMicros))]
            )
        }

        try await fixture.database.pruneTerminalPublicRepositoryMutationRequestsWithoutGate(
            nowMicroseconds: nowMicros
        )

        try await withRawConnection(root: fixture.root) { conn in
            let rows = try await conn.query(
                "SELECT request_id, status FROM public_repository_mutation_requests ORDER BY request_id"
            )
            let ids = rows.compactMap { $0.column("request_id")?.string }
            XCTAssertEqual(ids, ["old-reserved", "recent-abandoned"])
        }
    }

    func testTerminalReceiptsPruneBeyondOneHundredThousandCountBound() async throws {
        let fixture = try await makeRepository()
        defer { fixture.cleanUp() }

        let nowMicros: UInt64 = 2_000_000_000_000_000
        let recentMicros: UInt64 = nowMicros - (1000 * 1_000_000)

        // Insert 100,050 terminal rows
        try await withRawConnection(root: fixture.root) { conn in
            _ = try await conn.query(
                """
                INSERT INTO public_repository_mutation_requests(request_id, request_digest, base_commit_cid, base_revision, next_revision, status, integrity_digest, created_at)
                WITH RECURSIVE filler(n) AS (
                    SELECT 1 UNION ALL SELECT n + 1 FROM filler WHERE n < 100050
                )
                SELECT 'req-' || printf('%08d', n), x'0101010101010101010101010101010101010101010101010101010101010101', 'bafybase', 'rev', 'next-' || printf('%08d', n), 'abandoned', x'0101010101010101010101010101010101010101010101010101010101010101', ? + n
                FROM filler
                """,
                [.integer(Int(recentMicros))]
            )
        }

        try await fixture.database.pruneTerminalPublicRepositoryMutationRequestsWithoutGate(
            nowMicroseconds: nowMicros
        )

        try await withRawConnection(root: fixture.root) { conn in
            let countRows = try await conn.query(
                "SELECT COUNT(*) AS c FROM public_repository_mutation_requests WHERE status IN ('committed', 'abandoned')"
            )
            let count = countRows.first?.column("c")?.integer ?? 0
            XCTAssertLessThanOrEqual(count, 100_000, "terminal receipts exceeding 100,000 must be pruned down to <= 100,000")
            XCTAssertGreaterThan(count, 0)
        }
    }

    func testReopeningDatabasePerformsReceiptAndBlockCleanup() async throws {
        let fixture = try await makeRepository()
        defer { fixture.cleanUp() }
        let nowMicros: UInt64 = UInt64(Date().timeIntervalSince1970 * 1_000_000)
        let oldMicros: UInt64 = nowMicros - (30 * 3600 * 1_000_000)

        try await withRawConnection(root: fixture.root) { conn in
            _ = try await conn.query(
                """
                INSERT INTO public_repository_mutation_requests
                    (request_id, request_digest, base_commit_cid, base_revision, next_revision, status, integrity_digest, created_at)
                VALUES ('stale-on-open', x'0909090909090909090909090909090909090909090909090909090909090909', 'bafyold', 'revold', 'nextold', 'abandoned', x'0909090909090909090909090909090909090909090909090909090909090909', ?)
                """,
                [.integer(Int(oldMicros))]
            )
        }
        try await fixture.database.close()

        let reopened = try await SQLiteAccountDatabase(dataDirectory: fixture.root, did: did)

        try await withRawConnection(root: fixture.root) { conn in
            let rows = try await conn.query(
                "SELECT 1 FROM public_repository_mutation_requests WHERE request_id = 'stale-on-open'"
            )
            XCTAssertTrue(rows.isEmpty, "database open must prune stale terminal receipts")
        }
        try await reopened.close()
    }
    func testPreUpgradeTerminalReceiptsArePrunedOnOpenWhileReservedRemain() async throws {
        let fixture = try await makeRepository()
        defer { fixture.cleanUp() }
        try await fixture.database.close()

        try await withRawConnection(root: fixture.root) { conn in
            _ = try? await conn.query("DROP INDEX IF EXISTS public_repository_mutation_requests_retention")
            _ = try await conn.query("DROP TABLE public_repository_mutation_requests")
            _ = try await conn.query(
                """
                CREATE TABLE public_repository_mutation_requests (
                    request_id TEXT PRIMARY KEY,
                    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
                    base_commit_cid TEXT NOT NULL,
                    base_revision TEXT NOT NULL,
                    next_revision TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL CHECK(status IN ('reserved', 'committed', 'abandoned')),
                    committed_commit_cid TEXT,
                    committed_data_cid TEXT,
                    committed_projection BLOB,
                    committed_projection_digest BLOB CHECK(
                        committed_projection_digest IS NULL
                        OR length(committed_projection_digest) = 32
                    ),
                    integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32),
                    CHECK(
                        (status IN ('reserved', 'abandoned') AND committed_commit_cid IS NULL
                            AND committed_data_cid IS NULL AND committed_projection IS NULL
                            AND committed_projection_digest IS NULL)
                        OR
                        (status = 'committed' AND committed_commit_cid IS NOT NULL
                            AND committed_data_cid IS NOT NULL AND committed_projection IS NOT NULL
                            AND committed_projection_digest IS NOT NULL)
                    )
                )
                """
            )
            _ = try await conn.query(
                "DELETE FROM permissioned_repository_migrations WHERE version = 20"
            )
            // Seed pre-upgrade terminal abandoned receipt
            _ = try await conn.query(
                """
                INSERT INTO public_repository_mutation_requests
                    (request_id, request_digest, base_commit_cid, base_revision, next_revision, status, integrity_digest)
                VALUES ('pre-upgrade-abandoned', x'0101010101010101010101010101010101010101010101010101010101010101', 'bafybase1', 'rev1', 'next1', 'abandoned', x'0101010101010101010101010101010101010101010101010101010101010101')
                """
            )
            // Seed pre-upgrade reserved receipt
            _ = try await conn.query(
                """
                INSERT INTO public_repository_mutation_requests
                    (request_id, request_digest, base_commit_cid, base_revision, next_revision, status, integrity_digest)
                VALUES ('pre-upgrade-reserved', x'0202020202020202020202020202020202020202020202020202020202020202', 'bafybase2', 'rev2', 'next2', 'reserved', x'0202020202020202020202020202020202020202020202020202020202020202')
                """
            )
        }

        let upgraded = try await SQLiteAccountDatabase(dataDirectory: fixture.root, did: did)

        try await withRawConnection(root: fixture.root) { conn in
            let rows = try await conn.query(
                "SELECT request_id, status FROM public_repository_mutation_requests ORDER BY request_id"
            )
            let ids = rows.compactMap { $0.column("request_id")?.string }
            XCTAssertEqual(ids, ["pre-upgrade-reserved"], "pre-upgrade terminal receipt must be pruned on database open while reserved receipt is retained")
        }
        try await upgraded.close()
    }

    func testRetentionIndexCoversStatusAndCreatedAtQueryPlan() async throws {
        let fixture = try await makeRepository()
        defer { fixture.cleanUp() }

        try await withRawConnection(root: fixture.root) { conn in
            let planRows = try await conn.query(
                """
                EXPLAIN QUERY PLAN
                SELECT request_id FROM public_repository_mutation_requests
                WHERE status IN ('committed', 'abandoned')
                ORDER BY created_at ASC, request_id ASC
                LIMIT 1 OFFSET 100000
                """
            )
            let details = planRows.compactMap { $0.column("detail")?.string }.joined(separator: " ")
            XCTAssertTrue(
                details.contains("public_repository_mutation_requests_retention")
                    || details.contains("USING INDEX"),
                "probe query must use indexed scan, got query plan: \(details)"
            )
        }
    }

    // MARK: - Helpers

    private struct Repository {
        let root: URL
        let database: SQLiteAccountDatabase
        let key: P256.Signing.PrivateKey

        func cleanUp() {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
    }

    private func makeRepository() async throws -> Repository {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "PublicRepositoryReceiptRetentionTests-" + UUID().uuidString
        )
        let key = P256.Signing.PrivateKey()
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let genesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: genesisRevision,
            signingKey: key
        )
        _ = try await database.installPublicRepositoryGenesis(
            genesis,
            signingPublicKey: key.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
        return Repository(root: root, database: database, key: key)
    }

    private func withRawConnection<T>(
        root: URL,
        _ body: (SQLiteConnection) async throws -> T
    ) async throws -> T {
        let connection = try await SQLiteConnection.open(storage: .file(
            path: SQLiteLayout.accountDatabase(in: root, did: did).path
        ))
        _ = try? await connection.query("PRAGMA busy_timeout=5000")
        do {
            let value = try await body(connection)
            try await connection.close()
            return value
        } catch {
            try? await connection.close()
            throw error
        }
    }
}
