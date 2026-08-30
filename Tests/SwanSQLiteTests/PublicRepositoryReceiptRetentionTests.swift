import Crypto
import Foundation
import Petrel
import SQLiteNIO
import PetrelRepo
import SwanStorage
@testable import SwanSQLite
import XCTest

final class PublicRepositoryReceiptRetentionTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let genesisRevision = "3jzfcijpj2z2a"

    func testTerminalReceiptsOlderThan24HoursArePruned() async throws {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "PublicRepositoryReceiptRetentionTests-" + UUID().uuidString
        )
        defer { try? FileManager.default.removeItem(at: root) }

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

        let nowMicros = UInt64(1_750_000_000_000_000)
        let oldMicros = nowMicros - (25 * 3600 * 1_000_000) // 25 hours ago
        let recentMicros = nowMicros - (1 * 3600 * 1_000_000) // 1 hour ago

        // Insert receipts directly via raw SQL
        let raw = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(in: root, did: did).path)
        )
        defer { Task { try? await raw.close() } }

        // Old committed receipt (should be pruned)
        _ = try await raw.query(
            """
            INSERT INTO public_repository_mutation_requests(
                request_id, request_digest, base_commit_cid, base_revision,
                next_revision, status, committed_commit_cid, committed_data_cid,
                committed_projection, committed_projection_digest, integrity_digest,
                created_at
            ) VALUES (
                'old-committed', zeroblob(32), 'bafycommit', 'rev1', 'rev2',
                'committed', 'bafycommit2', 'bafydata', zeroblob(1), zeroblob(32),
                zeroblob(32), ?
            )
            """,
            [.integer(Int(oldMicros))]
        )

        // Old abandoned receipt (should be pruned)
        _ = try await raw.query(
            """
            INSERT INTO public_repository_mutation_requests(
                request_id, request_digest, base_commit_cid, base_revision,
                next_revision, status, integrity_digest, created_at
            ) VALUES (
                'old-abandoned', zeroblob(32), 'bafycommit', 'rev1', 'rev3',
                'abandoned', zeroblob(32), ?
            )
            """,
            [.integer(Int(oldMicros))]
        )

        // Recent committed receipt (must NOT be pruned)
        _ = try await raw.query(
            """
            INSERT INTO public_repository_mutation_requests(
                request_id, request_digest, base_commit_cid, base_revision,
                next_revision, status, committed_commit_cid, committed_data_cid,
                committed_projection, committed_projection_digest, integrity_digest,
                created_at
            ) VALUES (
                'recent-committed', zeroblob(32), 'bafycommit', 'rev1', 'rev4',
                'committed', 'bafycommit2', 'bafydata', zeroblob(1), zeroblob(32),
                zeroblob(32), ?
            )
            """,
            [.integer(Int(recentMicros))]
        )

        // Old reserved receipt (must NEVER be pruned)
        _ = try await raw.query(
            """
            INSERT INTO public_repository_mutation_requests(
                request_id, request_digest, base_commit_cid, base_revision,
                next_revision, status, integrity_digest, created_at
            ) VALUES (
                'old-reserved', zeroblob(32), 'bafycommit', 'rev1', 'rev5',
                'reserved', zeroblob(32), ?
            )
            """,
            [.integer(Int(oldMicros))]
        )

        // Trigger reservation which invokes receipt pruning
        let request = try PublicRepositoryMutationRequest(
            id: "trigger-prune",
            canonicalDigest: Data(repeating: 0x99, count: 32),
            baseCommitCID: genesis.commitCID
        )
        _ = try await database.reservePublicRepositoryRevision(
            request,
            wallClockMicroseconds: nowMicros
        )

        let checkRaw = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(in: root, did: did).path)
        )
        defer { Task { try? await checkRaw.close() } }

        let remaining = try await checkRaw.query(
            "SELECT request_id FROM public_repository_mutation_requests ORDER BY request_id"
        )
        let remainingIDs = remaining.compactMap { $0.column("request_id")?.string }

        XCTAssertFalse(remainingIDs.contains("old-committed"), "old committed receipt must be pruned")
        XCTAssertFalse(remainingIDs.contains("old-abandoned"), "old abandoned receipt must be pruned")
        XCTAssertTrue(remainingIDs.contains("recent-committed"), "recent committed receipt must be retained")
        XCTAssertTrue(remainingIDs.contains("old-reserved"), "reserved receipt must NEVER be pruned")

        try await database.close()
    }
}
