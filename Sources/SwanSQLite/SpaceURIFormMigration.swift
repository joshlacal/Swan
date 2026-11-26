import Crypto
import Foundation
import Petrel
import SQLiteNIO
import SwanCore
import SwanSpaces
import SwanStorage

/// Account-schema v32: space URIs moved from the spaces alpha form
/// `at://{spaceDid}/space/{rest}` to `at:space/{spaceDid}/{rest}` (reference
/// `packages/pds/src/db/rewrite-space-uris.ts` and migrations
/// `actor-store/db/migrations/011-space-uri.ts`,
/// `account-manager/db/migrations/013-space-uri.ts`).
///
/// Every stored space-URI column is rewritten in place. Each statement only
/// touches values still in the alpha form, so a re-run changes nothing. Record
/// values are left as they are: their CIDs cover any space URIs inside them.
///
/// Two deterministic markers bind the URI string and are recomputed for the
/// rows that moved: `permissioned_repository_state.current_commit` and
/// `permissioned_remote_replica_state.state_marker`. Digests that only guard
/// the replay of one earlier request (`permissioned_remote_replica_import_results`,
/// `permissioned_remote_replica_incremental_results`) and author signatures
/// held inside replicated commit blocks are not rewritten: they cover the old
/// URI and cannot be re-derived here. See
/// `docs/notes/permissioned-data-repin-scope.md`.
extension SQLiteAccountDatabase {
    static let spaceURIFormMigrationVersion = 32

    /// `(table, column)` pairs holding a space URI or a space-record URI.
    static let spaceURIColumns: [(table: String, column: String)] = [
        // Authority-owned space facts.
        ("permissioned_simple_space_authorities", "space_uri"),
        ("permissioned_simple_space_members", "space_uri"),
        ("permissioned_simple_space_clients", "space_uri"),
        ("permissioned_simple_space_managing_app_decisions", "space_uri"),
        ("permissioned_space_policy_migration_v29", "space_uri"),
        ("conversation_space_authorities", "space_uri"),
        ("permissioned_space_writers", "space_uri"),
        ("permissioned_space_recipient_tombstones", "space_uri"),
        ("permissioned_space_notification_receipts", "space_uri"),
        ("permissioned_space_sync_registrations", "space_uri"),
        ("permissioned_space_sync_notifications", "space_uri"),
        ("permissioned_issued_space_credentials", "space_uri"),
        ("permissioned_space_credential_revocation_notifications", "space_uri"),
        // This account's space repositories.
        ("permissioned_repository_state", "space_uri"),
        ("permissioned_restored_repository_closures", "space_uri"),
        ("permissioned_repository_history_resets", "space_uri"),
        ("permissioned_space_records", "space_uri"),
        ("permissioned_space_record_blobs", "space_uri"),
        ("permissioned_space_oplog", "space_uri"),
        ("permissioned_space_requests", "space_uri"),
        ("permissioned_space_outbox", "space_uri"),
        ("blob_namespace_references", "space_uri"),
        // Replicas of repositories hosted elsewhere.
        ("permissioned_remote_replica_state", "space_uri"),
        ("permissioned_remote_replica_blocks", "space_uri"),
        ("permissioned_remote_replica_block_chunks", "space_uri"),
        ("permissioned_remote_replica_records", "space_uri"),
        ("permissioned_remote_replica_import_sessions", "space_uri"),
        ("permissioned_remote_replica_import_results", "space_uri"),
        ("permissioned_remote_replica_incremental_results", "space_uri"),
        ("permissioned_remote_replica_incremental_progress", "space_uri"),
        ("permissioned_remote_replica_lifecycles", "space_uri"),
        ("permissioned_remote_replica_retired_events", "space_uri"),
        // The initial alpha sketch tables kept for compatibility.
        ("space_records", "space_uri"),
        ("space_records", "uri"),
        ("space_oplog", "space_uri"),
        ("space_outbox", "space_uri"),
    ]

    /// SQL matching a value still in the alpha form. A DID contains no `/`, so
    /// the first `/` after `at://` always ends the space DID.
    static func legacySpaceURIPredicate(_ column: String) -> String {
        "substr(\(column), 1, 5) = 'at://' AND substr(\(column), instr(substr(\(column), 6), '/') + 5, 7) = '/space/'"
    }

    /// `at://{spaceDid}/space/{rest}` -> `at:space/{spaceDid}/{rest}`, for the
    /// values of one column still in the alpha form.
    static func rewriteSpaceURIStatement(table: String, column: String) -> String {
        let slash = "instr(substr(\(column), 6), '/')"
        return """
            UPDATE \(table)
            SET \(column) = 'at:space/' || substr(\(column), 6, \(slash) - 1) || '/'
                || substr(\(column), \(slash) + 12)
            WHERE \(legacySpaceURIPredicate(column))
            """
    }

    /// Runs inside the account migration transaction, after every table that
    /// holds a space URI exists.
    func migrateSpaceURIFormIfNeeded() async throws {
        let version = Self.spaceURIFormMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        // Capture the rows whose markers bind the URI before it moves.
        let repositoryRows = try await connection.query(
            """
            SELECT space_uri, author_did FROM permissioned_repository_state
            WHERE \(Self.legacySpaceURIPredicate("space_uri"))
            """
        )
        let replicaRows = try await connection.query(
            """
            SELECT space_uri, repository_did FROM permissioned_remote_replica_state
            WHERE \(Self.legacySpaceURIPredicate("space_uri"))
            """
        )

        // Parent and child keys move in separate statements; check the
        // foreign keys once, at commit.
        _ = try await connection.query("PRAGMA defer_foreign_keys = ON")
        for (table, column) in Self.spaceURIColumns {
            let columns = try await connection.query("PRAGMA table_info(\(table))")
            guard columns.contains(where: { $0.column("name")?.string == column }) else {
                continue
            }
            _ = try await connection.query(
                Self.rewriteSpaceURIStatement(table: table, column: column)
            )
        }

        for row in repositoryRows {
            guard let legacy = row.column("space_uri")?.string,
                  let author = row.column("author_did")?.string,
                  let current = SpaceURI.fromLegacySpaceURI(legacy),
                  let space = try? SpaceURI(current),
                  space.rawValue == current else {
                // Not a canonical space URI before the move either; reads
                // keep reporting it as corrupt.
                continue
            }
            let state = try await connection.query(
                """
                SELECT revision, wire_revision, lthash
                FROM permissioned_repository_state
                WHERE space_uri = ? AND author_did = ?
                """,
                [.text(current), .text(author)]
            )
            guard let stateRow = state.first else { continue }
            let ltHash = try requiredBlob(stateRow, "lthash")
            guard ltHash.count == LtHash.byteCount else { continue }
            let revision = try requiredRevision(stateRow, "revision")
            let wireRevision = try requiredTID(stateRow, "wire_revision")
            let marker = try repositoryStateMarker(
                space: space,
                author: author,
                revision: revision,
                wireRevision: wireRevision,
                commitment: Data(SHA256.hash(data: ltHash))
            )
            _ = try await connection.query(
                """
                UPDATE permissioned_repository_state SET current_commit = ?
                WHERE space_uri = ? AND author_did = ?
                """,
                [blob(marker), .text(current), .text(author)]
            )
        }

        for row in replicaRows {
            guard let legacy = row.column("space_uri")?.string,
                  let repositoryDID = row.column("repository_did")?.string,
                  let current = SpaceURI.fromLegacySpaceURI(legacy),
                  let space = try? SpaceURI(current),
                  space.rawValue == current else {
                continue
            }
            let state = try await connection.query(
                """
                SELECT receiver_did, generation, wire_revision,
                       history_floor_wire_revision, commitment
                FROM permissioned_remote_replica_state
                WHERE space_uri = ? AND repository_did = ?
                """,
                [.text(current), .text(repositoryDID)]
            )
            guard let stateRow = state.first,
                  let receiverDID = stateRow.column("receiver_did")?.string,
                  let generation = stateRow.column("generation")?.integer,
                  generation > 0,
                  let target = try? PermissionedRemoteReplicaTarget(
                      receiverDID: receiverDID,
                      space: space,
                      repositoryDID: repositoryDID
                  ) else {
                continue
            }
            let wireRevision = try requiredTID(stateRow, "wire_revision")
            let historyFloor = try requiredTID(stateRow, "history_floor_wire_revision")
            let commitment = try requiredBlob(stateRow, "commitment")
            let marker = incrementalStateMarker(
                target: target,
                generation: UInt64(generation),
                wireRevision: wireRevision,
                historyFloor: historyFloor,
                commitment: commitment
            )
            _ = try await connection.query(
                """
                UPDATE permissioned_remote_replica_state SET state_marker = ?
                WHERE space_uri = ? AND repository_did = ?
                """,
                [blob(marker), .text(current), .text(repositoryDID)]
            )
        }

        _ = try await connection.query(
            """
            INSERT OR IGNORE INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(version),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }
}
