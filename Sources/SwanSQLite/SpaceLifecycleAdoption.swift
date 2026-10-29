import Foundation
import SQLiteNIO
import SwanCore
import SwanSpaces

/// The retained recipient deletion for one remote space: the authority's
/// deletion event and when this account recorded it.
public struct RecipientSpaceDeletionTombstone: Sendable, Equatable {
    public let deletionEventID: String
    public let closedAt: Date
}

extension SQLiteAccountDatabase {
    /// The recipient tombstone that closes replicated state for `space`, or
    /// `nil` when none is retained. Operators read it before adopting a
    /// recreated space (`swan account adopt-recreated-space`).
    public func recipientSpaceDeletionTombstone(
        _ space: SpaceURI
    ) async throws -> RecipientSpaceDeletionTombstone? {
        try await withReadConnectionGate {
            let rows = try await readConnection.query("""
                SELECT deletion_event_id, closed_at FROM permissioned_space_recipient_tombstones WHERE space_uri = ?
                """, [.text(space.rawValue)])
            guard let row = rows.first else { return nil }
            guard let eventID = row.column("deletion_event_id")?.string,
                  let closedAt = row.column("closed_at")?.integer, closedAt >= 0 else {
                throw SQLiteRepositoryError.corruptDatabase("recipient tombstone is invalid")
            }
            return RecipientSpaceDeletionTombstone(
                deletionEventID: eventID,
                closedAt: Date(timeIntervalSince1970: Double(closedAt) / 1_000_000)
            )
        }
    }

    /// Explicit owner-selected lifecycle transition. `authorization` and the
    /// issue time must come from the same freshly verified authority JWT.
    /// A read or retry must never call this method automatically; the
    /// production caller is the operator command
    /// `swan account adopt-recreated-space`.
    public func adoptRecreatedRemoteSpace(
        _ space: SpaceURI, expectedDeletionEventID: String,
        authorization: AuthorizationContext, credentialIssuedAt: Date,
        credentialDigest: Data, now: Date = Date()
    ) async throws {
        guard space.authority != accountDID, credentialDigest.count == 32,
              case let .spaceCredential(grant) = authorization,
              grant.subject == space.authority, grant.space == space,
              grant.permissions.contains(.read), grant.expiresAt > now,
              credentialIssuedAt <= now else { throw SwanError.unauthorized("fresh authority credential required") }
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query("""
                    SELECT deletion_event_id, closed_at FROM permissioned_space_recipient_tombstones WHERE space_uri = ?
                    """, [.text(space.rawValue)])
                guard let row = rows.first,
                      row.column("deletion_event_id")?.string == expectedDeletionEventID,
                      let closedAt = row.column("closed_at")?.integer,
                      credentialIssuedAt.timeIntervalSince1970 * 1_000_000 > Double(closedAt) else {
                    throw SwanError.unauthorized("space lifecycle changed or credential predates deletion")
                }
                try await retainRemoteReplicaGenerationFloor(space: space, eventID: expectedDeletionEventID)
                // This also invalidates staged and preverified work by deleting
                // its session/result identities in the same transaction.
                for table in ["permissioned_remote_replica_records", "permissioned_remote_replica_blocks",
                              "permissioned_remote_replica_state", "permissioned_remote_replica_import_sessions",
                              "permissioned_remote_replica_import_results", "permissioned_remote_replica_incremental_results",
                              "permissioned_remote_replica_incremental_progress", "permissioned_space_writers"] {
                    _ = try await connection.query("DELETE FROM \(table) WHERE space_uri = ?", [.text(space.rawValue)])
                }
                _ = try await connection.query("""
                    UPDATE permissioned_remote_replica_lifecycles SET adopted_at = ?, credential_digest = ? WHERE space_uri = ?
                    """, [.integer(Int(now.timeIntervalSince1970)), credentialDigest.sqliteData!, .text(space.rawValue)])
                _ = try await connection.query("""
                    INSERT OR IGNORE INTO permissioned_remote_replica_retired_events(space_uri, event_id, adopted_at)
                    VALUES (?, ?, ?)
                    """, [.text(space.rawValue), .text(expectedDeletionEventID), .integer(Int(now.timeIntervalSince1970))])
                _ = try await connection.query("DELETE FROM permissioned_space_recipient_tombstones WHERE space_uri = ?", [.text(space.rawValue)])
            }
        }
    }

    // Caller holds the connection gate and transaction. Keeping the monotonic
    // generation floor across deletions fences old in-memory incremental work.
    func retainRemoteReplicaGenerationFloor(space: SpaceURI, eventID: String) async throws {
        _ = try await connection.query("""
            INSERT INTO permissioned_remote_replica_lifecycles(space_uri, generation_floor, retired_event_id)
            VALUES (?, COALESCE((SELECT MAX(generation) FROM permissioned_remote_replica_state WHERE space_uri = ?), 0), ?)
            ON CONFLICT(space_uri) DO UPDATE SET generation_floor = MAX(generation_floor, excluded.generation_floor),
                retired_event_id = excluded.retired_event_id, adopted_at = NULL, credential_digest = NULL
            """, [.text(space.rawValue), .text(space.rawValue), .text(eventID)])
    }

    func remoteReplicaGenerationFloor(space: SpaceURI) async throws -> UInt64 {
        let rows = try await connection.query("SELECT generation_floor FROM permissioned_remote_replica_lifecycles WHERE space_uri = ?", [.text(space.rawValue)])
        return UInt64(rows.first?.column("generation_floor")?.integer ?? 0)
    }
}
