import Foundation
import SQLiteNIO
import SwanCore
import SwanSpaces
import SwanStorage

extension SQLiteAccountDatabase: ConversationSpaceAuthorityLifecycle {
    public func registerKnownConversationSpace(space: SpaceURI, now: Date = Date()) async throws {
        try validateConversationAuthority(space)
        let timestamp = try simpleSpaceTimestamp(now)
        try await withConnectionGate {
            try await transaction {
                let existing = try await connection.query("SELECT state FROM conversation_space_authorities WHERE space_uri = ?", [.text(space.rawValue)])
                if let row = existing.first {
                    guard row.column("state")?.string == "active" else { throw AuthorizedSimpleSpaceLifecycleError.deleted }
                    return
                }
                _ = try await connection.query("""
                    INSERT INTO conversation_space_authorities(space_uri, authority_did, generation, state, created_at, updated_at)
                    VALUES (?, ?, ?, 'active', ?, ?)
                    """, [.text(space.rawValue), .text(accountDID), .text(space.skey), .integer(timestamp), .integer(timestamp)])
            }
        }
    }

    public func requireConversationSpaceActive(space: SpaceURI) async throws {
        try validateConversationAuthority(space)
        try await withReadConnectionGate {
            let rows = try await readConnection.query("SELECT state FROM conversation_space_authorities WHERE space_uri = ? AND authority_did = ? AND generation = ?",
                [.text(space.rawValue), .text(accountDID), .text(space.skey)])
            guard let row = rows.first else { throw AuthorizedSimpleSpaceLifecycleError.notFound }
            guard row.column("state")?.string == "active" else { throw AuthorizedSimpleSpaceLifecycleError.deleted }
        }
    }

    public func beginConversationSpaceDeletion(space: SpaceURI, authorization: AuthorizationContext, now: Date = Date()) async throws -> ConversationSpaceDeletion {
        try validateConversationAuthority(space)
        try SpaceAuthorizationPolicy.requireManagement(space: space, authorization: authorization, operation: .delete)
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query("SELECT state, deletion_event_id FROM conversation_space_authorities WHERE space_uri = ?", [.text(space.rawValue)])
                if let row = rows.first, row.column("state")?.string != "active" {
                    guard let event = row.column("deletion_event_id")?.string else {
                        throw SQLiteRepositoryError.corruptDatabase("conversation deletion identity missing")
                    }
                    return try ConversationSpaceDeletion(space: space, eventID: event)
                }
                let event = UUID().uuidString.lowercased()
                _ = try await connection.query("""
                    INSERT INTO conversation_space_authorities(space_uri, authority_did, generation, state, deletion_event_id, deletion_started_at, created_at, updated_at)
                    VALUES (?, ?, ?, 'deleting', ?, ?, ?, ?)
                    ON CONFLICT(space_uri) DO UPDATE SET state = 'deleting', deletion_event_id = excluded.deletion_event_id,
                        deletion_started_at = excluded.deletion_started_at, updated_at = MAX(updated_at, excluded.updated_at)
                    """, [.text(space.rawValue), .text(accountDID), .text(space.skey), .text(event), .integer(timestamp), .integer(timestamp), .integer(timestamp)])
                // Stop queued repository updates as soon as deletion begins;
                // the reliable deletion notice is queued only after DS succeeds.
                _ = try await connection.query(
                    """
                    DELETE FROM permissioned_space_sync_notifications
                    WHERE space_uri = ? AND kind IN ('repoWrite', 'repoRemoved')
                    """,
                    [.text(space.rawValue)]
                )
                return try ConversationSpaceDeletion(space: space, eventID: event)
            }
        }
    }

    public func pendingConversationSpaceDeletions(authority: String) async throws -> [ConversationSpaceDeletion] {
        guard authority == accountDID else { throw SwanError.unauthorized("conversation authority belongs to another account") }
        return try await withReadConnectionGate {
            let rows = try await readConnection.query("""
                SELECT space_uri, deletion_event_id FROM conversation_space_authorities
                WHERE authority_did = ? AND state = 'deleting' ORDER BY updated_at, space_uri LIMIT 256
                """, [.text(authority)])
            return try rows.map { row in
                guard let raw = row.column("space_uri")?.string, let event = row.column("deletion_event_id")?.string else {
                    throw SQLiteRepositoryError.corruptDatabase("conversation deletion identity missing")
                }
                return try ConversationSpaceDeletion(space: SpaceURI(raw), eventID: event)
            }
        }
    }

    public func deferConversationSpaceDeletion(_ deletion: ConversationSpaceDeletion, now: Date) async throws {
        try validateConversationAuthority(deletion.space)
        let timestamp = try simpleSpaceTimestamp(now)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query("""
                    UPDATE conversation_space_authorities SET updated_at = MAX(updated_at, ?)
                    WHERE space_uri = ? AND state = 'deleting' AND deletion_event_id = ?
                    """, [.integer(timestamp), .text(deletion.space.rawValue), .text(deletion.eventID)])
            }
        }
    }

    public func finishConversationSpaceDeletion(_ deletion: ConversationSpaceDeletion, now: Date = Date()) async throws {
        try validateConversationAuthority(deletion.space)
        let timestamp = try simpleSpaceTimestamp(now)
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query("SELECT state, deletion_event_id FROM conversation_space_authorities WHERE space_uri = ?", [.text(deletion.space.rawValue)])
                guard let row = rows.first, row.column("deletion_event_id")?.string == deletion.eventID,
                      let state = row.column("state")?.string, state == "deleting" || state == "deleted" else {
                    throw SwanError.unauthorized("conversation deletion intent mismatch")
                }
                if state == "deleted" {
                    return
                }
                _ = try await connection.query("UPDATE conversation_space_authorities SET state = 'deleted', updated_at = MAX(updated_at, ?) WHERE space_uri = ?",
                    [.integer(timestamp), .text(deletion.space.rawValue)])
                _ = try await connection.query("DELETE FROM permissioned_space_writers WHERE space_uri = ?", [.text(deletion.space.rawValue)])
                try await deleteAuthorityRepositoryWithoutGate(space: deletion.space)
                try await enqueueSpaceDeletedNotificationsWithoutGate(
                    space: deletion.space,
                    timestamp: timestamp
                )
            }
        }
        try await recoverPrivateBlobLifecycle()
    }

    func validateConversationAuthority(_ space: SpaceURI) throws {
        guard space.authority == accountDID, space.spaceType == "blue.catbird.labyrinth.conversation",
              let generation = UUID(uuidString: space.skey), generation.uuidString.lowercased() == space.skey else {
            throw SwanError.unauthorized("invalid conversation authority generation")
        }
    }

    /// Called only with the writer connection gate already held.
    func requireConversationSpaceActiveWithoutGate(_ space: SpaceURI) async throws {
        try validateConversationAuthority(space)
        let rows = try await connection.query("SELECT state FROM conversation_space_authorities WHERE space_uri = ?", [.text(space.rawValue)])
        guard let row = rows.first else { throw AuthorizedSimpleSpaceLifecycleError.notFound }
        guard row.column("state")?.string == "active" else { throw AuthorizedSimpleSpaceLifecycleError.deleted }
    }

    func migrateConversationDeletionRecipientsIfNeeded() async throws {
        let columns = try await connection.query("PRAGMA table_info(conversation_space_authorities)")
        if !columns.contains(where: { $0.column("name")?.string == "deletion_started_at" }) {
            _ = try await connection.query("ALTER TABLE conversation_space_authorities ADD COLUMN deletion_started_at INTEGER CHECK(deletion_started_at >= 0)")
        }
        _ = try await connection.query("""
            UPDATE conversation_space_authorities SET deletion_started_at = updated_at
            WHERE state != 'active' AND deletion_started_at IS NULL
            """)
        // v30 discards the retired deletion-recipient snapshots and queues
        // deletion directly from the new endpoint/token registrations.
    }

}
