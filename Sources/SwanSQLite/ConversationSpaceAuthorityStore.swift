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
                _ = try await connection.query("""
                    INSERT INTO conversation_space_deletion_recipients(
                        space_uri, deletion_event_id, endpoint, owner_service_did, delivery_service_did, registration_expires_at)
                    SELECT space_uri, ?, endpoint, owner_service_did, delivery_service_did, expires_at
                    FROM permissioned_space_notification_registrations WHERE space_uri = ? AND expires_at > ?
                    """, [.text(event), .text(space.rawValue), .integer(timestamp)])
                // Existing or already-leased write hints become non-deliverable
                // as soon as deletion begins; deletion fanout waits for DS success.
                _ = try await connection.query("DELETE FROM permissioned_space_notification_fanout WHERE space_uri = ? AND kind = 'write'", [.text(space.rawValue)])
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
                    try await pruneCompletedDeletionRegistrationsWithoutGate(space: deletion.space)
                    return
                }
                _ = try await connection.query("UPDATE conversation_space_authorities SET state = 'deleted', updated_at = MAX(updated_at, ?) WHERE space_uri = ?",
                    [.integer(timestamp), .text(deletion.space.rawValue)])
                _ = try await connection.query("DELETE FROM permissioned_space_writers WHERE space_uri = ?", [.text(deletion.space.rawValue)])
                try await deleteAuthorityRepositoryWithoutGate(space: deletion.space)
                _ = try await connection.query("""
                    INSERT INTO permissioned_space_notification_fanout(
                        id, source_issuer, source_event_id, kind, space_uri, repo_did, wire_revision, commitment,
                        endpoint, attempts, created_at, available_at, lease_token, lease_expires_at)
                    SELECT upper(hex(randomblob(4))) || '-' || upper(hex(randomblob(2))) || '-' || upper(hex(randomblob(2))) || '-' || upper(hex(randomblob(2))) || '-' || upper(hex(randomblob(6))),
                        ?, ?, 'deleted', space_uri, NULL, NULL, NULL, endpoint, 0, ?, ?, NULL, NULL
                    FROM conversation_space_deletion_recipients WHERE space_uri = ? AND deletion_event_id = ?
                    ON CONFLICT(source_issuer, source_event_id, kind, endpoint) DO NOTHING
                    """, [.text(accountDID), .text(deletion.eventID), .integer(timestamp), .integer(timestamp), .text(deletion.space.rawValue), .text(deletion.eventID)])
                try await pruneCompletedDeletionRegistrationsWithoutGate(space: deletion.space)
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
        // Existing pending intents predate retry rotation. Their last update
        // is the begin timestamp; already queued terminal deliveries remain owed.
        _ = try await connection.query("""
            INSERT INTO conversation_space_deletion_recipients(
                space_uri, deletion_event_id, endpoint, owner_service_did, delivery_service_did, registration_expires_at)
            SELECT authority.space_uri, authority.deletion_event_id, registration.endpoint,
                registration.owner_service_did, registration.delivery_service_did, registration.expires_at
            FROM conversation_space_authorities AS authority
            JOIN permissioned_space_notification_registrations AS registration ON registration.space_uri = authority.space_uri
            WHERE (authority.state = 'deleting' AND registration.expires_at > authority.deletion_started_at)
               OR (authority.state = 'deleted' AND EXISTS (
                   SELECT 1 FROM permissioned_space_notification_fanout AS pending
                   WHERE pending.space_uri = authority.space_uri AND pending.source_event_id = authority.deletion_event_id
                     AND pending.endpoint = registration.endpoint AND pending.kind = 'deleted'))
            ON CONFLICT(space_uri, endpoint) DO NOTHING
            """)
    }

    /// Preserve every authenticated registration while removing its historical
    /// simple-space-only FK. Both authority kinds are admitted transactionally.
    func migrateConversationNotificationRegistrationForeignKeyIfNeeded() async throws {
        let references = try await connection.query("PRAGMA foreign_key_list(permissioned_space_notification_registrations)")
        guard !references.isEmpty else { return }
        _ = try await connection.query("""
            CREATE TABLE permissioned_space_notification_registrations_conversation_migration (
                space_uri TEXT NOT NULL, endpoint TEXT NOT NULL, repo_did TEXT,
                expires_at INTEGER NOT NULL CHECK(expires_at >= 0), updated_at INTEGER NOT NULL CHECK(updated_at >= 0),
                owner_service_did TEXT NOT NULL, delivery_service_did TEXT,
                PRIMARY KEY(space_uri, endpoint), CHECK(length(endpoint) > 0))
            """)
        _ = try await connection.query("""
            INSERT INTO permissioned_space_notification_registrations_conversation_migration
            SELECT space_uri, endpoint, repo_did, expires_at, updated_at, owner_service_did, delivery_service_did
            FROM permissioned_space_notification_registrations
            """)
        _ = try await connection.query("DROP TABLE permissioned_space_notification_registrations")
        _ = try await connection.query("ALTER TABLE permissioned_space_notification_registrations_conversation_migration RENAME TO permissioned_space_notification_registrations")
    }
}
