import Foundation
import SQLiteNIO
import SwanCore

extension SQLiteAccountDatabase {
    /// Account-schema v27 (SWAN-SYNC-4): key syncer registrations, owed
    /// conversation deletion recipients and fanout de-duplication by service
    /// identity instead of endpoint.
    static let spaceNotificationServiceKeyMigrationVersion = 27

    /// The registration identity stored in `service_key`. A service-named
    /// registration is keyed by its service identifier (a DID with an
    /// optional `#fragment`), matching the reference's
    /// `(space, serviceDid)` key; re-registering that service replaces its
    /// endpoint. A legacy endpoint-only registration has no service identity,
    /// so it keeps its endpoint key under a prefix no DID can start with.
    static let spaceNotificationServiceKeySQL =
        "COALESCE(delivery_service_did, 'endpoint:' || endpoint)"

    /// Fanout rows queued before v27 carry this empty key. Lookups match them
    /// by endpoint, which was unique per space when they were queued.
    static let legacyNotificationFanoutServiceKey = ""

    /// Account-schema v27. Rebuilds the three small notification tables
    /// whose keys named the endpoint, keeping `endpoint` as a column. Each
    /// rebuild is decided from the live schema rather than the marker alone,
    /// because older idempotent migrations may recreate a table in its prior
    /// shape. Runs inside the notification migration transaction, after v24.
    func migrateSpaceNotificationServiceKeysIfNeeded() async throws {
        if try await !notificationTableHasColumn("permissioned_space_notification_registrations", "service_key") {
            _ = try await connection.query(
                "DROP TABLE IF EXISTS permissioned_space_notification_registrations_v27"
            )
            _ = try await connection.query(
                """
                CREATE TABLE permissioned_space_notification_registrations_v27 (
                    space_uri TEXT NOT NULL,
                    service_key TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    repo_did TEXT,
                    expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
                    updated_at INTEGER NOT NULL CHECK(updated_at >= 0),
                    owner_service_did TEXT NOT NULL,
                    delivery_service_did TEXT,
                    PRIMARY KEY(space_uri, service_key),
                    CHECK(length(endpoint) > 0),
                    CHECK(service_key = \(Self.spaceNotificationServiceKeySQL))
                )
                """
            )
            // Before v27 one service could hold several endpoint rows; the
            // most recently updated one wins, as a re-registration would.
            _ = try await connection.query(
                """
                INSERT OR REPLACE INTO permissioned_space_notification_registrations_v27(
                    space_uri, service_key, endpoint, repo_did, expires_at, updated_at,
                    owner_service_did, delivery_service_did
                )
                SELECT space_uri, \(Self.spaceNotificationServiceKeySQL), endpoint, repo_did,
                    expires_at, updated_at, owner_service_did, delivery_service_did
                FROM permissioned_space_notification_registrations
                ORDER BY updated_at ASC, endpoint ASC
                """
            )
            _ = try await connection.query("DROP TABLE permissioned_space_notification_registrations")
            _ = try await connection.query(
                """
                ALTER TABLE permissioned_space_notification_registrations_v27
                RENAME TO permissioned_space_notification_registrations
                """
            )
        }
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS permissioned_space_notification_registrations_endpoint
            ON permissioned_space_notification_registrations(space_uri, endpoint)
            """
        )

        if try await !notificationTableHasColumn("conversation_space_deletion_recipients", "service_key") {
            _ = try await connection.query(
                "DROP TABLE IF EXISTS conversation_space_deletion_recipients_v27"
            )
            _ = try await connection.query(
                """
                CREATE TABLE conversation_space_deletion_recipients_v27 (
                    space_uri TEXT NOT NULL REFERENCES conversation_space_authorities(space_uri) ON DELETE CASCADE,
                    deletion_event_id TEXT NOT NULL,
                    service_key TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    owner_service_did TEXT NOT NULL,
                    delivery_service_did TEXT,
                    registration_expires_at INTEGER NOT NULL CHECK(registration_expires_at >= 0),
                    PRIMARY KEY(space_uri, service_key, endpoint),
                    CHECK(length(endpoint) > 0),
                    CHECK(service_key = \(Self.spaceNotificationServiceKeySQL))
                )
                """
            )
            _ = try await connection.query(
                """
                INSERT INTO conversation_space_deletion_recipients_v27(
                    space_uri, deletion_event_id, service_key, endpoint, owner_service_did,
                    delivery_service_did, registration_expires_at
                )
                SELECT space_uri, deletion_event_id, \(Self.spaceNotificationServiceKeySQL), endpoint,
                    owner_service_did, delivery_service_did, registration_expires_at
                FROM conversation_space_deletion_recipients
                """
            )
            _ = try await connection.query("DROP TABLE conversation_space_deletion_recipients")
            _ = try await connection.query(
                """
                ALTER TABLE conversation_space_deletion_recipients_v27
                RENAME TO conversation_space_deletion_recipients
                """
            )
        }

        if try await !notificationTableHasColumn("permissioned_space_notification_fanout", "service_key") {
            _ = try await connection.query(
                "DROP TABLE IF EXISTS permissioned_space_notification_fanout_v27"
            )
            _ = try await connection.query(
                """
                CREATE TABLE permissioned_space_notification_fanout_v27 (
                    id TEXT PRIMARY KEY,
                    source_issuer TEXT NOT NULL,
                    source_event_id TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('write', 'deleted')),
                    space_uri TEXT NOT NULL,
                    repo_did TEXT,
                    wire_revision TEXT,
                    commitment BLOB,
                    endpoint TEXT NOT NULL,
                    service_key TEXT NOT NULL DEFAULT '',
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                    created_at INTEGER NOT NULL CHECK(created_at >= 0),
                    available_at INTEGER NOT NULL CHECK(available_at >= 0),
                    lease_token TEXT,
                    lease_expires_at INTEGER,
                    space_rev TEXT,
                    prev_space_rev TEXT,
                    UNIQUE(source_issuer, source_event_id, kind, endpoint, service_key),
                    CHECK(
                        (kind = 'write' AND repo_did IS NOT NULL AND wire_revision IS NOT NULL
                            AND commitment IS NOT NULL AND length(commitment) = 32)
                        OR (kind = 'deleted' AND repo_did IS NULL AND wire_revision IS NULL
                            AND commitment IS NULL)
                    ),
                    CHECK(
                        (lease_token IS NULL AND lease_expires_at IS NULL)
                        OR (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL
                            AND lease_expires_at >= 0)
                    )
                )
                """
            )
            _ = try await connection.query(
                """
                INSERT INTO permissioned_space_notification_fanout_v27(
                    id, source_issuer, source_event_id, kind, space_uri, repo_did,
                    wire_revision, commitment, endpoint, service_key, attempts, created_at,
                    available_at, lease_token, lease_expires_at, space_rev, prev_space_rev
                )
                SELECT id, source_issuer, source_event_id, kind, space_uri, repo_did,
                    wire_revision, commitment, endpoint, ?, attempts, created_at,
                    available_at, lease_token, lease_expires_at, space_rev, prev_space_rev
                FROM permissioned_space_notification_fanout
                """,
                [.text(Self.legacyNotificationFanoutServiceKey)]
            )
            _ = try await connection.query("DROP TABLE permissioned_space_notification_fanout")
            _ = try await connection.query(
                """
                ALTER TABLE permissioned_space_notification_fanout_v27
                RENAME TO permissioned_space_notification_fanout
                """
            )
        }
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS permissioned_space_notification_fanout_available
            ON permissioned_space_notification_fanout(available_at, created_at, id)
            """
        )

        _ = try await connection.query(
            """
            INSERT OR IGNORE INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(Self.spaceNotificationServiceKeyMigrationVersion),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    func notificationTableHasColumn(_ table: String, _ column: String) async throws -> Bool {
        try await connection.query("PRAGMA table_info(\(table))").contains {
            $0.column("name")?.string == column
        }
    }
}
