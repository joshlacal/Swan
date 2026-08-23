import Foundation
import SQLiteNIO
import SwanStorage

/// Durable `app.bsky.actor` preferences in `control.sqlite`. This table is
/// intentionally the only place these documents live: preferences cannot be
/// proxied to an AppView, so this store is Swan's entire durability story for
/// them.
extension SQLiteControlDatabase: ActorPreferencesStore {
    /// The 1 MiB cap bounds what one account can store here. The HTTP layer
    /// rejects an oversized body with 400 before it ever reaches this
    /// migration's CHECK constraint.
    static let maximumActorPreferencesJSONBytes = 1_048_576

    func migrateActorPreferencesSchema() async throws {
        _ = try await connection.query(
            """
            CREATE TABLE IF NOT EXISTS actor_preferences (
                did TEXT PRIMARY KEY NOT NULL CHECK(length(did) BETWEEN 1 AND 2048),
                preferences_json BLOB NOT NULL CHECK(length(preferences_json) <= 1048576),
                updated_at INTEGER NOT NULL CHECK(updated_at >= 0)
            ) WITHOUT ROWID
            """
        )
    }

    public func actorPreferences(did: String) async throws -> Data? {
        guard AccountControlIdentifiers.isDID(did) else {
            throw AccountControlStoreError.invalidInput
        }
        return try await withConnectionGate {
            let rows = try await connection.query(
                "SELECT preferences_json FROM actor_preferences WHERE did = ?",
                [.text(did)]
            )
            guard rows.count <= 1 else {
                throw AccountControlStoreError.malformedRecord
            }
            guard let row = rows.first else { return nil }
            guard case let .blob(bytes) = row.column("preferences_json"),
                  (1 ... Self.maximumActorPreferencesJSONBytes).contains(bytes.readableBytes)
            else {
                throw AccountControlStoreError.malformedRecord
            }
            return Data(buffer: bytes)
        }
    }

    public func setActorPreferences(did: String, json: Data) async throws {
        guard AccountControlIdentifiers.isDID(did) else {
            throw AccountControlStoreError.invalidInput
        }
        guard (1 ... Self.maximumActorPreferencesJSONBytes).contains(json.count) else {
            throw AccountControlStoreError.invalidInput
        }
        let now = Int(Date().timeIntervalSince1970)
        guard now >= 0 else {
            throw AccountControlStoreError.invalidInput
        }
        try await withConnectionGate {
            try await transaction {
                let written = try await connection.query(
                    """
                    INSERT INTO actor_preferences(did, preferences_json, updated_at)
                    SELECT account.did, ?, ?
                    FROM accounts AS account
                    WHERE account.did = ? AND account.status = 'active'
                    ON CONFLICT(did) DO UPDATE SET
                        preferences_json = excluded.preferences_json,
                        updated_at = excluded.updated_at
                    RETURNING did
                    """,
                    [
                        .blob(ByteBuffer(data: json)),
                        .integer(now),
                        .text(did),
                    ]
                )
                guard let row = written.first else {
                    throw AccountControlStoreError.invalidTransition
                }
                guard written.count == 1,
                      row.column("did")?.string == did else {
                    throw AccountControlStoreError.malformedRecord
                }
            }
        }
    }
}
