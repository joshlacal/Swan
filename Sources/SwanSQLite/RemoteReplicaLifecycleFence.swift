import Foundation
import SQLiteNIO
import SwanCore
import SwanSpaces

extension SQLiteAccountDatabase {
    /// Account-schema v28 (audit SW-A): order a recipient's deletion notices
    /// against an adopted recreation of the same space URI.
    static let remoteReplicaLifecycleFenceMigrationVersion = 28

    /// Account-schema v28. Adds `authority_fence_at` to the remote replica
    /// lifecycle: the newest authority-signed time, in whole seconds, that
    /// this receiver has seen for the space. A deletion notice raises it to
    /// its service JWT's `iat`; adoption requires a credential issued after it
    /// and raises it to the credential's `iat`. Both values are signed by the
    /// space authority, so they compare on one clock. Older rows keep NULL,
    /// which leaves their behaviour unchanged. Runs inside the notification
    /// migration transaction, after the lifecycle table is installed.
    func migrateRemoteReplicaLifecycleFenceIfNeeded() async throws {
        if try await !notificationTableHasColumn("permissioned_remote_replica_lifecycles", "authority_fence_at") {
            _ = try await connection.query(
                """
                ALTER TABLE permissioned_remote_replica_lifecycles
                ADD COLUMN authority_fence_at INTEGER
                    CHECK(authority_fence_at IS NULL OR authority_fence_at >= 0)
                """
            )
        }
        _ = try await connection.query(
            """
            INSERT OR IGNORE INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(Self.remoteReplicaLifecycleFenceMigrationVersion),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    /// The space's authority fence, or `nil` when none is recorded. Caller
    /// holds the connection gate and transaction.
    func remoteReplicaAuthorityFence(space: SpaceURI) async throws -> Int64? {
        let rows = try await connection.query(
            "SELECT authority_fence_at FROM permissioned_remote_replica_lifecycles WHERE space_uri = ?",
            [.text(space.rawValue)]
        )
        guard let value = rows.first?.column("authority_fence_at"), !value.isNull else {
            return nil
        }
        guard let fence = value.integer, fence >= 0 else {
            throw SQLiteRepositoryError.corruptDatabase("remote replica lifecycle fence is invalid")
        }
        return Int64(fence)
    }

    /// Raises the space's authority fence to `issuedAt`, never lowering it.
    /// Caller holds the connection gate and transaction, and has already
    /// created the lifecycle row.
    func raiseRemoteReplicaAuthorityFence(space: SpaceURI, to issuedAt: Int64) async throws {
        _ = try await connection.query(
            """
            UPDATE permissioned_remote_replica_lifecycles
            SET authority_fence_at = MAX(COALESCE(authority_fence_at, 0), ?)
            WHERE space_uri = ?
            """,
            [.integer(Int(issuedAt)), .text(space.rawValue)]
        )
    }

    /// A JWT NumericDate in whole seconds, or `nil` for an absent or
    /// pre-epoch value, which then orders nothing.
    static func authoritySeconds(_ date: Date?) -> Int64? {
        guard let date, date.timeIntervalSince1970.isFinite, date.timeIntervalSince1970 >= 0,
              date.timeIntervalSince1970 < Double(Int64.max) else {
            return nil
        }
        return Int64(date.timeIntervalSince1970.rounded(.down))
    }
}
