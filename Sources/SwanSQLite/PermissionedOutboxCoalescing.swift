import Foundation
import SQLiteNIO
import SwanCore
import SwanSpaces

extension SQLiteAccountDatabase {
    /// Account-schema v25 (SWAN-SYNC-2): coalesce the notifyRepoUpdate outbox.
    static let permissionedOutboxCoalescingMigrationVersion = 25

    /// How long the repo host keeps retrying the newest state of one
    /// `(space, author)` pair. Bluesky retries for up to 24 hours per newer
    /// revision and resets the deadline when newer state arrives (October 1
    /// section 3). A row's `created_at` is the commit time of the newest
    /// state, because coalescing replaces older rows on every commit.
    public static let permissionedOutboxRetryWindow: TimeInterval = 24 * 60 * 60

    /// Removes rows that a newer commit to the same `(space, author)` pair
    /// supersedes. The delivery transport always announces the pair's
    /// current repository state, so one row per pair carries everything an
    /// older row would. A row under a live lease stays: its worker completes
    /// or fails it by lease token, and the newer row is delivered after it.
    /// Called with the writer connection gate and a transaction held, just
    /// before the newer row is inserted.
    func coalesceSupersededOutboxRowsWithoutGate(
        space: SpaceURI,
        author: String,
        now: Int
    ) async throws {
        _ = try await connection.query(
            """
            DELETE FROM permissioned_space_outbox
            WHERE space_uri = ? AND author_did = ?
              AND (lease_token IS NULL OR lease_expires_at <= ?)
            """,
            [.text(space.rawValue), .text(author), .integer(now)]
        )
    }

    /// Drops rows whose newest state is older than the retry window and that
    /// no live lease holds. A newer commit replaces the row and so restarts
    /// the window with a fresh attempt count. Called with the writer
    /// connection gate and a transaction held, before a row is leased.
    func expireOutboxRowsWithoutGate(now: Int, retryWindow: TimeInterval) async throws {
        guard retryWindow.isFinite, retryWindow > 0 else {
            throw SwanError.malformed("outbox retry window must be positive")
        }
        let cutoff = now - Int(min(retryWindow * 1_000_000, Double(now)))
        _ = try await connection.query(
            """
            DELETE FROM permissioned_space_outbox
            WHERE created_at <= ?
              AND (lease_token IS NULL OR lease_expires_at <= ?)
            """,
            [.integer(cutoff), .integer(now)]
        )
    }

    /// Account-schema v25. Keeps the newest unleased row per `(space,
    /// author)` pair and every leased row, and indexes the pair so the
    /// per-commit coalescing delete is a range seek. Runs inside the base
    /// migration transaction.
    func migratePermissionedOutboxCoalescingIfNeeded() async throws {
        let version = Self.permissionedOutboxCoalescingMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS permissioned_space_outbox_pair
            ON permissioned_space_outbox(space_uri, author_did)
            """
        )
        _ = try await connection.query(
            """
            DELETE FROM permissioned_space_outbox
            WHERE lease_token IS NULL
              AND id IN (
                  SELECT id FROM (
                      SELECT id, ROW_NUMBER() OVER (
                          PARTITION BY space_uri, author_did
                          ORDER BY revision DESC, created_at DESC, id DESC
                      ) AS position
                      FROM permissioned_space_outbox
                      WHERE lease_token IS NULL
                  )
                  WHERE position > 1
              )
            """
        )
        _ = try await connection.query(
            "INSERT INTO permissioned_repository_migrations(version, applied_at) VALUES (?, ?)",
            [
                .integer(version),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }
}
