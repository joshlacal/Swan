import Foundation
import SQLiteNIO

extension SQLiteAccountDatabase {
    /// Account-schema v26 (SWAN-SYNC-5): index the byte-ordered record path.
    static let permissionedSpaceRecordPathIndexMigrationVersion = 26

    /// One keyset step of the STAR export: the next record of one repository
    /// after `cursor` in strict bytewise path order (October 22 section 5).
    /// The primary key orders `(collection, rkey)`, which differs from path
    /// byte order because '.' (0x2E) sorts before '/' (0x2F), so this query
    /// needs the v26 expression index to seek instead of sorting the whole
    /// repository into a temporary B-tree on every step.
    static let repositorySTARNextRecordSQL = """
        SELECT collection, rkey, cid, revision, length(value) AS value_byte_count
        FROM permissioned_space_records
        WHERE space_uri = ? AND author_did = ?
          AND CAST(collection || '/' || rkey AS BLOB) > ?
        ORDER BY CAST(collection || '/' || rkey AS BLOB)
        LIMIT 1
        """

    /// Account-schema v26. The index expression must stay textually equal to
    /// the one in ``repositorySTARNextRecordSQL`` for SQLite to use it. The
    /// statement is idempotent and re-run on every open, so a dropped index
    /// is restored; the marker records the first installation.
    func migratePermissionedSpaceRecordPathIndexIfNeeded() async throws {
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS permissioned_space_records_star_path
            ON permissioned_space_records(
                space_uri, author_did, CAST(collection || '/' || rkey AS BLOB)
            )
            """
        )
        _ = try await connection.query(
            """
            INSERT OR IGNORE INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(Self.permissionedSpaceRecordPathIndexMigrationVersion),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }
}
