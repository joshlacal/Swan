import Foundation
import SQLiteNIO
import SwanCore
import SwanSpaces
import SwanStorage

/// The space revisions a space host assigned to one accepted writer update
/// (atproto#5574). `previousSpaceRevision` is the space's preceding accepted
/// update, `nil` for the first one, and becomes a forwarded `prevSpaceRev`.
public struct SpaceWriterSequence: Sendable, Equatable {
    public let spaceRevision: String
    public let previousSpaceRevision: String?

    public init(spaceRevision: String, previousSpaceRevision: String?) {
        self.spaceRevision = spaceRevision
        self.previousSpaceRevision = previousSpaceRevision
    }
}

/// TID arithmetic for space revisions. A TID is 13 base32-sortable
/// characters encoding a 64-bit value (53-bit microsecond timestamp, 10-bit
/// clock ID). Fixed width makes string order equal numeric order, so SQLite's
/// binary TEXT comparison pages correctly.
enum SpaceRevisionSequence {
    private static let alphabet = Array("234567abcdefghijklmnopqrstuvwxyz".utf8)
    private static let length = 13
    /// Petrel's `TID` accepts only a leading character in `234567`, i.e.
    /// values below `6 << 60`. Allocation never goes past the largest one.
    static let maximumValue: UInt64 = (6 << 60) - 1

    static func value(of tid: String) -> UInt64? {
        let bytes = Array(tid.utf8)
        guard bytes.count == length else { return nil }
        var result: UInt64 = 0
        for (index, byte) in bytes.enumerated() {
            guard let digit = alphabet.firstIndex(of: byte) else { return nil }
            // 13 digits carry 65 bits; the leading one is bounded first so
            // the shifts below can never discard a set bit.
            if index == 0, digit >= 6 { return nil }
            result = (result << 5) | UInt64(digit)
        }
        return result
    }

    static func string(_ value: UInt64) -> String {
        var characters = [UInt8](repeating: alphabet[0], count: length)
        var remaining = value
        for index in stride(from: length - 1, through: 0, by: -1) {
            characters[index] = alphabet[Int(remaining & 31)]
            remaining >>= 5
        }
        return String(decoding: characters, as: UTF8.self)
    }

    /// The TID for `date` with clock ID 0, clamped to the valid range.
    static func value(at date: Date) -> UInt64 {
        let micros = date.timeIntervalSince1970 * 1_000_000
        guard micros.isFinite, micros > 0 else { return 0 }
        let maximumMicros = Double(maximumValue >> 10)
        return UInt64(min(micros, maximumMicros).rounded(.down)) << 10
    }

    /// The reference's `TID.nextStr(prev)`: the clock's TID when it is newer
    /// than `previous`, else `previous + 1`. Strictly greater than `previous`
    /// even when the clock runs backwards or a stored revision is ahead.
    static func next(after previous: String?, now: Date) throws -> String {
        let clock = value(at: now)
        guard let previous else { return string(clock) }
        guard let previousValue = value(of: previous) else {
            throw SQLiteRepositoryError.corruptDatabase("invalid space revision")
        }
        if clock > previousValue { return string(clock) }
        guard previousValue < maximumValue else {
            throw SwanError.unavailable("space revision range is exhausted")
        }
        return string(previousValue + 1)
    }

    /// Deterministic backfill for writer rows recorded before space
    /// revisions existed. Rows are taken in `(repoRev, did)` order; each gets
    /// its own repoRev when that keeps the sequence strictly increasing,
    /// otherwise the predecessor plus one. RepoRevs beyond `ceiling` (the
    /// FutureRev horizon at migration time) are clamped so a stored far-future
    /// revision cannot exhaust the space's revision range.
    static func backfill(
        repoRevisions: [String],
        after floor: String?,
        ceiling: Date
    ) throws -> [String] {
        var previous: UInt64?
        if let floor {
            guard let floorValue = value(of: floor) else {
                throw SQLiteRepositoryError.corruptDatabase("invalid space revision")
            }
            previous = floorValue
        }
        let ceilingValue = value(at: ceiling)
        return try repoRevisions.map { repoRevision in
            guard let repoValue = value(of: repoRevision) else {
                throw SQLiteRepositoryError.corruptDatabase("invalid writer revision")
            }
            var candidate = min(repoValue, ceilingValue)
            if let previous, candidate <= previous {
                guard previous < maximumValue else {
                    throw SwanError.unavailable("space revision range is exhausted")
                }
                candidate = previous + 1
            }
            previous = candidate
            return string(candidate)
        }
    }
}

extension SQLiteAccountDatabase {
    static let spaceWriterSequenceMigrationVersion = 24

    /// Account-schema v24 (atproto#5574 space revisions). Adds `space_rev` to
    /// the writer set and `space_rev`/`prev_space_rev` to queued forwards,
    /// then gives every writer row without a space revision one from
    /// ``SpaceRevisionSequence/backfill(repoRevisions:after:ceiling:)``.
    /// Queued forwards from before this migration keep NULL revisions and are
    /// retired undelivered (syncers recover through `listWriters`).
    ///
    /// The columns and NULL rows are re-checked on every open instead of
    /// trusting the marker alone, because the v21 rebuild recreates the
    /// writer table with its original five columns if its marker is removed.
    /// Every step is idempotent and runs inside the caller's transaction.
    func migrateSpaceWriterSequenceIfNeeded(now: Date = Date()) async throws {
        if try await !tableHasColumn("permissioned_space_writers", "space_rev") {
            _ = try await connection.query(
                "ALTER TABLE permissioned_space_writers ADD COLUMN space_rev TEXT"
            )
        }
        for column in ["space_rev", "prev_space_rev"] {
            if try await !tableHasColumn("permissioned_space_notification_fanout", column) {
                _ = try await connection.query(
                    "ALTER TABLE permissioned_space_notification_fanout ADD COLUMN \(column) TEXT"
                )
            }
        }
        let pendingSpaces = try await connection.query(
            """
            SELECT DISTINCT space_uri FROM permissioned_space_writers
            WHERE space_rev IS NULL ORDER BY space_uri
            """
        )
        for spaceRow in pendingSpaces {
            guard let space = spaceRow.column("space_uri")?.string else {
                throw SQLiteRepositoryError.corruptDatabase("invalid writer space")
            }
            let floor = try await connection.query(
                """
                SELECT MAX(space_rev) AS floor FROM permissioned_space_writers
                WHERE space_uri = ? AND space_rev IS NOT NULL
                """,
                [.text(space)]
            ).first?.column("floor")?.string
            let rows = try await connection.query(
                """
                SELECT repo_did, wire_revision FROM permissioned_space_writers
                WHERE space_uri = ? AND space_rev IS NULL
                ORDER BY wire_revision ASC, repo_did ASC
                """,
                [.text(space)]
            )
            var repositories: [String] = []
            var repoRevisions: [String] = []
            for row in rows {
                guard let repository = row.column("repo_did")?.string,
                      let repoRevision = row.column("wire_revision")?.string else {
                    throw SQLiteRepositoryError.corruptDatabase("invalid writer row")
                }
                repositories.append(repository)
                repoRevisions.append(repoRevision)
            }
            let assigned = try SpaceRevisionSequence.backfill(
                repoRevisions: repoRevisions,
                after: floor,
                ceiling: now.addingTimeInterval(
                    AuthorizedSpaceWriteNotificationError.maximumFutureSkew
                )
            )
            for (repository, spaceRevision) in zip(repositories, assigned) {
                _ = try await connection.query(
                    """
                    UPDATE permissioned_space_writers SET space_rev = ?
                    WHERE space_uri = ? AND repo_did = ?
                    """,
                    [.text(spaceRevision), .text(space), .text(repository)]
                )
            }
        }
        // Uniqueness is what makes an exclusive `space_rev > cursor` page
        // boundary lossless; it is enforced, not assumed.
        _ = try await connection.query(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS permissioned_space_writers_space_rev
            ON permissioned_space_writers(space_uri, space_rev)
            """
        )
        _ = try await connection.query(
            """
            INSERT OR IGNORE INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(Self.spaceWriterSequenceMigrationVersion),
                .integer(Int(now.timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    /// Queues one authority-signed forward per endpoint with an active
    /// service-named registration matching `repository`. Each row carries the
    /// space revisions the space host just assigned. Endpoint-only
    /// registrations are never enqueued: with no service identity there is
    /// no audience a receiver could verify. When several services share an
    /// endpoint (SWAN-SYNC-4), the row names the lowest service key, the one
    /// the endpoint-keyed transport lookup
    /// (`spaceNotificationRegistrationService`) resolves; write forwards are
    /// reasonable-effort and syncers catch up through listWriters.
    func enqueueWriteForwardsWithoutGate(
        space: SpaceURI,
        sourceEventID: String,
        repository: String,
        wireRevision: String,
        commitment: Data,
        sequence: SpaceWriterSequence,
        timestamp: Int
    ) async throws {
        _ = try await connection.query(
            """
            INSERT INTO permissioned_space_notification_fanout(
                id, source_issuer, source_event_id, kind, space_uri,
                repo_did, wire_revision, commitment, endpoint, service_key,
                attempts, created_at, available_at,
                lease_token, lease_expires_at, space_rev, prev_space_rev
            )
            SELECT
                substr(h,1,8)||'-'||substr(h,9,4)||'-'||substr(h,13,4)
                    ||'-'||substr(h,17,4)||'-'||substr(h,21,12),
                ?, ?, 'write', ?,
                ?, ?, ?, endpoint, service_key,
                0, ?, ?, NULL, NULL, ?, ?
            FROM (
                SELECT hex(randomblob(16)) AS h, endpoint, service_key
                FROM (
                    SELECT endpoint, MIN(service_key) AS service_key
                    FROM permissioned_space_notification_registrations
                    WHERE space_uri = ?
                      AND delivery_service_did IS NOT NULL
                      AND expires_at > ?
                      AND (repo_did IS NULL OR repo_did = ?)
                    GROUP BY endpoint
                )
            )
            WHERE true
            ON CONFLICT(source_issuer, source_event_id, kind, endpoint, service_key) DO NOTHING
            """,
            [
                .text(space.authority), .text(sourceEventID),
                .text(space.rawValue),
                .text(repository),
                .text(wireRevision),
                commitment.sqliteData!,
                .integer(timestamp), .integer(timestamp),
                .text(sequence.spaceRevision),
                sequence.previousSpaceRevision.map { .text($0) } ?? .null,
                .text(space.rawValue),
                .integer(timestamp),
                .text(repository),
            ]
        )
    }

    /// Whether this authority database holds `space` as a live simple space.
    /// Only the lifecycle flag is read: a local write must not load the
    /// member list just to decide whether to sequence itself.
    func isActiveSimpleSpaceWithoutGate(_ space: SpaceURI) async throws -> Bool {
        let rows = try await connection.query(
            """
            SELECT is_deleted FROM permissioned_simple_space_authorities
            WHERE space_uri = ?
            """,
            [.text(space.rawValue)]
        )
        guard let row = rows.first else { return false }
        return row.column("is_deleted")?.integer == 0
    }

    private func tableHasColumn(_ table: String, _ column: String) async throws -> Bool {
        try await connection.query("PRAGMA table_info(\(table))").contains {
            $0.column("name")?.string == column
        }
    }

    /// The space's latest allocated revision. Each allocation is stored on the
    /// row it updated and allocations strictly increase, so the maximum over
    /// the current writer rows is the preceding accepted update.
    func latestSpaceRevisionWithoutGate(space: SpaceURI) async throws -> String? {
        let latest = try await connection.query(
            """
            SELECT space_rev FROM permissioned_space_writers
            WHERE space_uri = ? AND space_rev IS NOT NULL
            ORDER BY space_rev DESC LIMIT 1
            """,
            [.text(space.rawValue)]
        ).first?.column("space_rev")?.string
        if let latest, SpaceRevisionSequence.value(of: latest) == nil {
            throw SQLiteRepositoryError.corruptDatabase("invalid space revision")
        }
        return latest
    }
}
