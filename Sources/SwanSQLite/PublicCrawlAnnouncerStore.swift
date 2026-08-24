import Foundation
import SQLiteNIO
import SwanCore
import PetrelFirehose

/// One crawler origin's durable requestCrawl announcer state. All timestamps
/// are whole microseconds since the Unix epoch; `nextAttemptAt == nil` means
/// the origin has never been announced to.
public struct PublicCrawlAnnouncerState: Sendable, Equatable {
    public let crawlerOrigin: String
    public let attempts: Int64
    public let nextAttemptAt: Int64?
    public let lastAttemptAt: Int64?
    public let lastSuccessAt: Int64?

    public init(
        crawlerOrigin: String,
        attempts: Int64,
        nextAttemptAt: Int64?,
        lastAttemptAt: Int64?,
        lastSuccessAt: Int64?
    ) {
        self.crawlerOrigin = crawlerOrigin
        self.attempts = attempts
        self.nextAttemptAt = nextAttemptAt
        self.lastAttemptAt = lastAttemptAt
        self.lastSuccessAt = lastSuccessAt
    }
}

/// Durable per-crawler requestCrawl announcement state in `control.sqlite`.
/// Each row records the consecutive-failure counter and the microsecond
/// schedules that keep a healthy crawler on a 24 h refresh, a failing crawler
/// on exponential backoff, and both free of per-sequenced-event hammering.
/// The announcer performs HTTP strictly outside every store call, so this
/// store only ever sees outcomes after the transport decision.
extension SQLiteControlDatabase {
    func migratePublicCrawlAnnouncerSchema() async throws {
        _ = try await connection.query(
            """
            CREATE TABLE IF NOT EXISTS public_crawl_announcer_state (
                crawler_origin TEXT PRIMARY KEY CHECK(length(crawler_origin) > 0),
                attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                next_attempt_at INTEGER,
                last_attempt_at INTEGER,
                last_success_at INTEGER
            );
            """
        )
    }

    /// All durable announcer state, ordered by origin for deterministic
    /// passes. A configured crawler with no row has never been announced to.
    public func crawlAnnouncerStates() async throws -> [PublicCrawlAnnouncerState] {
        try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT crawler_origin, attempts, next_attempt_at,
                       last_attempt_at, last_success_at
                FROM public_crawl_announcer_state
                ORDER BY crawler_origin
                """
            )
            return try rows.map { row in
                guard let crawlerOrigin = row.column("crawler_origin")?.string,
                      !crawlerOrigin.isEmpty,
                      case let .integer(attempts)? = row.column("attempts"),
                      attempts >= 0 else {
                    throw SwanError.malformed(
                        "public crawl announcer state row is invalid"
                    )
                }
                return PublicCrawlAnnouncerState(
                    crawlerOrigin: crawlerOrigin,
                    attempts: Int64(attempts),
                    nextAttemptAt: try optionalCrawlAnnouncerMicros(
                        row, "next_attempt_at"
                    ),
                    lastAttemptAt: try optionalCrawlAnnouncerMicros(
                        row, "last_attempt_at"
                    ),
                    lastSuccessAt: try optionalCrawlAnnouncerMicros(
                        row, "last_success_at"
                    )
                )
            }
        }
    }

    /// Records one announce outcome as an upsert: a success resets the
    /// consecutive-failure counter and stamps `last_success_at`; a failure
    /// increments the counter and keeps the previous success stamp.
    public func recordCrawlAnnounceOutcome(
        origin: String,
        success: Bool,
        now: Date,
        nextAttemptAt: Date
    ) async throws {
        guard !origin.isEmpty, origin.utf8.count <= 2_048,
              !origin.utf8.contains(0) else {
            throw SwanError.malformed("public crawl announcer origin is invalid")
        }
        let successFlag = success ? 1 : 0
        let nowMicros = try PublicFirehoseTime.microseconds(now)
        let nextMicros = try PublicFirehoseTime.microseconds(nextAttemptAt)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    """
                    INSERT INTO public_crawl_announcer_state(
                        crawler_origin, attempts, next_attempt_at,
                        last_attempt_at, last_success_at
                    ) VALUES (
                        ?, CASE WHEN ? THEN 0 ELSE 1 END, ?, ?,
                        CASE WHEN ? THEN ? ELSE NULL END
                    )
                    ON CONFLICT(crawler_origin) DO UPDATE SET
                        attempts = CASE WHEN ? THEN 0 ELSE attempts + 1 END,
                        next_attempt_at = ?,
                        last_attempt_at = ?,
                        last_success_at =
                            CASE WHEN ? THEN ? ELSE last_success_at END
                    """,
                    [
                        .text(origin),
                        .integer(successFlag),
                        .integer(Int(nextMicros)),
                        .integer(Int(nowMicros)),
                        .integer(successFlag),
                        .integer(Int(nowMicros)),
                        .integer(successFlag),
                        .integer(Int(nextMicros)),
                        .integer(Int(nowMicros)),
                        .integer(successFlag),
                        .integer(Int(nowMicros)),
                    ]
                )
            }
        }
    }

    private func optionalCrawlAnnouncerMicros(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> Int64? {
        guard let value = row.column(column) else {
            throw SwanError.malformed("public crawl announcer state row is invalid")
        }
        if value.isNull { return nil }
        guard case let .integer(micros) = value else {
            throw SwanError.malformed("public crawl announcer state row is invalid")
        }
        return Int64(micros)
    }
}
