import Foundation
import SQLiteNIO
import SwanStorage

extension SQLiteControlDatabase: AccountLoginAdmissionStore {
    func migrateAccountLoginAdmissionSchema() async throws {
        let currentTable = """
            CREATE TABLE IF NOT EXISTS account_login_rate_limits (
                scope TEXT NOT NULL
                    CHECK(scope IN ('handle', 'direct-peer', 'handle-peer-pair')),
                key_digest BLOB NOT NULL CHECK(length(key_digest) = 32),
                window_started_at INTEGER NOT NULL CHECK(window_started_at >= 0),
                expires_at INTEGER NOT NULL CHECK(expires_at > window_started_at),
                attempts INTEGER NOT NULL CHECK(attempts BETWEEN 1 AND 10000),
                PRIMARY KEY(scope, key_digest)
            ) WITHOUT ROWID
            """
        _ = try await connection.query(
            currentTable
        )
        let columns = try await connection.query(
            "PRAGMA table_info(account_login_rate_limits)"
        )
        let columnNames = Set(columns.compactMap { $0.column("name")?.string })
        if columnNames.contains("window_microseconds"),
           !columnNames.contains("expires_at") {
            let requiredLegacyColumns: Set<String> = [
                "scope",
                "key_digest",
                "window_started_at",
                "window_microseconds",
                "attempts",
            ]
            guard requiredLegacyColumns.isSubset(of: columnNames) else {
                throw AccountControlStoreError.malformedRecord
            }
            let invalid = try await connection.query(
                """
                SELECT 1
                FROM account_login_rate_limits
                WHERE scope NOT IN ('handle', 'direct-peer', 'handle-peer-pair')
                   OR typeof(key_digest) != 'blob'
                   OR length(key_digest) != 32
                   OR typeof(window_started_at) != 'integer'
                   OR window_started_at < 0
                   OR typeof(window_microseconds) != 'integer'
                   OR window_microseconds <= 0
                   OR window_started_at > ? - window_microseconds
                   OR typeof(attempts) != 'integer'
                   OR attempts NOT BETWEEN 1 AND 10000
                LIMIT 1
                """,
                [.integer(Int.max)]
            )
            guard invalid.isEmpty else {
                throw AccountControlStoreError.malformedRecord
            }

            // SQLite cannot replace the old window-duration column in place.
            // Rebuild atomically inside the caller's BEGIN IMMEDIATE migration
            // transaction and preserve every still-valid bucket.
            _ = try await connection.query(
                "DROP TRIGGER IF EXISTS account_login_rate_limit_count_insert"
            )
            _ = try await connection.query(
                "DROP TRIGGER IF EXISTS account_login_rate_limit_count_delete"
            )
            _ = try await connection.query(
                "DROP INDEX IF EXISTS account_login_rate_limits_expiry"
            )
            _ = try await connection.query(
                """
                ALTER TABLE account_login_rate_limits
                RENAME TO account_login_rate_limits_window_v1
                """
            )
            _ = try await connection.query(currentTable)
            _ = try await connection.query(
                """
                INSERT INTO account_login_rate_limits(
                    scope, key_digest, window_started_at, expires_at, attempts
                )
                SELECT scope, key_digest, window_started_at,
                       window_started_at + window_microseconds, attempts
                FROM account_login_rate_limits_window_v1
                """
            )
            _ = try await connection.query(
                "DROP TABLE account_login_rate_limits_window_v1"
            )
        } else {
            let requiredCurrentColumns: Set<String> = [
                "scope",
                "key_digest",
                "window_started_at",
                "expires_at",
                "attempts",
            ]
            guard requiredCurrentColumns.isSubset(of: columnNames) else {
                throw AccountControlStoreError.malformedRecord
            }
        }
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS account_login_rate_limits_expiry
            ON account_login_rate_limits(expires_at, scope, key_digest)
            """
        )
        _ = try await connection.query(
            """
            CREATE TABLE IF NOT EXISTS account_login_rate_limit_capacity (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                entry_count INTEGER NOT NULL CHECK(entry_count >= 0)
            )
            """
        )
        _ = try await connection.query(
            """
            INSERT INTO account_login_rate_limit_capacity(
                singleton, entry_count
            )
            SELECT 1, COUNT(*) FROM account_login_rate_limits WHERE 1
            ON CONFLICT(singleton) DO UPDATE SET
                entry_count = excluded.entry_count
            """
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS account_login_rate_limit_count_insert
            AFTER INSERT ON account_login_rate_limits
            BEGIN
                UPDATE account_login_rate_limit_capacity
                SET entry_count = entry_count + 1
                WHERE singleton = 1;
            END
            """
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS account_login_rate_limit_count_delete
            AFTER DELETE ON account_login_rate_limits
            BEGIN
                UPDATE account_login_rate_limit_capacity
                SET entry_count = entry_count - 1
                WHERE singleton = 1;
            END
            """
        )
    }

    public func consumeLoginRateLimit(
        _ request: AccountLoginRateLimitRequest,
        now: Date
    ) async throws -> AccountLoginRateLimitDecision {
        let timestamp = try loginTimestamp(now)
        let prepared = try request.buckets.map { bucket -> PreparedLoginBucket in
            let end = try loginTimestamp(now.addingTimeInterval(bucket.window))
            guard end > timestamp else {
                throw AccountControlStoreError.invalidInput
            }
            return PreparedLoginBucket(
                bucket: bucket,
                expiresAt: end
            )
        }

        return try await withConnectionGate {
            try await transaction {
                // The global cleanup below is intentionally capped. Remove
                // the three requested rows first so a legitimate expired
                // bucket can never survive behind more than 512 unrelated
                // expired rows and be misclassified as corrupt.
                let candidatePlaceholders = Array(repeating: "(?, ?)", count: prepared.count).joined(separator: ", ")
                var candidateDeleteParams: [SQLiteData] = []
                for candidate in prepared {
                    candidateDeleteParams.append(.text(candidate.bucket.scope.rawValue))
                    candidateDeleteParams.append(candidate.bucket.keyDigest.sqliteData!)
                }
                candidateDeleteParams.append(.integer(timestamp))

                _ = try await connection.query(
                    """
                    DELETE FROM account_login_rate_limits
                    WHERE (scope, key_digest) IN (\(candidatePlaceholders))
                      AND expires_at <= ?
                    """,
                    candidateDeleteParams
                )

                // Cleanup is deliberately bounded. A table that is still full
                // after this pass rejects new keys instead of turning one
                // login request into unbounded maintenance work.
                _ = try await connection.query(
                    """
                    DELETE FROM account_login_rate_limits
                    WHERE (scope, key_digest) IN (
                        SELECT scope, key_digest
                        FROM account_login_rate_limits
                        WHERE expires_at <= ?
                        ORDER BY expires_at, scope, key_digest
                        LIMIT 512
                    )
                    """,
                    [.integer(timestamp)]
                )

                var candidateSelectParams: [SQLiteData] = []
                for candidate in prepared {
                    candidateSelectParams.append(.text(candidate.bucket.scope.rawValue))
                    candidateSelectParams.append(candidate.bucket.keyDigest.sqliteData!)
                }

                let rows = try await connection.query(
                    """
                    SELECT scope, key_digest, window_started_at, expires_at, attempts
                    FROM account_login_rate_limits
                    WHERE (scope, key_digest) IN (\(candidatePlaceholders))
                    """,
                    candidateSelectParams
                )

                let candidateMap = Dictionary(uniqueKeysWithValues: prepared.map { ($0.bucket.scope, $0.bucket.keyDigest) })
                var existing: [AccountLoginRateLimitScope: StoredLoginBucket] = [:]
                for row in rows {
                    guard case let .text(scopeText) = row.column("scope"),
                          let scope = AccountLoginRateLimitScope(rawValue: scopeText),
                          let expectedDigest = candidateMap[scope],
                          case let .blob(digestBuffer) = row.column("key_digest"),
                          Data(buffer: digestBuffer) == expectedDigest,
                          case let .integer(startedAt) = row.column("window_started_at"),
                          case let .integer(expiresAt) = row.column("expires_at"),
                          case let .integer(attempts) = row.column("attempts"),
                          startedAt >= 0,
                          expiresAt > startedAt,
                          (1 ... 10_000).contains(attempts),
                          existing[scope] == nil else {
                        throw AccountControlStoreError.malformedRecord
                    }
                    existing[scope] = StoredLoginBucket(
                        startedAt: startedAt,
                        expiresAt: expiresAt,
                        attempts: attempts
                    )
                }

                // A denied request must not allocate missing handle/pair keys:
                // otherwise one already-limited peer could vary handles until
                // it poisoned the global capacity bound.
                if prepared.contains(where: { candidate in
                    guard let stored = existing[candidate.bucket.scope] else {
                        return false
                    }
                    return stored.expiresAt > timestamp
                        && stored.attempts >= candidate.bucket.maximumAttempts
                }) {
                    return .limited
                }

                let newEntryCount = prepared.reduce(into: 0) { count, candidate in
                    if existing[candidate.bucket.scope] == nil {
                        count += 1
                    }
                }
                if newEntryCount > 0 {
                    let rows = try await connection.query(
                        """
                        SELECT entry_count
                        FROM account_login_rate_limit_capacity
                        WHERE singleton = 1
                        """
                    )
                    guard rows.count == 1,
                          case let .integer(rowCount) =
                          rows[0].column("entry_count"),
                          rowCount >= 0 else {
                        throw AccountControlStoreError.malformedRecord
                    }
                    guard rowCount <= request.maximumEntries else {
                        throw AccountControlStoreError.malformedRecord
                    }
                    guard rowCount + newEntryCount <= request.maximumEntries else {
                        return .capacityExhausted
                    }
                }

                var limited = false
                for candidate in prepared {
                    let bucket = candidate.bucket
                    guard let stored = existing[bucket.scope] else {
                        _ = try await connection.query(
                            """
                            INSERT INTO account_login_rate_limits(
                                scope, key_digest, window_started_at,
                                expires_at, attempts
                            ) VALUES (?, ?, ?, ?, 1)
                            """,
                            [
                                .text(bucket.scope.rawValue),
                                bucket.keyDigest.sqliteData!,
                                .integer(timestamp),
                                .integer(candidate.expiresAt),
                            ]
                        )
                        continue
                    }

                    // Expired rows were removed above. Treat any survivor
                    // whose arithmetic says otherwise as corrupt rather than
                    // silently resetting attacker-controlled durable state.
                    guard stored.expiresAt > stored.startedAt,
                          stored.expiresAt > timestamp else {
                        throw AccountControlStoreError.malformedRecord
                    }
                    if stored.attempts >= bucket.maximumAttempts {
                        limited = true
                        continue
                    }
                    _ = try await connection.query(
                        """
                        UPDATE account_login_rate_limits
                        SET attempts = attempts + 1
                        WHERE scope = ? AND key_digest = ?
                        """,
                        [
                            .text(bucket.scope.rawValue),
                            bucket.keyDigest.sqliteData!,
                        ]
                    )
                }
                return limited ? .limited : .allowed
            }
        }
    }

    private func loginTimestamp(_ date: Date) throws -> Int {
        let seconds = date.timeIntervalSince1970
        guard seconds.isFinite, seconds >= 0 else {
            throw AccountControlStoreError.invalidInput
        }
        let microseconds = seconds * 1_000_000
        guard microseconds.isFinite, microseconds <= Double(Int.max) else {
            throw AccountControlStoreError.invalidInput
        }
        return Int(microseconds.rounded(.down))
    }
}

private struct PreparedLoginBucket {
    let bucket: AccountLoginRateLimitBucket
    let expiresAt: Int
}

private struct StoredLoginBucket {
    let startedAt: Int
    let expiresAt: Int
    let attempts: Int
}
