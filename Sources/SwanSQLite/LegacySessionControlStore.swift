import Foundation
import SQLiteNIO
import SwanCore
import SwanStorage

/// Durable implementation of the canonical main legacy-session family.
///
/// Access and refresh rows live in `legacy_session_tokens`, beside exactly one
/// `legacy_session_families` authority. OAuth token families remain separate:
/// they require DPoP binding, while these bearer sessions never add a nullable
/// DPoP column to OAuth state.
extension SQLiteControlDatabase: LegacySessionStore {
    public func createLegacySessionFamily(
        familyID: String,
        did: String,
        appPasswordID: String?,
        accessDigest: Data,
        accessExpiresAt: Date,
        refreshDigest: Data,
        refreshExpiresAt: Date,
        now: Date
    ) async throws {
        guard accessDigest.count == 32, refreshDigest.count == 32 else {
            throw SwanError.malformed("legacy session digest")
        }
        let createdAt = try legacySessionTimestamp(now)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    """
                    INSERT INTO legacy_session_families
                        (family_id, did, app_password_id, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    [
                        .text(familyID),
                        .text(did),
                        appPasswordID.map(SQLiteData.text) ?? .null,
                        .integer(createdAt),
                    ]
                )
                try await insertLegacyToken(
                    digest: accessDigest,
                    familyID: familyID,
                    kind: .access,
                    expiresAt: accessExpiresAt
                )
                try await insertLegacyToken(
                    digest: refreshDigest,
                    familyID: familyID,
                    kind: .refresh,
                    expiresAt: refreshExpiresAt
                )
            }
        }
    }

    public func legacyAccessSession(digest: Data, now: Date) async throws -> LegacySessionFamily? {
        guard digest.count == 32 else { return nil }
        let instant = try legacySessionTimestamp(now)
        return try await withConnectionGate { () -> LegacySessionFamily? in
            let rows = try await connection.query(
                """
                SELECT f.family_id, f.did, f.app_password_id, f.created_at, f.revoked_at
                FROM legacy_session_tokens AS t
                JOIN legacy_session_families AS f ON f.family_id = t.family_id
                WHERE t.digest = ?
                  AND t.kind = 'access'
                  AND t.expires_at > ?
                  AND t.consumed_at IS NULL
                  AND f.revoked_at IS NULL
                LIMIT 1
                """,
                [digest.sqliteData!, .integer(instant)]
            )
            guard let row = rows.first else { return nil }
            return try legacySessionFamily(row)
        }
    }

    public func legacyRefreshSession(digest: Data, now: Date) async throws -> LegacyRefreshResolution {
        guard digest.count == 32 else { return .rejected }
        let instant = try legacySessionTimestamp(now)
        return try await withConnectionGate { () -> LegacyRefreshResolution in
            // Do not filter consumed rows: they are the replay evidence that
            // distinguishes a captured refresh token from an unknown token.
            let rows = try await connection.query(
                """
                SELECT t.consumed_at,
                       f.family_id, f.did, f.app_password_id, f.created_at, f.revoked_at
                FROM legacy_session_tokens AS t
                JOIN legacy_session_families AS f ON f.family_id = t.family_id
                WHERE t.digest = ?
                  AND t.kind = 'refresh'
                  AND t.expires_at > ?
                LIMIT 1
                """,
                [digest.sqliteData!, .integer(instant)]
            )
            guard let row = rows.first else { return .rejected }
            let family = try legacySessionFamily(row)
            guard family.revokedAt == nil else { return .rejected }
            guard let consumed = row.column("consumed_at"), consumed.isNull else {
                return .reused(family)
            }
            return .active(family)
        }
    }

    public func rotateLegacySession(
        familyID: String,
        consuming refreshDigest: Data,
        accessDigest: Data,
        accessExpiresAt: Date,
        replacementRefreshDigest: Data,
        replacementRefreshExpiresAt: Date,
        now: Date
    ) async throws -> Bool {
        guard refreshDigest.count == 32,
              accessDigest.count == 32,
              replacementRefreshDigest.count == 32 else { return false }
        let instant = try legacySessionTimestamp(now)
        return try await withConnectionGate { () -> Bool in
            try await transaction {
                // The conditional UPDATE is the single-use concurrency gate.
                // RETURNING makes the winner explicit even when two callers
                // share an identical clock value.
                let claimed = try await connection.query(
                    """
                    UPDATE legacy_session_tokens
                    SET consumed_at = ?
                    WHERE digest = ?
                      AND family_id = ?
                      AND kind = 'refresh'
                      AND consumed_at IS NULL
                    RETURNING digest
                    """,
                    [
                        .integer(instant),
                        refreshDigest.sqliteData!,
                        .text(familyID),
                    ]
                )
                guard claimed.count == 1 else { return false }

                try await insertLegacyToken(
                    digest: accessDigest,
                    familyID: familyID,
                    kind: .access,
                    expiresAt: accessExpiresAt
                )
                try await insertLegacyToken(
                    digest: replacementRefreshDigest,
                    familyID: familyID,
                    kind: .refresh,
                    expiresAt: replacementRefreshExpiresAt
                )
                return true
            }
        }
    }

    public func revokeLegacySessionFamily(familyID: String, now: Date) async throws {
        let instant = try legacySessionTimestamp(now)
        try await withConnectionGate {
            try await transaction {
                // Keep the family row as durable replay/revocation evidence;
                // delete its token material so no credential remains usable.
                _ = try await connection.query(
                    "UPDATE legacy_session_families SET revoked_at = COALESCE(revoked_at, ?) WHERE family_id = ?",
                    [.integer(instant), .text(familyID)]
                )
                _ = try await connection.query(
                    "DELETE FROM legacy_session_tokens WHERE family_id = ?",
                    [.text(familyID)]
                )
            }
        }
    }

    public func revokeLegacySessionFamily(familyID: String, did: String, now: Date) async throws {
        guard !did.isEmpty else { throw AccountControlStoreError.invalidInput }
        let instant = try legacySessionTimestamp(now)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    "UPDATE legacy_session_families SET revoked_at = COALESCE(revoked_at, ?) WHERE family_id = ? AND did = ?",
                    [.integer(instant), .text(familyID), .text(did)]
                )
                _ = try await connection.query(
                    "DELETE FROM legacy_session_tokens WHERE family_id = ? AND family_id IN (SELECT family_id FROM legacy_session_families WHERE did = ?)",
                    [.text(familyID), .text(did)]
                )
            }
        }
    }

    public func legacySessionFamilies(did: String, now: Date) async throws -> [LegacySessionFamilyMetadata] {
        guard !did.isEmpty else { throw AccountControlStoreError.invalidInput }
        let instant = try legacySessionTimestamp(now)
        return try await withConnectionGate { () -> [LegacySessionFamilyMetadata] in
            let rows = try await connection.query(
                """
                SELECT f.family_id, f.did, f.app_password_id, f.created_at,
                       f.revoked_at, f.reuse_detected_at,
                       MAX(t.expires_at) AS family_expires_at
                FROM legacy_session_families AS f
                LEFT JOIN legacy_session_tokens AS t ON t.family_id = f.family_id
                WHERE f.did = ?
                  AND f.revoked_at IS NULL
                  AND (t.expires_at IS NULL OR t.expires_at > ?)
                GROUP BY f.family_id
                ORDER BY f.created_at
                """,
                [.text(did), .integer(instant)]
            )
            return try rows.map { row -> LegacySessionFamilyMetadata in
                guard case let .text(familyID) = row.column("family_id"),
                      case let .text(accountDID) = row.column("did"),
                      case let .integer(createdAt) = row.column("created_at") else {
                    throw AccountControlStoreError.malformedRecord
                }
                let appPasswordID = optionalLegacyText(row.column("app_password_id"))
                let revokedAt = optionalLegacyDate(row.column("revoked_at"))
                let reuseDetectedAt = optionalLegacyDate(row.column("reuse_detected_at"))
                // The family projection's expiry is the latest live token
                // expiry; a family with no live tokens is already excluded.
                let expiry = row.column("family_expires_at").flatMap { value -> Date? in
                    guard case let .integer(raw) = value, raw >= 0 else { return nil }
                    return Date(timeIntervalSince1970: Double(raw) / 1_000_000)
                } ?? Date(timeIntervalSince1970: Double(createdAt) / 1_000_000)
                return try LegacySessionFamilyMetadata(
                    familyID: familyID,
                    accountDID: accountDID,
                    appPasswordID: appPasswordID,
                    createdAt: Date(timeIntervalSince1970: Double(createdAt) / 1_000_000),
                    expiresAt: expiry,
                    revokedAt: revokedAt,
                    reuseDetectedAt: reuseDetectedAt
                )
            }
        }
    }

    public func createLegacySessionFamilyConsumingGrant(
        familyID: String,
        did: String,
        appPasswordID: String?,
        accessDigest: Data,
        accessExpiresAt: Date,
        refreshDigest: Data,
        refreshExpiresAt: Date,
        authorizationGrantDigest: Data,
        authorizationContext: AccountAuthorizationContext,
        now: Date
    ) async throws {
        guard accessDigest.count == 32, refreshDigest.count == 32,
              authorizationGrantDigest.count == 32,
              authorizationContext.channel == .legacy,
              authorizationContext.purpose == "managementLogin" else {
            throw SwanError.malformed("legacy session grant")
        }
        let createdAt = try legacySessionTimestamp(now)
        try await withConnectionGate {
            try await ensureTask7DurableTables()
            try await transaction {
                do {
                    _ = try await consumeAuthorizationGrantLocked(
                        grantDigest: authorizationGrantDigest,
                        accountDID: did,
                        context: authorizationContext,
                        now: now
                    )
                } catch {
                    // A missing, replayed, expired, revision-mismatched, or
                    // wrong-channel/wrong-purpose grant aborts this
                    // transaction: no legacy session family is created.
                    throw AccountControlStoreError.invalidTransition
                }
                _ = try await connection.query(
                    """
                    INSERT INTO legacy_session_families
                        (family_id, did, app_password_id, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    [
                        .text(familyID),
                        .text(did),
                        appPasswordID.map(SQLiteData.text) ?? .null,
                        .integer(createdAt),
                    ]
                )
                try await insertLegacyToken(
                    digest: accessDigest,
                    familyID: familyID,
                    kind: .access,
                    expiresAt: accessExpiresAt
                )
                try await insertLegacyToken(
                    digest: refreshDigest,
                    familyID: familyID,
                    kind: .refresh,
                    expiresAt: refreshExpiresAt
                )
            }
        }
    }

    public func pruneLegacySessions(now: Date) async throws {
        let instant = try legacySessionTimestamp(now)
        _ = try await withConnectionGate {
            try await connection.query(
                "DELETE FROM legacy_session_tokens WHERE expires_at <= ?",
                [.integer(instant)]
            )
        }
    }

    private func insertLegacyToken(
        digest: Data,
        familyID: String,
        kind: LegacySessionTokenKind,
        expiresAt: Date
    ) async throws {
        _ = try await connection.query(
            """
            INSERT INTO legacy_session_tokens (digest, family_id, kind, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            [
                digest.sqliteData!,
                .text(familyID),
                .text(kind.rawValue),
                .integer(try legacySessionTimestamp(expiresAt)),
            ]
        )
    }

    private func legacySessionFamily(_ row: SQLiteRow) throws -> LegacySessionFamily {
        guard case let .text(familyID) = row.column("family_id"),
              case let .text(did) = row.column("did"),
              case let .integer(createdAt) = row.column("created_at") else {
            throw AccountControlStoreError.malformedRecord
        }
        var appPasswordID: String?
        if let value = row.column("app_password_id"), !value.isNull {
            guard case let .text(identifier) = value else {
                throw AccountControlStoreError.malformedRecord
            }
            appPasswordID = identifier
        }
        var revokedAt: Date?
        if let value = row.column("revoked_at"), !value.isNull {
            guard case let .integer(stamp) = value else {
                throw AccountControlStoreError.malformedRecord
            }
            revokedAt = Self.date(stamp)
        }
        return LegacySessionFamily(
            familyID: familyID,
            did: did,
            appPasswordID: appPasswordID,
            createdAt: Self.date(createdAt),
            revokedAt: revokedAt
        )
    }

    private func legacySessionTimestamp(_ date: Date) throws -> Int {
        let microseconds = date.timeIntervalSince1970 * 1_000_000
        guard microseconds.isFinite,
              microseconds >= 0,
              microseconds <= Double(Int.max) else {
            throw SwanError.malformed("legacy session timestamp is out of range")
        }
        return Int(microseconds.rounded(.down))
    }

    private static func date(_ value: Int) -> Date {
        Date(timeIntervalSince1970: Double(value) / 1_000_000)
    }
}

private func optionalLegacyDate(_ value: SQLiteData?) -> Date? {
    guard let value, !value.isNull else { return nil }
    guard case let .integer(raw) = value, raw >= 0 else { return nil }
    return Date(timeIntervalSince1970: Double(raw) / 1_000_000)
}

private func optionalLegacyText(_ value: SQLiteData?) -> String? {
    guard let value, !value.isNull else { return nil }
    guard case let .text(text) = value else { return nil }
    return text
}
