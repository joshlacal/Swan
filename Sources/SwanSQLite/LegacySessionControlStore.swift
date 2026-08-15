import Foundation
import SQLiteNIO
import SwanCore
import SwanStorage

/// Legacy (app-password) session families, in the control database.
///
/// Modelled on the OAuth token families and reusing their design — family,
/// rotation, reuse detection, family-wide revocation, digests at rest, never
/// plaintext — but deliberately a SIBLING rather than an extension of them.
/// `DurableOAuthTokenService.validateAccess` hard-requires a DPoP thumbprint on
/// the token family; bolting a nullable one on to admit bearer sessions would
/// weaken the invariant that makes every OAuth token sender-constrained.
extension SQLiteControlDatabase: LegacySessionStore {
    public func createLegacySessionFamily(
        familyID: String,
        did: String,
        appPasswordID: String,
        accessDigest: Data,
        accessExpiresAt: Date,
        refreshDigest: Data,
        refreshExpiresAt: Date,
        now: Date
    ) async throws {
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
                        .text(appPasswordID),
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
                """,
                [digest.sqliteData!, .integer(instant)]
            )
            guard let row = rows.first else { return nil }
            return try legacySessionFamily(row)
        }
    }

    public func legacyRefreshSession(digest: Data, now: Date) async throws -> LegacyRefreshResolution {
        let instant = try legacySessionTimestamp(now)
        return try await withConnectionGate { () -> LegacyRefreshResolution in
            // Deliberately does NOT filter on `consumed_at`: a consumed token is
            // the reuse signal, and filtering it out here would make reuse
            // indistinguishable from an unknown token, silently discarding the
            // one piece of evidence that a refresh token was captured.
            let rows = try await connection.query(
                """
                SELECT t.consumed_at,
                       f.family_id, f.did, f.app_password_id, f.created_at, f.revoked_at
                FROM legacy_session_tokens AS t
                JOIN legacy_session_families AS f ON f.family_id = t.family_id
                WHERE t.digest = ?
                  AND t.kind = 'refresh'
                  AND t.expires_at > ?
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
        let instant = try legacySessionTimestamp(now)
        return try await withConnectionGate { () -> Bool in
            try await transaction {
                // The UPDATE is the concurrency gate. Two simultaneous refreshes
                // of the same token both read `.active`, but only one can move
                // `consumed_at` from NULL, so exactly one mints a replacement
                // and the loser is told to retry rather than being handed a
                // second live session.
                _ = try await connection.query(
                    """
                    UPDATE legacy_session_tokens
                    SET consumed_at = ?
                    WHERE digest = ?
                      AND kind = 'refresh'
                      AND consumed_at IS NULL
                    """,
                    [.integer(instant), refreshDigest.sqliteData!]
                )
                let claimed = try await connection.query(
                    """
                    SELECT consumed_at FROM legacy_session_tokens
                    WHERE digest = ? AND consumed_at = ?
                    """,
                    [refreshDigest.sqliteData!, .integer(instant)]
                )
                guard !claimed.isEmpty else { return false }

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
                // The family row is kept and stamped rather than deleted, so a
                // reuse detection remains visible to an operator afterwards.
                // Its tokens go, so nothing about it is presentable again.
                _ = try await connection.query(
                    "UPDATE legacy_session_families SET revoked_at = ? WHERE family_id = ?",
                    [.integer(instant), .text(familyID)]
                )
                _ = try await connection.query(
                    "DELETE FROM legacy_session_tokens WHERE family_id = ?",
                    [.text(familyID)]
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
              case let .text(appPasswordID) = row.column("app_password_id"),
              case let .integer(createdAt) = row.column("created_at") else {
            throw AccountControlStoreError.malformedRecord
        }
        var revokedAt: Date?
        if let value = row.column("revoked_at"), !value.isNull {
            guard case let .integer(stamp) = value else {
                throw AccountControlStoreError.malformedRecord
            }
            revokedAt = Date(timeIntervalSince1970: Double(stamp) / 1_000_000)
        }
        return LegacySessionFamily(
            familyID: familyID,
            did: did,
            appPasswordID: appPasswordID,
            createdAt: Date(timeIntervalSince1970: Double(createdAt) / 1_000_000),
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
}
