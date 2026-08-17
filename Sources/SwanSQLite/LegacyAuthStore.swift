import Foundation
import SQLiteNIO
import SwanAccounts
import SwanCore
import SwanStorage

/// Compatibility adapter for the retired account-program service.
///
/// The adapter deliberately projects the old metadata protocol onto the
/// canonical `account_app_passwords`, `legacy_session_families`, and
/// `legacy_session_tokens` tables. It does not create, read, or write the
/// account branch's never-deployed `app_passwords`/`legacy_sessions` schema;
/// production uses `AppPasswordStore` and `LegacySessionStore` directly.
extension SQLiteControlDatabase: AccountLegacyAuthStore {
    public func createAppPassword(_ metadata: AppPasswordMetadata, now: Date) async throws {
        _ = now
        try await withConnectionGate {
            try await transaction {
                let duplicate = try await connection.query(
                    "SELECT 1 FROM account_app_passwords WHERE did = ? AND name = ? LIMIT 1",
                    [.text(metadata.accountDID), .text(metadata.canonicalName)]
                )
                guard duplicate.isEmpty else {
                    throw SwanError.unauthorized("app password already exists")
                }
                _ = try await connection.query(
                    """
                    INSERT INTO account_app_passwords
                        (id, did, name, digest, scopes, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    [
                        .text(metadata.id),
                        .text(metadata.accountDID),
                        .text(metadata.canonicalName),
                        .blob(ByteBuffer(data: metadata.secretDigest)),
                        .text(Self.encodeScopes(metadata.scopeStrings)),
                        .integer(Self.microseconds(metadata.createdAt)),
                    ]
                )
            }
        }
    }

    public func appPassword(
        accountDID: String,
        canonicalName: String,
        now: Date
    ) async throws -> AppPasswordMetadata? {
        _ = now
        return try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT id, did, name, digest, scopes, created_at
                FROM account_app_passwords
                WHERE did = ? AND name = ?
                LIMIT 1
                """,
                [.text(accountDID), .text(canonicalName)]
            )
            return try rows.first.map(Self.decodeAppPassword)
        }
    }

    public func appPassword(id: String, now: Date) async throws -> AppPasswordMetadata? {
        _ = now
        return try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT id, did, name, digest, scopes, created_at
                FROM account_app_passwords
                WHERE id = ?
                LIMIT 1
                """,
                [.text(id)]
            )
            return try rows.first.map(Self.decodeAppPassword)
        }
    }

    public func listAppPasswords(accountDID: String, now: Date) async throws -> [AppPasswordMetadata] {
        _ = now
        return try await withConnectionGate {
            try await connection.query(
                """
                SELECT id, did, name, digest, scopes, created_at
                FROM account_app_passwords
                WHERE did = ?
                ORDER BY created_at, id
                """,
                [.text(accountDID)]
            ).map(Self.decodeAppPassword)
        }
    }

    public func updateAppPasswordScopes(
        accountDID: String,
        canonicalName: String,
        scopes: Set<String>,
        now: Date
    ) async throws {
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT id FROM account_app_passwords
                    WHERE did = ? AND name = ?
                    LIMIT 1
                    """,
                    [.text(accountDID), .text(canonicalName)]
                )
                guard let id = rows.first?.column("id")?.string else {
                    throw SwanError.unauthorized("app password not found")
                }
                _ = try await connection.query(
                    "UPDATE account_app_passwords SET scopes = ? WHERE did = ? AND id = ?",
                    [.text(Self.encodeScopes(scopes)), .text(accountDID), .text(id)]
                )
                // A scope edit is a credential boundary. Keep the family row
                // for replay/revocation evidence and make every derived
                // session unusable immediately.
                _ = try await connection.query(
                    """
                    UPDATE legacy_session_families
                    SET revoked_at = COALESCE(revoked_at, ?)
                    WHERE app_password_id = ?
                    """,
                    [.integer(Self.microseconds(now)), .text(id)]
                )
            }
        }
    }

    public func revokeAppPassword(
        accountDID: String,
        canonicalName: String,
        now: Date
    ) async throws {
        _ = now
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT id FROM account_app_passwords
                    WHERE did = ? AND name = ?
                    LIMIT 1
                    """,
                    [.text(accountDID), .text(canonicalName)]
                )
                guard let id = rows.first?.column("id")?.string else {
                    throw SwanError.unauthorized("app password not found")
                }
                // The canonical foreign key cascades families and token rows.
                _ = try await connection.query(
                    "DELETE FROM account_app_passwords WHERE did = ? AND id = ?",
                    [.text(accountDID), .text(id)]
                )
            }
        }
    }

    public func markAppPasswordUsed(id: String, now: Date) async throws {
        // The canonical main row intentionally has no mutable last-used
        // projection. The compatibility API keeps this operation source
        // compatible without adding another credential authority/column.
        _ = (id, now)
    }

    public func createLegacySessionFromAppPassword(
        _ metadata: AppPasswordMetadata,
        family: LegacySessionFamilyMetadata,
        session: LegacySessionMetadata,
        sessionDigest: Data,
        now: Date
    ) async throws {
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT did, scopes FROM account_app_passwords
                    WHERE id = ?
                    LIMIT 1
                    """,
                    [.text(metadata.id)]
                )
                guard let row = rows.first,
                      row.column("did")?.string == metadata.accountDID,
                      row.column("scopes")?.string == Self.encodeScopes(metadata.scopeStrings) else {
                    throw SwanError.unauthorized("app password changed or revoked")
                }
                try await insertFamilyAndRefresh(
                    family: family,
                    refreshDigest: sessionDigest,
                    refreshExpiresAt: session.expiresAt,
                    now: now
                )
            }
        }
    }

    public func createLegacySessionFamily(
        _ family: LegacySessionFamilyMetadata,
        session: LegacySessionMetadata,
        sessionDigest: Data,
        now: Date
    ) async throws {
        try await withConnectionGate {
            try await transaction {
                try await insertFamilyAndRefresh(
                    family: family,
                    refreshDigest: sessionDigest,
                    refreshExpiresAt: session.expiresAt,
                    now: now
                )
            }
        }
    }

    public func legacySession(digest: Data, now: Date) async throws -> LegacySessionMetadata? {
        _ = now
        guard digest.count == 32 else {
            throw SwanError.invalidIdentifier("legacy session digest")
        }
        return try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT t.digest, t.expires_at,
                       f.family_id, f.did, f.app_password_id,
                       f.created_at, f.revoked_at, f.reuse_detected_at,
                       p.scopes AS app_scopes
                FROM legacy_session_tokens AS t
                JOIN legacy_session_families AS f ON f.family_id = t.family_id
                LEFT JOIN account_app_passwords AS p ON p.id = f.app_password_id
                WHERE t.digest = ? AND t.kind = 'refresh'
                LIMIT 1
                """,
                [.blob(ByteBuffer(data: digest))]
            )
            return try rows.first.map(Self.decodeSession)
        }
    }

    public func rotateOrRevokeFamilyOnReuse(
        _ request: LegacySessionRotationRequest
    ) async throws -> LegacySessionRotationOutcome {
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT t.family_id, t.consumed_at,
                           f.did, f.app_password_id, f.created_at,
                           f.revoked_at, f.reuse_detected_at
                    FROM legacy_session_tokens AS t
                    JOIN legacy_session_families AS f ON f.family_id = t.family_id
                    WHERE t.digest = ? AND t.kind = 'refresh'
                    LIMIT 1
                    """,
                    [.blob(ByteBuffer(data: request.oldDigest))]
                )
                guard let row = rows.first,
                      let familyID = row.column("family_id")?.string else {
                    throw SwanError.unauthorized("invalid refresh token")
                }
                let revoked = row.column("revoked_at")?.isNull == false
                let consumed = row.column("consumed_at")?.isNull == false
                if revoked || consumed {
                    let stamp = Self.microseconds(request.now)
                    _ = try await connection.query(
                        """
                        UPDATE legacy_session_families
                        SET revoked_at = COALESCE(revoked_at, ?),
                            reuse_detected_at = COALESCE(reuse_detected_at, ?)
                        WHERE family_id = ?
                        """,
                        [.integer(stamp), .integer(stamp), .text(familyID)]
                    )
                    return try .reuseDetectedAndFamilyRevoked(
                        familyID: familyID,
                        detectedAt: request.now,
                        revokedAt: request.now
                    )
                }

                let stamp = Self.microseconds(request.now)
                let claimed = try await connection.query(
                    """
                    UPDATE legacy_session_tokens
                    SET consumed_at = ?
                    WHERE digest = ? AND family_id = ?
                      AND kind = 'refresh' AND consumed_at IS NULL
                    RETURNING digest
                    """,
                    [
                        .integer(stamp),
                        .blob(ByteBuffer(data: request.oldDigest)),
                        .text(familyID),
                    ]
                )
                guard !claimed.isEmpty else {
                    let nowStamp = Self.microseconds(request.now)
                    _ = try await connection.query(
                        """
                        UPDATE legacy_session_families
                        SET revoked_at = COALESCE(revoked_at, ?),
                            reuse_detected_at = COALESCE(reuse_detected_at, ?)
                        WHERE family_id = ?
                        """,
                        [.integer(nowStamp), .integer(nowStamp), .text(familyID)]
                    )
                    return try .reuseDetectedAndFamilyRevoked(
                        familyID: familyID,
                        detectedAt: request.now,
                        revokedAt: request.now
                    )
                }
                _ = try await connection.query(
                    """
                    INSERT INTO legacy_session_tokens(digest, family_id, kind, expires_at)
                    VALUES (?, ?, 'refresh', ?)
                    """,
                    [
                        .blob(ByteBuffer(data: request.replacementDigest)),
                        .text(familyID),
                        .integer(Self.microseconds(request.replacement.expiresAt)),
                    ]
                )
                return .rotated(sessionID: request.replacement.sessionID)
            }
        }
    }

    public func purgeExpiredLegacySessions(now: Date) async throws {
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    "DELETE FROM legacy_session_tokens WHERE expires_at <= ?",
                    [.integer(Self.microseconds(now))]
                )
            }
        }
    }

    private func insertFamilyAndRefresh(
        family: LegacySessionFamilyMetadata,
        refreshDigest: Data,
        refreshExpiresAt: Date,
        now: Date
    ) async throws {
        _ = try await connection.query(
            """
            INSERT INTO legacy_session_families
                (family_id, did, app_password_id, created_at)
            VALUES (?, ?, ?, ?)
            """,
            [
                .text(family.familyID),
                .text(family.accountDID),
                family.appPasswordID.map(SQLiteData.text) ?? .null,
                .integer(Self.microseconds(family.createdAt)),
            ]
        )
        _ = try await connection.query(
            """
            INSERT INTO legacy_session_tokens(digest, family_id, kind, expires_at)
            VALUES (?, ?, 'refresh', ?)
            """,
            [
                .blob(ByteBuffer(data: refreshDigest)),
                .text(family.familyID),
                .integer(Self.microseconds(refreshExpiresAt)),
            ]
        )
        _ = now
    }

    private static func encodeScopes(_ scopes: Set<String>) -> String {
        scopes.sorted().joined(separator: " ")
    }

    private static func decodeScopes(_ value: SQLiteData?) throws -> Set<String> {
        guard case let .text(raw) = value else {
            throw SwanError.malformed("scope storage")
        }
        return Set(raw.split(separator: " ").map(String.init))
    }

    private static func decodeAppPassword(_ row: SQLiteRow) throws -> AppPasswordMetadata {
        guard let id = row.column("id")?.string,
              let did = row.column("did")?.string,
              let name = row.column("name")?.string,
              case let .blob(bytes) = row.column("digest"),
              let created = row.column("created_at")?.integer else {
            throw SwanError.malformed("app-password storage")
        }
        return try AppPasswordMetadata(
            id: id,
            accountDID: did,
            canonicalName: name,
            scopeStrings: try decodeScopes(row.column("scopes")),
            secretDigest: Data(buffer: bytes),
            createdAt: Date(timeIntervalSince1970: Double(created) / 1_000_000)
        )
    }

    private static func decodeSession(_ row: SQLiteRow) throws -> LegacySessionMetadata {
        guard case let .blob(digest) = row.column("digest"),
              let sessionID = try? LegacySessionID(digest: Data(buffer: digest)),
              let familyID = row.column("family_id")?.string,
              let did = row.column("did")?.string,
              let created = row.column("created_at")?.integer,
              let expires = row.column("expires_at")?.integer else {
            throw SwanError.malformed("legacy session storage")
        }
        let appPasswordID = row.column("app_password_id")?.string
        let revokedAt = Self.optionalDate(row.column("revoked_at"))
        let reuseDetectedAt = Self.optionalDate(row.column("reuse_detected_at"))
        // Session scopes are not a second authority. App-password scopes are
        // projected from the canonical credential row solely to reconstruct
        // the old metadata value; refresh still re-reads that row before it
        // mints any replacement authority.
        let scopes: Set<String>
        if appPasswordID == nil {
            scopes = [LegacyAccessGrant.fullAccessMarker]
        } else {
            scopes = try decodeScopes(row.column("app_scopes"))
        }
        return try LegacySessionMetadata(
            sessionID: sessionID,
            familyID: familyID,
            accountDID: did,
            appPasswordID: appPasswordID,
            scopeStrings: scopes,
            issuedAt: Date(timeIntervalSince1970: Double(created) / 1_000_000),
            expiresAt: Date(timeIntervalSince1970: Double(expires) / 1_000_000),
            revokedAt: revokedAt,
            reuseDetectedAt: reuseDetectedAt
        )
    }

    private static func optionalDate(_ value: SQLiteData?) -> Date? {
        guard let value, case let .integer(stamp) = value else { return nil }
        return Date(timeIntervalSince1970: Double(stamp) / 1_000_000)
    }

    private static func microseconds(_ date: Date) -> Int {
        let value = date.timeIntervalSince1970 * 1_000_000
        return value.isFinite && value >= 0 ? Int(value.rounded(.down)) : 0
    }
}
