import Foundation
import SQLiteNIO
import SwanCore
import SwanStorage

/// Lane-owned adapter for the tables created by the account foundation. It
/// intentionally adds no migration or router assembly: the integration owner
/// controls those shared paths.
extension SQLiteControlDatabase: AppPasswordStore, LegacySessionStore {
    public func createAppPassword(_ metadata: AppPasswordMetadata, now: Date) async throws {
        let scopes = try Self.encodeScopes(metadata.scopeStrings)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    "INSERT INTO app_passwords(app_password_id, account_did, canonical_name, scope_strings, secret_digest, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    [.text(metadata.id), .text(metadata.accountDID), .text(metadata.canonicalName), .blob(scopes), .blob(ByteBuffer(data: metadata.secretDigest)), .integer(Self.seconds(metadata.createdAt))]
                )
            }
        }
    }

    public func appPassword(accountDID: String, canonicalName: String, now: Date) async throws -> AppPasswordMetadata? {
        try await withConnectionGate {
            let rows = try await connection.query("SELECT * FROM app_passwords WHERE account_did = ? AND canonical_name = ? LIMIT 1", [.text(accountDID), .text(canonicalName)])
            return try rows.first.map(Self.decodeAppPassword)
        }
    }

    public func appPassword(id: String, now: Date) async throws -> AppPasswordMetadata? {
        try await withConnectionGate {
            let rows = try await connection.query("SELECT * FROM app_passwords WHERE app_password_id = ? LIMIT 1", [.text(id)])
            return try rows.first.map(Self.decodeAppPassword)
        }
    }

    public func listAppPasswords(accountDID: String, now: Date) async throws -> [AppPasswordMetadata] {
        try await withConnectionGate {
            try await connection.query("SELECT * FROM app_passwords WHERE account_did = ? ORDER BY created_at, app_password_id", [.text(accountDID)]).map(Self.decodeAppPassword)
        }
    }

    public func updateAppPasswordScopes(accountDID: String, canonicalName: String, scopes: Set<String>, now: Date) async throws {
        let encoded = try Self.encodeScopes(scopes)
        try await withConnectionGate {
            try await transaction {
                let existing = try await connection.query("SELECT 1 FROM app_passwords WHERE account_did = ? AND canonical_name = ? AND revoked_at IS NULL LIMIT 1", [.text(accountDID), .text(canonicalName)])
                guard !existing.isEmpty else { throw SwanError.unauthorized("app password not found") }
                _ = try await connection.query("UPDATE app_passwords SET scope_strings = ?, last_used_at = ? WHERE account_did = ? AND canonical_name = ? AND revoked_at IS NULL", [.blob(encoded), .integer(Self.seconds(now)), .text(accountDID), .text(canonicalName)])
            }
        }
    }

    public func revokeAppPassword(accountDID: String, canonicalName: String, now: Date) async throws {
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query("SELECT app_password_id FROM app_passwords WHERE account_did = ? AND canonical_name = ? AND revoked_at IS NULL LIMIT 1", [.text(accountDID), .text(canonicalName)])
                guard let id = rows.first?.column("app_password_id")?.string else { throw SwanError.unauthorized("app password not found") }
                _ = try await connection.query("UPDATE app_passwords SET revoked_at = ? WHERE app_password_id = ?", [.integer(Self.seconds(now)), .text(id)])
                _ = try await connection.query("UPDATE legacy_session_families SET revoked_at = ? WHERE app_password_id = ? AND revoked_at IS NULL", [.integer(Self.seconds(now)), .text(id)])
                _ = try await connection.query("UPDATE legacy_sessions SET revoked_at = ? WHERE app_password_id = ? AND revoked_at IS NULL", [.integer(Self.seconds(now)), .text(id)])
            }
        }
    }

    public func createLegacySessionFamily(_ family: LegacySessionFamilyMetadata, session: LegacySessionMetadata, sessionDigest: Data, now: Date) async throws {
        let familyExpiry = Self.seconds(family.expiresAt)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query("INSERT INTO legacy_session_families(family_id, account_did, app_password_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)", [.text(family.familyID), .text(family.accountDID), family.appPasswordID.map(SQLiteData.text) ?? .null, .integer(Self.seconds(family.createdAt)), .integer(familyExpiry)])
                try await insertSession(session, digest: sessionDigest)
            }
        }
    }

    public func legacySession(digest: Data, now: Date) async throws -> LegacySessionMetadata? {
        guard digest.count == 32 else { throw SwanError.invalidIdentifier("legacy session digest") }
        return try await withConnectionGate {
            let rows = try await connection.query("SELECT * FROM legacy_sessions WHERE session_digest = ? LIMIT 1", [.blob(ByteBuffer(data: digest))])
            return try rows.first.map(Self.decodeSession)
        }
    }

    public func rotateOrRevokeFamilyOnReuse(_ request: LegacySessionRotationRequest) async throws -> LegacySessionRotationOutcome {
        try await withConnectionGate {
            try await transaction {
                let oldRows = try await connection.query("SELECT * FROM legacy_sessions WHERE session_digest = ? LIMIT 1", [.blob(ByteBuffer(data: request.oldDigest))])
                guard let oldRow = oldRows.first else { throw SwanError.unauthorized("invalid refresh token") }
                let old = try Self.decodeSession(oldRow)
                let familyRows = try await connection.query("SELECT * FROM legacy_session_families WHERE family_id = ? LIMIT 1", [.text(old.familyID)])
                guard let familyRow = familyRows.first else { throw SwanError.malformed("legacy session family missing") }
                let familyRevoked = familyRow.column("revoked_at")?.integer != nil
                if old.revokedAt != nil || familyRevoked {
                    _ = try await connection.query("UPDATE legacy_session_families SET revoked_at = COALESCE(revoked_at, ?), reuse_detected_at = COALESCE(reuse_detected_at, ?) WHERE family_id = ?", [.integer(Self.seconds(request.now)), .integer(Self.seconds(request.now)), .text(old.familyID)])
                    _ = try await connection.query("UPDATE legacy_sessions SET revoked_at = COALESCE(revoked_at, ?), reuse_detected_at = COALESCE(reuse_detected_at, ?) WHERE family_id = ?", [.integer(Self.seconds(request.now)), .integer(Self.seconds(request.now)), .text(old.familyID)])
                    return try .reuseDetectedAndFamilyRevoked(familyID: old.familyID, detectedAt: request.now, revokedAt: request.now)
                }
                _ = try await connection.query("UPDATE legacy_sessions SET revoked_at = ?, rotated_at = ?, replaced_by_digest = ? WHERE session_digest = ? AND revoked_at IS NULL", [.integer(Self.seconds(request.now)), .integer(Self.seconds(request.now)), .blob(ByteBuffer(data: request.replacementDigest)), .blob(ByteBuffer(data: request.oldDigest))])
                try await insertSession(request.replacement, digest: request.replacementDigest)
                return .rotated(sessionID: request.replacement.sessionID)
            }
        }
    }

    public func revokeLegacySessionFamily(familyID: String, now: Date) async throws {
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query("UPDATE legacy_session_families SET revoked_at = COALESCE(revoked_at, ?) WHERE family_id = ?", [.integer(Self.seconds(now)), .text(familyID)])
                _ = try await connection.query("UPDATE legacy_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE family_id = ?", [.integer(Self.seconds(now)), .text(familyID)])
            }
        }
    }

    public func purgeExpiredLegacySessions(now: Date) async throws {
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query("DELETE FROM legacy_sessions WHERE expires_at <= ?", [.integer(Self.seconds(now))])
                _ = try await connection.query("DELETE FROM legacy_session_families WHERE expires_at <= ?", [.integer(Self.seconds(now))])
            }
        }
    }

    private func insertSession(_ session: LegacySessionMetadata, digest: Data) async throws {
        _ = try await connection.query(
            "INSERT INTO legacy_sessions(session_digest, family_id, account_did, app_password_id, scope_strings, issued_at, expires_at, revoked_at, rotated_at, replaced_by_digest, previous_session_digest, reuse_detected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [.blob(ByteBuffer(data: digest)), .text(session.familyID), .text(session.accountDID), session.appPasswordID.map(SQLiteData.text) ?? .null, .blob(try Self.encodeScopes(session.scopeStrings)), .integer(Self.seconds(session.issuedAt)), .integer(Self.seconds(session.expiresAt)), session.revokedAt.map { .integer(Self.seconds($0)) } ?? .null, session.rotatedAt.map { .integer(Self.seconds($0)) } ?? .null, session.replacedByDigest.map(ByteBuffer.init(data:)).map(SQLiteData.blob) ?? .null, session.previousSessionDigest.map(ByteBuffer.init(data:)).map(SQLiteData.blob) ?? .null, session.reuseDetectedAt.map { .integer(Self.seconds($0)) } ?? .null]
        )
    }

    private static func seconds(_ date: Date) -> Int { max(0, Int(date.timeIntervalSince1970)) }

    private static func encodeScopes(_ scopes: Set<String>) throws -> ByteBuffer { ByteBuffer(data: Data(scopes.sorted().joined(separator: " ").utf8)) }
    private static func decodeScopes(_ row: SQLiteRow) throws -> Set<String> {
        guard case let .blob(value) = row.column("scope_strings") else { throw SwanError.malformed("scope storage") }
        return Set(String(decoding: value.readableBytesView, as: UTF8.self).split(separator: " ").map(String.init))
    }
    private static func decodeAppPassword(_ row: SQLiteRow) throws -> AppPasswordMetadata {
        guard let id = row.column("app_password_id")?.string, let did = row.column("account_did")?.string, let name = row.column("canonical_name")?.string, case let .blob(bytes) = row.column("secret_digest"), let created = row.column("created_at")?.integer else { throw SwanError.malformed("app-password storage") }
        return try AppPasswordMetadata(id: id, accountDID: did, canonicalName: name, scopeStrings: decodeScopes(row), secretDigest: Data(buffer: bytes), createdAt: Date(timeIntervalSince1970: TimeInterval(created)), lastUsedAt: row.column("last_used_at")?.integer.map { Date(timeIntervalSince1970: TimeInterval($0)) }, revokedAt: row.column("revoked_at")?.integer.map { Date(timeIntervalSince1970: TimeInterval($0)) })
    }
    private static func decodeSession(_ row: SQLiteRow) throws -> LegacySessionMetadata {
        guard case let .blob(digest) = row.column("session_digest"), let id = try? LegacySessionID(digest: Data(buffer: digest)), let family = row.column("family_id")?.string, let did = row.column("account_did")?.string, let issued = row.column("issued_at")?.integer, let expires = row.column("expires_at")?.integer else { throw SwanError.malformed("legacy session storage") }
        return try LegacySessionMetadata(sessionID: id, familyID: family, accountDID: did, appPasswordID: row.column("app_password_id")?.string, scopeStrings: decodeScopes(row), issuedAt: Date(timeIntervalSince1970: TimeInterval(issued)), expiresAt: Date(timeIntervalSince1970: TimeInterval(expires)), revokedAt: row.column("revoked_at")?.integer.map { Date(timeIntervalSince1970: TimeInterval($0)) }, rotatedAt: row.column("rotated_at")?.integer.map { Date(timeIntervalSince1970: TimeInterval($0)) }, replacedByDigest: row.column("replaced_by_digest").flatMap { if case let .blob(value) = $0 { return Data(buffer: value) }; return nil }, previousSessionDigest: row.column("previous_session_digest").flatMap { if case let .blob(value) = $0 { return Data(buffer: value) }; return nil }, reuseDetectedAt: row.column("reuse_detected_at")?.integer.map { Date(timeIntervalSince1970: TimeInterval($0)) })
    }
}

private extension Data {
    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var data = Data(); data.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            data.append(byte); index = next
        }
        self = data
    }
}
