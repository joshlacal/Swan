import Crypto
import Foundation
import PetrelCrypto
import SQLiteNIO
import SwanCore
import SwanStorage

/// SQLite adapter for the account portal's durable pre-auth and management
/// session state. The foundation migration owns `management_sessions`; this
/// lane owns only the one-time pre-auth table and its expiry index.
extension SQLiteControlDatabase: ManagementSessionStore,
    ManagementSessionStepUpStore,
    SwanManagementPreAuthStore,
    SwanManagementCSRFStore,
    SwanManagementPreAuthSessionCoordinator
{
    public func migrateAccountPortalSessionSchema() async throws {
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    """
                    CREATE TABLE IF NOT EXISTS management_pre_auth (
                        token_digest BLOB PRIMARY KEY CHECK(length(token_digest) = 32),
                        expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
                    ) WITHOUT ROWID
                    """
                )
                _ = try await connection.query(
                    "CREATE INDEX IF NOT EXISTS management_pre_auth_expiry ON management_pre_auth(expires_at, token_digest)"
                )
            }
        }
    }

    public func put(digest: Data, expiresAt: Date) async {
        guard digest.count == 32, let expiry = portalTimestamp(expiresAt) else { return }
        do {
            try await withConnectionGate {
                try await transaction {
                    _ = try await connection.query(
                        "INSERT INTO management_pre_auth(token_digest, expires_at) VALUES(?, ?) ON CONFLICT(token_digest) DO UPDATE SET expires_at=excluded.expires_at",
                        [digest.sqliteData!, .integer(expiry)]
                    )
                }
            }
        } catch {
            // The protocol deliberately has no throwing put operation. A
            // failed durable write is therefore observable through the later
            // validation/consume result, never as a usable in-memory token.
        }
    }

    public func contains(digest: Data, now: Date) async -> Bool {
        guard digest.count == 32, let current = portalTimestamp(now) else { return false }
        do {
            return try await withConnectionGate {
                let rows = try await connection.query(
                    "SELECT 1 FROM management_pre_auth WHERE token_digest = ? AND expires_at >= ?",
                    [digest.sqliteData!, .integer(current)]
                )
                return rows.count == 1
            }
        } catch {
            return false
        }
    }

    public func take(digest: Data, now: Date) async -> Bool {
        guard digest.count == 32, let current = portalTimestamp(now) else { return false }
        do {
            return try await withConnectionGate {
                try await transaction {
                    let rows = try await connection.query(
                        "DELETE FROM management_pre_auth WHERE token_digest = ? AND expires_at >= ? RETURNING token_digest",
                        [digest.sqliteData!, .integer(current)]
                    )
                    return rows.count == 1
                }
            }
        } catch {
            return false
        }
    }

    public func createManagementSession(
        _ session: ManagementSessionMetadata,
        sessionDigest: Data,
        csrfDigest: Data,
        now: Date
    ) async throws {
        try validatePortalDigests(sessionDigest, csrfDigest)
        let current = try portalTimestampOrThrow(now)
        try await withConnectionGate {
            try await transaction {
                try await insertManagementSession(
                    session,
                    sessionDigest: sessionDigest,
                    csrfDigest: csrfDigest,
                    now: current
                )
            }
        }
    }

    public func managementSession(digest: Data, now: Date) async throws -> ManagementSessionMetadata? {
        guard digest.count == 32 else { throw AccountControlStoreError.invalidInput }
        _ = try portalTimestampOrThrow(now)
        return try await withConnectionGate {
            let rows = try await connection.query(
                "SELECT session_digest, account_did, csrf_digest, issued_at, idle_expires_at, absolute_expires_at, last_step_up_at, strength, revoked_at FROM management_sessions WHERE session_digest = ?",
                [digest.sqliteData!]
            )
            guard rows.count <= 1 else { throw AccountControlStoreError.malformedRecord }
            guard let row = rows.first else { return nil }
            return try decodeManagementSession(row)
        }
    }

    public func revokeManagementSession(digest: Data, now: Date) async throws {
        guard digest.count == 32 else { throw AccountControlStoreError.invalidInput }
        let current = try portalTimestampOrThrow(now)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    "UPDATE management_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE session_digest = ?",
                    [.integer(current), digest.sqliteData!]
                )
            }
        }
    }

    public func revokeManagementSession(digest: Data, accountDID: String, now: Date) async throws {
        guard digest.count == 32, !accountDID.isEmpty else {
            throw AccountControlStoreError.invalidInput
        }
        let current = try portalTimestampOrThrow(now)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    "UPDATE management_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE session_digest = ? AND account_did = ?",
                    [.integer(current), digest.sqliteData!, .text(accountDID)]
                )
            }
        }
    }

    public func revokeManagementSessions(accountDID: String, now: Date) async throws {
        guard !accountDID.isEmpty else {
            throw AccountControlStoreError.invalidInput
        }
        let current = try portalTimestampOrThrow(now)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    "UPDATE management_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE account_did = ?",
                    [.integer(current), .text(accountDID)]
                )
            }
        }
    }

    public func managementSessions(accountDID: String, now: Date) async throws -> [ManagementSessionMetadata] {
        guard !accountDID.isEmpty else { throw AccountControlStoreError.invalidInput }
        let current = try portalTimestampOrThrow(now)
        return try await withConnectionGate {
            let rows = try await connection.query(
                "SELECT session_digest, account_did, csrf_digest, issued_at, idle_expires_at, absolute_expires_at, last_step_up_at, strength, revoked_at FROM management_sessions WHERE account_did = ? AND revoked_at IS NULL AND idle_expires_at >= ? AND absolute_expires_at >= ? ORDER BY issued_at",
                [.text(accountDID), .integer(current), .integer(current)]
            )
            return try rows.map(decodeManagementSession)
        }
    }

    public func upgradeManagementSession(
        digest: Data,
        accountDID: String,
        strength: AuthenticationStrength,
        lastStepUpAt: Date,
        now: Date
    ) async throws {
        guard digest.count == 32, !accountDID.isEmpty,
              strength.isStepUp else {
            throw AccountControlStoreError.invalidInput
        }
        let current = try portalTimestampOrThrow(now)
        let verified = try portalTimestampOrThrow(lastStepUpAt)
        guard verified <= current else { throw AccountControlStoreError.invalidInput }
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    UPDATE management_sessions
                       SET last_step_up_at = ?, strength = ?
                     WHERE session_digest = ?
                       AND account_did = ?
                       AND revoked_at IS NULL
                       AND idle_expires_at >= ?
                       AND absolute_expires_at >= ?
                    RETURNING session_digest
                    """,
                    [
                        .integer(verified), .text(portalStrengthName(strength)),
                        digest.sqliteData!, .text(accountDID),
                        .integer(current), .integer(current),
                    ]
                )
                guard !rows.isEmpty else { throw AccountControlStoreError.notFound }
            }
        }
    }

    public func revokeOtherManagementSessions(
        accountDID: String,
        except sessionID: ManagementSessionID,
        now: Date
    ) async throws {
        guard !accountDID.isEmpty else { throw AccountControlStoreError.invalidInput }
        let current = try portalTimestampOrThrow(now)
        let exceptDigest: Data
        if let decoded = Hex.decode(sessionID.rawValue), decoded.count == 32 {
            exceptDigest = decoded
        } else {
            exceptDigest = Data(SHA256.hash(data: Data(sessionID.rawValue.utf8)))
        }
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    "UPDATE management_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE account_did = ? AND session_digest <> ?",
                    [.integer(current), .text(accountDID), exceptDigest.sqliteData!]
                )
            }
        }
    }

    public func purgeExpiredManagementSessions(now: Date) async throws {
        let current = try portalTimestampOrThrow(now)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    "DELETE FROM management_sessions WHERE absolute_expires_at < ? OR revoked_at < ?",
                    [.integer(current), .integer(current - 86_400 * 1_000_000)]
                )
                _ = try await connection.query(
                    "DELETE FROM management_pre_auth WHERE expires_at < ?",
                    [.integer(current)]
                )
            }
        }
    }

    public func put(sessionDigest: Data, csrfDigest: Data) async throws {
        try validatePortalDigests(sessionDigest, csrfDigest)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    "UPDATE management_sessions SET csrf_digest = ? WHERE session_digest = ?",
                    [csrfDigest.sqliteData!, sessionDigest.sqliteData!]
                )
            }
        }
    }

    public func digest(for sessionDigest: Data) async throws -> Data? {
        guard sessionDigest.count == 32 else { throw AccountControlStoreError.invalidInput }
        return try await withConnectionGate {
            let rows = try await connection.query(
                "SELECT csrf_digest FROM management_sessions WHERE session_digest = ?",
                [sessionDigest.sqliteData!]
            )
            guard rows.count <= 1 else { throw AccountControlStoreError.malformedRecord }
            guard let value = rows.first?.column("csrf_digest"), let digest = Data(sqliteData: value), digest.count == 32 else { return nil }
            return digest
        }
    }

    public func remove(sessionDigest: Data) async throws {
        guard sessionDigest.count == 32 else { throw AccountControlStoreError.invalidInput }
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    "UPDATE management_sessions SET csrf_digest = zeroblob(32) WHERE session_digest = ?",
                    [sessionDigest.sqliteData!]
                )
            }
        }
    }

    public func consumePreAuthAndCreateManagementSession(
        preAuthDigest: Data,
        session: ManagementSessionMetadata,
        sessionDigest: Data,
        csrfDigest: Data,
        now: Date
    ) async throws -> Bool {
        guard preAuthDigest.count == 32 else { throw AccountControlStoreError.invalidInput }
        try validatePortalDigests(sessionDigest, csrfDigest)
        let current = try portalTimestampOrThrow(now)
        return try await withConnectionGate {
            try await transaction {
                let consumed = try await connection.query(
                    "DELETE FROM management_pre_auth WHERE token_digest = ? AND expires_at >= ? RETURNING token_digest",
                    [preAuthDigest.sqliteData!, .integer(current)]
                )
                guard consumed.count == 1 else { return false }
                try await insertManagementSession(
                    session,
                    sessionDigest: sessionDigest,
                    csrfDigest: csrfDigest,
                    now: current
                )
                return true
            }
        }
    }

    public func consumePreAuthAndCreateManagementSessionConsumingGrant(
        preAuthDigest: Data,
        session: ManagementSessionMetadata,
        sessionDigest: Data,
        csrfDigest: Data,
        authorizationGrantDigest: Data,
        authorizationContext: AccountAuthorizationContext,
        now: Date
    ) async throws -> Bool {
        guard preAuthDigest.count == 32, authorizationGrantDigest.count == 32,
              authorizationContext.channel == .portal,
              authorizationContext.purpose == "managementLogin" else {
            throw AccountControlStoreError.invalidInput
        }
        try validatePortalDigests(sessionDigest, csrfDigest)
        let current = try portalTimestampOrThrow(now)
        return try await withConnectionGate {
            try await ensureTask7DurableTables()
            return try await transaction {
                let consumed = try await connection.query(
                    "DELETE FROM management_pre_auth WHERE token_digest = ? AND expires_at >= ? RETURNING token_digest",
                    [preAuthDigest.sqliteData!, .integer(current)]
                )
                guard consumed.count == 1 else { return false }
                do {
                    _ = try await consumeAuthorizationGrantLocked(
                        grantDigest: authorizationGrantDigest,
                        accountDID: session.accountDID,
                        context: authorizationContext,
                        now: now
                    )
                } catch {
                    // A missing, replayed, expired, revision-mismatched, or
                    // wrong-channel/wrong-purpose grant aborts this
                    // transaction: no portal session is issued.
                    throw AccountControlStoreError.invalidTransition
                }
                try await insertManagementSession(
                    session,
                    sessionDigest: sessionDigest,
                    csrfDigest: csrfDigest,
                    now: current
                )
                return true
            }
        }
    }

    private func insertManagementSession(
        _ session: ManagementSessionMetadata,
        sessionDigest: Data,
        csrfDigest: Data,
        now: Int
    ) async throws {
        let issued = try portalTimestampOrThrow(session.issuedAt)
        let idle = try portalTimestampOrThrow(session.idleExpiresAt)
        let absolute = try portalTimestampOrThrow(session.absoluteExpiresAt)
        guard issued <= now, idle >= issued, absolute >= idle else { throw AccountControlStoreError.invalidInput }
        _ = try await connection.query(
            "INSERT INTO management_sessions(session_digest, account_did, csrf_digest, issued_at, idle_expires_at, absolute_expires_at, last_step_up_at, strength, revoked_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [sessionDigest.sqliteData!, .text(session.accountDID), csrfDigest.sqliteData!, .integer(issued), .integer(idle), .integer(absolute), session.lastStepUpAt.map { (try? portalTimestampOrThrow($0)).map(SQLiteData.integer) ?? .null } ?? .null, .text(portalStrengthName(session.strength)), session.revokedAt.map { (try? portalTimestampOrThrow($0)).map(SQLiteData.integer) ?? .null } ?? .null]
        )
    }

    private func decodeManagementSession(_ row: SQLiteRow) throws -> ManagementSessionMetadata {
        guard case let .text(accountDID) = row.column("account_did"),
              case let .integer(issued) = row.column("issued_at"),
              case let .integer(idle) = row.column("idle_expires_at"),
              case let .integer(absolute) = row.column("absolute_expires_at"),
              case let .text(strength) = row.column("strength"),
              let sessionDigest = Data(sqliteData: row.column("session_digest")!),
              sessionDigest.count == 32 else { throw AccountControlStoreError.malformedRecord }
        let issuedAt = Date(timeIntervalSince1970: Double(issued) / 1_000_000)
        let lastStepUpAt: Date? = row.column("last_step_up_at").flatMap { value in
            guard case let .integer(raw) = value else { return nil }
            return Date(timeIntervalSince1970: Double(raw) / 1_000_000)
        }
        let parsedStrength = try portalStrength(name: strength, lastStepUpAt: lastStepUpAt ?? issuedAt)
        let sessionID = try ManagementSessionID(digest: sessionDigest)
        return try ManagementSessionMetadata(
            sessionID: sessionID,
            accountDID: accountDID,
            issuedAt: issuedAt,
            idleExpiresAt: Date(timeIntervalSince1970: Double(idle) / 1_000_000),
            absoluteExpiresAt: Date(timeIntervalSince1970: Double(absolute) / 1_000_000),
            lastStepUpAt: lastStepUpAt,
            strength: parsedStrength,
            revokedAt: row.column("revoked_at").flatMap { value in
                guard case let .integer(raw) = value else { return nil }
                return Date(timeIntervalSince1970: Double(raw) / 1_000_000)
            }
        )
    }
}

private func portalStrengthName(_ strength: AuthenticationStrength) -> String {
    switch strength {
    case .none: return "none"
    case .password: return "password"
    case .passwordPlusTOTP: return "passwordPlusTOTP"
    case .passwordPlusPasskey: return "passwordPlusPasskey"
    case .emailRecovery: return "emailRecovery"
    case .scopedAppPassword: return "scopedAppPassword"
    case .stepUpPassword: return "stepUpPassword"
    case let .stepUpMFA(base, _): return "stepUpMFA:\(base.rawValue)"
    }
}

private func portalStrength(name: String, lastStepUpAt: Date) throws -> AuthenticationStrength {
    switch name {
    case "none": return .none
    case "password": return .password
    case "passwordPlusTOTP": return .passwordPlusTOTP
    case "passwordPlusPasskey": return .passwordPlusPasskey
    case "emailRecovery": return .emailRecovery
    case "scopedAppPassword": return .scopedAppPassword
    case "stepUpPassword": return .stepUpPassword(verifiedAt: lastStepUpAt)
    case "stepUpMFA:passwordPlusTOTP": return .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: lastStepUpAt)
    case "stepUpMFA:passwordPlusPasskey": return .stepUpMFA(base: .passwordPlusPasskey, verifiedAt: lastStepUpAt)
    default: throw AccountControlStoreError.malformedRecord
    }
}

private func portalTimestamp(_ date: Date) -> Int? {
    let value = date.timeIntervalSince1970 * 1_000_000
    guard value.isFinite, value >= 0, value <= Double(Int.max) else { return nil }
    return Int(value.rounded(.down))
}

private func portalTimestampOrThrow(_ date: Date) throws -> Int {
    guard let value = portalTimestamp(date) else { throw AccountControlStoreError.invalidInput }
    return value
}

private func validatePortalDigests(_ session: Data, _ csrf: Data) throws {
    guard session.count == 32, csrf.count == 32 else { throw AccountControlStoreError.invalidInput }
}
