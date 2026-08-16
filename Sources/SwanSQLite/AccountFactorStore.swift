import Foundation
import Crypto
import SQLiteNIO
import SwanCore
import SwanStorage

extension SQLiteControlDatabase: AuthenticationFactorStore, TOTPSecretStore, RecoveryCodeStore, WebAuthnCredentialStore, WebAuthnChallengeStore, WebAuthnChallengeLookupStore, WebAuthnAtomicVerificationStore, WebAuthnEnrollmentStore, TOTPReplayStore, DurableFactorTokenStore, MFAAuditStore {
    public func listFactors(accountDID: String, now: Date) async throws -> [AuthenticationFactorMetadata] {
        return try await withConnectionGate {
            let rows = try await connection.query("SELECT factor_id, account_did, kind, label, lookup_digest, created_at, last_used_at, disabled_at FROM authentication_factors WHERE account_did = ? AND (disabled_at IS NULL OR disabled_at > ? ) ORDER BY created_at, factor_id", [.text(accountDID), .integer(factorTimestamp(now))])
            return try rows.map(decodeFactor)
        }
    }

    public func saveFactor(_ factor: AuthenticationFactorMetadata, now: Date) async throws {
        try await withConnectionGate {
            _ = try await connection.query("INSERT INTO authentication_factors(factor_id, account_did, kind, label, lookup_digest, created_at, last_used_at, disabled_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [.text(factor.id), .text(factor.accountDID), .text(factor.kind.rawValue), .text(factor.label), factor.lookupDigest.sqliteData!, .integer(factorTimestamp(factor.createdAt)), optionalTimestamp(factor.lastUsedAt), optionalTimestamp(factor.disabledAt)])
        }
    }

    public func disableFactor(id: String, accountDID: String, now: Date) async throws {
        try await withConnectionGate { _ = try await connection.query("UPDATE authentication_factors SET disabled_at = ? WHERE factor_id = ? AND account_did = ? AND disabled_at IS NULL", [.integer(factorTimestamp(now)), .text(id), .text(accountDID)]) }
    }

    public func reserveChallenge(_ challenge: FactorChallenge, now: Date) async throws {
        try await withConnectionGate { _ = try await connection.query("INSERT INTO factor_challenges(challenge_digest, account_did, factor_id, purpose, issued_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, ?)", [challenge.challengeDigest.sqliteData!, .text(challenge.accountDID), challenge.factorID.map(SQLiteData.text) ?? .null, .text(challenge.purpose.rawValue), .integer(factorTimestamp(challenge.issuedAt)), .integer(factorTimestamp(challenge.expiresAt)), optionalTimestamp(challenge.consumedAt)]) }
    }

    public func consumeChallenge(digest: Data, now: Date) async throws -> FactorChallenge {
        try await withConnectionGate { try await transaction {
            let changed = try await connection.query("UPDATE factor_challenges SET consumed_at = ? WHERE challenge_digest = ? AND consumed_at IS NULL AND expires_at > ? RETURNING challenge_digest", [.integer(factorTimestamp(now)), digest.sqliteData!, .integer(factorTimestamp(now))])
            guard !changed.isEmpty else { throw AccountControlStoreError.malformedRecord }
            let rows = try await connection.query("SELECT challenge_digest, account_did, factor_id, purpose, issued_at, expires_at, consumed_at FROM factor_challenges WHERE challenge_digest = ?", [digest.sqliteData!])
            guard let row = rows.first else { throw AccountControlStoreError.malformedRecord }
            return try decodeChallenge(row)
        } }
    }

    public func purgeExpiredFactorState(now: Date) async throws {
        try await withConnectionGate { try await ensureTask7DurableTables(); _ = try await transaction { _ = try await connection.query("DELETE FROM factor_challenges WHERE expires_at <= ?", [.integer(factorTimestamp(now))]); _ = try await connection.query("DELETE FROM webauthn_challenges WHERE expires_at <= ?", [.integer(factorTimestamp(now))]); _ = try await connection.query("DELETE FROM mfa_webauthn_challenge_context WHERE challenge_digest NOT IN (SELECT challenge_digest FROM webauthn_challenges)", []) } }
    }

    public func saveTOTPEnvelope(_ envelope: TOTPSecretEnvelope, now: Date) async throws {
        try await withConnectionGate {
            guard envelope.ciphertext.count <= 4096, envelope.nonce.count == 12, envelope.authenticationTag.count == 16 else { throw AccountControlStoreError.invalidInput }
            let inserted = try await connection.query("INSERT INTO totp_secret_envelopes(factor_id, account_did, key_reference, nonce, ciphertext, authentication_tag) SELECT ?, account_did, ?, ?, ?, ? FROM authentication_factors WHERE factor_id = ? AND kind = 'totp' AND disabled_at IS NULL RETURNING factor_id", [.text(envelope.factorID), .text(envelope.keyReference), envelope.nonce.sqliteData!, envelope.ciphertext.sqliteData!, envelope.authenticationTag.sqliteData!, .text(envelope.factorID)])
            guard !inserted.isEmpty else { throw AccountControlStoreError.notFound }
        }
    }

    public func totpEnvelope(factorID: String, accountDID: String) async throws -> TOTPSecretEnvelope? {
        try await withConnectionGate { let rows = try await connection.query("SELECT factor_id, key_reference, nonce, ciphertext, authentication_tag FROM totp_secret_envelopes WHERE factor_id = ? AND account_did = ?", [.text(factorID), .text(accountDID)]); guard let row = rows.first else { return nil }; return try TOTPSecretEnvelope(factorID: try requiredText(row, "factor_id"), keyReference: try requiredText(row, "key_reference"), nonce: try requiredBlob(row, "nonce"), ciphertext: try requiredBlob(row, "ciphertext"), authenticationTag: try requiredBlob(row, "authentication_tag")) }
    }

    public func deleteTOTPEnvelope(factorID: String, accountDID: String, now: Date) async throws {
        try await withConnectionGate { _ = try await connection.query("DELETE FROM totp_secret_envelopes WHERE factor_id = ? AND account_did = ?", [.text(factorID), .text(accountDID)]) }
    }

    public func replaceRecoveryCodeDigests(accountDID: String, digests: [RecoveryCodeDigest], now: Date) async throws {
        guard digests.count <= 32 else { throw AccountControlStoreError.invalidInput }
        try await withConnectionGate { try await transaction { _ = try await connection.query("DELETE FROM recovery_code_digests WHERE account_did = ?", [.text(accountDID)]); for digest in digests { _ = try await connection.query("INSERT INTO recovery_code_digests(account_did, digest, issued_at, consumed_at) VALUES (?, ?, ?, ?)", [.text(accountDID), digest.digest.sqliteData!, .integer(factorTimestamp(digest.issuedAt)), optionalTimestamp(digest.consumedAt)]) } } }
    }

    public func consumeRecoveryCode(digest: Data, accountDID: String, now: Date) async throws -> RecoveryCodeDigest {
        try await withConnectionGate { try await transaction {
            let changed = try await connection.query("UPDATE recovery_code_digests SET consumed_at = ? WHERE account_did = ? AND digest = ? AND consumed_at IS NULL AND EXISTS (SELECT 1 FROM authentication_factors f WHERE f.account_did = recovery_code_digests.account_did AND f.kind = 'recoveryCode' AND f.disabled_at IS NULL) RETURNING digest", [.integer(factorTimestamp(now)), .text(accountDID), digest.sqliteData!]); guard !changed.isEmpty else { throw AccountControlStoreError.malformedRecord }
            let rows = try await connection.query("SELECT account_did, digest, issued_at, consumed_at FROM recovery_code_digests WHERE account_did = ? AND digest = ?", [.text(accountDID), digest.sqliteData!]); guard let row = rows.first else { throw AccountControlStoreError.malformedRecord }; return try RecoveryCodeDigest(accountDID: requiredText(row, "account_did"), digest: requiredBlob(row, "digest"), issuedAt: requiredDate(row, "issued_at"), consumedAt: optionalDate(row, "consumed_at"))
        } }
    }

    public func saveWebAuthnCredential(_ credential: WebAuthnCredentialMetadata, now: Date) async throws {
        try await withConnectionGate { let parent = try await connection.query("SELECT factor_id FROM authentication_factors WHERE factor_id = ? AND account_did = ? AND kind = 'passkey' AND disabled_at IS NULL", [.text(credential.factorID), .text(credential.accountDID)]); guard !parent.isEmpty else { throw AccountControlStoreError.notFound }; _ = try await connection.query("INSERT INTO webauthn_credentials(credential_id_digest, account_did, factor_id, public_key_reference, sign_count, transports, created_at, last_used_at, disabled_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", [credential.credentialIDDigest.sqliteData!, .text(credential.accountDID), .text(credential.factorID), .text(credential.publicKeyReference), .integer(Int(credential.signCount)), try JSONEncoder().encode(credential.transports).sqliteData!, .integer(factorTimestamp(credential.createdAt)), optionalTimestamp(credential.lastUsedAt), optionalTimestamp(credential.disabledAt)]) }
    }

    public func webAuthnCredential(credentialIDDigest: Data, accountDID: String, now: Date) async throws -> WebAuthnCredentialMetadata? {
        try await withConnectionGate { let rows = try await connection.query("SELECT credential_id_digest, account_did, factor_id, public_key_reference, sign_count, transports, created_at, last_used_at, disabled_at FROM webauthn_credentials WHERE credential_id_digest = ? AND account_did = ?", [credentialIDDigest.sqliteData!, .text(accountDID)]); guard let row = rows.first else { return nil }; return try decodeCredential(row) }
    }

    public func compareAndSwapWebAuthnSignCount(_ update: WebAuthnSignCountUpdate) async throws -> WebAuthnSignCountUpdateOutcome {
        try await withConnectionGate { let changed = try await connection.query("UPDATE webauthn_credentials SET sign_count = ?, last_used_at = ? WHERE credential_id_digest = ? AND account_did = ? AND sign_count = ? AND sign_count < ? AND disabled_at IS NULL AND EXISTS (SELECT 1 FROM authentication_factors f WHERE f.factor_id = webauthn_credentials.factor_id AND f.account_did = webauthn_credentials.account_did AND f.kind = 'passkey' AND f.disabled_at IS NULL) RETURNING sign_count", [.integer(Int(update.proposed)), .integer(factorTimestamp(update.now)), update.credentialIDDigest.sqliteData!, .text(update.accountDID), .integer(Int(update.expectedCurrent)), .integer(Int(update.proposed))]); if !changed.isEmpty { return .updated(newCount: update.proposed) }; let rows = try await connection.query("SELECT sign_count FROM webauthn_credentials WHERE credential_id_digest = ? AND account_did = ?", [update.credentialIDDigest.sqliteData!, .text(update.accountDID)]); guard let value = rows.first?.column("sign_count")?.integer else { throw AccountControlStoreError.notFound }; return .rollbackDetected(storedCount: UInt32(clamping: value)) }
    }

    public func compareAndSwapWebAuthnSignCountAndConsumeChallenge(_ update: WebAuthnSignCountUpdate, challengeDigest: Data, now: Date) async throws -> WebAuthnSignCountUpdateOutcome {
        try await withConnectionGate { try await ensureTask7DurableTables(); return try await transaction {
            let changed = try await connection.query("UPDATE webauthn_credentials SET sign_count = ?, last_used_at = ? WHERE credential_id_digest = ? AND account_did = ? AND sign_count = ? AND sign_count < ? AND disabled_at IS NULL AND EXISTS (SELECT 1 FROM authentication_factors f WHERE f.factor_id = webauthn_credentials.factor_id AND f.account_did = webauthn_credentials.account_did AND f.kind = 'passkey' AND f.disabled_at IS NULL) RETURNING sign_count", [.integer(Int(update.proposed)), .integer(factorTimestamp(now)), update.credentialIDDigest.sqliteData!, .text(update.accountDID), .integer(Int(update.expectedCurrent)), .integer(Int(update.proposed))])
            guard !changed.isEmpty else { let rows = try await connection.query("SELECT sign_count FROM webauthn_credentials WHERE credential_id_digest = ? AND account_did = ?", [update.credentialIDDigest.sqliteData!, .text(update.accountDID)]); guard let value = rows.first?.column("sign_count")?.integer else { throw AccountControlStoreError.notFound }; return .rollbackDetected(storedCount: UInt32(clamping: value)) }
            let consumed = try await connection.query("UPDATE webauthn_challenges SET consumed_at = ? WHERE challenge_digest = ? AND account_did = ? AND consumed_at IS NULL AND expires_at > ? RETURNING challenge_digest", [.integer(factorTimestamp(now)), challengeDigest.sqliteData!, .text(update.accountDID), .integer(factorTimestamp(now))])
            guard !consumed.isEmpty else { throw AccountControlStoreError.malformedRecord }
            return .updated(newCount: update.proposed)
        } }
    }

    public func consumeEnrollmentChallengeAndSaveCredential(challengeDigest: Data, accountDID: String, credential: WebAuthnCredentialMetadata, now: Date) async throws {
        guard credential.accountDID == accountDID else { throw AccountControlStoreError.invalidInput }
        try await withConnectionGate { try await ensureTask7DurableTables(); try await transaction {
            let consumed = try await connection.query("UPDATE webauthn_challenges SET consumed_at = ? WHERE challenge_digest = ? AND account_did = ? AND credential_id_digest IS NULL AND consumed_at IS NULL AND expires_at > ? AND EXISTS (SELECT 1 FROM mfa_webauthn_challenge_context c WHERE c.challenge_digest = webauthn_challenges.challenge_digest AND c.purpose = 'enrollment') RETURNING challenge_digest", [.integer(factorTimestamp(now)), challengeDigest.sqliteData!, .text(accountDID), .integer(factorTimestamp(now))])
            guard !consumed.isEmpty else { throw AccountControlStoreError.malformedRecord }
            let parent = try await connection.query("SELECT factor_id FROM authentication_factors WHERE factor_id = ? AND account_did = ? AND kind = 'passkey' AND disabled_at IS NULL", [.text(credential.factorID), .text(accountDID)]); guard !parent.isEmpty else { throw AccountControlStoreError.notFound }
            _ = try await connection.query("INSERT INTO webauthn_credentials(credential_id_digest, account_did, factor_id, public_key_reference, sign_count, transports, created_at, last_used_at, disabled_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", [credential.credentialIDDigest.sqliteData!, .text(accountDID), .text(credential.factorID), .text(credential.publicKeyReference), .integer(Int(credential.signCount)), try JSONEncoder().encode(credential.transports).sqliteData!, .integer(factorTimestamp(credential.createdAt)), optionalTimestamp(credential.lastUsedAt), optionalTimestamp(credential.disabledAt)])
        } }
    }

    public func disableWebAuthnCredential(credentialIDDigest: Data, accountDID: String, now: Date) async throws { try await withConnectionGate { _ = try await connection.query("UPDATE webauthn_credentials SET disabled_at = ? WHERE credential_id_digest = ? AND account_did = ? AND disabled_at IS NULL", [.integer(factorTimestamp(now)), credentialIDDigest.sqliteData!, .text(accountDID)]) } }

    public func reserveWebAuthnChallenge(_ challenge: WebAuthnChallenge, now: Date) async throws { try await withConnectionGate { try await ensureTask7DurableTables(); try await transaction { if let credential = challenge.credentialIDDigest { let parent = try await connection.query("SELECT c.credential_id_digest FROM webauthn_credentials c JOIN authentication_factors f ON f.factor_id = c.factor_id AND f.account_did = c.account_did WHERE c.credential_id_digest = ? AND c.account_did = ? AND f.kind = 'passkey' AND f.disabled_at IS NULL AND c.disabled_at IS NULL", [credential.sqliteData!, .text(challenge.accountDID)]); guard !parent.isEmpty else { throw AccountControlStoreError.notFound } }; _ = try await connection.query("INSERT INTO webauthn_challenges(challenge_digest, account_did, credential_id_digest, relying_party_id, origin, issued_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [challenge.challengeDigest.sqliteData!, .text(challenge.accountDID), challenge.credentialIDDigest.map { $0.sqliteData! } ?? .null, .text(challenge.relyingPartyID), .text(challenge.origin), .integer(factorTimestamp(challenge.issuedAt)), .integer(factorTimestamp(challenge.expiresAt)), optionalTimestamp(challenge.consumedAt)]); _ = try await connection.query("INSERT INTO mfa_webauthn_challenge_context(challenge_digest, purpose) VALUES (?, ?)", [challenge.challengeDigest.sqliteData!, .text(challenge.purpose.rawValue)]) } } }

    public func consumeWebAuthnChallenge(digest: Data, accountDID: String, now: Date) async throws -> WebAuthnChallenge {
        try await withConnectionGate { try await ensureTask7DurableTables(); return try await transaction {
            let changed = try await connection.query("UPDATE webauthn_challenges SET consumed_at = ? WHERE challenge_digest = ? AND account_did = ? AND consumed_at IS NULL AND expires_at > ? RETURNING challenge_digest", [.integer(factorTimestamp(now)), digest.sqliteData!, .text(accountDID), .integer(factorTimestamp(now))]); guard !changed.isEmpty else { throw AccountControlStoreError.malformedRecord }
            let rows = try await connection.query("SELECT challenge_digest, account_did, credential_id_digest, relying_party_id, origin, issued_at, expires_at, consumed_at FROM webauthn_challenges WHERE challenge_digest = ? AND account_did = ?", [digest.sqliteData!, .text(accountDID)]); guard let row = rows.first else { throw AccountControlStoreError.malformedRecord }; let purposeRows = try await connection.query("SELECT purpose FROM mfa_webauthn_challenge_context WHERE challenge_digest = ?", [digest.sqliteData!]); guard let purposeRow = purposeRows.first, let purpose = FactorChallengePurpose(rawValue: try requiredText(purposeRow, "purpose")) else { throw AccountControlStoreError.malformedRecord }; return try WebAuthnChallenge(challengeDigest: requiredBlob(row, "challenge_digest"), accountDID: requiredText(row, "account_did"), credentialIDDigest: optionalBlob(row, "credential_id_digest"), purpose: purpose, relyingPartyID: requiredText(row, "relying_party_id"), origin: requiredText(row, "origin"), issuedAt: requiredDate(row, "issued_at"), expiresAt: requiredDate(row, "expires_at"), consumedAt: optionalDate(row, "consumed_at"))
        } }
    }

    public func webAuthnChallenge(digest: Data, accountDID: String, now: Date) async throws -> WebAuthnChallenge? {
        return try await withConnectionGate {
            try await ensureTask7DurableTables()
            let rows = try await connection.query("SELECT challenge_digest, account_did, credential_id_digest, relying_party_id, origin, issued_at, expires_at, consumed_at FROM webauthn_challenges WHERE challenge_digest = ? AND account_did = ? AND consumed_at IS NULL AND expires_at > ?", [digest.sqliteData!, .text(accountDID), .integer(factorTimestamp(now))])
            guard let row = rows.first else { return nil }
            let purposeRows = try await connection.query("SELECT purpose FROM mfa_webauthn_challenge_context WHERE challenge_digest = ?", [digest.sqliteData!]); guard let purposeRow = purposeRows.first, let purpose = FactorChallengePurpose(rawValue: try requiredText(purposeRow, "purpose")) else { throw AccountControlStoreError.malformedRecord }
            return try WebAuthnChallenge(challengeDigest: requiredBlob(row, "challenge_digest"), accountDID: requiredText(row, "account_did"), credentialIDDigest: optionalBlob(row, "credential_id_digest"), purpose: purpose, relyingPartyID: requiredText(row, "relying_party_id"), origin: requiredText(row, "origin"), issuedAt: requiredDate(row, "issued_at"), expiresAt: requiredDate(row, "expires_at"), consumedAt: optionalDate(row, "consumed_at"))
        }
    }

    public func compareAndSwapTOTPReplay(factorID: String, accountDID: String, expected: UInt64?, proposed: UInt64, now: Date) async throws -> Bool {
        guard proposed <= UInt64(Int.max), expected.map({ $0 <= UInt64(Int.max) }) ?? true else { throw AccountControlStoreError.invalidInput }
        return try await withConnectionGate {
            try await ensureTask7DurableTables()
            let rows: [SQLiteRow]
            if let expected {
                rows = try await connection.query("UPDATE totp_replay_state SET accepted_counter = ?, updated_at = ? WHERE factor_id = ? AND account_did = ? AND accepted_counter = ? AND EXISTS (SELECT 1 FROM authentication_factors f WHERE f.factor_id = totp_replay_state.factor_id AND f.account_did = totp_replay_state.account_did AND f.kind = 'totp' AND f.disabled_at IS NULL) RETURNING factor_id", [.integer(Int(proposed)), .integer(factorTimestamp(now)), .text(factorID), .text(accountDID), .integer(Int(expected))])
            } else {
                rows = try await connection.query("INSERT INTO totp_replay_state(factor_id, account_did, accepted_counter, updated_at) SELECT ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM authentication_factors WHERE factor_id = ? AND account_did = ? AND kind = 'totp' AND disabled_at IS NULL) ON CONFLICT(factor_id, account_did) DO UPDATE SET accepted_counter = excluded.accepted_counter, updated_at = excluded.updated_at WHERE totp_replay_state.accepted_counter < excluded.accepted_counter RETURNING factor_id", [.text(factorID), .text(accountDID), .integer(Int(proposed)), .integer(factorTimestamp(now)), .text(factorID), .text(accountDID)])
            }
            return !rows.isEmpty
        }
    }

    public func saveFactorToken(_ record: DurableFactorTokenRecord, now: Date) async throws {
        try await withConnectionGate {
            try await ensureTask7DurableTables()
            let strength = try JSONEncoder().encode(record.strength)
            _ = try await connection.query("DELETE FROM mfa_factor_tokens WHERE expires_at <= ? OR consumed_at IS NOT NULL OR revoked_at IS NOT NULL", [.integer(factorTimestamp(now))])
            _ = try await connection.query("INSERT INTO mfa_factor_tokens(digest, account_did, session_id, purpose, factor, strength, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [record.digest.sqliteData!, .text(record.accountDID), .text(record.sessionID), .text(record.purpose), .text(record.factor.rawValue), strength.sqliteData!, .integer(factorTimestamp(record.issuedAt)), .integer(factorTimestamp(record.expiresAt))])
        }
    }

    public func consumeFactorToken(digest: Data, accountDID: String, sessionID: String, purpose: String, factor: AuthenticationFactorKind, strength: AuthenticationStrength, now: Date) async throws -> DurableFactorTokenRecord {
        try await withConnectionGate { try await transaction {
            try await ensureTask7DurableTables()
            let strengthData = try JSONEncoder().encode(strength)
            let rows = try await connection.query("UPDATE mfa_factor_tokens SET consumed_at = ? WHERE digest = ? AND account_did = ? AND session_id = ? AND purpose = ? AND factor = ? AND strength = ? AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > ? RETURNING digest, account_did, session_id, purpose, factor, strength, issued_at, expires_at", [.integer(factorTimestamp(now)), digest.sqliteData!, .text(accountDID), .text(sessionID), .text(purpose), .text(factor.rawValue), strengthData.sqliteData!, .integer(factorTimestamp(now))])
            guard let row = rows.first, let factor = AuthenticationFactorKind(rawValue: try requiredText(row, "factor")) else { throw AccountControlStoreError.notFound }
            return try DurableFactorTokenRecord(digest: requiredBlob(row, "digest"), accountDID: requiredText(row, "account_did"), sessionID: requiredText(row, "session_id"), purpose: requiredText(row, "purpose"), factor: factor, strength: try JSONDecoder().decode(AuthenticationStrength.self, from: requiredBlob(row, "strength")), issuedAt: requiredDate(row, "issued_at"), expiresAt: requiredDate(row, "expires_at"))
        } }
    }

    public func revokeFactorTokens(accountDID: String, sessionID: String?, now: Date) async throws {
        try await withConnectionGate { try await ensureTask7DurableTables(); if let sessionID { _ = try await connection.query("UPDATE mfa_factor_tokens SET revoked_at = ? WHERE account_did = ? AND session_id = ? AND revoked_at IS NULL", [.integer(factorTimestamp(now)), .text(accountDID), .text(sessionID)]) } else { _ = try await connection.query("UPDATE mfa_factor_tokens SET revoked_at = ? WHERE account_did = ? AND revoked_at IS NULL", [.integer(factorTimestamp(now)), .text(accountDID)]) } }
    }

    public func appendMFAAuditEvent(_ event: MFAAuditEventRecord, now: Date) async throws {
        try await withConnectionGate {
            try await ensureTask7DurableTables()
            _ = try await connection.query("INSERT INTO mfa_audit_events(event, account_did, factor_id, success, occurred_at) VALUES (?, ?, ?, ?, ?)", [.text(event.event), .text(event.accountDID), event.factorID.map(SQLiteData.text) ?? .null, .integer(event.success ? 1 : 0), .integer(factorTimestamp(event.occurredAt))])
            _ = try await connection.query("DELETE FROM mfa_audit_events WHERE event_id NOT IN (SELECT event_id FROM mfa_audit_events ORDER BY event_id DESC LIMIT 10000)")
        }
    }
}

private extension SQLiteControlDatabase {
    func ensureTask7DurableTables() async throws {
        // This is intentionally adapter-local: Task 6 owns migration ordering.
        // IF NOT EXISTS makes the seam safe for already-provisioned databases.
        _ = try await connection.query("CREATE TABLE IF NOT EXISTS totp_replay_state (factor_id TEXT NOT NULL, account_did TEXT NOT NULL, accepted_counter INTEGER NOT NULL CHECK(accepted_counter >= 0), updated_at INTEGER NOT NULL, PRIMARY KEY(factor_id, account_did))")
        _ = try await connection.query("CREATE TABLE IF NOT EXISTS mfa_factor_tokens (digest BLOB PRIMARY KEY CHECK(length(digest) = 32), account_did TEXT NOT NULL, session_id TEXT NOT NULL, purpose TEXT NOT NULL, factor TEXT NOT NULL, strength BLOB NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER, revoked_at INTEGER)")
        _ = try await connection.query("CREATE TABLE IF NOT EXISTS mfa_audit_events (event_id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, account_did TEXT NOT NULL, factor_id TEXT, success INTEGER NOT NULL, occurred_at INTEGER NOT NULL)")
        _ = try await connection.query("CREATE TABLE IF NOT EXISTS mfa_webauthn_challenge_context (challenge_digest BLOB PRIMARY KEY CHECK(length(challenge_digest) = 32), purpose TEXT NOT NULL)")
    }
}

private func factorTimestamp(_ date: Date) -> Int { Int((date.timeIntervalSince1970 * 1_000_000).rounded(.down)) }
private func optionalTimestamp(_ date: Date?) -> SQLiteData { date.map { .integer(factorTimestamp($0)) } ?? .null }
private func requiredText(_ row: SQLiteRow, _ key: String) throws -> String { guard case let .text(value) = row.column(key) else { throw AccountControlStoreError.malformedRecord }; return value }
private func requiredBlob(_ row: SQLiteRow, _ key: String) throws -> Data { guard let value = row.column(key), let data = Data(sqliteData: value) else { throw AccountControlStoreError.malformedRecord }; return data }
private func optionalBlob(_ row: SQLiteRow, _ key: String) throws -> Data? { guard let value = row.column(key) else { throw AccountControlStoreError.malformedRecord }; return value.isNull ? nil : try requiredBlob(row, key) }
private func requiredDate(_ row: SQLiteRow, _ key: String) throws -> Date { guard case let .integer(value) = row.column(key) else { throw AccountControlStoreError.malformedRecord }; return Date(timeIntervalSince1970: Double(value) / 1_000_000) }
private func optionalDate(_ row: SQLiteRow, _ key: String) throws -> Date? { guard let value = row.column(key) else { throw AccountControlStoreError.malformedRecord }; if value.isNull { return nil }; return try requiredDate(row, key) }
private func decodeFactor(_ row: SQLiteRow) throws -> AuthenticationFactorMetadata { guard let kind = AuthenticationFactorKind(rawValue: try requiredText(row, "kind")) else { throw AccountControlStoreError.malformedRecord }; return try AuthenticationFactorMetadata(id: requiredText(row, "factor_id"), accountDID: requiredText(row, "account_did"), kind: kind, label: requiredText(row, "label"), lookupDigest: requiredBlob(row, "lookup_digest"), createdAt: requiredDate(row, "created_at"), lastUsedAt: optionalDate(row, "last_used_at"), disabledAt: optionalDate(row, "disabled_at")) }
private func decodeChallenge(_ row: SQLiteRow) throws -> FactorChallenge { guard let purpose = FactorChallengePurpose(rawValue: try requiredText(row, "purpose")) else { throw AccountControlStoreError.malformedRecord }; return try FactorChallenge(challengeDigest: requiredBlob(row, "challenge_digest"), accountDID: requiredText(row, "account_did"), factorID: optionalText(row, "factor_id"), purpose: purpose, issuedAt: requiredDate(row, "issued_at"), expiresAt: requiredDate(row, "expires_at"), consumedAt: optionalDate(row, "consumed_at")) }
private func optionalText(_ row: SQLiteRow, _ key: String) throws -> String? { guard let value = row.column(key) else { throw AccountControlStoreError.malformedRecord }; if value.isNull { return nil }; return try requiredText(row, key) }
private func decodeCredential(_ row: SQLiteRow) throws -> WebAuthnCredentialMetadata { try WebAuthnCredentialMetadata(credentialIDDigest: requiredBlob(row, "credential_id_digest"), accountDID: requiredText(row, "account_did"), factorID: requiredText(row, "factor_id"), publicKeyReference: requiredText(row, "public_key_reference"), signCount: UInt32(clamping: row.column("sign_count")?.integer ?? 0), transports: Set(try JSONDecoder().decode([String].self, from: requiredBlob(row, "transports"))), createdAt: requiredDate(row, "created_at"), lastUsedAt: optionalDate(row, "last_used_at"), disabledAt: optionalDate(row, "disabled_at")) }
