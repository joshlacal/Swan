import Foundation
import Crypto
import SQLiteNIO
import SwanCore
import SwanStorage

extension SQLiteControlDatabase: AuthenticationFactorStore, TOTPSecretStore, RecoveryCodeStore, WebAuthnCredentialStore, WebAuthnChallengeStore {
    public func listFactors(accountDID: String, now: Date) async throws -> [AuthenticationFactorMetadata] {
        try await withConnectionGate {
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
        try await withConnectionGate { _ = try await transaction { _ = try await connection.query("DELETE FROM factor_challenges WHERE expires_at <= ?", [.integer(factorTimestamp(now))]) } }
    }

    public func saveTOTPEnvelope(_ envelope: TOTPSecretEnvelope, now: Date) async throws {
        try await withConnectionGate {
            let inserted = try await connection.query("INSERT INTO totp_secret_envelopes(factor_id, account_did, key_reference, nonce, ciphertext, authentication_tag) SELECT ?, account_did, ?, ?, ?, ? FROM authentication_factors WHERE factor_id = ? RETURNING factor_id", [.text(envelope.factorID), .text(envelope.keyReference), envelope.nonce.sqliteData!, envelope.ciphertext.sqliteData!, envelope.authenticationTag.sqliteData!, .text(envelope.factorID)])
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
            let changed = try await connection.query("UPDATE recovery_code_digests SET consumed_at = ? WHERE account_did = ? AND digest = ? AND consumed_at IS NULL RETURNING digest", [.integer(factorTimestamp(now)), .text(accountDID), digest.sqliteData!]); guard !changed.isEmpty else { throw AccountControlStoreError.malformedRecord }
            let rows = try await connection.query("SELECT account_did, digest, issued_at, consumed_at FROM recovery_code_digests WHERE account_did = ? AND digest = ?", [.text(accountDID), digest.sqliteData!]); guard let row = rows.first else { throw AccountControlStoreError.malformedRecord }; return try RecoveryCodeDigest(accountDID: requiredText(row, "account_did"), digest: requiredBlob(row, "digest"), issuedAt: requiredDate(row, "issued_at"), consumedAt: optionalDate(row, "consumed_at"))
        } }
    }

    public func saveWebAuthnCredential(_ credential: WebAuthnCredentialMetadata, now: Date) async throws {
        try await withConnectionGate { _ = try await connection.query("INSERT INTO webauthn_credentials(credential_id_digest, account_did, factor_id, public_key_reference, sign_count, transports, created_at, last_used_at, disabled_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", [credential.credentialIDDigest.sqliteData!, .text(credential.accountDID), .text(credential.factorID), .text(credential.publicKeyReference), .integer(Int(credential.signCount)), try JSONEncoder().encode(credential.transports).sqliteData!, .integer(factorTimestamp(credential.createdAt)), optionalTimestamp(credential.lastUsedAt), optionalTimestamp(credential.disabledAt)]) }
    }

    public func webAuthnCredential(credentialIDDigest: Data, accountDID: String, now: Date) async throws -> WebAuthnCredentialMetadata? {
        try await withConnectionGate { let rows = try await connection.query("SELECT credential_id_digest, account_did, factor_id, public_key_reference, sign_count, transports, created_at, last_used_at, disabled_at FROM webauthn_credentials WHERE credential_id_digest = ? AND account_did = ?", [credentialIDDigest.sqliteData!, .text(accountDID)]); guard let row = rows.first else { return nil }; return try decodeCredential(row) }
    }

    public func compareAndSwapWebAuthnSignCount(_ update: WebAuthnSignCountUpdate) async throws -> WebAuthnSignCountUpdateOutcome {
        try await withConnectionGate { let changed = try await connection.query("UPDATE webauthn_credentials SET sign_count = ?, last_used_at = ? WHERE credential_id_digest = ? AND account_did = ? AND sign_count = ? AND sign_count < ? AND disabled_at IS NULL RETURNING sign_count", [.integer(Int(update.proposed)), .integer(factorTimestamp(update.now)), update.credentialIDDigest.sqliteData!, .text(update.accountDID), .integer(Int(update.expectedCurrent)), .integer(Int(update.proposed))]); if !changed.isEmpty { return .updated(newCount: update.proposed) }; let rows = try await connection.query("SELECT sign_count FROM webauthn_credentials WHERE credential_id_digest = ? AND account_did = ?", [update.credentialIDDigest.sqliteData!, .text(update.accountDID)]); guard let value = rows.first?.column("sign_count")?.integer else { throw AccountControlStoreError.notFound }; return .rollbackDetected(storedCount: UInt32(clamping: value)) }
    }

    public func disableWebAuthnCredential(credentialIDDigest: Data, accountDID: String, now: Date) async throws { try await withConnectionGate { _ = try await connection.query("UPDATE webauthn_credentials SET disabled_at = ? WHERE credential_id_digest = ? AND account_did = ? AND disabled_at IS NULL", [.integer(factorTimestamp(now)), credentialIDDigest.sqliteData!, .text(accountDID)]) } }

    public func reserveWebAuthnChallenge(_ challenge: WebAuthnChallenge, now: Date) async throws { try await withConnectionGate { _ = try await connection.query("INSERT INTO webauthn_challenges(challenge_digest, account_did, credential_id_digest, relying_party_id, origin, issued_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [challenge.challengeDigest.sqliteData!, .text(challenge.accountDID), challenge.credentialIDDigest.map { $0.sqliteData! } ?? .null, .text(challenge.relyingPartyID), .text(challenge.origin), .integer(factorTimestamp(challenge.issuedAt)), .integer(factorTimestamp(challenge.expiresAt)), optionalTimestamp(challenge.consumedAt)]) } }

    public func consumeWebAuthnChallenge(digest: Data, accountDID: String, now: Date) async throws -> WebAuthnChallenge {
        try await withConnectionGate { try await transaction {
            let changed = try await connection.query("UPDATE webauthn_challenges SET consumed_at = ? WHERE challenge_digest = ? AND account_did = ? AND consumed_at IS NULL AND expires_at > ? RETURNING challenge_digest", [.integer(factorTimestamp(now)), digest.sqliteData!, .text(accountDID), .integer(factorTimestamp(now))]); guard !changed.isEmpty else { throw AccountControlStoreError.malformedRecord }
            let rows = try await connection.query("SELECT challenge_digest, account_did, credential_id_digest, relying_party_id, origin, issued_at, expires_at, consumed_at FROM webauthn_challenges WHERE challenge_digest = ? AND account_did = ?", [digest.sqliteData!, .text(accountDID)]); guard let row = rows.first else { throw AccountControlStoreError.malformedRecord }; return try WebAuthnChallenge(challengeDigest: requiredBlob(row, "challenge_digest"), accountDID: requiredText(row, "account_did"), credentialIDDigest: optionalBlob(row, "credential_id_digest"), relyingPartyID: requiredText(row, "relying_party_id"), origin: requiredText(row, "origin"), issuedAt: requiredDate(row, "issued_at"), expiresAt: requiredDate(row, "expires_at"), consumedAt: optionalDate(row, "consumed_at"))
        } }
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
