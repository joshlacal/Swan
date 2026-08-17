import Foundation
import Crypto
import SQLiteNIO
import SwanCore
import SwanStorage

extension SQLiteControlDatabase: AuthenticationFactorStore, TOTPEnrollmentStore, RecoveryCodeStore, WebAuthnCredentialStore, WebAuthnChallengeStore, WebAuthnChallengeLookupStore, WebAuthnAtomicVerificationStore, WebAuthnEnrollmentStore, TOTPReplayStore, DurableFactorTokenAuthorizationStore, MFAAuditStore, OAuthMFAAdmissionStore {
    public func listFactors(accountDID: String, now: Date) async throws -> [AuthenticationFactorMetadata] {
        return try await withConnectionGate {
            let rows = try await connection.query("SELECT factor_id, account_did, kind, label, lookup_digest, created_at, last_used_at, disabled_at FROM authentication_factors WHERE account_did = ? AND created_at <= ? AND disabled_at IS NULL ORDER BY created_at, factor_id", [.text(accountDID), .integer(try factorTimestamp(now))])
            return try rows.map(decodeFactor)
        }
    }

    public func saveFactor(_ factor: AuthenticationFactorMetadata, now: Date) async throws {
        guard factor.createdAt <= now, factor.lastUsedAt.map({ $0 <= now }) ?? true, factor.disabledAt.map({ $0 <= now }) ?? true else { throw AccountControlStoreError.invalidInput }
        try await withConnectionGate {
            try await ensureTask7DurableTables()
            try await transaction {
                _ = try await connection.query("INSERT INTO authentication_factors(factor_id, account_did, kind, label, lookup_digest, created_at, last_used_at, disabled_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [.text(factor.id), .text(factor.accountDID), .text(factor.kind.rawValue), .text(factor.label), factor.lookupDigest.sqliteData!, .integer(try factorTimestamp(factor.createdAt)), try optionalTimestamp(factor.lastUsedAt), try optionalTimestamp(factor.disabledAt)])
                try await bumpFactorRevision(accountDID: factor.accountDID)
            }
        }
    }

    public func saveFactorIfAbsent(_ factor: AuthenticationFactorMetadata, now: Date) async throws -> Bool {
        guard factor.createdAt <= now, factor.lastUsedAt.map({ $0 <= now }) ?? true,
              factor.disabledAt.map({ $0 <= now }) ?? true else {
            throw AccountControlStoreError.invalidInput
        }
        return try await withConnectionGate {
            try await ensureTask7DurableTables()
            return try await transaction {
                let inserted = try await connection.query(
                    "INSERT INTO authentication_factors(factor_id, account_did, kind, label, lookup_digest, created_at, last_used_at, disabled_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(factor_id) DO NOTHING RETURNING factor_id",
                    [
                        .text(factor.id), .text(factor.accountDID), .text(factor.kind.rawValue),
                        .text(factor.label), factor.lookupDigest.sqliteData!,
                        .integer(try factorTimestamp(factor.createdAt)),
                        try optionalTimestamp(factor.lastUsedAt),
                        try optionalTimestamp(factor.disabledAt),
                    ]
                )
                if !inserted.isEmpty { try await bumpFactorRevision(accountDID: factor.accountDID) }
                return !inserted.isEmpty
            }
        }
    }

    public func disableFactor(id: String, accountDID: String, now: Date) async throws {
        try await withConnectionGate {
            try await ensureTask7DurableTables()
            try await transaction {
                let changed = try await connection.query("UPDATE authentication_factors SET disabled_at = ? WHERE factor_id = ? AND account_did = ? AND disabled_at IS NULL RETURNING factor_id", [.integer(try factorTimestamp(now)), .text(id), .text(accountDID)])
                if !changed.isEmpty { try await bumpFactorRevision(accountDID: accountDID) }
            }
        }
    }

    public func reserveChallenge(_ challenge: FactorChallenge, now: Date) async throws {
        guard challenge.issuedAt <= now, challenge.expiresAt > now else { throw AccountControlStoreError.invalidInput }
        try await withConnectionGate { if let factorID = challenge.factorID { let parent = try await connection.query("SELECT factor_id FROM authentication_factors WHERE factor_id = ? AND account_did = ? AND disabled_at IS NULL AND kind IN ('totp','passkey','recoveryCode')", [.text(factorID), .text(challenge.accountDID)]); guard !parent.isEmpty else { throw AccountControlStoreError.notFound } }; _ = try await connection.query("INSERT INTO factor_challenges(challenge_digest, account_did, factor_id, purpose, issued_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, ?)", [challenge.challengeDigest.sqliteData!, .text(challenge.accountDID), challenge.factorID.map(SQLiteData.text) ?? .null, .text(challenge.purpose.rawValue), .integer(try factorTimestamp(challenge.issuedAt)), .integer(try factorTimestamp(challenge.expiresAt)), try optionalTimestamp(challenge.consumedAt)]) }
    }

    public func consumeChallenge(digest: Data, now: Date) async throws -> FactorChallenge {
        try await withConnectionGate { try await transaction {
            let changed = try await connection.query("UPDATE factor_challenges SET consumed_at = ? WHERE challenge_digest = ? AND issued_at <= ? AND consumed_at IS NULL AND expires_at > ? AND (factor_id IS NULL OR EXISTS (SELECT 1 FROM authentication_factors f WHERE f.factor_id = factor_challenges.factor_id AND f.account_did = factor_challenges.account_did AND f.disabled_at IS NULL)) RETURNING challenge_digest", [.integer(try factorTimestamp(now)), digest.sqliteData!, .integer(try factorTimestamp(now)), .integer(try factorTimestamp(now))])
            guard !changed.isEmpty else { throw AccountControlStoreError.malformedRecord }
            let rows = try await connection.query("SELECT challenge_digest, account_did, factor_id, purpose, issued_at, expires_at, consumed_at FROM factor_challenges WHERE challenge_digest = ?", [digest.sqliteData!])
            guard let row = rows.first else { throw AccountControlStoreError.malformedRecord }
            return try decodeChallenge(row)
        } }
    }

    public func purgeExpiredFactorState(now: Date) async throws {
        try await withConnectionGate { try await ensureTask7DurableTables(); _ = try await transaction { _ = try await connection.query("DELETE FROM factor_challenges WHERE expires_at <= ?", [.integer(try factorTimestamp(now))]); _ = try await connection.query("DELETE FROM webauthn_challenges WHERE expires_at <= ?", [.integer(try factorTimestamp(now))]); _ = try await connection.query("DELETE FROM mfa_webauthn_challenge_context WHERE challenge_digest NOT IN (SELECT challenge_digest FROM webauthn_challenges)", []) } }
    }

    public func saveTOTPEnvelope(_ envelope: TOTPSecretEnvelope, now: Date) async throws {
        try await withConnectionGate {
            guard envelope.ciphertext.count <= 4096, envelope.nonce.count == 12, envelope.authenticationTag.count == 16 else { throw AccountControlStoreError.invalidInput }
            let inserted = try await connection.query("INSERT INTO totp_secret_envelopes(factor_id, account_did, key_reference, nonce, ciphertext, authentication_tag) SELECT ?, account_did, ?, ?, ?, ? FROM authentication_factors WHERE factor_id = ? AND kind = 'totp' AND disabled_at IS NULL RETURNING factor_id", [.text(envelope.factorID), .text(envelope.keyReference), envelope.nonce.sqliteData!, envelope.ciphertext.sqliteData!, envelope.authenticationTag.sqliteData!, .text(envelope.factorID)])
            guard !inserted.isEmpty else { throw AccountControlStoreError.notFound }
        }
    }

    public func savePendingTOTPEnvelope(_ envelope: TOTPSecretEnvelope, accountDID: String, expiresAt: Date, now: Date) async throws {
        guard envelope.ciphertext.count <= 4096, envelope.nonce.count == 12,
              envelope.authenticationTag.count == 16, envelope.factorID.count <= 128,
              envelope.keyReference.count <= 256, expiresAt > now else {
            throw AccountControlStoreError.invalidInput
        }
        try await withConnectionGate {
            try await ensureTask7DurableTables()
            let parent = try await connection.query(
                "SELECT factor_id FROM authentication_factors WHERE factor_id = ? AND account_did = ? AND kind = 'totp' AND disabled_at IS NOT NULL",
                [.text(envelope.factorID), .text(accountDID)]
            )
            guard !parent.isEmpty else { throw AccountControlStoreError.notFound }
            _ = try await connection.query(
                "INSERT INTO totp_pending_secret_envelopes(factor_id, account_did, key_reference, nonce, ciphertext, authentication_tag, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [.text(envelope.factorID), .text(accountDID), .text(envelope.keyReference), envelope.nonce.sqliteData!, envelope.ciphertext.sqliteData!, envelope.authenticationTag.sqliteData!, .integer(try factorTimestamp(now)), .integer(try factorTimestamp(expiresAt))]
            )
        }
    }

    public func pendingTOTPEnvelope(factorID: String, accountDID: String, now: Date) async throws -> TOTPSecretEnvelope? {
        try await withConnectionGate {
            try await ensureTask7DurableTables()
            let rows = try await connection.query(
                "SELECT factor_id, key_reference, nonce, ciphertext, authentication_tag FROM totp_pending_secret_envelopes WHERE factor_id = ? AND account_did = ? AND issued_at <= ? AND expires_at > ?",
                [.text(factorID), .text(accountDID), .integer(try factorTimestamp(now)), .integer(try factorTimestamp(now))]
            )
            guard let row = rows.first else { return nil }
            return try TOTPSecretEnvelope(
                factorID: try requiredText(row, "factor_id"),
                keyReference: try requiredText(row, "key_reference"),
                nonce: try requiredBlob(row, "nonce"),
                ciphertext: try requiredBlob(row, "ciphertext"),
                authenticationTag: try requiredBlob(row, "authentication_tag")
            )
        }
    }

    public func activatePendingTOTPEnvelope(factorID: String, accountDID: String, now: Date) async throws -> TOTPSecretEnvelope {
        try await withConnectionGate { try await transaction {
            try await ensureTask7DurableTables()
            let timestamp = try factorTimestamp(now)
            let rows = try await connection.query(
                "SELECT factor_id, key_reference, nonce, ciphertext, authentication_tag FROM totp_pending_secret_envelopes WHERE factor_id = ? AND account_did = ? AND issued_at <= ? AND expires_at > ?",
                [.text(factorID), .text(accountDID), .integer(timestamp), .integer(timestamp)]
            )
            guard let row = rows.first else { throw AccountControlStoreError.notFound }
            let envelope = try TOTPSecretEnvelope(
                factorID: try requiredText(row, "factor_id"),
                keyReference: try requiredText(row, "key_reference"),
                nonce: try requiredBlob(row, "nonce"),
                ciphertext: try requiredBlob(row, "ciphertext"),
                authenticationTag: try requiredBlob(row, "authentication_tag")
            )
            let enabled = try await connection.query(
                "UPDATE authentication_factors SET disabled_at = NULL WHERE factor_id = ? AND account_did = ? AND kind = 'totp' AND disabled_at IS NOT NULL RETURNING factor_id",
                [.text(factorID), .text(accountDID)]
            )
            guard !enabled.isEmpty else { throw AccountControlStoreError.notFound }
            try await bumpFactorRevision(accountDID: accountDID)
            _ = try await connection.query(
                "INSERT INTO totp_secret_envelopes(factor_id, account_did, key_reference, nonce, ciphertext, authentication_tag) VALUES (?, ?, ?, ?, ?, ?)",
                [.text(factorID), .text(accountDID), .text(envelope.keyReference), envelope.nonce.sqliteData!, envelope.ciphertext.sqliteData!, envelope.authenticationTag.sqliteData!]
            )
            _ = try await connection.query(
                "DELETE FROM totp_pending_secret_envelopes WHERE factor_id = ? AND account_did = ?",
                [.text(factorID), .text(accountDID)]
            )
            return envelope
        } }
    }

    public func totpEnvelope(factorID: String, accountDID: String) async throws -> TOTPSecretEnvelope? {
        try await withConnectionGate { let rows = try await connection.query("SELECT e.factor_id, e.key_reference, e.nonce, e.ciphertext, e.authentication_tag FROM totp_secret_envelopes e JOIN authentication_factors f ON f.factor_id = e.factor_id AND f.account_did = e.account_did AND f.kind = 'totp' AND f.disabled_at IS NULL WHERE e.factor_id = ? AND e.account_did = ?", [.text(factorID), .text(accountDID)]); guard let row = rows.first else { return nil }; return try TOTPSecretEnvelope(factorID: try requiredText(row, "factor_id"), keyReference: try requiredText(row, "key_reference"), nonce: try requiredBlob(row, "nonce"), ciphertext: try requiredBlob(row, "ciphertext"), authenticationTag: try requiredBlob(row, "authentication_tag")) }
    }

    public func deleteTOTPEnvelope(factorID: String, accountDID: String, now: Date) async throws {
        try await withConnectionGate { _ = try await connection.query("DELETE FROM totp_secret_envelopes WHERE factor_id = ? AND account_did = ?", [.text(factorID), .text(accountDID)]) }
    }

    public func replaceRecoveryCodeDigests(accountDID: String, digests: [RecoveryCodeDigest], now: Date) async throws {
        guard digests.count <= 32 else { throw AccountControlStoreError.invalidInput }
        guard digests.allSatisfy({ $0.issuedAt <= now }) else { throw AccountControlStoreError.invalidInput }
        try await withConnectionGate { try await ensureTask7DurableTables(); try await transaction { let parent = try await connection.query("SELECT factor_id FROM authentication_factors WHERE account_did = ? AND kind = 'recoveryCode' AND disabled_at IS NULL", [.text(accountDID)]); guard !parent.isEmpty else { throw AccountControlStoreError.notFound }; _ = try await connection.query("DELETE FROM recovery_code_digests WHERE account_did = ?", [.text(accountDID)]); for digest in digests { _ = try await connection.query("INSERT INTO recovery_code_digests(account_did, digest, issued_at, consumed_at) VALUES (?, ?, ?, ?)", [.text(accountDID), digest.digest.sqliteData!, .integer(try factorTimestamp(digest.issuedAt)), try optionalTimestamp(digest.consumedAt)]) }; try await bumpFactorRevision(accountDID: accountDID) } }
    }

    public func consumeRecoveryCode(digest: Data, accountDID: String, now: Date) async throws -> RecoveryCodeDigest {
        try await withConnectionGate { try await transaction {
            let changed = try await connection.query("UPDATE recovery_code_digests SET consumed_at = ? WHERE account_did = ? AND digest = ? AND issued_at <= ? AND consumed_at IS NULL AND EXISTS (SELECT 1 FROM authentication_factors f WHERE f.account_did = recovery_code_digests.account_did AND f.kind = 'recoveryCode' AND f.disabled_at IS NULL) RETURNING digest", [.integer(try factorTimestamp(now)), .text(accountDID), digest.sqliteData!, .integer(try factorTimestamp(now))]); guard !changed.isEmpty else { throw AccountControlStoreError.malformedRecord }
            let rows = try await connection.query("SELECT account_did, digest, issued_at, consumed_at FROM recovery_code_digests WHERE account_did = ? AND digest = ?", [.text(accountDID), digest.sqliteData!]); guard let row = rows.first else { throw AccountControlStoreError.malformedRecord }; return try RecoveryCodeDigest(accountDID: requiredText(row, "account_did"), digest: requiredBlob(row, "digest"), issuedAt: requiredDate(row, "issued_at"), consumedAt: optionalDate(row, "consumed_at"))
        } }
    }

    public func saveWebAuthnCredential(_ credential: WebAuthnCredentialMetadata, now: Date) async throws {
        guard credential.createdAt <= now else { throw AccountControlStoreError.invalidInput }
        try await withConnectionGate { let transports = try JSONEncoder().encode(credential.transports); let inserted = try await connection.query("INSERT INTO webauthn_credentials(credential_id_digest, account_did, factor_id, public_key_reference, sign_count, transports, created_at, last_used_at, disabled_at) SELECT ?, account_did, factor_id, ?, ?, ?, ?, ?, ? FROM authentication_factors WHERE factor_id = ? AND account_did = ? AND kind = 'passkey' AND disabled_at IS NULL RETURNING credential_id_digest", [credential.credentialIDDigest.sqliteData!, .text(credential.publicKeyReference), .integer(Int(credential.signCount)), transports.sqliteData!, .integer(try factorTimestamp(credential.createdAt)), try optionalTimestamp(credential.lastUsedAt), try optionalTimestamp(credential.disabledAt), .text(credential.factorID), .text(credential.accountDID)]); guard !inserted.isEmpty else { throw AccountControlStoreError.notFound } }
    }

    public func webAuthnCredential(credentialIDDigest: Data, accountDID: String, now: Date) async throws -> WebAuthnCredentialMetadata? {
        // Future-created credentials are corrupt and never usable.
        try await withConnectionGate { let rows = try await connection.query("SELECT credential_id_digest, account_did, factor_id, public_key_reference, sign_count, transports, created_at, last_used_at, disabled_at FROM webauthn_credentials WHERE credential_id_digest = ? AND account_did = ?", [credentialIDDigest.sqliteData!, .text(accountDID)]); guard let row = rows.first else { return nil }; let value = try decodeCredential(row); guard value.createdAt <= now else { throw AccountControlStoreError.malformedRecord }; return value }
    }

    public func compareAndSwapWebAuthnSignCount(_ update: WebAuthnSignCountUpdate) async throws -> WebAuthnSignCountUpdateOutcome {
        try await withConnectionGate { let changed = try await connection.query("UPDATE webauthn_credentials SET sign_count = ?, last_used_at = ? WHERE credential_id_digest = ? AND account_did = ? AND sign_count = ? AND sign_count < ? AND disabled_at IS NULL AND EXISTS (SELECT 1 FROM authentication_factors f WHERE f.factor_id = webauthn_credentials.factor_id AND f.account_did = webauthn_credentials.account_did AND f.kind = 'passkey' AND f.disabled_at IS NULL) RETURNING sign_count", [.integer(Int(update.proposed)), .integer(try factorTimestamp(update.now)), update.credentialIDDigest.sqliteData!, .text(update.accountDID), .integer(Int(update.expectedCurrent)), .integer(Int(update.proposed))]); if !changed.isEmpty { return .updated(newCount: update.proposed) }; let rows = try await connection.query("SELECT sign_count FROM webauthn_credentials WHERE credential_id_digest = ? AND account_did = ?", [update.credentialIDDigest.sqliteData!, .text(update.accountDID)]); guard let value = rows.first?.column("sign_count")?.integer else { throw AccountControlStoreError.notFound }; return .rollbackDetected(storedCount: UInt32(clamping: value)) }
    }

    public func compareAndSwapWebAuthnSignCountAndConsumeChallenge(_ update: WebAuthnSignCountUpdate, challengeDigest: Data, now: Date) async throws -> WebAuthnSignCountUpdateOutcome {
        try await withConnectionGate { try await ensureTask7DurableTables(); return try await transaction {
            let changed = try await connection.query("UPDATE webauthn_credentials SET sign_count = ?, last_used_at = ? WHERE credential_id_digest = ? AND account_did = ? AND sign_count = ? AND sign_count < ? AND disabled_at IS NULL AND EXISTS (SELECT 1 FROM authentication_factors f WHERE f.factor_id = webauthn_credentials.factor_id AND f.account_did = webauthn_credentials.account_did AND f.kind = 'passkey' AND f.disabled_at IS NULL) RETURNING sign_count", [.integer(Int(update.proposed)), .integer(try factorTimestamp(now)), update.credentialIDDigest.sqliteData!, .text(update.accountDID), .integer(Int(update.expectedCurrent)), .integer(Int(update.proposed))])
            guard !changed.isEmpty else { let rows = try await connection.query("SELECT sign_count FROM webauthn_credentials WHERE credential_id_digest = ? AND account_did = ?", [update.credentialIDDigest.sqliteData!, .text(update.accountDID)]); guard let value = rows.first?.column("sign_count")?.integer else { throw AccountControlStoreError.notFound }; return .rollbackDetected(storedCount: UInt32(clamping: value)) }
            let consumed = try await connection.query("UPDATE webauthn_challenges SET consumed_at = ? WHERE challenge_digest = ? AND account_did = ? AND issued_at <= ? AND (credential_id_digest IS NULL OR credential_id_digest = ?) AND consumed_at IS NULL AND expires_at > ? AND EXISTS (SELECT 1 FROM mfa_webauthn_challenge_context c WHERE c.challenge_digest = webauthn_challenges.challenge_digest AND c.purpose IN ('assertion', 'stepUp')) RETURNING challenge_digest", [.integer(try factorTimestamp(now)), challengeDigest.sqliteData!, .text(update.accountDID), .integer(try factorTimestamp(now)), update.credentialIDDigest.sqliteData!, .integer(try factorTimestamp(now))])
            guard !consumed.isEmpty else { throw AccountControlStoreError.malformedRecord }
            return .updated(newCount: update.proposed)
        } }
    }

    public func consumeEnrollmentChallengeAndSaveCredential(challengeDigest: Data, accountDID: String, credential: WebAuthnCredentialMetadata, now: Date) async throws {
        guard credential.accountDID == accountDID else { throw AccountControlStoreError.invalidInput }
        try await withConnectionGate { try await ensureTask7DurableTables(); try await transaction {
            let consumed = try await connection.query("UPDATE webauthn_challenges SET consumed_at = ? WHERE challenge_digest = ? AND account_did = ? AND credential_id_digest IS NULL AND issued_at <= ? AND consumed_at IS NULL AND expires_at > ? AND EXISTS (SELECT 1 FROM mfa_webauthn_challenge_context c WHERE c.challenge_digest = webauthn_challenges.challenge_digest AND c.purpose = 'enrollment') RETURNING challenge_digest", [.integer(try factorTimestamp(now)), challengeDigest.sqliteData!, .text(accountDID), .integer(try factorTimestamp(now))])
            guard !consumed.isEmpty else { throw AccountControlStoreError.malformedRecord }
            let parent = try await connection.query("SELECT factor_id FROM authentication_factors WHERE factor_id = ? AND account_did = ? AND kind = 'passkey' AND disabled_at IS NULL", [.text(credential.factorID), .text(accountDID)]); guard !parent.isEmpty else { throw AccountControlStoreError.notFound }
            _ = try await connection.query("INSERT INTO webauthn_credentials(credential_id_digest, account_did, factor_id, public_key_reference, sign_count, transports, created_at, last_used_at, disabled_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", [credential.credentialIDDigest.sqliteData!, .text(accountDID), .text(credential.factorID), .text(credential.publicKeyReference), .integer(Int(credential.signCount)), try JSONEncoder().encode(credential.transports).sqliteData!, .integer(try factorTimestamp(credential.createdAt)), try optionalTimestamp(credential.lastUsedAt), try optionalTimestamp(credential.disabledAt)])
        } }
    }

    public func disableWebAuthnCredential(credentialIDDigest: Data, accountDID: String, now: Date) async throws { try await withConnectionGate { _ = try await connection.query("UPDATE webauthn_credentials SET disabled_at = ? WHERE credential_id_digest = ? AND account_did = ? AND disabled_at IS NULL", [.integer(try factorTimestamp(now)), credentialIDDigest.sqliteData!, .text(accountDID)]) } }

    public func reserveWebAuthnChallenge(_ challenge: WebAuthnChallenge, now: Date) async throws { guard challenge.issuedAt <= now, challenge.expiresAt > now, (challenge.purpose == .enrollment ? challenge.credentialIDDigest == nil : challenge.credentialIDDigest != nil || challenge.factorID != nil) else { throw AccountControlStoreError.invalidInput }; try await withConnectionGate { try await ensureTask7DurableTables(); try await transaction { if let credential = challenge.credentialIDDigest { let parent = try await connection.query("SELECT c.credential_id_digest FROM webauthn_credentials c JOIN authentication_factors f ON f.factor_id = c.factor_id AND f.account_did = c.account_did WHERE c.credential_id_digest = ? AND c.account_did = ? AND f.kind = 'passkey' AND f.disabled_at IS NULL AND c.disabled_at IS NULL", [credential.sqliteData!, .text(challenge.accountDID)]); guard !parent.isEmpty else { throw AccountControlStoreError.notFound } }; _ = try await connection.query("INSERT INTO webauthn_challenges(challenge_digest, account_did, credential_id_digest, session_id, factor_id, relying_party_id, origin, issued_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [challenge.challengeDigest.sqliteData!, .text(challenge.accountDID), challenge.credentialIDDigest.map { $0.sqliteData! } ?? .null, challenge.sessionID.map(SQLiteData.text) ?? .null, challenge.factorID.map(SQLiteData.text) ?? .null, .text(challenge.relyingPartyID), .text(challenge.origin), .integer(try factorTimestamp(challenge.issuedAt)), .integer(try factorTimestamp(challenge.expiresAt)), try optionalTimestamp(challenge.consumedAt)]); _ = try await connection.query("INSERT INTO mfa_webauthn_challenge_context(challenge_digest, purpose, session_id, factor_id) VALUES (?, ?, ?, ?)", [challenge.challengeDigest.sqliteData!, .text(challenge.purpose.rawValue), challenge.sessionID.map(SQLiteData.text) ?? .null, challenge.factorID.map(SQLiteData.text) ?? .null]) } } }

    public func consumeWebAuthnChallenge(digest: Data, accountDID: String, now: Date) async throws -> WebAuthnChallenge {
        try await withConnectionGate { try await ensureTask7DurableTables(); return try await transaction {
            let changed = try await connection.query("UPDATE webauthn_challenges SET consumed_at = ? WHERE challenge_digest = ? AND account_did = ? AND issued_at <= ? AND consumed_at IS NULL AND expires_at > ? AND (credential_id_digest IS NULL OR EXISTS (SELECT 1 FROM webauthn_credentials c JOIN authentication_factors f ON f.factor_id = c.factor_id AND f.account_did = c.account_did WHERE c.credential_id_digest = webauthn_challenges.credential_id_digest AND c.account_did = webauthn_challenges.account_did AND c.disabled_at IS NULL AND f.kind = 'passkey' AND f.disabled_at IS NULL)) RETURNING challenge_digest", [.integer(try factorTimestamp(now)), digest.sqliteData!, .text(accountDID), .integer(try factorTimestamp(now))]); guard !changed.isEmpty else { throw AccountControlStoreError.malformedRecord }
            let rows = try await connection.query("SELECT challenge_digest, account_did, credential_id_digest, session_id, factor_id, relying_party_id, origin, issued_at, expires_at, consumed_at FROM webauthn_challenges WHERE challenge_digest = ? AND account_did = ?", [digest.sqliteData!, .text(accountDID)]); guard let row = rows.first else { throw AccountControlStoreError.malformedRecord }; let purposeRows = try await connection.query("SELECT purpose, session_id, factor_id FROM mfa_webauthn_challenge_context WHERE challenge_digest = ?", [digest.sqliteData!]); guard let purposeRow = purposeRows.first, let purpose = FactorChallengePurpose(rawValue: try requiredText(purposeRow, "purpose")) else { throw AccountControlStoreError.malformedRecord }; return try WebAuthnChallenge(challengeDigest: requiredBlob(row, "challenge_digest"), accountDID: requiredText(row, "account_did"), credentialIDDigest: optionalBlob(row, "credential_id_digest"), sessionID: optionalText(row, "session_id") ?? optionalText(purposeRow, "session_id"), factorID: optionalText(row, "factor_id") ?? optionalText(purposeRow, "factor_id"), purpose: purpose, relyingPartyID: requiredText(row, "relying_party_id"), origin: requiredText(row, "origin"), issuedAt: requiredDate(row, "issued_at"), expiresAt: requiredDate(row, "expires_at"), consumedAt: optionalDate(row, "consumed_at"))
        } }
    }

    public func webAuthnChallenge(digest: Data, accountDID: String, now: Date) async throws -> WebAuthnChallenge? {
        return try await withConnectionGate {
            try await ensureTask7DurableTables()
            let rows = try await connection.query("SELECT challenge_digest, account_did, credential_id_digest, session_id, factor_id, relying_party_id, origin, issued_at, expires_at, consumed_at FROM webauthn_challenges WHERE challenge_digest = ? AND account_did = ? AND issued_at <= ? AND consumed_at IS NULL AND expires_at > ?", [digest.sqliteData!, .text(accountDID), .integer(try factorTimestamp(now)), .integer(try factorTimestamp(now))])
            guard let row = rows.first else { return nil }
            let purposeRows = try await connection.query("SELECT purpose, session_id, factor_id FROM mfa_webauthn_challenge_context WHERE challenge_digest = ?", [digest.sqliteData!]); guard let purposeRow = purposeRows.first, let purpose = FactorChallengePurpose(rawValue: try requiredText(purposeRow, "purpose")) else { throw AccountControlStoreError.malformedRecord }
            return try WebAuthnChallenge(challengeDigest: requiredBlob(row, "challenge_digest"), accountDID: requiredText(row, "account_did"), credentialIDDigest: optionalBlob(row, "credential_id_digest"), sessionID: optionalText(row, "session_id") ?? optionalText(purposeRow, "session_id"), factorID: optionalText(row, "factor_id") ?? optionalText(purposeRow, "factor_id"), purpose: purpose, relyingPartyID: requiredText(row, "relying_party_id"), origin: requiredText(row, "origin"), issuedAt: requiredDate(row, "issued_at"), expiresAt: requiredDate(row, "expires_at"), consumedAt: optionalDate(row, "consumed_at"))
        }
    }

    public func compareAndSwapTOTPReplay(factorID: String, accountDID: String, expected: UInt64?, proposed: UInt64, now: Date) async throws -> Bool {
        guard proposed <= UInt64(Int.max), expected.map({ $0 <= UInt64(Int.max) }) ?? true else { throw AccountControlStoreError.invalidInput }
        return try await withConnectionGate {
            try await ensureTask7DurableTables()
            let rows: [SQLiteRow]
            if let expected {
                rows = try await connection.query("UPDATE totp_replay_state SET accepted_counter = ?, updated_at = ? WHERE factor_id = ? AND account_did = ? AND accepted_counter = ? AND EXISTS (SELECT 1 FROM authentication_factors f WHERE f.factor_id = totp_replay_state.factor_id AND f.account_did = totp_replay_state.account_did AND f.kind = 'totp' AND f.disabled_at IS NULL) RETURNING factor_id", [.integer(Int(proposed)), .integer(try factorTimestamp(now)), .text(factorID), .text(accountDID), .integer(Int(expected))])
            } else {
                rows = try await connection.query("INSERT INTO totp_replay_state(factor_id, account_did, accepted_counter, updated_at) SELECT ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM authentication_factors WHERE factor_id = ? AND account_did = ? AND kind = 'totp' AND disabled_at IS NULL) ON CONFLICT(factor_id, account_did) DO UPDATE SET accepted_counter = excluded.accepted_counter, updated_at = excluded.updated_at WHERE totp_replay_state.accepted_counter < excluded.accepted_counter RETURNING factor_id", [.text(factorID), .text(accountDID), .integer(Int(proposed)), .integer(try factorTimestamp(now)), .text(factorID), .text(accountDID)])
            }
            return !rows.isEmpty
        }
    }

    public func saveFactorToken(_ record: DurableFactorTokenRecord, now: Date) async throws {
        guard record.issuedAt <= now, record.expiresAt > now else { throw AccountControlStoreError.invalidInput }
        try await withConnectionGate {
            try await ensureTask7DurableTables()
            let strength = try JSONEncoder().encode(record.strength)
            let parent = try await connection.query("SELECT factor_id FROM authentication_factors WHERE factor_id = ? AND account_did = ? AND kind = ? AND disabled_at IS NULL", [.text(record.factorID), .text(record.accountDID), .text(record.factor.rawValue)]); guard !parent.isEmpty else { throw AccountControlStoreError.notFound }
            _ = try await connection.query("DELETE FROM mfa_factor_tokens WHERE expires_at <= ? OR consumed_at IS NOT NULL OR revoked_at IS NOT NULL", [.integer(try factorTimestamp(now))])
            _ = try await connection.query("INSERT INTO mfa_factor_tokens(digest, account_did, session_id, purpose, factor, factor_id, strength, issued_at, expires_at, channel, binding_digest, client_id, request_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [record.digest.sqliteData!, .text(record.accountDID), .text(record.sessionID), .text(record.purpose), .text(record.factor.rawValue), .text(record.factorID), strength.sqliteData!, .integer(try factorTimestamp(record.issuedAt)), .integer(try factorTimestamp(record.expiresAt)), .text(record.channel.rawValue), record.bindingDigest.map { $0.sqliteData! } ?? .null, record.clientID.map(SQLiteData.text) ?? .null, record.requestDigest.map { $0.sqliteData! } ?? .null])
        }
    }

    public func consumeFactorToken(digest: Data, accountDID: String, sessionID: String, purpose: String, factor: AuthenticationFactorKind, factorID: String, strength: AuthenticationStrength, now: Date) async throws -> DurableFactorTokenRecord {
        try await withConnectionGate { try await transaction {
            try await ensureTask7DurableTables()
            let rows = try await connection.query("UPDATE mfa_factor_tokens SET consumed_at = ? WHERE digest = ? AND account_did = ? AND session_id = ? AND purpose = ? AND factor = ? AND factor_id = ? AND issued_at <= ? AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > ? AND EXISTS (SELECT 1 FROM authentication_factors f WHERE f.factor_id = mfa_factor_tokens.factor_id AND f.account_did = mfa_factor_tokens.account_did AND f.kind = mfa_factor_tokens.factor AND f.disabled_at IS NULL) RETURNING digest, account_did, session_id, purpose, factor, factor_id, strength, issued_at, expires_at", [.integer(try factorTimestamp(now)), digest.sqliteData!, .text(accountDID), .text(sessionID), .text(purpose), .text(factor.rawValue), .text(factorID), .integer(try factorTimestamp(now)), .integer(try factorTimestamp(now))])
            guard let row = rows.first, let factor = AuthenticationFactorKind(rawValue: try requiredText(row, "factor")) else { throw AccountControlStoreError.notFound }
            let storedStrength = try JSONDecoder().decode(AuthenticationStrength.self, from: requiredBlob(row, "strength"))
            guard storedStrength == strength else { throw AccountControlStoreError.notFound }
            return try DurableFactorTokenRecord(digest: requiredBlob(row, "digest"), accountDID: requiredText(row, "account_did"), sessionID: requiredText(row, "session_id"), purpose: requiredText(row, "purpose"), factor: factor, factorID: requiredText(row, "factor_id"), strength: storedStrength, issuedAt: requiredDate(row, "issued_at"), expiresAt: requiredDate(row, "expires_at"))
        } }
    }

    /// Atomically consumes a step-up receipt bound to the currently
    /// authenticated management session. No caller-supplied factor or
    /// strength participates in this predicate; those values are returned
    /// from the durable row after the single-use update.
    public func consumeFactorTokenForStepUp(digest: Data, accountDID: String, sessionID: String, now: Date) async throws -> DurableFactorTokenRecord {
        try await withConnectionGate { try await transaction {
            try await ensureTask7DurableTables()
            let timestamp = try factorTimestamp(now)
            let rows = try await connection.query(
                """
                UPDATE mfa_factor_tokens
                   SET consumed_at = ?
                 WHERE digest = ?
                   AND account_did = ?
                   AND session_id = ?
                   AND purpose = 'stepUp'
                   AND issued_at <= ?
                   AND consumed_at IS NULL
                   AND revoked_at IS NULL
                   AND expires_at > ?
                   AND EXISTS (
                       SELECT 1 FROM authentication_factors f
                        WHERE f.factor_id = mfa_factor_tokens.factor_id
                          AND f.account_did = mfa_factor_tokens.account_did
                          AND f.kind = mfa_factor_tokens.factor
                          AND f.disabled_at IS NULL
                   )
                RETURNING digest, account_did, session_id, purpose, factor,
                          factor_id, strength, issued_at, expires_at
                """,
                [
                    .integer(timestamp), digest.sqliteData!, .text(accountDID),
                    .text(sessionID), .integer(timestamp), .integer(timestamp),
                ]
            )
            guard let row = rows.first,
                  let factor = AuthenticationFactorKind(rawValue: try requiredText(row, "factor")) else {
                throw AccountControlStoreError.notFound
            }
            let strength = try JSONDecoder().decode(
                AuthenticationStrength.self,
                from: requiredBlob(row, "strength")
            )
            return try DurableFactorTokenRecord(
                digest: requiredBlob(row, "digest"),
                accountDID: requiredText(row, "account_did"),
                sessionID: requiredText(row, "session_id"),
                purpose: requiredText(row, "purpose"),
                factor: factor,
                factorID: requiredText(row, "factor_id"),
                strength: strength,
                issuedAt: requiredDate(row, "issued_at"),
                expiresAt: requiredDate(row, "expires_at")
            )
        } }
    }

    /// Consume a login factor token without trusting caller-supplied factor,
    /// purpose, or strength metadata. Only the two login purposes are
    /// eligible, and the factor must still be active at the atomic update.
    /// When `sessionID` is supplied (the management portal path), it is part
    /// of the same atomic predicate as the account and token digest.
    public func consumeFactorTokenForLogin(digest: Data, accountDID: String, now: Date) async throws -> DurableFactorTokenRecord {
        try await consumeFactorTokenForLogin(digest: digest, accountDID: accountDID, sessionID: nil, now: now)
    }

    public func consumeFactorTokenForLogin(digest: Data, accountDID: String, sessionID: String, now: Date) async throws -> DurableFactorTokenRecord {
        try await consumeFactorTokenForLogin(digest: digest, accountDID: accountDID, sessionID: Optional(sessionID), now: now)
    }

    private func consumeFactorTokenForLogin(digest: Data, accountDID: String, sessionID: String?, now: Date) async throws -> DurableFactorTokenRecord {
        try await withConnectionGate { try await transaction {
            try await ensureTask7DurableTables()
            var statement = """
                UPDATE mfa_factor_tokens
                   SET consumed_at = ?
                 WHERE digest = ?
                   AND account_did = ?
                   AND channel IN ('account', 'legacy')
                   AND purpose IN ('managementLogin', 'loginRecovery')
                """
            var parameters: [SQLiteData] = [
                .integer(try factorTimestamp(now)),
                digest.sqliteData!,
                .text(accountDID),
            ]
            if let sessionID {
                statement += " AND session_id = ?"
                parameters.append(.text(sessionID))
            }
            statement += """
                   AND issued_at <= ?
                   AND consumed_at IS NULL
                   AND revoked_at IS NULL
                   AND expires_at > ?
                   AND EXISTS (
                       SELECT 1 FROM authentication_factors f
                        WHERE f.factor_id = mfa_factor_tokens.factor_id
                          AND f.account_did = mfa_factor_tokens.account_did
                          AND f.kind = mfa_factor_tokens.factor
                          AND f.disabled_at IS NULL
                   )
                RETURNING digest, account_did, session_id, purpose, factor,
                          factor_id, strength, issued_at, expires_at
                """
            parameters.append(.integer(try factorTimestamp(now)))
            parameters.append(.integer(try factorTimestamp(now)))
            let rows = try await connection.query(statement, parameters)
            guard let row = rows.first,
                  let factor = AuthenticationFactorKind(rawValue: try requiredText(row, "factor")) else {
                throw AccountControlStoreError.notFound
            }
            let strength = try JSONDecoder().decode(
                AuthenticationStrength.self,
                from: requiredBlob(row, "strength")
            )
            return try DurableFactorTokenRecord(
                digest: requiredBlob(row, "digest"),
                accountDID: requiredText(row, "account_did"),
                sessionID: requiredText(row, "session_id"),
                purpose: requiredText(row, "purpose"),
                factor: factor,
                factorID: requiredText(row, "factor_id"),
                strength: strength,
                issuedAt: requiredDate(row, "issued_at"),
                expiresAt: requiredDate(row, "expires_at")
            )
        } }
    }

    /// Consume a login receipt and commit the active-factor authorization
    /// decision under the same SQLite connection gate/transaction.  In
    /// particular, an email-recovery receipt is accepted only while recovery
    /// is the sole active factor; a mixed-factor account must present TOTP or
    /// passkey proof.
    public func consumeFactorTokenForLoginAndAuthorize(digest: Data, accountDID: String, now: Date) async throws -> DurableFactorTokenRecord {
        try await consumeFactorTokenForLoginAndAuthorize(digest: digest, accountDID: accountDID, sessionID: nil, now: now)
    }

    public func consumeFactorTokenForLoginAndAuthorize(digest: Data, accountDID: String, sessionID: String, now: Date) async throws -> DurableFactorTokenRecord {
        try await consumeFactorTokenForLoginAndAuthorize(digest: digest, accountDID: accountDID, sessionID: Optional(sessionID), now: now)
    }

    private func consumeFactorTokenForLoginAndAuthorize(digest: Data, accountDID: String, sessionID: String?, now: Date) async throws -> DurableFactorTokenRecord {
        try await withConnectionGate { try await transaction {
            try await ensureTask7DurableTables()
            let timestamp = try factorTimestamp(now)
            var statement = """
                UPDATE mfa_factor_tokens
                   SET consumed_at = ?
                 WHERE digest = ?
                   AND account_did = ?
                   AND channel IN ('account', 'legacy')
                   AND purpose IN ('managementLogin', 'loginRecovery')
                """
            var parameters: [SQLiteData] = [.integer(timestamp), digest.sqliteData!, .text(accountDID)]
            if let sessionID {
                statement += " AND session_id = ?"
                parameters.append(.text(sessionID))
            }
            statement += """
                   AND issued_at <= ?
                   AND consumed_at IS NULL
                   AND revoked_at IS NULL
                   AND expires_at > ?
                   AND EXISTS (
                       SELECT 1 FROM authentication_factors f
                        WHERE f.factor_id = mfa_factor_tokens.factor_id
                          AND f.account_did = mfa_factor_tokens.account_did
                          AND f.kind = mfa_factor_tokens.factor
                          AND f.disabled_at IS NULL
                   )
                RETURNING digest, account_did, session_id, purpose, factor,
                          factor_id, strength, issued_at, expires_at
                """
            parameters.append(.integer(timestamp)); parameters.append(.integer(timestamp))
            guard let row = try await connection.query(statement, parameters).first,
                  let factor = AuthenticationFactorKind(rawValue: try requiredText(row, "factor")) else {
                throw AccountControlStoreError.notFound
            }
            let strength = try JSONDecoder().decode(AuthenticationStrength.self, from: requiredBlob(row, "strength"))
            let active = try await connection.query(
                "SELECT kind FROM authentication_factors WHERE account_did = ? AND disabled_at IS NULL",
                [.text(accountDID)])
            let activeKinds = active.compactMap { $0.column("kind")?.string }.compactMap(AuthenticationFactorKind.init(rawValue:))
            let allowed: Bool
            if case .stepUpMFA = strength {
                allowed = !activeKinds.isEmpty
            } else if strength == .emailRecovery {
                allowed = !activeKinds.isEmpty && activeKinds.allSatisfy { $0 == .recoveryCode }
            } else {
                allowed = false
            }
            guard allowed else { throw AccountControlStoreError.notFound }
            return try DurableFactorTokenRecord(
                digest: requiredBlob(row, "digest"), accountDID: requiredText(row, "account_did"),
                sessionID: requiredText(row, "session_id"), purpose: requiredText(row, "purpose"),
                factor: factor, factorID: requiredText(row, "factor_id"), strength: strength,
                issuedAt: requiredDate(row, "issued_at"), expiresAt: requiredDate(row, "expires_at"))
        } }
    }

    public func revokeFactorTokens(accountDID: String, sessionID: String?, now: Date) async throws {
        try await withConnectionGate { try await ensureTask7DurableTables(); if let sessionID { _ = try await connection.query("UPDATE mfa_factor_tokens SET revoked_at = ? WHERE account_did = ? AND session_id = ? AND revoked_at IS NULL", [.integer(try factorTimestamp(now)), .text(accountDID), .text(sessionID)]) } else { _ = try await connection.query("UPDATE mfa_factor_tokens SET revoked_at = ? WHERE account_did = ? AND revoked_at IS NULL", [.integer(try factorTimestamp(now)), .text(accountDID)]) } }
    }

    public func beginOAuthMFAAdmission(
        accountDID: String,
        context: AccountAuthorizationContext,
        now: Date
    ) async throws -> OAuthMFAAdmission {
        guard context.channel == .oauth, context.purpose == "oauthToken" else {
            throw AccountControlStoreError.invalidInput
        }
        return try await withConnectionGate {
            try await ensureTask7DurableTables()
            return try await transaction {
                guard !(try await activeFactorKinds(accountDID: accountDID)).isEmpty else {
                    throw AccountControlStoreError.notFound
                }
                let revision = try await currentFactorRevision(accountDID: accountDID)
                let issuedAt = try factorTimestamp(now)
                let expiresAt = try factorTimestamp(now.addingTimeInterval(300))
                let digest = oauthPhaseDigest(accountDID: accountDID, context: context)
                _ = try await connection.query(
                    "INSERT INTO oauth_mfa_phases(phase_digest, account_did, session_id, csrf_digest, client_id, request_digest, factor_revision, issued_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL) ON CONFLICT(phase_digest) DO UPDATE SET factor_revision = excluded.factor_revision, issued_at = excluded.issued_at, expires_at = excluded.expires_at, consumed_at = NULL",
                    [digest.sqliteData!, .text(accountDID), .text(context.sessionID), context.csrfDigest!.sqliteData!, .text(context.clientID!), context.requestDigest!.sqliteData!, .integer(Int(revision)), .integer(issuedAt), .integer(expiresAt)]
                )
                return OAuthMFAAdmission(accountDID: accountDID, context: context, factorRevision: revision, issuedAt: now, expiresAt: now.addingTimeInterval(300))
            }
        }
    }

    public func consumeOAuthMFAAdmission(
        accountDID: String,
        context: AccountAuthorizationContext,
        now: Date
    ) async throws -> OAuthMFAAdmission {
        guard context.channel == .oauth, context.purpose == "oauthToken" else {
            throw AccountControlStoreError.invalidInput
        }
        return try await withConnectionGate {
            try await ensureTask7DurableTables()
            return try await transaction {
                let timestamp = try factorTimestamp(now)
                let digest = oauthPhaseDigest(accountDID: accountDID, context: context)
                let revision = try await currentFactorRevision(accountDID: accountDID)
                let rows = try await connection.query(
                    "UPDATE oauth_mfa_phases SET consumed_at = ? WHERE phase_digest = ? AND account_did = ? AND session_id = ? AND csrf_digest = ? AND client_id = ? AND request_digest = ? AND factor_revision = ? AND issued_at <= ? AND expires_at > ? AND consumed_at IS NULL RETURNING issued_at, expires_at",
                    [
                        .integer(timestamp), digest.sqliteData!, .text(accountDID), .text(context.sessionID),
                        context.csrfDigest!.sqliteData!, .text(context.clientID!), context.requestDigest!.sqliteData!,
                        .integer(Int(revision)), .integer(timestamp), .integer(timestamp),
                    ])
                guard let row = rows.first else { throw AccountControlStoreError.notFound }
                return OAuthMFAAdmission(accountDID: accountDID, context: context, factorRevision: revision, issuedAt: try requiredDate(row, "issued_at"), expiresAt: try requiredDate(row, "expires_at"))
            }
        }
    }

    public func factorRevision(accountDID: String, now: Date) async throws -> Int64 {
        _ = try factorTimestamp(now)
        return try await withConnectionGate {
            try await ensureTask7DurableTables()
            return try await currentFactorRevision(accountDID: accountDID)
        }
    }

    public func createPasswordAuthorizationGrant(
        grantDigest: Data,
        accountDID: String,
        context: AccountAuthorizationContext,
        now: Date
    ) async throws -> AccountAuthorizationGrant {
        guard grantDigest.count == 32 else { throw AccountControlStoreError.invalidInput }
        return try await withConnectionGate {
            try await ensureTask7DurableTables()
            return try await transaction {
                let active = try await activeFactorKinds(accountDID: accountDID)
                guard active.isEmpty else { throw AccountControlStoreError.notFound }
                let revision = try await currentFactorRevision(accountDID: accountDID)
                return try await insertAuthorizationGrant(
                    grantDigest: grantDigest,
                    accountDID: accountDID,
                    context: context,
                    factorRevision: revision,
                    strength: .password,
                    now: now
                )
            }
        }
    }

    public func consumeAuthorizationGrant(
        grantDigest: Data,
        accountDID: String,
        context: AccountAuthorizationContext,
        now: Date
    ) async throws -> AccountAuthorizationGrant {
        try await withConnectionGate {
            try await ensureTask7DurableTables()
            return try await transaction {
                try await consumeAuthorizationGrantLocked(
                    grantDigest: grantDigest,
                    accountDID: accountDID,
                    context: context,
                    now: now
                )
            }
        }
    }

    public func consumeFactorTokenForLoginAndCreateGrant(
        digest: Data,
        accountDID: String,
        context: AccountAuthorizationContext,
        grantDigest: Data,
        now: Date
    ) async throws -> AccountAuthorizationGrant {
        guard digest.count == 32, grantDigest.count == 32 else {
            throw AccountControlStoreError.invalidInput
        }
        return try await withConnectionGate {
            try await ensureTask7DurableTables()
            return try await transaction {
                let timestamp = try factorTimestamp(now)
                let allowedPurpose = context.purpose
                let rows = try await connection.query(
                    """
                    UPDATE mfa_factor_tokens
                       SET consumed_at = ?
                     WHERE digest = ?
                       AND account_did = ?
                       AND channel = ?
                       AND session_id = ?
                       AND purpose = ?
                       AND binding_digest IS ?
                       AND client_id IS ?
                       AND request_digest IS ?
                       AND issued_at <= ?
                       AND consumed_at IS NULL
                       AND revoked_at IS NULL
                       AND expires_at > ?
                       AND EXISTS (
                           SELECT 1 FROM authentication_factors f
                            WHERE f.factor_id = mfa_factor_tokens.factor_id
                              AND f.account_did = mfa_factor_tokens.account_did
                              AND f.kind = mfa_factor_tokens.factor
                              AND f.disabled_at IS NULL
                       )
                    RETURNING digest, account_did, session_id, purpose, factor,
                              factor_id, strength, issued_at, expires_at,
                              channel, binding_digest, client_id, request_digest
                    """,
                    [
                        .integer(timestamp), digest.sqliteData!, .text(accountDID),
                        .text(context.channel.rawValue), .text(context.sessionID),
                        .text(allowedPurpose), context.csrfDigest.map { $0.sqliteData! } ?? .null,
                        context.clientID.map(SQLiteData.text) ?? .null,
                        context.requestDigest.map { $0.sqliteData! } ?? .null,
                        .integer(timestamp), .integer(timestamp),
                    ]
                )
                guard let row = rows.first else { throw AccountControlStoreError.notFound }
                let strength = try JSONDecoder().decode(AuthenticationStrength.self, from: requiredBlob(row, "strength"))
                let active = try await activeFactorKinds(accountDID: accountDID)
                let allowed: Bool
                if case .stepUpMFA = strength {
                    allowed = !active.isEmpty
                } else if strength == .emailRecovery {
                    allowed = !active.isEmpty && active.allSatisfy { $0 == .recoveryCode }
                } else {
                    allowed = false
                }
                guard allowed else { throw AccountControlStoreError.notFound }
                let revision = try await currentFactorRevision(accountDID: accountDID)
                return try await insertAuthorizationGrant(
                    grantDigest: grantDigest,
                    accountDID: accountDID,
                    context: context,
                    factorRevision: revision,
                    strength: strength,
                    now: now
                )
            }
        }
    }

    public func appendMFAAuditEvent(_ event: MFAAuditEventRecord, now: Date) async throws {
        try await withConnectionGate {
            try await ensureTask7DurableTables()
            _ = try await connection.query("INSERT INTO mfa_audit_events(event, account_did, factor_id, success, occurred_at) VALUES (?, ?, ?, ?, ?)", [.text(event.event), .text(event.accountDID), event.factorID.map(SQLiteData.text) ?? .null, .integer(event.success ? 1 : 0), .integer(try factorTimestamp(event.occurredAt))])
            _ = try await connection.query("DELETE FROM mfa_audit_events WHERE event_id NOT IN (SELECT event_id FROM mfa_audit_events ORDER BY event_id DESC LIMIT 10000)")
        }
    }
}

extension SQLiteControlDatabase {
    func ensureTask7DurableTables() async throws {
        // This is intentionally adapter-local: Task 6 owns migration ordering.
        // IF NOT EXISTS makes the seam safe for already-provisioned databases.
        _ = try await connection.query("CREATE TABLE IF NOT EXISTS totp_replay_state (factor_id TEXT NOT NULL, account_did TEXT NOT NULL, accepted_counter INTEGER NOT NULL CHECK(accepted_counter >= 0), updated_at INTEGER NOT NULL, PRIMARY KEY(factor_id, account_did))")
        _ = try await connection.query("CREATE TABLE IF NOT EXISTS totp_pending_secret_envelopes (factor_id TEXT PRIMARY KEY, account_did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE, key_reference TEXT NOT NULL, nonce BLOB NOT NULL CHECK(length(nonce) = 12), ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 0), authentication_tag BLOB NOT NULL CHECK(length(authentication_tag) = 16), issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at > issued_at), FOREIGN KEY(factor_id, account_did) REFERENCES authentication_factors(factor_id, account_did) ON DELETE CASCADE)")
        _ = try await connection.query("CREATE TABLE IF NOT EXISTS mfa_factor_tokens (digest BLOB PRIMARY KEY CHECK(length(digest) = 32), account_did TEXT NOT NULL, session_id TEXT NOT NULL, purpose TEXT NOT NULL, factor TEXT NOT NULL, factor_id TEXT NOT NULL, strength BLOB NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER, revoked_at INTEGER, channel TEXT NOT NULL DEFAULT 'account', binding_digest BLOB, client_id TEXT, request_digest BLOB)")
        let tokenColumns = try await connection.query("PRAGMA table_info(mfa_factor_tokens)")
        let tokenNames = Set(tokenColumns.compactMap { $0.column("name")?.string })
        if !tokenNames.contains("channel") { _ = try await connection.query("ALTER TABLE mfa_factor_tokens ADD COLUMN channel TEXT NOT NULL DEFAULT 'account'") }
        if !tokenNames.contains("binding_digest") { _ = try await connection.query("ALTER TABLE mfa_factor_tokens ADD COLUMN binding_digest BLOB") }
        if !tokenNames.contains("client_id") { _ = try await connection.query("ALTER TABLE mfa_factor_tokens ADD COLUMN client_id TEXT") }
        if !tokenNames.contains("request_digest") { _ = try await connection.query("ALTER TABLE mfa_factor_tokens ADD COLUMN request_digest BLOB") }
        _ = try await connection.query("CREATE TABLE IF NOT EXISTS mfa_factor_revisions (account_did TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK(revision >= 0)) WITHOUT ROWID")
        _ = try await connection.query("CREATE TABLE IF NOT EXISTS account_authorization_grants (grant_digest BLOB PRIMARY KEY CHECK(length(grant_digest) = 32), account_did TEXT NOT NULL, channel TEXT NOT NULL, session_id TEXT NOT NULL, purpose TEXT NOT NULL, csrf_digest BLOB, client_id TEXT, request_digest BLOB, factor_revision INTEGER NOT NULL CHECK(factor_revision >= 0), strength BLOB NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER)")
        _ = try await connection.query("CREATE INDEX IF NOT EXISTS account_authorization_grants_expiry ON account_authorization_grants(expires_at, consumed_at)")
        _ = try await connection.query("CREATE TABLE IF NOT EXISTS oauth_mfa_phases (phase_digest BLOB PRIMARY KEY CHECK(length(phase_digest) = 32), account_did TEXT NOT NULL, session_id TEXT NOT NULL, csrf_digest BLOB NOT NULL CHECK(length(csrf_digest) = 32), client_id TEXT NOT NULL, request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), factor_revision INTEGER NOT NULL CHECK(factor_revision >= 0), issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER)")
        _ = try await connection.query("CREATE INDEX IF NOT EXISTS oauth_mfa_phases_expiry ON oauth_mfa_phases(expires_at, consumed_at)")
        _ = try await connection.query("CREATE TABLE IF NOT EXISTS mfa_audit_events (event_id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, account_did TEXT NOT NULL, factor_id TEXT, success INTEGER NOT NULL, occurred_at INTEGER NOT NULL)")
        _ = try await connection.query("CREATE TABLE IF NOT EXISTS mfa_webauthn_challenge_context (challenge_digest BLOB PRIMARY KEY CHECK(length(challenge_digest) = 32), purpose TEXT NOT NULL, session_id TEXT, factor_id TEXT)")
        let challengeColumns = try await connection.query("PRAGMA table_info(webauthn_challenges)")
        let challengeNames = Set(challengeColumns.compactMap { $0.column("name")?.string })
        if !challengeNames.contains("session_id") { _ = try await connection.query("ALTER TABLE webauthn_challenges ADD COLUMN session_id TEXT") }
        if !challengeNames.contains("factor_id") { _ = try await connection.query("ALTER TABLE webauthn_challenges ADD COLUMN factor_id TEXT") }
        let contextColumns = try await connection.query("PRAGMA table_info(mfa_webauthn_challenge_context)")
        let contextNames = Set(contextColumns.compactMap { $0.column("name")?.string })
        if !contextNames.contains("session_id") { _ = try await connection.query("ALTER TABLE mfa_webauthn_challenge_context ADD COLUMN session_id TEXT") }
        if !contextNames.contains("factor_id") { _ = try await connection.query("ALTER TABLE mfa_webauthn_challenge_context ADD COLUMN factor_id TEXT") }
    }

    func currentFactorRevision(accountDID: String) async throws -> Int64 {
        let rows = try await connection.query(
            "SELECT revision FROM mfa_factor_revisions WHERE account_did = ?",
            [.text(accountDID)]
        )
        guard let value = rows.first?.column("revision")?.integer,
              value >= 0 else { return 0 }
        return Int64(value)
    }

    func activeFactorKinds(accountDID: String) async throws -> [AuthenticationFactorKind] {
        let rows = try await connection.query(
            "SELECT kind FROM authentication_factors WHERE account_did = ? AND disabled_at IS NULL",
            [.text(accountDID)]
        )
        return rows.compactMap { $0.column("kind")?.string }
            .compactMap(AuthenticationFactorKind.init(rawValue:))
    }

    func bumpFactorRevision(accountDID: String) async throws {
        _ = try await connection.query(
            "INSERT INTO mfa_factor_revisions(account_did, revision) VALUES (?, 1) ON CONFLICT(account_did) DO UPDATE SET revision = mfa_factor_revisions.revision + 1",
            [.text(accountDID)]
        )
    }

    func insertAuthorizationGrant(
        grantDigest: Data,
        accountDID: String,
        context: AccountAuthorizationContext,
        factorRevision: Int64,
        strength: AuthenticationStrength,
        now: Date
    ) async throws -> AccountAuthorizationGrant {
        guard grantDigest.count == 32, factorRevision >= 0 else {
            throw AccountControlStoreError.invalidInput
        }
        let issued = try factorTimestamp(now)
        let expiresAt = now.addingTimeInterval(120)
        let expires = try factorTimestamp(expiresAt)
        let encodedStrength = try JSONEncoder().encode(strength)
        _ = try await connection.query(
            "INSERT INTO account_authorization_grants(grant_digest, account_did, channel, session_id, purpose, csrf_digest, client_id, request_digest, factor_revision, strength, issued_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
            [
                grantDigest.sqliteData!, .text(accountDID), .text(context.channel.rawValue),
                .text(context.sessionID), .text(context.purpose),
                context.csrfDigest.map { $0.sqliteData! } ?? .null,
                context.clientID.map(SQLiteData.text) ?? .null,
                context.requestDigest.map { $0.sqliteData! } ?? .null,
                .integer(Int(factorRevision)), encodedStrength.sqliteData!,
                .integer(issued), .integer(expires),
            ]
        )
        return try AccountAuthorizationGrant(
            grantDigest: grantDigest,
            accountDID: accountDID,
            context: context,
            factorRevision: factorRevision,
            strength: strength,
            issuedAt: now,
            expiresAt: expiresAt
        )
    }

    func consumeAuthorizationGrantLocked(
        grantDigest: Data,
        accountDID: String,
        context: AccountAuthorizationContext,
        now: Date
    ) async throws -> AccountAuthorizationGrant {
        guard grantDigest.count == 32 else { throw AccountControlStoreError.invalidInput }
        let timestamp = try factorTimestamp(now)
        let rows = try await connection.query(
            """
            UPDATE account_authorization_grants
               SET consumed_at = ?
             WHERE grant_digest = ?
               AND account_did = ?
               AND channel = ?
               AND session_id = ?
               AND purpose = ?
               AND csrf_digest IS ?
               AND client_id IS ?
               AND request_digest IS ?
               AND issued_at <= ?
               AND expires_at > ?
               AND consumed_at IS NULL
               AND factor_revision = COALESCE((SELECT revision FROM mfa_factor_revisions WHERE account_did = ?), 0)
            RETURNING grant_digest, account_did, channel, session_id, purpose,
                      csrf_digest, client_id, request_digest, factor_revision,
                      strength, issued_at, expires_at
            """,
            [
                .integer(timestamp), grantDigest.sqliteData!, .text(accountDID),
                .text(context.channel.rawValue), .text(context.sessionID),
                .text(context.purpose),
                context.csrfDigest.map { $0.sqliteData! } ?? .null,
                context.clientID.map(SQLiteData.text) ?? .null,
                context.requestDigest.map { $0.sqliteData! } ?? .null,
                .integer(timestamp), .integer(timestamp), .text(accountDID),
            ]
        )
        guard let row = rows.first,
              let channel = AccountAuthorizationChannel(rawValue: try requiredText(row, "channel")) else {
            throw AccountControlStoreError.notFound
        }
        let storedContext = try AccountAuthorizationContext(
            channel: channel,
            sessionID: try requiredText(row, "session_id"),
            csrfDigest: optionalBlob(row, "csrf_digest"),
            clientID: optionalText(row, "client_id"),
            requestDigest: optionalBlob(row, "request_digest"),
            purpose: try requiredText(row, "purpose")
        )
        let strength = try JSONDecoder().decode(AuthenticationStrength.self, from: requiredBlob(row, "strength"))
        return try AccountAuthorizationGrant(
            grantDigest: requiredBlob(row, "grant_digest"),
            accountDID: requiredText(row, "account_did"),
            context: storedContext,
            factorRevision: Int64(row.column("factor_revision")?.integer ?? -1),
            strength: strength,
            issuedAt: requiredDate(row, "issued_at"),
            expiresAt: requiredDate(row, "expires_at")
        )
    }
}

private func oauthPhaseDigest(accountDID: String, context: AccountAuthorizationContext) -> Data {
    var input = Data("swan-oauth-mfa-phase-v1\0".utf8)
    input.append(Data(accountDID.utf8)); input.append(0)
    input.append(Data(context.sessionID.utf8)); input.append(0)
    if let csrf = context.csrfDigest { input.append(csrf) }
    if let clientID = context.clientID { input.append(Data(clientID.utf8)) }
    if let request = context.requestDigest { input.append(request) }
    return Data(SHA256.hash(data: input))
}

private func factorTimestamp(_ date: Date) throws -> Int { let seconds = date.timeIntervalSince1970; guard seconds.isFinite, seconds >= 0, seconds <= 9_000_000_000 else { throw AccountControlStoreError.invalidInput }; let micros = seconds * 1_000_000; guard micros <= Double(Int.max) else { throw AccountControlStoreError.invalidInput }; return Int(micros.rounded(.down)) }
private func optionalTimestamp(_ date: Date?) throws -> SQLiteData { guard let date else { return .null }; return .integer(try factorTimestamp(date)) }
private func requiredText(_ row: SQLiteRow, _ key: String) throws -> String { guard case let .text(value) = row.column(key) else { throw AccountControlStoreError.malformedRecord }; return value }
private func requiredBlob(_ row: SQLiteRow, _ key: String) throws -> Data { guard let value = row.column(key), let data = Data(sqliteData: value) else { throw AccountControlStoreError.malformedRecord }; return data }
private func optionalBlob(_ row: SQLiteRow, _ key: String) throws -> Data? { guard let value = row.column(key) else { throw AccountControlStoreError.malformedRecord }; return value.isNull ? nil : try requiredBlob(row, key) }
private func requiredDate(_ row: SQLiteRow, _ key: String) throws -> Date { guard case let .integer(value) = row.column(key), value >= 0, value <= 9_000_000_000_000_000 else { throw AccountControlStoreError.malformedRecord }; return Date(timeIntervalSince1970: Double(value) / 1_000_000) }
private func optionalDate(_ row: SQLiteRow, _ key: String) throws -> Date? { guard let value = row.column(key) else { throw AccountControlStoreError.malformedRecord }; if value.isNull { return nil }; return try requiredDate(row, key) }
private func decodeFactor(_ row: SQLiteRow) throws -> AuthenticationFactorMetadata { guard let kind = AuthenticationFactorKind(rawValue: try requiredText(row, "kind")) else { throw AccountControlStoreError.malformedRecord }; return try AuthenticationFactorMetadata(id: requiredText(row, "factor_id"), accountDID: requiredText(row, "account_did"), kind: kind, label: requiredText(row, "label"), lookupDigest: requiredBlob(row, "lookup_digest"), createdAt: requiredDate(row, "created_at"), lastUsedAt: optionalDate(row, "last_used_at"), disabledAt: optionalDate(row, "disabled_at")) }
private func decodeChallenge(_ row: SQLiteRow) throws -> FactorChallenge { guard let purpose = FactorChallengePurpose(rawValue: try requiredText(row, "purpose")) else { throw AccountControlStoreError.malformedRecord }; return try FactorChallenge(challengeDigest: requiredBlob(row, "challenge_digest"), accountDID: requiredText(row, "account_did"), factorID: optionalText(row, "factor_id"), purpose: purpose, issuedAt: requiredDate(row, "issued_at"), expiresAt: requiredDate(row, "expires_at"), consumedAt: optionalDate(row, "consumed_at")) }
private func optionalText(_ row: SQLiteRow, _ key: String) throws -> String? { guard let value = row.column(key) else { throw AccountControlStoreError.malformedRecord }; if value.isNull { return nil }; return try requiredText(row, key) }
private func decodeCredential(_ row: SQLiteRow) throws -> WebAuthnCredentialMetadata { try WebAuthnCredentialMetadata(credentialIDDigest: requiredBlob(row, "credential_id_digest"), accountDID: requiredText(row, "account_did"), factorID: requiredText(row, "factor_id"), publicKeyReference: requiredText(row, "public_key_reference"), signCount: UInt32(clamping: row.column("sign_count")?.integer ?? 0), transports: Set(try JSONDecoder().decode([String].self, from: requiredBlob(row, "transports"))), createdAt: requiredDate(row, "created_at"), lastUsedAt: optionalDate(row, "last_used_at"), disabledAt: optionalDate(row, "disabled_at")) }
