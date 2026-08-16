import Crypto
import Foundation
import Petrel
import SQLiteNIO
import SwanCore
import SwanPublicRepository
import SwanSpaces
import SwanStorage

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Stable filesystem placement for per-account SQLite/WAL databases. The
/// control database contains registry and OAuth control-plane data only;
/// repository facts remain in the account database.
public enum SQLiteLayout {
    public static func controlDatabase(in dataDirectory: URL) -> URL {
        dataDirectory.appending(path: "control.sqlite")
    }

    public static func firehoseDatabase(in dataDirectory: URL) -> URL {
        dataDirectory.appending(path: "firehose.sqlite")
    }

    public static func accountDatabase(in dataDirectory: URL, did: String) -> URL {
        let digest = Hex.encode(SHA256.hash(data: Data(did.utf8)))
        return dataDirectory
            .appending(path: "actors")
            .appending(path: String(digest.prefix(2)))
            .appending(path: "\(digest).sqlite")
    }

    static func readOnlyURI(for path: String) throws -> String {
        let uriPathCharacters = CharacterSet(
            charactersIn:
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/"
        )
        guard path.hasPrefix("/"),
              let encoded = path.addingPercentEncoding(
                  withAllowedCharacters: uriPathCharacters
              ) else {
            throw SwanError.unavailable("SQLite read-only path is unavailable")
        }
        return "file:\(encoded)?mode=ro"
    }

    /// Connection-local configuration must run outside a migration write
    /// transaction (`foreign_keys` and `journal_mode` are not safely changed
    /// inside one). Schema DDL below is serialized separately with
    /// `BEGIN IMMEDIATE` by the owning SQLite database actor.
    public static let controlConnectionPragmas = [
        "PRAGMA busy_timeout=5000",
        "PRAGMA journal_mode=WAL",
        "PRAGMA foreign_keys=ON",
    ]

    /// Provisional bounded capacities for the account program. These values
    /// are deliberately frozen in source until operational evidence supports
    /// a reviewed increase; expiry indexes and the owning service's purge
    /// operation keep rows bounded between admission checks.
    public enum AccountControlSchemaCapacity {
        public static let maxIdentityBindings = 100_000
        public static let maxIdentityBindingHistory = 500_000
        public static let maxPendingIdentityClaims = 100_000
        public static let maxSignupAuthorizations = 100_000
        public static let maxSignupInvites = 100_000
        public static let maxAppPasswords = 100_000
        public static let maxLegacySessionFamilies = 100_000
        public static let maxLegacySessions = 500_000
        public static let maxManagementSessions = 500_000
        public static let maxAuthenticationFactors = 200_000
        public static let maxFactorChallenges = 500_000
        public static let maxTOTPEnvelopes = 200_000
        public static let maxRecoveryCodeDigests = 500_000
        public static let maxWebAuthnCredentials = 200_000
        public static let maxWebAuthnChallenges = 500_000
        public static let maxIdentityBindingsPerAccount = 1
        public static let maxIdentityBindingHistoryPerAccount = 64
        public static let maxPendingIdentityClaimsPerAccount = 16
        public static let maxSignupAuthorizationsPerAccount = 16
        public static let maxRedeemedSignupInvitesPerAccount = 32
        public static let maxAppPasswordsPerAccount = 32
        public static let maxLegacySessionFamiliesPerAccount = 64
        public static let maxLegacySessionsPerAccount = 256
        public static let maxManagementSessionsPerAccount = 256
        public static let maxAuthenticationFactorsPerAccount = 16
        public static let maxFactorChallengesPerAccount = 64
        public static let maxTOTPEnvelopesPerAccount = 16
        public static let maxRecoveryCodeDigestsPerAccount = 32
        public static let maxWebAuthnCredentialsPerAccount = 16
        public static let maxWebAuthnChallengesPerAccount = 64
    }

    public static let controlMigrations = controlConnectionPragmas + [
        "CREATE TABLE IF NOT EXISTS accounts (did TEXT PRIMARY KEY, handle TEXT UNIQUE NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL)",
        // Dedicated additive marker. Version 1 records the pre-account
        // program control schema; versions 2-7 are reserved in dependency
        // order and must never be reordered by a later lane.
        "CREATE TABLE IF NOT EXISTS control_schema_migrations (version INTEGER PRIMARY KEY CHECK(version > 0), applied_at INTEGER NOT NULL CHECK(applied_at >= 0))",
        "INSERT OR IGNORE INTO control_schema_migrations(version, applied_at) VALUES (1, unixepoch())",
        "INSERT OR IGNORE INTO control_schema_migrations(version, applied_at) VALUES (2, unixepoch())",
        "INSERT OR IGNORE INTO control_schema_migrations(version, applied_at) VALUES (3, unixepoch())",
        "INSERT OR IGNORE INTO control_schema_migrations(version, applied_at) VALUES (4, unixepoch())",
        "INSERT OR IGNORE INTO control_schema_migrations(version, applied_at) VALUES (5, unixepoch())",
        "INSERT OR IGNORE INTO control_schema_migrations(version, applied_at) VALUES (6, unixepoch())",
        """
        CREATE TABLE IF NOT EXISTS identity_bindings (
            account_did TEXT PRIMARY KEY REFERENCES accounts(did) ON DELETE CASCADE,
            identity_did TEXT NOT NULL UNIQUE,
            method TEXT NOT NULL CHECK(method IN ('plc', 'did-web')),
            handle TEXT NOT NULL,
            document_digest BLOB CHECK(document_digest IS NULL OR length(document_digest) = 32),
            claim_receipt_digest BLOB CHECK(claim_receipt_digest IS NULL OR length(claim_receipt_digest) = 32),
            reserved_key_id TEXT,
            last_validated_at INTEGER,
            grace_expires_at INTEGER,
            state TEXT NOT NULL CHECK(state IN ('active', 'suspended', 'released')),
            CHECK(method = 'did-web' OR (document_digest IS NULL AND claim_receipt_digest IS NULL AND reserved_key_id IS NULL)),
            CHECK(method = 'plc' OR (document_digest IS NOT NULL AND claim_receipt_digest IS NOT NULL AND length(reserved_key_id) > 0))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS identity_binding_history (
            account_did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
            replaced_at INTEGER NOT NULL CHECK(replaced_at >= 0),
            identity_did TEXT NOT NULL,
            document_digest BLOB CHECK(document_digest IS NULL OR length(document_digest) = 32),
            claim_receipt_digest BLOB CHECK(claim_receipt_digest IS NULL OR length(claim_receipt_digest) = 32),
            reserved_key_id TEXT,
            PRIMARY KEY(account_did, replaced_at)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS did_web_claim_transactions (
            request_id TEXT PRIMARY KEY,
            account_did TEXT REFERENCES accounts(did) ON DELETE CASCADE,
            target_did TEXT NOT NULL,
            handle TEXT NOT NULL,
            claim_nonce_digest BLOB NOT NULL CHECK(length(claim_nonce_digest) = 32),
            requested_document_digest BLOB CHECK(requested_document_digest IS NULL OR length(requested_document_digest) = 32),
            reserved_key_id TEXT,
            claim_receipt_digest BLOB CHECK(claim_receipt_digest IS NULL OR length(claim_receipt_digest) = 32),
            state TEXT NOT NULL CHECK(state IN ('reserved', 'pendingValidation', 'committing', 'committed', 'failed', 'expired')),
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
            step_up_receipt_digest BLOB CHECK(step_up_receipt_digest IS NULL OR length(step_up_receipt_digest) = 32)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS signup_authorizations (
            authorization_id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL UNIQUE,
            account_did TEXT REFERENCES accounts(did) ON DELETE CASCADE,
            policy TEXT NOT NULL CHECK(policy IN ('closed', 'inviteRequired', 'openProtected')),
            handle TEXT NOT NULL,
            email TEXT,
            identity_did TEXT,
            email_proof_digest BLOB CHECK(email_proof_digest IS NULL OR length(email_proof_digest) = 32),
            invite_digest BLOB CHECK(invite_digest IS NULL OR length(invite_digest) = 32),
            client_ip_bucket_digest BLOB NOT NULL CHECK(length(client_ip_bucket_digest) = 32),
            state TEXT NOT NULL CHECK(state IN ('issued', 'committing', 'committed', 'failed')),
            issued_at INTEGER NOT NULL CHECK(issued_at >= 0),
            expires_at INTEGER NOT NULL CHECK(expires_at >= issued_at),
            lease_expires_at INTEGER CHECK(lease_expires_at IS NULL OR (lease_expires_at >= issued_at AND lease_expires_at <= expires_at))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS signup_invites (
            invite_digest BLOB PRIMARY KEY CHECK(length(invite_digest) = 32),
            issued_at INTEGER NOT NULL CHECK(issued_at >= 0),
            expires_at INTEGER CHECK(expires_at IS NULL OR expires_at >= issued_at),
            redeemed_at INTEGER,
            redemption_account_did TEXT REFERENCES accounts(did) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS app_passwords (
            app_password_id TEXT PRIMARY KEY,
            account_did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
            canonical_name TEXT NOT NULL,
            scope_strings BLOB NOT NULL,
            secret_digest BLOB NOT NULL CHECK(length(secret_digest) = 32),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            last_used_at INTEGER,
            revoked_at INTEGER,
            UNIQUE(account_did, canonical_name),
            UNIQUE(app_password_id, account_did)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS legacy_session_families (
            family_id TEXT PRIMARY KEY,
            account_did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
            app_password_id TEXT,
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            expires_at INTEGER NOT NULL CHECK(expires_at >= created_at),
            revoked_at INTEGER,
            reuse_detected_at INTEGER,
            CHECK(reuse_detected_at IS NULL OR (revoked_at IS NOT NULL AND revoked_at >= reuse_detected_at)),
            UNIQUE(family_id, account_did),
            FOREIGN KEY(app_password_id, account_did) REFERENCES app_passwords(app_password_id, account_did) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS legacy_sessions (
            session_digest BLOB PRIMARY KEY CHECK(length(session_digest) = 32),
            family_id TEXT NOT NULL,
            account_did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
            app_password_id TEXT,
            scope_strings BLOB NOT NULL,
            issued_at INTEGER NOT NULL CHECK(issued_at >= 0),
            expires_at INTEGER NOT NULL CHECK(expires_at >= issued_at),
            revoked_at INTEGER,
            rotated_at INTEGER,
            replaced_by_digest BLOB CHECK(replaced_by_digest IS NULL OR length(replaced_by_digest) = 32),
            previous_session_digest BLOB CHECK(previous_session_digest IS NULL OR length(previous_session_digest) = 32),
            reuse_detected_at INTEGER,
            CHECK(replaced_by_digest IS NULL OR rotated_at IS NOT NULL),
            CHECK(reuse_detected_at IS NULL OR (revoked_at IS NOT NULL AND revoked_at >= reuse_detected_at)),
            FOREIGN KEY(family_id, account_did) REFERENCES legacy_session_families(family_id, account_did),
            FOREIGN KEY(app_password_id, account_did) REFERENCES app_passwords(app_password_id, account_did)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS management_sessions (
            session_digest BLOB PRIMARY KEY CHECK(length(session_digest) = 32),
            account_did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
            csrf_digest BLOB NOT NULL CHECK(length(csrf_digest) = 32),
            issued_at INTEGER NOT NULL CHECK(issued_at >= 0),
            idle_expires_at INTEGER NOT NULL CHECK(idle_expires_at >= issued_at),
            absolute_expires_at INTEGER NOT NULL CHECK(absolute_expires_at >= idle_expires_at),
            last_step_up_at INTEGER,
            strength TEXT NOT NULL,
            revoked_at INTEGER
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS authentication_factors (
            factor_id TEXT PRIMARY KEY,
            account_did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
            kind TEXT NOT NULL CHECK(kind IN ('passkey', 'totp', 'recoveryCode')),
            label TEXT NOT NULL,
            lookup_digest BLOB NOT NULL CHECK(length(lookup_digest) = 32),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            last_used_at INTEGER,
            disabled_at INTEGER,
            UNIQUE(account_did, lookup_digest),
            UNIQUE(factor_id, account_did)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS factor_challenges (
            challenge_digest BLOB PRIMARY KEY CHECK(length(challenge_digest) = 32),
            account_did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
            factor_id TEXT,
            purpose TEXT NOT NULL CHECK(purpose IN ('enrollment', 'assertion', 'stepUp')),
            issued_at INTEGER NOT NULL CHECK(issued_at >= 0),
            expires_at INTEGER NOT NULL CHECK(expires_at >= issued_at),
            consumed_at INTEGER,
            FOREIGN KEY(factor_id, account_did) REFERENCES authentication_factors(factor_id, account_did) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS totp_secret_envelopes (
            factor_id TEXT PRIMARY KEY,
            account_did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
            key_reference TEXT NOT NULL,
            nonce BLOB NOT NULL CHECK(length(nonce) = 12),
            ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 0),
            authentication_tag BLOB NOT NULL CHECK(length(authentication_tag) = 16),
            FOREIGN KEY(factor_id, account_did) REFERENCES authentication_factors(factor_id, account_did) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS recovery_code_digests (
            account_did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
            digest BLOB NOT NULL CHECK(length(digest) = 32),
            issued_at INTEGER NOT NULL CHECK(issued_at >= 0),
            consumed_at INTEGER,
            PRIMARY KEY(account_did, digest)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
            credential_id_digest BLOB PRIMARY KEY CHECK(length(credential_id_digest) = 32),
            account_did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
            factor_id TEXT NOT NULL,
            public_key_reference TEXT NOT NULL,
            sign_count INTEGER NOT NULL CHECK(sign_count >= 0),
            transports BLOB NOT NULL,
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            last_used_at INTEGER,
            disabled_at INTEGER,
            UNIQUE(credential_id_digest, account_did),
            FOREIGN KEY(factor_id, account_did) REFERENCES authentication_factors(factor_id, account_did) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS webauthn_challenges (
            challenge_digest BLOB PRIMARY KEY CHECK(length(challenge_digest) = 32),
            account_did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
            credential_id_digest BLOB CHECK(credential_id_digest IS NULL OR length(credential_id_digest) = 32),
            relying_party_id TEXT NOT NULL,
            origin TEXT NOT NULL,
            issued_at INTEGER NOT NULL CHECK(issued_at >= 0),
            expires_at INTEGER NOT NULL CHECK(expires_at >= issued_at),
            consumed_at INTEGER,
            FOREIGN KEY(credential_id_digest, account_did) REFERENCES webauthn_credentials(credential_id_digest, account_did) ON DELETE CASCADE
        )
        """,
        "CREATE INDEX IF NOT EXISTS did_web_claim_transactions_expiry ON did_web_claim_transactions(expires_at, request_id)",
        "CREATE INDEX IF NOT EXISTS identity_binding_history_account ON identity_binding_history(account_did, replaced_at)",
        "CREATE INDEX IF NOT EXISTS signup_authorizations_expiry ON signup_authorizations(expires_at, authorization_id)",
        "CREATE INDEX IF NOT EXISTS signup_invites_expiry ON signup_invites(expires_at, invite_digest)",
        "CREATE INDEX IF NOT EXISTS legacy_session_families_expiry ON legacy_session_families(expires_at, family_id)",
        "CREATE INDEX IF NOT EXISTS legacy_sessions_expiry ON legacy_sessions(expires_at, session_digest)",
        "CREATE INDEX IF NOT EXISTS management_sessions_expiry ON management_sessions(absolute_expires_at, session_digest)",
        "CREATE INDEX IF NOT EXISTS factor_challenges_expiry ON factor_challenges(expires_at, challenge_digest)",
        "CREATE INDEX IF NOT EXISTS totp_secret_envelopes_account ON totp_secret_envelopes(account_did, factor_id)",
        "CREATE INDEX IF NOT EXISTS recovery_code_digests_account ON recovery_code_digests(account_did, consumed_at, digest)",
        "CREATE INDEX IF NOT EXISTS webauthn_credentials_account ON webauthn_credentials(account_did, credential_id_digest)",
        "CREATE INDEX IF NOT EXISTS webauthn_challenges_expiry ON webauthn_challenges(expires_at, challenge_digest)",
        // Admission triggers enforce the frozen global capacities. Account
        // services purge expired rows before retrying; failure is explicit,
        // never an unbounded insert or silent overwrite.
        "CREATE TRIGGER IF NOT EXISTS identity_bindings_capacity BEFORE INSERT ON identity_bindings WHEN (SELECT COUNT(*) FROM identity_bindings) >= 100000 BEGIN SELECT RAISE(ABORT, 'identity binding capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS identity_binding_history_capacity BEFORE INSERT ON identity_binding_history WHEN (SELECT COUNT(*) FROM identity_binding_history) >= 500000 BEGIN SELECT RAISE(ABORT, 'identity binding history capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS did_web_claim_transactions_capacity BEFORE INSERT ON did_web_claim_transactions WHEN (SELECT COUNT(*) FROM did_web_claim_transactions) >= 100000 BEGIN SELECT RAISE(ABORT, 'identity claim capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS signup_authorizations_capacity BEFORE INSERT ON signup_authorizations WHEN (SELECT COUNT(*) FROM signup_authorizations) >= 100000 BEGIN SELECT RAISE(ABORT, 'signup authorization capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS signup_invites_capacity BEFORE INSERT ON signup_invites WHEN (SELECT COUNT(*) FROM signup_invites) >= 100000 BEGIN SELECT RAISE(ABORT, 'signup invite capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS app_passwords_capacity BEFORE INSERT ON app_passwords WHEN (SELECT COUNT(*) FROM app_passwords) >= 100000 BEGIN SELECT RAISE(ABORT, 'app password capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS legacy_session_families_capacity BEFORE INSERT ON legacy_session_families WHEN (SELECT COUNT(*) FROM legacy_session_families) >= 100000 BEGIN SELECT RAISE(ABORT, 'legacy session family capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS legacy_sessions_capacity BEFORE INSERT ON legacy_sessions WHEN (SELECT COUNT(*) FROM legacy_sessions) >= 500000 BEGIN SELECT RAISE(ABORT, 'legacy session capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS management_sessions_capacity BEFORE INSERT ON management_sessions WHEN (SELECT COUNT(*) FROM management_sessions) >= 500000 BEGIN SELECT RAISE(ABORT, 'management session capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS authentication_factors_capacity BEFORE INSERT ON authentication_factors WHEN (SELECT COUNT(*) FROM authentication_factors) >= 200000 BEGIN SELECT RAISE(ABORT, 'authentication factor capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS factor_challenges_capacity BEFORE INSERT ON factor_challenges WHEN (SELECT COUNT(*) FROM factor_challenges) >= 500000 BEGIN SELECT RAISE(ABORT, 'factor challenge capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS webauthn_credentials_capacity BEFORE INSERT ON webauthn_credentials WHEN (SELECT COUNT(*) FROM webauthn_credentials) >= 200000 BEGIN SELECT RAISE(ABORT, 'WebAuthn credential capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS webauthn_challenges_capacity BEFORE INSERT ON webauthn_challenges WHEN (SELECT COUNT(*) FROM webauthn_challenges) >= 500000 BEGIN SELECT RAISE(ABORT, 'WebAuthn challenge capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS recovery_code_digests_capacity BEFORE INSERT ON recovery_code_digests WHEN (SELECT COUNT(*) FROM recovery_code_digests) >= 500000 BEGIN SELECT RAISE(ABORT, 'recovery code capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS identity_bindings_account_capacity BEFORE INSERT ON identity_bindings WHEN (SELECT COUNT(*) FROM identity_bindings WHERE account_did = NEW.account_did) >= 1 BEGIN SELECT RAISE(ABORT, 'identity binding account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS identity_binding_history_account_capacity BEFORE INSERT ON identity_binding_history WHEN (SELECT COUNT(*) FROM identity_binding_history WHERE account_did = NEW.account_did) >= 64 BEGIN SELECT RAISE(ABORT, 'identity binding history account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS did_web_claim_transactions_account_capacity BEFORE INSERT ON did_web_claim_transactions WHEN NEW.account_did IS NOT NULL AND (SELECT COUNT(*) FROM did_web_claim_transactions WHERE account_did = NEW.account_did) >= 16 BEGIN SELECT RAISE(ABORT, 'identity claim account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS signup_authorizations_account_capacity BEFORE INSERT ON signup_authorizations WHEN NEW.account_did IS NOT NULL AND (SELECT COUNT(*) FROM signup_authorizations WHERE account_did = NEW.account_did) >= 16 BEGIN SELECT RAISE(ABORT, 'signup authorization account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS signup_invites_account_capacity BEFORE INSERT ON signup_invites WHEN NEW.redemption_account_did IS NOT NULL AND (SELECT COUNT(*) FROM signup_invites WHERE redemption_account_did = NEW.redemption_account_did) >= 32 BEGIN SELECT RAISE(ABORT, 'redeemed signup invite account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS app_passwords_account_capacity BEFORE INSERT ON app_passwords WHEN (SELECT COUNT(*) FROM app_passwords WHERE account_did = NEW.account_did) >= 32 BEGIN SELECT RAISE(ABORT, 'app password account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS legacy_session_families_account_capacity BEFORE INSERT ON legacy_session_families WHEN (SELECT COUNT(*) FROM legacy_session_families WHERE account_did = NEW.account_did) >= 64 BEGIN SELECT RAISE(ABORT, 'legacy session family account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS legacy_sessions_account_capacity BEFORE INSERT ON legacy_sessions WHEN (SELECT COUNT(*) FROM legacy_sessions WHERE account_did = NEW.account_did) >= 256 BEGIN SELECT RAISE(ABORT, 'legacy session account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS management_sessions_account_capacity BEFORE INSERT ON management_sessions WHEN (SELECT COUNT(*) FROM management_sessions WHERE account_did = NEW.account_did) >= 256 BEGIN SELECT RAISE(ABORT, 'management session account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS authentication_factors_account_capacity BEFORE INSERT ON authentication_factors WHEN (SELECT COUNT(*) FROM authentication_factors WHERE account_did = NEW.account_did) >= 16 BEGIN SELECT RAISE(ABORT, 'authentication factor account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS factor_challenges_account_capacity BEFORE INSERT ON factor_challenges WHEN (SELECT COUNT(*) FROM factor_challenges WHERE account_did = NEW.account_did) >= 64 BEGIN SELECT RAISE(ABORT, 'factor challenge account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS totp_secret_envelopes_account_capacity BEFORE INSERT ON totp_secret_envelopes WHEN (SELECT COUNT(*) FROM totp_secret_envelopes WHERE account_did = NEW.account_did) >= 16 BEGIN SELECT RAISE(ABORT, 'TOTP envelope account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS webauthn_credentials_account_capacity BEFORE INSERT ON webauthn_credentials WHEN (SELECT COUNT(*) FROM webauthn_credentials WHERE account_did = NEW.account_did) >= 16 BEGIN SELECT RAISE(ABORT, 'WebAuthn credential account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS webauthn_challenges_account_capacity BEFORE INSERT ON webauthn_challenges WHEN (SELECT COUNT(*) FROM webauthn_challenges WHERE account_did = NEW.account_did) >= 64 BEGIN SELECT RAISE(ABORT, 'WebAuthn challenge account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS recovery_code_digests_account_capacity BEFORE INSERT ON recovery_code_digests WHEN (SELECT COUNT(*) FROM recovery_code_digests WHERE account_did = NEW.account_did) >= 32 BEGIN SELECT RAISE(ABORT, 'recovery code account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS identity_bindings_account_immutable BEFORE UPDATE OF account_did ON identity_bindings WHEN NEW.account_did <> OLD.account_did BEGIN SELECT RAISE(ABORT, 'identity binding account ownership is immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS identity_binding_history_account_immutable BEFORE UPDATE OF account_did ON identity_binding_history WHEN NEW.account_did <> OLD.account_did BEGIN SELECT RAISE(ABORT, 'identity history account ownership is immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS did_web_claim_transactions_account_immutable BEFORE UPDATE OF account_did ON did_web_claim_transactions WHEN NEW.account_did IS NOT OLD.account_did AND NOT (OLD.account_did IS NULL AND NEW.account_did IS NOT NULL) BEGIN SELECT RAISE(ABORT, 'identity claim account ownership is immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS did_web_claim_transactions_account_transition_capacity BEFORE UPDATE OF account_did ON did_web_claim_transactions WHEN OLD.account_did IS NULL AND NEW.account_did IS NOT NULL AND (SELECT COUNT(*) FROM did_web_claim_transactions WHERE account_did = NEW.account_did) >= 16 BEGIN SELECT RAISE(ABORT, 'identity claim account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS signup_authorizations_account_immutable BEFORE UPDATE OF account_did ON signup_authorizations WHEN NEW.account_did IS NOT OLD.account_did AND NOT (OLD.account_did IS NULL AND NEW.account_did IS NOT NULL) BEGIN SELECT RAISE(ABORT, 'signup authorization account ownership is immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS signup_authorizations_account_transition_capacity BEFORE UPDATE OF account_did ON signup_authorizations WHEN OLD.account_did IS NULL AND NEW.account_did IS NOT NULL AND (SELECT COUNT(*) FROM signup_authorizations WHERE account_did = NEW.account_did) >= 16 BEGIN SELECT RAISE(ABORT, 'signup authorization account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS app_passwords_account_immutable BEFORE UPDATE OF account_did ON app_passwords WHEN NEW.account_did <> OLD.account_did BEGIN SELECT RAISE(ABORT, 'app password account ownership is immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS legacy_session_families_account_immutable BEFORE UPDATE OF account_did ON legacy_session_families WHEN NEW.account_did <> OLD.account_did BEGIN SELECT RAISE(ABORT, 'legacy family account ownership is immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS legacy_sessions_account_immutable BEFORE UPDATE OF account_did ON legacy_sessions WHEN NEW.account_did <> OLD.account_did BEGIN SELECT RAISE(ABORT, 'legacy session account ownership is immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS management_sessions_account_immutable BEFORE UPDATE OF account_did ON management_sessions WHEN NEW.account_did <> OLD.account_did BEGIN SELECT RAISE(ABORT, 'management session account ownership is immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS authentication_factors_account_immutable BEFORE UPDATE OF account_did ON authentication_factors WHEN NEW.account_did <> OLD.account_did BEGIN SELECT RAISE(ABORT, 'factor account ownership is immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS factor_challenges_account_immutable BEFORE UPDATE OF account_did ON factor_challenges WHEN NEW.account_did <> OLD.account_did BEGIN SELECT RAISE(ABORT, 'factor challenge account ownership is immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS totp_secret_envelopes_account_immutable BEFORE UPDATE OF account_did ON totp_secret_envelopes WHEN NEW.account_did <> OLD.account_did BEGIN SELECT RAISE(ABORT, 'TOTP envelope account ownership is immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS recovery_code_digests_account_immutable BEFORE UPDATE OF account_did ON recovery_code_digests WHEN NEW.account_did <> OLD.account_did BEGIN SELECT RAISE(ABORT, 'recovery code account ownership is immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS webauthn_credentials_account_immutable BEFORE UPDATE OF account_did ON webauthn_credentials WHEN NEW.account_did <> OLD.account_did BEGIN SELECT RAISE(ABORT, 'WebAuthn credential account ownership is immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS webauthn_challenges_account_immutable BEFORE UPDATE OF account_did ON webauthn_challenges WHEN NEW.account_did <> OLD.account_did BEGIN SELECT RAISE(ABORT, 'WebAuthn challenge account ownership is immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS signup_invites_redemption_capacity BEFORE UPDATE OF redemption_account_did ON signup_invites WHEN OLD.redemption_account_did IS NOT NULL AND NEW.redemption_account_did IS NOT OLD.redemption_account_did BEGIN SELECT RAISE(ABORT, 'signup invite redemption ownership is immutable'); END",
        "CREATE TRIGGER IF NOT EXISTS signup_invites_redemption_account_capacity BEFORE UPDATE OF redemption_account_did ON signup_invites WHEN OLD.redemption_account_did IS NULL AND NEW.redemption_account_did IS NOT NULL AND (SELECT COUNT(*) FROM signup_invites WHERE redemption_account_did = NEW.redemption_account_did) >= 32 BEGIN SELECT RAISE(ABORT, 'redeemed signup invite account capacity exhausted'); END",
        "CREATE TRIGGER IF NOT EXISTS webauthn_sign_count_monotonic BEFORE UPDATE OF sign_count ON webauthn_credentials WHEN NEW.sign_count <= OLD.sign_count BEGIN SELECT RAISE(ABORT, 'WebAuthn sign count rollback'); END",
        "CREATE TABLE IF NOT EXISTS oauth_tokens (digest BLOB PRIMARY KEY, family_id TEXT NOT NULL, subject TEXT NOT NULL, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS oauth_client_metadata (client_id TEXT PRIMARY KEY, document BLOB NOT NULL, expires_at INTEGER NOT NULL)",
        """
        CREATE TABLE IF NOT EXISTS oauth_control_client_metadata (
            client_id TEXT PRIMARY KEY,
            document BLOB NOT NULL,
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_client_metadata_freshness (
            client_id TEXT PRIMARY KEY,
            latest_generation INTEGER NOT NULL
                CHECK(latest_generation > 0),
            published_generation INTEGER NOT NULL DEFAULT 0
                CHECK(published_generation >= 0)
                CHECK(published_generation <= latest_generation),
            retain_until INTEGER NOT NULL DEFAULT 0
                CHECK(retain_until >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_client_metadata_generation (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            last_generation INTEGER NOT NULL
                CHECK(last_generation >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_token_families (
            family_id TEXT PRIMARY KEY,
            subject TEXT NOT NULL,
            issuer TEXT NOT NULL,
            client_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            scopes BLOB NOT NULL,
            dpop_jkt TEXT,
            client_assertion_key_id TEXT,
            client_assertion_algorithm TEXT,
            client_assertion_jkt TEXT,
            refresh_token_allowed INTEGER NOT NULL DEFAULT 1 CHECK(refresh_token_allowed IN (0, 1)),
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
            revoked_at INTEGER CHECK(revoked_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_par_requests (
            request_digest BLOB PRIMARY KEY CHECK(length(request_digest) = 32),
            issuer TEXT NOT NULL,
            client_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            scopes BLOB NOT NULL,
            dpop_jkt TEXT,
            client_assertion_key_id TEXT,
            client_assertion_algorithm TEXT,
            client_assertion_jkt TEXT,
            refresh_token_allowed INTEGER NOT NULL DEFAULT 1 CHECK(refresh_token_allowed IN (0, 1)),
            state TEXT NOT NULL,
            state_digest BLOB NOT NULL CHECK(length(state_digest) = 32),
            code_challenge_method TEXT NOT NULL CHECK(code_challenge_method = 'S256'),
            code_challenge_s256 TEXT NOT NULL,
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
            consumed_at INTEGER CHECK(consumed_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_par_state_replays (
            state_digest BLOB PRIMARY KEY CHECK(length(state_digest) = 32),
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_authorization_codes (
            code_digest BLOB PRIMARY KEY CHECK(length(code_digest) = 32),
            family_id TEXT NOT NULL REFERENCES oauth_control_token_families(family_id) ON DELETE CASCADE,
            code_challenge_method TEXT NOT NULL CHECK(code_challenge_method = 'S256'),
            code_challenge_s256 TEXT NOT NULL,
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
            reuse_expires_at INTEGER NOT NULL CHECK(reuse_expires_at >= 0),
            consumed_at INTEGER CHECK(consumed_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_access_tokens (
            token_digest BLOB PRIMARY KEY CHECK(length(token_digest) = 32),
            family_id TEXT NOT NULL REFERENCES oauth_control_token_families(family_id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_refresh_tokens (
            token_digest BLOB PRIMARY KEY CHECK(length(token_digest) = 32),
            family_id TEXT NOT NULL REFERENCES oauth_control_token_families(family_id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
            used_at INTEGER CHECK(used_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_dpop_replays (
            jti_digest BLOB PRIMARY KEY CHECK(length(jti_digest) = 32),
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_client_assertion_replays (
            jti_digest BLOB PRIMARY KEY CHECK(length(jti_digest) = 32),
            client_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_delegation_replays (
            jti_digest BLOB PRIMARY KEY CHECK(length(jti_digest) = 32),
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_client_attestation_replays (
            replay_digest BLOB PRIMARY KEY CHECK(length(replay_digest) = 32),
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS plc_credential_key_continuity (
            issuer TEXT PRIMARY KEY
                CHECK(length(issuer) = 32 AND issuer GLOB 'did:plc:*'),
            terminal_cid TEXT NOT NULL
                CHECK(length(terminal_cid) = 59 AND terminal_cid GLOB 'bafyrei*')
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS plc_account_preparation_intents (
            request_id TEXT PRIMARY KEY,
            did TEXT NOT NULL UNIQUE,
            canonical_handle TEXT NOT NULL UNIQUE,
            pds_origin TEXT NOT NULL,
            repository_revision TEXT NOT NULL,
            operation_cid TEXT NOT NULL UNIQUE,
            stage INTEGER NOT NULL CHECK(stage BETWEEN 1 AND 4)
        )
        """,
        "CREATE INDEX IF NOT EXISTS oauth_control_access_token_expiry ON oauth_control_access_tokens(expires_at)",
        "CREATE INDEX IF NOT EXISTS oauth_control_refresh_token_expiry ON oauth_control_refresh_tokens(expires_at)",
        "CREATE INDEX IF NOT EXISTS oauth_control_family_expiry ON oauth_control_token_families(expires_at)",
        "CREATE INDEX IF NOT EXISTS oauth_control_client_metadata_cleanup ON oauth_control_client_metadata(expires_at, client_id)",
        "CREATE INDEX IF NOT EXISTS oauth_control_par_request_cleanup ON oauth_control_par_requests(expires_at, request_digest)",
        "CREATE INDEX IF NOT EXISTS oauth_control_par_state_cleanup ON oauth_control_par_state_replays(expires_at, state_digest)",
        "CREATE INDEX IF NOT EXISTS oauth_control_authorization_code_expiry_cleanup ON oauth_control_authorization_codes(consumed_at, expires_at, code_digest)",
        "CREATE INDEX IF NOT EXISTS oauth_control_authorization_code_reuse_cleanup ON oauth_control_authorization_codes(consumed_at, reuse_expires_at, code_digest)",
        "CREATE INDEX IF NOT EXISTS oauth_control_authorization_code_family ON oauth_control_authorization_codes(family_id)",
        "CREATE INDEX IF NOT EXISTS oauth_control_access_token_cleanup ON oauth_control_access_tokens(expires_at, token_digest)",
        "CREATE INDEX IF NOT EXISTS oauth_control_access_token_family ON oauth_control_access_tokens(family_id)",
        "CREATE INDEX IF NOT EXISTS oauth_control_refresh_token_cleanup ON oauth_control_refresh_tokens(expires_at, token_digest)",
        "CREATE INDEX IF NOT EXISTS oauth_control_refresh_token_family ON oauth_control_refresh_tokens(family_id)",
        "CREATE INDEX IF NOT EXISTS oauth_control_dpop_replay_cleanup ON oauth_control_dpop_replays(expires_at, jti_digest)",
        "CREATE INDEX IF NOT EXISTS oauth_control_client_assertion_replay_cleanup ON oauth_control_client_assertion_replays(expires_at, jti_digest)",
        "CREATE INDEX IF NOT EXISTS permissioned_space_delegation_replay_cleanup ON permissioned_space_delegation_replays(expires_at, jti_digest)",
        "CREATE INDEX IF NOT EXISTS permissioned_space_client_attestation_replay_cleanup ON permissioned_space_client_attestation_replays(expires_at, replay_digest)",
        "CREATE INDEX IF NOT EXISTS oauth_control_family_cleanup ON oauth_control_token_families(expires_at, family_id)",
        """
        CREATE TABLE IF NOT EXISTS account_lifecycle_generation (
            did TEXT PRIMARY KEY,
            generation INTEGER NOT NULL CHECK(generation >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS public_lifecycle_migrations (
            version INTEGER PRIMARY KEY CHECK(version > 0),
            applied_at INTEGER NOT NULL CHECK(applied_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS lifecycle_event_batches (
            batch_id TEXT PRIMARY KEY,
            did TEXT NOT NULL,
            generation INTEGER NOT NULL CHECK(generation >= 1),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1)),
            UNIQUE(did, generation)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS lifecycle_event_items (
            batch_id TEXT NOT NULL
                REFERENCES lifecycle_event_batches(batch_id) ON DELETE CASCADE,
            batch_ordinal INTEGER NOT NULL CHECK(batch_ordinal >= 0),
            source_key TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL CHECK(kind IN ('sync', 'identity', 'account')),
            payload BLOB NOT NULL CHECK(length(payload) > 0),
            car_bytes BLOB,
            PRIMARY KEY(batch_id, batch_ordinal),
            CHECK(
                (kind = 'sync' AND car_bytes IS NOT NULL AND length(car_bytes) > 0)
                OR (kind IN ('identity', 'account') AND car_bytes IS NULL)
            )
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS lifecycle_event_batches_pending
        ON lifecycle_event_batches(did, generation, created_at, batch_id)
        """,
    ]

    public static let accountConnectionPragmas = [
        "PRAGMA busy_timeout=5000",
        "PRAGMA journal_mode=WAL",
        "PRAGMA foreign_keys=ON",
    ]

    /// Authority-owned `com.atproto.simplespace` facts. These stay in the
    /// authority's account database, never in a member repository database or
    /// the cross-account control store. Keep these statements together because
    /// the v3 schema migration must rebuild the parent and all FK children as
    /// one unit when relaxing the original policy/managing-app CHECK.
    static let simpleSpaceAuthoritySchemaStatements = [
        """
        CREATE TABLE IF NOT EXISTS permissioned_simple_space_authorities (
            space_uri TEXT PRIMARY KEY,
            owner_did TEXT NOT NULL,
            policy TEXT NOT NULL CHECK(policy IN ('public', 'member-list', 'managing-app')),
            app_access TEXT NOT NULL CHECK(app_access IN ('open', 'allow-list')),
            managing_app TEXT,
            is_deleted INTEGER NOT NULL CHECK(is_deleted IN (0, 1)),
            revision INTEGER NOT NULL CHECK(revision > 0),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            updated_at INTEGER NOT NULL CHECK(updated_at >= created_at),
            CHECK(managing_app IS NULL OR length(managing_app) > 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_simple_space_members (
            space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
            member_did TEXT NOT NULL,
            PRIMARY KEY(space_uri, member_did)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_simple_space_clients (
            space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
            client_id TEXT NOT NULL,
            PRIMARY KEY(space_uri, client_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_simple_space_managing_app_decisions (
            space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
            user_did TEXT NOT NULL,
            PRIMARY KEY(space_uri, user_did)
        )
        """,
    ]

    /// The authority-owned synchronisation registry. These rows contain only
    /// DIDs, TIDs, LtHash commitments, opaque service-event IDs, and delivery
    /// endpoints. They never contain a record CID/value, CAR, credential, or
    /// private blob reference. Keep this separate from the member tables:
    /// writer discovery is explicitly not an access-control list.
    static let spaceNotificationSchemaStatements = [
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_writers (
            space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
            repo_did TEXT NOT NULL,
            wire_revision TEXT NOT NULL,
            commitment BLOB NOT NULL CHECK(length(commitment) = 32),
            updated_at INTEGER NOT NULL CHECK(updated_at >= 0),
            PRIMARY KEY(space_uri, repo_did)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_notification_registrations (
            space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
            endpoint TEXT NOT NULL,
            repo_did TEXT,
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
            updated_at INTEGER NOT NULL CHECK(updated_at >= 0),
            PRIMARY KEY(space_uri, endpoint),
            CHECK(length(endpoint) > 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_notification_receipts (
            issuer TEXT NOT NULL,
            event_id TEXT NOT NULL,
            space_uri TEXT NOT NULL,
            received_at INTEGER NOT NULL CHECK(received_at >= 0),
            PRIMARY KEY(issuer, event_id, space_uri)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_recipient_tombstones (
            space_uri TEXT PRIMARY KEY,
            authority_did TEXT NOT NULL,
            deletion_event_id TEXT NOT NULL,
            closed_at INTEGER NOT NULL CHECK(closed_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_notification_fanout (
            id TEXT PRIMARY KEY,
            source_issuer TEXT NOT NULL,
            source_event_id TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('write', 'deleted')),
            space_uri TEXT NOT NULL,
            repo_did TEXT,
            wire_revision TEXT,
            commitment BLOB,
            endpoint TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            available_at INTEGER NOT NULL CHECK(available_at >= 0),
            lease_token TEXT,
            lease_expires_at INTEGER,
            UNIQUE(source_issuer, source_event_id, kind, endpoint),
            CHECK(
                (kind = 'write' AND repo_did IS NOT NULL AND wire_revision IS NOT NULL
                    AND commitment IS NOT NULL AND length(commitment) = 32)
                OR (kind = 'deleted' AND repo_did IS NULL AND wire_revision IS NULL
                    AND commitment IS NULL)
            ),
            CHECK(
                (lease_token IS NULL AND lease_expires_at IS NULL)
                OR (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL
                    AND lease_expires_at >= 0)
            )
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS permissioned_space_writers_page
        ON permissioned_space_writers(space_uri, repo_did)
        """,
        """
        CREATE INDEX IF NOT EXISTS permissioned_space_notification_fanout_available
        ON permissioned_space_notification_fanout(available_at, created_at, id)
        """,
    ]

    public static let accountMigrations = accountConnectionPragmas + [
        // These four tables are retained for compatibility with the initial
        // alpha sketch. Durable repository APIs below use the explicitly
        // namespaced public_repository_* and permissioned_* tables.
        "CREATE TABLE IF NOT EXISTS public_records (uri TEXT PRIMARY KEY, value BLOB NOT NULL, revision INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS space_records (space_uri TEXT NOT NULL, uri TEXT NOT NULL, value BLOB NOT NULL, revision INTEGER NOT NULL, PRIMARY KEY(space_uri, uri))",
        "CREATE TABLE IF NOT EXISTS space_oplog (space_uri TEXT NOT NULL, revision INTEGER NOT NULL, operation BLOB NOT NULL, commitment BLOB NOT NULL, PRIMARY KEY(space_uri, revision))",
        "CREATE TABLE IF NOT EXISTS space_outbox (id TEXT PRIMARY KEY, space_uri TEXT NOT NULL, revision INTEGER NOT NULL, payload BLOB NOT NULL, attempts INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS blob_refs (cid TEXT NOT NULL, namespace TEXT NOT NULL, PRIMARY KEY(cid, namespace))",
        """
        CREATE TABLE IF NOT EXISTS public_repository_records (
            uri TEXT PRIMARY KEY,
            value BLOB NOT NULL,
            cid TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS public_repository_genesis (
            did TEXT PRIMARY KEY,
            revision TEXT NOT NULL,
            commit_cid TEXT NOT NULL,
            car BLOB NOT NULL,
            installed_at INTEGER NOT NULL CHECK(installed_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS public_repository_state (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            did TEXT NOT NULL UNIQUE,
            revision TEXT NOT NULL,
            commit_cid TEXT NOT NULL,
            data_cid TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS public_repository_blocks (
            cid TEXT PRIMARY KEY,
            bytes BLOB NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS public_repository_record_index (
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            record_cid TEXT NOT NULL,
            PRIMARY KEY(collection, rkey)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS public_repository_mutation_requests (
            request_id TEXT PRIMARY KEY,
            request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
            base_commit_cid TEXT NOT NULL,
            base_revision TEXT NOT NULL,
            next_revision TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL CHECK(status IN ('reserved', 'committed', 'abandoned')),
            committed_commit_cid TEXT,
            committed_data_cid TEXT,
            committed_projection BLOB,
            committed_projection_digest BLOB CHECK(
                committed_projection_digest IS NULL
                OR length(committed_projection_digest) = 32
            ),
            integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32),
            CHECK(
                    (status IN ('reserved', 'abandoned') AND committed_commit_cid IS NULL
                    AND committed_data_cid IS NULL AND committed_projection IS NULL
                    AND committed_projection_digest IS NULL)
                OR
                (status = 'committed' AND committed_commit_cid IS NOT NULL
                    AND committed_data_cid IS NOT NULL AND committed_projection IS NOT NULL
                    AND committed_projection_digest IS NOT NULL)
            )
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS public_repository_revision_allocator (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            highest_value INTEGER NOT NULL CHECK(highest_value >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS public_repository_import_sessions (
            session_id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL UNIQUE,
            request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
            account_did TEXT NOT NULL,
            expected_base_commit_cid TEXT NOT NULL,
            verifier_identity TEXT NOT NULL,
            maximum_record_block_bytes INTEGER NOT NULL CHECK(maximum_record_block_bytes > 0),
            maximum_car_bytes INTEGER NOT NULL CHECK(maximum_car_bytes > 0),
            maximum_car_blocks INTEGER NOT NULL CHECK(maximum_car_blocks > 0),
            maximum_mst_nodes INTEGER NOT NULL CHECK(maximum_mst_nodes > 0),
            maximum_mst_entries_per_node INTEGER NOT NULL CHECK(maximum_mst_entries_per_node > 0),
            maximum_cbor_nesting_depth INTEGER NOT NULL CHECK(maximum_cbor_nesting_depth > 0),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            expires_at INTEGER NOT NULL CHECK(expires_at >= created_at),
            status TEXT NOT NULL CHECK(status IN ('receiving', 'verifying', 'verified', 'poisoned', 'consumed')),
            root_cid TEXT,
            received_byte_count INTEGER NOT NULL DEFAULT 0 CHECK(received_byte_count >= 0),
            frame_count INTEGER NOT NULL DEFAULT 0 CHECK(frame_count >= 0),
            verified_commit_cid TEXT,
            verified_data_cid TEXT,
            verified_revision TEXT,
            reachable_block_count INTEGER,
            record_count INTEGER,
            commit_block_count INTEGER,
            mst_block_count INTEGER,
            record_block_count INTEGER,
            index_count INTEGER,
            verified_projection_digest BLOB
                CHECK(verified_projection_digest IS NULL
                    OR length(verified_projection_digest) = 32)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS public_repository_import_blocks (
            session_id TEXT NOT NULL REFERENCES public_repository_import_sessions(session_id) ON DELETE CASCADE,
            cid TEXT NOT NULL,
            bytes BLOB NOT NULL,
            PRIMARY KEY(session_id, cid)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS public_repository_import_reachable (
            session_id TEXT NOT NULL REFERENCES public_repository_import_sessions(session_id) ON DELETE CASCADE,
            cid TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('commit', 'mst', 'record')),
            PRIMARY KEY(session_id, cid)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS public_repository_import_record_index (
            session_id TEXT NOT NULL REFERENCES public_repository_import_sessions(session_id) ON DELETE CASCADE,
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            record_cid TEXT NOT NULL,
            PRIMARY KEY(session_id, collection, rkey)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS public_repository_import_results (
            request_id TEXT PRIMARY KEY,
            request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
            account_did TEXT NOT NULL,
            expected_base_commit_cid TEXT NOT NULL,
            verifier_identity TEXT NOT NULL,
            maximum_record_block_bytes INTEGER NOT NULL,
            maximum_car_bytes INTEGER NOT NULL,
            maximum_car_blocks INTEGER NOT NULL,
            maximum_mst_nodes INTEGER NOT NULL,
            maximum_mst_entries_per_node INTEGER NOT NULL,
            maximum_cbor_nesting_depth INTEGER NOT NULL,
            revision TEXT NOT NULL,
            commit_cid TEXT NOT NULL,
            data_cid TEXT NOT NULL,
            reachable_block_count INTEGER NOT NULL CHECK(reachable_block_count > 0),
            record_count INTEGER NOT NULL CHECK(record_count >= 0),
            consumed_at INTEGER NOT NULL CHECK(consumed_at >= 0),
            integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32)
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS public_repository_import_expiry
        ON public_repository_import_sessions(status, expires_at)
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_remote_replica_state (
            receiver_did TEXT NOT NULL,
            space_uri TEXT NOT NULL,
            repository_did TEXT NOT NULL,
            generation INTEGER NOT NULL CHECK(generation > 0),
            wire_revision TEXT NOT NULL,
            history_floor_wire_revision TEXT NOT NULL,
            lthash BLOB NOT NULL CHECK(length(lthash) = 2048),
            commitment BLOB NOT NULL CHECK(length(commitment) = 32),
            state_marker BLOB NOT NULL CHECK(length(state_marker) > 0),
            installed_at INTEGER NOT NULL CHECK(installed_at >= 0),
            PRIMARY KEY(space_uri, repository_did)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_remote_replica_blocks (
            space_uri TEXT NOT NULL,
            repository_did TEXT NOT NULL,
            cid TEXT NOT NULL,
            byte_count INTEGER NOT NULL
                CHECK(byte_count BETWEEN 1 AND 1048576),
            chunk_count INTEGER NOT NULL CHECK(chunk_count BETWEEN 1 AND 16),
            generation INTEGER NOT NULL CHECK(generation > 0),
            PRIMARY KEY(space_uri, repository_did, generation, cid)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_remote_replica_block_chunks (
            space_uri TEXT NOT NULL,
            repository_did TEXT NOT NULL,
            generation INTEGER NOT NULL CHECK(generation > 0),
            cid TEXT NOT NULL,
            chunk_index INTEGER NOT NULL CHECK(chunk_index BETWEEN 0 AND 15),
            bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 65536),
            PRIMARY KEY(
                space_uri, repository_did, generation, cid, chunk_index
            ),
            FOREIGN KEY(space_uri, repository_did, generation, cid)
                REFERENCES permissioned_remote_replica_blocks(
                    space_uri, repository_did, generation, cid
                ) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_remote_replica_records (
            space_uri TEXT NOT NULL,
            repository_did TEXT NOT NULL,
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            cid TEXT NOT NULL,
            generation INTEGER NOT NULL CHECK(generation > 0),
            PRIMARY KEY(
                space_uri, repository_did, generation, collection, rkey
            ),
            FOREIGN KEY(space_uri, repository_did, generation, cid)
                REFERENCES permissioned_remote_replica_blocks(
                    space_uri, repository_did, generation, cid
                )
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_remote_replica_import_sessions (
            session_id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL UNIQUE,
            request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
            source_origin TEXT NOT NULL,
            receiver_did TEXT NOT NULL,
            space_uri TEXT NOT NULL,
            repository_did TEXT NOT NULL,
            expected_base_generation INTEGER,
            expected_base_wire_revision TEXT,
            expected_base_history_floor TEXT,
            expected_base_lthash BLOB,
            expected_base_commitment BLOB,
            expected_base_marker BLOB,
            freshness_wire_revision TEXT,
            freshness_commitment BLOB,
            verifier_identity TEXT NOT NULL,
            profile_id TEXT NOT NULL,
            maximum_car_bytes INTEGER NOT NULL,
            maximum_record_bytes INTEGER NOT NULL,
            maximum_index_entries INTEGER NOT NULL,
            maximum_unique_blocks INTEGER NOT NULL,
            maximum_logical_restored_bytes INTEGER NOT NULL
                CHECK(maximum_logical_restored_bytes BETWEEN 1 AND 268435456),
            status TEXT NOT NULL CHECK(
                status IN (
                    'receiving', 'verifying', 'verified',
                    'preparing', 'poisoned', 'consumed'
                )
            ),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            expires_at INTEGER NOT NULL CHECK(expires_at > created_at),
            commit_root_cid TEXT,
            index_root_cid TEXT,
            verified_commit_body BLOB
                CHECK(verified_commit_body IS NULL
                    OR length(verified_commit_body) <= 65536),
            verified_commit_body_digest BLOB
                CHECK(verified_commit_body_digest IS NULL
                    OR length(verified_commit_body_digest) = 32),
            verified_wire_revision TEXT,
            verified_lthash BLOB
                CHECK(verified_lthash IS NULL
                    OR length(verified_lthash) = 2048),
            verified_commitment BLOB
                CHECK(verified_commitment IS NULL
                    OR length(verified_commitment) = 32),
            verified_record_count INTEGER,
            verified_unique_block_count INTEGER,
            verified_received_byte_count INTEGER,
            verified_projection_digest BLOB
                CHECK(verified_projection_digest IS NULL
                    OR length(verified_projection_digest) = 32),
            prepared_generation INTEGER CHECK(
                prepared_generation IS NULL OR prepared_generation > 0
            ),
            prepared_projection_digest BLOB CHECK(
                prepared_projection_digest IS NULL
                    OR length(prepared_projection_digest) = 32
            ),
            CHECK(
                (expected_base_generation IS NULL
                    AND expected_base_wire_revision IS NULL
                    AND expected_base_history_floor IS NULL
                    AND expected_base_lthash IS NULL
                    AND expected_base_commitment IS NULL
                    AND expected_base_marker IS NULL)
                OR
                (expected_base_generation IS NOT NULL
                    AND expected_base_wire_revision IS NOT NULL
                    AND expected_base_history_floor IS NOT NULL
                    AND length(expected_base_lthash) = 2048
                    AND length(expected_base_commitment) = 32
                    AND expected_base_marker IS NOT NULL)
            ),
            CHECK(
                (freshness_wire_revision IS NULL
                    AND freshness_commitment IS NULL)
                OR
                (freshness_wire_revision IS NOT NULL
                    AND length(freshness_commitment) = 32)
            )
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_remote_replica_import_index (
            session_id TEXT NOT NULL REFERENCES
                permissioned_remote_replica_import_sessions(session_id)
                ON DELETE CASCADE,
            path BLOB NOT NULL,
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            cid TEXT NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0, 1)),
            PRIMARY KEY(session_id, path),
            UNIQUE(session_id, collection, rkey)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_remote_replica_import_blocks (
            session_id TEXT NOT NULL REFERENCES
                permissioned_remote_replica_import_sessions(session_id)
                ON DELETE CASCADE,
            cid TEXT NOT NULL,
            byte_count INTEGER NOT NULL
                CHECK(byte_count BETWEEN 1 AND 1048576),
            chunk_count INTEGER NOT NULL DEFAULT 0
                CHECK(chunk_count BETWEEN 0 AND 16),
            complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0, 1)),
            PRIMARY KEY(session_id, cid)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS
            permissioned_remote_replica_import_block_chunks (
            session_id TEXT NOT NULL,
            cid TEXT NOT NULL,
            chunk_index INTEGER NOT NULL CHECK(chunk_index BETWEEN 0 AND 15),
            bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 65536),
            PRIMARY KEY(session_id, cid, chunk_index),
            FOREIGN KEY(session_id, cid)
                REFERENCES permissioned_remote_replica_import_blocks(
                    session_id, cid
                ) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_remote_replica_import_results (
            request_id TEXT PRIMARY KEY,
            request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
            -- This is computed by the storage boundary from the complete
            -- import binding.  It is intentionally separate from the
            -- caller-supplied request digest: a low-level caller must not be
            -- able to replay a request while changing the expected base,
            -- freshness witness, or resource limits.
            binding_digest BLOB CHECK(
                binding_digest IS NULL OR length(binding_digest) = 32
            ),
            source_origin TEXT NOT NULL,
            receiver_did TEXT NOT NULL,
            space_uri TEXT NOT NULL,
            repository_did TEXT NOT NULL,
            base_generation INTEGER,
            installed_generation INTEGER NOT NULL CHECK(installed_generation > 0),
            installed_wire_revision TEXT NOT NULL,
            installed_history_floor TEXT NOT NULL,
            installed_lthash BLOB NOT NULL CHECK(length(installed_lthash) = 2048),
            installed_commitment BLOB NOT NULL
                CHECK(length(installed_commitment) = 32),
            installed_marker BLOB NOT NULL,
            commit_root_cid TEXT NOT NULL,
            index_root_cid TEXT NOT NULL,
            record_count INTEGER NOT NULL CHECK(record_count >= 0),
            unique_block_count INTEGER NOT NULL CHECK(unique_block_count >= 0),
            verifier_identity TEXT NOT NULL,
            profile_id TEXT NOT NULL,
            maximum_logical_restored_bytes INTEGER NOT NULL
                CHECK(maximum_logical_restored_bytes BETWEEN 1 AND 268435456),
            committed_at INTEGER NOT NULL CHECK(committed_at >= 0),
            integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS
            permissioned_remote_replica_incremental_results (
            request_id TEXT NOT NULL
                CHECK(length(request_id) BETWEEN 1 AND 512),
            request_sequence BLOB NOT NULL CHECK(length(request_sequence) = 8),
            request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
            batch_digest BLOB NOT NULL CHECK(length(batch_digest) = 32),
            receiver_did TEXT NOT NULL,
            space_uri TEXT NOT NULL,
            repository_did TEXT NOT NULL,
            expected_generation INTEGER NOT NULL
                CHECK(expected_generation > 0),
            expected_wire_revision TEXT NOT NULL,
            expected_commitment BLOB NOT NULL
                CHECK(length(expected_commitment) = 32),
            expected_marker BLOB NOT NULL CHECK(length(expected_marker) > 0),
            installed_generation INTEGER NOT NULL
                CHECK(installed_generation > 0),
            installed_wire_revision TEXT NOT NULL,
            installed_history_floor TEXT NOT NULL,
            installed_lthash BLOB NOT NULL CHECK(length(installed_lthash) = 2048),
            installed_commitment BLOB NOT NULL
                CHECK(length(installed_commitment) = 32),
            installed_marker BLOB NOT NULL CHECK(length(installed_marker) > 0),
            record_count INTEGER NOT NULL CHECK(record_count >= 0),
            operation_count INTEGER NOT NULL
                CHECK(operation_count BETWEEN 1 AND 4096),
            applied_at INTEGER NOT NULL CHECK(applied_at >= 0),
            integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32),
            PRIMARY KEY(receiver_did, space_uri, repository_did, request_id),
            UNIQUE(receiver_did, space_uri, repository_did, request_sequence)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS
            permissioned_remote_replica_incremental_progress (
            receiver_did TEXT NOT NULL,
            space_uri TEXT NOT NULL,
            repository_did TEXT NOT NULL,
            replay_floor BLOB NOT NULL CHECK(length(replay_floor) = 8),
            high_watermark BLOB NOT NULL CHECK(length(high_watermark) = 8),
            PRIMARY KEY(receiver_did, space_uri, repository_did)
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS
            permissioned_remote_replica_incremental_results_retention
        ON permissioned_remote_replica_incremental_results(
            receiver_did, space_uri, repository_did, request_sequence
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS permissioned_remote_replica_import_expiry
        ON permissioned_remote_replica_import_sessions(status, expires_at)
        """,
        """
        CREATE INDEX IF NOT EXISTS
            permissioned_remote_replica_import_index_canonical_page
        ON permissioned_remote_replica_import_index(
            session_id, length(path), path
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS
            permissioned_remote_replica_import_index_cid
        ON permissioned_remote_replica_import_index(session_id, cid)
        """,
        """
        CREATE INDEX IF NOT EXISTS permissioned_remote_replica_records_page
        ON permissioned_remote_replica_records(
            space_uri, repository_did, generation, collection, rkey
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS permissioned_remote_replica_records_cid
        ON permissioned_remote_replica_records(
            space_uri, repository_did, generation, cid
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS
            permissioned_remote_replica_records_canonical_page
        ON permissioned_remote_replica_records(
            space_uri,
            repository_did,
            generation,
            length(CAST(collection || '/' || rkey AS BLOB)),
            CAST(collection || '/' || rkey AS BLOB)
        )
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS
            permissioned_remote_replica_one_active_import
        ON permissioned_remote_replica_import_sessions(
            receiver_did, space_uri, repository_did
        )
        WHERE status IN ('receiving', 'verifying', 'verified', 'preparing')
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS
            permissioned_remote_replica_one_active_import_v2
        ON permissioned_remote_replica_import_sessions(
            receiver_did, space_uri, repository_did
        )
        WHERE status IN ('receiving', 'verifying', 'verified', 'preparing')
           OR (status = 'poisoned' AND prepared_generation IS NOT NULL)
        """,
        """
        CREATE TABLE IF NOT EXISTS plc_account_preparation_journal (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            request_id TEXT NOT NULL UNIQUE,
            canonical_handle TEXT NOT NULL,
            pds_origin TEXT NOT NULL,
            repository_revision TEXT NOT NULL,
            operation_signing_did_key TEXT NOT NULL,
            operation_rotation_did_key TEXT NOT NULL,
            operation_signature TEXT NOT NULL,
            signing_key_reference TEXT NOT NULL,
            rotation_key_reference TEXT NOT NULL,
            public_genesis_commit_cid TEXT,
            stage INTEGER NOT NULL CHECK(stage BETWEEN 1 AND 4),
            CHECK(
                (stage = 1 AND public_genesis_commit_cid IS NULL)
                OR (stage > 1 AND public_genesis_commit_cid IS NOT NULL)
            )
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS plc_identity_operations (
            sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
            cid TEXT NOT NULL UNIQUE,
            previous_cid TEXT,
            canonical_json BLOB NOT NULL CHECK(length(canonical_json) > 0 AND length(canonical_json) <= 32768),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            signing_key_generation INTEGER NOT NULL CHECK(signing_key_generation > 0),
            rotation_key_generation INTEGER NOT NULL CHECK(rotation_key_generation = signing_key_generation)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_repository_state (
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision >= 0),
            wire_revision TEXT NOT NULL,
            lthash BLOB NOT NULL CHECK(length(lthash) = 2048),
            current_commit BLOB NOT NULL,
            PRIMARY KEY(space_uri, author_did)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_restored_repository_closures (
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            reason TEXT NOT NULL CHECK(reason = 'missing-authority-policy-v1'),
            PRIMARY KEY(space_uri, author_did)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_repository_migrations (
            version INTEGER PRIMARY KEY CHECK(version > 0),
            applied_at INTEGER NOT NULL CHECK(applied_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_records (
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            value BLOB NOT NULL,
            cid TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision > 0),
            PRIMARY KEY(space_uri, author_did, collection, rkey)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_oplog (
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision > 0),
            operation_index INTEGER NOT NULL CHECK(operation_index >= 0),
            wire_revision TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('create', 'update', 'delete')),
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            value BLOB,
            cid TEXT,
            previous_cid TEXT,
            commitment BLOB NOT NULL,
            PRIMARY KEY(space_uri, author_did, revision, operation_index),
            CHECK(
                (action IN ('create', 'update') AND value IS NOT NULL AND cid IS NOT NULL)
                OR (action = 'delete' AND value IS NULL AND cid IS NULL)
            ),
            CHECK(
                (action = 'create' AND previous_cid IS NULL)
                OR (action IN ('update', 'delete') AND previous_cid IS NOT NULL)
            )
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_requests (
            request_id TEXT PRIMARY KEY,
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            base_revision INTEGER NOT NULL CHECK(base_revision >= 0),
            final_revision INTEGER NOT NULL CHECK(final_revision >= base_revision),
            event_id TEXT NOT NULL UNIQUE,
            -- Receipts are retained to the same depth as the oplog. Rows
            -- written before this column existed carry the zero default and
            -- are therefore evicted before any stamped row.
            created_at INTEGER NOT NULL DEFAULT 0 CHECK(created_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_outbox (
            id TEXT PRIMARY KEY,
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision >= 0),
            payload BLOB NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            available_at INTEGER NOT NULL CHECK(available_at >= 0),
            lease_token TEXT,
            lease_expires_at INTEGER,
            CHECK(
                (lease_token IS NULL AND lease_expires_at IS NULL)
                OR (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL
                    AND lease_expires_at >= 0)
            )
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS permissioned_space_outbox_pending
        ON permissioned_space_outbox(created_at, id)
        """,
    ] + simpleSpaceAuthoritySchemaStatements + [
        """
        CREATE TABLE IF NOT EXISTS blob_payloads (
            cid TEXT PRIMARY KEY,
            -- `payload` is retained only to migrate pre-CAS rows. New rows
            -- carry a zero-length marker and are read from a private file.
            payload BLOB NOT NULL,
            storage_kind TEXT NOT NULL DEFAULT 'legacy-sqlite'
                CHECK(storage_kind IN ('legacy-sqlite', 'cas-v1')),
            -- Physical CAS lifecycle/reclamation is keyed by this digest,
            -- not the logical CID. A legacy sha256 label and CIDv1/raw label
            -- can legitimately name the same immutable file.
            cas_digest TEXT CHECK(cas_digest IS NULL OR length(cas_digest) = 64),
            byte_count INTEGER CHECK(byte_count >= 0),
            mime_type TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS blob_namespace_references (
            cid TEXT NOT NULL REFERENCES blob_payloads(cid) ON DELETE CASCADE,
            -- `staged` is an uploaded blob no commit has claimed yet. Only
            -- `public` is served to an anonymous reader; a staged edge is
            -- consumed by the public or permissioned commit that promotes it,
            -- or it expires.
            namespace_kind TEXT NOT NULL
                CHECK(namespace_kind IN ('public', 'space', 'staged')),
            space_uri TEXT NOT NULL,
            -- Unix seconds this edge was created, and the only input to both
            -- sweeps: staged expiry, and garbage collection of a public edge
            -- no repository record justifies. A NULL is never swept, so a
            -- writer that forgets to stamp an edge leaks storage rather than
            -- deleting a live blob.
            created_at INTEGER CHECK(created_at IS NULL OR created_at >= 0),
            PRIMARY KEY(cid, namespace_kind, space_uri),
            CHECK(
                (namespace_kind = 'public' AND space_uri = '')
                OR (namespace_kind = 'space' AND length(space_uri) > 0)
                OR (namespace_kind = 'staged' AND space_uri = '')
            )
        )
        """,
        // The sweep index is created by the v15 migration, not here: a pre-v15
        // database still has a reference table without `created_at` when these
        // statements run, and indexing a column that does not exist yet fails
        // the whole schema transaction.
        // This table deliberately outlives `blob_payloads` while a private
        // file is pending reclamation.  SQLite commits reachability changes
        // before any unlink; startup can then complete a crash-interrupted
        // unlink without ever restoring a reference to a missing file.
        """
        CREATE TABLE IF NOT EXISTS blob_cas_lifecycle (
            cid TEXT PRIMARY KEY,
            state TEXT NOT NULL CHECK(state IN ('creating', 'ready', 'reclaiming')),
            updated_at INTEGER NOT NULL CHECK(updated_at >= 0)
        )
        """,
    ]
}

public enum SQLiteRepositoryError: Error, Sendable, Equatable {
    case duplicateRequest(UUID)
    case corruptDatabase(String)
    case revisionOutOfRange(UInt64)
    case conflictingPublicFirehoseSourceKey(String)
}

/// A canonical public-repository record URI. Permissioned space record URIs
/// use `SpaceRecordURI` and cannot be passed to the public APIs accidentally.
public struct PublicRecordURI: Sendable, Hashable, CustomStringConvertible {
    public let rawValue: String
    public let authority: String
    public let collection: String
    public let rkey: String

    public init(_ rawValue: String) throws {
        guard rawValue.hasPrefix("at://"),
              !rawValue.contains("?"),
              !rawValue.contains("#")
        else {
            throw SwanError.invalidIdentifier(rawValue)
        }
        let fields = rawValue.dropFirst(5).split(
            separator: "/",
            omittingEmptySubsequences: false
        )
        guard fields.count == 3, fields.allSatisfy({ !$0.isEmpty }) else {
            throw SwanError.invalidIdentifier(rawValue)
        }
        let authority = String(fields[0])
        let collection = String(fields[1])
        let rkey = String(fields[2])
        // Reuse the canonical DID, NSID, and record-key validation already
        // enforced by the permissioned URI domain.
        _ = try SpaceURI(
            authority: authority,
            spaceType: collection,
            skey: rkey
        )
        self.rawValue = rawValue
        self.authority = authority
        self.collection = collection
        self.rkey = rkey
    }

    public var description: String { rawValue }
}

public struct PersistedPublicRecord: Sendable, Equatable {
    public let uri: PublicRecordURI
    public let value: Data
    public let cid: String
    public let revision: UInt64
}

public struct PersistedSpaceRecord: Sendable, Equatable {
    public let uri: SpaceRecordURI
    public let value: Data
    public let cid: String
    public let revision: UInt64
}

/// The value-free facts required to preflight a permissioned write. Keeping
/// this projection separate from ``PersistedSpaceRecord`` prevents a writer
/// from materializing every existing record body merely to check whether a
/// touched URI exists or to remove its LtHash element.
public struct PersistedSpaceRecordMetadata: Sendable, Equatable {
    public let uri: SpaceRecordURI
    public let cid: String
    public let revision: UInt64

    public init(uri: SpaceRecordURI, cid: String, revision: UInt64) {
        self.uri = uri
        self.cid = cid
        self.revision = revision
    }
}

/// The write carries an already-derived CID, but the SQLite boundary verifies
/// it against canonical DAG-CBOR before any transaction can persist it.
public enum SQLiteSpaceWrite: Sendable, Equatable {
    case create(uri: SpaceRecordURI, value: Data, cid: String)
    case put(uri: SpaceRecordURI, value: Data, cid: String)
    case update(uri: SpaceRecordURI, value: Data, cid: String)
    case delete(uri: SpaceRecordURI)

    fileprivate var uri: SpaceRecordURI {
        switch self {
        case let .create(uri, _, _), let .put(uri, _, _),
             let .update(uri, _, _), let .delete(uri): uri
        }
    }

    fileprivate var valueByteCount: Int {
        switch self {
        case let .create(_, value, _), let .put(_, value, _),
             let .update(_, value, _):
            value.count
        case .delete:
            0
        }
    }
}

/// A permissioned batch that has passed every preflight check and carries no
/// durable effect yet.  It exists so a publication lease can be taken around
/// the SQLite transaction alone rather than around the reads, the
/// authorization checks, and the CID computation that precede it.
public struct StagedAuthorizedWriteBatch: Sendable {
    public let expectedRevision: UInt64
    public let requestID: UUID
    public let wireRevision: TID
    public let writes: [SQLiteSpaceWrite]

    public init(
        expectedRevision: UInt64,
        requestID: UUID,
        wireRevision: TID,
        writes: [SQLiteSpaceWrite]
    ) {
        self.expectedRevision = expectedRevision
        self.requestID = requestID
        self.wireRevision = wireRevision
        self.writes = writes
    }
}

public struct PersistedOplogCursor: Sendable, Hashable, Comparable {
    public let revision: UInt64
    public let index: UInt64

    public init(revision: UInt64, index: UInt64) {
        self.revision = revision
        self.index = index
    }

    public static func < (lhs: Self, rhs: Self) -> Bool {
        (lhs.revision, lhs.index) < (rhs.revision, rhs.index)
    }
}

public enum PersistedRepoAction: String, Sendable, Equatable {
    case create
    case update
    case delete
}

public struct PersistedSpaceOplogEntry: Sendable, Equatable {
    public let cursor: PersistedOplogCursor
    public let wireRevision: TID
    public let action: PersistedRepoAction
    public let write: SQLiteSpaceWrite
    public let cid: String?
    public let previousCID: String?
    public let commitment: Data

    public var revision: UInt64 { cursor.revision }
    public var index: UInt64 { cursor.index }
}

public struct PersistedRepositoryState: Sendable, Equatable {
    public let space: SpaceURI
    public let author: String
    public let revision: UInt64
    public let wireRevision: TID
    public let ltHash: Data
    /// Deterministic repository-state marker. Reader-specific commit envelopes
    /// and their IKM/signatures/content bindings are never stored here.
    public let commit: Data

    public var commitment: Data { Data(SHA256.hash(data: ltHash)) }
}

public struct PersistedRepositorySnapshot: Sendable, Equatable {
    public let state: PersistedRepositoryState
    public let records: [PersistedSpaceRecord]
}

/// Read-only, domain-shaped inventory used by portable account export. It
/// contains no paths, SQL handles, payload bytes, sessions, or key material.
/// Each listed repository is loaded later through `repositorySnapshot`, and
/// each blob through the existing verified `BlobStore` API.
public struct SQLitePortableExportInventory: Sendable, Equatable {
    public struct Repository: Sendable, Equatable {
        public let space: SpaceURI
        public let author: String

        public init(space: SpaceURI, author: String) {
            self.space = space
            self.author = author
        }
    }

    public let repositories: [Repository]
    public let blobs: [BlobReference]

    public init(repositories: [Repository], blobs: [BlobReference]) {
        self.repositories = repositories
        self.blobs = blobs
    }
}

/// Offline-only input for restoring one fully verified permissioned CAR.
/// The SPI keeps this policy-bypassing boundary out of request-time modules.
@_spi(PortableRestore)
public struct SQLitePortableRestoreRepository: Sendable, Equatable {
    public let space: SpaceURI
    public let author: String
    public let wireRevision: TID
    public let records: [SpaceRecord]
    public let ltHash: Data
    public let commitment: Data

    public init(
        space: SpaceURI,
        author: String,
        recovery: VerifiedSpaceCARRecovery
    ) {
        self.space = space
        self.author = author
        wireRevision = recovery.wireRevision
        records = recovery.records
        ltHash = recovery.ltHash
        commitment = recovery.commitment
    }
}

@_spi(PortableRestore)
public struct SQLitePortableRestoreRepositoryMetadata: Sendable, Equatable {
    public let space: SpaceURI
    public let author: String
    public let wireRevision: TID
    public let recordCount: Int
    public let logicalRestoredByteCount: Int
    public let ltHash: Data
    public let commitment: Data

    public init(
        space: SpaceURI,
        author: String,
        verification: VerifiedStreamingSpaceCARRecovery
    ) {
        self.space = space
        self.author = author
        wireRevision = verification.wireRevision
        recordCount = verification.recordCount
        logicalRestoredByteCount = verification.logicalRestoredByteCount
        ltHash = verification.ltHash
        commitment = verification.commitment
    }

    init(
        space: SpaceURI,
        author: String,
        wireRevision: TID,
        recordCount: Int,
        logicalRestoredByteCount: Int,
        ltHash: Data,
        commitment: Data
    ) {
        self.space = space
        self.author = author
        self.wireRevision = wireRevision
        self.recordCount = recordCount
        self.logicalRestoredByteCount = logicalRestoredByteCount
        self.ltHash = ltHash
        self.commitment = commitment
    }
}

public enum PersistedOplogRead: Sendable, Equatable {
    case incremental([PersistedSpaceOplogEntry])
    /// The cursor predates retained operations. These durable facts are the
    /// input SwanSpaces needs to construct a fresh full-recovery CAR.
    case fullRecoveryRequired(PersistedRepositorySnapshot)
}

/// One wire-shaped permissioned oplog entry.  Unlike the write-side durable
/// entry, `value` is the live-record join result: it is absent when a later
/// write superseded this operation or when the caller requested metadata
/// only.  Historic oplog values never escape through this projection.
public struct PersistedWireOplogEntry: Sendable, Equatable {
    public let wireRevision: TID
    public let action: PersistedRepoAction
    public let uri: SpaceRecordURI
    public let cid: String?
    public let previousCID: String?
    public let value: Data?

    public init(
        wireRevision: TID,
        action: PersistedRepoAction,
        uri: SpaceRecordURI,
        cid: String?,
        previousCID: String?,
        value: Data?
    ) {
        self.wireRevision = wireRevision
        self.action = action
        self.uri = uri
        self.cid = cid
        self.previousCID = previousCID
        self.value = value
    }
}

/// Read-only result for the wire-TID incremental-sync surface.  The recovery
/// branch intentionally carries no snapshot so a caller cannot accidentally
/// turn `listRepoOps` into a full-repository export.
public enum PersistedWireOplogRead: Sendable, Equatable {
    case incremental(state: PersistedRepositoryState?, entries: [PersistedWireOplogEntry])
    case fullRecoveryRequired
}

public struct PersistedRepositoryCommit: Sendable, Equatable {
    public let state: PersistedRepositoryState
    public let entries: [PersistedSpaceOplogEntry]
    public let outbox: PersistedOutboxEvent
}

/// The facade-level oplog view retains every protocol fact SQLite persisted.
/// In particular, a single repository revision may contain several ordered
/// operations, and a delete deliberately has a null new CID but a previous
/// CID. Collapsing this into the legacy in-memory oplog loses wire semantics.
public struct DurableSpaceOplogEntry: Sendable, Equatable {
    public let cursor: PersistedOplogCursor
    public let wireRevision: TID
    public let action: PersistedRepoAction
    public let write: SpaceWrite
    public let cid: String?
    public let previousCID: String?
    public let commitment: Data

    public var revision: UInt64 { cursor.revision }
    public var index: UInt64 { cursor.index }

    public init(
        cursor: PersistedOplogCursor,
        wireRevision: TID,
        action: PersistedRepoAction,
        write: SpaceWrite,
        cid: String?,
        previousCID: String?,
        commitment: Data
    ) {
        self.cursor = cursor
        self.wireRevision = wireRevision
        self.action = action
        self.write = write
        self.cid = cid
        self.previousCID = previousCID
        self.commitment = commitment
    }
}

public enum DurableSpaceSyncResponse: Sendable, Equatable {
    case incremental([DurableSpaceOplogEntry])
    case fullSnapshot(revision: UInt64, records: [SpaceRecord], commitment: Data)
}

/// Current durable repository facts. A never-written repository has revision
/// zero and no wire revision; after its first commit all values are recovered
/// from SQLite's deterministic state marker and records, not an actor cache.
public struct DurableSpaceRepositoryState: Sendable, Equatable {
    public let space: SpaceURI
    public let author: String
    public let revision: UInt64
    public let wireRevision: TID?
    public let ltHash: Data
    public let commitment: Data

    public init(
        space: SpaceURI,
        author: String,
        revision: UInt64,
        wireRevision: TID?,
        ltHash: Data,
        commitment: Data
    ) {
        self.space = space
        self.author = author
        self.revision = revision
        self.wireRevision = wireRevision
        self.ltHash = ltHash
        self.commitment = commitment
    }
}

/// Authority facts recovered from the authority account's SQLite database.
/// `revision` advances only when a lifecycle, policy, membership, client, or
/// managing-app decision actually changes; duplicate mutations are explicit
/// no-ops and therefore retain the prior revision.
public struct DurableSimpleSpaceState: Sendable, Equatable {
    public let space: SimpleSpace
    public let revision: UInt64

    public init(space: SimpleSpace, revision: UInt64) {
        self.space = space
        self.revision = revision
    }
}

public struct PersistedOutboxEvent: Sendable, Equatable {
    public let id: UUID
    public let space: SpaceURI
    public let author: String
    public let revision: UInt64
    public let payload: Data
    public let attempts: Int
}

/// A durable lease held by one delivery worker. The token is deliberately
/// separate from the notification passed to a transport: transports need an
/// idempotency key, but never authority to acknowledge a database event.
public struct PersistedOutboxLease: Sendable, Equatable {
    public let event: PersistedOutboxEvent
    public let token: UUID
    public let expiresAt: Date

    public init(event: PersistedOutboxEvent, token: UUID, expiresAt: Date) {
        self.event = event
        self.token = token
        self.expiresAt = expiresAt
    }
}

/// A durable authority fanout intent. It is deliberately independent from
/// the writer PDS outbox: the former is created while accepting an incoming
/// service announcement, whereas the latter is created atomically with a
/// local repository commit. Neither carries any permissioned record content.
public struct PersistedSpaceNotificationFanout: Sendable, Equatable {
    public enum Kind: String, Sendable, Equatable {
        case write
        case deleted
    }

    public let id: UUID
    public let sourceIssuer: String
    public let sourceEventID: String
    public let kind: Kind
    public let space: SpaceURI
    public let repository: String?
    public let wireRevision: String?
    public let commitment: Data?
    public let endpoint: String
    public let attempts: Int

    public init(
        id: UUID,
        sourceIssuer: String,
        sourceEventID: String,
        kind: Kind,
        space: SpaceURI,
        repository: String?,
        wireRevision: String?,
        commitment: Data?,
        endpoint: String,
        attempts: Int
    ) {
        self.id = id
        self.sourceIssuer = sourceIssuer
        self.sourceEventID = sourceEventID
        self.kind = kind
        self.space = space
        self.repository = repository
        self.wireRevision = wireRevision
        self.commitment = commitment
        self.endpoint = endpoint
        self.attempts = attempts
    }
}

/// A lease for one authority fanout intent. The endpoint is exposed only to a
/// transport after it has been validated by that transport's SSRF policy; it
/// is never rendered by a public XRPC response or stored in an error string.
public struct PersistedSpaceNotificationFanoutLease: Sendable, Equatable {
    public let event: PersistedSpaceNotificationFanout
    public let token: UUID
    public let expiresAt: Date

    public init(event: PersistedSpaceNotificationFanout, token: UUID, expiresAt: Date) {
        self.event = event
        self.token = token
        self.expiresAt = expiresAt
    }
}

actor SQLiteConnectionGate {
    private var isHeld = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        if !isHeld {
            isHeld = true
            return
        }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        if waiters.isEmpty {
            isHeld = false
        } else {
            waiters.removeFirst().resume()
        }
    }
}

/// `flock` coordinates distinct processes, but advisory file locks do not
/// reliably block independently opened descriptors in the same process on all
/// supported platforms.  Keep a keyed async gate as the in-process half of
/// the blob lifecycle lock.  Each operation takes at most one key, so this
/// cannot form a lock-order cycle with SQLite's single writer.
private actor SQLiteBlobLifecycleCoordinator {
    struct Key: Hashable, Sendable {
        let dataDirectory: String
        let accountNamespace: String
        let digestHex: String
    }

    private var held: Set<Key> = []
    private var waiters: [Key: [CheckedContinuation<Void, Never>]] = [:]

    func acquire(_ key: Key) async {
        guard !held.contains(key) else {
            await withCheckedContinuation { waiters[key, default: []].append($0) }
            return
        }
        held.insert(key)
    }

    func release(_ key: Key) {
        guard let next = waiters[key]?.first else {
            held.remove(key)
            return
        }
        waiters[key]?.removeFirst()
        if waiters[key]?.isEmpty == true {
            waiters.removeValue(forKey: key)
        }
        next.resume()
    }
}

private let sqliteBlobLifecycleCoordinator = SQLiteBlobLifecycleCoordinator()
private let sqlitePermissionedCARSpoolAdmission =
    try? SpaceCARSpoolAdmission()

struct SQLiteTestingHooks: Sendable {
    var beforeApplyCommit: (@Sendable () async throws -> Void)?
    var afterSnapshotStateRead: (@Sendable () async -> Void)?
    /// Fires after `repositoryState` releases the account connection, which is
    /// the first durable read a permissioned batch performs. A test parks here
    /// to observe what a *staging* batch holds — in particular that it does
    /// not hold the control-plane publication lease.
    var afterRepositoryStateRead: (@Sendable () async -> Void)?
    var beforeBlobReferenceCommit: (@Sendable () async throws -> Void)?
    var beforeLegacyBlobMigrationCommit: (@Sendable () async throws -> Void)?
    var afterBlobReclaimCommit: (@Sendable () async throws -> Void)?
    var permissionedBlobPublicReachabilityOverride: (@Sendable (String) -> Bool?)?
    var afterPublicRepositoryMutatingSQL: (@Sendable (Int) async throws -> Void)?
    var afterRemoteReplicaMutatingSQL: (@Sendable (Int) async throws -> Void)?
    var beforePermanentDeletionClose: (@Sendable () async throws -> Void)?
    var beforeWireOplogValueMaterialization: (@Sendable () async throws -> Void)?
    var incrementalReplayRetentionOperationLimit: Int?

    init(
        beforeApplyCommit: (@Sendable () async throws -> Void)? = nil,
        afterSnapshotStateRead: (@Sendable () async -> Void)? = nil,
        afterRepositoryStateRead: (@Sendable () async -> Void)? = nil,
        beforeBlobReferenceCommit: (@Sendable () async throws -> Void)? = nil,
        beforeLegacyBlobMigrationCommit: (@Sendable () async throws -> Void)? = nil,
        afterBlobReclaimCommit: (@Sendable () async throws -> Void)? = nil,
        permissionedBlobPublicReachabilityOverride: (@Sendable (String) -> Bool?)? = nil,
        afterPublicRepositoryMutatingSQL: (@Sendable (Int) async throws -> Void)? = nil,
        afterRemoteReplicaMutatingSQL: (@Sendable (Int) async throws -> Void)? = nil,
        beforePermanentDeletionClose: (@Sendable () async throws -> Void)? = nil,
        beforeWireOplogValueMaterialization: (@Sendable () async throws -> Void)? = nil,
        incrementalReplayRetentionOperationLimit: Int? = nil
    ) {
        self.beforeApplyCommit = beforeApplyCommit
        self.afterSnapshotStateRead = afterSnapshotStateRead
        self.afterRepositoryStateRead = afterRepositoryStateRead
        self.beforeBlobReferenceCommit = beforeBlobReferenceCommit
        self.beforeLegacyBlobMigrationCommit = beforeLegacyBlobMigrationCommit
        self.afterBlobReclaimCommit = afterBlobReclaimCommit
        self.permissionedBlobPublicReachabilityOverride =
            permissionedBlobPublicReachabilityOverride
        self.afterPublicRepositoryMutatingSQL = afterPublicRepositoryMutatingSQL
        self.afterRemoteReplicaMutatingSQL = afterRemoteReplicaMutatingSQL
        self.beforePermanentDeletionClose = beforePermanentDeletionClose
        self.beforeWireOplogValueMaterialization = beforeWireOplogValueMaterialization
        self.incrementalReplayRetentionOperationLimit =
            incrementalReplayRetentionOperationLimit
    }
}

private struct LoadedSimpleSpaceAuthority: Sendable {
    let state: DurableSimpleSpaceState
    let managingAppAllowedUsers: Set<String>
}

/// The concrete SQLite/WAL boundary. Its actor is a coordination aid, while
/// `BEGIN IMMEDIATE` makes the oplog/outbox write atomic even if another Swan
/// process later opens the same file.
public enum SQLiteAccountDatabaseOpenMode: Sendable, Equatable {
    case managed
    /// Open an existing writable account database without creating the
    /// account directory or database file. This is used by recovery and
    /// other operator workflows where a control-plane row is not sufficient
    /// evidence that repository storage exists.
    case existingManaged
    case existingPortableExportSource
    @_spi(PortableRestore) case descriptorBackedOperatorRestore(rootDescriptor: Int32)
    @_spi(PortableRestore) case descriptorBackedOperatorRestoreSource(rootDescriptor: Int32)
}

public actor SQLiteAccountDatabase: StreamingBlobStore, PublicRepositoryGenesisStore {
    private static let permissionedRepositoryStorageMigrationVersion = 1
    private static let permissionedOutboxLeaseMigrationVersion = 2
    private static let simpleSpaceAuthoritySchemaMigrationVersion = 3
    private static let fileBackedBlobSchemaMigrationVersion = 4
    private static let fileBackedBlobLifecycleMigrationVersion = 5
    private static let physicalBlobCASLifecycleMigrationVersion = 6
    private static let spaceNotificationReceiptMigrationVersion = 7
    private static let permissionedRemoteReplicaResultBindingMigrationVersion = 8
    private static let spaceNotificationReceiptCompactionMigrationVersion = 9
    private static let accountBlobQuotaMigrationVersion = 10
    private static let permissionedRemoteReplicaIncrementalSequenceMigrationVersion = 11
    private static let permissionedRemoteReplicaLogicalLimitMigrationVersion = 12
    private static let publicFirehoseOutboxMigrationVersion = 13
    private static let publicFirehoseCompletionAnchorMigrationVersion = 14
    private static let stagedBlobNamespaceMigrationVersion = 15
    private static let permissionedRequestReceiptRetentionMigrationVersion = 16

    /// How long an uploaded blob no commit has claimed stays staged.
    ///
    /// A staged edge is never anonymously reachable, so this bound is about
    /// storage and the account reference quota, not confidentiality. It is
    /// long enough that a composer holding an attachment across an app
    /// restart still commits against the original upload, and short enough
    /// that abandoned uploads do not accumulate into a durable ledger. A
    /// client whose staged edge has expired simply re-uploads: the payload is
    /// content-addressed, so the retry is idempotent.
    static let stagedBlobReferenceLifetimeSeconds = 7 * 24 * 60 * 60

    /// The per-sweep bound on expired staged edges. Reclamation takes a
    /// per-digest lifecycle lock and can unlink a file, so a sweep stays
    /// bounded rather than holding a request behind an unbounded cleanup.
    static let maximumStagedBlobReferencePurge = 64

    /// How long a public blob edge no repository record justifies is kept
    /// before it can be collected.
    ///
    /// This is deliberately generous, and it is the only thing standing
    /// between the sweep and a client that uploads on Monday and commits the
    /// record on Friday. It must comfortably exceed the longest realistic
    /// upload-to-commit gap, because the cost of being too eager (a live blob
    /// deleted out from under a pending record) is far worse than the cost of
    /// being too patient (storage held a little longer).
    static let publicBlobReferenceGracePeriodSeconds = 14 * 24 * 60 * 60

    /// The per-sweep bound on collectable public edges. Deliberately smaller
    /// than the staged bound: each removal is a lifecycle-locked transaction
    /// plus a possible unlink, and this sweep can run on an upload path.
    static let maximumPublicBlobReferencePurge = 16

    /// A read credential may register notification recipients, but it must
    /// not be able to turn the later deletion fanout into an unbounded
    /// transaction. Keep the limit per space so one noisy space cannot grow
    /// another space's delivery work; re-registering an existing endpoint is
    /// still allowed when the limit has been reached.
    static let maximumNotificationRegistrationsPerSpace = 1_024

    /// Authority-owned simple-space tables are loaded into domain Sets for
    /// policy evaluation. Keep the durable state bounded before any request
    /// can cause that materialization, and keep these values aligned with the
    /// public domain limits used by the in-memory authority.
    static let maximumSimpleSpaceMembers = SimpleSpaceLimits.maximumMembersPerSpace
    static let maximumSimpleSpaceClients = SimpleSpaceLimits.maximumClientAllowListEntries
    static let maximumSimpleSpaceManagingAppDecisions =
        SimpleSpaceLimits.maximumManagingAppDecisionsPerSpace

    /// Portable export is an operator action, but its inventory must still be
    /// bounded before any repository/blob payload is opened. These ceilings
    /// are deliberately below the CAR/index admission limits and make the
    /// metadata arrays returned by the legacy inventory API a fixed-size
    /// projection rather than an attacker-controlled allocation.
    public static let maximumPortableExportRepositories = 100_000
    public static let maximumPortableExportBlobs = 100_000

    let connection: SQLiteConnection
    let connectionGate = SQLiteConnectionGate()
    let dataDirectory: URL
    let accountDID: String
    private let oplogRetention: Int
    private let blobQuota: AccountBlobQuota
    private let portableExportReadOnly: Bool
    private let descriptorBackedRestore: Bool
    private var accountDirectoryDescriptor: Int32
    private var databaseFileDescriptor: Int32
    private var accountLifecycleLockDescriptor: Int32
    private let externalBodyLeases =
        SQLiteAccountExternalBodyLeaseGate()
    var testingHooks = SQLiteTestingHooks()
    private var activeWriteTransactions = 0
    private var isClosed = false

    public init(
        dataDirectory: URL,
        did: String,
        oplogRetention: Int = 10_000,
        blobQuota: AccountBlobQuota = .conservative,
        openMode: SQLiteAccountDatabaseOpenMode = .managed
    ) async throws {
        guard oplogRetention > 0 else {
            throw SwanError.malformed("oplog retention must be positive")
        }
        _ = try SpaceURI(
            authority: did,
            spaceType: "app.swan.account",
            skey: "self"
        )
        let rootDescriptor = switch openMode {
        case .managed:
            try SQLiteProtectedPaths.openRoot(dataDirectory)
        case .existingManaged, .existingPortableExportSource:
            try SQLiteProtectedPaths.openExistingRoot(dataDirectory)
        case let .descriptorBackedOperatorRestore(descriptor),
             let .descriptorBackedOperatorRestoreSource(descriptor):
            try SQLiteProtectedPaths.duplicateOwnerOnlyDirectory(descriptor)
        }
        let accountDescriptor: Int32
        do {
            accountDescriptor = switch openMode {
            case .managed:
                try SQLiteProtectedPaths.openAccountDirectory(
                    rootDescriptor: rootDescriptor,
                    did: did
                )
            case .existingManaged, .existingPortableExportSource:
                try SQLiteProtectedPaths.openExistingAccountDirectory(
                    rootDescriptor: rootDescriptor,
                    did: did
                )
            case .descriptorBackedOperatorRestore:
                try SQLiteProtectedPaths.openAccountDirectory(
                    rootDescriptor: rootDescriptor,
                    did: did
                )
            case .descriptorBackedOperatorRestoreSource:
                try SQLiteProtectedPaths.openExistingAccountDirectory(
                    rootDescriptor: rootDescriptor,
                    did: did
                )
            }
        } catch {
            SQLiteProtectedPaths.closeDirectory(rootDescriptor)
            throw error
        }
        let lifecycleLockDescriptor: Int32
        do {
            lifecycleLockDescriptor = try SQLiteProtectedPaths
                .openAccountLifecycleLock(
                    accountDirectoryDescriptor: accountDescriptor,
                    did: did,
                    exclusive: false
                )
        } catch {
            SQLiteProtectedPaths.closeDirectory(accountDescriptor)
            SQLiteProtectedPaths.closeDirectory(rootDescriptor)
            throw error
        }
        let databasePath: String
        var heldDatabaseDescriptor: Int32 = -1
        do {
            let name = "\(Hex.encode(SHA256.hash(data: Data(did.utf8)))).sqlite"
            let path = SQLiteLayout.accountDatabase(in: dataDirectory, did: did)
                .standardizedFileURL.path
            switch openMode {
            case .managed:
                // Keep an exact-file descriptor for the lifetime of the
                // connection even though SQLite still opens the ordinary
                // path below (WAL sidecars must live beside that path). Public
                // repository admission uses this descriptor to prove that
                // the directory entry still names the inode SQLite opened.
                heldDatabaseDescriptor = try SQLiteProtectedPaths.openDatabaseFileDescriptor(
                    parentDescriptor: accountDescriptor,
                    name: name,
                    create: true
                )
                databasePath = path
            case .existingManaged, .existingPortableExportSource:
                heldDatabaseDescriptor = try SQLiteProtectedPaths.openDatabaseFileDescriptor(
                    parentDescriptor: accountDescriptor,
                    name: name,
                    create: false
                )
                databasePath = path
            case .descriptorBackedOperatorRestore:
                heldDatabaseDescriptor = try SQLiteProtectedPaths.openDatabaseFileDescriptor(
                    parentDescriptor: accountDescriptor,
                    name: name,
                    create: true
                )
                databasePath = try SQLiteProtectedPaths.databasePath(
                    for: heldDatabaseDescriptor
                )
            case .descriptorBackedOperatorRestoreSource:
                heldDatabaseDescriptor = try SQLiteProtectedPaths.openDatabaseFileDescriptor(
                    parentDescriptor: accountDescriptor,
                    name: name,
                    create: false
                )
                databasePath = try SQLiteProtectedPaths.databasePath(
                    for: heldDatabaseDescriptor
                )
            }
        } catch {
            SQLiteProtectedPaths.closeDirectory(heldDatabaseDescriptor)
            SQLiteProtectedPaths.closeAccountLifecycleLock(
                lifecycleLockDescriptor
            )
            SQLiteProtectedPaths.closeDirectory(accountDescriptor)
            SQLiteProtectedPaths.closeDirectory(rootDescriptor)
            throw error
        }
        let readOnly: Bool
        let descriptorBacked: Bool
        switch openMode {
        case .managed, .existingManaged:
            readOnly = false
            descriptorBacked = false
        case .existingPortableExportSource:
            readOnly = true
            descriptorBacked = false
        case .descriptorBackedOperatorRestore:
            readOnly = false
            descriptorBacked = true
        case .descriptorBackedOperatorRestoreSource:
            readOnly = true
            descriptorBacked = true
        }
        SQLiteProtectedPaths.closeDirectory(rootDescriptor)
        self.dataDirectory = descriptorBacked
            ? URL(fileURLWithPath: "/descriptor-backed-operator-restore")
            : dataDirectory.standardizedFileURL
        self.accountDID = did
        self.oplogRetention = oplogRetention
        self.blobQuota = blobQuota
        portableExportReadOnly = readOnly
        descriptorBackedRestore = descriptorBacked
        let openedConnection: SQLiteConnection
        do {
            let connectionPath = try readOnly
                ? SQLiteLayout.readOnlyURI(for: databasePath)
                : databasePath
            openedConnection = try await SQLiteConnection.open(
                storage: .file(path: connectionPath)
            )
        } catch {
            SQLiteProtectedPaths.closeDirectory(heldDatabaseDescriptor)
            SQLiteProtectedPaths.closeAccountLifecycleLock(
                lifecycleLockDescriptor
            )
            SQLiteProtectedPaths.closeDirectory(accountDescriptor)
            throw error
        }
        connection = openedConnection
        accountDirectoryDescriptor = accountDescriptor
        databaseFileDescriptor = heldDatabaseDescriptor
        accountLifecycleLockDescriptor = lifecycleLockDescriptor
        if !readOnly {
            do {
                try await migrateWithoutGate()
                _ = try await recoverExpiredPublicRepositoryImportSessionsWithoutGate(
                    now: Int(Date().timeIntervalSince1970)
                )
                _ = try await recoverExpiredPermissionedRemoteReplicaImportSessionsWithoutGate(
                    now: Int64(Date().timeIntervalSince1970)
                )
                try await recoverPrivateBlobLifecycle()
                try await purgeExpiredStagedBlobReferences()
                try await purgeUnreferencedPublicBlobReferences()
                if !descriptorBacked {
                    try SQLiteProtectedPaths.hardenSQLiteFiles(
                        parentDescriptor: accountDescriptor,
                        databaseName: "\(Hex.encode(SHA256.hash(data: Data(did.utf8)))).sqlite"
                    )
                }
            } catch {
                try? await openedConnection.close()
                SQLiteProtectedPaths.closeDirectory(heldDatabaseDescriptor)
                SQLiteProtectedPaths.closeAccountLifecycleLock(
                    lifecycleLockDescriptor
                )
                SQLiteProtectedPaths.closeDirectory(accountDescriptor)
                throw error
            }
        } else {
            // The mode=ro URI above makes the durable account database
            // immutable while still allowing CAR export to create/drop
            // connection-local TEMP index tables. SQLite's query_only pragma
            // also rejects TEMP writes, which are required by the bounded
            // repository snapshot path.
        }
    }

    /// Service lifecycle owns shutdown explicitly; deinit cannot safely launch
    /// a task that captures an actor instance under Swift 6 isolation rules.
    public func close() async throws {
        // Lifecycle transfers, shutdown recovery, and rejected admissions can
        // all converge on the same actor. Closing twice must be a harmless
        // replay rather than invoking SQLiteNIO on an already-closed handle.
        guard !isClosed else { return }
        isClosed = true
        try await withConnectionGate {
            let descriptor = accountDirectoryDescriptor
            let databaseDescriptor = databaseFileDescriptor
            let lifecycleDescriptor = accountLifecycleLockDescriptor
            accountDirectoryDescriptor = -1
            databaseFileDescriptor = -1
            accountLifecycleLockDescriptor = -1
            defer {
                SQLiteProtectedPaths.closeDirectory(databaseDescriptor)
                SQLiteProtectedPaths.closeAccountLifecycleLock(
                    lifecycleDescriptor
                )
                SQLiteProtectedPaths.closeDirectory(descriptor)
            }
            try await connection.close()
        }
    }

    /// Returns the identity of the exact database file descriptor retained
    /// for this connection. The descriptor is kept even for normal WAL
    /// databases (SQLite still uses the directory path for sidecars), so
    /// public-read admission can detect a directory-entry replacement without
    /// relying on a second, request-time open.
    func publicRepositoryDatabaseDescriptorIdentity()
        throws -> SQLitePublicRepositoryFileIdentity
    {
        guard databaseFileDescriptor >= 0 else {
            throw PublicRepositoryReadError.unavailable(reason: .fileIdentityMismatch)
        }
        var metadata = stat()
        guard fstat(databaseFileDescriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(),
              (metadata.st_mode & 0o777) == 0o600,
              metadata.st_nlink == 1 else {
            throw PublicRepositoryReadError.unavailable(reason: .fileIdentityMismatch)
        }
        return SQLitePublicRepositoryFileIdentity(
            device: UInt64(metadata.st_dev),
            inode: UInt64(metadata.st_ino)
        )
    }

    /// Permanent deletion first closes admission in the escaping-body gate,
    /// then waits for every previously authorized public/private blob stream
    /// to release its descriptor before the database lifecycle lease is
    /// dropped. This is stronger than ordinary service shutdown.
    public func closeForPermanentDeletion() async throws {
        await externalBodyLeases.revokeAndWait()
        try await testingHooks.beforePermanentDeletionClose?()
        try await close()
    }

    public func migrate() async throws {
        try await withConnectionGate {
            try await migrateWithoutGate()
            _ = try await recoverExpiredPublicRepositoryImportSessionsWithoutGate(
                now: Int(Date().timeIntervalSince1970)
            )
            _ = try await recoverExpiredPermissionedRemoteReplicaImportSessionsWithoutGate(
                now: Int64(Date().timeIntervalSince1970)
            )
        }
        try await recoverPrivateBlobLifecycle()
        try await purgeExpiredStagedBlobReferences()
        try await purgeUnreferencedPublicBlobReferences()
    }

    func installTestingHooks(_ hooks: SQLiteTestingHooks) {
        testingHooks = hooks
    }

    /// Test-only probe used to prove an injected delivery transport is called
    /// after the lease transaction has committed. It intentionally exposes no
    /// SQLite connection or row data.
    func hasActiveWriteTransactionForTesting() -> Bool {
        activeWriteTransactions > 0
    }

    private func migrateWithoutGate() async throws {
        // Keep connection-local PRAGMAs outside the transaction, then make
        // schema installation and data upgrades one cross-process write.
        let pragmas = descriptorBackedRestore
            ? ["PRAGMA journal_mode=MEMORY", "PRAGMA foreign_keys=ON"]
            : SQLiteLayout.accountConnectionPragmas
        for statement in pragmas {
            _ = try await connection.query(statement)
        }
        try await transaction {
            for statement in SQLiteLayout.accountMigrations.dropFirst(
                SQLiteLayout.accountConnectionPragmas.count
            ) {
                _ = try await connection.query(statement)
            }
            try await migratePermissionedRepositoryStorageIfNeeded()
            try await migratePermissionedOutboxLeasesIfNeeded()
            try await migrateFileBackedBlobSchemaIfNeeded()
            try await migrateFileBackedBlobLifecycleIfNeeded()
            try await migratePhysicalBlobCASLifecycleIfNeeded()
            try await migrateAccountBlobQuotaIfNeeded()
            try await migrateStagedBlobNamespaceIfNeeded()
            try await migratePublicRepositoryRequestIntegrityIfNeeded()
            try await migratePublicRepositoryImportProjectionBindingIfNeeded()
            try await migratePermissionedRemoteReplicaResultBindingIfNeeded()
            try await migratePermissionedRemoteReplicaIncrementalSequenceIfNeeded()
            try await migratePermissionedRemoteReplicaLogicalLimitIfNeeded()
            try await migratePublicFirehoseOutboxIfNeeded()
            try await migratePublicFirehoseCompletionAnchorsIfNeeded()
            try await migratePermissionedRequestReceiptRetentionIfNeeded()
        }
        // SQLite cannot replace a CHECK constraint in place. This migration
        // rebuilds the simple-space parent and its FK children after the base
        // schema transaction so foreign-key enforcement can be disabled only
        // for that tightly scoped copy.
        try await migrateSimpleSpaceAuthoritySchemaIfNeeded()
        // These tables reference the current v3 authority parent. Install
        // them only after any old simple-space parent has been rebuilt; doing
        // it in the base transaction would make SQLite retarget their foreign
        // keys to the temporary v2 parent during an upgrade.
        try await transaction {
            for statement in SQLiteLayout.spaceNotificationSchemaStatements {
                _ = try await connection.query(statement)
            }
        }
        try await migrateSpaceNotificationReceiptScopeIfNeeded()
        try await compactSpaceNotificationReceiptsIfNeeded()
    }

    /// The first notification schema keyed receipts only by issuer and JTI.
    /// A service JTI is consumed in the context of one space, so retaining that
    /// key globally could suppress a valid announcement for a second space if
    /// a writer reused a JTI. Rebuild the small receipt table transactionally;
    /// no record or blob data is involved, and the existing rows remain valid.
    private func migrateSpaceNotificationReceiptScopeIfNeeded() async throws {
        let version = Self.spaceNotificationReceiptMigrationVersion
        try await transaction {
            let applied = try await connection.query(
                "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
                [.integer(version)]
            )
            guard applied.isEmpty else { return }

            _ = try await connection.query(
                "ALTER TABLE permissioned_space_notification_receipts RENAME TO permissioned_space_notification_receipts_v6"
            )
            _ = try await connection.query(
                """
                CREATE TABLE permissioned_space_notification_receipts (
                    issuer TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    space_uri TEXT NOT NULL,
                    received_at INTEGER NOT NULL CHECK(received_at >= 0),
                    PRIMARY KEY(issuer, event_id, space_uri)
                )
                """
            )
            _ = try await connection.query(
                """
                INSERT INTO permissioned_space_notification_receipts(
                    issuer, event_id, space_uri, received_at
                )
                SELECT issuer, event_id, space_uri, received_at
                FROM permissioned_space_notification_receipts_v6
                """
            )
            _ = try await connection.query(
                "DROP TABLE permissioned_space_notification_receipts_v6"
            )
            _ = try await connection.query(
                """
                INSERT INTO permissioned_repository_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                [
                    .integer(version),
                    .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
                ]
            )
        }
    }

    /// Older alpha builds retained one receipt for every service event ID.
    /// Once the durable writer row has advanced, an older event cannot change
    /// state; after a recipient tombstone, no later event can change state at
    /// all. Keep only the newest receipt for each issuer/space pair so replay
    /// protection remains useful without turning an untrusted notification
    /// stream into permanent account-database growth.
    private func compactSpaceNotificationReceiptsIfNeeded() async throws {
        let version = Self.spaceNotificationReceiptCompactionMigrationVersion
        try await transaction {
            let applied = try await connection.query(
                "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
                [.integer(version)]
            )
            guard applied.isEmpty else { return }
            _ = try await connection.query(
                """
                DELETE FROM permissioned_space_notification_receipts AS old
                WHERE EXISTS (
                    SELECT 1
                    FROM permissioned_space_notification_receipts AS newer
                    WHERE newer.issuer = old.issuer
                      AND newer.space_uri = old.space_uri
                      AND (
                          newer.received_at > old.received_at
                          OR (
                              newer.received_at = old.received_at
                              AND newer.event_id > old.event_id
                          )
                      )
                )
                """
            )
            _ = try await connection.query(
                """
                INSERT INTO permissioned_repository_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                [
                    .integer(version),
                    .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
                ]
            )
        }
    }

    private func migratePublicRepositoryRequestIntegrityIfNeeded() async throws {
        let columns = try await connection.query(
            "PRAGMA table_info(public_repository_mutation_requests)"
        )
        let hasIntegrity = columns.contains { $0.column("name")?.string == "integrity_digest" }
        let schemaRows = try await connection.query(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'public_repository_mutation_requests'"
        )
        let schema = schemaRows.first?.column("sql")?.string ?? ""
        if schema.contains("'abandoned'") { return }
        let rows = try await connection.query(
            "SELECT COUNT(*) AS count FROM public_repository_mutation_requests"
        )
        guard case let .integer(count)? = rows.first?.column("count"),
              hasIntegrity || count == 0 else {
            throw SQLiteRepositoryError.corruptDatabase(
                "legacy public repository request rows require offline recovery"
            )
        }
        _ = try await connection.query(
            """
            ALTER TABLE public_repository_mutation_requests
            RENAME TO public_repository_mutation_requests_pre_integrity
            """
        )
        _ = try await connection.query(
            """
            CREATE TABLE public_repository_mutation_requests (
                request_id TEXT PRIMARY KEY,
                request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
                base_commit_cid TEXT NOT NULL,
                base_revision TEXT NOT NULL,
                next_revision TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL CHECK(status IN ('reserved', 'committed', 'abandoned')),
                committed_commit_cid TEXT,
                committed_data_cid TEXT,
                committed_projection BLOB,
                committed_projection_digest BLOB CHECK(
                    committed_projection_digest IS NULL
                    OR length(committed_projection_digest) = 32
                ),
                integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32),
                CHECK(
                    (status IN ('reserved', 'abandoned') AND committed_commit_cid IS NULL
                        AND committed_data_cid IS NULL AND committed_projection IS NULL
                        AND committed_projection_digest IS NULL)
                    OR
                    (status = 'committed' AND committed_commit_cid IS NOT NULL
                        AND committed_data_cid IS NOT NULL AND committed_projection IS NOT NULL
                        AND committed_projection_digest IS NOT NULL)
                )
            )
            """
        )
        if hasIntegrity {
            _ = try await connection.query(
                "INSERT INTO public_repository_mutation_requests SELECT * FROM public_repository_mutation_requests_pre_integrity"
            )
        }
        _ = try await connection.query("DROP TABLE public_repository_mutation_requests_pre_integrity")
    }

    /// Task 42 originally shipped staging tables before the exact projection
    /// binding columns. In-flight sessions cannot be upgraded safely because
    /// their verifier result is process-local, so discard them atomically;
    /// durable import results remain the sole replay truth.
    private func migratePublicRepositoryImportProjectionBindingIfNeeded() async throws {
        let columns = try await connection.query(
            "PRAGMA table_info(public_repository_import_sessions)"
        )
        let existing = Set(columns.compactMap { $0.column("name")?.string })
        let additions = [
            ("commit_block_count", "INTEGER"),
            ("mst_block_count", "INTEGER"),
            ("record_block_count", "INTEGER"),
            ("index_count", "INTEGER"),
            (
                "verified_projection_digest",
                "BLOB CHECK(verified_projection_digest IS NULL OR length(verified_projection_digest) = 32)"
            ),
        ]
        var changed = false
        for (name, declaration) in additions where !existing.contains(name) {
            _ = try await connection.query(
                "ALTER TABLE public_repository_import_sessions ADD COLUMN \(name) \(declaration)"
            )
            changed = true
        }
        if changed {
            _ = try await connection.query(
                "DELETE FROM public_repository_import_sessions"
            )
        }
    }

    /// Durable replay results written before the storage boundary owned the
    /// complete import binding cannot be upgraded safely: the old row did not
    /// retain the expected-base tuple, freshness witness, or limits. Keep the
    /// row for audit/export purposes, but leave its binding digest NULL so a
    /// replay fails closed with `conflictingRequestReuse` instead of being
    /// treated as an idempotent success.
    private func migratePermissionedRemoteReplicaResultBindingIfNeeded()
        async throws
    {
        let version = Self.permissionedRemoteReplicaResultBindingMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        try await addAccountColumnIfMissing(
            table: "permissioned_remote_replica_import_results",
            column: "binding_digest",
            definition: "BLOB CHECK(binding_digest IS NULL OR length(binding_digest) = 32)"
        )
        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(version),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    /// Legacy incremental replay rows cannot be assigned an authenticated
    /// per-target sequence after the fact. Refuse to open such a database
    /// rather than silently converting retained request IDs into reusable
    /// identities. Empty alpha tables can be rebuilt safely.
    private func migratePermissionedRemoteReplicaIncrementalSequenceIfNeeded()
        async throws
    {
        let version = Self
            .permissionedRemoteReplicaIncrementalSequenceMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        let columns = try await connection.query(
            "PRAGMA table_info(permissioned_remote_replica_incremental_results)"
        )
        let names = Set(columns.compactMap { $0.column("name")?.string })
        if !names.contains("request_sequence") {
            let rows = try await connection.query(
                "SELECT COUNT(*) AS count FROM permissioned_remote_replica_incremental_results"
            )
            guard rows.first?.column("count")?.integer == 0 else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "legacy incremental replay rows require offline recovery"
                )
            }
            _ = try await connection.query(
                "DROP TABLE permissioned_remote_replica_incremental_results"
            )
            _ = try await connection.query(
                """
                CREATE TABLE permissioned_remote_replica_incremental_results (
                    request_id TEXT NOT NULL
                        CHECK(length(request_id) BETWEEN 1 AND 512),
                    request_sequence BLOB NOT NULL
                        CHECK(length(request_sequence) = 8),
                    request_digest BLOB NOT NULL
                        CHECK(length(request_digest) = 32),
                    batch_digest BLOB NOT NULL
                        CHECK(length(batch_digest) = 32),
                    receiver_did TEXT NOT NULL,
                    space_uri TEXT NOT NULL,
                    repository_did TEXT NOT NULL,
                    expected_generation INTEGER NOT NULL
                        CHECK(expected_generation > 0),
                    expected_wire_revision TEXT NOT NULL,
                    expected_commitment BLOB NOT NULL
                        CHECK(length(expected_commitment) = 32),
                    expected_marker BLOB NOT NULL
                        CHECK(length(expected_marker) > 0),
                    installed_generation INTEGER NOT NULL
                        CHECK(installed_generation > 0),
                    installed_wire_revision TEXT NOT NULL,
                    installed_history_floor TEXT NOT NULL,
                    installed_lthash BLOB NOT NULL
                        CHECK(length(installed_lthash) = 2048),
                    installed_commitment BLOB NOT NULL
                        CHECK(length(installed_commitment) = 32),
                    installed_marker BLOB NOT NULL
                        CHECK(length(installed_marker) > 0),
                    record_count INTEGER NOT NULL CHECK(record_count >= 0),
                    operation_count INTEGER NOT NULL
                        CHECK(operation_count BETWEEN 1 AND 4096),
                    applied_at INTEGER NOT NULL CHECK(applied_at >= 0),
                    integrity_digest BLOB NOT NULL
                        CHECK(length(integrity_digest) = 32),
                    PRIMARY KEY(
                        receiver_did, space_uri, repository_did, request_id
                    ),
                    UNIQUE(
                        receiver_did, space_uri, repository_did,
                        request_sequence
                    )
                )
                """
            )
            _ = try await connection.query(
                """
                CREATE INDEX
                    permissioned_remote_replica_incremental_results_retention
                ON permissioned_remote_replica_incremental_results(
                    receiver_did, space_uri, repository_did, request_sequence
                )
                """
            )
        }

        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(version),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    /// Full-CAR recovery replay is valid only under the exact resource limits
    /// that governed the original import. Older schemas did not retain the
    /// logical restored-byte ceiling, so nonempty legacy session/result tables
    /// cannot be upgraded without inventing security-relevant state. Empty
    /// alpha tables are safe to extend in place.
    private func migratePermissionedRemoteReplicaLogicalLimitIfNeeded()
        async throws
    {
        let version = Self.permissionedRemoteReplicaLogicalLimitMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        let tables = [
            "permissioned_remote_replica_import_sessions",
            "permissioned_remote_replica_import_results",
        ]
        var missing: [String] = []
        for table in tables {
            let columns = try await connection.query("PRAGMA table_info(\(table))")
            let names = Set(columns.compactMap { $0.column("name")?.string })
            if !names.contains("maximum_logical_restored_bytes") {
                missing.append(table)
            }
        }

        if !missing.isEmpty {
            for table in tables {
                let rows = try await connection.query(
                    "SELECT COUNT(*) AS count FROM \(table)"
                )
                guard rows.first?.column("count")?.integer == 0 else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "legacy remote replica logical-limit bindings require offline recovery"
                    )
                }
            }
            for table in missing {
                _ = try await connection.query(
                    """
                    ALTER TABLE \(table)
                    ADD COLUMN maximum_logical_restored_bytes INTEGER NOT NULL
                        CHECK(maximum_logical_restored_bytes BETWEEN 1 AND 268435456)
                    """
                )
            }
        }

        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(version),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    /// Installs the account-local public firehose outbox. A source row always
    /// contains CAR bytes: commit rows carry the exact diff CAR and sync rows
    /// the exact commit-only CAR. There is intentionally no nullable
    /// `diff_car` column.
    private func migratePublicFirehoseOutboxIfNeeded() async throws {
        let version = Self.publicFirehoseOutboxMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        _ = try await connection.query(
        """
        CREATE TABLE IF NOT EXISTS public_event_outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_key TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL CHECK(kind IN ('commit', 'sync')),
            lifecycle_generation INTEGER NOT NULL DEFAULT 0
                CHECK(lifecycle_generation >= 0),
            payload BLOB NOT NULL CHECK(length(payload) > 0),
            car_bytes BLOB NOT NULL CHECK(length(car_bytes) > 0),
            attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            available_at INTEGER NOT NULL CHECK(available_at >= 0),
            lease_token TEXT,
            lease_expires_at INTEGER,
            CHECK(
                (lease_token IS NULL AND lease_expires_at IS NULL)
                OR (
                    lease_token IS NOT NULL
                    AND lease_expires_at IS NOT NULL
                    AND lease_expires_at >= 0
                )
            )
        );
        """
        )
        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(version),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    /// Retains completed source keys indefinitely so a retry can still prove
    /// exact idempotence after the global append has committed. Completed rows
    /// contain only already-public firehose material; pruning requires a
    /// separately designed tombstone that preserves the same conflict checks.
    private func migratePublicFirehoseCompletionAnchorsIfNeeded() async throws {
        let version = Self.publicFirehoseCompletionAnchorMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        try await addAccountColumnIfMissing(
            table: "public_event_outbox",
            column: "completed",
            definition: "INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1))"
        )
        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(version),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    /// Gives the durable request-receipt ledger the enqueue stamp its depth
    /// retention orders by. Existing receipts take the zero default rather than
    /// a synthetic timestamp: their real enqueue time was never recorded, and
    /// claiming one would let a pre-upgrade row outrank a stamped row. Zero
    /// sorts oldest, so the first prune after the upgrade evicts them first.
    /// The rows themselves are preserved; nothing is rewritten or dropped.
    private func migratePermissionedRequestReceiptRetentionIfNeeded() async throws {
        let version = Self.permissionedRequestReceiptRetentionMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        try await addAccountColumnIfMissing(
            table: "permissioned_space_requests",
            column: "created_at",
            definition: "INTEGER NOT NULL DEFAULT 0 CHECK(created_at >= 0)"
        )
        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(version),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    /// Upgrades rows written before the persistence API owned its state marker
    /// and outbox-body construction. The sentinel is committed with the row
    /// rewrites: reopening a current database must validate tampering rather
    /// than silently repair it.
    private func migratePermissionedRepositoryStorageIfNeeded() async throws {
        let version = Self.permissionedRepositoryStorageMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        let stateRows = try await connection.query(
            """
            SELECT space_uri, author_did, revision, wire_revision, lthash,
                   current_commit
            FROM permissioned_repository_state
            ORDER BY space_uri, author_did
            """
        )
        for row in stateRows {
            let spaceRaw = try requiredText(row, "space_uri")
            let author = try requiredText(row, "author_did")
            let space = try migrationSpace(
                rawValue: spaceRaw,
                author: author,
                table: "permissioned repository state"
            )
            let revision = try requiredRevision(row, "revision")
            let wireRevision = try requiredTID(row, "wire_revision")
            let ltHash = try requiredBlob(row, "lthash")
            guard ltHash.count == LtHash.byteCount else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "invalid LtHash byte count"
                )
            }
            // Legacy callers supplied arbitrary commit bytes. They are
            // intentionally not interpreted, but a non-BLOB row is malformed.
            _ = try requiredBlob(row, "current_commit")
            let marker = try repositoryStateMarker(
                space: space,
                author: author,
                revision: revision,
                wireRevision: wireRevision,
                commitment: Data(SHA256.hash(data: ltHash))
            )
            _ = try await connection.query(
                """
                UPDATE permissioned_repository_state
                SET current_commit = ?
                WHERE space_uri = ? AND author_did = ?
                """,
                [blob(marker), .text(spaceRaw), .text(author)]
            )
        }

        let outboxRows = try await connection.query(
            """
            SELECT id, space_uri, author_did, revision, payload, attempts,
                   created_at
            FROM permissioned_space_outbox
            ORDER BY created_at, id
            """
        )
        for row in outboxRows {
            let idRaw = try requiredText(row, "id")
            guard let eventID = UUID(uuidString: idRaw) else {
                throw SQLiteRepositoryError.corruptDatabase("invalid outbox id")
            }
            let spaceRaw = try requiredText(row, "space_uri")
            let author = try requiredText(row, "author_did")
            _ = try migrationSpace(
                rawValue: spaceRaw,
                author: author,
                table: "permissioned outbox"
            )
            _ = try requiredRevision(row, "revision")
            _ = try requiredBlob(row, "payload")
            _ = try requiredNonnegativeInteger(row, "attempts")
            _ = try requiredInteger(row, "created_at")
            _ = try await connection.query(
                "UPDATE permissioned_space_outbox SET payload = ? WHERE id = ?",
                [blob(opaqueNotificationPayload(eventID: eventID)), .text(idRaw)]
            )
        }

        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(version),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    /// Adds durable delivery scheduling and lease columns without widening the
    /// control database. The marker/payload migration is version 1; this
    /// version is intentionally separate so an upgraded database is never
    /// silently rewritten after a later integrity failure.
    private func migratePermissionedOutboxLeasesIfNeeded() async throws {
        let version = Self.permissionedOutboxLeaseMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        try await addAccountColumnIfMissing(
            table: "permissioned_space_outbox",
            column: "available_at",
            definition: "INTEGER NOT NULL DEFAULT 0"
        )
        try await addAccountColumnIfMissing(
            table: "permissioned_space_outbox",
            column: "lease_token",
            definition: "TEXT"
        )
        try await addAccountColumnIfMissing(
            table: "permissioned_space_outbox",
            column: "lease_expires_at",
            definition: "INTEGER"
        )
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS permissioned_space_outbox_available
            ON permissioned_space_outbox(available_at, created_at, id)
            """
        )

        let rows = try await connection.query(
            """
            SELECT id, payload, attempts, created_at, available_at,
                   lease_token, lease_expires_at
            FROM permissioned_space_outbox
            ORDER BY created_at, id
            """
        )
        for row in rows {
            let idRaw = try requiredText(row, "id")
            guard let eventID = UUID(uuidString: idRaw) else {
                throw SQLiteRepositoryError.corruptDatabase("invalid outbox id")
            }
            let payload = try requiredBlob(row, "payload")
            guard payload == opaqueNotificationPayload(eventID: eventID) else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "invalid opaque notification payload"
                )
            }
            _ = try requiredNonnegativeInteger(row, "attempts")
            let createdAt = try requiredNonnegativeInteger(row, "created_at")
            let availableAt = try requiredNonnegativeInteger(row, "available_at")
            let lease = try decodeOutboxLease(row)
            if lease.token == nil {
                // Rows written before this migration initially receive a zero
                // default. Make that explicit as immediately eligible at their
                // original enqueue time, without changing an intentional
                // positive retry deadline.
                if availableAt == 0 && createdAt > 0 {
                    _ = try await connection.query(
                        "UPDATE permissioned_space_outbox SET available_at = ? WHERE id = ?",
                        [.integer(createdAt), .text(idRaw)]
                    )
                }
            }
        }

        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(version),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    /// Adds only metadata to the existing blob table.  Historical bodies stay
    /// in their legacy column until an authorized compatibility read can stage
    /// and commit them into the private CAS.  This avoids a startup-wide read
    /// of potentially very large blobs and, importantly, never changes their
    /// namespace reachability while migrating storage media.
    private func migrateFileBackedBlobSchemaIfNeeded() async throws {
        let version = Self.fileBackedBlobSchemaMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        try await addAccountColumnIfMissing(
            table: "blob_payloads",
            column: "storage_kind",
            definition: "TEXT NOT NULL DEFAULT 'legacy-sqlite'"
        )
        try await addAccountColumnIfMissing(
            table: "blob_payloads",
            column: "byte_count",
            definition: "INTEGER"
        )
        try await addAccountColumnIfMissing(
            table: "blob_payloads",
            column: "mime_type",
            definition: "TEXT"
        )

        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(version),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    /// Makes every historical payload measurable by the account quota. SQLite
    /// computes `length(payload)` without materializing the BLOB in Swift, so
    /// the migration remains bounded in process memory. The sentinel and all
    /// metadata repairs commit in the same immediate migration transaction.
    private func migrateAccountBlobQuotaIfNeeded() async throws {
        let version = Self.accountBlobQuotaMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        _ = try await connection.query(
            """
            UPDATE blob_payloads
            SET byte_count = length(payload)
            WHERE storage_kind = 'legacy-sqlite' AND byte_count IS NULL
            """
        )
        let invalid = try await connection.query(
            """
            SELECT 1 FROM blob_payloads
            WHERE byte_count IS NULL OR byte_count < 0
            LIMIT 1
            """
        )
        guard invalid.isEmpty else {
            throw SQLiteRepositoryError.corruptDatabase(
                "blob quota metadata is incomplete"
            )
        }
        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(version),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    /// Admits the `staged` upload namespace. SQLite cannot replace a CHECK
    /// constraint in place, so a pre-v15 reference table is rebuilt: rename,
    /// recreate with the widened kind and the `staged_at` expiry column, copy
    /// every row verbatim, drop the old table.
    ///
    /// No existing row changes meaning. Every committed row is `public` or
    /// `space` and stays exactly that, with a NULL `staged_at`, so an account
    /// that already serves blobs keeps serving precisely the same set. The
    /// table is a per-account reference index bounded by
    /// ``AccountBlobQuota/maximumReferences``, not a payload store, so the
    /// copy is small and no blob bytes move.
    private func migrateStagedBlobNamespaceIfNeeded() async throws {
        let version = Self.stagedBlobNamespaceMigrationVersion
        // Drive this off the observed table shape rather than the marker
        // alone. A restored or repaired database can carry a marker for a
        // shape it does not have, and a reference table without `created_at`
        // fails every upload — so the shape is the authority and the marker
        // only records that the work has been done.
        let columns = try await connection.query(
            "PRAGMA table_info(blob_namespace_references)"
        )
        let alreadyMigrated = columns.contains {
            $0.column("name")?.string == "created_at"
        }
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        if alreadyMigrated, !applied.isEmpty { return }

        if !alreadyMigrated {
            _ = try await connection.query(
                """
                ALTER TABLE blob_namespace_references
                RENAME TO blob_namespace_references_v14
                """
            )
            _ = try await connection.query(
                """
                CREATE TABLE blob_namespace_references (
                    cid TEXT NOT NULL REFERENCES blob_payloads(cid)
                        ON DELETE CASCADE,
                    namespace_kind TEXT NOT NULL
                        CHECK(namespace_kind IN ('public', 'space', 'staged')),
                    space_uri TEXT NOT NULL,
                    created_at INTEGER
                        CHECK(created_at IS NULL OR created_at >= 0),
                    PRIMARY KEY(cid, namespace_kind, space_uri),
                    CHECK(
                        (namespace_kind = 'public' AND space_uri = '')
                        OR (namespace_kind = 'space' AND length(space_uri) > 0)
                        OR (namespace_kind = 'staged' AND space_uri = '')
                    )
                )
                """
            )
            // Existing edges are stamped with the upgrade instant, not with
            // NULL and not with zero. Nothing an account already serves
            // disappears when this ships — every inherited edge starts its
            // grace period now — and the historical orphans this scan is
            // about still become collectable one grace period later.
            _ = try await connection.query(
                """
                INSERT INTO blob_namespace_references(
                    cid, namespace_kind, space_uri, created_at
                )
                SELECT cid, namespace_kind, space_uri, ?
                FROM blob_namespace_references_v14
                """,
                [.integer(Int(Date().timeIntervalSince1970))]
            )
            _ = try await connection.query(
                "DROP TABLE blob_namespace_references_v14"
            )
        }
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS blob_namespace_references_sweep
            ON blob_namespace_references(namespace_kind, created_at)
            """
        )

        guard applied.isEmpty else { return }
        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(version),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    /// Enrolls already-file-backed v4 rows in the durable lifecycle ledger
    /// without reading a single legacy BLOB.  Legacy rows are deliberately
    /// absent until an authorized compatibility read validates that exact
    /// payload and starts its one-CID lifecycle.
    private func migrateFileBackedBlobLifecycleIfNeeded() async throws {
        let version = Self.fileBackedBlobLifecycleMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        let timestamp = Int(Date().timeIntervalSince1970 * 1_000_000)
        let lifecycleColumns = try await connection.query(
            "PRAGMA table_info(blob_cas_lifecycle)"
        )
        // A repaired/current database may already have the v6 physical-digest
        // table while a manually restored migration marker is absent. Do not
        // attempt a legacy-CID insert into that newer shape; v6 below will
        // validate/reconcile it.
        guard lifecycleColumns.contains(where: { $0.column("name")?.string == "cid" }) else {
            _ = try await connection.query(
                """
                INSERT INTO permissioned_repository_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                [.integer(version), .integer(timestamp)]
            )
            return
        }
        _ = try await connection.query(
            """
            INSERT INTO blob_cas_lifecycle(cid, state, updated_at)
            SELECT cid, 'ready', ?
            FROM blob_payloads
            WHERE storage_kind = 'cas-v1'
            ON CONFLICT(cid) DO NOTHING
            """,
            [.integer(timestamp)]
        )
        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [.integer(version), .integer(timestamp)]
        )
    }

    /// v5 keyed lifecycle rows by logical CID. That is insufficient because
    /// the legacy `sha256:<digest>` compatibility name and the canonical raw
    /// CID can name one physical CAS file. v6 records the digest beside every
    /// CAS metadata row and rebuilds the lifecycle ledger around that physical
    /// identity, without selecting any payload BLOB.
    private func migratePhysicalBlobCASLifecycleIfNeeded() async throws {
        let version = Self.physicalBlobCASLifecycleMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        try await addAccountColumnIfMissing(
            table: "blob_payloads",
            column: "cas_digest",
            definition: "TEXT"
        )

        let casRows = try await connection.query(
            "SELECT cid, cas_digest FROM blob_payloads WHERE storage_kind = 'cas-v1'"
        )
        var activeDigests = Set<String>()
        for row in casRows {
            let cid = try requiredText(row, "cid")
            let digest: String
            do {
                digest = try blobDigestHex(cid: cid, allowLegacy: true)
            } catch {
                throw SQLiteRepositoryError.corruptDatabase("invalid CAS blob CID")
            }
            if let stored = row.column("cas_digest"), !stored.isNull {
                guard stored.string == digest else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "CAS blob digest does not match CID"
                    )
                }
            }
            _ = try await connection.query(
                "UPDATE blob_payloads SET cas_digest = ? WHERE cid = ?",
                [.text(digest), .text(cid)]
            )
            activeDigests.insert(digest)
        }

        let lifecycleColumns = try await connection.query(
            "PRAGMA table_info(blob_cas_lifecycle)"
        )
        let hasLegacyCIDKey = lifecycleColumns.contains {
            $0.column("name")?.string == "cid"
        }
        var lifecycleByDigest: [String: BlobCASLifecycleState] = [:]
        if hasLegacyCIDKey {
            let lifecycleRows = try await connection.query(
                "SELECT cid, state FROM blob_cas_lifecycle"
            )
            for row in lifecycleRows {
                let cid = try requiredText(row, "cid")
                let digest: String
                do {
                    digest = try blobDigestHex(cid: cid, allowLegacy: true)
                } catch {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "invalid legacy CAS lifecycle CID"
                    )
                }
                guard let state = BlobCASLifecycleState(
                    rawValue: try requiredText(row, "state")
                ) else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "invalid legacy CAS lifecycle state"
                    )
                }
                lifecycleByDigest[digest] = lifecycleByDigest[digest] ?? state
            }
        } else {
            let lifecycleRows = try await connection.query(
                "SELECT digest_hex, state FROM blob_cas_lifecycle"
            )
            for row in lifecycleRows {
                let digest = try requiredText(row, "digest_hex")
                guard legacyBlobDigest("sha256:\(digest)") != nil,
                      let state = BlobCASLifecycleState(
                          rawValue: try requiredText(row, "state")
                      )
                else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "invalid CAS lifecycle row"
                    )
                }
                lifecycleByDigest[digest] = state
            }
        }

        // A durable CAS metadata row always wins over a stale reclaiming
        // intent. Conversely, an old ready/creating row with no metadata is
        // conservatively reclaimed on the next startup.
        for digest in activeDigests {
            lifecycleByDigest[digest] = .ready
        }
        let inactiveLifecycleDigests = lifecycleByDigest.keys.filter {
            !activeDigests.contains($0)
        }
        for digest in inactiveLifecycleDigests {
            lifecycleByDigest[digest] = .reclaiming
        }

        if hasLegacyCIDKey {
            _ = try await connection.query(
                """
                CREATE TABLE blob_cas_lifecycle_v6 (
                    digest_hex TEXT PRIMARY KEY CHECK(length(digest_hex) = 64),
                    state TEXT NOT NULL CHECK(state IN ('creating', 'ready', 'reclaiming')),
                    updated_at INTEGER NOT NULL CHECK(updated_at >= 0)
                )
                """
            )
            let timestamp = Int(Date().timeIntervalSince1970 * 1_000_000)
            for (digest, state) in lifecycleByDigest {
                _ = try await connection.query(
                    """
                    INSERT INTO blob_cas_lifecycle_v6(digest_hex, state, updated_at)
                    VALUES (?, ?, ?)
                    """,
                    [.text(digest), .text(state.rawValue), .integer(timestamp)]
                )
            }
            _ = try await connection.query("DROP TABLE blob_cas_lifecycle")
            _ = try await connection.query(
                "ALTER TABLE blob_cas_lifecycle_v6 RENAME TO blob_cas_lifecycle"
            )
        } else {
            let timestamp = Int(Date().timeIntervalSince1970 * 1_000_000)
            _ = try await connection.query("DELETE FROM blob_cas_lifecycle")
            for (digest, state) in lifecycleByDigest {
                _ = try await connection.query(
                    """
                    INSERT INTO blob_cas_lifecycle(digest_hex, state, updated_at)
                    VALUES (?, ?, ?)
                    """,
                    [.text(digest), .text(state.rawValue), .integer(timestamp)]
                )
            }
        }

        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [.integer(version), .integer(Int(Date().timeIntervalSince1970 * 1_000_000))]
        )
    }

    /// Replaces the original schema constraint which tied `managing_app` to
    /// `managing-app` policy. The pinned TypeScript `updateSpace` procedure
    /// patches those fields independently, so a policy-only change must retain
    /// a configured app and an empty update must be able to clear it. SQLite
    /// has no `ALTER CHECK`; copy the parent and every child table in one
    /// immediate transaction while foreign keys are disabled, then validate
    /// the reconstructed graph before recording the migration sentinel.
    private func migrateSimpleSpaceAuthoritySchemaIfNeeded() async throws {
        let version = Self.simpleSpaceAuthoritySchemaMigrationVersion
        _ = try await connection.query("PRAGMA foreign_keys = OFF")
        do {
            try await transaction {
                // This must be the first operation after BEGIN IMMEDIATE.
                // A different process can finish the rebuild after this
                // connection's base-schema transaction and before it reaches
                // here. Checking outside this transaction would let both
                // openers decide to rebuild the same tables.
                let applied = try await connection.query(
                    "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
                    [.integer(version)]
                )
                guard applied.isEmpty else { return }

                // Validate the legacy child tables before copying them. A
                // schema rebuild must not turn an oversized persisted policy
                // into a large transient Swift Set or an unbounded INSERT
                // transaction merely because the account is being reopened.
                try await validateSimpleSpaceTableBounds(
                    table: "permissioned_simple_space_members",
                    maximum: Self.maximumSimpleSpaceMembers,
                    label: "members"
                )
                try await validateSimpleSpaceTableBounds(
                    table: "permissioned_simple_space_clients",
                    maximum: Self.maximumSimpleSpaceClients,
                    label: "clients"
                )
                try await validateSimpleSpaceTableBounds(
                    table: "permissioned_simple_space_managing_app_decisions",
                    maximum: Self.maximumSimpleSpaceManagingAppDecisions,
                    label: "managing-app decisions"
                )

                try await renameSimpleSpaceAuthorityTablesForMigration()
                for statement in SQLiteLayout.simpleSpaceAuthoritySchemaStatements {
                    _ = try await connection.query(statement)
                }
                try await copySimpleSpaceAuthorityTablesFromMigration()
                try await dropSimpleSpaceAuthorityMigrationTables()

                let violations = try await connection.query("PRAGMA foreign_key_check")
                guard violations.isEmpty else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "simple-space schema migration violated foreign keys"
                    )
                }
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_repository_migrations(version, applied_at)
                    VALUES (?, ?)
                    """,
                    [
                        .integer(version),
                        .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
                    ]
                )
            }
            _ = try await connection.query("PRAGMA foreign_keys = ON")
        } catch {
            _ = try? await connection.query("PRAGMA foreign_keys = ON")
            throw error
        }
    }

    private func validateSimpleSpaceTableBounds(
        table: String,
        maximum: Int,
        label: String
    ) async throws {
        let rows = try await connection.query(
            """
            SELECT 1
            FROM \(table)
            GROUP BY space_uri
            HAVING COUNT(*) > ?
            LIMIT 1
            """,
            [.integer(maximum)]
        )
        guard rows.isEmpty else {
            throw SQLiteRepositoryError.corruptDatabase(
                "simple-space \(label) state exceeds its bound"
            )
        }
    }

    private func renameSimpleSpaceAuthorityTablesForMigration() async throws {
        _ = try await connection.query(
            "ALTER TABLE permissioned_simple_space_authorities RENAME TO permissioned_simple_space_authorities_schema_v2"
        )
        _ = try await connection.query(
            "ALTER TABLE permissioned_simple_space_members RENAME TO permissioned_simple_space_members_schema_v2"
        )
        _ = try await connection.query(
            "ALTER TABLE permissioned_simple_space_clients RENAME TO permissioned_simple_space_clients_schema_v2"
        )
        _ = try await connection.query(
            "ALTER TABLE permissioned_simple_space_managing_app_decisions RENAME TO permissioned_simple_space_managing_app_decisions_schema_v2"
        )
    }

    private func copySimpleSpaceAuthorityTablesFromMigration() async throws {
        _ = try await connection.query(
            """
            INSERT INTO permissioned_simple_space_authorities(
                space_uri, owner_did, policy, app_access, managing_app,
                is_deleted, revision, created_at, updated_at
            )
            SELECT space_uri, owner_did, policy, app_access, managing_app,
                   is_deleted, revision, created_at, updated_at
            FROM permissioned_simple_space_authorities_schema_v2
            """
        )
        _ = try await connection.query(
            """
            INSERT INTO permissioned_simple_space_members(space_uri, member_did)
            SELECT space_uri, member_did
            FROM permissioned_simple_space_members_schema_v2
            """
        )
        _ = try await connection.query(
            """
            INSERT INTO permissioned_simple_space_clients(space_uri, client_id)
            SELECT space_uri, client_id
            FROM permissioned_simple_space_clients_schema_v2
            """
        )
        _ = try await connection.query(
            """
            INSERT INTO permissioned_simple_space_managing_app_decisions(space_uri, user_did)
            SELECT space_uri, user_did
            FROM permissioned_simple_space_managing_app_decisions_schema_v2
            """
        )
    }

    private func dropSimpleSpaceAuthorityMigrationTables() async throws {
        // Drop children before their old parent. The new child tables already
        // reference the replacement parent, so this cannot hide a violation.
        _ = try await connection.query(
            "DROP TABLE permissioned_simple_space_managing_app_decisions_schema_v2"
        )
        _ = try await connection.query(
            "DROP TABLE permissioned_simple_space_clients_schema_v2"
        )
        _ = try await connection.query(
            "DROP TABLE permissioned_simple_space_members_schema_v2"
        )
        _ = try await connection.query(
            "DROP TABLE permissioned_simple_space_authorities_schema_v2"
        )
    }

    private func addAccountColumnIfMissing(
        table: String,
        column: String,
        definition: String
    ) async throws {
        let rows = try await connection.query("PRAGMA table_info(\(table))")
        if rows.contains(where: { $0.column("name")?.string == column }) {
            return
        }
        _ = try await connection.query(
            "ALTER TABLE \(table) ADD COLUMN \(column) \(definition)"
        )
    }

    private func migrationSpace(
        rawValue: String,
        author: String,
        table: String
    ) throws -> SpaceURI {
        guard author == accountDID,
              let space = try? SpaceURI(rawValue),
              space.rawValue == rawValue
        else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid \(table) ownership"
            )
        }
        return space
    }

    // MARK: Public repository namespace

    public func putPublicRecord(
        uri: PublicRecordURI,
        value: Data,
        cid: String,
        revision: UInt64
    ) async throws {
        guard uri.authority == accountDID else {
            throw SwanError.unauthorized(
                "public record belongs to another account"
            )
        }
        guard !cid.isEmpty else { throw SwanError.malformed("record CID is empty") }
        let storedRevision = try sqliteRevision(revision)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    """
                    INSERT INTO public_repository_records(uri, value, cid, revision)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(uri) DO UPDATE SET
                        value = excluded.value,
                        cid = excluded.cid,
                        revision = excluded.revision
                    """,
                    [.text(uri.rawValue), blob(value), .text(cid), .integer(storedRevision)]
                )
            }
        }
    }

    public func publicRecord(_ uri: PublicRecordURI) async throws -> PersistedPublicRecord? {
        guard uri.authority == accountDID else {
            throw SwanError.unauthorized(
                "public record belongs to another account"
            )
        }
        return try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT value, cid, revision
                FROM public_repository_records
                WHERE uri = ?
                """,
                [.text(uri.rawValue)]
            )
            guard let row = rows.first else { return nil }
            return PersistedPublicRecord(
                uri: uri,
                value: try requiredBlob(row, "value"),
                cid: try requiredText(row, "cid"),
                revision: try requiredRevision(row, "revision")
            )
        }
    }

    // MARK: Public repository genesis

    /// Installs the one immutable empty public-repository genesis for this
    /// account database. The candidate is re-derived from its CAR before any
    /// write, so callers cannot smuggle inconsistent cached fields alongside a
    /// valid byte payload. Existing state is verified again under the supplied
    /// public key before it is returned.
    public func installPublicRepositoryGenesis(
        _ candidate: PublicRepositoryGenesis,
        signingPublicKey: P256.Signing.PublicKey,
        installedAt: Date
    ) async throws -> PublicRepositoryGenesisInstallation {
        let verifiedCandidate = try verifiedPublicGenesis(
            car: candidate.car,
            signingPublicKey: signingPublicKey
        )
        let timestamp = try publicGenesisTimestamp(installedAt)
        let persistedAt = Date(timeIntervalSince1970: Double(timestamp) / 1_000_000)
        let candidateState = try PersistedPublicRepositoryGenesis(
            genesis: verifiedCandidate,
            installedAt: persistedAt
        )

        return try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT did, revision, commit_cid, car, installed_at
                    FROM public_repository_genesis
                    """
                )
                guard rows.count <= 1 else {
                    throw PublicRepositoryGenesisStoreError.corruptStoredGenesis
                }
                guard let row = rows.first else {
                    _ = try await connection.query(
                        """
                        INSERT INTO public_repository_genesis(
                            did, revision, commit_cid, car, installed_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        [
                            .text(verifiedCandidate.did),
                            .text(verifiedCandidate.revision),
                            .text(verifiedCandidate.commitCID.string),
                            blob(verifiedCandidate.car),
                            .integer(timestamp),
                        ]
                    )
                    try await installPublicRepositoryTruth(verifiedCandidate)
                    return PublicRepositoryGenesisInstallation(
                        persisted: candidateState,
                        wasAlreadyInstalled: false
                    )
                }

                let stored = try decodeStoredPublicRepositoryGenesis(
                    row,
                    signingPublicKey: signingPublicKey
                )
                guard stored.genesis == verifiedCandidate else {
                    throw PublicRepositoryGenesisStoreError.conflictingGenesis
                }
                try await installPublicRepositoryTruth(verifiedCandidate)
                return PublicRepositoryGenesisInstallation(
                    persisted: stored,
                    wasAlreadyInstalled: true
                )
            }
        }
    }

    private func installPublicRepositoryTruth(
        _ genesis: PublicRepositoryGenesis
    ) async throws {
        let stateRows = try await connection.query(
            """
            SELECT did, revision, commit_cid, data_cid
            FROM public_repository_state WHERE singleton = 1
            """
        )
        guard stateRows.count <= 1 else {
            throw PublicRepositoryGenesisStoreError.corruptStoredGenesis
        }
        if let row = stateRows.first {
            guard row.column("did")?.string == genesis.did,
                  let revision = row.column("revision")?.string,
                  (try? PublicRepositoryTID(revision)) != nil,
                  let commitString = row.column("commit_cid")?.string,
                  let commitCID = try? CID.parse(commitString),
                  commitCID.string == commitString,
                  (try? PublicRepositoryCID.validate(commitCID)) != nil,
                  let dataString = row.column("data_cid")?.string,
                  let dataCID = try? CID.parse(dataString),
                  dataCID.string == dataString,
                  (try? PublicRepositoryCID.validate(dataCID)) != nil
            else {
                throw PublicRepositoryGenesisStoreError.corruptStoredGenesis
            }
            for cid in [commitCID, dataCID] {
                let read = try await boundedPublicRepositoryBlock(
                    connection: connection, cid: cid
                )
                guard case let .bytes(bytes) = read,
                      (try? PublicRepositoryCID.validate(cid, blockBytes: bytes)) != nil else {
                    throw PublicRepositoryGenesisStoreError.corruptStoredGenesis
                }
            }
        } else {
            _ = try await connection.query(
                """
                INSERT INTO public_repository_state(
                    singleton, did, revision, commit_cid, data_cid
                ) VALUES (1, ?, ?, ?, ?)
                """,
                [
                    .text(genesis.did),
                    .text(genesis.revision),
                    .text(genesis.commitCID.string),
                    .text(genesis.emptyMSTCID.string),
                ]
            )
        }
        for (cid, bytes) in [
            (genesis.commitCID, genesis.signedCommit),
            (genesis.emptyMSTCID, genesis.emptyMST),
        ] {
            switch try await boundedPublicRepositoryBlock(
                connection: connection, cid: cid
            ) {
            case .missing:
                _ = try await connection.query(
                    "INSERT INTO public_repository_blocks(cid, bytes) VALUES (?, ?)",
                    [.text(cid.string), bytes.sqliteData!]
                )
            case .oversized:
                throw PublicRepositoryGenesisStoreError.corruptStoredGenesis
            case let .bytes(existingBytes):
                guard existingBytes == bytes else {
                    throw PublicRepositoryGenesisStoreError.corruptStoredGenesis
                }
            }
        }
    }

    /// Loading is deliberately validation work, not a best-effort cache read:
    /// any tampered row rejects the whole operation and is never repaired from
    /// a caller-provided candidate.
    public func loadPublicRepositoryGenesis(
        did: String,
        signingPublicKey: P256.Signing.PublicKey
    ) async throws -> PersistedPublicRepositoryGenesis? {
        guard did == accountDID else {
            throw PublicRepositoryGenesisStoreError.ownershipMismatch
        }
        do {
            try PublicRepositoryGenesisCodec.validateDID(did)
        } catch {
            throw PublicRepositoryGenesisStoreError.ownershipMismatch
        }
        return try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT did, revision, commit_cid, car, installed_at
                FROM public_repository_genesis
                """
            )
            guard rows.count <= 1 else {
                throw PublicRepositoryGenesisStoreError.corruptStoredGenesis
            }
            guard let row = rows.first else { return nil }
            return try decodeStoredPublicRepositoryGenesis(
                row,
                signingPublicKey: signingPublicKey
            )
        }
    }

    // MARK: Permissioned repository namespace

    /// Atomically performs revision CAS, replay reservation, record mutations,
    /// state/oplog persistence, retention, and notification enqueueing. It
    /// performs no network I/O.
    public func apply(
        space: SpaceURI,
        author: String,
        expectedRevision: UInt64,
        requestID: UUID,
        wireRevision: TID,
        writes: [SQLiteSpaceWrite],
        eventID: UUID = UUID()
    ) async throws -> PersistedRepositoryCommit {
        try requireAccount(author)
        guard !writes.isEmpty else {
            throw SwanError.malformed("repository batch must contain a write")
        }
        var aggregateValueBytes = 0
        for write in writes {
            aggregateValueBytes = try SpaceWriteLimits.addingValueBytes(
                aggregateValueBytes,
                write.valueByteCount
            )
        }
        try SpaceWriteLimits.validate(
            operationCount: writes.count,
            aggregateValueBytes: aggregateValueBytes
        )
        for write in writes {
            guard write.uri.space == space, write.uri.author == author else {
                throw SwanError.unauthorized("record belongs to another repository")
            }
            switch write {
            case let .create(_, value, cid),
                 let .put(_, value, cid),
                 let .update(_, value, cid):
                do {
                    try SpaceCARCodec.validateCanonicalRecord(
                        value,
                        expectedCID: cid
                    )
                } catch {
                    throw SwanError.malformed(
                        "record must be canonical DAG-CBOR with its exact CID"
                    )
                }
            case .delete:
                break
            }
        }
        var permissionedBlobCIDs = Set<String>()
        for write in writes {
            switch write {
            case let .create(_, value, _), let .put(_, value, _), let .update(_, value, _):
                do {
                    permissionedBlobCIDs.formUnion(
                        try rawBlobCIDs(in: value)
                    )
                } catch {
                    throw SwanError.malformed(
                        "permissioned record blob references are invalid"
                    )
                }
            case .delete:
                break
            }
        }
        _ = try sqliteRevision(expectedRevision)

        return try await withConnectionGate {
            try await transaction {
            try await requireLocalRepositorySpaceOpen(space)
            let duplicate = try await connection.query(
                "SELECT 1 FROM permissioned_space_requests WHERE request_id = ?",
                [.text(requestID.uuidString)]
            )
            guard duplicate.isEmpty else {
                throw SQLiteRepositoryError.duplicateRequest(requestID)
            }

            let current = try await loadState(space: space, author: author)
            let actualRevision = current?.revision ?? 0
            guard expectedRevision == actualRevision else {
                throw SwanError.conflict(
                    expected: expectedRevision,
                    actual: actualRevision
                )
            }
            if let current, wireRevision <= current.wireRevision {
                throw SwanError.malformed(
                    "wire revision must advance"
                )
            }
            try await promotePermissionedBlobReferences(
                permissionedBlobCIDs.sorted(), space: space
            )

            var ltHash = try LtHash(
                serialized: current?.ltHash ?? Data(repeating: 0, count: LtHash.byteCount)
            )
            guard actualRevision < UInt64(Int.max) else {
                throw SQLiteRepositoryError.revisionOutOfRange(actualRevision)
            }
            let revision = actualRevision + 1
            let storedRevision = try sqliteRevision(revision)
            var entries: [PersistedSpaceOplogEntry] = []

            for (operationIndex, write) in writes.enumerated() {
                let uri = write.uri
                let old = try await loadRecord(uri)
                let action: PersistedRepoAction
                let previousCID = old?.cid
                let newCID: String? = switch write {
                case let .create(_, _, cid), let .put(_, _, cid), let .update(_, _, cid): cid
                case .delete: nil
                }

                switch write {
                case let .create(_, value, cid):
                    guard old == nil else {
                        throw SwanError.malformed("cannot create an existing record")
                    }
                    action = .create
                    ltHash.add(
                        element: "\(uri.collection)/\(uri.rkey)/\(cid)"
                    )
                    _ = try await connection.query(
                        """
                        INSERT INTO permissioned_space_records(
                            space_uri, author_did, collection, rkey,
                            value, cid, revision
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        [
                            .text(space.rawValue), .text(author),
                            .text(uri.collection), .text(uri.rkey),
                            blob(value), .text(cid), .integer(storedRevision),
                        ]
                    )
                case let .put(_, value, cid), let .update(_, value, cid):
                    if case .update = write, old == nil {
                        throw SwanError.malformed("cannot update a missing record")
                    }
                    action = old == nil ? .create : .update
                    if let old {
                        ltHash.remove(element: ltHashElement(for: old))
                    }
                    ltHash.add(
                        element: "\(uri.collection)/\(uri.rkey)/\(cid)"
                    )
                    _ = try await connection.query(
                        """
                        INSERT INTO permissioned_space_records(
                            space_uri, author_did, collection, rkey,
                            value, cid, revision
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(space_uri, author_did, collection, rkey)
                        DO UPDATE SET
                            value = excluded.value,
                            cid = excluded.cid,
                            revision = excluded.revision
                        """,
                        [
                            .text(space.rawValue), .text(author),
                            .text(uri.collection), .text(uri.rkey),
                            blob(value), .text(cid), .integer(storedRevision),
                        ]
                    )
                case .delete:
                    action = .delete
                    guard let old else {
                        throw SwanError.malformed("cannot delete a missing record")
                    }
                    ltHash.remove(element: ltHashElement(for: old))
                    _ = try await connection.query(
                        """
                        DELETE FROM permissioned_space_records
                        WHERE space_uri = ? AND author_did = ?
                          AND collection = ? AND rkey = ?
                        """,
                        [
                            .text(space.rawValue), .text(author),
                            .text(uri.collection), .text(uri.rkey),
                        ]
                    )
                }

                let commitment = ltHash.commitment
                try await insertOplog(
                    space: space,
                    author: author,
                    revision: storedRevision,
                    operationIndex: operationIndex,
                    wireRevision: wireRevision,
                    action: action,
                    previousCID: previousCID,
                    write: write,
                    commitment: commitment
                )
                entries.append(
                    PersistedSpaceOplogEntry(
                        cursor: PersistedOplogCursor(
                            revision: revision,
                            index: UInt64(operationIndex)
                        ),
                        wireRevision: wireRevision,
                        action: action,
                        write: write,
                        cid: newCID,
                        previousCID: previousCID,
                        commitment: commitment
                    )
                )
            }

            let storedFinalRevision = try sqliteRevision(revision)
            let marker = try repositoryStateMarker(
                space: space,
                author: author,
                revision: revision,
                wireRevision: wireRevision,
                commitment: ltHash.commitment
            )
            _ = try await connection.query(
                """
                INSERT INTO permissioned_repository_state(
                    space_uri, author_did, revision, wire_revision,
                    lthash, current_commit
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(space_uri, author_did) DO UPDATE SET
                    revision = excluded.revision,
                    wire_revision = excluded.wire_revision,
                    lthash = excluded.lthash,
                    current_commit = excluded.current_commit
                """,
                [
                    .text(space.rawValue), .text(author),
                    .integer(storedFinalRevision),
                    .text(wireRevision.toString()), blob(ltHash.serialized),
                    blob(marker),
                ]
            )

            let createdAt = Int(Date().timeIntervalSince1970 * 1_000_000)
            _ = try await connection.query(
                """
                INSERT INTO permissioned_space_requests(
                    request_id, space_uri, author_did,
                    base_revision, final_revision, event_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    .text(requestID.uuidString), .text(space.rawValue),
                    .text(author), .integer(try sqliteRevision(expectedRevision)),
                    .integer(storedFinalRevision), .text(eventID.uuidString),
                    .integer(createdAt),
                ]
            )

            let notificationPayload = opaqueNotificationPayload(eventID: eventID)
            _ = try await connection.query(
                """
                INSERT INTO permissioned_space_outbox(
                    id, space_uri, author_did, revision,
                    payload, attempts, created_at, available_at,
                    lease_token, lease_expires_at
                ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, NULL, NULL)
                """,
                [
                    .text(eventID.uuidString), .text(space.rawValue),
                    .text(author), .integer(storedFinalRevision),
                    blob(notificationPayload), .integer(createdAt),
                    .integer(createdAt),
                ]
            )

            try await testingHooks.beforeApplyCommit?()

            let cutoffRows = try await connection.query(
                """
                SELECT revision
                FROM permissioned_space_oplog
                WHERE space_uri = ? AND author_did = ?
                ORDER BY revision DESC, operation_index DESC
                LIMIT 1 OFFSET ?
                """,
                [
                    .text(space.rawValue), .text(author),
                    .integer(oplogRetention - 1),
                ]
            )
            if let cutoffRow = cutoffRows.first {
                let oldestRetainedRevision = try requiredRevision(
                    cutoffRow,
                    "revision"
                )
                _ = try await connection.query(
                    """
                    DELETE FROM permissioned_space_oplog
                    WHERE space_uri = ? AND author_did = ? AND revision < ?
                    """,
                    [
                        .text(space.rawValue), .text(author),
                        .integer(try sqliteRevision(oldestRetainedRevision)),
                    ]
                )
            }

            // The receipt ledger is a replay reservation, not the state guard:
            // the revision CAS above is what refuses a stale write, so a
            // request older than this window is answered as a conflict instead
            // of a duplicate. Retain it to the same depth as the oplog rather
            // than by age, so one retention knob governs both and neither
            // outlives the other. `created_at` orders the window; the final
            // revision breaks ties and orders unstamped pre-upgrade rows.
            let receiptCutoffRows = try await connection.query(
                """
                SELECT created_at, final_revision
                FROM permissioned_space_requests
                WHERE space_uri = ? AND author_did = ?
                ORDER BY created_at DESC, final_revision DESC
                LIMIT 1 OFFSET ?
                """,
                [
                    .text(space.rawValue), .text(author),
                    .integer(oplogRetention - 1),
                ]
            )
            if let receiptCutoffRow = receiptCutoffRows.first {
                let oldestRetainedStamp = try requiredNonnegativeInteger(
                    receiptCutoffRow,
                    "created_at"
                )
                let oldestRetainedReceipt = try requiredRevision(
                    receiptCutoffRow,
                    "final_revision"
                )
                _ = try await connection.query(
                    """
                    DELETE FROM permissioned_space_requests
                    WHERE space_uri = ? AND author_did = ?
                      AND (created_at < ?
                           OR (created_at = ? AND final_revision < ?))
                    """,
                    [
                        .text(space.rawValue), .text(author),
                        .integer(oldestRetainedStamp),
                        .integer(oldestRetainedStamp),
                        .integer(try sqliteRevision(oldestRetainedReceipt)),
                    ]
                )
            }

            let state = PersistedRepositoryState(
                space: space,
                author: author,
                revision: revision,
                wireRevision: wireRevision,
                ltHash: ltHash.serialized,
                commit: marker
            )
            let outbox = PersistedOutboxEvent(
                id: eventID,
                space: space,
                author: author,
                revision: revision,
                payload: notificationPayload,
                attempts: 0
            )
            return PersistedRepositoryCommit(
                state: state,
                entries: entries,
                outbox: outbox
            )
            }
        }
    }

    public func repositorySnapshot(
        space: SpaceURI,
        author: String
    ) async throws -> PersistedRepositorySnapshot? {
        try requireAccount(author)
        return try await withConnectionGate {
            try await readTransaction {
                try await requireLocalRepositorySpaceOpen(space)
                return try await repositorySnapshotWithoutTransaction(
                    space: space,
                    author: author
                )
            }
        }
    }

    /// Enumerates only locally reachable portable-export content under one
    /// SQLite read snapshot. Payload materialization and filesystem output are
    /// deliberately outside this transaction.
    public func portableExportInventory() async throws -> SQLitePortableExportInventory {
        try await withConnectionGate {
            try await readTransaction {
                let repositoryCountRows = try await connection.query(
                    "SELECT COUNT(*) AS row_count FROM permissioned_repository_state"
                )
                guard repositoryCountRows.count == 1,
                      case let .integer(repositoryCount) =
                          repositoryCountRows[0].column("row_count"),
                      (0 ... Self.maximumPortableExportRepositories)
                          .contains(repositoryCount) else {
                    throw SwanError.unavailable(
                        "portable export repository inventory exceeds its bound"
                    )
                }
                let repositoryRows = try await connection.query(
                    """
                    SELECT space_uri, author_did
                    FROM permissioned_repository_state
                    ORDER BY space_uri, author_did
                    """
                )
                let repositories = try repositoryRows.map { row in
                    let rawSpace = try requiredText(row, "space_uri")
                    let author = try requiredText(row, "author_did")
                    let space: SpaceURI
                    do {
                        space = try SpaceURI(rawSpace)
                    } catch {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "invalid portable export repository identity"
                        )
                    }
                    guard author == accountDID,
                          space.rawValue == rawSpace else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "invalid portable export repository owner"
                        )
                    }
                    return SQLitePortableExportInventory.Repository(
                        space: space,
                        author: author
                    )
                }

                let blobCountRows = try await connection.query(
                    """
                    SELECT COUNT(*) AS row_count
                    FROM blob_namespace_references AS reference
                    WHERE reference.namespace_kind = 'public'
                       OR EXISTS (
                           SELECT 1
                           FROM permissioned_repository_state AS repository
                           WHERE repository.space_uri = reference.space_uri
                             AND repository.author_did = ?
                       )
                    """,
                    [.text(accountDID)]
                )
                guard blobCountRows.count == 1,
                      case let .integer(blobCount) =
                          blobCountRows[0].column("row_count"),
                      (0 ... Self.maximumPortableExportBlobs).contains(blobCount) else {
                    throw SwanError.unavailable(
                        "portable export blob inventory exceeds its bound"
                    )
                }
                let blobRows = try await connection.query(
                    """
                    SELECT cid, namespace_kind, space_uri
                    FROM blob_namespace_references AS reference
                    WHERE reference.namespace_kind = 'public'
                       OR EXISTS (
                           SELECT 1
                           FROM permissioned_repository_state AS repository
                           WHERE repository.space_uri = reference.space_uri
                             AND repository.author_did = ?
                       )
                    ORDER BY namespace_kind, space_uri, cid
                    """,
                    [.text(accountDID)]
                )
                guard blobRows.count == blobCount else {
                    throw SwanError.unavailable(
                        "portable export blob inventory changed during snapshot"
                    )
                }
                let blobs = try blobRows.map { row in
                    let cid = try requiredText(row, "cid")
                    let kind = try requiredText(row, "namespace_kind")
                    let rawSpace = try requiredText(row, "space_uri")
                    let namespace: BlobNamespace
                    switch (kind, rawSpace.isEmpty) {
                    case ("public", true):
                        namespace = .public
                    case ("space", false):
                        do {
                            namespace = .space(try SpaceURI(rawSpace))
                        } catch {
                            throw SQLiteRepositoryError.corruptDatabase(
                                "invalid portable export blob namespace"
                            )
                        }
                    default:
                        throw SQLiteRepositoryError.corruptDatabase(
                            "invalid portable export blob namespace"
                        )
                    }
                    return BlobReference(cid: cid, namespace: namespace)
                }
                return SQLitePortableExportInventory(
                    repositories: repositories,
                    blobs: blobs
                )
            }
        }
    }

    /// Installs verified full-recovery snapshots into a brand-new account
    /// database without manufacturing oplog, outbox, authority, membership,
    /// or client-policy rows. Every installed repository is marked HTTP-closed
    /// until a later backup format can authenticate its authority policy.
    @_spi(PortableRestore)
    public func restorePortableRepositories(
        _ repositories: [SQLitePortableRestoreRepository]
    ) async throws {
        let ordered = repositories.sorted {
            ($0.space.rawValue, $0.author) < ($1.space.rawValue, $1.author)
        }
        guard ordered == repositories,
              Set(ordered.map { "\($0.space.rawValue)\u{0}\($0.author)" }).count
                == ordered.count else {
            throw SQLiteRepositoryError.corruptDatabase(
                "portable restore repository inventory is invalid"
            )
        }
        for repository in ordered {
            try validatePortableRestoreRepository(repository)
        }

        try await withConnectionGate {
            try await transaction {
                for table in [
                    "permissioned_repository_state",
                    "permissioned_space_records",
                    "permissioned_space_oplog",
                    "permissioned_space_requests",
                    "permissioned_space_outbox",
                    "permissioned_restored_repository_closures",
                ] {
                    let rows = try await connection.query(
                        "SELECT 1 FROM \(table) LIMIT 1"
                    )
                    guard rows.isEmpty else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "portable restore target is not empty"
                        )
                    }
                }

                for repository in ordered {
                    try Task.checkCancellation()
                    for record in repository.records {
                        _ = try await connection.query(
                            """
                            INSERT INTO permissioned_space_records(
                                space_uri, author_did, collection, rkey,
                                value, cid, revision
                            ) VALUES (?, ?, ?, ?, ?, ?, 1)
                            """,
                            [
                                .text(repository.space.rawValue),
                                .text(repository.author),
                                .text(record.uri.collection),
                                .text(record.uri.rkey),
                                blob(record.value),
                                .text(record.cid),
                            ]
                        )
                    }
                    let marker = try repositoryStateMarker(
                        space: repository.space,
                        author: repository.author,
                        revision: 1,
                        wireRevision: repository.wireRevision,
                        commitment: repository.commitment
                    )
                    _ = try await connection.query(
                        """
                        INSERT INTO permissioned_repository_state(
                            space_uri, author_did, revision, wire_revision,
                            lthash, current_commit
                        ) VALUES (?, ?, 1, ?, ?, ?)
                        """,
                        [
                            .text(repository.space.rawValue),
                            .text(repository.author),
                            .text(repository.wireRevision.toString()),
                            blob(repository.ltHash),
                            blob(marker),
                        ]
                    )
                    _ = try await connection.query(
                        """
                        INSERT INTO permissioned_restored_repository_closures(
                            space_uri, author_did, reason
                        ) VALUES (?, ?, 'missing-authority-policy-v1')
                        """,
                        [
                            .text(repository.space.rawValue),
                            .text(repository.author),
                        ]
                    )
                }
            }
        }
    }

    /// Installs one already-stream-verified permissioned repository while
    /// retaining at most a single record value. The scratch actor is local
    /// descriptor-backed SQLite; no network operation occurs in this
    /// transaction.
    @_spi(PortableRestore)
    public func restorePortableRepositoryStreaming(
        _ repository: SQLitePortableRestoreRepositoryMetadata,
        staging: SQLiteSpaceCARRecoveryIndex
    ) async throws {
        try requireAccount(repository.author)
        guard repository.recordCount >= 0,
              (0 ... SpaceCARRecoveryLimits.absoluteMaximumLogicalRestoredBytes)
              .contains(repository.logicalRestoredByteCount),
              repository.ltHash.count == LtHash.byteCount,
              repository.commitment
              == Data(SHA256.hash(data: repository.ltHash))
        else {
            throw SQLiteRepositoryError.corruptDatabase(
                "portable restore repository state is invalid"
            )
        }
        try await withConnectionGate {
            try await transaction {
                let existing = try await connection.query(
                    """
                    SELECT 1 FROM permissioned_repository_state
                    WHERE space_uri = ? AND author_did = ?
                    LIMIT 1
                    """,
                    [.text(repository.space.rawValue), .text(repository.author)]
                )
                guard existing.isEmpty else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "portable restore repository inventory is invalid"
                    )
                }
                var cursor: String?
                var installedCount = 0
                var installedLogicalByteCount = 0
                var calculatedLtHash = LtHash()
                while let staged = try await staging.nextStagedRecord(
                    afterPath: cursor
                ) {
                    try Task.checkCancellation()
                    let components = staged.path.split(
                        separator: "/",
                        omittingEmptySubsequences: false
                    ).map(String.init)
                    guard components.count == 2 else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "portable restore record path is invalid"
                        )
                    }
                    let uri = try SpaceRecordURI(
                        space: repository.space,
                        author: repository.author,
                        collection: components[0],
                        rkey: components[1]
                    )
                    try SpaceCARCodec.validateCanonicalRecord(
                        staged.value,
                        expectedCID: staged.cid.string
                    )
                    let (nextInstalledLogicalByteCount, overflow) =
                        installedLogicalByteCount.addingReportingOverflow(
                            staged.value.count
                        )
                    guard !overflow,
                          nextInstalledLogicalByteCount
                          <= repository.logicalRestoredByteCount,
                          nextInstalledLogicalByteCount
                          <= SpaceCARRecoveryLimits
                          .absoluteMaximumLogicalRestoredBytes
                    else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "portable restore logical byte budget is invalid"
                        )
                    }
                    _ = try await connection.query(
                        """
                        INSERT INTO permissioned_space_records(
                            space_uri, author_did, collection, rkey,
                            value, cid, revision
                        ) VALUES (?, ?, ?, ?, ?, ?, 1)
                        """,
                        [
                            .text(repository.space.rawValue),
                            .text(repository.author),
                            .text(uri.collection), .text(uri.rkey),
                            blob(staged.value), .text(staged.cid.string),
                        ]
                    )
                    calculatedLtHash.add(
                        element:
                        "\(uri.collection)/\(uri.rkey)/\(staged.cid.string)"
                    )
                    installedCount += 1
                    installedLogicalByteCount = nextInstalledLogicalByteCount
                    cursor = staged.path
                }
                guard installedCount == repository.recordCount,
                      installedLogicalByteCount
                      == repository.logicalRestoredByteCount,
                      calculatedLtHash.serialized == repository.ltHash,
                      calculatedLtHash.commitment == repository.commitment
                else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "portable restore repository state is invalid"
                    )
                }
                let marker = try repositoryStateMarker(
                    space: repository.space,
                    author: repository.author,
                    revision: 1,
                    wireRevision: repository.wireRevision,
                    commitment: repository.commitment
                )
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_repository_state(
                        space_uri, author_did, revision, wire_revision,
                        lthash, current_commit
                    ) VALUES (?, ?, 1, ?, ?, ?)
                    """,
                    [
                        .text(repository.space.rawValue),
                        .text(repository.author),
                        .text(repository.wireRevision.toString()),
                        blob(repository.ltHash), blob(marker),
                    ]
                )
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_restored_repository_closures(
                        space_uri, author_did, reason
                    ) VALUES (?, ?, 'missing-authority-policy-v1')
                    """,
                    [.text(repository.space.rawValue), .text(repository.author)]
                )
            }
        }
    }

    /// Reopens and revalidates the offline restore inventory while
    /// intentionally bypassing only the V1 HTTP-closure marker.
    @_spi(PortableRestore)
    public func validatePortableRestore(
        repositories expected: [SQLitePortableRestoreRepository]
    ) async throws {
        for repository in expected {
            try validatePortableRestoreRepository(repository)
        }
        try await withConnectionGate {
            try await readTransaction {
                let states = try await connection.query(
                    """
                    SELECT space_uri, author_did
                    FROM permissioned_repository_state
                    ORDER BY space_uri, author_did
                    """
                )
                guard states.count == expected.count else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "portable restore repository inventory is invalid"
                    )
                }
                for (row, repository) in zip(states, expected) {
                    guard try requiredText(row, "space_uri")
                            == repository.space.rawValue,
                          try requiredText(row, "author_did")
                            == repository.author else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "portable restore repository inventory is invalid"
                        )
                    }
                }
                let rows = try await connection.query(
                    """
                    SELECT space_uri, author_did, reason
                    FROM permissioned_restored_repository_closures
                    ORDER BY space_uri, author_did
                    """
                )
                guard rows.count == expected.count else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "portable restore closure inventory is invalid"
                    )
                }
                for (row, repository) in zip(rows, expected) {
                    guard try requiredText(row, "space_uri") == repository.space.rawValue,
                          try requiredText(row, "author_did") == repository.author,
                          try requiredText(row, "reason") == "missing-authority-policy-v1",
                          let snapshot = try await repositorySnapshotWithoutTransaction(
                              space: repository.space,
                              author: repository.author
                          ),
                          snapshot.state.revision == 1,
                          snapshot.state.wireRevision == repository.wireRevision,
                          snapshot.state.ltHash == repository.ltHash,
                          snapshot.state.commitment == repository.commitment,
                          snapshot.records.map(\.uri) == repository.records.map(\.uri),
                          snapshot.records.map(\.value) == repository.records.map(\.value),
                          snapshot.records.map(\.cid) == repository.records.map(\.cid),
                          snapshot.records.allSatisfy({ $0.revision == 1 }) else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "portable restore repository validation failed"
                        )
                    }
                }
                for table in [
                    "permissioned_space_oplog",
                    "permissioned_space_requests",
                    "permissioned_space_outbox",
                    "permissioned_simple_space_authorities",
                    "permissioned_simple_space_members",
                    "permissioned_simple_space_clients",
                    "permissioned_simple_space_managing_app_decisions",
                    "permissioned_space_writers",
                    "permissioned_space_notification_registrations",
                ] {
                    let unexpected = try await connection.query(
                        "SELECT 1 FROM \(table) LIMIT 1"
                    )
                    guard unexpected.isEmpty else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "portable restore fabricated policy or delivery state"
                        )
                    }
                }
            }
        }
    }

    @_spi(PortableRestore)
    public func validatePortableRestoreStreaming(
        repositories expected: [SQLitePortableRestoreRepositoryMetadata]
    ) async throws {
        let ordered = expected.sorted {
            ($0.space.rawValue, $0.author) < ($1.space.rawValue, $1.author)
        }
        guard ordered == expected,
              Set(ordered.map { "\($0.space.rawValue)\u{0}\($0.author)" }).count
                == ordered.count else {
            throw SQLiteRepositoryError.corruptDatabase(
                "portable restore repository inventory is invalid"
            )
        }
        try await withConnectionGate {
            try await readTransaction {
                for repository in ordered {
                    try Task.checkCancellation()
                    guard repository.recordCount >= 0,
                          (0 ... SpaceCARRecoveryLimits
                            .absoluteMaximumLogicalRestoredBytes)
                            .contains(repository.logicalRestoredByteCount),
                          repository.ltHash.count == LtHash.byteCount,
                          repository.commitment
                            == Data(SHA256.hash(data: repository.ltHash))
                    else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "portable restore repository validation failed"
                        )
                    }
                    guard let state = try await loadState(
                        space: repository.space,
                        author: repository.author
                    ),
                        state.revision == 1,
                        state.wireRevision == repository.wireRevision,
                        state.ltHash == repository.ltHash,
                        state.commitment == repository.commitment
                    else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "portable restore repository validation failed"
                        )
                    }
                    var cursorCollection: String?
                    var cursorRKey: String?
                    var count = 0
                    var logicalRestoredByteCount = 0
                    var ltHash = LtHash()
                    while true {
                        try Task.checkCancellation()
                        let rows: [SQLiteRow]
                        if let cursorCollection, let cursorRKey {
                            rows = try await connection.query(
                                """
                                SELECT collection, rkey, cid,
                                       length(value) AS value_byte_count
                                FROM permissioned_space_records
                                WHERE space_uri = ? AND author_did = ?
                                  AND (collection > ? OR (collection = ? AND rkey > ?))
                                ORDER BY collection, rkey
                                LIMIT 256
                                """,
                                [
                                    .text(repository.space.rawValue),
                                    .text(repository.author),
                                    .text(cursorCollection),
                                    .text(cursorCollection), .text(cursorRKey),
                                ]
                            )
                        } else {
                            rows = try await connection.query(
                                """
                                SELECT collection, rkey, cid,
                                       length(value) AS value_byte_count
                                FROM permissioned_space_records
                                WHERE space_uri = ? AND author_did = ?
                                ORDER BY collection, rkey
                                LIMIT 256
                                """,
                                [
                                    .text(repository.space.rawValue),
                                    .text(repository.author),
                                ]
                            )
                        }
                        guard !rows.isEmpty else { break }
                        for row in rows {
                            try Task.checkCancellation()
                            let collection = try requiredText(row, "collection")
                            let rkey = try requiredText(row, "rkey")
                            let cid = try requiredText(row, "cid")
                            let valueByteCount = try requiredNonnegativeInteger(
                                row,
                                "value_byte_count"
                            )
                            guard valueByteCount
                                    <= SpaceCARRecoveryLimits
                                        .absoluteMaximumRecordBytes
                            else {
                                throw SQLiteRepositoryError.corruptDatabase(
                                    "portable restore repository validation failed"
                                )
                            }
                            _ = try SpaceRecordURI(
                                space: repository.space,
                                author: repository.author,
                                collection: collection,
                                rkey: rkey
                            )
                            let valueRows = try await connection.query(
                                """
                                SELECT value
                                FROM permissioned_space_records
                                WHERE space_uri = ? AND author_did = ?
                                  AND collection = ? AND rkey = ?
                                  AND length(value) = ?
                                  AND length(value) <= ?
                                LIMIT 1
                                """,
                                [
                                    .text(repository.space.rawValue),
                                    .text(repository.author),
                                    .text(collection), .text(rkey),
                                    .integer(valueByteCount),
                                    .integer(
                                        SpaceCARRecoveryLimits
                                            .absoluteMaximumRecordBytes
                                    ),
                                ]
                            )
                            guard valueRows.count == 1,
                                  let valueRow = valueRows.first else {
                                throw SQLiteRepositoryError.corruptDatabase(
                                    "portable restore repository validation failed"
                                )
                            }
                            let value = try requiredBlob(valueRow, "value")
                            guard value.count == valueByteCount else {
                                throw SQLiteRepositoryError.corruptDatabase(
                                    "portable restore repository validation failed"
                                )
                            }
                            do {
                                try SpaceCARCodec.validateCanonicalRecord(
                                    value,
                                    expectedCID: cid
                                )
                            } catch {
                                throw SQLiteRepositoryError.corruptDatabase(
                                    "portable restore repository validation failed"
                                )
                            }
                            let (nextLogicalRestoredByteCount, overflow) =
                                logicalRestoredByteCount.addingReportingOverflow(
                                    value.count
                                )
                            guard !overflow,
                                  nextLogicalRestoredByteCount
                                    <= repository.logicalRestoredByteCount,
                                  nextLogicalRestoredByteCount
                                    <= SpaceCARRecoveryLimits
                                        .absoluteMaximumLogicalRestoredBytes
                            else {
                                throw SQLiteRepositoryError.corruptDatabase(
                                    "portable restore repository validation failed"
                                )
                            }
                            ltHash.add(element: "\(collection)/\(rkey)/\(cid)")
                            count += 1
                            logicalRestoredByteCount =
                                nextLogicalRestoredByteCount
                            cursorCollection = collection
                            cursorRKey = rkey
                        }
                    }
                    guard count == repository.recordCount,
                          logicalRestoredByteCount
                            == repository.logicalRestoredByteCount,
                          ltHash.serialized == repository.ltHash,
                          ltHash.commitment == repository.commitment
                    else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "portable restore repository validation failed"
                        )
                    }
                }
                let closures = try await connection.query(
                    """
                    SELECT space_uri, author_did, reason
                    FROM permissioned_restored_repository_closures
                    ORDER BY space_uri, author_did
                    """
                )
                guard closures.count == ordered.count else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "portable restore closure inventory is invalid"
                    )
                }
                for (row, repository) in zip(closures, ordered) {
                    guard try requiredText(row, "space_uri")
                        == repository.space.rawValue,
                        try requiredText(row, "author_did")
                        == repository.author,
                        try requiredText(row, "reason")
                        == "missing-authority-policy-v1"
                    else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "portable restore closure inventory is invalid"
                        )
                    }
                }
                for table in [
                    "permissioned_space_oplog",
                    "permissioned_space_requests",
                    "permissioned_space_outbox",
                    "permissioned_simple_space_authorities",
                    "permissioned_simple_space_members",
                    "permissioned_simple_space_clients",
                    "permissioned_simple_space_managing_app_decisions",
                    "permissioned_space_writers",
                    "permissioned_space_notification_registrations",
                ] {
                    let unexpected = try await connection.query(
                        "SELECT 1 FROM \(table) LIMIT 1"
                    )
                    guard unexpected.isEmpty else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "portable restore fabricated policy or delivery state"
                        )
                    }
                }
            }
        }
    }

    /// Restores one verified blob under its manifest-selected namespace while
    /// preserving either a current raw CID or the alpha's legacy sha256 label.
    @_spi(PortableRestore)
    public func restorePortableBlob(
        _ data: Data,
        expectedCID: String,
        namespace: BlobNamespace
    ) async throws -> BlobReference {
        let computedRawCID = CID.fromBlob(data).string
        if expectedCID.hasPrefix("sha256:") {
            guard expectedCID
                == "sha256:\(Hex.encode(SHA256.hash(data: data)))" else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "portable restore blob CID is invalid"
                )
            }
        } else {
            guard expectedCID == computedRawCID else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "portable restore blob CID is invalid"
                )
            }
        }
        let digestHex = try blobDigestHex(cid: expectedCID, allowLegacy: true)
        let byteCount = try blobByteCount(data.count)
        let columns = blobNamespaceColumns(namespace)
        let restoreRepositorySpace: SpaceURI?
        switch namespace {
        case .public:
            restoreRepositorySpace = nil
        case let .space(space):
            restoreRepositorySpace = space
        case .staged:
            // A portable export never contains a staged edge, so a manifest
            // that claims one is not a Swan export.
            throw SQLiteRepositoryError.corruptDatabase(
                "portable restore blob namespace is invalid"
            )
        }
        return try await withPrivateBlobLifecycleLock(digestHex: digestHex) {
            try await putBlobLocked(
                .memory(data),
                cid: expectedCID,
                digestHex: digestHex,
                byteCount: byteCount,
                namespace: namespace,
                namespaceKind: columns.kind,
                spaceURI: columns.spaceURI,
                mimeType: nil,
                restoreRepositorySpace: restoreRepositorySpace
            )
        }
    }

    @_spi(PortableRestore)
    public func restorePortableBlobStreaming(
        expectedCID: String,
        expectedByteCount: Int,
        namespace: BlobNamespace,
        source: @escaping @Sendable (
            @escaping (Data) async throws -> Void
        ) async throws -> Void
    ) async throws -> BlobReference {
        guard expectedByteCount >= 0,
              expectedByteCount <= 512 * 1024 * 1024
        else {
            throw SQLiteRepositoryError.corruptDatabase(
                "portable restore blob length is invalid"
            )
        }
        let spoolHandle = try SQLiteProtectedPaths
            .makeUnlinkedPortableRestoreBlobSpool(
                accountDirectoryDescriptor: accountDirectoryDescriptor
            )
        let spool = SQLiteBlobUploadSpool(
            handle: spoolHandle,
            maximumBytes: max(expectedByteCount, 1)
        )
        defer { spool.close() }
        let sink: (Data) async throws -> Void = { chunk in
            try Task.checkCancellation()
            try spool.append(chunk)
        }
        try await source(sink)
        let summary = try spool.finish()
        guard summary.byteCount == expectedByteCount else {
            throw SQLiteRepositoryError.corruptDatabase(
                "portable restore blob length is invalid"
            )
        }
        let digestHex = Hex.encode(summary.digest)
        let rawCID = CID(
            codec: .raw,
            multihash: Multihash(
                algorithm: Multihash.sha256Code,
                length: Multihash.sha256Length,
                digest: summary.digest
            )
        ).string
        guard expectedCID == rawCID
            || expectedCID == "sha256:\(digestHex)"
        else {
            throw SQLiteRepositoryError.corruptDatabase(
                "portable restore blob CID is invalid"
            )
        }
        let columns = blobNamespaceColumns(namespace)
        let restoreRepositorySpace: SpaceURI?
        switch namespace {
        case .public: restoreRepositorySpace = nil
        case let .space(space): restoreRepositorySpace = space
        case .staged:
            throw SQLiteRepositoryError.corruptDatabase(
                "portable restore blob namespace is invalid"
            )
        }
        try Task.checkCancellation()
        return try await withPrivateBlobLifecycleLock(digestHex: digestHex) {
            try await putBlobLocked(
                .file(
                    descriptor: spool.fileDescriptor,
                    length: summary.byteCount,
                    digest: summary.digest
                ),
                cid: expectedCID,
                digestHex: digestHex,
                byteCount: summary.byteCount,
                namespace: namespace,
                namespaceKind: columns.kind,
                spaceURI: columns.spaceURI,
                mimeType: nil,
                restoreRepositorySpace: restoreRepositorySpace
            )
        }
    }

    @_spi(PortableRestore)
    public func validatePortableBlob(
        _ reference: BlobReference,
        expectedByteCount: Int
    ) async throws {
        let columns = blobNamespaceColumns(reference.namespace)
        let stored = try await blobPayload(
            cid: reference.cid,
            namespaceKind: columns.kind,
            spaceURI: columns.spaceURI,
            includeLegacyPayload: false
        )
        guard stored.storageKind == .casV1,
              stored.byteCount == expectedByteCount,
              let digestHex = stored.casDigest
        else {
            throw SQLiteRepositoryError.corruptDatabase(
                "portable restore blob validation failed"
            )
        }
        try verifyPrivateBlobFile(
            digestHex: digestHex,
            expectedLength: expectedByteCount
        )
    }

    /// Builds a private, bounded-memory CAR suffix from one SQLite read
    /// snapshot. The spool contains only the validated DRISL index and record
    /// blocks: a reader-specific signed commit is intentionally created later
    /// by the OAuth/account-key layer and never reaches disk here.
    ///
    /// The read transaction is held only while SQLite is read and private
    /// files are written. It is released before Hummingbird can write a byte
    /// to a client, so a slow/disconnected client cannot hold a database
    /// transaction open.
    public func prepareRepositoryCARSnapshot(
        space: SpaceURI,
        author: String
    ) async throws -> AuthorizedSpaceRepositoryCARSnapshot? {
        try requireAccount(author)
        guard let lease = sqlitePermissionedCARSpoolAdmission?.reserve(
            accountDID: author,
            maximumBytes: SpaceCARProductionLimits.maximumWorkingSpoolBytes
        ) else {
            throw SpaceCARProductionLimits.limitExceeded()
        }
        var transferredLease = false
        defer {
            if !transferredLease {
                lease.release()
            }
        }
        let prepared = try await withConnectionGate {
            try await withRepositoryCARIndexTable {
                try await readTransaction {
                    try Task.checkCancellation()
                    try await requireLocalRepositorySpaceOpen(space)
                    return try await prepareRepositoryCARSnapshotWithoutTransaction(
                        space: space,
                        author: author,
                        lease: lease
                    )
                }
            }
        }
        if prepared != nil {
            transferredLease = true
        }
        return prepared
    }

    private func prepareRepositoryCARSnapshotWithoutTransaction(
        space: SpaceURI,
        author: String,
        lease: SpaceCARSpoolLease
    ) async throws -> AuthorizedSpaceRepositoryCARSnapshot? {
        guard let state = try await loadState(space: space, author: author) else {
            return nil
        }
        try Task.checkCancellation()
        let recordCount = try await requireRepositoryCARProductionAdmission(
            space: space,
            author: author
        )
        try Task.checkCancellation()
        let bodyHandle = try SQLiteProtectedPaths.makeUnlinkedPermissionedCARSpool(
            in: dataDirectory
        )
        var transferredBodyHandle = false
        defer {
            if !transferredBodyHandle {
                try? bodyHandle.close()
            }
        }
        try await populateRepositoryCARIndex(space: space, author: author)
        try Task.checkCancellation()
        guard try await repositoryCARIndexRecordCount() == recordCount else {
            throw SQLiteRepositoryError.corruptDatabase(
                "permissioned CAR record count changed during snapshot"
            )
        }
        try Task.checkCancellation()
        // Shared with the ordinary snapshot test hook so the CAR path proves
        // it remains one stable read transaction even while another WAL
        // connection commits a newer revision. The metadata projection is
        // already populated so tests can also inspect the connection-local
        // keyset plan at this stable-snapshot boundary.
        await testingHooks.afterSnapshotStateRead?()
        try Task.checkCancellation()
        let indexHandle =
            try SQLiteProtectedPaths.makeUnlinkedPermissionedCARSpool(
                in: dataDirectory
            )
        var indexClosed = false
        defer {
            if !indexClosed { try? indexHandle.close() }
        }

        var indexHash = SHA256()
        let indexPrefix = try SpaceCARCodec.streamingIndexPrefix(recordCount: recordCount)
        try writeCARSpoolData(indexPrefix, to: indexHandle)
        indexHash.update(data: indexPrefix)
        var indexSize = indexPrefix.count

        var calculatedLtHash = LtHash()
        var canonicalCursor: (length: Int, pathBytes: Data)?
        var indexedCount = 0
        while true {
            try Task.checkCancellation()
            guard let record = try await nextRepositoryCARIndexRecord(
                space: space,
                author: author,
                after: canonicalCursor
            ) else {
                break
            }
            let path = "\(record.uri.collection)/\(record.uri.rkey)"
            let pathBytes = Data(path.utf8)
            let length = pathBytes.count
            if let cursor = canonicalCursor,
               length < cursor.length
                || (
                    length == cursor.length
                        && !cursor.pathBytes.lexicographicallyPrecedes(pathBytes)
                )
            {
                throw SQLiteRepositoryError.corruptDatabase("permissioned CAR index order is invalid")
            }
            let cid = try repositoryCARCID(for: record)
            let entry = try SpaceCARCodec.streamingIndexEntry(path: path, cid: cid)
            let (nextIndexSize, indexSizeOverflow) =
                indexSize.addingReportingOverflow(entry.count)
            guard !indexSizeOverflow,
                  nextIndexSize
                    <= SpaceCARProductionLimits.maximumLogicalMetadataBytes
            else {
                throw SpaceCARProductionLimits.limitExceeded()
            }
            indexSize = nextIndexSize
            try writeCARSpoolData(entry, to: indexHandle)
            indexHash.update(data: entry)
            calculatedLtHash.add(element: "\(path)/\(cid.string)")
            canonicalCursor = (length, pathBytes)
            indexedCount += 1
        }
        guard indexedCount == recordCount,
              calculatedLtHash.commitment == state.commitment
        else {
            throw SQLiteRepositoryError.corruptDatabase("permissioned CAR snapshot does not match repository state")
        }

        let indexCID = CID(
            codec: .dagCBOR,
            multihash: .init(
                algorithm: Multihash.sha256Code,
                length: Multihash.sha256Length,
                digest: Data(indexHash.finalize())
            )
        )

        var bodyByteCount = 0
        let indexBlockPrefix = try SpaceCARCodec.streamingBlockPrefix(
            cid: indexCID,
            dataLength: indexSize
        )
        try reserveRepositoryCARBodyBytes(
            indexBlockPrefix.count,
            currentByteCount: &bodyByteCount
        )
        try reserveRepositoryCARBodyBytes(
            indexSize,
            currentByteCount: &bodyByteCount
        )
        try writeCARSpoolData(indexBlockPrefix, to: bodyHandle)
        try copyCARSpoolFile(indexHandle, to: bodyHandle)
        try indexHandle.close()
        indexClosed = true

        var lexicalCursor: (collection: String, rkey: String)?
        var visitedCount = 0
        while true {
            try Task.checkCancellation()
            guard let selected = try await nextRepositoryCARRecord(
                space: space,
                author: author,
                after: lexicalCursor
            ) else {
                break
            }
            let record = selected.record
            if let cursor = lexicalCursor,
               record.uri.collection < cursor.collection ||
               (record.uri.collection == cursor.collection && record.uri.rkey <= cursor.rkey) {
                throw SQLiteRepositoryError.corruptDatabase("permissioned CAR record order is invalid")
            }
            let cid = try repositoryCARCID(for: record)
            if selected.shouldEmit {
                guard record.valueByteCount
                    <= SpaceCARProductionLimits.maximumRecordBytes
                else {
                    throw SpaceCARProductionLimits.limitExceeded()
                }
                let blockPrefix = try SpaceCARCodec.streamingBlockPrefix(
                    cid: cid,
                    dataLength: record.valueByteCount
                )
                let (blockByteCount, overflow) = blockPrefix.count
                    .addingReportingOverflow(record.valueByteCount)
                guard !overflow else {
                    throw SpaceCARProductionLimits.limitExceeded()
                }
                try reserveRepositoryCARBodyBytes(
                    blockByteCount,
                    currentByteCount: &bodyByteCount
                )
                try writeCARSpoolData(blockPrefix, to: bodyHandle)
                try await streamAndValidateRepositoryCARValue(
                    for: record,
                    expectedCID: cid,
                    to: bodyHandle
                )
                try await markRepositoryCARCIDEmitted(cid.string)
            } else {
                // A shared CID still requires validating every persisted value.
                // Otherwise a corrupt duplicate row could be hidden behind the
                // one canonical CAR block emitted for an earlier path.
                try await streamAndValidateRepositoryCARValue(
                    for: record,
                    expectedCID: cid,
                    to: nil
                )
            }
            lexicalCursor = (record.uri.collection, record.uri.rkey)
            visitedCount += 1
        }
        guard visitedCount == recordCount else {
            throw SQLiteRepositoryError.corruptDatabase("permissioned CAR record count changed during snapshot")
        }
        try bodyHandle.synchronize()
        try Task.checkCancellation()
        try bodyHandle.seek(toOffset: 0)

        let prepared = AuthorizedSpaceRepositoryCARSnapshot(
            state: AuthorizedSpaceRepositoryCommitState(
                space: state.space,
                author: state.author,
                wireRevision: state.wireRevision.toString(),
                commitment: state.commitment
            ),
            spool: try SpaceCARBodySpool(
                indexCID: indexCID,
                fileHandle: bodyHandle,
                bodyByteCount: bodyByteCount,
                lease: lease
            )
        )
        transferredBodyHandle = true
        return prepared
    }

    /// Rejects adversarial path cardinality, TEMP projection amplification,
    /// and incompatible record bodies before creating either CAR payload
    /// spool. This runs inside the same read snapshot as subsequent encoding.
    private func requireRepositoryCARProductionAdmission(
        space: SpaceURI,
        author: String
    ) async throws -> Int {
        let countRows = try await connection.query(
            """
            SELECT COUNT(*) AS record_count
            FROM permissioned_space_records
            WHERE space_uri = ? AND author_did = ?
            """,
            [.text(space.rawValue), .text(author)]
        )
        guard let countRow = countRows.first else {
            throw SQLiteRepositoryError.corruptDatabase(
                "permissioned CAR count is unavailable"
            )
        }
        let count = try requiredRevision(countRow, "record_count")
        guard count <= UInt64(SpaceCARProductionLimits.maximumRecordCount) else {
            throw SpaceCARProductionLimits.limitExceeded()
        }

        let admissionRows = try await connection.query(
            """
            SELECT
              COALESCE(
                SUM(
                  2 * length(CAST(collection || '/' || rkey AS BLOB))
                  + length(CAST(cid AS BLOB))
                  + 64
                ),
                0
              ) AS logical_metadata_bytes,
              COALESCE(MAX(length(value)), 0) AS maximum_record_bytes
            FROM permissioned_space_records
            WHERE space_uri = ? AND author_did = ?
            """,
            [.text(space.rawValue), .text(author)]
        )
        guard let admission = admissionRows.first,
              let logicalMetadataBytes = admission
                .column("logical_metadata_bytes")?.integer,
              let maximumRecordBytes = admission
                .column("maximum_record_bytes")?.integer,
              logicalMetadataBytes >= 0,
              maximumRecordBytes >= 0,
              logicalMetadataBytes
                <= SpaceCARProductionLimits.maximumLogicalMetadataBytes,
              maximumRecordBytes
                <= SpaceCARProductionLimits.maximumRecordBytes
        else {
            throw SpaceCARProductionLimits.limitExceeded()
        }
        return Int(count)
    }

    /// Materializes only canonical path metadata. Record values stay in the
    /// repository table and are fetched one at a time through its full primary
    /// key after the metadata keyset selects the next path.
    private func populateRepositoryCARIndex(
        space: SpaceURI,
        author: String
    ) async throws {
        _ = try await connection.query(
            """
            INSERT INTO temp.swan_repository_car_index(
                path_length, path_bytes, collection, rkey, cid, emitted
            )
            SELECT length(CAST(collection || '/' || rkey AS BLOB)),
                   CAST(collection || '/' || rkey AS BLOB),
                   collection,
                   rkey,
                   cid,
                   0
            FROM permissioned_space_records
            WHERE space_uri = ? AND author_did = ?
            """,
            [.text(space.rawValue), .text(author)]
        )
    }

    private func repositoryCARIndexRecordCount() async throws -> Int {
        let rows = try await connection.query(
            """
            SELECT COUNT(*) AS record_count
            FROM temp.swan_repository_car_index
            """
        )
        guard let row = rows.first else {
            throw SQLiteRepositoryError.corruptDatabase("permissioned CAR count is unavailable")
        }
        let count = try requiredRevision(row, "record_count")
        guard count <= UInt64(Int.max) else {
            throw SQLiteRepositoryError.corruptDatabase("permissioned CAR record count is invalid")
        }
        return Int(count)
    }

    /// Fetches one row at a time rather than retaining an array of repository
    /// values. Canonical DAG-CBOR map order is length then UTF-8 bytes.
    private func nextRepositoryCARIndexRecord(
        space: SpaceURI,
        author: String,
        after cursor: (length: Int, pathBytes: Data)?
    ) async throws -> RepositoryCARRecordMetadata? {
        let rows: [SQLiteRow]
        if let cursor {
            rows = try await connection.query(
                """
                SELECT records.collection, records.rkey,
                       records.cid, records.revision,
                       length(records.value) AS value_byte_count
                FROM temp.swan_repository_car_index AS metadata
                JOIN permissioned_space_records AS records
                  ON records.space_uri = ?
                 AND records.author_did = ?
                 AND records.collection = metadata.collection
                 AND records.rkey = metadata.rkey
                WHERE (metadata.path_length, metadata.path_bytes) > (?, ?)
                ORDER BY metadata.path_length, metadata.path_bytes
                LIMIT 1
                """,
                [
                    .text(space.rawValue), .text(author),
                    .integer(cursor.length), cursor.pathBytes.sqliteData!,
                ]
            )
        } else {
            rows = try await connection.query(
                """
                SELECT records.collection, records.rkey,
                       records.cid, records.revision,
                       length(records.value) AS value_byte_count
                FROM temp.swan_repository_car_index AS metadata
                JOIN permissioned_space_records AS records
                  ON records.space_uri = ?
                 AND records.author_did = ?
                 AND records.collection = metadata.collection
                 AND records.rkey = metadata.rkey
                ORDER BY metadata.path_length, metadata.path_bytes
                LIMIT 1
                """,
                [.text(space.rawValue), .text(author)]
            )
        }
        guard let row = rows.first else { return nil }
        return try decodeRepositoryCARRecordMetadata(
            row,
            space: space,
            author: author
        )
    }

    /// The proposal requires record blocks to follow lexicographic
    /// `collection/rkey` order, which is intentionally distinct from the
    /// canonical map-key order used for the DRISL index.
    private func nextRepositoryCARRecord(
        space: SpaceURI,
        author: String,
        after cursor: (collection: String, rkey: String)?
    ) async throws -> (
        record: RepositoryCARRecordMetadata,
        shouldEmit: Bool
    )? {
        let rows: [SQLiteRow]
        if let cursor {
            rows = try await connection.query(
                """
                SELECT records.collection, records.rkey,
                       records.cid, records.revision,
                       length(records.value) AS value_byte_count,
                       metadata.emitted AS car_cid_emitted
                FROM permissioned_space_records AS records
                JOIN temp.swan_repository_car_index AS metadata
                  ON metadata.collection = records.collection
                 AND metadata.rkey = records.rkey
                 AND metadata.cid = records.cid
                WHERE records.space_uri = ? AND records.author_did = ?
                  AND (records.collection, records.rkey) > (?, ?)
                ORDER BY records.collection, records.rkey
                LIMIT 1
                """,
                [
                    .text(space.rawValue), .text(author),
                    .text(cursor.collection), .text(cursor.rkey),
                ]
            )
        } else {
            rows = try await connection.query(
                """
                SELECT records.collection, records.rkey,
                       records.cid, records.revision,
                       length(records.value) AS value_byte_count,
                       metadata.emitted AS car_cid_emitted
                FROM permissioned_space_records AS records
                JOIN temp.swan_repository_car_index AS metadata
                  ON metadata.collection = records.collection
                 AND metadata.rkey = records.rkey
                 AND metadata.cid = records.cid
                WHERE records.space_uri = ? AND records.author_did = ?
                ORDER BY records.collection, records.rkey
                LIMIT 1
                """,
                [.text(space.rawValue), .text(author)]
            )
        }
        guard let row = rows.first else { return nil }
        guard let emitted = row.column("car_cid_emitted")?.integer,
              emitted == 0 || emitted == 1
        else {
            throw SQLiteRepositoryError.corruptDatabase(
                "permissioned CAR CID projection is invalid"
            )
        }
        return (
            try decodeRepositoryCARRecordMetadata(
                row,
                space: space,
                author: author
            ),
            emitted == 0
        )
    }

    private func markRepositoryCARCIDEmitted(_ cid: String) async throws {
        _ = try await connection.query(
            """
            UPDATE temp.swan_repository_car_index
            SET emitted = 1
            WHERE cid = ? AND emitted = 0
            """,
            [.text(cid)]
        )
        // This runs while the caller owns `connectionGate`, so no other
        // statement can replace SQLite's connection-local changes count
        // between the UPDATE and this constant-size scalar query.
        let rows = try await connection.query(
            "SELECT changes() AS changed_count"
        )
        guard rows.count == 1,
              let changed = rows[0].column("changed_count")?.integer,
              changed > 0,
              changed <= SpaceCARProductionLimits.maximumRecordCount
        else {
            throw SQLiteRepositoryError.corruptDatabase(
                "permissioned CAR CID projection is invalid"
            )
        }
    }

    private struct RepositoryCARRecordMetadata {
        let uri: SpaceRecordURI
        let cid: String
        let valueByteCount: Int
    }

    private func decodeRepositoryCARRecordMetadata(
        _ row: SQLiteRow,
        space: SpaceURI,
        author: String
    ) throws -> RepositoryCARRecordMetadata {
        let uri = try SpaceRecordURI(
            space: space,
            author: author,
            collection: requiredText(row, "collection"),
            rkey: requiredText(row, "rkey")
        )
        let valueByteCount = try requiredInteger(row, "value_byte_count")
        guard valueByteCount >= 0 else {
            throw SQLiteRepositoryError.corruptDatabase(
                "permissioned CAR record length is invalid"
            )
        }
        // Preserve the existing corruption check even though a CAR frame does
        // not otherwise need the persisted revision.
        _ = try requiredRevision(row, "revision")
        return RepositoryCARRecordMetadata(
            uri: uri,
            cid: try requiredText(row, "cid"),
            valueByteCount: valueByteCount
        )
    }

    private func repositoryCARCID(
        for record: RepositoryCARRecordMetadata
    ) throws -> CID {
        try CID.parse(record.cid)
    }

    /// Hashes every persisted record through bounded SQLite BLOB slices and,
    /// for the first path referencing a CID, copies those same slices into the
    /// private CAR spool. Avoiding a full `SQLiteRow` BLOB here is essential:
    /// Foundation's debug allocator can retain one freed ~1 MiB region per row,
    /// turning a nominally streaming 256 MiB read into a 256 MiB RSS increase.
    private func streamAndValidateRepositoryCARValue(
        for record: RepositoryCARRecordMetadata,
        expectedCID: CID,
        to destination: FileHandle?
    ) async throws {
        var hasher = SHA256()
        var offset = 0
        while offset < record.valueByteCount {
            try Task.checkCancellation()
            let chunkByteCount = min(
                SpaceCARBodySpool.maximumChunkBytes,
                record.valueByteCount - offset
            )
            let rows = try await connection.query(
                """
                SELECT substr(value, ?, ?) AS value_chunk,
                       length(value) AS value_byte_count
                FROM permissioned_space_records
                WHERE space_uri = ? AND author_did = ?
                  AND collection = ? AND rkey = ?
                """,
                [
                    .integer(offset + 1), .integer(chunkByteCount),
                    .text(record.uri.space.rawValue), .text(record.uri.author),
                    .text(record.uri.collection), .text(record.uri.rkey),
                ]
            )
            guard rows.count == 1 else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "permissioned CAR record changed during snapshot"
                )
            }
            let row = rows[0]
            guard try requiredInteger(row, "value_byte_count")
                    == record.valueByteCount
            else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "permissioned CAR record changed during snapshot"
                )
            }
            let chunk = try requiredBlob(row, "value_chunk")
            guard chunk.count == chunkByteCount else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "permissioned CAR record is truncated"
                )
            }
            hasher.update(data: chunk)
            if let destination {
                try writeCARSpoolData(chunk, to: destination)
            }
            offset += chunk.count
        }
        let calculated = CID(
            codec: .dagCBOR,
            multihash: .init(
                algorithm: Multihash.sha256Code,
                length: Multihash.sha256Length,
                digest: Data(hasher.finalize())
            )
        )
        guard calculated == expectedCID else {
            throw SQLiteRepositoryError.corruptDatabase("permissioned CAR record CID does not match value")
        }
    }

    private func reserveRepositoryCARBodyBytes(
        _ bytes: Int,
        currentByteCount: inout Int
    ) throws {
        guard bytes >= 0 else {
            throw SpaceCARProductionLimits.limitExceeded()
        }
        let (next, overflow) = currentByteCount.addingReportingOverflow(bytes)
        guard !overflow,
              next <= SpaceCARProductionLimits.maximumBodyBytes
        else {
            throw SpaceCARProductionLimits.limitExceeded()
        }
        currentByteCount = next
    }

    private func writeCARSpoolData(_ data: Data, to handle: FileHandle) throws {
        var offset = 0
        while offset < data.count {
            try Task.checkCancellation()
            let end = min(offset + SpaceCARBodySpool.maximumChunkBytes, data.count)
            try handle.write(contentsOf: data[offset ..< end])
            offset = end
        }
    }

    private func copyCARSpoolFile(
        _ source: FileHandle,
        to destination: FileHandle
    ) throws {
        try source.synchronize()
        try source.seek(toOffset: 0)
        while let chunk = try source.read(
            upToCount: SpaceCARBodySpool.maximumChunkBytes
        ),
              !chunk.isEmpty {
            try Task.checkCancellation()
            try destination.write(contentsOf: chunk)
        }
    }

    /// Loads only the current permissioned repository state.  Sync commit
    /// creation must not read every record merely to obtain the durable LtHash
    /// commitment and wire TID.
    public func repositoryState(
        space: SpaceURI,
        author: String
    ) async throws -> PersistedRepositoryState? {
        try requireAccount(author)
        let state = try await withConnectionGate {
            try await readTransaction {
                try await requireLocalRepositorySpaceOpen(space)
                return try await loadState(space: space, author: author)
            }
        }
        await testingHooks.afterRepositoryStateRead?()
        return state
    }

    /// Enumerates the small, value-free local-PDS hosted-space projection for
    /// this account.  This intentionally reads only `space_uri` identity
    /// columns: it never touches record values, CIDs, blob references, or
    /// simple-space policy/member state.  Request authorization and active
    /// account/path admission belong to `SQLitePreMigratedAccountDirectory`;
    /// this account-local primitive cannot select another database.
    public func hostedSpaceURIs(
        spaceType: String?,
        authority: String?,
        cursor: SpaceURI?,
        limit: Int
    ) async throws -> [SpaceURI] {
        guard (1 ... 100).contains(limit) else {
            throw SwanError.malformed("invalid hosted-space page limit")
        }
        return try await withConnectionGate {
            try await readTransaction {
                // `UNION` de-duplicates exact identity rows before Swift
                // validates their canonical `SpaceURI` spelling and applies
                // type/authority/cursor paging.  A local authority deletion,
                // recipient tombstone, or v1 restored-policy closure always
                // wins over a repository-state row.
                let rows = try await connection.query(
                    """
                    SELECT space_uri, MAX(is_local_authority) AS is_local_authority
                    FROM (
                        SELECT a.space_uri AS space_uri, 1 AS is_local_authority
                        FROM permissioned_simple_space_authorities AS a
                        WHERE a.owner_did = ?
                          AND a.is_deleted = 0
                          AND NOT EXISTS (
                              SELECT 1
                              FROM permissioned_space_recipient_tombstones AS t
                              WHERE t.space_uri = a.space_uri
                          )
                        UNION
                        SELECT r.space_uri AS space_uri, 0 AS is_local_authority
                        FROM permissioned_repository_state AS r
                        WHERE r.author_did = ?
                          AND NOT EXISTS (
                              SELECT 1
                              FROM permissioned_simple_space_authorities AS a
                              WHERE a.space_uri = r.space_uri AND a.is_deleted != 0
                          )
                          AND NOT EXISTS (
                              SELECT 1
                              FROM permissioned_space_recipient_tombstones AS t
                              WHERE t.space_uri = r.space_uri
                          )
                          AND NOT EXISTS (
                              SELECT 1
                              FROM permissioned_restored_repository_closures AS c
                              WHERE c.space_uri = r.space_uri
                                AND c.author_did = r.author_did
                                AND c.reason = 'missing-authority-policy-v1'
                          )
                    )
                    WHERE (? IS NULL OR space_uri GLOB ?)
                      AND (? IS NULL OR substr(space_uri, 1, length(?)) = ?)
                      AND (? IS NULL OR space_uri > ?)
                    GROUP BY space_uri
                    ORDER BY space_uri ASC
                    LIMIT ?
                    """,
                    [
                        .text(accountDID),
                        .text(accountDID),
                        spaceType.map { "at://*/space/\($0)/*" }.map(SQLiteData.text) ?? .null,
                        spaceType.map { "at://*/space/\($0)/*" }.map(SQLiteData.text) ?? .null,
                        authority.map { "at://\($0)/space/" }.map(SQLiteData.text) ?? .null,
                        authority.map { "at://\($0)/space/" }.map(SQLiteData.text) ?? .null,
                        authority.map { "at://\($0)/space/" }.map(SQLiteData.text) ?? .null,
                        cursor.map { SQLiteData.text($0.rawValue) } ?? .null,
                        cursor.map { SQLiteData.text($0.rawValue) } ?? .null,
                        .integer(limit),
                    ]
                )

                let validated = try rows.map { row -> SpaceURI in
                    let raw = try requiredText(row, "space_uri")
                    let space: SpaceURI
                    do {
                        space = try SpaceURI(raw)
                    } catch {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "invalid hosted-space identity"
                        )
                    }
                    guard space.rawValue == raw else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "noncanonical hosted-space identity"
                        )
                    }
                    guard try requiredInteger(row, "is_local_authority") == 0
                        || space.authority == accountDID else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "invalid hosted-space authority ownership"
                        )
                    }
                    return space
                }
                return Array(validated.lazy.filter { space in
                    (spaceType == nil || space.spaceType == spaceType)
                        && (authority == nil || space.authority == authority)
                        && (cursor == nil || space.rawValue > cursor!.rawValue)
                }.prefix(limit))
            }
        }
    }

    private func repositorySnapshotWithoutTransaction(
        space: SpaceURI,
        author: String
    ) async throws -> PersistedRepositorySnapshot? {
        guard let state = try await loadState(space: space, author: author) else {
            return nil
        }
        await testingHooks.afterSnapshotStateRead?()
        let rows = try await connection.query(
            """
            SELECT collection, rkey, value, cid, revision
            FROM permissioned_space_records
            WHERE space_uri = ? AND author_did = ?
            ORDER BY collection, rkey
            """,
            [.text(space.rawValue), .text(author)]
        )
        let records = try rows.map {
            try decodeRecord($0, space: space, author: author)
        }
        return PersistedRepositorySnapshot(state: state, records: records)
    }

    public func spaceRecord(
        _ uri: SpaceRecordURI
    ) async throws -> PersistedSpaceRecord? {
        try requireAccount(uri.author)
        return try await withConnectionGate {
            try await readTransaction {
                try await requireLocalRepositorySpaceOpen(uri.space)
                guard try await loadState(space: uri.space, author: uri.author) != nil else {
                    return nil
                }
                return try await loadRecord(uri)
            }
        }
    }

    /// Reads only the value-free facts needed to preflight a bounded write
    /// batch. The query is performed inside one read transaction so a caller
    /// cannot observe a mixture of repository generations, while record bodies
    /// remain completely untouched.
    public func spaceRecordMetadata(
        space: SpaceURI,
        author: String,
        uris: [SpaceRecordURI]
    ) async throws -> [SpaceRecordURI: PersistedSpaceRecordMetadata] {
        try requireAccount(author)
        guard uris.count <= 4_096 else {
            throw SwanError.malformed("permissioned write batch is too large")
        }
        var uniqueURIs = Set<SpaceRecordURI>()
        uniqueURIs.reserveCapacity(uris.count)
        for uri in uris {
            guard uri.space == space, uri.author == author else {
                throw SwanError.unauthorized("record belongs to another repository")
            }
            uniqueURIs.insert(uri)
        }
        return try await withConnectionGate {
            try await readTransaction {
                try await requireLocalRepositorySpaceOpen(space)
                var result: [SpaceRecordURI: PersistedSpaceRecordMetadata] = [:]
                result.reserveCapacity(uniqueURIs.count)
                for uri in uniqueURIs {
                    if let metadata = try await loadRecordMetadata(uri) {
                        result[uri] = metadata
                    }
                }
                return result
            }
        }
    }

    /// Returns one deterministic permissioned page without selecting the
    /// complete repository. SQLite first selects ordered keys and scalar value
    /// lengths, enforcing the aggregate byte budget before it opens any record
    /// body; only the accepted keys are then decoded from the same read
    /// transaction. A page may be shorter than `limit` at the byte boundary,
    /// and the caller continues with the last returned key.
    public func repositoryRecordPage(
        space: SpaceURI,
        author: String,
        collection: String?,
        cursorCollection: String?,
        cursorRKey: String?,
        reverse: Bool,
        limit: Int,
        maximumAggregateRecordBytes: Int
    ) async throws -> [PersistedSpaceRecord] {
        try requireAccount(author)
        guard (1 ... 100).contains(limit),
              maximumAggregateRecordBytes > 0,
              (cursorCollection == nil) == (cursorRKey == nil) else {
            throw SwanError.malformed("permissioned record page is invalid")
        }
        if let collection {
            _ = try SpaceRecordURI(
                space: space,
                author: author,
                collection: collection,
                rkey: "scope"
            )
        }
        if let cursorCollection, let cursorRKey {
            _ = try SpaceRecordURI(
                space: space,
                author: author,
                collection: cursorCollection,
                rkey: cursorRKey
            )
        }

        return try await withConnectionGate {
            try await readTransaction {
                try await requireLocalRepositorySpaceOpen(space)

                var predicates = [
                    "space_uri = ?",
                    "author_did = ?",
                ]
                var parameters: [SQLiteData] = [
                    .text(space.rawValue),
                    .text(author),
                ]
                if let collection {
                    predicates.append("collection = ?")
                    parameters.append(.text(collection))
                }
                if let cursorCollection, let cursorRKey {
                    if reverse {
                        predicates.append(
                            "(collection > ? OR (collection = ? AND rkey > ?))"
                        )
                    } else {
                        predicates.append(
                            "(collection < ? OR (collection = ? AND rkey < ?))"
                        )
                    }
                    parameters.append(.text(cursorCollection))
                    parameters.append(.text(cursorCollection))
                    parameters.append(.text(cursorRKey))
                }
                let order = reverse ? "ASC" : "DESC"
                parameters.append(.integer(limit))
                let rows = try await connection.query(
                    """
                    SELECT collection, rkey, cid, revision,
                           length(value) AS value_bytes
                    FROM permissioned_space_records
                    WHERE \(predicates.joined(separator: " AND "))
                    ORDER BY collection \(order), rkey \(order)
                    LIMIT ?
                    """,
                    parameters
                )

                var selected: [(uri: SpaceRecordURI, valueBytes: Int)] = []
                selected.reserveCapacity(rows.count)
                var aggregateBytes = 0
                for row in rows {
                    let uri = try SpaceRecordURI(
                        space: space,
                        author: author,
                        collection: try requiredText(row, "collection"),
                        rkey: try requiredText(row, "rkey")
                    )
                    let valueBytes = try requiredNonnegativeInteger(
                        row,
                        "value_bytes"
                    )
                    let (next, overflow) = aggregateBytes
                        .addingReportingOverflow(valueBytes)
                    guard !overflow else {
                        throw SwanError.unavailable(
                            "permissioned record page exceeds response budget"
                        )
                    }
                    guard next <= maximumAggregateRecordBytes else {
                        // A single record is bounded at write time. If a
                        // future schema permits a larger value, fail closed
                        // rather than returning a page that can never be
                        // encoded within the advertised response budget.
                        if selected.isEmpty {
                            throw SwanError.unavailable(
                                "permissioned record page exceeds response budget"
                            )
                        }
                        break
                    }
                    selected.append((uri: uri, valueBytes: valueBytes))
                    aggregateBytes = next
                }

                var records: [PersistedSpaceRecord] = []
                records.reserveCapacity(selected.count)
                for item in selected {
                    guard let record = try await loadRecord(item.uri),
                          record.value.count == item.valueBytes else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "permissioned record page changed during snapshot"
                        )
                    }
                    records.append(record)
                }
                return records
            }
        }
    }

    public func spaceOplog(
        space: SpaceURI,
        author: String,
        since requestedRevision: UInt64
    ) async throws -> PersistedOplogRead {
        try requireAccount(author)
        return try await withConnectionGate {
            try await readTransaction {
                try await requireLocalRepositorySpaceOpen(space)
                return try await spaceOplogWithoutTransaction(
                    space: space,
                    author: author,
                    afterRevision: requestedRevision,
                    afterIndex: nil
                )
            }
        }
    }

    /// Returns an incremental page after an XRPC wire-TID cursor.
    /// The reference PDS treats TIDs as its protocol cursor, while its
    /// operation ordering is still `(commit revision, operation index)`.
    /// Keep that distinction here: a batch may deliberately contain multiple
    /// operations with the same wire TID. `since` cannot resume inside that
    /// batch, so `limit` selects a terminal revision and the returned page is
    /// extended to include every operation with that revision. A page can
    /// therefore contain more than `limit` entries, but it can never silently
    /// split a batch that the next `since` cursor would skip.
    public func wireOplog(
        space: SpaceURI,
        author: String,
        since: TID?,
        limit: Int,
        includeValues: Bool,
        maximumAggregateValueBytes: Int = PublicRepositoryJSONReadLimits
            .maximumListRepoOpsValueBytes
    ) async throws -> PersistedWireOplogRead {
        try requireAccount(author)
        guard (1 ... 1_000).contains(limit),
              maximumAggregateValueBytes > 0 else {
            throw SwanError.malformed("permissioned oplog page limit is invalid")
        }
        return try await withConnectionGate {
            try await readTransaction {
                try await requireLocalRepositorySpaceOpen(space)
                return try await wireOplogWithoutTransaction(
                    space: space,
                    author: author,
                    since: since,
                    limit: limit,
                    includeValues: includeValues,
                    maximumAggregateValueBytes: maximumAggregateValueBytes
                )
            }
        }
    }

    private func wireOplogWithoutTransaction(
        space: SpaceURI,
        author: String,
        since: TID?,
        limit: Int,
        includeValues: Bool,
        maximumAggregateValueBytes: Int
    ) async throws -> PersistedWireOplogRead {
        guard let state = try await loadState(space: space, author: author) else {
            return .incremental(state: nil, entries: [])
        }

        if let since {
            let oldestRows = try await connection.query(
                """
                SELECT wire_revision
                FROM permissioned_space_oplog
                WHERE space_uri = ? AND author_did = ?
                ORDER BY revision, operation_index
                LIMIT 1
                """,
                [.text(space.rawValue), .text(author)]
            )
            guard let oldestRow = oldestRows.first else {
                // A state without retained history cannot safely answer an
                // incremental request from a known cursor.
                return .fullRecoveryRequired
            }
            let oldest = try requiredTID(oldestRow, "wire_revision")
            // TIDs cannot express the predecessor relationship that SQLite's
            // private numeric cursor has.  Be conservatively fail-closed: a
            // cursor older than the first retained TID gets the later full
            // CAR recovery path rather than a plausible, divergent delta.
            if since < oldest {
                return .fullRecoveryRequired
            }
        }

        // A wire TID is the only public cursor. Summarize complete TID groups
        // before selecting any BLOB values. This preserves atomic batches while
        // enforcing both the requested operation limit and a byte budget using
        // scalar metadata only; a same-TID batch that cannot fit fails closed.
        let valueBytesExpression = includeValues
            ? "COALESCE(SUM(COALESCE(length(live.value), 0)), 0)"
            : "0"
        let groupRows = try await connection.query(
            """
            SELECT oplog.wire_revision,
                   MIN(oplog.revision) AS first_revision,
                   MIN(oplog.operation_index) AS first_operation_index,
                   COUNT(*) AS operation_count,
                   \(valueBytesExpression) AS value_bytes
            FROM permissioned_space_oplog AS oplog
            LEFT JOIN permissioned_space_records AS live
              ON live.space_uri = oplog.space_uri
             AND live.author_did = oplog.author_did
             AND live.collection = oplog.collection
             AND live.rkey = oplog.rkey
             AND live.cid = oplog.cid
            WHERE oplog.space_uri = ? AND oplog.author_did = ?
              AND (? IS NULL OR oplog.wire_revision > ?)
            GROUP BY oplog.wire_revision
            ORDER BY first_revision, first_operation_index
            LIMIT ?
            """,
            [
                .text(space.rawValue), .text(author),
                since.map { .text($0.toString()) } ?? .null,
                since.map { .text($0.toString()) } ?? .null,
                .integer(limit),
            ]
        )
        guard !groupRows.isEmpty else {
            return .incremental(state: state, entries: [])
        }

        let maximumAggregateOperations = PublicRepositoryJSONReadLimits
            .maximumListRepoOpsOperations
        var selectedOperationCount = 0
        var aggregateValueBytes = 0
        var boundary: TID?
        for row in groupRows {
            let operationCount = try requiredNonnegativeInteger(
                row,
                "operation_count"
            )
            guard operationCount > 0 else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "oplog group has no operations"
                )
            }
            guard operationCount <= maximumAggregateOperations else {
                throw SwanError.unavailable(
                    "permissioned oplog page exceeds response budget"
                )
            }
            let valueBytes = try requiredNonnegativeInteger(row, "value_bytes")
            let (nextBytes, bytesOverflow) = aggregateValueBytes
                .addingReportingOverflow(valueBytes)
            let (nextOperations, operationsOverflow) = selectedOperationCount
                .addingReportingOverflow(operationCount)
            guard !bytesOverflow, !operationsOverflow else {
                throw SwanError.unavailable("permissioned oplog page exceeds response budget")
            }
            if boundary == nil && valueBytes > maximumAggregateValueBytes {
                throw SwanError.unavailable("permissioned oplog page exceeds response budget")
            }
            if boundary != nil,
               nextBytes > maximumAggregateValueBytes
                || nextOperations > maximumAggregateOperations {
                break
            }
            boundary = try requiredTID(row, "wire_revision")
            aggregateValueBytes = nextBytes
            selectedOperationCount = nextOperations
            if selectedOperationCount >= limit {
                break
            }
        }
        guard let boundary else {
            throw SwanError.unavailable("permissioned oplog page exceeds response budget")
        }

        let rows: [SQLiteRow]
        if includeValues {
            try await testingHooks.beforeWireOplogValueMaterialization?()
            rows = try await connection.query(
                """
                SELECT oplog.wire_revision, oplog.action, oplog.collection,
                       oplog.rkey, oplog.cid, oplog.previous_cid,
                       live.value AS current_value
                FROM permissioned_space_oplog AS oplog
                LEFT JOIN permissioned_space_records AS live
                  ON live.space_uri = oplog.space_uri
                 AND live.author_did = oplog.author_did
                 AND live.collection = oplog.collection
                 AND live.rkey = oplog.rkey
                 AND live.cid = oplog.cid
                WHERE oplog.space_uri = ? AND oplog.author_did = ?
                  AND (? IS NULL OR oplog.wire_revision > ?)
                  AND oplog.wire_revision <= ?
                ORDER BY oplog.revision, oplog.operation_index
                """,
                [
                    .text(space.rawValue), .text(author),
                    since.map { .text($0.toString()) } ?? .null,
                    since.map { .text($0.toString()) } ?? .null,
                    .text(boundary.toString()),
                ]
            )
        } else {
            rows = try await connection.query(
                """
                SELECT wire_revision, action, collection, rkey, cid,
                       previous_cid, NULL AS current_value
                FROM permissioned_space_oplog
                WHERE space_uri = ? AND author_did = ?
                  AND (? IS NULL OR wire_revision > ?)
                  AND wire_revision <= ?
                ORDER BY revision, operation_index
                """,
                [
                    .text(space.rawValue), .text(author),
                    since.map { .text($0.toString()) } ?? .null,
                    since.map { .text($0.toString()) } ?? .null,
                    .text(boundary.toString()),
                ]
            )
        }
        guard rows.count <= maximumAggregateOperations else {
            throw SwanError.unavailable("permissioned oplog page exceeds response budget")
        }
        if includeValues {
            let actualValueBytes = try rows.reduce(into: 0) { total, row in
                guard case let .blob(value) = row.column("current_value") else {
                    return
                }
                let (next, overflow) = total.addingReportingOverflow(value.readableBytes)
                guard !overflow else {
                    throw SwanError.unavailable(
                        "permissioned oplog page exceeds response budget"
                    )
                }
                total = next
            }
            guard actualValueBytes <= maximumAggregateValueBytes else {
                throw SwanError.unavailable("permissioned oplog page exceeds response budget")
            }
        }
        return .incremental(
            state: state,
            entries: try rows.map {
                try decodeWireOplog($0, space: space, author: author)
            }
        )
    }

    /// Cursor-precise variant for adapters that page within one commit.
    public func spaceOplog(
        space: SpaceURI,
        author: String,
        after cursor: PersistedOplogCursor?
    ) async throws -> PersistedOplogRead {
        try requireAccount(author)
        return try await withConnectionGate {
            try await readTransaction {
                try await requireLocalRepositorySpaceOpen(space)
                return try await spaceOplogWithoutTransaction(
                    space: space,
                    author: author,
                    afterRevision: cursor?.revision ?? 0,
                    afterIndex: cursor?.index
                )
            }
        }
    }

    private func spaceOplogWithoutTransaction(
        space: SpaceURI,
        author: String,
        afterRevision requestedRevision: UInt64,
        afterIndex requestedIndex: UInt64?
    ) async throws -> PersistedOplogRead {
        guard let state = try await loadState(space: space, author: author) else {
            return .incremental([])
        }
        guard requestedRevision < state.revision
                || (requestedRevision == state.revision && requestedIndex != nil)
        else {
            return .incremental([])
        }
        let oldestRows = try await connection.query(
            """
            SELECT MIN(revision) AS oldest_revision
            FROM permissioned_space_oplog
            WHERE space_uri = ? AND author_did = ?
            """,
            [.text(space.rawValue), .text(author)]
        )
        let oldest: UInt64?
        if let row = oldestRows.first,
           let value = row.column("oldest_revision"),
           !value.isNull {
            oldest = try revision(value, column: "oldest_revision")
        } else {
            oldest = nil
        }
        guard let oldest else {
            guard let snapshot = try await repositorySnapshotWithoutTransaction(
                space: space,
                author: author
            ) else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "repository state has no snapshot"
                )
            }
            return .fullRecoveryRequired(snapshot)
        }
        let cursorPredatesRetention = if requestedIndex != nil {
            requestedRevision < oldest
        } else {
            oldest > 0 && requestedRevision < oldest - 1
        }
        if cursorPredatesRetention {
            guard let snapshot = try await repositorySnapshotWithoutTransaction(
                space: space,
                author: author
            ) else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "repository state has no snapshot"
                )
            }
            return .fullRecoveryRequired(snapshot)
        }

        let rows: [SQLiteRow]
        if let requestedIndex {
            rows = try await connection.query(
                """
                SELECT revision, operation_index, wire_revision, action,
                       collection, rkey, value, cid, previous_cid, commitment
                FROM permissioned_space_oplog
                WHERE space_uri = ? AND author_did = ?
                  AND (
                    revision > ?
                    OR (revision = ? AND operation_index > ?)
                  )
                ORDER BY revision, operation_index
                """,
                [
                    .text(space.rawValue), .text(author),
                    .integer(try sqliteRevision(requestedRevision)),
                    .integer(try sqliteRevision(requestedRevision)),
                    .integer(try sqliteRevision(requestedIndex)),
                ]
            )
        } else {
            rows = try await connection.query(
                """
                SELECT revision, operation_index, wire_revision, action,
                       collection, rkey, value, cid, previous_cid, commitment
                FROM permissioned_space_oplog
                WHERE space_uri = ? AND author_did = ? AND revision > ?
                ORDER BY revision, operation_index
                """,
                [
                    .text(space.rawValue), .text(author),
                    .integer(try sqliteRevision(requestedRevision)),
                ]
            )
        }
        return .incremental(
            try rows.map {
                try decodeOplog($0, space: space, author: author)
            }
        )
    }

    // MARK: Durable simple-space authority

    /// Creates one authority-owned simple space. The authority/account and
    /// OAuth management checks run while the insert transaction is held, so a
    /// stale caller cannot race a policy mutation into a foreign account.
    public func createSimpleSpace(
        space: SpaceURI,
        owner: String,
        configuration: SimpleSpaceConfiguration,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try validateSimpleSpaceConfiguration(configuration)
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space, owner: owner)
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .create
                )
                let existing = try await connection.query(
                    "SELECT 1 FROM permissioned_simple_space_authorities WHERE space_uri = ?",
                    [.text(space.rawValue)]
                )
                guard existing.isEmpty else {
                    throw SwanError.conflict(expected: 0, actual: 1)
                }
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_simple_space_authorities(
                        space_uri, owner_did, policy, app_access, managing_app,
                        is_deleted, revision, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 0, 1, ?, ?)
                    """,
                    [
                        .text(space.rawValue), .text(owner),
                        .text(configuration.policy.rawValue),
                        .text(simpleSpaceAppAccessName(configuration.appAccess)),
                        configuration.managingApp.map(SQLiteData.text) ?? .null,
                        .integer(timestamp), .integer(timestamp),
                    ]
                )
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_simple_space_members(space_uri, member_did)
                    VALUES (?, ?)
                    """,
                    [.text(space.rawValue), .text(owner)]
                )
                try await replaceSimpleSpaceClients(
                    space: space,
                    appAccess: configuration.appAccess
                )
                return try await requiredSimpleSpace(space).state
            }
        }
    }

    /// Reads authority facts from the account database. This local storage API
    /// deliberately has no public HTTP surface. Full authority facts expose
    /// membership and the client allow-list, so only the managing authority
    /// can retrieve them; there is no accidentally-public projection yet.
    public func simpleSpace(
        _ space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws -> DurableSimpleSpaceState? {
        try requireAuthorityAccount(space: space)
        return try await withConnectionGate {
            try await readTransaction {
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .update
                )
                return try await loadSimpleSpace(space)?.state
            }
        }
    }

    /// Reads a bounded member page directly from SQLite.  The older facade
    /// obtained `SimpleSpace` first and then sorted its `Set`, which made a
    /// request for ten members materialize every member in the authority
    /// account.  This path validates the scalar authority facts and cardinality
    /// with bounded/counting queries, then uses a keyset predicate for the
    /// actual page.
    public func simpleSpaceMemberPage(
        space: SpaceURI,
        limit: Int,
        cursor: String?,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSimpleSpaceMemberPage {
        guard (1 ... 1_000).contains(limit) else {
            throw SwanError.malformed("invalid member page limit")
        }
        if let cursor {
            guard isValidSimpleSpaceDID(cursor) else {
                throw SwanError.malformed("invalid member cursor")
            }
        }
        try requireAuthorityAccount(space: space)
        return try await withConnectionGate {
            try await readTransaction {
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .update
                )
                let authorityRows = try await connection.query(
                    """
                    SELECT owner_did, policy, app_access, managing_app, is_deleted
                    FROM permissioned_simple_space_authorities
                    WHERE space_uri = ?
                    LIMIT 1
                    """,
                    [.text(space.rawValue)]
                )
                guard let authorityRow = authorityRows.first else {
                    throw AuthorizedSimpleSpaceLifecycleError.notFound
                }
                let owner = try requiredText(authorityRow, "owner_did")
                guard owner == space.authority, isValidSimpleSpaceDID(owner) else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "invalid simple-space owner"
                    )
                }
                let policyRaw = try requiredText(authorityRow, "policy")
                guard let policy = SimpleSpacePolicy(rawValue: policyRaw) else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "invalid simple-space policy"
                    )
                }
                let appAccessRaw = try requiredText(authorityRow, "app_access")
                guard appAccessRaw == "open" || appAccessRaw == "allow-list" else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "invalid simple-space app access"
                    )
                }
                if let managingApp = authorityRow.column("managing_app"), !managingApp.isNull {
                    try validateSimpleSpaceAppIdentifier(
                        try requiredText(authorityRow, "managing_app")
                    )
                }
                let deleted = try requiredInteger(authorityRow, "is_deleted")
                guard deleted == 0 || deleted == 1 else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "invalid simple-space deleted state"
                    )
                }
                guard deleted == 0 else {
                    throw AuthorizedSimpleSpaceLifecycleError.notFound
                }

                let memberCountRows = try await connection.query(
                    """
                    SELECT COUNT(*) AS count
                    FROM permissioned_simple_space_members
                    WHERE space_uri = ?
                    """,
                    [.text(space.rawValue)]
                )
                let memberCount = try requiredNonnegativeInteger(
                    try requiredRow(memberCountRows),
                    "count"
                )
                guard memberCount <= Self.maximumSimpleSpaceMembers else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "simple-space members exceed their bound"
                    )
                }
                let ownerRows = try await connection.query(
                    """
                    SELECT 1
                    FROM permissioned_simple_space_members
                    WHERE space_uri = ? AND member_did = ?
                    LIMIT 1
                    """,
                    [.text(space.rawValue), .text(owner)]
                )
                guard !ownerRows.isEmpty else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "simple-space owner is not a member"
                    )
                }

                let clientCountRows = try await connection.query(
                    """
                    SELECT COUNT(*) AS count
                    FROM permissioned_simple_space_clients
                    WHERE space_uri = ?
                    """,
                    [.text(space.rawValue)]
                )
                let clientCount = try requiredNonnegativeInteger(
                    try requiredRow(clientCountRows),
                    "count"
                )
                guard clientCount <= Self.maximumSimpleSpaceClients else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "simple-space clients exceed their bound"
                    )
                }
                if appAccessRaw == "open" {
                    guard clientCount == 0 else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "open simple space has client restrictions"
                        )
                    }
                }
                let decisionCountRows = try await connection.query(
                    """
                    SELECT COUNT(*) AS count
                    FROM permissioned_simple_space_managing_app_decisions
                    WHERE space_uri = ?
                    """,
                    [.text(space.rawValue)]
                )
                let decisionCount = try requiredNonnegativeInteger(
                    try requiredRow(decisionCountRows),
                    "count"
                )
                guard decisionCount <= Self.maximumSimpleSpaceManagingAppDecisions else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "simple-space managing-app decisions exceed their bound"
                    )
                }
                if policy != .managingApp {
                    guard decisionCount == 0 else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "non-managing simple space has app decisions"
                        )
                    }
                }

                let memberRows: [SQLiteRow]
                if let cursor {
                    memberRows = try await connection.query(
                        """
                        SELECT member_did
                        FROM permissioned_simple_space_members
                        WHERE space_uri = ? AND member_did > ?
                        ORDER BY member_did ASC
                        LIMIT ?
                        """,
                        [
                            .text(space.rawValue), .text(cursor),
                            .integer(limit),
                        ]
                    )
                } else {
                    memberRows = try await connection.query(
                        """
                        SELECT member_did
                        FROM permissioned_simple_space_members
                        WHERE space_uri = ?
                        ORDER BY member_did ASC
                        LIMIT ?
                        """,
                        [.text(space.rawValue), .integer(limit)]
                    )
                }
                let members = try memberRows.map { row in
                    let member = try requiredText(row, "member_did")
                    guard isValidSimpleSpaceDID(member) else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "invalid simple-space member"
                        )
                    }
                    return member
                }
                return AuthorizedSimpleSpaceMemberPage(
                    members: members,
                    cursor: members.last
                )
            }
        }
    }

    public func updateSimpleSpace(
        space: SpaceURI,
        configuration: SimpleSpaceConfiguration,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try validateSimpleSpaceConfiguration(configuration)
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space)
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .update
                )
                let stored = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(stored.state)
                guard stored.state.space.configuration != configuration else {
                    return stored.state
                }
                let previous = stored.state.space.configuration
                let nextRevision = try nextSimpleSpaceRevision(stored.state.revision)
                _ = try await connection.query(
                    """
                    UPDATE permissioned_simple_space_authorities
                    SET policy = ?, app_access = ?, managing_app = ?,
                        revision = ?,
                        updated_at = CASE WHEN updated_at > ? THEN updated_at ELSE ? END
                    WHERE space_uri = ?
                    """,
                    [
                        .text(configuration.policy.rawValue),
                        .text(simpleSpaceAppAccessName(configuration.appAccess)),
                        configuration.managingApp.map(SQLiteData.text) ?? .null,
                        .integer(try sqliteRevision(nextRevision)),
                        .integer(timestamp), .integer(timestamp),
                        .text(space.rawValue),
                    ]
                )
                try await replaceSimpleSpaceClients(
                    space: space,
                    appAccess: configuration.appAccess
                )
                // A decision belongs to one managing app identity. Never
                // transfer it when the policy is disabled or the app changes.
                if previous.policy != .managingApp
                    || configuration.policy != .managingApp
                    || previous.managingApp != configuration.managingApp {
                    _ = try await connection.query(
                        "DELETE FROM permissioned_simple_space_managing_app_decisions WHERE space_uri = ?",
                        [.text(space.rawValue)]
                    )
                }
                return try await requiredSimpleSpace(space).state
            }
        }
    }

    /// Applies an XRPC `updateSpace` patch inside one authority transaction.
    /// Fetching configuration in the HTTP layer and writing it back later
    /// would race another patch and turn an omitted property into a stale
    /// reset, so the patch is resolved against the durable row while the
    /// write transaction is held.
    public func patchSimpleSpace(
        space: SpaceURI,
        patch: SimpleSpaceConfigurationPatch,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space)
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .update
                )
                let stored = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(stored.state)
                let configuration = try patch.applying(
                    to: stored.state.space.configuration
                )
                try validateSimpleSpaceConfiguration(configuration)
                guard configuration != stored.state.space.configuration else {
                    return stored.state
                }
                let previous = stored.state.space.configuration
                let nextRevision = try nextSimpleSpaceRevision(stored.state.revision)
                _ = try await connection.query(
                    """
                    UPDATE permissioned_simple_space_authorities
                    SET policy = ?, app_access = ?, managing_app = ?,
                        revision = ?,
                        updated_at = CASE WHEN updated_at > ? THEN updated_at ELSE ? END
                    WHERE space_uri = ?
                    """,
                    [
                        .text(configuration.policy.rawValue),
                        .text(simpleSpaceAppAccessName(configuration.appAccess)),
                        configuration.managingApp.map(SQLiteData.text) ?? .null,
                        .integer(try sqliteRevision(nextRevision)),
                        .integer(timestamp), .integer(timestamp),
                        .text(space.rawValue),
                    ]
                )
                try await replaceSimpleSpaceClients(
                    space: space,
                    appAccess: configuration.appAccess
                )
                if previous.policy != .managingApp
                    || configuration.policy != .managingApp
                    || previous.managingApp != configuration.managingApp {
                    _ = try await connection.query(
                        "DELETE FROM permissioned_simple_space_managing_app_decisions WHERE space_uri = ?",
                        [.text(space.rawValue)]
                    )
                }
                return try await requiredSimpleSpace(space).state
            }
        }
    }

    public func addSimpleSpaceMember(
        space: SpaceURI,
        member: String,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        guard isValidSimpleSpaceDID(member) else {
            throw SwanError.invalidIdentifier(member)
        }
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space)
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .update
                )
                let stored = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(stored.state)
                guard !stored.state.space.members.contains(member) else {
                    return stored.state
                }
                guard stored.state.space.members.count < Self.maximumSimpleSpaceMembers else {
                    throw SwanError.unavailable(
                        "simple-space member capacity exhausted"
                    )
                }
                _ = try await connection.query(
                    "INSERT INTO permissioned_simple_space_members(space_uri, member_did) VALUES (?, ?)",
                    [.text(space.rawValue), .text(member)]
                )
                try await touchSimpleSpace(space: space, revision: stored.state.revision, timestamp: timestamp)
                return try await requiredSimpleSpace(space).state
            }
        }
    }

    public func removeSimpleSpaceMember(
        space: SpaceURI,
        member: String,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        guard isValidSimpleSpaceDID(member) else {
            throw SwanError.invalidIdentifier(member)
        }
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space)
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .update
                )
                let stored = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(stored.state)
                guard member != stored.state.space.owner else {
                    throw SwanError.malformed("a space owner cannot be removed")
                }
                guard stored.state.space.members.contains(member) else {
                    return stored.state
                }
                _ = try await connection.query(
                    "DELETE FROM permissioned_simple_space_members WHERE space_uri = ? AND member_did = ?",
                    [.text(space.rawValue), .text(member)]
                )
                try await touchSimpleSpace(space: space, revision: stored.state.revision, timestamp: timestamp)
                return try await requiredSimpleSpace(space).state
            }
        }
    }

    /// Changes a single client restriction without accepting a mutable
    /// allow-list from an untrusted caller. Open policies cannot accumulate
    /// latent client rows that might become active on a later policy switch.
    public func setSimpleSpaceClientAccess(
        space: SpaceURI,
        clientID: String,
        allowed: Bool,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try validateSimpleSpaceAppIdentifier(clientID)
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space)
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .update
                )
                let stored = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(stored.state)
                guard case .allowList = stored.state.space.configuration.appAccess else {
                    throw SwanError.malformed("client restrictions require an allow-list policy")
                }
                let currentlyAllowed: Bool
                if case let .allowList(clients) = stored.state.space.configuration.appAccess {
                    currentlyAllowed = clients.contains(clientID)
                } else {
                    currentlyAllowed = false
                }
                guard currentlyAllowed != allowed else { return stored.state }
                if allowed {
                    let clientCount: Int
                    if case let .allowList(clients) = stored.state.space.configuration.appAccess {
                        clientCount = clients.count
                    } else {
                        clientCount = 0
                    }
                    guard clientCount < Self.maximumSimpleSpaceClients else {
                        throw SwanError.unavailable(
                            "simple-space client allow-list capacity exhausted"
                        )
                    }
                    _ = try await connection.query(
                        "INSERT INTO permissioned_simple_space_clients(space_uri, client_id) VALUES (?, ?)",
                        [.text(space.rawValue), .text(clientID)]
                    )
                } else {
                    _ = try await connection.query(
                        "DELETE FROM permissioned_simple_space_clients WHERE space_uri = ? AND client_id = ?",
                        [.text(space.rawValue), .text(clientID)]
                    )
                }
                try await touchSimpleSpace(space: space, revision: stored.state.revision, timestamp: timestamp)
                return try await requiredSimpleSpace(space).state
            }
        }
    }

    /// Records the managing app's result for a user. The app identity is an
    /// explicit, already-validated service context, not an ambient boolean;
    /// client-attestation verification remains a separate policy component
    /// for this alpha.
    public func setSimpleSpaceManagingAppAccess(
        space: SpaceURI,
        user: String,
        allowed: Bool,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        guard isValidSimpleSpaceDID(user) else {
            throw SwanError.invalidIdentifier(user)
        }
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space)
                let stored = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(stored.state)
                guard case let .service(subject, audience) = authorization,
                      audience == space.authority,
                      let managingApp = stored.state.space.configuration.managingApp,
                      subject == managingApp
                else {
                    throw SwanError.unauthorized("wrong managing app")
                }
                guard stored.state.space.configuration.policy == .managingApp,
                      stored.state.space.configuration.managingApp == managingApp
                else {
                    throw SwanError.unauthorized("wrong managing app")
                }
                let currentlyAllowed = stored.managingAppAllowedUsers.contains(user)
                guard currentlyAllowed != allowed else { return stored.state }
                if allowed {
                    guard stored.managingAppAllowedUsers.count
                        < Self.maximumSimpleSpaceManagingAppDecisions else {
                        throw SwanError.unavailable(
                            "simple-space managing-app decision capacity exhausted"
                        )
                    }
                    _ = try await connection.query(
                        "INSERT INTO permissioned_simple_space_managing_app_decisions(space_uri, user_did) VALUES (?, ?)",
                        [.text(space.rawValue), .text(user)]
                    )
                } else {
                    _ = try await connection.query(
                        "DELETE FROM permissioned_simple_space_managing_app_decisions WHERE space_uri = ? AND user_did = ?",
                        [.text(space.rawValue), .text(user)]
                    )
                }
                try await touchSimpleSpace(space: space, revision: stored.state.revision, timestamp: timestamp)
                return try await requiredSimpleSpace(space).state
            }
        }
    }

    /// Deletion is an authenticated, idempotent lifecycle transition. It
    /// leaves authority facts as a tombstone, so subsequent reads and
    /// credential issuance fail closed instead of allowing silent recreation.
    public func deleteSimpleSpace(
        space: SpaceURI,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space)
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .delete
                )
                let stored = try await requiredSimpleSpace(space)
                guard !stored.state.space.isDeleted else { return stored.state }
                let nextRevision = try nextSimpleSpaceRevision(stored.state.revision)
                _ = try await connection.query(
                    """
                    UPDATE permissioned_simple_space_authorities
                    SET is_deleted = 1, revision = ?,
                        updated_at = CASE WHEN updated_at > ? THEN updated_at ELSE ? END
                    WHERE space_uri = ?
                    """,
                    [
                        .integer(try sqliteRevision(nextRevision)),
                        .integer(timestamp), .integer(timestamp),
                        .text(space.rawValue),
                    ]
                )
                // The lifecycle tombstone and every registered-recipient
                // notification intent commit together.  Delivery happens
                // later through the lease worker; endpoint strings stay
                // opaque here and no record/CAR data enters the queue.
                let deletionEventID = UUID().uuidString.lowercased()
                let recipients = try await connection.query(
                    """
                    SELECT endpoint FROM permissioned_space_notification_registrations
                    WHERE space_uri = ? AND expires_at > ?
                    ORDER BY endpoint ASC
                    """,
                    [.text(space.rawValue), .integer(timestamp)]
                )
                for row in recipients {
                    let endpoint = try validNotificationEndpoint(
                        try requiredText(row, "endpoint")
                    )
                    _ = try await connection.query(
                        """
                        INSERT INTO permissioned_space_notification_fanout(
                            id, source_issuer, source_event_id, kind, space_uri,
                            repo_did, wire_revision, commitment, endpoint,
                            attempts, created_at, available_at,
                            lease_token, lease_expires_at
                        ) VALUES (?, ?, ?, 'deleted', ?, NULL, NULL, NULL, ?, 0, ?, ?, NULL, NULL)
                        ON CONFLICT(source_issuer, source_event_id, kind, endpoint) DO NOTHING
                        """,
                        [
                            .text(UUID().uuidString), .text(space.authority),
                            .text(deletionEventID), .text(space.rawValue),
                            .text(endpoint), .integer(timestamp), .integer(timestamp),
                        ]
                    )
                }
                return try await requiredSimpleSpace(space).state
            }
        }
    }

    // MARK: Authority writer set and notification registry

    /// Lists only the authority's durable writer hint after a verified space
    /// credential has bound the request to this exact space. This is not a
    /// member-list read and must never become an OAuth/public discovery path.
    public func spaceWriters(
        space: SpaceURI,
        limit: Int,
        cursor: String?,
        authorization: AuthorizationContext
    ) async throws -> [AuthorizedSpaceWriter] {
        guard (1 ... 1_000).contains(limit) else {
            throw SwanError.malformed("invalid writer page limit")
        }
        if let cursor {
            guard isValidSimpleSpaceDID(cursor) else {
                throw SwanError.malformed("invalid writer cursor")
            }
        }
        try requireAuthorityAccount(space: space)
        guard case let .spaceCredential(grant) = authorization,
              grant.space == space else {
            throw SwanError.unauthorized("space credential is required")
        }
        try grant.allows(.read)
        return try await withConnectionGate {
            try await readTransaction {
                let state = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(state.state)
                var values: [SQLiteData] = [.text(space.rawValue)]
                var cursorClause = ""
                if let cursor {
                    cursorClause = " AND repo_did > ?"
                    values.append(.text(cursor))
                }
                values.append(.integer(limit))
                let rows = try await connection.query(
                    """
                    SELECT repo_did, wire_revision, commitment
                    FROM permissioned_space_writers
                    WHERE space_uri = ?\(cursorClause)
                    ORDER BY repo_did ASC
                    LIMIT ?
                    """,
                    values
                )
                return try rows.map { row in
                    let repository = try requiredText(row, "repo_did")
                    guard isValidSimpleSpaceDID(repository) else {
                        throw SQLiteRepositoryError.corruptDatabase("invalid writer repository")
                    }
                    let wireRevision = try requiredTID(row, "wire_revision").toString()
                    let commitment = try requiredBlob(row, "commitment")
                    guard commitment.count == 32 else {
                        throw SQLiteRepositoryError.corruptDatabase("invalid writer commitment")
                    }
                    return AuthorizedSpaceWriter(
                        space: space,
                        repository: repository,
                        wireRevision: wireRevision,
                        commitment: commitment
                    )
                }
            }
        }
    }

    /// Replaces one endpoint's subscription atomically. A registration is
    /// keyed by the delivery endpoint, matching the pinned PDS. Re-registering
    /// with a different optional repo replaces it; expiry cleanup below acts
    /// as removal without accepting a broad administration endpoint.
    public func registerSpaceNotification(
        _ registration: AuthorizedSpaceNotificationRegistration,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws {
        let endpoint = try validNotificationEndpoint(registration.endpoint)
        if let repository = registration.repository {
            guard isValidSimpleSpaceDID(repository) else {
                throw SwanError.invalidIdentifier("notification repository")
            }
        }
        let timestamp = try simpleSpaceTimestamp(now)
        let expiry = try simpleSpaceTimestamp(registration.expiresAt)
        guard expiry > timestamp,
              expiry - timestamp <= 24 * 60 * 60 * 1_000_000 else {
            throw SwanError.malformed("notification registration lifetime is invalid")
        }
        try requireAuthorityAccount(space: registration.space)
        guard case let .spaceCredential(grant) = authorization,
              grant.space == registration.space else {
            throw SwanError.unauthorized("space credential is required")
        }
        try grant.allows(.read)
        try await withConnectionGate {
            try await transaction {
                let state = try await requiredSimpleSpace(registration.space)
                try requireActiveSimpleSpace(state.state)
                // Expired registrations are no longer recipients. Prune them
                // before admission so expiry immediately returns capacity and
                // the count below is part of the same write transaction.
                _ = try await connection.query(
                    """
                    DELETE FROM permissioned_space_notification_registrations
                    WHERE space_uri = ? AND expires_at <= ?
                    """,
                    [.text(registration.space.rawValue), .integer(timestamp)]
                )
                let existing = try await connection.query(
                    """
                    SELECT 1
                    FROM permissioned_space_notification_registrations
                    WHERE space_uri = ? AND endpoint = ?
                    LIMIT 1
                    """,
                    [.text(registration.space.rawValue), .text(endpoint)]
                )
                if existing.isEmpty {
                    let countRows = try await connection.query(
                        """
                        SELECT COUNT(*) AS registration_count
                        FROM permissioned_space_notification_registrations
                        WHERE space_uri = ?
                        """,
                        [.text(registration.space.rawValue)]
                    )
                    guard let countRow = countRows.first,
                          try requiredNonnegativeInteger(countRow, "registration_count")
                              < Self.maximumNotificationRegistrationsPerSpace else {
                        throw SwanError.unavailable(
                            "notification registration capacity exhausted"
                        )
                    }
                }
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_space_notification_registrations(
                        space_uri, endpoint, repo_did, expires_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(space_uri, endpoint) DO UPDATE SET
                        repo_did = excluded.repo_did,
                        expires_at = excluded.expires_at,
                        updated_at = excluded.updated_at
                    """,
                    [
                        .text(registration.space.rawValue), .text(endpoint),
                        registration.repository.map(SQLiteData.text) ?? .null,
                        .integer(expiry), .integer(timestamp),
                    ]
                )
            }
        }
    }

    /// Checks the durable registration immediately before a fanout transport
    /// uses it. A replaced, expired, or future removed registration turns a
    /// leased fanout row into a safe no-op rather than allowing a stale queue
    /// entry to keep sending to an endpoint after policy has changed.
    public func isSpaceNotificationRegistrationActive(
        space: SpaceURI,
        endpoint: String,
        repository: String?,
        now: Date = Date()
    ) async throws -> Bool {
        let endpoint = try validNotificationEndpoint(endpoint)
        if let repository {
            guard isValidSimpleSpaceDID(repository) else {
                throw SwanError.invalidIdentifier("notification repository")
            }
        }
        let timestamp = try simpleSpaceTimestamp(now)
        try requireAuthorityAccount(space: space)
        return try await withConnectionGate {
            try await readTransaction {
                let rows = try await connection.query(
                    """
                    SELECT repo_did, expires_at
                    FROM permissioned_space_notification_registrations
                    WHERE space_uri = ? AND endpoint = ?
                    """,
                    [.text(space.rawValue), .text(endpoint)]
                )
                guard let row = rows.first,
                      try requiredNonnegativeInteger(row, "expires_at") > timestamp else {
                    return false
                }
                let selectedRepository = row.column("repo_did")?.string
                // A repo-specific registration receives matching writes;
                // deletions (`repository == nil`) notify every still-active
                // recipient because the authority is no longer available to
                // send a later lifecycle signal.
                return repository == nil || selectedRepository == nil || selectedRepository == repository
            }
        }
    }

    /// Accepts a service-authenticated write announcement at the authority.
    /// Duplicate receipt IDs and stale TIDs are successful no-ops; an equal
    /// TID with a different commitment is a fail-closed conflict. The durable
    /// writer state and all fanout intents commit before any network delivery.
    public func receiveSpaceWriteNotification(
        _ notification: AuthorizedSpaceWriteNotification,
        now: Date = Date()
    ) async throws {
        guard notification.issuer == notification.repository,
              notification.audience == notification.space.authority,
              isValidSimpleSpaceDID(notification.repository),
              isValidSimpleSpaceDID(notification.issuer),
              (try? TID(tidString: notification.wireRevision)) != nil,
              notification.commitment.count == 32 else {
            throw SwanError.unauthorized("invalid write notification")
        }
        let eventID = try validServiceEventID(notification.eventID)
        let timestamp = try simpleSpaceTimestamp(now)
        try requireAuthorityAccount(space: notification.space)
        try await withConnectionGate {
            try await transaction {
                let state = try await requiredSimpleSpace(notification.space)
                try requireActiveSimpleSpace(state.state)
                guard state.state.space.members.contains(notification.repository) else {
                    throw SwanError.unauthorized("writer is not a space member")
                }

                let receipt = try await connection.query(
                    """
                    SELECT 1 FROM permissioned_space_notification_receipts
                    WHERE issuer = ? AND event_id = ? AND space_uri = ?
                    """,
                    [
                        .text(notification.issuer), .text(eventID),
                        .text(notification.space.rawValue),
                    ]
                )
                guard receipt.isEmpty else { return }

                let existing = try await connection.query(
                    """
                    SELECT wire_revision, commitment
                    FROM permissioned_space_writers
                    WHERE space_uri = ? AND repo_did = ?
                    """,
                    [.text(notification.space.rawValue), .text(notification.repository)]
                )
                var advancesWriter = true
                if let row = existing.first {
                    let currentRevision = try requiredTID(row, "wire_revision").toString()
                    let currentCommitment = try requiredBlob(row, "commitment")
                    guard currentCommitment.count == 32 else {
                        throw SQLiteRepositoryError.corruptDatabase("invalid writer commitment")
                    }
                    if notification.wireRevision < currentRevision {
                        advancesWriter = false
                    } else if notification.wireRevision == currentRevision {
                        guard currentCommitment == notification.commitment else {
                            throw SwanError.conflict(expected: 0, actual: 1)
                        }
                        advancesWriter = false
                    }
                }

                // The durable writer row is the replay-safe monotonic state.
                // Do not retain a unique receipt for every reordered stale
                // event; it cannot affect the state after this point.
                guard advancesWriter else { return }

                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_space_notification_receipts(
                        issuer, event_id, space_uri, received_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    [
                        .text(notification.issuer), .text(eventID),
                        .text(notification.space.rawValue), .integer(timestamp),
                    ]
                )
                _ = try await connection.query(
                    """
                    DELETE FROM permissioned_space_notification_receipts
                    WHERE issuer = ? AND space_uri = ? AND event_id != ?
                    """,
                    [
                        .text(notification.issuer),
                        .text(notification.space.rawValue),
                        .text(eventID),
                    ]
                )

                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_space_writers(
                        space_uri, repo_did, wire_revision, commitment, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(space_uri, repo_did) DO UPDATE SET
                        wire_revision = excluded.wire_revision,
                        commitment = excluded.commitment,
                        updated_at = excluded.updated_at
                    """,
                    [
                        .text(notification.space.rawValue), .text(notification.repository),
                        .text(notification.wireRevision), blob(notification.commitment),
                        .integer(timestamp),
                    ]
                )

                // Do not enqueue an authority-signed `notifyWrite` fanout.
                // The pinned TypeScript receiver requires `iss == repo`, but
                // this authority has only its own key and cannot truthfully
                // sign for another member writer. Registrations remain local
                // discovery/authority state; cross-host write fanout awaits a
                // compatible upstream receiver contract. Deletion fanout is
                // separate and remains authority-signed by definition.
            }
        }
    }

    /// Records a verified deletion only on the selected local recipient
    /// account. This alpha intentionally does not invent a remote-space row:
    /// the tombstone is an isolated receipt used to reject later fanout state,
    /// not a substitute for remote operation application.
    public func receiveSpaceDeletionNotification(
        space: SpaceURI,
        issuer: String,
        audience: String,
        eventID: String,
        now: Date = Date()
    ) async throws {
        guard issuer == space.authority, audience == accountDID,
              isValidSimpleSpaceDID(issuer) else {
            throw SwanError.unauthorized("invalid space deletion notification")
        }
        let eventID = try validServiceEventID(eventID)
        let timestamp = try simpleSpaceTimestamp(now)
        try await withConnectionGate {
            try await transaction {
                // The deletion service JWT names no space: it carries only
                // `iss`, `aud`, `lxm`, `jti` and time claims, and the verifier
                // keeps no replay cache by design. The route can therefore
                // only require that the body space's authority equals the
                // issuer, so one valid token would otherwise mint a permanent
                // tombstone — and a permanent receipt, since receipt identity
                // includes `space_uri` — for every SpaceURI under that
                // authority. The pinned receiver bounds this by no-oping
                // unless the recipient already knows the space
                // (`packages/pds/src/api/com/atproto/space/notifySpaceDeleted.ts:33-34`).
                // Participation here is the same pair of facts the hosted
                // space projection reports: an authority row this account
                // owns, or a local repository row it authored.
                let participation = try await connection.query(
                    """
                    SELECT 1
                    FROM permissioned_repository_state
                    WHERE space_uri = ? AND author_did = ?
                    UNION ALL
                    SELECT 1
                    FROM permissioned_simple_space_authorities
                    WHERE space_uri = ? AND owner_did = ?
                    LIMIT 1
                    """,
                    [
                        .text(space.rawValue), .text(accountDID),
                        .text(space.rawValue), .text(accountDID),
                    ]
                )
                guard !participation.isEmpty else { return }
                let tombstones = try await connection.query(
                    """
                    SELECT 1
                    FROM permissioned_space_recipient_tombstones
                    WHERE space_uri = ?
                    """,
                    [.text(space.rawValue)]
                )
                // A tombstone is terminal. Future event IDs are no-ops and
                // must not create an unbounded replay-receipt stream.
                guard tombstones.isEmpty else { return }
                let duplicate = try await connection.query(
                    """
                    SELECT 1
                    FROM permissioned_space_notification_receipts
                    WHERE issuer = ? AND event_id = ? AND space_uri = ?
                    """,
                    [
                        .text(issuer), .text(eventID), .text(space.rawValue),
                    ]
                )
                guard duplicate.isEmpty else { return }
                _ = try await connection.query(
                    """
                    DELETE FROM permissioned_space_notification_receipts
                    WHERE issuer = ? AND space_uri = ?
                    """,
                    [.text(issuer), .text(space.rawValue)]
                )
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_space_notification_receipts(
                        issuer, event_id, space_uri, received_at
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(issuer, event_id, space_uri) DO NOTHING
                    """,
                    [.text(issuer), .text(eventID), .text(space.rawValue), .integer(timestamp)]
                )
                // A recipient may retain a local repository for its own
                // writes in this remote space. Persist a closure rather than
                // creating a synthetic remote authority row or applying any
                // remote operation. All local repository read/write entry
                // points consult this tombstone, and stale writer outbox rows
                // are removed in the same transaction so a later restart
                // cannot announce a deleted repository.
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_space_recipient_tombstones(
                        space_uri, authority_did, deletion_event_id, closed_at
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(space_uri) DO NOTHING
                    """,
                    [
                        .text(space.rawValue), .text(issuer), .text(eventID),
                        .integer(timestamp),
                    ]
                )
                _ = try await connection.query(
                    "DELETE FROM permissioned_space_outbox WHERE space_uri = ?",
                    [.text(space.rawValue)]
                )
            }
        }
    }

    /// Evaluates persisted policy facts in a read transaction before the
    /// caller mints a transient read credential. The supplied authorization
    /// context is already verified by the OAuth/delegation layer, but it must
    /// still name the user for whom a credential is being minted. It never
    /// mutates membership or carries policy state in memory across a restart.
    public func authorizeSimpleSpaceRead(
        space: SpaceURI,
        user: String,
        clientID: String?,
        authorization: AuthorizationContext
    ) async throws {
        guard isValidSimpleSpaceDID(user) else {
            throw SwanError.invalidIdentifier(user)
        }
        if let clientID { try validateSimpleSpaceAppIdentifier(clientID) }
        try requireAuthorityAccount(space: space)
        try await withConnectionGate {
            try await readTransaction {
                try requireSimpleSpaceCredentialRequester(
                    space: space,
                    user: user,
                    authorization: authorization
                )
                let stored = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(stored.state)
                switch stored.state.space.configuration.appAccess {
                case .open:
                    break
                case let .allowList(clients):
                    guard let clientID, clients.contains(clientID) else {
                        throw SimpleSpaceCredentialPolicyError.appNotAuthorized
                    }
                }
                switch stored.state.space.configuration.policy {
                case .public:
                    break
                case .memberList:
                    guard stored.state.space.members.contains(user) else {
                        throw SwanError.unauthorized("user is not a space member")
                    }
                case .managingApp:
                    guard stored.managingAppAllowedUsers.contains(user) else {
                        throw SwanError.unauthorized("managing app denied user access")
                    }
                }
            }
        }
    }

    // MARK: Durable blob namespace

    public func put(
        _ data: Data,
        namespace: BlobNamespace
    ) async throws -> BlobReference {
        try await putBlob(data, namespace: namespace)
    }

    public func data(for reference: BlobReference) async throws -> Data {
        try await blobData(for: reference)
    }

    public func publicData(cid: String) async throws -> Data? {
        try await publicBlobData(cid: cid)
    }

    public func remove(_ reference: BlobReference) async throws {
        try await removeBlobReference(reference)
    }

    public func putBlob(
        _ data: Data,
        namespace: BlobNamespace,
        mimeType: String? = nil
    ) async throws -> BlobReference {
        let cid = CID.fromBlob(data).string
        let digestHex = try blobDigestHex(cid: cid, allowLegacy: false)
        let byteCount = try blobByteCount(data.count)
        let storedMIMEType = safeBlobMIMEType(mimeType)
        let columns = blobNamespaceColumns(namespace)
        return try await withPrivateBlobLifecycleLock(digestHex: digestHex) {
            try await putBlobLocked(
                .memory(data),
                cid: cid,
                digestHex: digestHex,
                byteCount: byteCount,
                namespace: namespace,
                namespaceKind: columns.kind,
                spaceURI: columns.spaceURI,
                mimeType: storedMIMEType
            )
        }
    }

    /// Streams an upload into an anonymous owner-only spool, hashes it while
    /// it arrives, and adopts it into the same durable CAS/reference
    /// transaction used by ordinary blob writes. No request-sized `Data` is
    /// created, and every failure path closes the descriptor and leaves no
    /// reachable public reference.
    public func putStreaming(
        namespace: BlobNamespace,
        mimeType: String?,
        maximumBytes: Int,
        source: @escaping @Sendable (
            @escaping (Data) async throws -> Void
        ) async throws -> Void
    ) async throws -> BlobReference {
        guard maximumBytes > 0 else {
            throw SwanError.malformed("blob upload limit is invalid")
        }
        if case .staged = namespace {
            // The account creating the pressure clears it. Sweeping before
            // admission also means an abandoned edge cannot keep an account
            // at its reference ceiling — the quota leak is the half of this
            // that bites even when nothing confidential is involved.
            try await purgeExpiredStagedBlobReferences()
            try await purgeUnreferencedPublicBlobReferences()
        }
        let spoolHandle = try SQLiteProtectedPaths.makeUnlinkedPublicBlobSpool(
            in: dataDirectory
        )
        let spool = SQLiteBlobUploadSpool(
            handle: spoolHandle,
            maximumBytes: maximumBytes
        )
        defer { spool.close() }

        let sink: (Data) async throws -> Void = { chunk in
            try spool.append(chunk)
        }
        try await source(sink)
        let summary = try spool.finish()
        guard summary.byteCount > 0 else {
            throw SwanError.malformed("blob upload is empty")
        }
        let cid = CID(
            codec: .raw,
            multihash: Multihash(
                algorithm: Multihash.sha256Code,
                length: Multihash.sha256Length,
                digest: summary.digest
            )
        )
        let digestHex = Hex.encode(summary.digest)
        let columns = blobNamespaceColumns(namespace)
        return try await withPrivateBlobLifecycleLock(digestHex: digestHex) {
            try await putBlobLocked(
                .file(
                    descriptor: spool.fileDescriptor,
                    length: summary.byteCount,
                    digest: summary.digest
                ),
                cid: cid.string,
                digestHex: digestHex,
                byteCount: summary.byteCount,
                namespace: namespace,
                namespaceKind: columns.kind,
                spaceURI: columns.spaceURI,
                mimeType: safeBlobMIMEType(mimeType)
            )
        }
    }

    public func blobData(for reference: BlobReference) async throws -> Data {
        let columns = blobNamespaceColumns(reference.namespace)
        let stored = try await blobPayload(
            cid: reference.cid,
            namespaceKind: columns.kind,
            spaceURI: columns.spaceURI
        )
        return try await materializeBlobData(stored)
    }

    /// Streams one already-reachable blob without turning the export path
    /// into a whole-payload `Data` allocation. CAS-v1 blobs use the same
    /// descriptor-backed body as HTTP. Legacy SQLite rows are still selected
    /// through bounded SQLite substr() slices and remain subject to the
    /// caller's aggregate byte bound. Ordinary compatibility reads may still
    /// materialize a legacy row so they can migrate it to CAS.
    public func streamBlobData(
        for reference: BlobReference,
        maximumBytes: Int,
        consume: @escaping @Sendable (Data) async throws -> Void
    ) async throws {
        guard maximumBytes >= 0 else {
            throw SwanError.malformed("blob export limit is invalid")
        }
        let columns = blobNamespaceColumns(reference.namespace)
        let stored = try await blobPayload(
            cid: reference.cid,
            namespaceKind: columns.kind,
            spaceURI: columns.spaceURI,
            includeLegacyPayload: false
        )
        guard stored.byteCount <= maximumBytes else {
            throw SwanError.unavailable("blob exceeds export limits")
        }
        switch stored.storageKind {
        case .legacySQLite:
            try await streamLegacySQLiteBlobData(
                stored: stored,
                namespaceKind: columns.kind,
                spaceURI: columns.spaceURI,
                consume: consume
            )
        case .casV1:
            let body = try await fileBackedBlobBody(stored)
            try await body.streamBody(
                maximumChunkBytes: SpaceCARBodySpool.maximumChunkBytes,
                consume: consume
            )
        }
    }

    public func publicBlobData(cid: String) async throws -> Data? {
        guard let stored = try await blobPayloadIfReachable(
            cid: cid,
            namespaceKind: "public",
            spaceURI: ""
        ) else {
            return nil
        }
        return try await materializeBlobData(stored)
    }

    /// Opens an already reachable public CAS entry as a verified one-shot
    /// stream. Legacy SQLite payload rows are intentionally not exposed by
    /// this path: serving them through `Data` would violate the bounded-memory
    /// public transfer contract, so they fail closed until migrated by an
    /// explicit maintenance operation.
    public func publicBlob(cid: String) async throws -> PublicBlob? {
        _ = try canonicalRawBlobCID(cid)
        guard let stored = try await publicBlobMetadataIfReachable(
            cid: cid,
            namespaceKind: "public",
            spaceURI: ""
        ) else {
            return nil
        }
        let body = try await fileBackedBlobBody(stored)
        return PublicBlob(mimeType: stored.mimeType, body: body)
    }

    public func publicBlobExists(cid: String) async throws -> Bool {
        _ = try canonicalRawBlobCID(cid)
        return try await publicBlobMetadataIfReachable(
            cid: cid,
            namespaceKind: "public",
            spaceURI: ""
        ) != nil
    }

    public func publicBlobMetadata(cid: String) async throws -> PublicBlobMetadata? {
        _ = try canonicalRawBlobCID(cid)
        guard let stored = try await publicBlobMetadataIfReachable(
            cid: cid,
            namespaceKind: "public",
            spaceURI: ""
        ) else {
            return nil
        }
        return PublicBlobMetadata(mimeType: stored.mimeType, size: stored.byteCount)
    }

    /// Metadata for a staged upload or an already-public blob, so the
    /// authenticated mutation surface can check a record's declared
    /// `size`/`mimeType` before signing the commit that promotes it.
    ///
    /// This deliberately does not open a body and is not reachable from the
    /// anonymous read allow-list; the promotion itself still happens inside
    /// the commit transaction, which re-derives reachability under the same
    /// serialization boundary.
    public func uploadedBlobMetadata(cid: String) async throws -> PublicBlobMetadata? {
        _ = try canonicalRawBlobCID(cid)
        if let stored = try await publicBlobMetadataIfReachable(
            cid: cid,
            namespaceKind: "public",
            spaceURI: ""
        ) {
            return PublicBlobMetadata(mimeType: stored.mimeType, size: stored.byteCount)
        }
        guard let staged = try await publicBlobMetadataIfReachable(
            cid: cid,
            namespaceKind: "staged",
            spaceURI: ""
        ) else {
            return nil
        }
        return PublicBlobMetadata(mimeType: staged.mimeType, size: staged.byteCount)
    }

    /// Drops staged upload edges older than
    /// ``stagedBlobReferenceLifetimeSeconds`` and reclaims any payload they
    /// were the last reference to.
    ///
    /// This runs at startup and again before each new staged upload, so the
    /// account that creates staging pressure is the one that clears it. If
    /// neither ever happens again the residue is still bounded — a staged
    /// edge is never anonymously reachable, and
    /// ``AccountBlobQuota/maximumReferences`` caps how many can exist — so a
    /// missing sweep degrades to a quota cost, never to disclosure.
    @discardableResult
    public func purgeExpiredStagedBlobReferences(
        now: Date = Date()
    ) async throws -> Int {
        let cutoff = Int(now.timeIntervalSince1970)
            - Self.stagedBlobReferenceLifetimeSeconds
        let expired = try await withConnectionGate {
            try await connection.query(
                """
                SELECT cid FROM blob_namespace_references
                WHERE namespace_kind = 'staged'
                  AND created_at IS NOT NULL AND created_at < ?
                ORDER BY created_at ASC
                LIMIT ?
                """,
                [
                    .integer(cutoff),
                    .integer(Self.maximumStagedBlobReferencePurge),
                ]
            )
        }
        var purged = 0
        for row in expired {
            guard let cid = row.column("cid")?.string else { continue }
            // `removeBlobReference` owns the per-digest lifecycle lock, the
            // remaining-reference check, and the crash-safe unlink. A CID a
            // concurrent commit has already promoted simply deletes nothing.
            try await removeBlobReference(
                BlobReference(cid: cid, namespace: .staged)
            )
            purged += 1
        }
        return purged
    }

    /// Collects public blob edges that no public repository record justifies.
    ///
    /// This is the garbage collection the blob-isolation design named as owed
    /// and never shipped: nothing but a successful permissioned commit has
    /// ever removed a public edge, so an upload that was never committed — or
    /// whose record was later deleted — held its edge, its CAS file, and its
    /// slice of ``AccountBlobQuota`` forever, with no operator recourse.
    ///
    /// A candidate must satisfy all four of:
    /// - `namespace_kind = 'public'`;
    /// - `created_at` older than ``publicBlobReferenceGracePeriodSeconds``, so
    ///   an ordinary upload-then-commit sequence is never a candidate at all;
    /// - no `space` edge for the same CID, so a blob a permissioned record
    ///   owns is never touched by the public sweep;
    /// - absent from the public repository's own blob-link projection.
    ///
    /// The projection is computed **once per sweep** rather than per candidate.
    /// `publicRepositoryContainsBlobCIDWithoutGate` answers the same question
    /// but walks and decodes the entire record index for each CID it is asked
    /// about; `publicRepositoryBlobCIDs()` is the same walk producing the whole
    /// set, so one call decides every candidate. It is also skipped entirely
    /// when no candidate is old enough, which is the steady state.
    ///
    /// Failure is never propagated to whatever triggered the sweep. This is
    /// opportunistic maintenance: a repository too large to project, or one
    /// with no published state yet, must not fail an upload or an account
    /// open.
    @discardableResult
    public func purgeUnreferencedPublicBlobReferences(
        now: Date = Date()
    ) async throws -> Int {
        let cutoff = Int(now.timeIntervalSince1970)
            - Self.publicBlobReferenceGracePeriodSeconds
        let candidates = try await withConnectionGate {
            try await connection.query(
                """
                SELECT reference.cid AS cid
                FROM blob_namespace_references AS reference
                WHERE reference.namespace_kind = 'public'
                  AND reference.created_at IS NOT NULL
                  AND reference.created_at < ?
                  AND NOT EXISTS (
                      SELECT 1 FROM blob_namespace_references AS owned
                      WHERE owned.cid = reference.cid
                        AND owned.namespace_kind = 'space'
                  )
                ORDER BY reference.created_at ASC
                LIMIT ?
                """,
                [
                    .integer(cutoff),
                    .integer(Self.maximumPublicBlobReferencePurge),
                ]
            )
        }
        guard !candidates.isEmpty else { return 0 }

        let referenced: Set<String>
        do {
            referenced = Set(try await publicRepositoryBlobCIDs().map(\.string))
        } catch {
            // A repository that cannot be projected right now keeps every
            // edge. Collecting on a partial answer would delete live blobs.
            return 0
        }

        var purged = 0
        for row in candidates {
            guard let cid = row.column("cid")?.string,
                  !referenced.contains(cid) else {
                continue
            }
            try await removeBlobReference(
                BlobReference(cid: cid, namespace: .public)
            )
            purged += 1
        }
        return purged
    }

    public func removeBlobReference(_ reference: BlobReference) async throws {
        let columns = blobNamespaceColumns(reference.namespace)
        let digestHex = try blobDigestHex(cid: reference.cid, allowLegacy: true)
        try await withPrivateBlobLifecycleLock(digestHex: digestHex) {
            let needsReclamation = try await withConnectionGate {
                try await transaction {
                    let metadata = try await blobPayloadIfReachableWithoutGate(
                        cid: reference.cid,
                        namespaceKind: columns.kind,
                        spaceURI: columns.spaceURI
                    )
                    _ = try await connection.query(
                        """
                        DELETE FROM blob_namespace_references
                        WHERE cid = ? AND namespace_kind = ? AND space_uri = ?
                        """,
                        [
                            .text(reference.cid), .text(columns.kind),
                            .text(columns.spaceURI),
                        ]
                    )
                    let remaining = try await connection.query(
                        "SELECT 1 FROM blob_namespace_references WHERE cid = ? LIMIT 1",
                        [.text(reference.cid)]
                    )
                    guard remaining.isEmpty else { return false }

                    // Reachability changes commit before a file unlink.  The
                    // durable `reclaiming` intent survives a crash between
                    // these two effects and is reconciled at startup or by
                    // this request after COMMIT.
                    _ = try await connection.query(
                        "DELETE FROM blob_payloads WHERE cid = ?",
                        [.text(reference.cid)]
                    )
                    guard metadata?.storageKind == .casV1 else { return false }
                    if try await hasFileBackedPayloadWithoutGate(digestHex: digestHex) {
                        // Another logical CID (for example a legacy sha256
                        // alias) still reaches the same physical CAS file.
                        try await setBlobLifecycleStateWithoutGate(
                            digestHex: digestHex,
                            state: .ready
                        )
                        return false
                    }
                    try await setBlobLifecycleStateWithoutGate(
                        digestHex: digestHex,
                        state: .reclaiming
                    )
                    return true
                }
            }
            if needsReclamation {
                if let hook = testingHooks.afterBlobReclaimCommit {
                    try await hook()
                }
                try await reconcilePrivateBlobLifecycleLocked(
                    digestHex: digestHex
                )
            }
        }
    }

    /// Opens only a private, exact namespace reference for the streaming
    /// permissioned blob surface.  `getBlob` passes a canonical raw CID; a
    /// legacy `sha256:` compatibility row is deliberately impossible to reach
    /// here even if it has a valid private reference.
    public func permissionedBlob(
        space: SpaceURI,
        author: String,
        cid: String
    ) async throws -> AuthorizedSpaceBlob? {
        try requireAccount(author)
        guard author == accountDID else {
            throw SwanError.unauthorized("account database ownership mismatch")
        }
        _ = try canonicalRawBlobCID(cid)
        let stored = try await withConnectionGate {
            try await readTransaction {
                try await requireReadablePermissionedBlobRepository(space)
                return try await blobPayloadIfReachableWithoutGate(
                    cid: cid,
                    namespaceKind: "space",
                    spaceURI: space.rawValue
                )
            }
        }
        guard let stored else {
            return nil
        }
        let body = try await fileBackedBlobBody(stored)
        return AuthorizedSpaceBlob(mimeType: stored.mimeType, body: body)
    }

    /// The declared length of the same private, exact namespace reference
    /// ``permissionedBlob`` would open, read without selecting a payload and
    /// without opening a file-backed body.
    ///
    /// Every gate ``permissionedBlob`` applies is applied here in the same
    /// order — account ownership, canonical raw CID, the connection gate, the
    /// read transaction, and repository readability — so this cannot answer a
    /// request the streaming form would refuse.
    public func permissionedBlobMetadata(
        space: SpaceURI,
        author: String,
        cid: String
    ) async throws -> AuthorizedSpaceBlobMetadata? {
        try requireAccount(author)
        guard author == accountDID else {
            throw SwanError.unauthorized("account database ownership mismatch")
        }
        _ = try canonicalRawBlobCID(cid)
        let stored = try await withConnectionGate {
            try await readTransaction {
                try await requireReadablePermissionedBlobRepository(space)
                return try await blobPayloadIfReachableWithoutGate(
                    cid: cid,
                    namespaceKind: "space",
                    spaceURI: space.rawValue,
                    includeLegacyPayload: false
                )
            }
        }
        guard let stored else {
            return nil
        }
        return AuthorizedSpaceBlobMetadata(size: stored.byteCount)
    }

    private struct StoredBlobPayload: Sendable {
        enum StorageKind: String, Sendable {
            case legacySQLite = "legacy-sqlite"
            case casV1 = "cas-v1"
        }

        let cid: String
        let storageKind: StorageKind
        let byteCount: Int
        let mimeType: String?
        let casDigest: String?
        let legacyPayload: Data?
    }

    private enum BlobCASLifecycleState: String, Sendable {
        case creating
        case ready
        case reclaiming
    }

    private enum BlobCASPreparation: Sendable {
        case existingCAS
        case staging
    }

    private enum BlobCASPayloadSource: Sendable {
        case memory(Data)
        case file(descriptor: Int32, length: Int, digest: Data)
    }

    /// Holds both halves of the lifecycle lock over a file stage/adoption and
    /// its SQLite commit.  The async coordinator is required even though a
    /// descriptor `flock` is also held: same-process `flock` behavior for
    /// independently opened descriptors is not sufficiently portable to be
    /// the only exclusion mechanism.
    private func withPrivateBlobLifecycleLock<T: Sendable>(
        digestHex: String,
        _ body: () async throws -> T
    ) async throws -> T {
        let key = SQLiteBlobLifecycleCoordinator.Key(
            dataDirectory: dataDirectory.path,
            accountNamespace: accountBlobNamespace,
            digestHex: digestHex
        )
        await sqliteBlobLifecycleCoordinator.acquire(key)
        var descriptor: Int32 = -1
        do {
            descriptor = try SQLiteProtectedPaths.openPrivateBlobLifecycleLock(
                accountDirectoryDescriptor: accountDirectoryDescriptor,
                accountNamespace: accountBlobNamespace,
                digestHex: digestHex
            )
        } catch {
            await sqliteBlobLifecycleCoordinator.release(key)
            throw error
        }
        do {
            let result = try await body()
            SQLiteProtectedPaths.closePrivateBlobLifecycleLock(descriptor)
            await sqliteBlobLifecycleCoordinator.release(key)
            return result
        } catch {
            SQLiteProtectedPaths.closePrivateBlobLifecycleLock(descriptor)
            await sqliteBlobLifecycleCoordinator.release(key)
            throw error
        }
    }

    private func putBlobLocked(
        _ source: BlobCASPayloadSource,
        cid: String,
        digestHex: String,
        byteCount: Int,
        namespace: BlobNamespace,
        namespaceKind: String,
        spaceURI: String,
        mimeType: String?,
        restoreRepositorySpace: SpaceURI? = nil
    ) async throws -> BlobReference {
        let preparation: BlobCASPreparation = try await withConnectionGate {
            try await transaction {
                if let restoreRepositorySpace {
                    guard namespaceKind == "space",
                          spaceURI == restoreRepositorySpace.rawValue else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "portable blob restore namespace is invalid"
                        )
                    }
                    try await requirePortableBlobRestoreRepository(
                        restoreRepositorySpace
                    )
                }
                switch try await blobStorageKindWithoutGate(cid: cid) {
                case .casV1:
                    try await setBlobLifecycleStateWithoutGate(
                        digestHex: digestHex,
                        state: .ready
                    )
                    return .existingCAS
                case .legacySQLite:
                    // A valid v4 legacy row uses the historical sha256 label,
                    // never a raw CID. Treat a collision as durable
                    // corruption rather than overwriting it.
                    throw SQLiteRepositoryError.corruptDatabase(
                        "raw blob CID collides with legacy storage"
                    )
                case nil:
                    // Persist the creation intent before touching the file.
                    // A crash now has no reference and recovery can reclaim
                    // either a missing or a partially staged CAS entry.
                    try await setBlobLifecycleStateWithoutGate(
                        digestHex: digestHex,
                        state: .creating
                    )
                    return .staging
                }
            }
        }

        do {
            switch preparation {
            case .existingCAS:
                try verifyPrivateBlobFile(
                    digestHex: digestHex,
                    expectedLength: byteCount
                )
            case .staging:
                let created: Bool
                switch source {
                case let .memory(data):
                    created = try SQLiteProtectedPaths.createPrivateBlob(
                        accountDirectoryDescriptor: accountDirectoryDescriptor,
                        accountNamespace: accountBlobNamespace,
                        digestHex: digestHex,
                        payload: data
                    )
                case let .file(descriptor, length, digest):
                    created = try SQLiteProtectedPaths.createPrivateBlobFromFile(
                        accountDirectoryDescriptor: accountDirectoryDescriptor,
                        accountNamespace: accountBlobNamespace,
                        digestHex: digestHex,
                        sourceDescriptor: descriptor,
                        expectedLength: length,
                        expectedDigest: digest
                    )
                }
                if !created {
                    // An unreferenced orphan can be adopted only after a full
                    // digest/length check while this CID lock is held.
                    try verifyPrivateBlobFile(
                        digestHex: digestHex,
                        expectedLength: byteCount
                    )
                }
            }

            if let hook = testingHooks.beforeBlobReferenceCommit {
                try await hook()
            }
            try await withConnectionGate {
                try await transaction {
                    if let restoreRepositorySpace {
                        try await requirePortableBlobRestoreRepository(
                            restoreRepositorySpace
                        )
                    }
                    try await admitBlobQuotaWithoutGate(
                        cid: cid,
                        byteCount: byteCount,
                        references: [(
                            namespaceKind: namespaceKind,
                            spaceURI: spaceURI,
                        )]
                    )
                    _ = try await connection.query(
                        """
                        INSERT INTO blob_payloads(
                            cid, payload, storage_kind, cas_digest, byte_count, mime_type
                        ) VALUES (?, zeroblob(0), 'cas-v1', ?, ?, ?)
                        ON CONFLICT(cid) DO NOTHING
                        """,
                        [
                            .text(cid), .text(digestHex), .integer(byteCount),
                            mimeType.map(SQLiteData.text) ?? .null,
                        ]
                    )
                    // Re-creating an existing edge restarts its grace period:
                    // the second upload is a fresh, equally unclaimed intent,
                    // and refreshing a timer can never widen reachability —
                    // it only delays collection.
                    _ = try await connection.query(
                        """
                        INSERT INTO blob_namespace_references(
                            cid, namespace_kind, space_uri, created_at
                        ) VALUES (?, ?, ?, ?)
                        ON CONFLICT(cid, namespace_kind, space_uri)
                        DO UPDATE SET created_at = excluded.created_at
                        """,
                        [
                            .text(cid), .text(namespaceKind), .text(spaceURI),
                            .integer(Int(Date().timeIntervalSince1970)),
                        ]
                    )
                    try await setBlobLifecycleStateWithoutGate(
                        digestHex: digestHex,
                        state: .ready
                    )
                }
            }
        } catch {
            if preparation == .staging {
                // Keep a durable reclaiming intent until the file has been
                // safely unlinked. If the transaction outcome is uncertain,
                // reconciliation rechecks metadata before deletion.
                try? await abandonPrivateBlobCreationLocked(
                    digestHex: digestHex
                )
            }
            throw error
        }
        return BlobReference(cid: cid, namespace: namespace)
    }

    /// Admits one payload and every planned reference edge against the
    /// committed account graph.
    /// The caller owns `BEGIN IMMEDIATE`, so two actors or processes cannot
    /// both observe the same remaining capacity and oversubscribe it. Existing
    /// payloads and exact references contribute zero, preserving CAS dedup.
    func admitBlobQuotaWithoutGate(
        cid: String,
        byteCount: Int,
        references: [(namespaceKind: String, spaceURI: String)]
    ) async throws {
        let existingPayload = try await connection.query(
            "SELECT byte_count FROM blob_payloads WHERE cid = ? LIMIT 1",
            [.text(cid)]
        )
        if let row = existingPayload.first {
            guard let storedByteCount = row.column("byte_count")?.integer,
                  storedByteCount == byteCount
            else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "blob quota payload metadata does not match content"
                )
            }
        }
        var addedReferences = 0
        var uniqueReferences = Set<String>()
        for reference in references {
            let key = "\(reference.namespaceKind)\u{0}\(reference.spaceURI)"
            guard uniqueReferences.insert(key).inserted else { continue }
            let existingReference = try await connection.query(
                """
                SELECT 1 FROM blob_namespace_references
                WHERE cid = ? AND namespace_kind = ? AND space_uri = ?
                LIMIT 1
                """,
                [
                    .text(cid), .text(reference.namespaceKind),
                    .text(reference.spaceURI),
                ]
            )
            if existingReference.isEmpty {
                let (next, overflow) = addedReferences.addingReportingOverflow(1)
                guard !overflow else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "blob quota reference plan overflowed"
                    )
                }
                addedReferences = next
            }
        }
        let usageRows = try await connection.query(
            """
            SELECT
                COALESCE((SELECT SUM(byte_count) FROM blob_payloads), 0)
                    AS unique_bytes,
                (SELECT COUNT(*) FROM blob_namespace_references)
                    AS reference_count
            """
        )
        guard usageRows.count == 1,
              let uniqueBytes = usageRows[0].column("unique_bytes")?.integer,
              let referenceCount = usageRows[0].column("reference_count")?.integer,
              uniqueBytes >= 0, referenceCount >= 0
        else {
            throw SQLiteRepositoryError.corruptDatabase(
                "blob quota usage is invalid"
            )
        }
        let addedBytes = existingPayload.isEmpty ? byteCount : 0
        let (admittedBytes, byteOverflow) = uniqueBytes.addingReportingOverflow(
            addedBytes
        )
        guard !byteOverflow, admittedBytes <= blobQuota.maximumUniqueBytes else {
            throw BlobQuotaError.uniqueBytesExceeded(
                limit: blobQuota.maximumUniqueBytes
            )
        }
        let (admittedReferences, referenceOverflow) = referenceCount
            .addingReportingOverflow(addedReferences)
        guard !referenceOverflow,
              admittedReferences <= blobQuota.maximumReferences else {
            throw BlobQuotaError.referenceCountExceeded(
                limit: blobQuota.maximumReferences
            )
        }
    }

    private func blobStorageKindWithoutGate(
        cid: String
    ) async throws -> StoredBlobPayload.StorageKind? {
        let rows = try await connection.query(
            "SELECT storage_kind FROM blob_payloads WHERE cid = ?",
            [.text(cid)]
        )
        guard let row = rows.first else { return nil }
        guard let storageKind = StoredBlobPayload.StorageKind(
            rawValue: try requiredText(row, "storage_kind")
        ) else {
            throw SQLiteRepositoryError.corruptDatabase("invalid blob storage kind")
        }
        return storageKind
    }

    private func hasFileBackedPayloadWithoutGate(
        digestHex: String
    ) async throws -> Bool {
        let rows = try await connection.query(
            """
            SELECT 1
            FROM blob_payloads
            WHERE storage_kind = 'cas-v1' AND cas_digest = ?
            LIMIT 1
            """,
            [.text(digestHex)]
        )
        return !rows.isEmpty
    }

    private func blobLifecycleStateWithoutGate(
        digestHex: String
    ) async throws -> BlobCASLifecycleState? {
        let rows = try await connection.query(
            "SELECT state FROM blob_cas_lifecycle WHERE digest_hex = ?",
            [.text(digestHex)]
        )
        guard let row = rows.first else { return nil }
        guard let state = BlobCASLifecycleState(
            rawValue: try requiredText(row, "state")
        ) else {
            throw SQLiteRepositoryError.corruptDatabase("invalid blob lifecycle state")
        }
        return state
    }

    private func setBlobLifecycleStateWithoutGate(
        digestHex: String,
        state: BlobCASLifecycleState
    ) async throws {
        _ = try await connection.query(
            """
            INSERT INTO blob_cas_lifecycle(digest_hex, state, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(digest_hex) DO UPDATE SET
                state = excluded.state,
                updated_at = excluded.updated_at
            """,
            [
                .text(digestHex), .text(state.rawValue),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    private func abandonPrivateBlobCreationLocked(
        digestHex: String
    ) async throws {
        let needsReclamation = try await withConnectionGate {
            try await transaction {
                if try await hasFileBackedPayloadWithoutGate(digestHex: digestHex) {
                    try await setBlobLifecycleStateWithoutGate(
                        digestHex: digestHex,
                        state: .ready
                    )
                    return false
                }
                try await setBlobLifecycleStateWithoutGate(
                    digestHex: digestHex,
                    state: .reclaiming
                )
                return true
            }
        }
        if needsReclamation {
            try await reconcilePrivateBlobLifecycleLocked(
                digestHex: digestHex
            )
        }
    }

    private func reconcilePrivateBlobLifecycleLocked(
        digestHex: String
    ) async throws {
        let shouldUnlink = try await withConnectionGate {
            try await transaction {
                let hasPayload = try await hasFileBackedPayloadWithoutGate(
                    digestHex: digestHex
                )
                let lifecycle = try await blobLifecycleStateWithoutGate(
                    digestHex: digestHex
                )
                if hasPayload {
                    // A re-reference won the CID lock before this reconciler.
                    // Preserve its CAS and clear the stale reclaim intent.
                    if lifecycle != .ready {
                        try await setBlobLifecycleStateWithoutGate(
                            digestHex: digestHex,
                            state: .ready
                        )
                    }
                    return false
                }
                guard lifecycle != nil else { return false }
                if lifecycle != .reclaiming {
                    try await setBlobLifecycleStateWithoutGate(
                        digestHex: digestHex,
                        state: .reclaiming
                    )
                }
                return true
            }
        }
        guard shouldUnlink else { return }

        // Filesystem effects are intentionally outside the SQLite
        // transaction.  The already-committed reclaiming state makes a crash
        // here recoverable without ever pointing a live reference at a
        // missing file.
        try SQLiteProtectedPaths.removePrivateBlob(
            accountDirectoryDescriptor: accountDirectoryDescriptor,
            accountNamespace: accountBlobNamespace,
            digestHex: digestHex
        )
        try await withConnectionGate {
            try await transaction {
                guard try await hasFileBackedPayloadWithoutGate(digestHex: digestHex) == false,
                      try await blobLifecycleStateWithoutGate(digestHex: digestHex) == .reclaiming
                else {
                    return
                }
                _ = try await connection.query(
                    "DELETE FROM blob_cas_lifecycle WHERE digest_hex = ?",
                    [.text(digestHex)]
                )
            }
        }
    }

    private func recoverPrivateBlobLifecycle() async throws {
        let candidates = try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT digest_hex
                FROM blob_cas_lifecycle
                WHERE state != 'ready'
                ORDER BY digest_hex
                """
            )
            return try rows.map { try requiredText($0, "digest_hex") }
        }
        for digestHex in candidates {
            guard legacyBlobDigest("sha256:\(digestHex)") != nil else {
                throw SQLiteRepositoryError.corruptDatabase("invalid blob lifecycle digest")
            }
            try await withPrivateBlobLifecycleLock(digestHex: digestHex) {
                try await reconcilePrivateBlobLifecycleLocked(
                    digestHex: digestHex
                )
            }
        }
    }

    private func verifyPrivateBlobFile(
        digestHex: String,
        expectedLength: Int
    ) throws {
        guard let expectedDigest = legacyBlobDigest("sha256:\(digestHex)") else {
            throw SQLiteRepositoryError.corruptDatabase("invalid CAS blob digest")
        }
        guard let lease = externalBodyLeases.acquire() else {
            throw SwanError.unavailable(
                "permissioned blob storage is unavailable"
            )
        }
        var descriptor: Int32 = -1
        do {
            descriptor = try SQLiteProtectedPaths.openPrivateBlob(
                accountDirectoryDescriptor: accountDirectoryDescriptor,
                accountNamespace: accountBlobNamespace,
                digestHex: digestHex
            )
            let body = try SQLiteVerifiedSpaceBlobBody(
                descriptor: descriptor,
                expectedDigest: expectedDigest,
                expectedLength: expectedLength,
                externalLease: lease
            )
            body.discardUnstreamed()
        } catch {
            SQLiteProtectedPaths.closeDirectory(descriptor)
            lease.release()
            throw error
        }
    }

    private func blobPayload(
        cid: String,
        namespaceKind: String,
        spaceURI: String,
        includeLegacyPayload: Bool = true
    ) async throws -> StoredBlobPayload {
        guard let stored = try await blobPayloadIfReachable(
            cid: cid,
            namespaceKind: namespaceKind,
            spaceURI: spaceURI,
            includeLegacyPayload: includeLegacyPayload
        ) else {
            throw SwanError.unauthorized("blob is not reachable in this namespace")
        }
        return stored
    }

    private func blobPayloadIfReachable(
        cid: String,
        namespaceKind: String,
        spaceURI: String,
        includeLegacyPayload: Bool = true
    ) async throws -> StoredBlobPayload? {
        try await withConnectionGate {
            try await blobPayloadIfReachableWithoutGate(
                cid: cid,
                namespaceKind: namespaceKind,
                spaceURI: spaceURI,
                includeLegacyPayload: includeLegacyPayload
            )
        }
    }

    /// Metadata-only lookup for bounded HTTP projections.  Selecting the
    /// legacy SQLite payload here would let a public request materialize an
    /// arbitrarily large row before the caller can fail closed.  The public
    /// streaming surface therefore accepts only CAS-v1 rows and verifies the
    /// reference, digest, length, and MIME metadata without selecting
    /// `payload` at all.
    private func publicBlobMetadataIfReachable(
        cid: String,
        namespaceKind: String,
        spaceURI: String
    ) async throws -> StoredBlobPayload? {
        try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT blob_payloads.cid, blob_payloads.storage_kind,
                       blob_payloads.cas_digest, blob_payloads.byte_count,
                       blob_payloads.mime_type
                FROM blob_payloads
                JOIN blob_namespace_references USING(cid)
                WHERE blob_payloads.cid = ? AND namespace_kind = ? AND space_uri = ?
                """,
                [.text(cid), .text(namespaceKind), .text(spaceURI)]
            )
            guard let row = rows.first else { return nil }
            let storedCID = try requiredText(row, "cid")
            guard storedCID == cid,
                  try requiredText(row, "storage_kind") == StoredBlobPayload.StorageKind.casV1.rawValue else {
                throw SwanError.unavailable("public blob storage is unavailable")
            }
            guard let byteValue = row.column("byte_count"),
                  !byteValue.isNull,
                  let byteCount = byteValue.integer,
                  byteCount >= 0 else {
                throw SQLiteRepositoryError.corruptDatabase("missing public blob size")
            }
            let digest = try blobDigestHex(cid: storedCID, allowLegacy: false)
            guard let storedDigest = row.column("cas_digest")?.string,
                  storedDigest == digest,
                  legacyBlobDigest("sha256:\(storedDigest)") != nil else {
                throw SQLiteRepositoryError.corruptDatabase("invalid public blob CID")
            }
            let mimeType: String?
            if let value = row.column("mime_type"), !value.isNull {
                guard let raw = value.string else {
                    throw SQLiteRepositoryError.corruptDatabase("invalid public blob MIME type")
                }
                mimeType = safeBlobMIMEType(raw)
            } else {
                mimeType = nil
            }
            return StoredBlobPayload(
                cid: storedCID,
                storageKind: .casV1,
                byteCount: byteCount,
                mimeType: mimeType,
                casDigest: storedDigest,
                legacyPayload: nil
            )
        }
    }

    private func blobPayloadIfReachableWithoutGate(
        cid: String,
        namespaceKind: String,
        spaceURI: String,
        includeLegacyPayload: Bool = true
    ) async throws -> StoredBlobPayload? {
        // The legacy payload is selected only by compatibility reads that
        // explicitly need a materialized value. Export streaming uses the
        // metadata-only form and reads bounded substr() slices below, so a
        // historical SQLite row cannot become an unbounded Data allocation.
        let payloadSelection = includeLegacyPayload
            ? "blob_payloads.payload"
            : "NULL AS payload"
        let rows = try await connection.query(
            """
            SELECT blob_payloads.cid, \(payloadSelection),
                   blob_payloads.storage_kind, blob_payloads.cas_digest,
                   blob_payloads.byte_count,
                   length(blob_payloads.payload) AS payload_length,
                   blob_payloads.mime_type
            FROM blob_payloads
            JOIN blob_namespace_references USING(cid)
            WHERE blob_payloads.cid = ? AND namespace_kind = ? AND space_uri = ?
            """,
            [.text(cid), .text(namespaceKind), .text(spaceURI)]
        )
        guard let row = rows.first else { return nil }
        let storedCID = try requiredText(row, "cid")
        guard storedCID == cid,
              let storageKind = StoredBlobPayload.StorageKind(
                  rawValue: try requiredText(row, "storage_kind")
              )
        else {
            throw SQLiteRepositoryError.corruptDatabase("invalid blob metadata")
        }
        let storedByteCount: Int
        if let value = row.column("byte_count"), !value.isNull {
            guard let integer = value.integer, integer >= 0 else {
                throw SQLiteRepositoryError.corruptDatabase("invalid blob size")
            }
            storedByteCount = integer
        } else if storageKind == .legacySQLite {
            guard let payloadLength = row.column("payload_length")?.integer,
                  payloadLength >= 0 else {
                throw SQLiteRepositoryError.corruptDatabase("invalid legacy blob size")
            }
            storedByteCount = payloadLength
        } else {
            throw SQLiteRepositoryError.corruptDatabase("missing blob size")
        }
        let mimeType: String?
        if let value = row.column("mime_type"), !value.isNull {
            guard let raw = value.string else {
                throw SQLiteRepositoryError.corruptDatabase("invalid blob MIME type")
            }
            mimeType = safeBlobMIMEType(raw)
        } else {
            mimeType = nil
        }
        let legacyPayload: Data?
        let casDigest: String?
        switch storageKind {
        case .legacySQLite:
            if includeLegacyPayload {
                let payload = try requiredBlob(row, "payload")
                guard legacyBlobCID(payload) == storedCID,
                      payload.count == storedByteCount else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "legacy blob payload does not match metadata"
                    )
                }
                legacyPayload = payload
            } else {
                legacyPayload = nil
            }
            casDigest = nil
        case .casV1:
            let digest = try blobDigestHex(cid: storedCID, allowLegacy: true)
            guard let storedDigest = row.column("cas_digest")?.string,
                  storedDigest == digest,
                  legacyBlobDigest("sha256:\(storedDigest)") != nil else {
                throw SQLiteRepositoryError.corruptDatabase("invalid CAS blob CID")
            }
            legacyPayload = nil
            casDigest = storedDigest
        }
        return StoredBlobPayload(
            cid: storedCID,
            storageKind: storageKind,
            byteCount: storedByteCount,
            mimeType: mimeType,
            casDigest: casDigest,
            legacyPayload: legacyPayload
        )
    }

    /// Streams a historical SQLite blob without selecting its payload as a
    /// client-side Data value. SQLite's substr() operates on the BLOB inside
    /// the engine and returns one bounded chunk per query. A read transaction
    /// keeps the metadata, chunks, and digest verification on one snapshot;
    /// the caller's consumer is invoked only with the current chunk.
    private func streamLegacySQLiteBlobData(
        stored: StoredBlobPayload,
        namespaceKind: String,
        spaceURI: String,
        consume: @escaping @Sendable (Data) async throws -> Void
    ) async throws {
        guard stored.storageKind == .legacySQLite,
              stored.legacyPayload == nil,
              let expectedDigest = legacyBlobDigest(stored.cid) else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid legacy blob metadata"
            )
        }
        try await withConnectionGate {
            try await readTransaction {
                var offset = 0
                var digest = SHA256()
                let chunkSize = SpaceCARBodySpool.maximumChunkBytes
                while offset < stored.byteCount {
                    try Task.checkCancellation()
                    let rows = try await connection.query(
                        """
                        SELECT substr(blob_payloads.payload, ?, ?) AS chunk
                        FROM blob_payloads
                        JOIN blob_namespace_references USING(cid)
                        WHERE blob_payloads.cid = ?
                          AND namespace_kind = ? AND space_uri = ?
                        """,
                        [
                            .integer(offset + 1), .integer(chunkSize),
                            .text(stored.cid), .text(namespaceKind),
                            .text(spaceURI),
                        ]
                    )
                    guard let row = rows.first else {
                        throw SwanError.unauthorized(
                            "blob is not reachable in this namespace"
                        )
                    }
                    let chunk = try requiredBlob(row, "chunk")
                    guard !chunk.isEmpty,
                          chunk.count <= min(chunkSize, stored.byteCount - offset) else {
                        throw SQLiteRepositoryError.corruptDatabase(
                            "invalid legacy blob chunk"
                        )
                    }
                    digest.update(data: chunk)
                    try await consume(chunk)
                    offset += chunk.count
                }
                guard Data(digest.finalize()) == expectedDigest else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "legacy blob payload does not match metadata"
                    )
                }
            }
        }
    }

    private func materializeBlobData(_ stored: StoredBlobPayload) async throws -> Data {
        switch stored.storageKind {
        case .legacySQLite:
            guard let payload = stored.legacyPayload else {
                throw SQLiteRepositoryError.corruptDatabase("missing legacy blob payload")
            }
            guard legacyBlobCID(payload) == stored.cid,
                  payload.count == stored.byteCount else {
                throw SQLiteRepositoryError.corruptDatabase("invalid legacy blob payload")
            }
            if !portableExportReadOnly {
                try await migrateLegacyBlobToCAS(stored, payload: payload)
            }
            return payload
        case .casV1:
            let body = try await fileBackedBlobBody(stored)
            let output = SQLiteDataAccumulator(capacity: stored.byteCount)
            try await body.streamBody(maximumChunkBytes: 64 * 1_024) { chunk in
                output.append(chunk)
            }
            let data = output.data
            guard data.count == stored.byteCount else {
                throw SwanError.unavailable("permissioned blob storage is unavailable")
            }
            return data
        }
    }

    private func migrateLegacyBlobToCAS(
        _ stored: StoredBlobPayload,
        payload: Data
    ) async throws {
        guard stored.storageKind == .legacySQLite,
              legacyBlobCID(payload) == stored.cid,
              payload.count == stored.byteCount else {
            throw SQLiteRepositoryError.corruptDatabase("invalid legacy blob migration")
        }
        let digestHex = try blobDigestHex(cid: stored.cid, allowLegacy: true)
        try await withPrivateBlobLifecycleLock(digestHex: digestHex) {
            let preparation = try await withConnectionGate {
                try await transaction {
                    switch try await blobStorageKindWithoutGate(cid: stored.cid) {
                    case .casV1:
                        return false
                    case .legacySQLite:
                        try await setBlobLifecycleStateWithoutGate(
                            digestHex: digestHex,
                            state: .creating
                        )
                        return true
                    case nil:
                        // The last authorized reference was removed after the
                        // compatibility read began. Returning its already
                        // validated payload is fine, but do not create an
                        // unreachable replacement file.
                        return false
                    }
                }
            }
            guard preparation else { return }

            do {
                let created = try SQLiteProtectedPaths.createPrivateBlob(
                    accountDirectoryDescriptor: accountDirectoryDescriptor,
                    accountNamespace: accountBlobNamespace,
                    digestHex: digestHex,
                    payload: payload
                )
                if !created {
                    try verifyPrivateBlobFile(
                        digestHex: digestHex,
                        expectedLength: stored.byteCount
                    )
                }
                if let hook = testingHooks.beforeLegacyBlobMigrationCommit {
                    try await hook()
                }
                try await withConnectionGate {
                    try await transaction {
                        guard try await blobStorageKindWithoutGate(cid: stored.cid) == .legacySQLite else {
                            throw SQLiteRepositoryError.corruptDatabase(
                                "legacy blob changed during migration"
                            )
                        }
                        _ = try await connection.query(
                            """
                            UPDATE blob_payloads
                            SET payload = zeroblob(0), storage_kind = 'cas-v1',
                                cas_digest = ?, byte_count = ?
                            WHERE cid = ? AND storage_kind = 'legacy-sqlite'
                            """,
                            [
                                .text(digestHex), .integer(stored.byteCount),
                                .text(stored.cid),
                            ]
                        )
                        try await setBlobLifecycleStateWithoutGate(
                            digestHex: digestHex,
                            state: .ready
                        )
                    }
                }
            } catch {
                try? await abandonPrivateBlobCreationLocked(
                    digestHex: digestHex
                )
                throw error
            }
        }
    }

    private func fileBackedBlobBody(
        _ stored: StoredBlobPayload
    ) async throws -> SQLiteVerifiedSpaceBlobBody {
        guard stored.storageKind == .casV1 else {
            throw SQLiteRepositoryError.corruptDatabase("blob is not file backed")
        }
        guard let digestHex = stored.casDigest else {
            throw SQLiteRepositoryError.corruptDatabase("missing CAS blob digest")
        }
        guard let digest = legacyBlobDigest("sha256:\(digestHex)") else {
            throw SQLiteRepositoryError.corruptDatabase("invalid CAS blob digest")
        }
        guard let lease = externalBodyLeases.acquire() else {
            throw SwanError.unavailable(
                "permissioned blob storage is unavailable"
            )
        }
        var descriptor: Int32 = -1
        do {
            descriptor = try SQLiteProtectedPaths.openPrivateBlob(
                accountDirectoryDescriptor: accountDirectoryDescriptor,
                accountNamespace: accountBlobNamespace,
                digestHex: digestHex
            )
            return try SQLiteVerifiedSpaceBlobBody(
                descriptor: descriptor,
                expectedDigest: digest,
                expectedLength: stored.byteCount,
                externalLease: lease
            )
        } catch {
            SQLiteProtectedPaths.closeDirectory(descriptor)
            lease.release()
            throw error
        }
    }

    /// Stores both the committed operation and its notification intent in one
    /// transaction. Dispatch must happen after this method returns; it is never
    /// awaited while SQLite holds the transaction.
    public func appendOplogAndOutbox(
        space: SpaceURI,
        revision: UInt64,
        operation: Data,
        commitment: Data,
        eventID: UUID = UUID()
    ) async throws -> PersistedOutboxEvent {
        try requireAccount(space.authority)
        let storedRevision = try sqliteRevision(revision)
        let notificationPayload = opaqueNotificationPayload(eventID: eventID)
        let createdAt = try outboxTimestamp(Date())
        try await withConnectionGate {
            try await transaction {
                try await requireLocalRepositorySpaceOpen(space)
                _ = try await connection.query(
                    "INSERT INTO space_oplog(space_uri, revision, operation, commitment) VALUES (?, ?, ?, ?)",
                    [
                        .text(space.rawValue), .integer(storedRevision),
                        blob(operation), blob(commitment),
                    ]
                )
                _ = try await connection.query(
                    """
                INSERT INTO permissioned_space_outbox(
                    id, space_uri, author_did, revision,
                    payload, attempts, created_at, available_at,
                    lease_token, lease_expires_at
                ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, NULL, NULL)
                """,
                [
                    .text(eventID.uuidString), .text(space.rawValue),
                        .text(space.authority), .integer(storedRevision),
                        blob(notificationPayload),
                        .integer(createdAt), .integer(createdAt),
                ]
                )
            }
        }
        return PersistedOutboxEvent(
            id: eventID,
            space: space,
            author: space.authority,
            revision: revision,
            payload: notificationPayload,
            attempts: 0
        )
    }

    /// Atomically claims the oldest notification that is eligible for delivery.
    /// An expired lease is eligible again after a process crash. This method
    /// contains only SQLite work: callers must invoke a transport only after it
    /// returns and complete or fail the lease with the exact token below.
    public func leaseNextOutbox(
        now: Date = Date(),
        leaseDuration: TimeInterval
    ) async throws -> PersistedOutboxLease? {
        let nowTimestamp = try outboxTimestamp(now)
        let leaseExpiry = try outboxTimestamp(
            now.addingTimeInterval(try validOutboxInterval(leaseDuration, name: "lease duration"))
        )
        return try await withConnectionGate {
            try await transaction {
                let token = UUID()
                let rows = try await connection.query(
                    """
                    SELECT id, space_uri, author_did, revision, payload, attempts,
                           lease_token, lease_expires_at
                    FROM permissioned_space_outbox
                    WHERE available_at <= ?
                      AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                    ORDER BY available_at, created_at, id
                    LIMIT 1
                    """,
                    [.integer(nowTimestamp), .integer(nowTimestamp)]
                )
                guard let row = rows.first else { return nil }
                let event = try decodeOutboxEvent(row)
                _ = try decodeOutboxLease(row)
                _ = try await connection.query(
                    """
                    UPDATE permissioned_space_outbox
                    SET lease_token = ?, lease_expires_at = ?
                    WHERE id = ?
                    """,
                    [
                        .text(token.uuidString), .integer(leaseExpiry),
                        .text(event.id.uuidString),
                    ]
                )
                return PersistedOutboxLease(
                    event: event,
                    token: token,
                    expiresAt: Date(timeIntervalSince1970: Double(leaseExpiry) / 1_000_000)
                )
            }
        }
    }

    /// Deletes an event only if the caller still owns its durable lease. A
    /// stale worker can therefore never acknowledge an event reclaimed by a
    /// later worker after its lease expired.
    @discardableResult
    public func completeOutboxLease(
        eventID: UUID,
        token: UUID
    ) async throws -> Bool {
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT id, space_uri, author_did, revision, payload, attempts,
                           lease_token, lease_expires_at
                    FROM permissioned_space_outbox
                    WHERE id = ?
                    """,
                    [.text(eventID.uuidString)]
                )
                guard let row = rows.first else { return false }
                _ = try decodeOutboxEvent(row)
                let lease = try decodeOutboxLease(row)
                guard lease.token == token
                else {
                    return false
                }
                _ = try await connection.query(
                    "DELETE FROM permissioned_space_outbox WHERE id = ? AND lease_token = ?",
                    [.text(eventID.uuidString), .text(token.uuidString)]
                )
                return true
            }
        }
    }

    /// Records a failed delivery only while the same lease is current, then
    /// clears that lease and makes the opaque event eligible at `retryAt`.
    /// Returning `nil` means another worker reclaimed or completed the event.
    @discardableResult
    public func failOutboxLease(
        eventID: UUID,
        token: UUID,
        retryAt: Date
    ) async throws -> Int? {
        let retryTimestamp = try outboxTimestamp(retryAt)
        return try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT id, space_uri, author_did, revision, payload, attempts,
                           lease_token, lease_expires_at
                    FROM permissioned_space_outbox
                    WHERE id = ?
                    """,
                    [.text(eventID.uuidString)]
                )
                guard let row = rows.first else { return nil }
                let event = try decodeOutboxEvent(row)
                let lease = try decodeOutboxLease(row)
                guard lease.token == token
                else {
                    return nil
                }
                guard event.attempts < Int.max else {
                    throw SQLiteRepositoryError.corruptDatabase("outbox attempts overflow")
                }
                let nextAttempts = event.attempts + 1
                _ = try await connection.query(
                    """
                    UPDATE permissioned_space_outbox
                    SET attempts = ?, available_at = ?,
                        lease_token = NULL, lease_expires_at = NULL
                    WHERE id = ? AND lease_token = ?
                    """,
                    [
                        .integer(nextAttempts), .integer(retryTimestamp),
                        .text(eventID.uuidString), .text(token.uuidString),
                    ]
                )
                return nextAttempts
            }
        }
    }

    public func pendingOutbox(limit: Int = 100) async throws -> [PersistedOutboxEvent] {
        guard limit >= 0 else {
            throw SwanError.malformed("outbox limit must not be negative")
        }
        return try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT id, space_uri, author_did, revision, payload, attempts,
                       lease_token, lease_expires_at
                FROM permissioned_space_outbox
                ORDER BY created_at, id
                LIMIT ?
                """,
                [.integer(limit)]
            )
            return try rows.map { row in
                _ = try decodeOutboxLease(row)
                return try decodeOutboxEvent(row)
            }
        }
    }

    /// Claims one durable authority fanout intent. It deliberately mirrors the
    /// commit outbox lease API rather than sharing its table: registrations are
    /// authority-owned, while a commit outbox is owned by the writer PDS.
    public func leaseNextNotificationFanout(
        now: Date = Date(),
        leaseDuration: TimeInterval
    ) async throws -> PersistedSpaceNotificationFanoutLease? {
        let nowTimestamp = try outboxTimestamp(now)
        let leaseExpiry = try outboxTimestamp(
            now.addingTimeInterval(try validOutboxInterval(leaseDuration, name: "lease duration"))
        )
        return try await withConnectionGate {
            try await transaction {
                let token = UUID()
                let rows = try await connection.query(
                    """
                    SELECT id, source_issuer, source_event_id, kind, space_uri,
                           repo_did, wire_revision, commitment, endpoint, attempts,
                           lease_token, lease_expires_at
                    FROM permissioned_space_notification_fanout
                    WHERE available_at <= ?
                      AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                    ORDER BY available_at, created_at, id
                    LIMIT 1
                    """,
                    [.integer(nowTimestamp), .integer(nowTimestamp)]
                )
                guard let row = rows.first else { return nil }
                let event = try decodeNotificationFanout(row)
                _ = try decodeNotificationFanoutLease(row)
                _ = try await connection.query(
                    """
                    UPDATE permissioned_space_notification_fanout
                    SET lease_token = ?, lease_expires_at = ?
                    WHERE id = ?
                    """,
                    [.text(token.uuidString), .integer(leaseExpiry), .text(event.id.uuidString)]
                )
                return PersistedSpaceNotificationFanoutLease(
                    event: event,
                    token: token,
                    expiresAt: Date(timeIntervalSince1970: Double(leaseExpiry) / 1_000_000)
                )
            }
        }
    }

    @discardableResult
    public func completeNotificationFanoutLease(
        eventID: UUID,
        token: UUID
    ) async throws -> Bool {
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT id, source_issuer, source_event_id, kind, space_uri,
                           repo_did, wire_revision, commitment, endpoint, attempts,
                           lease_token, lease_expires_at
                    FROM permissioned_space_notification_fanout WHERE id = ?
                    """,
                    [.text(eventID.uuidString)]
                )
                guard let row = rows.first else { return false }
                _ = try decodeNotificationFanout(row)
                let lease = try decodeNotificationFanoutLease(row)
                guard lease.token == token else { return false }
                _ = try await connection.query(
                    "DELETE FROM permissioned_space_notification_fanout WHERE id = ? AND lease_token = ?",
                    [.text(eventID.uuidString), .text(token.uuidString)]
                )
                return true
            }
        }
    }

    @discardableResult
    public func failNotificationFanoutLease(
        eventID: UUID,
        token: UUID,
        retryAt: Date
    ) async throws -> Int? {
        let retryTimestamp = try outboxTimestamp(retryAt)
        return try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT id, source_issuer, source_event_id, kind, space_uri,
                           repo_did, wire_revision, commitment, endpoint, attempts,
                           lease_token, lease_expires_at
                    FROM permissioned_space_notification_fanout WHERE id = ?
                    """,
                    [.text(eventID.uuidString)]
                )
                guard let row = rows.first else { return nil }
                let event = try decodeNotificationFanout(row)
                let lease = try decodeNotificationFanoutLease(row)
                guard lease.token == token else { return nil }
                guard event.attempts < Int.max else {
                    throw SQLiteRepositoryError.corruptDatabase("notification fanout attempts overflow")
                }
                let nextAttempts = event.attempts + 1
                _ = try await connection.query(
                    """
                    UPDATE permissioned_space_notification_fanout
                    SET attempts = ?, available_at = ?,
                        lease_token = NULL, lease_expires_at = NULL
                    WHERE id = ? AND lease_token = ?
                    """,
                    [
                        .integer(nextAttempts), .integer(retryTimestamp),
                        .text(eventID.uuidString), .text(token.uuidString),
                    ]
                )
                return nextAttempts
            }
        }
    }

    public func pendingNotificationFanout(
        limit: Int = 100
    ) async throws -> [PersistedSpaceNotificationFanout] {
        guard (0 ... 10_000).contains(limit) else {
            throw SwanError.malformed("notification fanout limit is invalid")
        }
        return try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT id, source_issuer, source_event_id, kind, space_uri,
                       repo_did, wire_revision, commitment, endpoint, attempts,
                       lease_token, lease_expires_at
                FROM permissioned_space_notification_fanout
                ORDER BY created_at, id LIMIT ?
                """,
                [.integer(limit)]
            )
            return try rows.map { row in
                _ = try decodeNotificationFanoutLease(row)
                return try decodeNotificationFanout(row)
            }
        }
    }

    // MARK: Transaction and decoding helpers

    func withConnectionGate<T: Sendable>(
        _ body: () async throws -> T
    ) async throws -> T {
        if ProcessInfo.processInfo.environment["SWAN_SYNC_STAGE_LOG"] == "1" {
            FileHandle.standardError.write(Data("[sqlite] gate acquire\n".utf8))
        }
        await connectionGate.acquire()
        do {
            let result = try await body()
            await connectionGate.release()
            if ProcessInfo.processInfo.environment["SWAN_SYNC_STAGE_LOG"] == "1" {
                FileHandle.standardError.write(Data("[sqlite] gate release\n".utf8))
            }
            return result
        } catch {
            await connectionGate.release()
            if ProcessInfo.processInfo.environment["SWAN_SYNC_STAGE_LOG"] == "1" {
                FileHandle.standardError.write(Data("[sqlite] gate release\n".utf8))
            }
            throw error
        }
    }

    func transaction<T: Sendable>(
        _ body: () async throws -> T
    ) async throws -> T {
        _ = try await connection.query("BEGIN IMMEDIATE")
        activeWriteTransactions += 1
        do {
            let result = try await body()
            _ = try await connection.query("COMMIT")
            activeWriteTransactions -= 1
            return result
        } catch {
            _ = try? await connection.query("ROLLBACK")
            activeWriteTransactions -= 1
            throw error
        }
    }

    func readTransaction<T: Sendable>(
        _ body: () async throws -> T
    ) async throws -> T {
        _ = try await connection.query("BEGIN")
        do {
            let result = try await body()
            _ = try await connection.query("COMMIT")
            return result
        } catch {
            _ = try? await connection.query("ROLLBACK")
            throw error
        }
    }

    /// Owns the connection-local canonical-path projection for exactly one CAR
    /// read. Callers already hold `connectionGate`; cleanup therefore happens
    /// after the read transaction has committed or rolled back and before any
    /// other operation can reuse this SQLite connection.
    private func withRepositoryCARIndexTable<T: Sendable>(
        _ body: () async throws -> T
    ) async throws -> T {
        _ = try await connection.query(
            "DROP TABLE IF EXISTS temp.swan_repository_car_index"
        )
        try Task.checkCancellation()
        _ = try await connection.query(
            """
            CREATE TEMP TABLE swan_repository_car_index (
                path_length INTEGER NOT NULL,
                path_bytes BLOB NOT NULL,
                collection TEXT NOT NULL,
                rkey TEXT NOT NULL,
                cid TEXT NOT NULL,
                emitted INTEGER NOT NULL DEFAULT 0
                    CHECK(emitted IN (0, 1)),
                PRIMARY KEY(path_length, path_bytes)
            ) WITHOUT ROWID
            """
        )
        _ = try await connection.query(
            """
            CREATE INDEX temp.swan_repository_car_index_cid
            ON swan_repository_car_index(cid, emitted)
            """
        )
        do {
            let result = try await body()
            _ = try await connection.query(
                "DROP TABLE temp.swan_repository_car_index"
            )
            try Task.checkCancellation()
            return result
        } catch {
            _ = try? await connection.query(
                "DROP TABLE IF EXISTS temp.swan_repository_car_index"
            )
            throw error
        }
    }

    private func requireAuthorityAccount(
        space: SpaceURI,
        owner: String? = nil
    ) throws {
        guard space.authority == accountDID else {
            throw SwanError.unauthorized(
                "simple-space authority belongs to another account"
            )
        }
        if let owner {
            guard owner == space.authority,
                  isValidSimpleSpaceDID(owner)
            else {
                throw SwanError.unauthorized(
                    "only the authority DID may own this simple space"
                )
            }
        }
    }

    private func requireAuthorityManagement(
        space: SpaceURI,
        authorization: AuthorizationContext,
        operation: SimpleSpaceManagementOperation
    ) throws {
        try SpaceAuthorizationPolicy.requireManagement(
            space: space,
            authorization: authorization,
            operation: operation
        )
    }

    /// A credential request is made on behalf of its eventual reader. The
    /// authority must not allow an arbitrary authenticated account to mint a
    /// credential for a member merely by naming that member in the request.
    /// Service authentication is deliberately excluded: it is used only by
    /// the separately modeled managing-app decision endpoint.
    private func requireSimpleSpaceCredentialRequester(
        space: SpaceURI,
        user: String,
        authorization: AuthorizationContext
    ) throws {
        switch authorization {
        case let .accountOAuth(subject, _):
            guard subject == user else {
                throw SwanError.unauthorized(
                    "credential requester does not match the requested user"
                )
            }
        case let .spaceDelegation(subject, delegatedSpace):
            guard subject == user, delegatedSpace == space else {
                throw SwanError.unauthorized(
                    "delegation does not match the requested user or space"
                )
            }
        case let .spaceCredential(grant):
            guard grant.subject == user, grant.space == space else {
                throw SwanError.unauthorized(
                    "delegated credential does not match the requested user"
                )
            }
            try grant.allows(.read)
        case let .spaceSelfRead(subject, grantSpace):
            guard subject == user, grantSpace == space else {
                throw SwanError.unauthorized(
                    "self-read grant does not match the requested user"
                )
            }
        case .accountManagement, .accountLegacySession:
            throw SwanError.unauthorized(
                "account session cannot mint permissioned-space credentials"
            )
        case .public, .service:
            throw SwanError.unauthorized(
                "credential issuance requires a user OAuth or delegated grant"
            )
        }
    }

    private func requireActiveSimpleSpace(
        _ state: DurableSimpleSpaceState
    ) throws {
        guard !state.space.isDeleted else {
            throw AuthorizedSimpleSpaceLifecycleError.notFound
        }
    }

    private func validateSimpleSpaceConfiguration(
        _ configuration: SimpleSpaceConfiguration
    ) throws {
        switch configuration.appAccess {
        case .open:
            break
        case let .allowList(clients):
            guard clients.count <= Self.maximumSimpleSpaceClients else {
                throw SwanError.unavailable(
                    "simple-space client allow-list capacity exhausted"
                )
            }
            for client in clients {
                try validateSimpleSpaceAppIdentifier(client)
            }
        }
        // `updateSpace` patches policy and managingApp independently. Retain
        // a valid configured app through a policy-only transition exactly as
        // the pinned TypeScript store does; policy evaluation consults it only
        // for `managing-app`. Its syntax remains fail-closed in every state.
        if let managingApp = configuration.managingApp {
            try validateSimpleSpaceAppIdentifier(managingApp)
        }
    }

    private func validateSimpleSpaceAppIdentifier(
        _ identifier: String
    ) throws {
        guard !identifier.isEmpty,
              identifier.utf8.count <= 2_048,
              identifier.unicodeScalars.allSatisfy({
                  $0.value >= 0x20 && $0.value != 0x7F
              })
        else {
            throw SwanError.invalidIdentifier(identifier)
        }
    }

    /// `SpaceURI` intentionally keeps its lexical helpers file-private. Use
    /// its public throwing initializer as the one source of truth instead of
    /// copying a relaxed DID regular expression into the persistence layer.
    private func isValidSimpleSpaceDID(_ did: String) -> Bool {
        (try? SpaceURI(
            authority: did,
            spaceType: "app.swan.validation",
            skey: "did"
        )) != nil
    }

    private func simpleSpaceTimestamp(_ date: Date) throws -> Int {
        let microseconds = date.timeIntervalSince1970 * 1_000_000
        guard microseconds.isFinite,
              microseconds >= 0,
              microseconds <= Double(Int.max)
        else {
            throw SwanError.malformed("simple-space timestamp is out of range")
        }
        return Int(microseconds)
    }

    /// SQLite owns only a bounded opaque endpoint string. The HTTP transport
    /// performs the authoritative scheme/DNS/redirect policy immediately
    /// before use; keeping the lexical guard here prevents corrupt rows from
    /// becoming unbounded or control-character-bearing transport input.
    private func validNotificationEndpoint(_ value: String) throws -> String {
        guard !value.isEmpty,
              value.utf8.count <= 4_096,
              value.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }),
              let components = URLComponents(string: value),
              components.scheme != nil,
              components.host != nil,
              components.user == nil,
              components.password == nil,
              components.fragment == nil else {
            throw SwanError.malformed("notification endpoint is invalid")
        }
        return value
    }

    private func validServiceEventID(_ value: String) throws -> String {
        guard !value.isEmpty,
              value.utf8.count <= 256,
              value.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw SwanError.malformed("service notification event is invalid")
        }
        return value
    }

    private func simpleSpaceAppAccessName(
        _ appAccess: SimpleSpaceAppAccess
    ) -> String {
        switch appAccess {
        case .open: "open"
        case .allowList: "allow-list"
        }
    }

    private func requiredSimpleSpace(
        _ space: SpaceURI
    ) async throws -> LoadedSimpleSpaceAuthority {
        guard let stored = try await loadSimpleSpace(space) else {
            throw AuthorizedSimpleSpaceLifecycleError.notFound
        }
        return stored
    }

    private func loadSimpleSpace(
        _ expectedSpace: SpaceURI
    ) async throws -> LoadedSimpleSpaceAuthority? {
        let rows = try await connection.query(
            """
            SELECT space_uri, owner_did, policy, app_access, managing_app,
                   is_deleted, revision, created_at, updated_at
            FROM permissioned_simple_space_authorities
            WHERE space_uri = ?
            """,
            [.text(expectedSpace.rawValue)]
        )
        guard let row = rows.first else { return nil }
        guard rows.count == 1 else {
            throw SQLiteRepositoryError.corruptDatabase(
                "duplicate simple-space authority state"
            )
        }
        let spaceRaw = try requiredText(row, "space_uri")
        guard let space = try? SpaceURI(spaceRaw),
              space == expectedSpace,
              space.rawValue == spaceRaw,
              space.authority == accountDID
        else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space authority ownership"
            )
        }
        let owner = try requiredText(row, "owner_did")
        guard owner == space.authority, isValidSimpleSpaceDID(owner) else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space owner"
            )
        }
        let policyRaw = try requiredText(row, "policy")
        guard let policy = SimpleSpacePolicy(rawValue: policyRaw) else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space policy"
            )
        }
        let appAccessRaw = try requiredText(row, "app_access")
        guard appAccessRaw == "open" || appAccessRaw == "allow-list" else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space app access"
            )
        }
        let managingApp: String?
        if let value = row.column("managing_app"), !value.isNull {
            managingApp = try requiredText(row, "managing_app")
            try validateSimpleSpaceAppIdentifier(managingApp!)
        } else {
            managingApp = nil
        }
        let deleted = try requiredInteger(row, "is_deleted")
        guard deleted == 0 || deleted == 1 else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space deleted state"
            )
        }
        let revision = try requiredRevision(row, "revision")
        guard revision > 0 else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space revision"
            )
        }
        let createdAt = try requiredNonnegativeInteger(row, "created_at")
        let updatedAt = try requiredNonnegativeInteger(row, "updated_at")
        guard updatedAt >= createdAt else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space timestamps"
            )
        }

        let memberRows = try await connection.query(
            """
            SELECT member_did
            FROM permissioned_simple_space_members
            WHERE space_uri = ?
            ORDER BY member_did
            LIMIT ?
            """,
            [
                .text(space.rawValue),
                .integer(Self.maximumSimpleSpaceMembers + 1),
            ]
        )
        guard memberRows.count <= Self.maximumSimpleSpaceMembers else {
            throw SQLiteRepositoryError.corruptDatabase(
                "simple-space members exceed their bound"
            )
        }
        var members = Set<String>()
        for memberRow in memberRows {
            let member = try requiredText(memberRow, "member_did")
            guard isValidSimpleSpaceDID(member), members.insert(member).inserted else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "invalid simple-space member"
                )
            }
        }

        let clientRows = try await connection.query(
            """
            SELECT client_id
            FROM permissioned_simple_space_clients
            WHERE space_uri = ?
            ORDER BY client_id
            LIMIT ?
            """,
            [
                .text(space.rawValue),
                .integer(Self.maximumSimpleSpaceClients + 1),
            ]
        )
        guard clientRows.count <= Self.maximumSimpleSpaceClients else {
            throw SQLiteRepositoryError.corruptDatabase(
                "simple-space clients exceed their bound"
            )
        }
        var clients = Set<String>()
        for clientRow in clientRows {
            let clientID = try requiredText(clientRow, "client_id")
            try validateSimpleSpaceAppIdentifier(clientID)
            guard clients.insert(clientID).inserted else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "duplicate simple-space client"
                )
            }
        }
        let appAccess: SimpleSpaceAppAccess
        switch appAccessRaw {
        case "open":
            guard clients.isEmpty else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "open simple space has client restrictions"
                )
            }
            appAccess = .open
        case "allow-list":
            appAccess = .allowList(clients)
        default:
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space app access"
            )
        }
        let configuration: SimpleSpaceConfiguration
        do {
            configuration = try SimpleSpaceConfiguration(
                policy: policy,
                appAccess: appAccess,
                managingApp: managingApp
            )
            try validateSimpleSpaceConfiguration(configuration)
        } catch {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space configuration"
            )
        }

        let managingDecisionRows = try await connection.query(
            """
            SELECT user_did
            FROM permissioned_simple_space_managing_app_decisions
            WHERE space_uri = ?
            ORDER BY user_did
            LIMIT ?
            """,
            [
                .text(space.rawValue),
                .integer(Self.maximumSimpleSpaceManagingAppDecisions + 1),
            ]
        )
        guard managingDecisionRows.count
            <= Self.maximumSimpleSpaceManagingAppDecisions else {
            throw SQLiteRepositoryError.corruptDatabase(
                "simple-space managing-app decisions exceed their bound"
            )
        }
        var managingAppAllowedUsers = Set<String>()
        for decisionRow in managingDecisionRows {
            let user = try requiredText(decisionRow, "user_did")
            guard isValidSimpleSpaceDID(user),
                  managingAppAllowedUsers.insert(user).inserted
            else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "invalid simple-space managing-app decision"
                )
            }
        }
        guard policy == .managingApp || managingAppAllowedUsers.isEmpty else {
            throw SQLiteRepositoryError.corruptDatabase(
                "non-managing simple space has app decisions"
            )
        }
        let snapshot: SimpleSpace
        do {
            snapshot = try SimpleSpace(
                uri: space,
                owner: owner,
                configuration: configuration,
                members: members,
                isDeleted: deleted == 1
            )
        } catch {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space authority state"
            )
        }
        return LoadedSimpleSpaceAuthority(
            state: DurableSimpleSpaceState(space: snapshot, revision: revision),
            managingAppAllowedUsers: managingAppAllowedUsers
        )
    }

    private func replaceSimpleSpaceClients(
        space: SpaceURI,
        appAccess: SimpleSpaceAppAccess
    ) async throws {
        _ = try await connection.query(
            "DELETE FROM permissioned_simple_space_clients WHERE space_uri = ?",
            [.text(space.rawValue)]
        )
        guard case let .allowList(clients) = appAccess else { return }
        guard clients.count <= Self.maximumSimpleSpaceClients else {
            throw SwanError.unavailable(
                "simple-space client allow-list capacity exhausted"
            )
        }
        for clientID in clients.sorted() {
            _ = try await connection.query(
                "INSERT INTO permissioned_simple_space_clients(space_uri, client_id) VALUES (?, ?)",
                [.text(space.rawValue), .text(clientID)]
            )
        }
    }

    private func touchSimpleSpace(
        space: SpaceURI,
        revision: UInt64,
        timestamp: Int
    ) async throws {
        let nextRevision = try nextSimpleSpaceRevision(revision)
        _ = try await connection.query(
            """
            UPDATE permissioned_simple_space_authorities
            SET revision = ?,
                updated_at = CASE WHEN updated_at > ? THEN updated_at ELSE ? END
            WHERE space_uri = ?
            """,
            [
                .integer(try sqliteRevision(nextRevision)),
                .integer(timestamp), .integer(timestamp), .text(space.rawValue),
            ]
        )
    }

    private func nextSimpleSpaceRevision(_ revision: UInt64) throws -> UInt64 {
        guard revision < UInt64(Int.max) else {
            throw SQLiteRepositoryError.revisionOutOfRange(revision)
        }
        return revision + 1
    }

    private func requireAccount(_ author: String) throws {
        guard author == accountDID else {
            throw SwanError.unauthorized(
                "repository author belongs to another account"
            )
        }
    }

    private func validatePortableRestoreRepository(
        _ repository: SQLitePortableRestoreRepository
    ) throws {
        try requireAccount(repository.author)
        guard repository.ltHash.count == LtHash.byteCount,
              repository.commitment == Data(SHA256.hash(data: repository.ltHash)),
              repository.records == repository.records.sorted(by: {
                  ($0.uri.collection, $0.uri.rkey)
                    < ($1.uri.collection, $1.uri.rkey)
              }),
              Set(repository.records.map {
                  "\($0.uri.collection)\u{0}\($0.uri.rkey)"
              }).count == repository.records.count else {
            throw SQLiteRepositoryError.corruptDatabase(
                "portable restore repository state is invalid"
            )
        }
        var ltHash = LtHash()
        var totalBytes = 0
        for record in repository.records {
            guard record.uri.space == repository.space,
                  record.uri.author == repository.author,
                  record.revision == 1,
                  record.value.count
                    <= SpaceCARRecoveryLimits.absoluteMaximumRecordBytes,
                  totalBytes <= 1_024 * 1_024 * 1_024 - record.value.count,
                  (try? SpaceCARCodec.validateCanonicalRecord(
                    record.value,
                    expectedCID: record.cid
                  )) != nil else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "portable restore record is invalid"
                )
            }
            totalBytes += record.value.count
            ltHash.add(
                element:
                    "\(record.uri.collection)/\(record.uri.rkey)/\(record.cid)"
            )
        }
        guard ltHash.serialized == repository.ltHash,
              ltHash.commitment == repository.commitment else {
            throw SQLiteRepositoryError.corruptDatabase(
                "portable restore LtHash is invalid"
            )
        }
    }

    /// A verified authority deletion closes any local recipient repository
    /// without manufacturing remote authority state or applying remote
    /// operations. This helper is used only while an existing SQLite
    /// transaction is held, so it cannot race a deletion into a stale read or
    /// write. It intentionally does not reveal whether the receiver retained
    /// records before the closure.
    private func requireLocalRepositorySpaceOpen(_ space: SpaceURI) async throws {
        let rows = try await connection.query(
            "SELECT 1 FROM permissioned_space_recipient_tombstones WHERE space_uri = ?",
            [.text(space.rawValue)]
        )
        let restoredClosures = try await connection.query(
            """
            SELECT 1
            FROM permissioned_restored_repository_closures
            WHERE space_uri = ? AND author_did = ?
            """,
            [.text(space.rawValue), .text(accountDID)]
        )
        guard rows.isEmpty, restoredClosures.isEmpty else {
            throw SwanError.unauthorized("permissioned space is closed")
        }
    }

    /// Portable restore may stage bytes for a repository that is deliberately
    /// HTTP-closed by `missing-authority-policy-v1`. It still requires the
    /// matching account-owned repository state and rejects authority or
    /// recipient tombstones before creating lifecycle metadata, CAS content,
    /// or a namespace reference.
    private func requirePortableBlobRestoreRepository(
        _ space: SpaceURI
    ) async throws {
        let rows = try await connection.query(
            """
            SELECT 1
            FROM permissioned_repository_state AS repository
            WHERE repository.space_uri = ?
              AND repository.author_did = ?
              AND NOT EXISTS (
                  SELECT 1
                  FROM permissioned_space_recipient_tombstones AS recipient
                  WHERE recipient.space_uri = repository.space_uri
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM permissioned_simple_space_authorities AS authority
                  WHERE authority.space_uri = repository.space_uri
                    AND authority.is_deleted != 0
              )
            LIMIT 1
            """,
            [.text(space.rawValue), .text(accountDID)]
        )
        guard !rows.isEmpty else {
            throw SwanError.unauthorized(
                "permissioned repository is unavailable for blob restore"
            )
        }
    }

    /// Request-time reads are stricter than offline restore staging. The
    /// repository, tombstone/closure checks, and exact blob namespace
    /// reference are all read from the caller's one SQLite snapshot.
    private func requireReadablePermissionedBlobRepository(
        _ space: SpaceURI
    ) async throws {
        let rows = try await connection.query(
            """
            SELECT 1
            FROM permissioned_repository_state AS repository
            WHERE repository.space_uri = ?
              AND repository.author_did = ?
              AND NOT EXISTS (
                  SELECT 1
                  FROM permissioned_space_recipient_tombstones AS recipient
                  WHERE recipient.space_uri = repository.space_uri
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM permissioned_restored_repository_closures AS closure
                  WHERE closure.space_uri = repository.space_uri
                    AND closure.author_did = repository.author_did
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM permissioned_simple_space_authorities AS authority
                  WHERE authority.space_uri = repository.space_uri
                    AND authority.is_deleted != 0
              )
            LIMIT 1
            """,
            [.text(space.rawValue), .text(accountDID)]
        )
        guard !rows.isEmpty else {
            throw SwanError.unauthorized(
                "permissioned repository is unavailable for blob read"
            )
        }
    }

    private func loadState(
        space: SpaceURI,
        author: String
    ) async throws -> PersistedRepositoryState? {
        let rows = try await connection.query(
            """
            SELECT revision, wire_revision, lthash, current_commit
            FROM permissioned_repository_state
            WHERE space_uri = ? AND author_did = ?
            """,
            [.text(space.rawValue), .text(author)]
        )
        guard let row = rows.first else { return nil }
        let ltHash = try requiredBlob(row, "lthash")
        guard ltHash.count == LtHash.byteCount else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid LtHash byte count"
            )
        }
        let revision = try requiredRevision(row, "revision")
        let wireRevision = try requiredTID(row, "wire_revision")
        let marker = try requiredBlob(row, "current_commit")
        let expectedMarker = try repositoryStateMarker(
            space: space,
            author: author,
            revision: revision,
            wireRevision: wireRevision,
            commitment: Data(SHA256.hash(data: ltHash))
        )
        guard marker == expectedMarker else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid deterministic repository state marker"
            )
        }
        return PersistedRepositoryState(
            space: space,
            author: author,
            revision: revision,
            wireRevision: wireRevision,
            ltHash: ltHash,
            commit: marker
        )
    }

    private func loadRecord(
        _ uri: SpaceRecordURI
    ) async throws -> PersistedSpaceRecord? {
        let rows = try await connection.query(
            """
            SELECT collection, rkey, value, cid, revision
            FROM permissioned_space_records
            WHERE space_uri = ? AND author_did = ?
              AND collection = ? AND rkey = ?
            """,
            [
                .text(uri.space.rawValue), .text(uri.author),
                .text(uri.collection), .text(uri.rkey),
            ]
        )
        guard let row = rows.first else { return nil }
        return try decodeRecord(row, space: uri.space, author: uri.author)
    }

    private func loadRecordMetadata(
        _ uri: SpaceRecordURI
    ) async throws -> PersistedSpaceRecordMetadata? {
        let rows = try await connection.query(
            """
            SELECT collection, rkey, cid, revision
            FROM permissioned_space_records
            WHERE space_uri = ? AND author_did = ?
              AND collection = ? AND rkey = ?
            """,
            [
                .text(uri.space.rawValue), .text(uri.author),
                .text(uri.collection), .text(uri.rkey),
            ]
        )
        guard let row = rows.first else { return nil }
        let storedURI = try SpaceRecordURI(
            space: uri.space,
            author: uri.author,
            collection: try requiredText(row, "collection"),
            rkey: try requiredText(row, "rkey")
        )
        guard storedURI == uri else {
            throw SQLiteRepositoryError.corruptDatabase(
                "permissioned record metadata identity mismatch"
            )
        }
        let cid = try requiredText(row, "cid")
        guard (try? CID.parse(cid)) != nil else {
            throw SQLiteRepositoryError.corruptDatabase(
                "permissioned record metadata CID is invalid"
            )
        }
        return PersistedSpaceRecordMetadata(
            uri: storedURI,
            cid: cid,
            revision: try requiredRevision(row, "revision")
        )
    }

    private func decodeRecord(
        _ row: SQLiteRow,
        space: SpaceURI,
        author: String
    ) throws -> PersistedSpaceRecord {
        let uri = try SpaceRecordURI(
            space: space,
            author: author,
            collection: requiredText(row, "collection"),
            rkey: requiredText(row, "rkey")
        )
        return PersistedSpaceRecord(
            uri: uri,
            value: try requiredBlob(row, "value"),
            cid: try requiredText(row, "cid"),
            revision: try requiredRevision(row, "revision")
        )
    }

    private func insertOplog(
        space: SpaceURI,
        author: String,
        revision: Int,
        operationIndex: Int,
        wireRevision: TID,
        action: PersistedRepoAction,
        previousCID: String?,
        write: SQLiteSpaceWrite,
        commitment: Data
    ) async throws {
        let value: SQLiteData
        let cid: SQLiteData
        switch write {
        case let .create(_, bytes, recordCID), let .put(_, bytes, recordCID),
             let .update(_, bytes, recordCID):
            value = blob(bytes)
            cid = .text(recordCID)
        case .delete:
            value = .null
            cid = .null
        }
        _ = try await connection.query(
            """
            INSERT INTO permissioned_space_oplog(
                space_uri, author_did, revision, operation_index,
                wire_revision, action, collection, rkey,
                value, cid, previous_cid, commitment
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                .text(space.rawValue), .text(author), .integer(revision),
                .integer(operationIndex), .text(wireRevision.toString()),
                .text(action.rawValue),
                .text(write.uri.collection),
                .text(write.uri.rkey), value, cid,
                previousCID.map(SQLiteData.text) ?? .null,
                blob(commitment),
            ]
        )
    }

    private func decodeOplog(
        _ row: SQLiteRow,
        space: SpaceURI,
        author: String
    ) throws -> PersistedSpaceOplogEntry {
        let uri = try SpaceRecordURI(
            space: space,
            author: author,
            collection: requiredText(row, "collection"),
            rkey: requiredText(row, "rkey")
        )
        let write: SQLiteSpaceWrite
        let actionRaw = try requiredText(row, "action")
        guard let action = PersistedRepoAction(rawValue: actionRaw) else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid oplog action"
            )
        }
        switch action {
        case .create, .update:
            write = .put(
                uri: uri,
                value: try requiredBlob(row, "value"),
                cid: try requiredText(row, "cid")
            )
        case .delete:
            write = .delete(uri: uri)
        }
        let cid = row.column("cid")?.string
        let previousCID = row.column("previous_cid")?.string
        switch action {
        case .create where previousCID != nil:
            throw SQLiteRepositoryError.corruptDatabase(
                "create oplog entry has a previous CID"
            )
        case .update where previousCID == nil:
            throw SQLiteRepositoryError.corruptDatabase(
                "update oplog entry has no previous CID"
            )
        case .delete where previousCID == nil:
            throw SQLiteRepositoryError.corruptDatabase(
                "delete oplog entry has no previous CID"
            )
        default:
            break
        }
        return PersistedSpaceOplogEntry(
            cursor: PersistedOplogCursor(
                revision: try requiredRevision(row, "revision"),
                index: try requiredRevision(row, "operation_index")
            ),
            wireRevision: try requiredTID(row, "wire_revision"),
            action: action,
            write: write,
            cid: cid,
            previousCID: previousCID,
            commitment: try requiredBlob(row, "commitment")
        )
    }

    /// Decodes the read-side join projection.  Validate the durable action
    /// shape before HTTP has a chance to render nullable CIDs: corrupted rows
    /// must become an opaque unavailable response, not a malformed partial
    /// operation list.
    private func decodeWireOplog(
        _ row: SQLiteRow,
        space: SpaceURI,
        author: String
    ) throws -> PersistedWireOplogEntry {
        let actionRaw = try requiredText(row, "action")
        guard let action = PersistedRepoAction(rawValue: actionRaw) else {
            throw SQLiteRepositoryError.corruptDatabase("invalid oplog action")
        }
        let uri = try SpaceRecordURI(
            space: space,
            author: author,
            collection: try requiredText(row, "collection"),
            rkey: try requiredText(row, "rkey")
        )
        let cid = row.column("cid")?.string
        let previousCID = row.column("previous_cid")?.string
        let value: Data?
        if let currentValue = row.column("current_value"), !currentValue.isNull {
            guard let decoded = Data(sqliteData: currentValue) else {
                throw SQLiteRepositoryError.corruptDatabase("invalid current_value")
            }
            value = decoded
        } else {
            value = nil
        }
        switch action {
        case .create:
            guard cid != nil, previousCID == nil else {
                throw SQLiteRepositoryError.corruptDatabase("invalid create oplog entry")
            }
        case .update:
            guard cid != nil, previousCID != nil else {
                throw SQLiteRepositoryError.corruptDatabase("invalid update oplog entry")
            }
        case .delete:
            guard cid == nil, previousCID != nil, value == nil else {
                throw SQLiteRepositoryError.corruptDatabase("invalid delete oplog entry")
            }
        }
        return PersistedWireOplogEntry(
            wireRevision: try requiredTID(row, "wire_revision"),
            action: action,
            uri: uri,
            cid: cid,
            previousCID: previousCID,
            value: value
        )
    }

    private func ltHashElement(for record: PersistedSpaceRecord) -> String {
        "\(record.uri.collection)/\(record.uri.rkey)/\(record.cid)"
    }

    private func repositoryStateMarker(
        space: SpaceURI,
        author: String,
        revision: UInt64,
        wireRevision: TID,
        commitment: Data
    ) throws -> Data {
        guard revision <= UInt64(Int.max) else {
            throw SQLiteRepositoryError.revisionOutOfRange(revision)
        }
        return try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "author", value: author),
            (key: "commitment", value: commitment),
            (key: "revision", value: Int(revision)),
            (key: "space", value: space.rawValue),
            (key: "wireRevision", value: wireRevision.toString()),
        ]))
    }

    private func decodeOutboxEvent(
        _ row: SQLiteRow
    ) throws -> PersistedOutboxEvent {
        guard let id = row.column("id")?.string.flatMap(UUID.init(uuidString:)),
              let spaceRaw = row.column("space_uri")?.string,
              let author = row.column("author_did")?.string
        else {
            throw SQLiteRepositoryError.corruptDatabase("invalid outbox row")
        }
        guard author == accountDID,
              let space = try? SpaceURI(spaceRaw),
              space.rawValue == spaceRaw
        else {
            throw SQLiteRepositoryError.corruptDatabase("invalid outbox ownership")
        }
        let payload = try requiredBlob(row, "payload")
        guard payload == opaqueNotificationPayload(eventID: id) else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid opaque notification payload"
            )
        }
        return PersistedOutboxEvent(
            id: id,
            space: space,
            author: author,
            revision: try requiredRevision(row, "revision"),
            payload: payload,
            attempts: try requiredNonnegativeInteger(row, "attempts")
        )
    }

    private func decodeOutboxLease(
        _ row: SQLiteRow
    ) throws -> (token: UUID?, expiresAt: Int?) {
        let token = row.column("lease_token")
        let expiry = row.column("lease_expires_at")
        switch (token, expiry) {
        case (.some(.null), .some(.null)):
            return (nil, nil)
        case let (.some(.text(rawToken)), .some(.integer(rawExpiry))):
            guard let token = UUID(uuidString: rawToken), rawExpiry >= 0 else {
                throw SQLiteRepositoryError.corruptDatabase("invalid outbox lease")
            }
            return (token, rawExpiry)
        default:
            throw SQLiteRepositoryError.corruptDatabase("invalid outbox lease")
        }
    }

    private func decodeNotificationFanout(
        _ row: SQLiteRow
    ) throws -> PersistedSpaceNotificationFanout {
        guard let id = row.column("id")?.string.flatMap(UUID.init(uuidString:)),
              let issuer = row.column("source_issuer")?.string,
              let eventID = row.column("source_event_id")?.string,
              let kindRaw = row.column("kind")?.string,
              let kind = PersistedSpaceNotificationFanout.Kind(rawValue: kindRaw),
              let spaceRaw = row.column("space_uri")?.string,
              let space = try? SpaceURI(spaceRaw),
              space.rawValue == spaceRaw,
              let endpoint = row.column("endpoint")?.string else {
            throw SQLiteRepositoryError.corruptDatabase("invalid notification fanout row")
        }
        _ = try validServiceEventID(eventID)
        _ = try validNotificationEndpoint(endpoint)
        guard isValidSimpleSpaceDID(issuer) else {
            throw SQLiteRepositoryError.corruptDatabase("invalid notification fanout issuer")
        }
        let repository = row.column("repo_did")?.string
        let wireRevision = row.column("wire_revision")?.string
        let commitment = row.column("commitment").flatMap { column -> Data? in
            if case let .blob(data) = column { return Data(buffer: data) }
            return nil
        }
        switch kind {
        case .write:
            guard let repository,
                  isValidSimpleSpaceDID(repository),
                  let wireRevision,
                  (try? TID(tidString: wireRevision)) != nil,
                  let commitment,
                  commitment.count == 32 else {
                throw SQLiteRepositoryError.corruptDatabase("invalid write notification fanout")
            }
        case .deleted:
            guard repository == nil, wireRevision == nil, commitment == nil else {
                throw SQLiteRepositoryError.corruptDatabase("invalid deletion notification fanout")
            }
        }
        return PersistedSpaceNotificationFanout(
            id: id,
            sourceIssuer: issuer,
            sourceEventID: eventID,
            kind: kind,
            space: space,
            repository: repository,
            wireRevision: wireRevision,
            commitment: commitment,
            endpoint: endpoint,
            attempts: try requiredNonnegativeInteger(row, "attempts")
        )
    }

    private func decodeNotificationFanoutLease(
        _ row: SQLiteRow
    ) throws -> (token: UUID?, expiresAt: Int?) {
        let token = row.column("lease_token")
        let expiry = row.column("lease_expires_at")
        switch (token, expiry) {
        case (.some(.null), .some(.null)):
            return (nil, nil)
        case let (.some(.text(rawToken)), .some(.integer(rawExpiry))):
            guard let token = UUID(uuidString: rawToken), rawExpiry >= 0 else {
                throw SQLiteRepositoryError.corruptDatabase("invalid notification fanout lease")
            }
            return (token, rawExpiry)
        default:
            throw SQLiteRepositoryError.corruptDatabase("invalid notification fanout lease")
        }
    }

    private func validOutboxInterval(
        _ interval: TimeInterval,
        name: String
    ) throws -> TimeInterval {
        // Lease and retry scheduling are intentionally bounded. Long-lived
        // leases would turn a stopped worker into an avoidable availability
        // failure, while unbounded doubles could overflow SQLite timestamps.
        guard interval.isFinite, interval > 0, interval <= 86_400 else {
            throw SwanError.malformed("\(name) must be between zero and one day")
        }
        return interval
    }

    private func outboxTimestamp(_ date: Date) throws -> Int {
        let microseconds = date.timeIntervalSince1970 * 1_000_000
        guard microseconds.isFinite,
              microseconds >= 0,
              microseconds <= Double(Int.max)
        else {
            throw SwanError.malformed("outbox timestamp is out of range")
        }
        return Int(microseconds.rounded(.down))
    }

    private func opaqueNotificationPayload(eventID: UUID) -> Data {
        Data(eventID.uuidString.lowercased().utf8)
    }

    private func blobNamespaceColumns(
        _ namespace: BlobNamespace
    ) -> (kind: String, spaceURI: String) {
        switch namespace {
        case .public:
            ("public", "")
        case let .space(space):
            ("space", space.rawValue)
        case .staged:
            ("staged", "")
        }
    }

    /// Account databases share the two-hex layout shard, so the CAS must add
    /// the full DID hash before its content digest.  Otherwise two unrelated
    /// accounts that happen to share a layout prefix could race on a payload
    /// file while SQLite tracks references only in their separate databases.
    private var accountBlobNamespace: String {
        Hex.encode(SHA256.hash(data: Data(accountDID.utf8)))
    }

    private func legacyBlobCID(_ payload: Data) -> String {
        "sha256:\(Hex.encode(SHA256.hash(data: payload)))"
    }

    private func canonicalRawBlobCID(_ value: String) throws -> CID {
        let cid: CID
        do {
            cid = try CID.parse(value)
        } catch {
            throw SwanError.malformed("blob CID is invalid")
        }
        guard cid.string == value,
              cid.codec == .raw,
              cid.multihash.algorithm == Multihash.sha256Code,
              cid.multihash.length == Multihash.sha256Length,
              cid.multihash.digest.count == Int(Multihash.sha256Length) else {
            throw SwanError.malformed("blob CID is invalid")
        }
        return cid
    }

    /// Extracts raw CID links from a permissioned record before the write
    /// transaction. Raw links are the wire representation of AT blob
    /// references; DAG-CBOR links remain repository blocks and are ignored by
    /// this projection. The decoder is bounded by the already-enforced record
    /// byte limit, and the result is de-duplicated before namespace promotion.
    private func rawBlobCIDs(in value: Data) throws -> [String] {
        let decoded = try CARRepository.decodeRecordCBOR(value)
        var cids = Set<String>()

        func visitAny(_ value: Any) {
            if let link = value as? ATProtoLink,
               link.cid.codec == .raw,
               link.cid.multihash.algorithm == Multihash.sha256Code,
               link.cid.multihash.length == Multihash.sha256Length {
                cids.insert(link.cid.string)
                return
            }
            if let map = value as? OrderedCBORMap {
                for entry in map.entries { visitAny(entry.value) }
                return
            }
            if let map = value as? [String: Any] {
                for item in map.values { visitAny(item) }
                return
            }
            if let array = value as? [Any] {
                for item in array { visitAny(item) }
            }
        }

        func visit(_ value: ATProtocolValueContainer) throws {
            switch value {
            case let .knownType(known):
                visitAny(try known.toCBORValue())
            case let .object(fields):
                for item in fields.values { try visit(item) }
            case let .array(values):
                for item in values { try visit(item) }
            case let .link(link):
                visitAny(link)
            case let .unknownType(_, nested):
                try visit(nested)
            default:
                break
            }
        }

        try visit(decoded)
        return cids.sorted()
    }

    /// Moves a freshly uploaded blob into the private space namespace as part
    /// of the same SQLite transaction as its permissioned record.
    ///
    /// The staged upload edge is consumed unconditionally: a permissioned
    /// record has claimed those bytes, and a later same-CID re-upload creates
    /// a fresh staged edge that is likewise never anonymously reachable. A
    /// CID a validated public record also references keeps (or has restored)
    /// its public reference — that blob is genuinely published and
    /// `com.atproto.sync.getBlob` must keep serving it. Existing private
    /// references are idempotent, including when another space already owns
    /// the CAS.
    private func promotePermissionedBlobReferences(
        _ cids: [String],
        space: SpaceURI
    ) async throws {
        for cid in cids {
            _ = try canonicalRawBlobCID(cid)
            let payloadRows = try await connection.query(
                """
                SELECT blob_payloads.storage_kind, blob_payloads.cas_digest,
                       blob_payloads.byte_count
                FROM blob_payloads
                WHERE blob_payloads.cid = ?
                LIMIT 1
                """,
                [.text(cid)]
            )
            guard let payloadRow = payloadRows.first,
                  try requiredText(payloadRow, "storage_kind") == "cas-v1",
                  try payloadRow.column("cas_digest")?.string
                    == blobDigestHex(cid: cid, allowLegacy: false),
                  let byteCount = payloadRow.column("byte_count")?.integer,
                  byteCount > 0 else {
                throw SwanError.malformed(
                    "permissioned blob is not available from the account"
                )
            }

            // The upload edge is consumed by this commit. Removing it before
            // the idempotent private insert means an existing private edge
            // can never let a re-created staged edge survive.
            _ = try await connection.query(
                """
                DELETE FROM blob_namespace_references
                WHERE cid = ? AND namespace_kind = 'staged' AND space_uri = ''
                """,
                [.text(cid)]
            )

            let retainPublicReference: Bool
            if let override = testingHooks
                .permissionedBlobPublicReachabilityOverride?(cid) {
                retainPublicReference = override
            } else {
                retainPublicReference = try await
                    publicRepositoryContainsBlobCIDWithoutGate(cid)
            }
            if !retainPublicReference {
                // Repairs a public edge no validated public record justifies.
                // Uploads no longer create one, so this now only catches a
                // record deletion or an inherited pre-v15 edge.
                _ = try await connection.query(
                    """
                    DELETE FROM blob_namespace_references
                    WHERE cid = ? AND namespace_kind = 'public' AND space_uri = ''
                    """,
                    [.text(cid)]
                )
            }
            var plannedReferences = [(
                namespaceKind: "space",
                spaceURI: space.rawValue,
            )]
            if retainPublicReference {
                plannedReferences.append((namespaceKind: "public", spaceURI: ""))
            }
            try await admitBlobQuotaWithoutGate(
                cid: cid,
                byteCount: Int(byteCount),
                references: plannedReferences
            )
            let stamp = SQLiteData.integer(Int(Date().timeIntervalSince1970))
            _ = try await connection.query(
                """
                INSERT INTO blob_namespace_references(
                    cid, namespace_kind, space_uri, created_at
                ) VALUES (?, 'space', ?, ?)
                ON CONFLICT(cid, namespace_kind, space_uri) DO NOTHING
                """,
                [.text(cid), .text(space.rawValue), stamp]
            )
            if retainPublicReference {
                _ = try await connection.query(
                    """
                    INSERT INTO blob_namespace_references(
                        cid, namespace_kind, space_uri, created_at
                    ) VALUES (?, 'public', '', ?)
                    ON CONFLICT(cid, namespace_kind, space_uri) DO NOTHING
                    """,
                    [.text(cid), stamp]
                )
            }
        }
    }

    private func blobDigestHex(cid: String, allowLegacy: Bool) throws -> String {
        if let parsed = try? canonicalRawBlobCID(cid) {
            return Hex.encode(parsed.multihash.digest)
        }
        guard allowLegacy,
              cid.utf8.count == 71,
              cid.hasPrefix("sha256:"),
              let digest = legacyBlobDigest(cid) else {
            throw SwanError.malformed("blob CID is invalid")
        }
        return Hex.encode(digest)
    }

    private func legacyBlobDigest(_ value: String) -> Data? {
        guard value.utf8.count == 71, value.hasPrefix("sha256:") else {
            return nil
        }
        let characters = Array(value.dropFirst("sha256:".count).utf8)
        guard characters.count == 64 else { return nil }
        var output = Data()
        output.reserveCapacity(32)
        for index in stride(from: 0, to: characters.count, by: 2) {
            func nibble(_ value: UInt8) -> UInt8? {
                switch value {
                case UInt8(ascii: "0") ... UInt8(ascii: "9"):
                    value - UInt8(ascii: "0")
                case UInt8(ascii: "a") ... UInt8(ascii: "f"):
                    value - UInt8(ascii: "a") + 10
                default:
                    nil
                }
            }
            guard let high = nibble(characters[index]),
                  let low = nibble(characters[index + 1]) else {
                return nil
            }
            output.append((high << 4) | low)
        }
        return output
    }

    private func blobByteCount(_ count: Int) throws -> Int {
        guard count >= 0 else {
            throw SwanError.malformed("blob size is invalid")
        }
        return count
    }

    /// Keep the original upload MIME only when it is a simple header token
    /// pair.  A database row is never allowed to introduce a line break,
    /// parameter, or other response-header syntax at the HTTP boundary.
    private func safeBlobMIMEType(_ value: String?) -> String? {
        guard let value,
              !value.isEmpty,
              value.utf8.count <= 255,
              value.utf8.allSatisfy({ byte in
                  (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
                      || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
                      || (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
                      || "!#$&^_.+-/".utf8.contains(byte)
              }),
              value.filter({ $0 == "/" }).count == 1,
              !value.hasPrefix("/"), !value.hasSuffix("/")
        else {
            return nil
        }
        return value
    }

    private func verifiedPublicGenesis(
        car: Data,
        signingPublicKey: P256.Signing.PublicKey
    ) throws -> PublicRepositoryGenesis {
        let verified: PublicRepositoryGenesis
        do {
            verified = try PublicRepositoryGenesisCodec.verify(
                car: car,
                publicKey: signingPublicKey
            )
        } catch {
            throw PublicRepositoryGenesisStoreError.corruptStoredGenesis
        }
        guard verified.did == accountDID else {
            throw PublicRepositoryGenesisStoreError.ownershipMismatch
        }
        return verified
    }

    private func decodeStoredPublicRepositoryGenesis(
        _ row: SQLiteRow,
        signingPublicKey: P256.Signing.PublicKey
    ) throws -> PersistedPublicRepositoryGenesis {
        do {
            let did = try requiredText(row, "did")
            let revision = try requiredText(row, "revision")
            let commitCID = try requiredText(row, "commit_cid")
            let car = try requiredBlob(row, "car")
            let timestamp = try requiredNonnegativeInteger(row, "installed_at")
            guard did == accountDID else {
                throw PublicRepositoryGenesisStoreError.ownershipMismatch
            }
            let verified = try verifiedPublicGenesis(
                car: car,
                signingPublicKey: signingPublicKey
            )
            guard verified.did == did,
                  verified.revision == revision,
                  verified.commitCID.string == commitCID else {
                throw PublicRepositoryGenesisStoreError.corruptStoredGenesis
            }
            return try PersistedPublicRepositoryGenesis(
                genesis: verified,
                installedAt: Date(timeIntervalSince1970: Double(timestamp) / 1_000_000)
            )
        } catch let error as PublicRepositoryGenesisStoreError {
            throw error
        } catch {
            throw PublicRepositoryGenesisStoreError.corruptStoredGenesis
        }
    }

    private func publicGenesisTimestamp(_ date: Date) throws -> Int {
        let microseconds = date.timeIntervalSince1970 * 1_000_000
        guard microseconds.isFinite,
              microseconds >= 0,
              microseconds <= Double(Int.max)
        else {
            throw PublicRepositoryGenesisStoreError.invalidTimestamp
        }
        return Int(microseconds.rounded(.down))
    }

    private func sqliteRevision(_ revision: UInt64) throws -> Int {
        guard revision <= UInt64(Int.max) else {
            throw SQLiteRepositoryError.revisionOutOfRange(revision)
        }
        return Int(revision)
    }

    private func requiredNonnegativeInteger(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> Int {
        let value = try requiredInteger(row, column)
        guard value >= 0 else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid \(column)"
            )
        }
        return value
    }

    private func requiredRow(_ rows: [SQLiteRow]) throws -> SQLiteRow {
        guard rows.count == 1, let row = rows.first else {
            throw SQLiteRepositoryError.corruptDatabase(
                "aggregate query returned an invalid row count"
            )
        }
        return row
    }

    private func requiredInteger(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> Int {
        guard let value = row.column(column), case let .integer(integer) = value else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid \(column)"
            )
        }
        return integer
    }

    private func requiredRevision(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> UInt64 {
        guard let value = row.column(column) else {
            throw SQLiteRepositoryError.corruptDatabase(
                "missing \(column)"
            )
        }
        return try revision(value, column: column)
    }

    private func revision(
        _ data: SQLiteData,
        column: String
    ) throws -> UInt64 {
        guard case let .integer(value) = data, value >= 0 else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid \(column)"
            )
        }
        return UInt64(value)
    }

    private func requiredBlob(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> Data {
        guard let value = row.column(column),
              let data = Data(sqliteData: value)
        else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid \(column)"
            )
        }
        return data
    }

    private func requiredText(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> String {
        guard let value = row.column(column)?.string else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid \(column)"
            )
        }
        return value
    }

    private func requiredTID(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> TID {
        let value = try requiredText(row, column)
        guard let tid = try? TID(tidString: value) else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid \(column)"
            )
        }
        return tid
    }

    private func blob(_ data: Data) -> SQLiteData {
        // SQLiteNIO's Foundation conformance binds Data as a native BLOB.
        data.sqliteData!
    }
}

private final class SQLiteDataAccumulator: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Data

    init(capacity: Int) {
        value = Data()
        value.reserveCapacity(max(0, capacity))
    }

    func append(_ chunk: Data) {
        lock.lock()
        value.append(chunk)
        lock.unlock()
    }

    var data: Data {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

/// A process-local, bounded upload accumulator. It owns only a fixed-size
/// staging descriptor and a digest/counter; chunks are never retained after
/// they are written.
private final class SQLiteBlobUploadSpool: @unchecked Sendable {
    private let lock = NSLock()
    private let handle: FileHandle
    private let maximumBytes: Int
    private var digest = SHA256()
    private var byteCount = 0
    private var isClosed = false

    init(handle: FileHandle, maximumBytes: Int) {
        self.handle = handle
        self.maximumBytes = maximumBytes
    }

    var fileDescriptor: Int32 { handle.fileDescriptor }

    func append(_ chunk: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        guard !isClosed else {
            throw SwanError.unavailable("public blob staging is unavailable")
        }
        guard chunk.count <= maximumBytes - byteCount else {
            throw SwanError.malformed("blob upload exceeds its limit")
        }
        guard !chunk.isEmpty else { return }
        try handle.write(contentsOf: chunk)
        digest.update(data: chunk)
        byteCount += chunk.count
    }

    func finish() throws -> (digest: Data, byteCount: Int) {
        lock.lock()
        defer { lock.unlock() }
        guard !isClosed else {
            throw SwanError.unavailable("public blob staging is unavailable")
        }
        try handle.synchronize()
        guard lseek(handle.fileDescriptor, 0, SEEK_SET) == 0 else {
            throw SwanError.unavailable("public blob staging is unavailable")
        }
        return (Data(digest.finalize()), byteCount)
    }

    func close() {
        lock.lock()
        defer { lock.unlock() }
        guard !isClosed else { return }
        isClosed = true
        try? handle.close()
    }
}

/// A one-shot, already-open descriptor for an authorized private blob.  The
/// digest check completes before this object reaches HTTP, so the response
/// cannot start successfully and later discover that a swapped/corrupt file
/// had a different CID.  It intentionally exposes neither a path nor a way
/// to seek/reopen the payload.
private final class SQLiteAccountExternalBodyLeaseGate:
    @unchecked Sendable
{
    private let lock = NSLock()
    private var accepting = true
    private var activeLeaseCount = 0
    private var drainWaiters: [CheckedContinuation<Void, Never>] = []

    func acquire() -> SQLiteAccountExternalBodyLease? {
        lock.lock()
        defer { lock.unlock() }
        guard accepting else { return nil }
        activeLeaseCount += 1
        return SQLiteAccountExternalBodyLease(gate: self)
    }

    func revokeAndWait() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            accepting = false
            if activeLeaseCount == 0 {
                lock.unlock()
                continuation.resume()
            } else {
                drainWaiters.append(continuation)
                lock.unlock()
            }
        }
    }

    fileprivate func release() {
        let waiters: [CheckedContinuation<Void, Never>]
        lock.lock()
        guard activeLeaseCount > 0 else {
            lock.unlock()
            return
        }
        activeLeaseCount -= 1
        if !accepting, activeLeaseCount == 0 {
            waiters = drainWaiters
            drainWaiters.removeAll()
        } else {
            waiters = []
        }
        lock.unlock()
        for waiter in waiters {
            waiter.resume()
        }
    }
}

private final class SQLiteAccountExternalBodyLease:
    @unchecked Sendable
{
    private let lock = NSLock()
    private weak var gate: SQLiteAccountExternalBodyLeaseGate?

    init(gate: SQLiteAccountExternalBodyLeaseGate) {
        self.gate = gate
    }

    deinit { release() }

    func release() {
        lock.lock()
        let current = gate
        gate = nil
        lock.unlock()
        current?.release()
    }
}

private final class SQLiteVerifiedSpaceBlobBody: @unchecked Sendable,
    AuthorizedSpaceBlobBody
{
    private let lock = NSLock()
    private var descriptor: Int32
    private var externalLease: SQLiteAccountExternalBodyLease?
    let contentLength: Int

    init(
        descriptor: Int32,
        expectedDigest: Data,
        expectedLength: Int,
        externalLease: SQLiteAccountExternalBodyLease
    ) throws {
        guard expectedLength >= 0, expectedDigest.count == 32 else {
            throw SwanError.unavailable("permissioned blob storage is unavailable")
        }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(),
              (metadata.st_mode & 0o777) == 0o600,
              metadata.st_size >= 0,
              metadata.st_size <= off_t(Int.max),
              Int(metadata.st_size) == expectedLength else {
            throw SwanError.unavailable("permissioned blob storage is unavailable")
        }

        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        var digest = SHA256()
        var readLength = 0
        while let chunk = try handle.read(upToCount: 64 * 1_024), !chunk.isEmpty {
            try Task.checkCancellation()
            digest.update(data: chunk)
            guard readLength <= expectedLength - chunk.count else {
                throw SwanError.unavailable("permissioned blob storage is unavailable")
            }
            readLength += chunk.count
        }
        guard readLength == expectedLength,
              Data(digest.finalize()) == expectedDigest,
              lseek(descriptor, 0, SEEK_SET) == 0 else {
            throw SwanError.unavailable("permissioned blob storage is unavailable")
        }

        self.descriptor = descriptor
        self.externalLease = externalLease
        contentLength = expectedLength
    }

    deinit {
        closeDescriptor()
        releaseExternalLease()
    }

    func streamBody(
        maximumChunkBytes: Int,
        consume: (Data) async throws -> Void
    ) async throws {
        guard (1 ... 64 * 1_024).contains(maximumChunkBytes) else {
            closeDescriptor()
            releaseExternalLease()
            throw SwanError.malformed("permissioned blob chunk size is invalid")
        }
        let descriptor = takeDescriptor()
        guard descriptor >= 0 else {
            throw SwanError.unavailable("permissioned blob storage is unavailable")
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer {
            try? handle.close()
            releaseExternalLease()
        }
        while true {
            try Task.checkCancellation()
            guard let chunk = try handle.read(upToCount: maximumChunkBytes),
                  !chunk.isEmpty else {
                return
            }
            try await consume(chunk)
        }
    }

    /// Releases a verified descriptor that was opened only to validate an
    /// existing CAS entry before lifecycle adoption.  This keeps the verifier
    /// one-shot just like the HTTP streaming path without buffering a body.
    func discardUnstreamed() {
        closeDescriptor()
        releaseExternalLease()
    }

    private func takeDescriptor() -> Int32 {
        lock.lock()
        defer { lock.unlock() }
        let result = descriptor
        descriptor = -1
        return result
    }

    private func closeDescriptor() {
        let descriptor = takeDescriptor()
        if descriptor >= 0 { _ = close(descriptor) }
    }

    private func releaseExternalLease() {
        lock.lock()
        let lease = externalLease
        externalLease = nil
        lock.unlock()
        lease?.release()
    }
}

/// Permissioned-repository facade backed solely by `SQLiteAccountDatabase`.
///
/// The actor holds immutable routing dependencies only; records, revisions,
/// oplog entries, and commit facts are read from SQLite for every operation.
/// Reader-specific commit envelopes are deliberately never persisted.
public actor DurableSpaceRepository {
    private let database: SQLiteAccountDatabase
    private let space: SpaceURI
    private let author: String

    public init(
        database: SQLiteAccountDatabase,
        space: SpaceURI,
        author: String
    ) throws {
        // Reuse the domain's strict DID grammar without fabricating any
        // repository state for this facade.
        _ = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.swan.repository",
            rkey: "state"
        )
        self.database = database
        self.space = space
        self.author = author
    }

    public func record(
        _ uri: SpaceRecordURI,
        authorization: AuthorizationContext
    ) async throws -> SpaceRecord? {
        try requireRepositoryURI(uri)
        try requireRead(uri: uri, authorization: authorization)
        return try await database.spaceRecord(uri).map(record(from:))
    }

    /// Applies one write with an exact SQLite revision CAS, a caller-selected
    /// replay key, and a monotonically advancing wire TID.
    public func apply(
        _ write: SpaceWrite,
        expectedRevision: UInt64,
        requestID: UUID,
        wireRevision: TID,
        authorization: AuthorizationContext
    ) async throws -> DurableSpaceOplogEntry {
        let entries = try await applyAtomically(
            [write],
            expectedRevision: expectedRevision,
            requestID: requestID,
            wireRevision: wireRevision,
            authorization: authorization
        )
        guard entries.count == 1, let entry = entries.first else {
            throw SQLiteRepositoryError.corruptDatabase(
                "single repository write produced an invalid oplog result"
            )
        }
        return entry
    }

    /// Preflights every write against a mutable copy of one expected SQLite
    /// snapshot, then hands the same expected revision to SQLite for the
    /// authoritative CAS. The mutable copy gives an atomic create → update or
    /// create → delete batch the same permission and LtHash semantics SQLite
    /// will commit, while the source of that copy remains the expected durable
    /// snapshot rather than facade-owned repository state.
    public func applyAtomically(
        _ writes: [SpaceWrite],
        expectedRevision: UInt64,
        requestID: UUID,
        wireRevision: TID,
        authorization: AuthorizationContext
    ) async throws -> [DurableSpaceOplogEntry] {
        guard !writes.isEmpty else { return [] }
        var aggregateValueBytes = 0
        for write in writes {
            aggregateValueBytes = try SpaceWriteLimits.addingValueBytes(
                aggregateValueBytes,
                write.valueByteCount
            )
        }
        try SpaceWriteLimits.validate(
            operationCount: writes.count,
            aggregateValueBytes: aggregateValueBytes
        )
        guard expectedRevision < UInt64(Int.max) else {
            throw SQLiteRepositoryError.revisionOutOfRange(expectedRevision)
        }

        let state = try await database.repositoryState(
            space: space,
            author: author
        )
        let actualRevision = state?.revision ?? 0
        guard actualRevision == expectedRevision else {
            throw SwanError.conflict(expected: expectedRevision, actual: actualRevision)
        }
        let finalRevision = expectedRevision + 1

        let targetURIs = writes.map(uri(for:))
        var expectedRecords = try await database.spaceRecordMetadata(
            space: space,
            author: author,
            uris: targetURIs
        )
        var nextLtHash = try LtHash(
            serialized: state?.ltHash
                ?? Data(repeating: 0, count: LtHash.byteCount)
        )
        var sqliteWrites: [SQLiteSpaceWrite] = []

        for write in writes {
            let uri = uri(for: write)
            try requireRepositoryURI(uri)
            let expectedRecord = expectedRecords[uri]
            switch write {
            case let .put(uri, value):
                let permission: SpacePermission = expectedRecord == nil ? .create : .update
                try requireWrite(
                    uri: uri,
                    authorization: authorization,
                    permission: permission
                )
                let cid = CID.fromDAGCBOR(value).string
                if let expectedRecord {
                    nextLtHash.remove(element: ltHashElement(for: expectedRecord))
                }
                nextLtHash.add(element: "\(uri.collection)/\(uri.rkey)/\(cid)")
                sqliteWrites.append(.put(uri: uri, value: value, cid: cid))
                expectedRecords[uri] = PersistedSpaceRecordMetadata(
                    uri: uri,
                    cid: cid,
                    revision: finalRevision
                )
            case let .delete(uri):
                try requireWrite(
                    uri: uri,
                    authorization: authorization,
                    permission: .delete
                )
                guard let expectedRecord else {
                    throw SwanError.malformed("cannot delete a missing record")
                }
                nextLtHash.remove(element: ltHashElement(for: expectedRecord))
                sqliteWrites.append(.delete(uri: uri))
                expectedRecords.removeValue(forKey: uri)
            }
        }

        let eventID = UUID()
        let persisted = try await database.apply(
            space: space,
            author: author,
            expectedRevision: expectedRevision,
            requestID: requestID,
            wireRevision: wireRevision,
            writes: sqliteWrites,
            eventID: eventID
        )
        return persisted.entries.map(oplogEntry(from:))
    }

    /// Applies XRPC operation kinds without collapsing them into a generic
    /// upsert before SQLite has made the revision-CAS decision.  This is the
    /// write-side counterpart to the read projections: it reads only the
    /// local durable snapshot needed to choose the expected revision and to
    /// preflight an ordered batch, then performs one no-network transaction.
    ///
    /// Callers that publish under a control-plane lease must use
    /// `stageAuthorizedWrites` and `commitStagedWrites` separately, so the
    /// lease covers only the durable transaction.  This convenience form runs
    /// both halves back to back and is what a caller with no fence wants.
    public func applyAuthorizedWrites(
        _ writes: [AuthorizedSpaceRepositoryWrite],
        requestID: UUID,
        wireRevision: TID,
        authorization: AuthorizationContext
    ) async throws -> [AuthorizedSpaceRepositoryWriteResult] {
        let staged = try await stageAuthorizedWrites(
            writes,
            requestID: requestID,
            wireRevision: wireRevision,
            authorization: authorization
        )
        return try await commitStagedWrites(staged)
    }

    /// The preflight half of `applyAuthorizedWrites`: limit validation, the
    /// durable reads that choose the expected revision, every authorization
    /// check, and CID computation.  It makes nothing durable, so a caller can
    /// run it *before* taking a publication lease instead of underneath one.
    public func stageAuthorizedWrites(
        _ writes: [AuthorizedSpaceRepositoryWrite],
        requestID: UUID,
        wireRevision: TID,
        authorization: AuthorizationContext
    ) async throws -> StagedAuthorizedWriteBatch {
        guard !writes.isEmpty else {
            throw SwanError.malformed("repository batch must contain a write")
        }
        var aggregateValueBytes = 0
        for write in writes {
            aggregateValueBytes = try SpaceWriteLimits.addingValueBytes(
                aggregateValueBytes,
                write.valueByteCount
            )
        }
        try SpaceWriteLimits.validate(
            operationCount: writes.count,
            aggregateValueBytes: aggregateValueBytes
        )

        let state = try await database.repositoryState(space: space, author: author)
        let expectedRevision = state?.revision ?? 0
        let targetURIs = writes.map(\.uri)
        var expectedRecords = try await database.spaceRecordMetadata(
            space: space,
            author: author,
            uris: targetURIs
        )
        var sqliteWrites: [SQLiteSpaceWrite] = []

        for write in writes {
            let uri = write.uri
            try requireRepositoryURI(uri)
            let existing = expectedRecords[uri]
            switch write {
            case let .create(_, value):
                try requireWrite(uri: uri, authorization: authorization, permission: .create)
                guard existing == nil else {
                    throw SwanError.malformed("cannot create an existing record")
                }
                let cid = CID.fromDAGCBOR(value).string
                sqliteWrites.append(.create(uri: uri, value: value, cid: cid))
                expectedRecords[uri] = PersistedSpaceRecordMetadata(uri: uri, cid: cid, revision: expectedRevision + 1)
            case let .put(_, value):
                // A `putRecord` can be either branch when the transaction
                // reaches SQLite, so both grants are mandatory before the
                // state-dependent choice is made.
                try requireWrite(uri: uri, authorization: authorization, permission: .create)
                try requireWrite(uri: uri, authorization: authorization, permission: .update)
                let cid = CID.fromDAGCBOR(value).string
                sqliteWrites.append(.put(uri: uri, value: value, cid: cid))
                expectedRecords[uri] = PersistedSpaceRecordMetadata(uri: uri, cid: cid, revision: expectedRevision + 1)
            case let .update(_, value):
                try requireWrite(uri: uri, authorization: authorization, permission: .update)
                guard existing != nil else {
                    throw SwanError.malformed("cannot update a missing record")
                }
                let cid = CID.fromDAGCBOR(value).string
                sqliteWrites.append(.update(uri: uri, value: value, cid: cid))
                expectedRecords[uri] = PersistedSpaceRecordMetadata(uri: uri, cid: cid, revision: expectedRevision + 1)
            case .delete:
                try requireWrite(uri: uri, authorization: authorization, permission: .delete)
                guard existing != nil else {
                    throw SwanError.malformed("cannot delete a missing record")
                }
                sqliteWrites.append(.delete(uri: uri))
                expectedRecords.removeValue(forKey: uri)
            }
        }

        return StagedAuthorizedWriteBatch(
            expectedRevision: expectedRevision,
            requestID: requestID,
            wireRevision: wireRevision,
            writes: sqliteWrites
        )
    }

    /// The durable half of `applyAuthorizedWrites`: one no-network SQLite
    /// transaction over an already-staged batch.  Nothing here reads the
    /// control store, so a caller may hold a control-plane write lease across
    /// it.  The revision CAS inside `database.apply` — not the staging read —
    /// is what rejects a batch staged against a superseded revision.
    public func commitStagedWrites(
        _ staged: StagedAuthorizedWriteBatch
    ) async throws -> [AuthorizedSpaceRepositoryWriteResult] {
        let persisted = try await database.apply(
            space: space,
            author: author,
            expectedRevision: staged.expectedRevision,
            requestID: staged.requestID,
            wireRevision: staged.wireRevision,
            writes: staged.writes
        )
        return try persisted.entries.map { entry in
            let action: AuthorizedSpaceRepositoryWriteResult.Action = switch entry.action {
            case .create: .create
            case .update: .update
            case .delete: .delete
            }
            guard entry.write.uri.space == space, entry.write.uri.author == author else {
                throw SQLiteRepositoryError.corruptDatabase("write result belongs to another repository")
            }
            return AuthorizedSpaceRepositoryWriteResult(
                action: action,
                uri: entry.write.uri,
                cid: entry.cid
            )
        }
    }

    /// Returns ordered incremental operations when retained, or a durable full
    /// snapshot after an oplog gap. Recovery only reads SQLite; it does not
    /// mutate or replace local repository state.
    public func sync(
        since requestedRevision: UInt64,
        authorization: AuthorizationContext
    ) async throws -> DurableSpaceSyncResponse {
        try requireRead(uri: nil, authorization: authorization)
        switch try await database.spaceOplog(
            space: space,
            author: author,
            since: requestedRevision
        ) {
        case let .incremental(entries):
            return .incremental(entries.map(oplogEntry(from:)))
        case let .fullRecoveryRequired(snapshot):
            return .fullSnapshot(
                revision: snapshot.state.revision,
                records: snapshot.records.map(record(from:)),
                commitment: snapshot.state.commitment
            )
        }
    }

    public func currentState(
        authorization: AuthorizationContext
    ) async throws -> DurableSpaceRepositoryState {
        try requireRead(uri: nil, authorization: authorization)
        let snapshot = try await database.repositorySnapshot(
            space: space,
            author: author
        )
        if let snapshot {
            return state(from: snapshot.state)
        }
        let ltHash = LtHash()
        return DurableSpaceRepositoryState(
            space: space,
            author: author,
            revision: 0,
            wireRevision: nil,
            ltHash: ltHash.serialized,
            commitment: ltHash.commitment
        )
    }

    /// Returns only the durable facts that an account-key backed signer needs
    /// for a fresh reader-specific commit.  A never-written repository has a
    /// zero LtHash commitment but no wire revision, so the HTTP handler emits
    /// no signed commit exactly like the pinned TypeScript PDS.
    public func currentCommitState(
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceRepositoryCommitState {
        try requireRead(uri: nil, authorization: authorization)
        if let state = try await database.repositoryState(space: space, author: author) {
            return AuthorizedSpaceRepositoryCommitState(
                space: state.space,
                author: state.author,
                wireRevision: state.wireRevision.toString(),
                commitment: state.commitment
            )
        }
        return AuthorizedSpaceRepositoryCommitState(
            space: space,
            author: author,
            wireRevision: nil,
            commitment: LtHash().commitment
        )
    }

    /// Returns only the durable wire revision after preflighting the exact
    /// action grants in an XRPC write batch. It intentionally exposes no
    /// commitment or record facts to a write-only caller.
    public func currentWireRevisionForWrite(
        _ writes: [AuthorizedSpaceRepositoryWrite],
        authorization: AuthorizationContext
    ) async throws -> String? {
        guard !writes.isEmpty else {
            throw SwanError.malformed("repository batch must contain a write")
        }
        var aggregateValueBytes = 0
        for write in writes {
            aggregateValueBytes = try SpaceWriteLimits.addingValueBytes(
                aggregateValueBytes,
                write.valueByteCount
            )
        }
        try SpaceWriteLimits.validate(
            operationCount: writes.count,
            aggregateValueBytes: aggregateValueBytes
        )
        for write in writes {
            let uri = write.uri
            try requireRepositoryURI(uri)
            switch write {
            case .create:
                try requireWrite(uri: uri, authorization: authorization, permission: .create)
            case .put:
                try requireWrite(uri: uri, authorization: authorization, permission: .create)
                try requireWrite(uri: uri, authorization: authorization, permission: .update)
            case .update:
                try requireWrite(uri: uri, authorization: authorization, permission: .update)
            case .delete:
                try requireWrite(uri: uri, authorization: authorization, permission: .delete)
            }
        }
        return try await database.repositoryState(space: space, author: author)?.wireRevision.toString()
    }

    /// Creates a private, immutable full-recovery snapshot after applying the
    /// same aggregate read policy used by the repository endpoints. In
    /// particular, a collection-qualified OAuth scope cannot downgrade this
    /// into a partial repository export.
    public func prepareCARSnapshot(
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceRepositoryCARSnapshot? {
        try requireRead(uri: nil, authorization: authorization)
        return try await database.prepareRepositoryCARSnapshot(
            space: space,
            author: author
        )
    }

    /// The declared length of that same blob, under the identical aggregate
    /// repository-read check.  A collection-qualified OAuth grant cannot use
    /// this to learn whether a blob exists any more than it can open one.
    public func permissionedBlobMetadata(
        cid: String,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceBlobMetadata? {
        try requireRead(uri: nil, authorization: authorization)
        return try await database.permissionedBlobMetadata(
            space: space,
            author: author,
            cid: cid
        )
    }

    /// Opens one already-authorized, file-backed blob body.  Blob retrieval is
    /// an aggregate repository read: a collection-qualified OAuth grant may
    /// read its individual records but cannot be repurposed into an arbitrary
    /// blob oracle.
    public func permissionedBlob(
        cid: String,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceBlob? {
        try requireRead(uri: nil, authorization: authorization)
        return try await database.permissionedBlob(
            space: space,
            author: author,
            cid: cid
        )
    }

    /// Reads the pinned wire-TID incremental oplog page.  The durable query
    /// joins values only against their matching live records; this facade
    /// preserves operation ordering and maps a retention gap to an explicit
    /// recovery requirement rather than synthesizing an incomplete delta.
    public func incrementalOplog(
        since: TID?,
        limit: Int,
        includeValues: Bool,
        maximumAggregateValueBytes: Int = PublicRepositoryJSONReadLimits
            .maximumListRepoOpsValueBytes,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceRepositoryOplogRead {
        try requireRead(uri: nil, authorization: authorization)
        switch try await database.wireOplog(
            space: space,
            author: author,
            since: since,
            limit: limit,
            includeValues: includeValues,
            maximumAggregateValueBytes: maximumAggregateValueBytes
        ) {
        case let .incremental(state, entries):
            let projectedState: AuthorizedSpaceRepositoryCommitState
            if let state {
                projectedState = AuthorizedSpaceRepositoryCommitState(
                    space: state.space,
                    author: state.author,
                    wireRevision: state.wireRevision.toString(),
                    commitment: state.commitment
                )
            } else {
                projectedState = AuthorizedSpaceRepositoryCommitState(
                    space: space,
                    author: author,
                    wireRevision: nil,
                    commitment: LtHash().commitment
                )
            }
            return .incremental(
                state: projectedState,
                entries: entries.map { entry in
                    AuthorizedSpaceRepositoryOplogEntry(
                        wireRevision: entry.wireRevision.toString(),
                        collection: entry.uri.collection,
                        rkey: entry.uri.rkey,
                        cid: entry.cid,
                        previousCID: entry.previousCID,
                        value: entry.value
                    )
                }
            )
        case .fullRecoveryRequired:
            return .fullRecoveryRequired
        }
    }

    public func snapshot(
        authorization: AuthorizationContext
    ) async throws -> [SpaceRecord] {
        try requireRead(uri: nil, authorization: authorization)
        return try await database.repositorySnapshot(
            space: space,
            author: author
        )?.records.map(record(from:)) ?? []
    }

    /// Returns the exact page shape used by the pinned
    /// `com.atproto.space.listRecords` reader. The pinned implementation
    /// orders the default page descending by `(collection, rkey)` and flips
    /// to ascending only when `reverse` is true. Cursor syntax that cannot
    /// name a domain record is deliberately ignored, matching the reference
    /// reader's tolerant `parseListCursor` behavior.
    ///
    /// This remains a domain operation: a collection-qualified OAuth grant
    /// is checked against a synthetic, valid record URI before the durable
    /// snapshot is queried. An omitted collection therefore cannot silently
    /// downgrade an aggregate response to a censored list.
    public func listRecords(
        collection: String?,
        limit: Int,
        cursor: String?,
        reverse: Bool,
        authorization: AuthorizationContext
    ) async throws -> [SpaceRecord] {
        guard (1 ... 100).contains(limit) else {
            throw SwanError.malformed("permissioned record page limit is invalid")
        }

        let authorizationURI: SpaceRecordURI?
        if let collection {
            // The value exists only to carry the collection into the domain
            // policy. It is never queried or serialized.
            authorizationURI = try SpaceRecordURI(
                space: space,
                author: author,
                collection: collection,
                rkey: "scope"
            )
        } else {
            authorizationURI = nil
        }
        try requireRead(uri: authorizationURI, authorization: authorization)

        let cursorKey = cursor.flatMap(Self.parseListCursor)
        let records = try await database.repositoryRecordPage(
            space: space,
            author: author,
            collection: collection,
            cursorCollection: cursorKey?.collection,
            cursorRKey: cursorKey?.rkey,
            reverse: reverse,
            limit: limit,
            maximumAggregateRecordBytes: PublicRepositoryJSONReadLimits
                .maximumAggregateRecordBlockBytes
        )
        return records.map(record(from:))
    }

    /// Builds a new, reader-specific commit envelope and complete CAR for each
    /// request. SQLite holds a deterministic state marker only, never IKM,
    /// context signatures, or reader content bindings.
    public func exportCAR(
        rev: String,
        signingKey: P256.Signing.PrivateKey,
        authorization: AuthorizationContext
    ) async throws -> SpaceCAR {
        try requireRead(uri: nil, authorization: authorization)
        let snapshot = try await database.repositorySnapshot(
            space: space,
            author: author
        )
        let ltHash = try LtHash(
            serialized: snapshot?.state.ltHash
                ?? Data(repeating: 0, count: LtHash.byteCount)
        )
        let commit = try SpaceCommitCodec.createReaderEnvelope(
            space: space,
            author: author,
            rev: rev,
            commitment: ltHash.commitment,
            key: signingKey
        )
        return try SpaceCARCodec.encode(
            commit: commit,
            records: snapshot?.records.map(record(from:)) ?? []
        )
    }

    private func requireRepositoryURI(_ uri: SpaceRecordURI) throws {
        guard uri.space == space, uri.author == author else {
            throw SwanError.unauthorized("record belongs to another repository")
        }
    }

    private func requireRead(
        uri: SpaceRecordURI?,
        authorization: AuthorizationContext
    ) throws {
        try SpaceAuthorizationPolicy.require(
            space: space,
            author: author,
            uri: uri,
            authorization: authorization,
            permission: .read
        )
    }

    private func requireWrite(
        uri: SpaceRecordURI,
        authorization: AuthorizationContext,
        permission: SpacePermission
    ) throws {
        if case .service = authorization {
            throw SwanError.unauthorized(
                "service authentication cannot write a permissioned repository"
            )
        }
        try SpaceAuthorizationPolicy.require(
            space: space,
            author: author,
            uri: uri,
            authorization: authorization,
            permission: permission
        )
    }

    private func uri(for write: SpaceWrite) -> SpaceRecordURI {
        switch write {
        case let .put(uri, _), let .delete(uri): uri
        }
    }

    private func record(from persisted: PersistedSpaceRecord) -> SpaceRecord {
        SpaceRecord(
            uri: persisted.uri,
            value: persisted.value,
            cid: persisted.cid,
            revision: persisted.revision
        )
    }

    private func oplogEntry(
        from persisted: PersistedSpaceOplogEntry
    ) -> DurableSpaceOplogEntry {
        let write: SpaceWrite
        switch persisted.write {
        case let .create(uri, value, _), let .put(uri, value, _),
             let .update(uri, value, _):
            write = .put(uri: uri, value: value)
        case let .delete(uri):
            write = .delete(uri: uri)
        }
        return DurableSpaceOplogEntry(
            cursor: persisted.cursor,
            wireRevision: persisted.wireRevision,
            action: persisted.action,
            write: write,
            cid: persisted.cid,
            previousCID: persisted.previousCID,
            commitment: persisted.commitment
        )
    }

    private func state(from persisted: PersistedRepositoryState) -> DurableSpaceRepositoryState {
        DurableSpaceRepositoryState(
            space: persisted.space,
            author: persisted.author,
            revision: persisted.revision,
            wireRevision: persisted.wireRevision,
            ltHash: persisted.ltHash,
            commitment: persisted.commitment
        )
    }

    private func ltHashElement(for record: PersistedSpaceRecordMetadata) -> String {
        "\(record.uri.collection)/\(record.uri.rkey)/\(record.cid)"
    }

    private static func parseListCursor(
        _ cursor: String
    ) -> (collection: String, rkey: String)? {
        let pieces = cursor.split(separator: "/", omittingEmptySubsequences: false)
        guard pieces.count == 2,
              let URI = try? SpaceRecordURI(
                  space: try SpaceURI(
                      authority: "did:plc:abcdefghijklmnopqrstuvwx",
                      spaceType: "app.swan.cursor",
                      skey: "cursor"
                  ),
                  author: "did:plc:abcdefghijklmnopqrstuvwx",
                  collection: String(pieces[0]),
                  rkey: String(pieces[1])
              ) else {
            return nil
        }
        return (URI.collection, URI.rkey)
    }
}

/// SQLite-backed `com.atproto.simplespace` authority facade. It retains no
/// authority, membership, client, or managing-app decisions in actor memory:
/// every operation delegates to the authority account database. A member's
/// repository can still be hosted in a different account database; this
/// facade simply refuses to create authority state anywhere but the DID named
/// by `SpaceURI.authority`.
public actor DurableSimpleSpaceAuthority {
    private let database: SQLiteAccountDatabase
    private let credentials: HMACSpaceCredentialAuthority?

    public init(
        database: SQLiteAccountDatabase,
        credentialSecret: Data
    ) throws {
        guard credentialSecret.count >= 16 else {
            throw SwanError.malformed("simple-space credential secret is too short")
        }
        self.database = database
        credentials = HMACSpaceCredentialAuthority(key: credentialSecret)
    }

    /// Lifecycle-only facade used by the startup-preopened HTTP authority
    /// directory. It intentionally cannot mint credentials: that requires a
    /// separately configured secret-bearing authority instance.
    public init(lifecycleDatabase database: SQLiteAccountDatabase) {
        self.database = database
        credentials = nil
    }

    public func create(
        space: SpaceURI,
        owner: String,
        configuration: SimpleSpaceConfiguration,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try await database.createSimpleSpace(
            space: space,
            owner: owner,
            configuration: configuration,
            authorization: authorization,
            now: now
        )
    }

    public func space(
        _ space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws -> DurableSimpleSpaceState? {
        try await database.simpleSpace(space, authorization: authorization)
    }

    public func update(
        space: SpaceURI,
        configuration: SimpleSpaceConfiguration,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try await database.updateSimpleSpace(
            space: space,
            configuration: configuration,
            authorization: authorization,
            now: now
        )
    }

    public func update(
        space: SpaceURI,
        patch: SimpleSpaceConfigurationPatch,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try await database.patchSimpleSpace(
            space: space,
            patch: patch,
            authorization: authorization,
            now: now
        )
    }

    public func addMember(
        space: SpaceURI,
        member: String,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try await database.addSimpleSpaceMember(
            space: space,
            member: member,
            authorization: authorization,
            now: now
        )
    }

    public func removeMember(
        space: SpaceURI,
        member: String,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try await database.removeSimpleSpaceMember(
            space: space,
            member: member,
            authorization: authorization,
            now: now
        )
    }

    public func memberPage(
        space: SpaceURI,
        limit: Int,
        cursor: String?,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSimpleSpaceMemberPage {
        try await database.simpleSpaceMemberPage(
            space: space,
            limit: limit,
            cursor: cursor,
            authorization: authorization
        )
    }

    public func setClientAccess(
        space: SpaceURI,
        clientID: String,
        allowed: Bool,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try await database.setSimpleSpaceClientAccess(
            space: space,
            clientID: clientID,
            allowed: allowed,
            authorization: authorization,
            now: now
        )
    }

    public func setManagingAppAccess(
        space: SpaceURI,
        user: String,
        allowed: Bool,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try await database.setSimpleSpaceManagingAppAccess(
            space: space,
            user: user,
            allowed: allowed,
            authorization: authorization,
            now: now
        )
    }

    public func delete(
        space: SpaceURI,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try await database.deleteSimpleSpace(
            space: space,
            authorization: authorization,
            now: now
        )
    }

    /// Credentials remain transient reader artifacts. SQLite records the
    /// policy facts that permitted issuance, never the credential envelope,
    /// nonce, MAC, or its two-hour expiry.
    public func issueReadCredential(
        space: SpaceURI,
        user: String,
        clientID: String?,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> SignedSpaceCredential {
        try await database.authorizeSimpleSpaceRead(
            space: space,
            user: user,
            clientID: clientID,
            authorization: authorization
        )
        let grant = SpaceGrant(
            subject: user,
            space: space,
            permissions: [.read],
            expiresAt: now.addingTimeInterval(2 * 60 * 60),
            clientID: clientID
        )
        guard let credentials else {
            throw SwanError.unavailable("credential authority is unavailable")
        }
        return try credentials.issue(SpaceCredential(grant: grant, issuedAt: now))
    }
}
