import SQLiteNIO

extension SQLiteControlDatabase {
    /// Installs every account-program table at the control database's single
    /// startup migration boundary. Lane-local lazy DDL remains idempotent for
    /// tests, but production never reaches a request with a partial schema.
    func migrateAccountProgramIntegrationV8() async throws {
        let marker = try await connection.query(
            "SELECT 1 FROM control_schema_migrations WHERE version = 8 LIMIT 1"
        )
        // The per-account app-password ceiling is part of the current-main
        // contract, not a property of the never-deployed account-program
        // schema. Rebuild the trigger even when V8 was already recorded: an
        // earlier integration build installed the old 32-row trigger and
        // SQLite has no ALTER TRIGGER operation. The surrounding migration
        // transaction makes the drop/recreate atomic with startup.
        if !marker.isEmpty {
            try await recreateCanonicalAppPasswordCapacityTrigger()
            return
        }

        try await rebuildIdentityBindingsForReleasedIdentityReuseIfNeeded()

        let statements = [
            """
            CREATE TABLE IF NOT EXISTS did_web_signing_key_reservations (
              request_id TEXT PRIMARY KEY, account_did TEXT, target_did TEXT NOT NULL,
              handle TEXT NOT NULL, key_id TEXT NOT NULL, key_type TEXT NOT NULL,
              public_key BLOB NOT NULL, nonce BLOB NOT NULL UNIQUE,
              expires_at INTEGER NOT NULL, claim_bytes BLOB NOT NULL,
              claim_receipt_digest BLOB NOT NULL, pds_url TEXT NOT NULL,
              claim_service_endpoint TEXT NOT NULL, state TEXT NOT NULL,
              created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS did_web_step_up_receipts (
              receipt_digest BLOB PRIMARY KEY CHECK(length(receipt_digest) = 32),
              session_id TEXT NOT NULL, account_did TEXT NOT NULL,
              operation TEXT NOT NULL, mfa_strength TEXT NOT NULL,
              verified_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
              consumed_at INTEGER
            )
            """,
            "CREATE UNIQUE INDEX IF NOT EXISTS identity_did_web_active_identity_uq ON identity_bindings(identity_did) WHERE method='did-web' AND state != 'released'",
            "CREATE UNIQUE INDEX IF NOT EXISTS identity_did_web_active_handle_uq ON identity_bindings(handle) WHERE method='did-web' AND state != 'released'",
            "CREATE INDEX IF NOT EXISTS did_web_signing_key_reservations_expiry ON did_web_signing_key_reservations(expires_at, request_id)",
            "CREATE INDEX IF NOT EXISTS did_web_signing_key_reservations_account ON did_web_signing_key_reservations(account_did, state, request_id)",
            "CREATE INDEX IF NOT EXISTS did_web_step_up_receipts_expiry ON did_web_step_up_receipts(expires_at, receipt_digest)",
            """
            CREATE TABLE IF NOT EXISTS signup_invite_reservations(
              invite_digest BLOB PRIMARY KEY CHECK(length(invite_digest)=32),
              authorization_id TEXT NOT NULL, reserved_until INTEGER NOT NULL)
            """,
            """
            CREATE TABLE IF NOT EXISTS signup_email_proofs(
              proof_digest BLOB PRIMARY KEY CHECK(length(proof_digest)=32),
              email TEXT NOT NULL, handle TEXT NOT NULL, issued_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL, consumed_at INTEGER)
            """,
            """
            CREATE TABLE IF NOT EXISTS signup_email_proof_reservations(
              proof_digest BLOB PRIMARY KEY CHECK(length(proof_digest)=32),
              authorization_id TEXT NOT NULL, reserved_until INTEGER NOT NULL)
            """,
            """
            CREATE TABLE IF NOT EXISTS signup_authorization_reservations(
              authorization_id TEXT PRIMARY KEY,
              input_digest BLOB NOT NULL CHECK(length(input_digest)=32),
              reserved_until INTEGER NOT NULL)
            """,
            """
            CREATE TABLE IF NOT EXISTS signup_authorization_results(
              authorization_id TEXT PRIMARY KEY,
              input_digest BLOB NOT NULL CHECK(length(input_digest)=32),
              account_did TEXT NOT NULL, session_id TEXT NOT NULL,
              committed_at INTEGER NOT NULL)
            """,
            """
            CREATE TABLE IF NOT EXISTS signup_email_request_outbox(
              proof_digest BLOB PRIMARY KEY CHECK(length(proof_digest)=32),
              delivery_id TEXT NOT NULL UNIQUE, email TEXT NOT NULL,
              handle TEXT NOT NULL, protected_envelope BLOB NOT NULL,
              issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
              state TEXT NOT NULL DEFAULT 'pending', lease_token BLOB,
              lease_expires_at INTEGER, next_attempt_at INTEGER NOT NULL DEFAULT 0,
              attempts INTEGER NOT NULL DEFAULT 0, delivered_at INTEGER)
            """,
            "CREATE INDEX IF NOT EXISTS signup_invite_reservations_expiry ON signup_invite_reservations(reserved_until, invite_digest)",
            "CREATE INDEX IF NOT EXISTS signup_email_proofs_expiry ON signup_email_proofs(expires_at, proof_digest)",
            "CREATE INDEX IF NOT EXISTS signup_email_proof_reservations_expiry ON signup_email_proof_reservations(reserved_until, proof_digest)",
            "CREATE INDEX IF NOT EXISTS signup_authorization_reservations_expiry ON signup_authorization_reservations(reserved_until, authorization_id)",
            "CREATE INDEX IF NOT EXISTS signup_email_request_outbox_claim ON signup_email_request_outbox(state, next_attempt_at, lease_expires_at, issued_at)",
            """
            CREATE TABLE IF NOT EXISTS management_pre_auth (
              token_digest BLOB PRIMARY KEY CHECK(length(token_digest) = 32),
              expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
            ) WITHOUT ROWID
            """,
            "CREATE INDEX IF NOT EXISTS management_pre_auth_expiry ON management_pre_auth(expires_at, token_digest)",
            "CREATE TABLE IF NOT EXISTS totp_replay_state (factor_id TEXT NOT NULL, account_did TEXT NOT NULL, accepted_counter INTEGER NOT NULL CHECK(accepted_counter >= 0), updated_at INTEGER NOT NULL, PRIMARY KEY(factor_id, account_did))",
            "CREATE TABLE IF NOT EXISTS mfa_factor_tokens (digest BLOB PRIMARY KEY CHECK(length(digest) = 32), account_did TEXT NOT NULL, session_id TEXT NOT NULL, purpose TEXT NOT NULL, factor TEXT NOT NULL, factor_id TEXT NOT NULL, strength BLOB NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER, revoked_at INTEGER)",
            "CREATE TABLE IF NOT EXISTS mfa_audit_events (event_id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, account_did TEXT NOT NULL, factor_id TEXT, success INTEGER NOT NULL, occurred_at INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS mfa_webauthn_challenge_context (challenge_digest BLOB PRIMARY KEY CHECK(length(challenge_digest) = 32), purpose TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS mfa_factor_tokens_expiry ON mfa_factor_tokens(expires_at, digest)",
            "CREATE INDEX IF NOT EXISTS mfa_factor_tokens_account ON mfa_factor_tokens(account_did, session_id, consumed_at, revoked_at)",
            "CREATE INDEX IF NOT EXISTS mfa_audit_events_account ON mfa_audit_events(account_did, occurred_at, event_id)",
        ]
        for statement in statements { _ = try await connection.query(statement) }
        try await recreateCanonicalAppPasswordCapacityTrigger()
        _ = try await connection.query(
            "INSERT INTO control_schema_migrations(version, applied_at) VALUES (8, unixepoch())"
        )
    }

    private func recreateCanonicalAppPasswordCapacityTrigger() async throws {
        _ = try await connection.query(
            "DROP TRIGGER IF EXISTS account_app_passwords_account_capacity"
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER account_app_passwords_account_capacity
            BEFORE INSERT ON account_app_passwords
            WHEN (SELECT COUNT(*) FROM account_app_passwords WHERE did = NEW.did) >= \(SQLiteLayout.AccountControlSchemaCapacity.maxAppPasswordsPerAccount)
            BEGIN
                SELECT RAISE(ABORT, 'app password account capacity exhausted');
            END
            """
        )
    }

    private func rebuildIdentityBindingsForReleasedIdentityReuseIfNeeded() async throws {
        let rows = try await connection.query(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='identity_bindings'"
        )
        guard let sql = rows.first?.column("sql")?.string,
              sql.uppercased().contains("IDENTITY_DID TEXT NOT NULL UNIQUE") else { return }

        _ = try await connection.query("ALTER TABLE identity_bindings RENAME TO identity_bindings_v7")
        _ = try await connection.query(
            """
            CREATE TABLE identity_bindings (
              account_did TEXT PRIMARY KEY REFERENCES accounts(did) ON DELETE CASCADE,
              identity_did TEXT NOT NULL,
              method TEXT NOT NULL CHECK(method IN ('plc', 'did-web')),
              handle TEXT NOT NULL,
              document_digest BLOB CHECK(document_digest IS NULL OR length(document_digest) = 32),
              claim_receipt_digest BLOB CHECK(claim_receipt_digest IS NULL OR length(claim_receipt_digest) = 32),
              reserved_key_id TEXT, last_validated_at INTEGER, grace_expires_at INTEGER,
              state TEXT NOT NULL CHECK(state IN ('active', 'suspended', 'released')),
              CHECK(method = 'did-web' OR (document_digest IS NULL AND claim_receipt_digest IS NULL AND reserved_key_id IS NULL)),
              CHECK(method = 'plc' OR (document_digest IS NOT NULL AND claim_receipt_digest IS NOT NULL AND length(reserved_key_id) > 0))
            )
            """
        )
        _ = try await connection.query(
            "INSERT INTO identity_bindings SELECT account_did,identity_did,method,handle,document_digest,claim_receipt_digest,reserved_key_id,last_validated_at,grace_expires_at,state FROM identity_bindings_v7"
        )
        _ = try await connection.query("DROP TABLE identity_bindings_v7")
        _ = try await connection.query("CREATE TRIGGER identity_bindings_capacity BEFORE INSERT ON identity_bindings WHEN (SELECT COUNT(*) FROM identity_bindings) >= 100000 BEGIN SELECT RAISE(ABORT, 'identity binding capacity exhausted'); END")
        _ = try await connection.query("CREATE TRIGGER identity_bindings_account_capacity BEFORE INSERT ON identity_bindings WHEN (SELECT COUNT(*) FROM identity_bindings WHERE account_did = NEW.account_did) >= 1 BEGIN SELECT RAISE(ABORT, 'identity binding account capacity exhausted'); END")
        _ = try await connection.query("CREATE TRIGGER identity_bindings_account_immutable BEFORE UPDATE OF account_did ON identity_bindings WHEN NEW.account_did <> OLD.account_did BEGIN SELECT RAISE(ABORT, 'identity binding account ownership is immutable'); END")
    }
}
