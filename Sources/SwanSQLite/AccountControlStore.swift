import Foundation
import SQLiteNIO
import SwanCore
import SwanPublicFirehose
import SwanStorage

extension SQLiteControlDatabase {
    // MARK: Account control schema

    /// Once a delivery crosses the durable pre-network fence, keep its lease
    /// alive for the maximum bounded SMTP attempt window. This prevents a
    /// normal short claim lease from being reclaimed while the network call is
    /// still in flight; the delivery service must complete or fail within the
    /// same five-minute bound.
    static let maximumEmailDeliveryAttemptDuration: TimeInterval = 300

    /// Email rate-limit keys are intentionally keyed by HMAC digests, so an
    /// attacker can otherwise create a durable row for every address they
    /// submit. Keep the table globally bounded and reclaim only a capped
    /// number of expired rows per request.
    static let maximumEmailRateLimitEntries = 4_096
    static let emailRateLimitPurgeBatchSize = 512
    static let emailRecoveryPurgeBatchSize = 256
    private static let legacyEmailRateLimitWindowMicroseconds =
        86_400 * 1_000_000

    /// Evolves the alpha `accounts` registry in place. Legacy accounts retain
    /// a NULL verifier, which decodes only as `.missing`; migration never
    /// fabricates a usable credential from an absent column.
    func migrateAccountControlSchema() async throws {
        try await addColumnIfMissing(
            table: "accounts",
            column: "updated_at",
            definition: "INTEGER"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "password_verifier",
            definition: "TEXT"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "signing_key_generation",
            definition: "INTEGER"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "signing_key_reference",
            definition: "TEXT"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "rotation_key_generation",
            definition: "INTEGER"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "rotation_key_reference",
            definition: "TEXT"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "public_genesis_commit_cid",
            definition: "TEXT"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "tombstone_declared_at",
            definition: "INTEGER"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "tombstone_reason",
            definition: "TEXT"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "export_declared_at",
            definition: "INTEGER"
        )
        try await addColumnIfMissing(
            table: "accounts",
            column: "export_reference",
            definition: "TEXT"
        )

        _ = try await connection.query(
            "UPDATE accounts SET updated_at = created_at WHERE updated_at IS NULL"
        )

        // The first alpha table had a binary unique `handle` column but no
        // canonical-case guarantee. Reject a legacy ambiguity rather than
        // allowing two spellings of a canonical handle to become usable.
        let collisions = try await connection.query(
            """
            SELECT lower(handle) AS canonical_handle
            FROM accounts
            GROUP BY lower(handle)
            HAVING COUNT(*) > 1
            """
        )
        guard collisions.isEmpty else { throw AccountControlStoreError.malformedRecord }
        _ = try await connection.query(
            "UPDATE accounts SET handle = lower(handle) WHERE handle != lower(handle)"
        )
        _ = try await connection.query(
            "CREATE UNIQUE INDEX IF NOT EXISTS accounts_canonical_handle_unique ON accounts(lower(handle))"
        )
        _ = try await connection.query(
            """
            CREATE TABLE IF NOT EXISTS account_emails (
                did TEXT PRIMARY KEY REFERENCES accounts(did) ON DELETE CASCADE,
                email TEXT NOT NULL UNIQUE,
                verified_at INTEGER CHECK(verified_at >= 0),
                updated_at INTEGER NOT NULL CHECK(updated_at >= 0)
            )
            """
        )
        _ = try await connection.query(
            """
            CREATE TABLE IF NOT EXISTS account_email_tokens (
                digest BLOB PRIMARY KEY CHECK(length(digest) = 32),
                did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
                email TEXT NOT NULL,
                purpose TEXT NOT NULL CHECK(purpose IN ('verify-email', 'password-recovery')),
                expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
                consumed_at INTEGER CHECK(consumed_at >= 0)
            )
            """
        )
        // Pre-binding alpha databases cannot prove which address received an
        // outstanding token. Add the column, then invalidate those legacy
        // proofs instead of guessing that the account's current address was
        // also the delivery address.
        try await addColumnIfMissing(
            table: "account_email_tokens",
            column: "email",
            definition: "TEXT"
        )
        try await addColumnIfMissing(
            table: "account_email_tokens",
            column: "delivery_id",
            definition: "TEXT"
        )
        _ = try await connection.query(
            "DELETE FROM account_email_tokens WHERE email IS NULL"
        )
        _ = try await connection.query("CREATE INDEX IF NOT EXISTS account_email_tokens_expiry ON account_email_tokens(expires_at)")
        _ = try await connection.query(
            "CREATE INDEX IF NOT EXISTS account_email_tokens_account_purpose ON account_email_tokens(did, purpose)"
        )
        _ = try await connection.query(
            "CREATE UNIQUE INDEX IF NOT EXISTS account_email_tokens_delivery_id_unique ON account_email_tokens(delivery_id) WHERE delivery_id IS NOT NULL"
        )
        _ = try await connection.query(
            """
            CREATE TABLE IF NOT EXISTS account_email_delivery_outbox (
                delivery_id TEXT PRIMARY KEY
                    CHECK(length(delivery_id) = 43)
                    CHECK(delivery_id NOT GLOB '*[^A-Za-z0-9_-]*'),
                did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
                email TEXT NOT NULL,
                email_generation INTEGER NOT NULL CHECK(email_generation > 0),
                purpose TEXT NOT NULL
                    CHECK(purpose IN ('verify-email', 'password-recovery')),
                expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
                state TEXT NOT NULL
                    CHECK(state IN ('pending', 'leased', 'sent', 'cancelled')),
                lease_owner TEXT,
                lease_expires_at INTEGER CHECK(lease_expires_at >= 0),
                attempts INTEGER NOT NULL DEFAULT 0
                    CHECK(attempts BETWEEN 0 AND 64),
                next_attempt_at INTEGER NOT NULL CHECK(next_attempt_at >= 0),
                created_at INTEGER NOT NULL CHECK(created_at >= 0),
                send_started_at INTEGER CHECK(send_started_at >= 0),
                sent_at INTEGER CHECK(sent_at >= 0),
                CHECK(
                    (state = 'leased' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
                    OR
                    (state != 'leased' AND lease_owner IS NULL AND lease_expires_at IS NULL)
                )
            )
            """
        )
        // A delivery can be claimed in one transaction and reach SMTP only
        // after a second transaction. Persist that boundary so permanent
        // deletion can serialize against the actual network attempt. Legacy
        // rows start with a NULL fence and remain reclaimable after restart.
        try await addColumnIfMissing(
            table: "account_email_delivery_outbox",
            column: "send_started_at",
            definition: "INTEGER"
        )
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS account_email_delivery_due
            ON account_email_delivery_outbox(state, next_attempt_at, created_at)
            """
        )
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS account_email_delivery_account_purpose
            ON account_email_delivery_outbox(did, purpose)
            """
        )
        let currentEmailRateLimitTable = """
            CREATE TABLE IF NOT EXISTS account_email_rate_limits (
                scope TEXT NOT NULL CHECK(scope IN ('did', 'email', 'direct-peer')),
                key_digest BLOB NOT NULL CHECK(length(key_digest) = 32),
                window_started_at INTEGER NOT NULL CHECK(window_started_at >= 0),
                expires_at INTEGER NOT NULL CHECK(expires_at > window_started_at),
                attempts INTEGER NOT NULL CHECK(attempts BETWEEN 1 AND 10000),
                PRIMARY KEY(scope, key_digest)
            ) WITHOUT ROWID
            """
        _ = try await connection.query(currentEmailRateLimitTable)
        let rateLimitColumns = try await connection.query(
            "PRAGMA table_info(account_email_rate_limits)"
        )
        let rateLimitColumnNames = Set(
            rateLimitColumns.compactMap { $0.column("name")?.string }
        )
        if !rateLimitColumnNames.contains("expires_at") {
            let legacyColumns: Set<String> = [
                "scope", "key_digest", "window_started_at", "attempts",
            ]
            guard legacyColumns.isSubset(of: rateLimitColumnNames) else {
                throw AccountControlStoreError.malformedRecord
            }
            let invalidLegacyRows = try await connection.query(
                """
                SELECT 1
                FROM account_email_rate_limits
                WHERE scope NOT IN ('did', 'email', 'direct-peer')
                   OR typeof(key_digest) != 'blob'
                   OR length(key_digest) != 32
                   OR typeof(window_started_at) != 'integer'
                   OR window_started_at < 0
                   OR window_started_at > ?
                   OR typeof(attempts) != 'integer'
                   OR attempts NOT BETWEEN 1 AND 10000
                LIMIT 1
                """,
                [.integer(Int.max - Self.legacyEmailRateLimitWindowMicroseconds)]
            )
            guard invalidLegacyRows.isEmpty else {
                throw AccountControlStoreError.malformedRecord
            }
            _ = try await connection.query(
                "DROP INDEX IF EXISTS account_email_rate_limits_expiry"
            )
            _ = try await connection.query(
                "DROP TRIGGER IF EXISTS account_email_rate_limit_count_insert"
            )
            _ = try await connection.query(
                "DROP TRIGGER IF EXISTS account_email_rate_limit_count_delete"
            )
            _ = try await connection.query(
                "ALTER TABLE account_email_rate_limits RENAME TO account_email_rate_limits_v1"
            )
            _ = try await connection.query(currentEmailRateLimitTable)
            _ = try await connection.query(
                """
                INSERT INTO account_email_rate_limits(
                    scope, key_digest, window_started_at, expires_at, attempts
                )
                SELECT scope, key_digest, window_started_at,
                       window_started_at + ?, attempts
                FROM account_email_rate_limits_v1
                """,
                [.integer(Self.legacyEmailRateLimitWindowMicroseconds)]
            )
            _ = try await connection.query(
                "DROP TABLE account_email_rate_limits_v1"
            )
        } else {
            let requiredColumns: Set<String> = [
                "scope", "key_digest", "window_started_at", "expires_at", "attempts",
            ]
            guard requiredColumns.isSubset(of: rateLimitColumnNames) else {
                throw AccountControlStoreError.malformedRecord
            }
        }
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS account_email_rate_limits_expiry
            ON account_email_rate_limits(expires_at, scope, key_digest)
            """
        )
        _ = try await connection.query(
            """
            CREATE TABLE IF NOT EXISTS account_email_rate_limit_capacity (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                entry_count INTEGER NOT NULL CHECK(entry_count >= 0)
            )
            """
        )
        _ = try await connection.query(
            """
            INSERT INTO account_email_rate_limit_capacity(singleton, entry_count)
            SELECT 1, COUNT(*) FROM account_email_rate_limits WHERE 1
            ON CONFLICT(singleton) DO UPDATE SET entry_count = excluded.entry_count
            """
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS account_email_rate_limit_count_insert
            AFTER INSERT ON account_email_rate_limits
            BEGIN
                UPDATE account_email_rate_limit_capacity
                SET entry_count = entry_count + 1
                WHERE singleton = 1;
            END
            """
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS account_email_rate_limit_count_delete
            AFTER DELETE ON account_email_rate_limits
            BEGIN
                UPDATE account_email_rate_limit_capacity
                SET entry_count = entry_count - 1
                WHERE singleton = 1;
            END
            """
        )
        try await trimEmailRateLimitOverflowLocked()
        // Password-recovery requests always leave this short-lived, keyed
        // marker. It contains no DID or plaintext mailbox, and gives unknown
        // and known canonical addresses the same durable admission shape.
        _ = try await connection.query(
            """
            CREATE TABLE IF NOT EXISTS account_password_recovery_work (
                lookup_digest BLOB PRIMARY KEY CHECK(length(lookup_digest) = 32),
                expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
                created_at INTEGER NOT NULL CHECK(created_at >= 0),
                account_candidate INTEGER NOT NULL DEFAULT 0 CHECK(account_candidate IN (0, 1)),
                delivery_id TEXT,
                proof_digest BLOB,
                email_envelope BLOB,
                lease_owner TEXT,
                lease_expires_at INTEGER,
                attempts INTEGER NOT NULL DEFAULT 0
            ) WITHOUT ROWID
            """
        )
        // Older alpha databases had only the three marker columns. Add the
        // asynchronous queue fields without attempting to infer or revive
        // legacy requests whose bearer material was never persisted.
        try await addColumnIfMissing(
            table: "account_password_recovery_work",
            column: "account_candidate",
            definition: "INTEGER NOT NULL DEFAULT 0 CHECK(account_candidate IN (0, 1))"
        )
        try await addColumnIfMissing(
            table: "account_password_recovery_work",
            column: "delivery_id",
            definition: "TEXT"
        )
        try await addColumnIfMissing(
            table: "account_password_recovery_work",
            column: "proof_digest",
            definition: "BLOB"
        )
        try await addColumnIfMissing(
            table: "account_password_recovery_work",
            column: "email_envelope",
            definition: "BLOB"
        )
        try await addColumnIfMissing(
            table: "account_password_recovery_work",
            column: "lease_owner",
            definition: "TEXT"
        )
        try await addColumnIfMissing(
            table: "account_password_recovery_work",
            column: "lease_expires_at",
            definition: "INTEGER"
        )
        try await addColumnIfMissing(
            table: "account_password_recovery_work",
            column: "attempts",
            definition: "INTEGER NOT NULL DEFAULT 0"
        )
        _ = try await connection.query(
            """
            DELETE FROM account_password_recovery_work
            WHERE delivery_id IS NULL
               OR proof_digest IS NULL
               OR email_envelope IS NULL
            """
        )
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS account_password_recovery_work_expiry
            ON account_password_recovery_work(expires_at, lookup_digest)
            """
        )
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS account_password_recovery_work_lease
            ON account_password_recovery_work(lease_expires_at, created_at)
            """
        )
        try await trimPasswordRecoveryWorkOverflowLocked()
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS account_email_tokens_email_required_insert
            BEFORE INSERT ON account_email_tokens
            WHEN NEW.email IS NULL
            BEGIN
                SELECT RAISE(ABORT, 'email token address is required');
            END
            """
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS account_email_tokens_email_required_update
            BEFORE UPDATE OF email ON account_email_tokens
            WHEN NEW.email IS NULL
            BEGIN
                SELECT RAISE(ABORT, 'email token address is required');
            END
            """
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS accounts_status_valid_insert
            BEFORE INSERT ON accounts
            WHEN NEW.status = ''
              OR length(NEW.status) > 64
              OR substr(NEW.status, 1, 1) NOT GLOB '[a-z]'
              OR NEW.status GLOB '*[^a-z0-9_-]*'
            BEGIN
                SELECT RAISE(ABORT, 'invalid account status');
            END
            """
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS accounts_status_valid_update
            BEFORE UPDATE OF status ON accounts
            WHEN NEW.status = ''
              OR length(NEW.status) > 64
              OR substr(NEW.status, 1, 1) NOT GLOB '[a-z]'
              OR NEW.status GLOB '*[^a-z0-9_-]*'
            BEGIN
                SELECT RAISE(ABORT, 'invalid account status');
            END
            """
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS accounts_handle_canonical_insert
            BEFORE INSERT ON accounts
            WHEN NEW.handle != lower(NEW.handle)
            BEGIN
                SELECT RAISE(ABORT, 'account handle must be canonical');
            END
            """
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS accounts_handle_canonical_update
            BEFORE UPDATE OF handle ON accounts
            WHEN NEW.handle != lower(NEW.handle)
            BEGIN
                SELECT RAISE(ABORT, 'account handle must be canonical');
            END
            """
        )
        try await migrateAccountLoginAdmissionSchema()
        try await migrateAccountPermanentDeletionSchema()
        try await migratePublicCrawlAnnouncerSchema()
    }

    // MARK: AccountControlStore

    /// Offline-restore invariant: exactly one selected account exists and no
    /// OAuth, replay, client-metadata, email/recovery, PLC credential-key
    /// continuity, or PLC-preparation control state was fabricated. Kept
    /// behind SPI so request-time modules cannot treat it as a general
    /// control-plane inspection API.
    @_spi(PortableRestore)
    public func validateOperatorRestoreOnlyAccount(did: String) async throws {
        try await validateOperatorRestoreOnlyAccount(
            did: did,
            plcCredentialKeyContinuity: []
        )
    }

    /// The operator-backup variant authenticates an exact PLC continuity
    /// inventory inside its encrypted payload. Every other control-plane table
    /// remains empty; continuity is compared exactly instead of being mistaken
    /// for fabricated state.
    @_spi(PortableRestore)
    public func validateOperatorRestoreOnlyAccount(
        did: String,
        plcCredentialKeyContinuity checkpoints:
            [PLCCredentialKeyContinuityCheckpoint],
        plcAccountPreparationIntent expectedIntent: PLCAccountPreparationIntent? = nil
    ) async throws {
        guard AccountControlIdentifiers.isDID(did) else {
            throw AccountControlStoreError.invalidInput
        }
        let inventory = try PLCCredentialKeyContinuityInventory(
            checkpoints: checkpoints
        )
        try await withConnectionGate {
            try await validateOperatorRestoreOnlyAccountLocked(
                did: did,
                plcCredentialKeyContinuity: inventory,
                plcAccountPreparationIntent: expectedIntent
            )
        }
    }

    /// Installs the restored account and its authenticated global PLC trust
    /// anchors in the same `BEGIN IMMEDIATE` transaction. A preexisting exact
    /// inventory is idempotent; a partial or conflicting terminal is rejected
    /// without inserting the account or altering any checkpoint.
    @_spi(PortableRestore)
    public func restoreOperatorAccountAndPLCCredentialKeyContinuity(
        _ registration: AccountControlRegistration,
        checkpoints: [PLCCredentialKeyContinuityCheckpoint],
        plcAccountPreparationIntent: PLCAccountPreparationIntent? = nil
    ) async throws -> AccountControlAccount {
        try validate(registration: registration)
        let inventory = try PLCCredentialKeyContinuityInventory(
            checkpoints: checkpoints
        )
        if let plcAccountPreparationIntent {
            guard plcAccountPreparationIntent.did == registration.did,
                  plcAccountPreparationIntent.canonicalHandle
                    == registration.canonicalHandle,
                  plcAccountPreparationIntent.repositoryRevision
                    .isEmpty == false,
                  plcAccountPreparationIntent.stage == .submitted else {
                throw AccountControlStoreError.invalidInput
            }
        }
        return try await withConnectionGate {
            try await transaction {
                let existing =
                    try await plcCredentialKeyContinuityInventoryLocked()
                guard existing.checkpoints.isEmpty || existing == inventory else {
                    throw PLCCredentialKeyContinuityStoreError
                        .continuityViolation
                }
                try await installPLCCredentialKeyContinuityInventoryLocked(
                    inventory
                )
                if let plcAccountPreparationIntent {
                    try await insertPLCAccountPreparationIntentLocked(
                        plcAccountPreparationIntent
                    )
                }
                return try await insertAccountLocked(registration)
            }
        }
    }

    public func createAccount(
        _ registration: AccountControlRegistration
    ) async throws -> AccountControlAccount {
        try validate(registration: registration)
        return try await withConnectionGate {
            try await transaction {
                try await insertAccountLocked(registration)
            }
        }
    }

    public func rotateAccountKeys(
        did: String,
        request: AccountControlKeyRotationRequest,
        now: Date
    ) async throws -> AccountControlAccount {
        guard AccountControlIdentifiers.isDID(did) else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                let account = try await requiredAccount(did: did)
                guard account.status.authorizesAccount else {
                    throw AccountControlStoreError.invalidTransition
                }
                guard let signing = account.signingKey,
                      let rotation = account.rotationKey,
                      signing.generation == request.expectedGeneration,
                      rotation.generation == request.expectedGeneration,
                      signing.purpose == .signing,
                      rotation.purpose == .rotation else {
                    throw AccountControlStoreError.invalidTransition
                }
                let rotated = try await connection.query(
                    """
                    UPDATE accounts
                    SET signing_key_generation = ?, signing_key_reference = ?,
                        rotation_key_generation = ?, rotation_key_reference = ?,
                        updated_at = CASE
                            WHEN updated_at >= ? THEN updated_at + 1
                            ELSE ?
                        END
                    WHERE did = ?
                      AND signing_key_generation = ?
                      AND rotation_key_generation = ?
                      AND updated_at < ?
                    RETURNING updated_at
                    """,
                    [
                        .integer(try controlGeneration(request.signingKey.generation)),
                        .text(request.signingKey.reference),
                        .integer(try controlGeneration(request.rotationKey.generation)),
                        .text(request.rotationKey.reference),
                        .integer(timestamp), .integer(timestamp), .text(did),
                        .integer(try controlGeneration(request.expectedGeneration)),
                        .integer(try controlGeneration(request.expectedGeneration)),
                        .integer(Int.max),
                    ]
                )
                guard rotated.count == 1,
                      case let .integer(revision) =
                          rotated[0].column("updated_at"),
                      revision > 0 else {
                    throw AccountControlStoreError.invalidTransition
                }
                let updated = try await requiredAccount(did: did)
                guard updated.signingKey == request.signingKey,
                      updated.rotationKey == request.rotationKey else {
                    throw AccountControlStoreError.invalidTransition
                }
                return updated
            }
        }
    }

    public func account(did: String) async throws -> AccountControlAccount? {
        guard AccountControlIdentifiers.isDID(did) else { throw AccountControlStoreError.invalidInput }
        return try await withConnectionGate {
            let rows = try await connection.query(
                accountSelectSQL + " WHERE did = ?",
                [.text(did)]
            )
            guard let row = rows.first else { return nil }
            return try decodeAccount(row)
        }
    }

    public func account(canonicalHandle: String) async throws -> AccountControlAccount? {
        guard AccountControlIdentifiers.isCanonicalHandle(canonicalHandle) else {
            throw AccountControlStoreError.invalidInput
        }
        return try await withConnectionGate {
            let rows = try await connection.query(
                accountSelectSQL + " WHERE handle = ?",
                [.text(canonicalHandle)]
            )
            guard let row = rows.first else { return nil }
            return try decodeAccount(row)
        }
    }

    /// A startup-only inventory for services that must preopen known account
    /// databases. Keep this status-only: control credentials, handles, keys,
    /// exports, and repository metadata must not cross this boundary.
    public func activeAccountDIDs() async throws -> [String] {
        try await withConnectionGate {
            let rows = try await connection.query(
                "SELECT did, status FROM accounts WHERE status = 'active' ORDER BY did"
            )
            var result: [String] = []
            var previous: String?
            for row in rows {
                let did = try requiredText(row, "did")
                let status = try AccountControlStatus(rawValue: requiredText(row, "status"))
                guard AccountControlIdentifiers.isDID(did),
                      status == .active,
                      status.isCanonicalValue,
                      previous.map({ $0 < did }) ?? true else {
                    throw AccountControlStoreError.malformedRecord
                }
                result.append(did)
                previous = did
            }
            return result
        }
    }

    public func associateEmail(did: String, email: AccountEmailAddress, now: Date) async throws {
        guard AccountControlIdentifiers.isDID(did) else { throw AccountControlStoreError.invalidInput }
        let timestamp = try controlTimestamp(now)
        try await withConnectionGate {
            try await transaction {
                let accounts = try await connection.query(
                    "SELECT status, updated_at FROM accounts WHERE did = ?",
                    [.text(did)]
                )
                guard let account = accounts.first else {
                    throw AccountControlStoreError.notFound
                }
                let status = try AccountControlStatus(
                    rawValue: requiredText(account, "status")
                )
                guard status == .active, status.isCanonicalValue else {
                    throw AccountControlStoreError.invalidTransition
                }
                let advanced = try await connection.query(
                    """
                    UPDATE accounts
                    SET updated_at = CASE
                        WHEN updated_at >= ? THEN updated_at + 1
                        ELSE ?
                    END
                    WHERE did = ? AND status = 'active'
                      AND updated_at < ?
                    RETURNING updated_at
                    """,
                    [
                        .integer(timestamp), .integer(timestamp), .text(did),
                        .integer(Int.max),
                    ]
                )
                guard advanced.count == 1,
                      case let .integer(generation) =
                          advanced[0].column("updated_at"),
                      generation > 0 else {
                    throw AccountControlStoreError.malformedRecord
                }
                // Treat every association as a new address generation. Delete
                // proofs in the same write transaction before resetting
                // verification so A -> B -> A cannot revive a proof delivered
                // to the first A generation.
                _ = try await connection.query(
                    "DELETE FROM account_email_tokens WHERE did = ?",
                    [.text(did)]
                )
                _ = try await connection.query(
                    "DELETE FROM account_email_delivery_outbox WHERE did = ?",
                    [.text(did)]
                )
                _ = try await connection.query(
                    """
                    INSERT INTO account_emails(did, email, verified_at, updated_at) VALUES (?, ?, NULL, ?)
                    ON CONFLICT(did) DO UPDATE SET email = excluded.email, verified_at = NULL, updated_at = excluded.updated_at
                    """, [.text(did), .text(email.value), .integer(generation)]
                )
            }
        }
    }

    public func enqueueEmailProofDelivery(
        _ request: AccountEmailProofDeliveryRequest
    ) async throws -> AccountEmailEnqueueOutcome {
        guard request.purpose == .verifyEmail,
              AccountControlIdentifiers.isDID(request.did),
              (try? AccountEmailAddress(request.email.value)) == request.email,
              request.proofDigest.count == 32 else {
            throw AccountControlStoreError.invalidInput
        }
        let expiry = try controlTimestamp(request.expiresAt)
        let created = try controlTimestamp(request.createdAt)
        guard expiry > created else { throw AccountControlStoreError.invalidInput }
        return try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT a.status, e.email, e.updated_at
                    FROM accounts AS a
                    LEFT JOIN account_emails AS e ON e.did = a.did
                    WHERE a.did = ?
                    """,
                    [.text(request.did)]
                )
                guard let row = rows.first else { return .accountNotFound }
                let status = try AccountControlStatus(
                    rawValue: requiredText(row, "status")
                )
                guard status == .active, status.isCanonicalValue else {
                    return .accountNotFound
                }
                guard try optionalText(row, "email") == request.email.value,
                      let generation = try optionalInteger(row, "updated_at"),
                      generation > 0 else {
                    return .invalidEmail
                }
                try await insertEmailProofDeliveryLocked(
                    deliveryID: request.deliveryID,
                    did: request.did,
                    email: request.email,
                    emailGeneration: generation,
                    purpose: request.purpose,
                    proofDigest: request.proofDigest,
                    expiresAt: expiry,
                    createdAt: created
                )
                return .enqueued
            }
        }
    }

    public func enqueuePasswordRecoveryDelivery(
        _ request: AccountPasswordRecoveryDeliveryRequest
    ) async throws {
        guard request.proofDigest.count == 32,
              request.lookupDigest.count == 32,
              (28 ... 4_096).contains(request.emailEnvelope.count) else {
            throw AccountControlStoreError.invalidInput
        }
        let expiry = try controlTimestamp(request.expiresAt)
        let created = try controlTimestamp(request.createdAt)
        guard expiry > created else { throw AccountControlStoreError.invalidInput }
        try await withConnectionGate {
            try await transaction {
                // Every canonical request performs one keyed, account-free
                // write before the account lookup. The marker is deliberately
                // not tied to a DID and expires with the requested proof.
                // Keep request-time cleanup bounded.  This table has a hard
                // global capacity, but a legacy or crash-recovered database
                // may still contain the full expired set.  A plain DELETE
                // over the indexed expiry column would turn one blind
                // request into an unbounded write transaction and could
                // monopolize the shared control database.  The same batch
                // contract is used by the background/claim purge path.
                _ = try await connection.query(
                    """
                    DELETE FROM account_password_recovery_work
                    WHERE lookup_digest IN (
                        SELECT lookup_digest
                        FROM account_password_recovery_work
                        WHERE expires_at <= ?
                        ORDER BY expires_at, created_at, lookup_digest
                        LIMIT ?
                    )
                    """,
                    [
                        .integer(created),
                        .integer(Self.passwordRecoveryWorkPurgeBatchSize),
                    ]
                )
                let existingMarker = try await connection.query(
                    """
                    SELECT 1
                    FROM account_password_recovery_work
                    WHERE lookup_digest = ?
                    LIMIT 1
                    """,
                    [blob(request.lookupDigest)]
                )
                guard existingMarker.count <= 1 else {
                    throw AccountControlStoreError.malformedRecord
                }
                // Perform the same indexed lookup for every canonical
                // request. The HTTP layer retains its bounded response floor,
                // and only this one-bit capacity class is stored; the
                // plaintext address is never written to the marker.
                let accountRows = try await connection.query(
                    """
                    SELECT 1
                    FROM account_emails AS e
                    JOIN accounts AS a ON a.did = e.did
                    WHERE e.email = ?
                      AND e.verified_at IS NOT NULL
                      AND a.status = 'active'
                    LIMIT 2
                    """,
                    [.text(request.email.value)]
                )
                guard accountRows.count <= 1 else {
                    throw AccountControlStoreError.malformedRecord
                }
                let accountCandidate = !accountRows.isEmpty
                if existingMarker.isEmpty {
                    let countRows = try await connection.query(
                        """
                        SELECT COUNT(*) AS row_count,
                               COALESCE(SUM(CASE WHEN account_candidate = 0 THEN 1 ELSE 0 END), 0)
                                   AS anonymous_count
                        FROM account_password_recovery_work
                        """
                    )
                    guard countRows.count == 1,
                          case let .integer(rowCount) =
                              countRows[0].column("row_count"),
                          case let .integer(anonymousCount) =
                              countRows[0].column("anonymous_count"),
                          rowCount >= 0,
                          anonymousCount >= 0 else {
                        throw AccountControlStoreError.malformedRecord
                    }
                    let anonymousLimit =
                        Self.maximumPasswordRecoveryWorkMarkers
                        - Self.passwordRecoveryKnownAccountReserve
                    guard rowCount < Self.maximumPasswordRecoveryWorkMarkers,
                          accountCandidate || anonymousCount < anonymousLimit else {
                        // The HTTP layer collapses this with all other
                        // account-dependent recovery outcomes. Rejecting the
                        // new marker keeps the blind response contract while
                        // preserving the durable capacity invariant.
                        throw SwanError.unavailable(
                            "password recovery work capacity is exhausted"
                        )
                    }
                }
                _ = try await connection.query(
                    """
                    INSERT INTO account_password_recovery_work(
                        lookup_digest, expires_at, created_at, account_candidate,
                        delivery_id, proof_digest, email_envelope,
                        lease_owner, lease_expires_at, attempts
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, 0)
                    ON CONFLICT(lookup_digest) DO UPDATE SET
                        expires_at = excluded.expires_at,
                        created_at = excluded.created_at,
                        account_candidate = excluded.account_candidate,
                        delivery_id = excluded.delivery_id,
                        proof_digest = excluded.proof_digest,
                        email_envelope = excluded.email_envelope,
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        attempts = 0
                    """,
                    [
                        blob(request.lookupDigest),
                        .integer(expiry),
                        .integer(created),
                        .integer(accountCandidate ? 1 : 0),
                        .text(request.deliveryID.rawValue),
                        blob(request.proofDigest),
                        blob(request.emailEnvelope),
                    ]
                )
            }
        }
    }

    public func claimNextPasswordRecoveryWork(
        workerID: String,
        now: Date,
        leaseDuration: TimeInterval
    ) async throws -> AccountPasswordRecoveryWorkLease? {
        guard AccountEmailStorageValidation.isWorkerID(workerID),
              leaseDuration.isFinite,
              (0.1 ... 300).contains(leaseDuration) else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        let leaseExpiry = try controlTimestamp(
            now.addingTimeInterval(leaseDuration)
        )
        return try await withConnectionGate {
            try await transaction {
                try await purgeExpiredEmailRecoveryStateLocked(
                    timestamp: timestamp
                )
                _ = try await connection.query(
                    """
                    UPDATE account_password_recovery_work
                    SET lease_owner = NULL,
                        lease_expires_at = NULL,
                        attempts = 0
                    WHERE lease_expires_at IS NOT NULL
                      AND lease_expires_at <= ?
                    """,
                    [.integer(timestamp)]
                )
                let candidates = try await connection.query(
                    """
                    SELECT lookup_digest
                    FROM account_password_recovery_work
                    WHERE expires_at > ?
                      AND lease_owner IS NULL
                      AND attempts < 64
                    ORDER BY created_at, lookup_digest
                    LIMIT 1
                    """,
                    [.integer(timestamp)]
                )
                guard let candidate = candidates.first else { return nil }
                guard case let .blob(lookupDigest) =
                          candidate.column("lookup_digest"),
                      lookupDigest.readableBytes == 32 else {
                    throw AccountControlStoreError.malformedRecord
                }
                let rows = try await connection.query(
                    """
                    UPDATE account_password_recovery_work
                    SET lease_owner = ?,
                        lease_expires_at = ?,
                        attempts = attempts + 1
                    WHERE lookup_digest = ?
                      AND expires_at > ?
                      AND lease_owner IS NULL
                      AND attempts < 64
                    RETURNING lookup_digest, delivery_id, proof_digest,
                              email_envelope, expires_at, created_at, attempts
                    """,
                    [
                        .text(workerID), .integer(leaseExpiry),
                        blob(Data(lookupDigest.readableBytesView)),
                        .integer(timestamp),
                    ]
                )
                guard rows.count <= 1 else {
                    throw AccountControlStoreError.malformedRecord
                }
                guard let row = rows.first else { return nil }
                guard case let .blob(returnedLookup) =
                          row.column("lookup_digest"),
                      case let .blob(proofDigest) =
                          row.column("proof_digest"),
                      case let .blob(emailEnvelope) =
                          row.column("email_envelope"),
                      returnedLookup.readableBytes == 32,
                      proofDigest.readableBytes == 32,
                      (28 ... 4_096).contains(emailEnvelope.readableBytes),
                      case let .integer(expiresAt) =
                          row.column("expires_at"),
                      case let .integer(createdAt) =
                          row.column("created_at"),
                      case let .integer(attempts) =
                          row.column("attempts"),
                      expiresAt > createdAt,
                      (1 ... 64).contains(attempts) else {
                    throw AccountControlStoreError.malformedRecord
                }
                let deliveryID: String
                do {
                    deliveryID = try requiredText(row, "delivery_id")
                } catch {
                    throw AccountControlStoreError.malformedRecord
                }
                do {
                    return try AccountPasswordRecoveryWorkLease(
                        deliveryID: AccountEmailDeliveryID(
                            rawValue: deliveryID
                        ),
                        lookupDigest: Data(returnedLookup.readableBytesView),
                        proofDigest: Data(proofDigest.readableBytesView),
                        emailEnvelope: Data(emailEnvelope.readableBytesView),
                        expiresAt: Date(
                            timeIntervalSince1970: Double(expiresAt) / 1_000_000
                        ),
                        createdAt: Date(
                            timeIntervalSince1970: Double(createdAt) / 1_000_000
                        ),
                        attempts: attempts
                    )
                } catch {
                    throw AccountControlStoreError.malformedRecord
                }
            }
        }
    }

    public func materializePasswordRecoveryWork(
        _ work: AccountPasswordRecoveryWorkLease,
        email: AccountEmailAddress,
        workerID: String,
        now: Date
    ) async throws -> AccountPasswordRecoveryWorkMaterialization {
        guard AccountEmailStorageValidation.isWorkerID(workerID),
              (try? AccountEmailAddress(email.value)) == email else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        let expiry = try controlTimestamp(work.expiresAt)
        let created = try controlTimestamp(work.createdAt)
        return try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT delivery_id, proof_digest, email_envelope,
                           expires_at, created_at
                    FROM account_password_recovery_work
                    WHERE lookup_digest = ?
                      AND lease_owner = ?
                      AND lease_expires_at > ?
                      AND expires_at > ?
                    """,
                    [
                        blob(work.lookupDigest),
                        .text(workerID),
                        .integer(timestamp),
                        .integer(timestamp),
                    ]
                )
                guard rows.count <= 1 else {
                    throw AccountControlStoreError.malformedRecord
                }
                guard let row = rows.first,
                      case let .integer(rowExpiry) =
                          row.column("expires_at"),
                      case let .integer(rowCreated) =
                          row.column("created_at"),
                      rowExpiry == expiry,
                      rowCreated == created,
                      case let .blob(proofDigest) =
                          row.column("proof_digest"),
                      case let .blob(emailEnvelope) =
                          row.column("email_envelope"),
                      proofDigest.readableBytes == 32,
                      (28 ... 4_096).contains(emailEnvelope.readableBytes) else {
                    return .discarded
                }
                guard (try? requiredText(row, "delivery_id"))
                    == work.deliveryID.rawValue else {
                    return .discarded
                }

                let accountRows = try await connection.query(
                    """
                    SELECT a.did, e.updated_at
                    FROM account_emails AS e
                    JOIN accounts AS a ON a.did = e.did
                    WHERE e.email = ?
                      AND e.verified_at IS NOT NULL
                      AND a.status = 'active'
                    """,
                    [.text(email.value)]
                )
                guard accountRows.count <= 1 else {
                    throw AccountControlStoreError.malformedRecord
                }
                if let accountRow = accountRows.first {
                    let did = try requiredText(accountRow, "did")
                    guard AccountControlIdentifiers.isDID(did),
                          case let .integer(generation) =
                              accountRow.column("updated_at"),
                          generation > 0 else {
                        throw AccountControlStoreError.malformedRecord
                    }
                    try await insertEmailProofDeliveryLocked(
                        deliveryID: work.deliveryID,
                        did: did,
                        email: email,
                        emailGeneration: generation,
                        purpose: .passwordRecovery,
                        proofDigest: Data(proofDigest.readableBytesView),
                        expiresAt: expiry,
                        createdAt: created
                    )
                    _ = try await connection.query(
                        """
                        DELETE FROM account_password_recovery_work
                        WHERE lookup_digest = ? AND lease_owner = ?
                        """,
                        [blob(work.lookupDigest), .text(workerID)]
                    )
                    return .enqueued
                }

                _ = try await connection.query(
                    """
                    DELETE FROM account_password_recovery_work
                    WHERE lookup_digest = ? AND lease_owner = ?
                    """,
                    [blob(work.lookupDigest), .text(workerID)]
                )
                return .discarded
            }
        }
    }

    public func discardPasswordRecoveryWork(
        _ work: AccountPasswordRecoveryWorkLease,
        workerID: String,
        now: Date
    ) async throws {
        guard AccountEmailStorageValidation.isWorkerID(workerID) else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    """
                    DELETE FROM account_password_recovery_work
                    WHERE lookup_digest = ?
                      AND lease_owner = ?
                      AND lease_expires_at > ?
                    """,
                    [
                        blob(work.lookupDigest),
                        .text(workerID),
                        .integer(timestamp),
                    ]
                )
            }
        }
    }

    public func claimNextEmailDelivery(
        workerID: String,
        now: Date,
        leaseDuration: TimeInterval
    ) async throws -> AccountEmailDeliveryLease? {
        guard AccountEmailStorageValidation.isWorkerID(workerID),
              leaseDuration.isFinite,
              (0.1 ... 300).contains(leaseDuration) else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        let leaseExpiry = try controlTimestamp(
            now.addingTimeInterval(leaseDuration)
        )
        return try await withConnectionGate {
            try await transaction {
                try await purgeExpiredEmailRecoveryStateLocked(
                    timestamp: timestamp
                )
                _ = try await connection.query(
                    """
                    UPDATE account_email_delivery_outbox
                    SET state = 'pending',
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        send_started_at = NULL
                    WHERE delivery_id IN (
                        SELECT delivery_id
                        FROM account_email_delivery_outbox
                        WHERE state = 'leased'
                          AND lease_expires_at <= ?
                        ORDER BY lease_expires_at, created_at, delivery_id
                        LIMIT ?
                    )
                    """,
                    [
                        .integer(timestamp),
                        .integer(Self.emailRecoveryPurgeBatchSize),
                    ]
                )
                let candidates = try await connection.query(
                    """
                    SELECT o.delivery_id
                    FROM account_email_delivery_outbox AS o
                    JOIN account_email_tokens AS t
                      ON t.delivery_id = o.delivery_id
                     AND t.did = o.did
                     AND t.email = o.email
                     AND t.purpose = o.purpose
                    JOIN accounts AS a ON a.did = o.did
                    JOIN account_emails AS e
                      ON e.did = o.did
                     AND e.email = o.email
                     AND e.updated_at = o.email_generation
                    WHERE o.state = 'pending'
                      AND o.next_attempt_at <= ?
                      AND o.expires_at > ?
                      AND t.consumed_at IS NULL
                      AND t.expires_at = o.expires_at
                      AND a.status = 'active'
                    ORDER BY o.next_attempt_at, o.created_at, o.delivery_id
                    LIMIT 1
                    """,
                    [.integer(timestamp), .integer(timestamp)]
                )
                guard let candidate = candidates.first else { return nil }
                let deliveryID = try requiredText(candidate, "delivery_id")
                let claimed = try await connection.query(
                    """
                    UPDATE account_email_delivery_outbox
                    SET state = 'leased',
                        lease_owner = ?,
                        lease_expires_at = ?,
                        attempts = attempts + 1
                    WHERE delivery_id = ?
                      AND state = 'pending'
                      AND attempts < 64
                    RETURNING delivery_id, did, email, email_generation,
                              purpose, expires_at, attempts
                    """,
                    [
                        .text(workerID), .integer(leaseExpiry),
                        .text(deliveryID),
                    ]
                )
                guard claimed.count <= 1 else {
                    throw AccountControlStoreError.malformedRecord
                }
                guard let row = claimed.first else { return nil }
                return try decodeEmailDeliveryLease(row)
            }
        }
    }

    public func beginEmailDeliveryAttempt(
        deliveryID: AccountEmailDeliveryID,
        workerID: String,
        now: Date
    ) async throws -> Bool {
        guard AccountEmailStorageValidation.isWorkerID(workerID) else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        let fenceExpiry = try controlTimestamp(
            now.addingTimeInterval(Self.maximumEmailDeliveryAttemptDuration)
        )
        return try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    UPDATE account_email_delivery_outbox
                    SET send_started_at = ?,
                        lease_expires_at = CASE
                            WHEN lease_expires_at < ? THEN ?
                            ELSE lease_expires_at
                        END
                    WHERE delivery_id = ?
                      AND state = 'leased'
                      AND lease_owner = ?
                      AND lease_expires_at > ?
                      AND expires_at > ?
                      AND EXISTS (
                          SELECT 1 FROM accounts AS a
                          WHERE a.did = account_email_delivery_outbox.did
                            AND a.status = 'active'
                      )
                      AND EXISTS (
                          SELECT 1 FROM account_email_tokens AS t
                          WHERE t.delivery_id = account_email_delivery_outbox.delivery_id
                            AND t.did = account_email_delivery_outbox.did
                            AND t.email = account_email_delivery_outbox.email
                            AND t.purpose = account_email_delivery_outbox.purpose
                            AND t.consumed_at IS NULL
                            AND t.expires_at = account_email_delivery_outbox.expires_at
                      )
                    RETURNING delivery_id
                    """,
                    [
                        .integer(timestamp), .integer(fenceExpiry),
                        .integer(fenceExpiry), .text(deliveryID.rawValue),
                        .text(workerID), .integer(timestamp), .integer(timestamp),
                    ]
                )
                guard rows.count <= 1 else {
                    throw AccountControlStoreError.malformedRecord
                }
                return rows.count == 1
            }
        }
    }

    public func acknowledgeEmailDelivery(
        deliveryID: AccountEmailDeliveryID,
        workerID: String,
        now: Date
    ) async throws -> Bool {
        guard AccountEmailStorageValidation.isWorkerID(workerID) else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try await purgeExpiredEmailRecoveryStateLocked(
                    timestamp: timestamp
                )
                let rows = try await connection.query(
                    """
                    UPDATE account_email_delivery_outbox
                    SET state = 'sent',
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        send_started_at = NULL,
                        sent_at = ?
                    WHERE delivery_id = ?
                      AND state = 'leased'
                      AND lease_owner = ?
                      AND expires_at > ?
                    RETURNING delivery_id
                    """,
                    [
                        .integer(timestamp), .text(deliveryID.rawValue),
                        .text(workerID), .integer(timestamp),
                    ]
                )
                guard rows.count <= 1 else {
                    throw AccountControlStoreError.malformedRecord
                }
                return rows.count == 1
            }
        }
    }

    public func retryEmailDelivery(
        deliveryID: AccountEmailDeliveryID,
        workerID: String,
        now: Date,
        policy: AccountEmailRetryPolicy
    ) async throws -> AccountEmailRetryDisposition {
        guard AccountEmailStorageValidation.isWorkerID(workerID) else {
            throw AccountControlStoreError.invalidInput
        }
        _ = try controlTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT attempts, expires_at
                    FROM account_email_delivery_outbox
                    WHERE delivery_id = ?
                      AND state = 'leased'
                      AND lease_owner = ?
                    """,
                    [.text(deliveryID.rawValue), .text(workerID)]
                )
                guard rows.count <= 1 else {
                    throw AccountControlStoreError.malformedRecord
                }
                guard let row = rows.first,
                      case let .integer(attempts) = row.column("attempts"),
                      case let .integer(expiresAt) = row.column("expires_at"),
                      attempts > 0, attempts <= 64,
                      expiresAt >= 0 else {
                    return .expired
                }
                let exponent = min(max(attempts - 1, 0), 30)
                let delay = min(
                    policy.maximumDelay,
                    policy.initialDelay * pow(2, Double(exponent))
                )
                let nextDate = now.addingTimeInterval(delay)
                let nextTimestamp = try controlTimestamp(nextDate)
                guard attempts < policy.maximumAttempts,
                      nextTimestamp < expiresAt else {
                    _ = try await connection.query(
                        "DELETE FROM account_email_tokens WHERE delivery_id = ?",
                        [.text(deliveryID.rawValue)]
                    )
                    _ = try await connection.query(
                        """
                        UPDATE account_email_delivery_outbox
                        SET state = 'cancelled',
                            lease_owner = NULL,
                            lease_expires_at = NULL,
                            send_started_at = NULL
                        WHERE delivery_id = ?
                        """,
                        [.text(deliveryID.rawValue)]
                    )
                    return .expired
                }
                _ = try await connection.query(
                    """
                    UPDATE account_email_delivery_outbox
                    SET state = 'pending',
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        send_started_at = NULL,
                        next_attempt_at = ?
                    WHERE delivery_id = ?
                    """,
                    [.integer(nextTimestamp), .text(deliveryID.rawValue)]
                )
                return .scheduled(nextAttemptAt: nextDate)
            }
        }
    }

    public func purgeExpiredEmailRecoveryState(now: Date) async throws {
        let timestamp = try controlTimestamp(now)
        try await withConnectionGate {
            try await transaction {
                try await purgeExpiredEmailRecoveryStateLocked(
                    timestamp: timestamp
                )
            }
        }
    }

    public func consumeEmailRateLimit(
        key: AccountEmailRateLimitKey,
        policy: AccountEmailRateLimitPolicy,
        now: Date
    ) async throws -> AccountEmailRateLimitDecision {
        guard key.digest.count == 32 else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        let windowEnd = try controlTimestamp(
            now.addingTimeInterval(policy.window)
        )
        let windowWidth = windowEnd - timestamp
        guard windowWidth > 0 else {
            throw AccountControlStoreError.invalidInput
        }
        return try await withConnectionGate {
            try await transaction {
                // Remove the requested expired row first, then perform only a
                // bounded global cleanup. A legitimate key cannot be hidden
                // behind an attacker-created backlog of expired digests.
                _ = try await connection.query(
                    """
                    DELETE FROM account_email_rate_limits
                    WHERE scope = ? AND key_digest = ? AND expires_at <= ?
                    """,
                    [
                        .text(key.scope.rawValue), blob(key.digest),
                        .integer(timestamp),
                    ]
                )
                _ = try await connection.query(
                    """
                    DELETE FROM account_email_rate_limits
                    WHERE (scope, key_digest) IN (
                        SELECT scope, key_digest
                        FROM account_email_rate_limits
                        WHERE expires_at <= ?
                        ORDER BY expires_at, scope, key_digest
                        LIMIT ?
                    )
                    """,
                    [
                        .integer(timestamp),
                        .integer(Self.emailRateLimitPurgeBatchSize),
                    ]
                )
                let rows = try await connection.query(
                    """
                    SELECT window_started_at, expires_at, attempts
                    FROM account_email_rate_limits
                    WHERE scope = ? AND key_digest = ?
                    """,
                    [.text(key.scope.rawValue), blob(key.digest)]
                )
                guard rows.count <= 1 else {
                    throw AccountControlStoreError.malformedRecord
                }
                guard let row = rows.first else {
                    let capacityRows = try await connection.query(
                        """
                        SELECT entry_count
                        FROM account_email_rate_limit_capacity
                        WHERE singleton = 1
                        """
                    )
                    guard capacityRows.count == 1,
                          case let .integer(entryCount) =
                          capacityRows[0].column("entry_count"),
                          (0 ... Self.maximumEmailRateLimitEntries).contains(entryCount) else {
                        throw AccountControlStoreError.malformedRecord
                    }
                    guard entryCount < Self.maximumEmailRateLimitEntries else {
                        return .limited(until: now.addingTimeInterval(policy.window))
                    }
                    _ = try await connection.query(
                        """
                        INSERT INTO account_email_rate_limits(
                            scope, key_digest, window_started_at, expires_at, attempts
                        ) VALUES (?, ?, ?, ?, 1)
                        """,
                        [
                            .text(key.scope.rawValue), blob(key.digest),
                            .integer(timestamp), .integer(windowEnd),
                        ]
                    )
                    return .allowed(
                        remaining: policy.maximumAttempts - 1
                    )
                }
                guard case let .integer(startedAt) =
                          row.column("window_started_at"),
                      case let .integer(expiresAt) = row.column("expires_at"),
                      case let .integer(attempts) = row.column("attempts"),
                      startedAt >= 0,
                      expiresAt > startedAt,
                      (1 ... 10_000).contains(attempts) else {
                    throw AccountControlStoreError.malformedRecord
                }
                if timestamp >= expiresAt {
                    _ = try await connection.query(
                        """
                        UPDATE account_email_rate_limits
                        SET window_started_at = ?, expires_at = ?, attempts = 1
                        WHERE scope = ? AND key_digest = ?
                        """,
                        [
                            .integer(timestamp), .integer(windowEnd),
                            .text(key.scope.rawValue), blob(key.digest),
                        ]
                    )
                    return .allowed(
                        remaining: policy.maximumAttempts - 1
                    )
                }
                if attempts >= policy.maximumAttempts {
                    return .limited(
                        until: Date(
                            timeIntervalSince1970:
                                Double(expiresAt) / 1_000_000
                        )
                    )
                }
                _ = try await connection.query(
                    """
                    UPDATE account_email_rate_limits
                    SET attempts = attempts + 1
                    WHERE scope = ? AND key_digest = ?
                    """,
                    [.text(key.scope.rawValue), blob(key.digest)]
                )
                return .allowed(
                    remaining: policy.maximumAttempts - attempts - 1
                )
            }
        }
    }

    public func associatedEmail(did: String) async throws -> AccountEmailAddress? {
        guard AccountControlIdentifiers.isDID(did) else { throw AccountControlStoreError.invalidInput }
        return try await withConnectionGate {
            let rows = try await connection.query("SELECT email FROM account_emails WHERE did = ?", [.text(did)])
            guard let row = rows.first, let value = try optionalText(row, "email") else { return nil }
            return try AccountEmailAddress(value)
        }
    }

    public func verifiedEmail(did: String) async throws -> AccountEmailAddress? {
        guard AccountControlIdentifiers.isDID(did) else { throw AccountControlStoreError.invalidInput }
        return try await withConnectionGate {
            let rows = try await connection.query("SELECT email FROM account_emails WHERE did = ? AND verified_at IS NOT NULL", [.text(did)])
            guard let row = rows.first, let value = try optionalText(row, "email") else { return nil }
            return try AccountEmailAddress(value)
        }
    }

    public func issueEmailToken(
        did: String,
        email: AccountEmailAddress,
        purpose: AccountEmailTokenPurpose,
        digest: Data,
        expiresAt: Date,
        now: Date
    ) async throws {
        guard AccountControlIdentifiers.isDID(did), digest.count == 32 else { throw AccountControlStoreError.invalidInput }
        let expiry = try controlTimestamp(expiresAt), timestamp = try controlTimestamp(now)
        guard expiry > timestamp else { throw AccountControlStoreError.invalidInput }
        try await withConnectionGate {
            try await transaction {
                // This is the linearization point with the delivery service:
                // the address chosen before generating the raw token must
                // still be current, and the account must still authorize.
                let current = try await connection.query(
                    """
                    SELECT e.email
                    FROM account_emails AS e
                    JOIN accounts AS a ON a.did = e.did
                    WHERE e.did = ? AND e.email = ? AND a.status = 'active'
                    """,
                    [.text(did), .text(email.value)]
                )
                guard current.count == 1,
                      try requiredText(current[0], "email") == email.value else {
                    throw AccountControlStoreError.notFound
                }
                _ = try await connection.query(
                    """
                    DELETE FROM account_email_delivery_outbox
                    WHERE did = ? AND purpose = ?
                    """,
                    [.text(did), .text(purpose.rawValue)]
                )
                _ = try await connection.query(
                    """
                    DELETE FROM account_email_tokens
                    WHERE did = ? AND purpose = ?
                    """,
                    [.text(did), .text(purpose.rawValue)]
                )
                _ = try await connection.query(
                    """
                    INSERT INTO account_email_tokens(
                        digest, did, email, purpose, expires_at, consumed_at
                    ) VALUES (?, ?, ?, ?, ?, NULL)
                    """,
                    [
                        blob(digest), .text(did), .text(email.value),
                        .text(purpose.rawValue), .integer(expiry),
                    ]
                )
            }
        }
    }

    public func confirmEmail(
        _ request: AccountEmailConfirmationRequest,
        now: Date
    ) async throws -> Bool {
        try await confirmEmailProof(request, now: now) == .confirmed
    }

    public func confirmEmailProof(
        _ request: AccountEmailConfirmationRequest,
        now: Date
    ) async throws -> AccountEmailConfirmationOutcome {
        guard AccountControlIdentifiers.isDID(request.did),
              (try? AccountEmailAddress(request.email.value)) == request.email,
              request.proofDigest.count == 32 else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                let claimed = try await connection.query(
                    """
                    UPDATE account_email_tokens
                    SET consumed_at = ?
                    WHERE digest = ?
                      AND did = ?
                      AND email = ?
                      AND purpose = 'verify-email'
                      AND consumed_at IS NULL
                      AND expires_at > ?
                      AND EXISTS (
                          SELECT 1
                          FROM accounts AS a
                          JOIN account_emails AS e ON e.did = a.did
                          WHERE a.did = account_email_tokens.did
                            AND a.status = 'active'
                            AND e.email = account_email_tokens.email
                      )
                    RETURNING did, email
                    """,
                    [
                        .integer(timestamp), blob(request.proofDigest),
                        .text(request.did), .text(request.email.value),
                        .integer(timestamp),
                    ]
                )
                guard claimed.count <= 1 else {
                    throw AccountControlStoreError.malformedRecord
                }
                guard let row = claimed.first else {
                    let accounts = try await connection.query(
                        "SELECT status FROM accounts WHERE did = ?",
                        [.text(request.did)]
                    )
                    guard let account = accounts.first else {
                        return .accountNotFound
                    }
                    let status = try AccountControlStatus(
                        rawValue: requiredText(account, "status")
                    )
                    guard status == .active, status.isCanonicalValue else {
                        return .accountNotFound
                    }
                    let emailRows = try await connection.query(
                        "SELECT email FROM account_emails WHERE did = ?",
                        [.text(request.did)]
                    )
                    guard let emailRow = emailRows.first,
                          try requiredText(emailRow, "email")
                              == request.email.value else {
                        return .invalidEmail
                    }
                    let tokens = try await connection.query(
                        """
                        SELECT expires_at, consumed_at
                        FROM account_email_tokens
                        WHERE digest = ?
                          AND did = ?
                          AND email = ?
                          AND purpose = 'verify-email'
                        """,
                        [
                            blob(request.proofDigest), .text(request.did),
                            .text(request.email.value),
                        ]
                    )
                    guard tokens.count <= 1 else {
                        throw AccountControlStoreError.malformedRecord
                    }
                    guard let token = tokens.first,
                          case let .integer(expiresAt) =
                              token.column("expires_at"),
                          expiresAt >= 0 else {
                        return .invalidToken
                    }
                    if try optionalInteger(token, "consumed_at") != nil {
                        return .invalidToken
                    }
                    return expiresAt <= timestamp
                        ? .expiredToken
                        : .invalidToken
                }
                guard try requiredText(row, "did") == request.did,
                      try requiredText(row, "email") == request.email.value else {
                    throw AccountControlStoreError.malformedRecord
                }
                let advanced = try await connection.query(
                    """
                    UPDATE accounts
                    SET updated_at = CASE
                        WHEN updated_at >= ? THEN updated_at + 1
                        ELSE ?
                    END
                    WHERE did = ? AND status = 'active'
                      AND updated_at < ?
                    RETURNING updated_at
                    """,
                    [
                        .integer(timestamp), .integer(timestamp),
                        .text(request.did), .integer(Int.max),
                    ]
                )
                guard advanced.count == 1,
                      case let .integer(generation) =
                          advanced[0].column("updated_at"),
                      generation > 0 else {
                    throw AccountControlStoreError.malformedRecord
                }
                let verified = try await connection.query(
                    """
                    UPDATE account_emails
                    SET verified_at = ?, updated_at = ?
                    WHERE did = ? AND email = ?
                    RETURNING did
                    """,
                    [
                        .integer(timestamp), .integer(generation),
                        .text(request.did), .text(request.email.value),
                    ]
                )
                guard verified.count == 1,
                      try requiredText(verified[0], "did") == request.did else {
                    throw AccountControlStoreError.malformedRecord
                }
                _ = try await connection.query(
                    """
                    DELETE FROM account_email_tokens
                    WHERE did = ? AND purpose = 'verify-email'
                    """,
                    [.text(request.did)]
                )
                _ = try await connection.query(
                    """
                    DELETE FROM account_email_delivery_outbox
                    WHERE did = ? AND purpose = 'verify-email'
                    """,
                    [.text(request.did)]
                )
                return .confirmed
            }
        }
    }

    public func consumeEmailToken(digest: Data, purpose: AccountEmailTokenPurpose, now: Date) async throws -> String? {
        guard digest.count == 32 else { throw AccountControlStoreError.invalidInput }
        // Recovery must never cross the old split-phase
        // consume-then-replace boundary. Keep wrong-purpose/legacy callers
        // indistinguishable from an unknown proof without burning the token.
        guard purpose == .verifyEmail else { return nil }
        let timestamp = try controlTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                // The conditional UPDATE is the cross-connection/process
                // linearization point. A preceding SELECT followed by an
                // unchecked UPDATE would let two deferred transactions both
                // return the same proof as consumed.
                let claimed = try await connection.query(
                    """
                    UPDATE account_email_tokens
                    SET consumed_at = ?
                    WHERE digest = ?
                      AND purpose = ?
                      AND delivery_id IS NULL
                      AND consumed_at IS NULL
                      AND expires_at > ?
                      AND EXISTS (
                          SELECT 1
                          FROM accounts AS a
                          JOIN account_emails AS e ON e.did = a.did
                          WHERE a.did = account_email_tokens.did
                            AND a.status = 'active'
                            AND e.email = account_email_tokens.email
                      )
                    RETURNING did, email
                    """,
                    [
                        .integer(timestamp), blob(digest),
                        .text(purpose.rawValue), .integer(timestamp),
                    ]
                )
                guard claimed.count == 1 else { return nil }
                let did = try requiredText(claimed[0], "did")
                let email = try requiredText(claimed[0], "email")
                guard (try? AccountEmailAddress(email))?.value == email else {
                    throw AccountControlStoreError.malformedRecord
                }
                let advanced = try await connection.query(
                    """
                    UPDATE accounts
                    SET updated_at = CASE
                        WHEN updated_at >= ? THEN updated_at + 1
                        ELSE ?
                    END
                    WHERE did = ? AND status = 'active'
                      AND updated_at < ?
                    RETURNING updated_at
                    """,
                    [
                        .integer(timestamp), .integer(timestamp), .text(did),
                        .integer(Int.max),
                    ]
                )
                guard advanced.count == 1,
                      case let .integer(generation) =
                          advanced[0].column("updated_at"),
                      generation > 0 else {
                    throw AccountControlStoreError.malformedRecord
                }
                let verified = try await connection.query(
                    """
                    UPDATE account_emails
                    SET verified_at = ?, updated_at = ?
                    WHERE did = ? AND email = ?
                    RETURNING did
                    """,
                    [
                        .integer(timestamp), .integer(generation),
                        .text(did), .text(email),
                    ]
                )
                guard verified.count == 1 else {
                    throw AccountControlStoreError.malformedRecord
                }
                return did
            }
        }
    }

    public func passwordRecoveryConfirmation(
        proofDigest: Data,
        now: Date
    ) async throws -> AccountPasswordRecoveryConfirmation? {
        let outcome = try await passwordRecoveryLookup(
            proofDigest: proofDigest,
            now: now
        )
        guard case let .ready(confirmation) = outcome else { return nil }
        return confirmation
    }

    public func passwordRecoveryLookup(
        proofDigest: Data,
        now: Date
    ) async throws -> AccountPasswordRecoveryLookupOutcome {
        guard proofDigest.count == 32 else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        return try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT did, email, expires_at, consumed_at
                FROM account_email_tokens
                WHERE digest = ? AND purpose = 'password-recovery'
                """,
                [blob(proofDigest)]
            )
            guard rows.count <= 1 else {
                throw AccountControlStoreError.malformedRecord
            }
            guard let row = rows.first else { return .invalidToken }
            guard case let .integer(expiresAt) = row.column("expires_at"),
                  expiresAt >= 0 else {
                throw AccountControlStoreError.malformedRecord
            }
            if try optionalInteger(row, "consumed_at") != nil {
                return .invalidToken
            }
            if expiresAt <= timestamp { return .expiredToken }
            do {
                let confirmation = try AccountPasswordRecoveryConfirmation(
                    did: requiredText(row, "did"),
                    email: AccountEmailAddress(requiredText(row, "email")),
                    proofDigest: proofDigest
                )
                let eligible = try await connection.query(
                    """
                    SELECT 1
                    FROM accounts AS a
                    JOIN account_emails AS e ON e.did = a.did
                    WHERE a.did = ?
                      AND a.status = 'active'
                      AND e.email = ?
                      AND e.verified_at IS NOT NULL
                    """,
                    [
                        .text(confirmation.did),
                        .text(confirmation.email.value),
                    ]
                )
                guard eligible.count == 1 else { return .invalidToken }
                return .ready(confirmation)
            } catch let error as AccountControlStoreError {
                guard error == .invalidInput else { throw error }
                throw AccountControlStoreError.malformedRecord
            }
        }
    }

    public func completePasswordRecovery(
        _ request: AccountPasswordRecoveryRequest,
        now: Date
    ) async throws -> AccountPasswordRecoveryResult {
        guard AccountControlIdentifiers.isDID(request.did),
              (try? AccountEmailAddress(request.email.value)) == request.email,
              request.proofDigest.count == 32,
              validVerifier(request.expectedVerifier),
              validVerifier(request.replacementVerifier),
              request.replacementVerifier != request.expectedVerifier else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                // This conditional update is the linearization point for the
                // complete recovery. BEGIN IMMEDIATE serializes it across
                // independently opened Swan processes, while the EXISTS clause
                // binds the proof to the exact active account and its current,
                // verified email generation.
                let replaced = try await connection.query(
                    """
                    UPDATE accounts
                    SET password_verifier = ?,
                        updated_at = CASE
                            WHEN updated_at >= ? THEN updated_at + 1
                            ELSE ?
                        END
                    WHERE did = ?
                      AND status = 'active'
                      AND password_verifier = ?
                      AND updated_at < ?
                      AND EXISTS (
                          SELECT 1
                          FROM account_email_tokens AS t
                          JOIN account_emails AS e
                            ON e.did = t.did AND e.email = t.email
                          WHERE t.digest = ?
                            AND t.did = accounts.did
                            AND t.email = ?
                            AND t.purpose = 'password-recovery'
                            AND t.consumed_at IS NULL
                            AND t.expires_at > ?
                            AND e.did = accounts.did
                            AND e.email = ?
                            AND e.verified_at IS NOT NULL
                      )
                    RETURNING did
                    """,
                    [
                        .text(request.replacementVerifier),
                        .integer(timestamp), .integer(timestamp),
                        .text(request.did), .text(request.expectedVerifier),
                        .integer(Int.max),
                        blob(request.proofDigest), .text(request.email.value),
                        .integer(timestamp), .text(request.email.value),
                    ]
                )
                guard replaced.count <= 1 else {
                    throw AccountControlStoreError.malformedRecord
                }
                guard let row = replaced.first else { return .unchanged }
                guard try requiredText(row, "did") == request.did else {
                    throw AccountControlStoreError.malformedRecord
                }

                // A successful recovery invalidates both the winning proof and
                // every other verification/recovery proof for the account.
                _ = try await connection.query(
                    "DELETE FROM account_email_tokens WHERE did = ?",
                    [.text(request.did)]
                )
                _ = try await connection.query(
                    "DELETE FROM account_email_delivery_outbox WHERE did = ?",
                    [.text(request.did)]
                )
                // Families are created before authorization-code redemption,
                // so revoking all of them also prevents a pre-recovery code
                // from minting a fresh token pair afterwards.
                _ = try await connection.query(
                    """
                    UPDATE oauth_control_token_families
                    SET revoked_at = COALESCE(revoked_at, ?)
                    WHERE subject = ?
                    """,
                    [.integer(timestamp), .text(request.did)]
                )
                return .completed
            }
        }
    }

    public func credential(did: String) async throws -> AccountControlCredential? {
        guard AccountControlIdentifiers.isDID(did) else { throw AccountControlStoreError.invalidInput }
        return try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT password_verifier, updated_at
                FROM accounts
                WHERE did = ? AND status = 'active'
                """,
                [.text(did)]
            )
            guard let row = rows.first else { return nil }
            guard let verifier = try optionalText(row, "password_verifier") else { return nil }
            guard validVerifier(verifier) else { throw AccountControlStoreError.malformedRecord }
            return try AccountControlCredential(
                did: did,
                verifier: verifier,
                updatedAt: try requiredDate(row, "updated_at")
            )
        }
    }

    public func replaceCredential(
        did: String,
        expectedVerifier: String,
        replacementVerifier: String,
        now: Date
    ) async throws -> AccountCredentialReplacement {
        guard AccountControlIdentifiers.isDID(did), validVerifier(expectedVerifier), validVerifier(replacementVerifier) else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    "SELECT password_verifier, status FROM accounts WHERE did = ?",
                    [.text(did)]
                )
                guard let row = rows.first else { throw AccountControlStoreError.notFound }
                let status = try AccountControlStatus(
                    rawValue: requiredText(row, "status")
                )
                guard status.authorizesAccount,
                      status.isCanonicalValue,
                      try optionalText(row, "password_verifier") == expectedVerifier else {
                    return .unchanged
                }
                let replaced = try await connection.query(
                    """
                    UPDATE accounts
                    SET password_verifier = ?,
                        updated_at = CASE
                            WHEN updated_at >= ? THEN updated_at + 1
                            ELSE ?
                        END
                    WHERE did = ? AND password_verifier = ? AND status = 'active'
                      AND updated_at < ?
                    RETURNING updated_at
                    """,
                    [
                        .text(replacementVerifier),
                        .integer(timestamp), .integer(timestamp), .text(did),
                        .text(expectedVerifier), .integer(Int.max),
                    ]
                )
                guard replaced.count == 1,
                      case let .integer(revision) =
                          replaced[0].column("updated_at"),
                      revision > 0 else {
                    throw AccountControlStoreError.malformedRecord
                }
                return .replaced
            }
        }
    }

    /// The final account authorization decision is made in one SQLite write
    /// transaction. A password that was verified against a stale credential,
    /// or an account suspended/deleted while Argon2 was running, cannot cross
    /// this boundary as a successful authentication.
    public func finalizeAuthentication(
        did: String,
        expectedVerifier: String,
        replacementVerifier: String?,
        now: Date
    ) async throws -> AccountAuthenticationFinalization? {
        guard AccountControlIdentifiers.isDID(did), validVerifier(expectedVerifier),
              replacementVerifier.map(validVerifier) ?? true else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    accountSelectSQL + " WHERE did = ?",
                    [.text(did)]
                )
                guard let row = rows.first else { return nil }
                let account = try decodeAccount(row)
                guard account.status.authorizesAccount,
                      try optionalText(row, "password_verifier") == expectedVerifier else {
                    return nil
                }

                let credentialWasReplaced: Bool
                if let replacementVerifier, replacementVerifier != expectedVerifier {
                    let replaced = try await connection.query(
                        """
                        UPDATE accounts
                        SET password_verifier = ?,
                            updated_at = CASE
                                WHEN updated_at >= ? THEN updated_at + 1
                                ELSE ?
                            END
                        WHERE did = ? AND password_verifier = ? AND status = 'active'
                          AND updated_at < ?
                        RETURNING updated_at
                        """,
                        [
                            .text(replacementVerifier),
                            .integer(timestamp), .integer(timestamp), .text(did),
                            .text(expectedVerifier), .integer(Int.max),
                        ]
                    )
                    guard replaced.count == 1 else {
                        throw AccountControlStoreError.malformedRecord
                    }
                    credentialWasReplaced = true
                } else {
                    credentialWasReplaced = false
                }
                let finalized = try await requiredAccount(did: did)
                guard finalized.status.authorizesAccount else {
                    throw AccountControlStoreError.malformedRecord
                }
                return AccountAuthenticationFinalization(
                    account: finalized,
                    credentialWasReplaced: credentialWasReplaced
                )
            }
        }
    }

    public func transitionStatus(
        did: String,
        to status: AccountControlStatus,
        declaration: AccountLifecycleDeclaration,
        emitting: AccountLifecycleEmission?,
        now: Date
    ) async throws -> AccountControlAccount {
        guard AccountControlIdentifiers.isDID(did) else {
            throw AccountControlStoreError.invalidInput
        }
        guard status.isCanonicalValue else { throw AccountControlStoreError.invalidStatus }
        // Lifecycle metadata can arrive through a Codable or other opaque
        // boundary. Revalidate it immediately before persistence so only
        // bounded operator text and digest-only export references enter the
        // control database.
        guard declaration.tombstone?.isCanonicalValue ?? true,
              declaration.export?.isCanonicalValue ?? true else {
            throw AccountControlStoreError.invalidInput
        }
        let timestamp = try controlTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                let account = try await requiredAccount(did: did)
                try AccountStatusTransitionPolicy.standard.validate(
                    from: account.status,
                    to: status
                )
                if status.authorizesAccount, !account.status.authorizesAccount {
                    let recoveryResidue = try await connection.query(
                        """
                        SELECT 1
                        FROM account_email_tokens
                        WHERE did = ?
                        UNION ALL
                        SELECT 1
                        FROM account_email_delivery_outbox
                        WHERE did = ?
                        LIMIT 1
                        """,
                        [.text(did), .text(did)]
                    )
                    guard recoveryResidue.isEmpty else {
                        throw AccountControlStoreError.invalidTransition
                    }
                }
                guard declaration.tombstone == nil else {
                    throw AccountControlStoreError.invalidInput
                }
                let tombstoneTimestamp = try declaration.tombstone.map {
                    try controlTimestamp($0.declaredAt)
                }
                let exportTimestamp = try declaration.export.map {
                    try controlTimestamp($0.declaredAt)
                }
                let transitioned = try await connection.query(
                    """
                    UPDATE accounts
                    SET status = ?,
                        updated_at = CASE
                            WHEN updated_at >= ? THEN updated_at + 1
                            ELSE ?
                        END,
                        tombstone_declared_at = COALESCE(?, tombstone_declared_at),
                        tombstone_reason = COALESCE(?, tombstone_reason),
                        export_declared_at = COALESCE(?, export_declared_at),
                        export_reference = COALESCE(?, export_reference)
                    WHERE did = ? AND updated_at < ?
                    RETURNING updated_at
                    """,
                    [
                        .text(status.rawValue),
                        .integer(timestamp), .integer(timestamp),
                        optionalInteger(tombstoneTimestamp), optionalText(declaration.tombstone?.reason),
                        optionalInteger(exportTimestamp), optionalText(declaration.export?.reference),
                        .text(did), .integer(Int.max),
                    ]
                )
                guard transitioned.count == 1,
                      case let .integer(revision) =
                          transitioned[0].column("updated_at"),
                      revision > 0 else {
                    throw AccountControlStoreError.malformedRecord
                }
                if !status.authorizesAccount {
                    // Suspension/deactivation is also a recovery-proof
                    // revocation boundary. Account status rejects the proof
                    // immediately; cleanup is page-limited so one account
                    // cannot monopolize the shared write transaction. A
                    // repeated inactive transition drains another page, and
                    // reactivation remains blocked until no residue remains.
                    try await purgeEmailRecoveryStateForInactiveAccountLocked(
                        did: did,
                        timestamp: timestamp
                    )
                    if account.status.authorizesAccount {
                        // Families are created before authorization-code
                        // redemption, so this permanently revokes every
                        // pre-deactivation code, access token, and refresh
                        // token without deleting their audit rows.
                        _ = try await connection.query(
                            """
                            UPDATE oauth_control_token_families
                            SET revoked_at = COALESCE(revoked_at, ?)
                            WHERE subject = ?
                            """,
                            [.integer(timestamp), .text(did)]
                        )
                    }
                }
                if let emitting,
                   account.status != status,
                   let material = Self.publicAccountMaterial(
                       did: did,
                       status: status,
                       time: PublicFirehoseTime.encode(now)
                   ) {
                    // The batch commits or rolls back with the status write,
                    // so a failed transition can never leave an #account
                    // announcement for a status the account never reached.
                    let item = LifecycleEventItem(
                        sourceKey: PublicFirehoseSourceKey.account(
                            did: did,
                            operationID: emitting.operationID
                        ),
                        kind: .account,
                        payload: try JSONEncoder().encode(material),
                        carBytes: nil
                    )
                    _ = try await enqueueLifecycleEventBatchInTransaction(
                        did: did,
                        operationID: emitting.operationID,
                        items: [item],
                        now: now
                    )
                }
                return try await requiredAccount(did: did)
            }
        }
    }

    /// Maps an account control status to its public firehose representation.
    /// `nil` means the status has no public representation and emits nothing.
    /// `deleting`/`deleted` are policy-unreachable through `transitionStatus`;
    /// `unknown` has no public counterpart.
    private static func publicAccountMaterial(
        did: String,
        status: AccountControlStatus,
        time: String
    ) -> PublicFirehoseAccountMaterial? {
        switch status {
        case .active:
            return .init(did: did, active: true, status: nil, time: time)
        case .deactivated:
            return .init(did: did, active: false, status: .deactivated, time: time)
        case .suspended:
            return .init(did: did, active: false, status: .suspended, time: time)
        case .takendown:
            return .init(did: did, active: false, status: .takendown, time: time)
        case .desynchronized:
            return .init(did: did, active: false, status: .desynchronized, time: time)
        case .throttled:
            return .init(did: did, active: false, status: .throttled, time: time)
        case .deleting, .deleted, .unknown:
            return nil
        }
    }

    /// Runs one already-staged, network-free account mutation while holding
    /// the control-plane write transaction that authorizes the account. A
    /// lifecycle transition therefore linearizes either before this lease
    /// (and is observed as non-active) or after the mutation commits. Callers
    /// must not perform network I/O in `operation`; this is a short final
    /// publication fence, not a general-purpose transaction wrapper.
    public func withActiveAccountAuthorization<T: Sendable>(
        did: String,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        guard AccountControlIdentifiers.isDID(did) else {
            throw AccountControlStoreError.invalidInput
        }
        return try await withConnectionGate {
            try await transaction {
                let account = try await requiredAccount(did: did)
                guard account.status.authorizesAccount else {
                    throw AccountControlStoreError.invalidTransition
                }
                return try await operation()
            }
        }
    }

    /// Same authorization fence as `withActiveAccountAuthorization`, but also
    /// snapshots the DID's current lifecycle generation inside the same
    /// control-plane write transaction. The authorization check and the
    /// generation read therefore linearize together: a lifecycle transition
    /// either happens before this fence (observed as inactive, or as the
    /// prior generation) or after the publication returns. Callers must not
    /// perform network I/O in `operation`; this is a short final publication
    /// fence, not a general-purpose transaction wrapper.
    public func withActiveAccountFirehoseAuthorization<T: Sendable>(
        did: String,
        operation: @escaping @Sendable (Int64) async throws -> T
    ) async throws -> T {
        guard AccountControlIdentifiers.isDID(did) else {
            throw AccountControlStoreError.invalidInput
        }
        return try await withConnectionGate {
            try await transaction {
                let account = try await requiredAccount(did: did)
                guard account.status.authorizesAccount else {
                    throw AccountControlStoreError.invalidTransition
                }
                let rows = try await connection.query(
                    "SELECT generation FROM account_lifecycle_generation WHERE did = ?",
                    [.text(did)]
                )
                let generation = Int64(rows.first?.column("generation")?.integer ?? 0)
                return try await operation(generation)
            }
        }
    }

    // MARK: Account email recovery internals

    private func insertEmailProofDeliveryLocked(
        deliveryID: AccountEmailDeliveryID,
        did: String,
        email: AccountEmailAddress,
        emailGeneration: Int,
        purpose: AccountEmailTokenPurpose,
        proofDigest: Data,
        expiresAt: Int,
        createdAt: Int
    ) async throws {
        guard AccountControlIdentifiers.isDID(did),
              (try? AccountEmailAddress(email.value)) == email,
              emailGeneration > 0,
              proofDigest.count == 32,
              expiresAt > createdAt else {
            throw AccountControlStoreError.invalidInput
        }
        _ = try await connection.query(
            """
            DELETE FROM account_email_delivery_outbox
            WHERE did = ? AND purpose = ?
            """,
            [.text(did), .text(purpose.rawValue)]
        )
        _ = try await connection.query(
            """
            DELETE FROM account_email_tokens
            WHERE did = ? AND purpose = ?
            """,
            [.text(did), .text(purpose.rawValue)]
        )
        _ = try await connection.query(
            """
            INSERT INTO account_email_tokens(
                digest, did, email, purpose, expires_at, consumed_at,
                delivery_id
            ) VALUES (?, ?, ?, ?, ?, NULL, ?)
            """,
            [
                blob(proofDigest), .text(did), .text(email.value),
                .text(purpose.rawValue), .integer(expiresAt),
                .text(deliveryID.rawValue),
            ]
        )
        _ = try await connection.query(
            """
            INSERT INTO account_email_delivery_outbox(
                delivery_id, did, email, email_generation, purpose,
                expires_at, state, lease_owner, lease_expires_at,
                attempts, next_attempt_at, created_at, sent_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending', NULL, NULL, 0, ?, ?, NULL)
            """,
            [
                .text(deliveryID.rawValue), .text(did), .text(email.value),
                .integer(emailGeneration), .text(purpose.rawValue),
                .integer(expiresAt), .integer(createdAt),
                .integer(createdAt),
            ]
        )
    }

    private func purgeExpiredEmailRecoveryStateLocked(
        timestamp: Int
    ) async throws {
        guard timestamp >= 0 else {
            throw AccountControlStoreError.invalidInput
        }
        _ = try await connection.query(
            """
            DELETE FROM account_email_delivery_outbox
            WHERE delivery_id IN (
                SELECT delivery_id
                FROM account_email_delivery_outbox
                WHERE expires_at <= ?
                  AND NOT (
                      send_started_at IS NOT NULL
                      AND (lease_expires_at IS NULL OR lease_expires_at > ?)
                  )
                ORDER BY expires_at, created_at, delivery_id
                LIMIT ?
            )
            """,
            [
                .integer(timestamp), .integer(timestamp),
                .integer(Self.emailRecoveryPurgeBatchSize),
            ]
        )
        _ = try await connection.query(
            """
            DELETE FROM account_email_tokens
            WHERE digest IN (
                SELECT digest
                FROM account_email_tokens
                WHERE expires_at <= ?
                ORDER BY expires_at, digest
                LIMIT ?
            )
            """,
            [
                .integer(timestamp),
                .integer(Self.emailRecoveryPurgeBatchSize),
            ]
        )
        _ = try await connection.query(
            """
            DELETE FROM account_password_recovery_work
            WHERE lookup_digest IN (
                SELECT lookup_digest
                FROM account_password_recovery_work
                WHERE expires_at <= ?
                ORDER BY expires_at, created_at, lookup_digest
                LIMIT ?
            )
            """,
            [
                .integer(timestamp),
                .integer(Self.passwordRecoveryWorkPurgeBatchSize),
            ]
        )
        _ = try await connection.query(
            """
            DELETE FROM account_email_rate_limits
            WHERE (scope, key_digest) IN (
                SELECT scope, key_digest
                FROM account_email_rate_limits
                WHERE expires_at <= ?
                ORDER BY expires_at, scope, key_digest
                LIMIT ?
            )
            """,
            [
                .integer(timestamp),
                .integer(Self.emailRateLimitPurgeBatchSize),
            ]
        )
    }

    private func purgeEmailRecoveryStateForInactiveAccountLocked(
        did: String,
        timestamp: Int
    ) async throws {
        guard AccountControlIdentifiers.isDID(did), timestamp >= 0 else {
            throw AccountControlStoreError.invalidInput
        }
        _ = try await connection.query(
            """
            DELETE FROM account_email_delivery_outbox
            WHERE delivery_id IN (
                SELECT delivery_id
                FROM account_email_delivery_outbox
                WHERE did = ?
                  AND NOT (
                      send_started_at IS NOT NULL
                      AND (lease_expires_at IS NULL OR lease_expires_at > ?)
                  )
                ORDER BY expires_at, created_at, delivery_id
                LIMIT ?
            )
            """,
            [
                .text(did), .integer(timestamp),
                .integer(Self.emailRecoveryPurgeBatchSize),
            ]
        )
        _ = try await connection.query(
            """
            DELETE FROM account_email_tokens
            WHERE digest IN (
                SELECT digest
                FROM account_email_tokens
                WHERE did = ?
                ORDER BY expires_at, digest
                LIMIT ?
            )
            """,
            [.text(did), .integer(Self.emailRecoveryPurgeBatchSize)]
        )
    }

    /// Normalize any legacy table that was larger than the new global cap.
    /// Deterministic oldest-first eviction keeps the migration bounded and
    /// leaves active rows usable without exposing their HMAC preimages.
    private func trimEmailRateLimitOverflowLocked() async throws {
        let countRows = try await connection.query(
            "SELECT COUNT(*) AS row_count FROM account_email_rate_limits"
        )
        guard countRows.count == 1,
              case let .integer(rowCount) = countRows[0].column("row_count"),
              rowCount >= 0 else {
            throw AccountControlStoreError.malformedRecord
        }
        let overflow = rowCount - Self.maximumEmailRateLimitEntries
        guard overflow > 0 else { return }
        _ = try await connection.query(
            """
            DELETE FROM account_email_rate_limits
            WHERE (scope, key_digest) IN (
                SELECT scope, key_digest
                FROM account_email_rate_limits
                ORDER BY expires_at, scope, key_digest
                LIMIT ?
            )
            """,
            [.integer(overflow)]
        )
    }

    /// Keep a legacy database within the same bound enforced for new
    /// requests. The migration runs inside BEGIN IMMEDIATE, so no writer can
    /// observe an over-capacity state after this normalization completes.
    private func trimPasswordRecoveryWorkOverflowLocked() async throws {
        let countRows = try await connection.query(
            "SELECT COUNT(*) AS row_count FROM account_password_recovery_work"
        )
        guard countRows.count == 1,
              case let .integer(rowCount) = countRows[0].column("row_count"),
              rowCount >= 0 else {
            throw AccountControlStoreError.malformedRecord
        }
        let overflow = rowCount - Self.maximumPasswordRecoveryWorkMarkers
        guard overflow > 0 else { return }
        _ = try await connection.query(
            """
            DELETE FROM account_password_recovery_work
            WHERE lookup_digest IN (
                SELECT lookup_digest
                FROM account_password_recovery_work
                ORDER BY expires_at, created_at, lookup_digest
                LIMIT ?
            )
            """,
            [.integer(overflow)]
        )
    }

    private func decodeEmailDeliveryLease(
        _ row: SQLiteRow
    ) throws -> AccountEmailDeliveryLease {
        guard case let .integer(generation) =
                  row.column("email_generation"),
              case let .integer(expiresAt) = row.column("expires_at"),
              case let .integer(attempts) = row.column("attempts"),
              generation > 0,
              expiresAt >= 0,
              (1 ... 64).contains(attempts),
              let purpose = AccountEmailTokenPurpose(
                  rawValue: try requiredText(row, "purpose")
              ) else {
            throw AccountControlStoreError.malformedRecord
        }
        do {
            return try AccountEmailDeliveryLease(
                deliveryID: AccountEmailDeliveryID(
                    rawValue: requiredText(row, "delivery_id")
                ),
                did: requiredText(row, "did"),
                email: AccountEmailAddress(requiredText(row, "email")),
                emailGeneration: UInt64(generation),
                purpose: purpose,
                expiresAt: Date(
                    timeIntervalSince1970: Double(expiresAt) / 1_000_000
                ),
                attempts: attempts
            )
        } catch {
            throw AccountControlStoreError.malformedRecord
        }
    }

    // MARK: Operator-restore internals

    private func insertAccountLocked(
        _ registration: AccountControlRegistration
    ) async throws -> AccountControlAccount {
        let didRows = try await connection.query(
            """
            SELECT did FROM accounts WHERE did = ?
            UNION ALL
            SELECT did FROM account_deletion_tombstones WHERE did = ?
            """,
            [.text(registration.did), .text(registration.did)]
        )
        guard didRows.isEmpty else {
            throw AccountControlStoreError.duplicateDID
        }
        let handleRows = try await connection.query(
            "SELECT did FROM accounts WHERE handle = ?",
            [.text(registration.canonicalHandle)]
        )
        guard handleRows.isEmpty else {
            throw AccountControlStoreError.duplicateHandle
        }

        let createdAt = try controlTimestamp(registration.createdAt)
        _ = try await connection.query(
            """
            INSERT INTO accounts(
                did, handle, status, created_at, updated_at,
                password_verifier,
                signing_key_generation, signing_key_reference,
                rotation_key_generation, rotation_key_reference,
                public_genesis_commit_cid,
                tombstone_declared_at, tombstone_reason,
                export_declared_at, export_reference
            ) VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL)
            """,
            [
                .text(registration.did), .text(registration.canonicalHandle),
                .integer(createdAt), .integer(createdAt),
                .text(registration.passwordVerifier),
                .integer(
                    try controlGeneration(registration.signingKey.generation)
                ),
                .text(registration.signingKey.reference),
                .integer(
                    try controlGeneration(registration.rotationKey.generation)
                ),
                .text(registration.rotationKey.reference),
                optionalText(registration.publicGenesisCommitCID),
            ]
        )
        return try await requiredAccount(did: registration.did)
    }

    private func validateOperatorRestoreOnlyAccountLocked(
        did: String,
        plcCredentialKeyContinuity expected:
            PLCCredentialKeyContinuityInventory,
        plcAccountPreparationIntent expectedIntent: PLCAccountPreparationIntent? = nil
    ) async throws {
        let accounts = try await connection.query(
            "SELECT did FROM accounts ORDER BY did"
        )
        guard accounts.count == 1,
              try requiredText(accounts[0], "did") == did else {
            throw AccountControlStoreError.malformedRecord
        }
        for table in [
            "oauth_tokens",
            "oauth_client_metadata",
            "oauth_control_client_metadata",
            "oauth_control_client_metadata_freshness",
            "oauth_control_token_families",
            "oauth_control_par_requests",
            "oauth_control_par_state_replays",
            "oauth_control_authorization_codes",
            "oauth_control_access_tokens",
            "oauth_control_refresh_tokens",
            "oauth_control_dpop_replays",
            "oauth_control_client_assertion_replays",
            "permissioned_space_delegation_replays",
            "permissioned_space_client_attestation_replays",
            "account_emails",
            "account_email_tokens",
            "account_email_delivery_outbox",
            "account_email_rate_limits",
            "account_password_recovery_work",
            "account_login_rate_limits",
            "account_deletion_jobs",
            "account_deletion_staging_keys",
            "account_deletion_tombstones",
        ] {
            let rows = try await connection.query(
                "SELECT 1 FROM \(table) LIMIT 1"
            )
            guard rows.isEmpty else {
                throw AccountControlStoreError.malformedRecord
            }
        }
        let preparationRows = try await connection.query(
            """
            SELECT request_id, did, canonical_handle, pds_origin,
                   repository_revision, operation_cid, stage
            FROM plc_account_preparation_intents
            ORDER BY request_id ASC
            """
        )
        if let expectedIntent {
            guard preparationRows.count == 1,
                  let row = preparationRows.first,
                  try decodeOperatorRestorePreparationIntent(row)
                    == expectedIntent else {
                throw AccountControlStoreError.malformedRecord
            }
        } else {
            guard preparationRows.isEmpty else {
                throw AccountControlStoreError.malformedRecord
            }
        }
        let loginCapacity = try await connection.query(
            """
            SELECT entry_count
            FROM account_login_rate_limit_capacity
            WHERE singleton = 1
            """
        )
        guard loginCapacity.count == 1,
              case .integer(0) = loginCapacity[0].column("entry_count") else {
            throw AccountControlStoreError.malformedRecord
        }
        guard try await plcCredentialKeyContinuityInventoryLocked()
            == expected else {
            throw AccountControlStoreError.malformedRecord
        }
    }

    private func insertPLCAccountPreparationIntentLocked(
        _ intent: PLCAccountPreparationIntent
    ) async throws {
        _ = try await connection.query(
            """
            INSERT INTO plc_account_preparation_intents(
                request_id, did, canonical_handle, pds_origin,
                repository_revision, operation_cid, stage
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                .text(intent.requestID),
                .text(intent.did),
                .text(intent.canonicalHandle),
                .text(intent.pdsOrigin),
                .text(intent.repositoryRevision),
                .text(intent.operationCID),
                .integer(intent.stage.rawValue),
            ]
        )
    }

    private func decodeOperatorRestorePreparationIntent(
        _ row: SQLiteRow
    ) throws -> PLCAccountPreparationIntent {
        guard case let .integer(rawStage) = row.column("stage"),
              let stage = PLCAccountPreparationStage(rawValue: Int(rawStage)) else {
            throw AccountControlStoreError.malformedRecord
        }
        do {
            return try PLCAccountPreparationIntent(
                requestID: try requiredText(row, "request_id"),
                did: try requiredText(row, "did"),
                canonicalHandle: try requiredText(row, "canonical_handle"),
                pdsOrigin: try requiredText(row, "pds_origin"),
                repositoryRevision: try requiredText(row, "repository_revision"),
                operationCID: try requiredText(row, "operation_cid"),
                stage: stage
            )
        } catch {
            throw AccountControlStoreError.malformedRecord
        }
    }

    // MARK: Decoding and validation

    private var accountSelectSQL: String {
        """
        SELECT did, handle, status, created_at, updated_at, password_verifier,
               signing_key_generation, signing_key_reference,
               rotation_key_generation, rotation_key_reference,
               public_genesis_commit_cid,
               tombstone_declared_at, tombstone_reason,
               export_declared_at, export_reference
        FROM accounts
        """
    }

    private func requiredAccount(did: String) async throws -> AccountControlAccount {
        let rows = try await connection.query(
            accountSelectSQL + " WHERE did = ?",
            [.text(did)]
        )
        guard let row = rows.first else { throw AccountControlStoreError.notFound }
        return try decodeAccount(row)
    }

    private func decodeAccount(_ row: SQLiteRow) throws -> AccountControlAccount {
        let did = try requiredText(row, "did")
        let handle = try requiredText(row, "handle")
        guard AccountControlIdentifiers.isDID(did),
              AccountControlIdentifiers.isCanonicalHandle(handle) else {
            throw AccountControlStoreError.malformedRecord
        }
        let status = try AccountControlStatus(rawValue: try requiredText(row, "status"))
        let signingKey = try decodeKeyReference(
            row,
            generationColumn: "signing_key_generation",
            referenceColumn: "signing_key_reference",
            purpose: .signing
        )
        let rotationKey = try decodeKeyReference(
            row,
            generationColumn: "rotation_key_generation",
            referenceColumn: "rotation_key_reference",
            purpose: .rotation
        )
        let publicGenesisCommitCID = try optionalText(row, "public_genesis_commit_cid")
        let tombstone = try decodeTombstone(row)
        let export = try decodeExport(row)
        let credentialState: AccountCredentialState
        if let verifier = try optionalText(row, "password_verifier") {
            guard validVerifier(verifier) else { throw AccountControlStoreError.malformedRecord }
            credentialState = .configured
        } else {
            credentialState = .missing
        }
        do {
            return try AccountControlAccount(
                did: did,
                canonicalHandle: handle,
                status: status,
                createdAt: try requiredDate(row, "created_at"),
                updatedAt: try requiredDate(row, "updated_at"),
                credentialState: credentialState,
                signingKey: signingKey,
                rotationKey: rotationKey,
                publicGenesisCommitCID: publicGenesisCommitCID,
                tombstone: tombstone,
                export: export
            )
        } catch {
            throw AccountControlStoreError.malformedRecord
        }
    }

    private func decodeKeyReference(
        _ row: SQLiteRow,
        generationColumn: String,
        referenceColumn: String,
        purpose: AccountControlKeyReference.Purpose
    ) throws -> AccountControlKeyReference? {
        let generation = try optionalInteger(row, generationColumn)
        let reference = try optionalText(row, referenceColumn)
        guard generation != nil || reference != nil else { return nil }
        guard let generation, let reference, generation > 0 else {
            throw AccountControlStoreError.malformedRecord
        }
        do {
            return try AccountControlKeyReference(
                purpose: purpose,
                generation: UInt64(generation),
                reference: reference
            )
        } catch {
            throw AccountControlStoreError.malformedRecord
        }
    }

    private func decodeTombstone(_ row: SQLiteRow) throws -> AccountTombstoneMetadata? {
        let timestamp = try optionalDate(row, "tombstone_declared_at")
        let reason = try optionalText(row, "tombstone_reason")
        guard timestamp != nil || reason != nil else { return nil }
        guard let timestamp else { throw AccountControlStoreError.malformedRecord }
        do {
            return try AccountTombstoneMetadata(declaredAt: timestamp, reason: reason)
        } catch {
            throw AccountControlStoreError.malformedRecord
        }
    }

    private func decodeExport(_ row: SQLiteRow) throws -> AccountExportMetadata? {
        let timestamp = try optionalDate(row, "export_declared_at")
        let reference = try optionalText(row, "export_reference")
        guard timestamp != nil || reference != nil else { return nil }
        guard let timestamp, let reference else { throw AccountControlStoreError.malformedRecord }
        do {
            // Legacy/corrupted rows are not grandfathered: only the public
            // digest constructor may decode an export declaration.
            return try AccountExportMetadata(declaredAt: timestamp, reference: reference)
        } catch {
            throw AccountControlStoreError.malformedRecord
        }
    }

    private func validate(registration: AccountControlRegistration) throws {
        guard AccountControlIdentifiers.isDID(registration.did),
              AccountControlIdentifiers.isCanonicalHandle(registration.canonicalHandle),
              validVerifier(registration.passwordVerifier),
              registration.signingKey.isCanonicalValue,
              registration.rotationKey.isCanonicalValue,
              registration.signingKey.generation == registration.rotationKey.generation,
              registration.signingKey.purpose == .signing,
              registration.rotationKey.purpose == .rotation,
              registration.publicGenesisCommitCID.map(AccountControlIdentifiers.isPublicGenesisCommitCID) ?? true else {
            throw AccountControlStoreError.invalidInput
        }
        _ = try controlTimestamp(registration.createdAt)
    }

    private func controlTimestamp(_ date: Date) throws -> Int {
        let seconds = date.timeIntervalSince1970
        guard seconds.isFinite, seconds >= 0 else { throw AccountControlStoreError.invalidInput }
        let value = seconds * 1_000_000
        guard value.isFinite, value <= Double(Int.max) else {
            throw AccountControlStoreError.invalidInput
        }
        return Int(value.rounded(.down))
    }

    private func controlGeneration(_ generation: UInt64) throws -> Int {
        guard generation > 0, generation <= UInt64(Int.max) else {
            throw AccountControlStoreError.invalidInput
        }
        return Int(generation)
    }

    private func requiredDate(_ row: SQLiteRow, _ column: String) throws -> Date {
        guard case let .integer(value) = row.column(column), value >= 0 else {
            throw AccountControlStoreError.malformedRecord
        }
        return Date(timeIntervalSince1970: Double(value) / 1_000_000)
    }

    private func optionalDate(_ row: SQLiteRow, _ column: String) throws -> Date? {
        guard let value = row.column(column) else { throw AccountControlStoreError.malformedRecord }
        if value.isNull { return nil }
        guard case let .integer(raw) = value, raw >= 0 else {
            throw AccountControlStoreError.malformedRecord
        }
        return Date(timeIntervalSince1970: Double(raw) / 1_000_000)
    }

    private func requiredText(_ row: SQLiteRow, _ column: String) throws -> String {
        guard case let .text(value) = row.column(column), validIdentifier(value) else {
            throw AccountControlStoreError.malformedRecord
        }
        return value
    }

    private func optionalText(_ row: SQLiteRow, _ column: String) throws -> String? {
        guard let value = row.column(column) else { throw AccountControlStoreError.malformedRecord }
        if value.isNull { return nil }
        guard case let .text(text) = value, !text.utf8.contains(0) else {
            throw AccountControlStoreError.malformedRecord
        }
        return text
    }

    private func optionalInteger(_ row: SQLiteRow, _ column: String) throws -> Int? {
        guard let value = row.column(column) else { throw AccountControlStoreError.malformedRecord }
        if value.isNull { return nil }
        guard case let .integer(integer) = value else {
            throw AccountControlStoreError.malformedRecord
        }
        return integer
    }

    private func optionalText(_ value: String?) -> SQLiteData {
        value.map(SQLiteData.text) ?? .null
    }

    private func blob(_ data: Data) -> SQLiteData { data.sqliteData! }

    private func optionalInteger(_ value: Int?) -> SQLiteData {
        value.map(SQLiteData.integer) ?? .null
    }

    private func validIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 2_048 &&
            value.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7e }
    }

    private func validVerifier(_ value: String) -> Bool {
        value.hasPrefix("$argon2id$v=19$") && value.utf8.count <= 1_024 &&
            value.utf8.allSatisfy { $0 >= 0x20 && $0 <= 0x7e }
    }
}
