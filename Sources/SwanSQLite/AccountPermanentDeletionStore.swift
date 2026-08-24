import Foundation
import SQLiteNIO
import PetrelFirehose
import SwanStorage

extension SQLiteControlDatabase: AccountDeletionControlStore {
    static let maximumPendingDeletionPageSize = 100

    func migrateAccountPermanentDeletionSchema() async throws {
        _ = try await connection.query(
            """
            CREATE TABLE IF NOT EXISTS account_deletion_jobs (
                did TEXT PRIMARY KEY REFERENCES accounts(did) ON DELETE CASCADE,
                stage TEXT NOT NULL CHECK(stage IN (
                    'control-scrubbed',
                    'key-material-destroyed',
                    'account-data-destroyed',
                    'plc-tombstoned'
                )),
                revision INTEGER NOT NULL CHECK(revision > 0),
                requested_at INTEGER NOT NULL CHECK(requested_at >= 0),
                updated_at INTEGER NOT NULL CHECK(updated_at >= requested_at),
                tombstone_declared_at INTEGER NOT NULL
                    CHECK(tombstone_declared_at >= 0),
                tombstone_reason TEXT,
                export_declared_at INTEGER CHECK(export_declared_at >= 0),
                export_reference TEXT,
                rotation_key_generation INTEGER
                    CHECK(rotation_key_generation > 0),
                rotation_key_reference TEXT,
                CHECK(
                    (export_declared_at IS NULL AND export_reference IS NULL)
                    OR
                    (export_declared_at IS NOT NULL
                        AND export_reference IS NOT NULL)
                ),
                CHECK(
                    (rotation_key_generation IS NULL
                        AND rotation_key_reference IS NULL)
                    OR
                    (rotation_key_generation IS NOT NULL
                        AND rotation_key_reference IS NOT NULL)
                )
            )
            """
        )
        try await addColumnIfMissing(
            table: "account_deletion_jobs",
            column: "rotation_key_generation",
            definition: "INTEGER"
        )
        try await addColumnIfMissing(
            table: "account_deletion_jobs",
            column: "rotation_key_reference",
            definition: "TEXT"
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS account_deletion_rotation_valid_insert
            BEFORE INSERT ON account_deletion_jobs
            WHEN
                ((NEW.rotation_key_generation IS NULL)
                    != (NEW.rotation_key_reference IS NULL))
                OR (
                    NEW.rotation_key_generation IS NOT NULL
                    AND (
                        NEW.rotation_key_generation <= 0
                        OR NEW.rotation_key_reference
                            != (
                                'account-rotation:'
                                || NEW.rotation_key_generation
                            )
                    )
                )
                OR (
                    NEW.stage IN (
                        'key-material-destroyed',
                        'account-data-destroyed'
                    )
                    AND NEW.rotation_key_generation IS NOT NULL
                )
            BEGIN
                SELECT RAISE(ABORT, 'invalid deletion rotation key');
            END
            """
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS account_deletion_rotation_valid_update
            BEFORE UPDATE OF
                stage, rotation_key_generation, rotation_key_reference
            ON account_deletion_jobs
            WHEN
                ((NEW.rotation_key_generation IS NULL)
                    != (NEW.rotation_key_reference IS NULL))
                OR (
                    NEW.rotation_key_generation IS NOT NULL
                    AND (
                        NEW.rotation_key_generation <= 0
                        OR NEW.rotation_key_reference
                            != (
                                'account-rotation:'
                                || NEW.rotation_key_generation
                            )
                    )
                )
                OR (
                    NEW.stage IN (
                        'key-material-destroyed',
                        'account-data-destroyed'
                    )
                    AND NEW.rotation_key_generation IS NOT NULL
                )
            BEGIN
                SELECT RAISE(ABORT, 'invalid deletion rotation key');
            END
            """
        )
        _ = try await connection.query(
            """
            CREATE TABLE IF NOT EXISTS account_deletion_staging_keys (
                did TEXT NOT NULL REFERENCES account_deletion_jobs(did)
                    ON DELETE CASCADE,
                request_id TEXT NOT NULL,
                canonical_handle TEXT NOT NULL,
                pds_origin TEXT NOT NULL,
                repository_revision TEXT NOT NULL,
                PRIMARY KEY(did, request_id)
            ) WITHOUT ROWID
            """
        )
        _ = try await connection.query(
            """
            CREATE TRIGGER IF NOT EXISTS account_deletion_one_staging_key_insert
            BEFORE INSERT ON account_deletion_staging_keys
            WHEN EXISTS (
                SELECT 1 FROM account_deletion_staging_keys
                WHERE did = NEW.did
            )
            BEGIN
                SELECT RAISE(ABORT, 'only one deletion staging key is allowed');
            END
            """
        )
        _ = try await connection.query(
            """
            CREATE TABLE IF NOT EXISTS account_deletion_tombstones (
                did TEXT PRIMARY KEY,
                finalized_at INTEGER NOT NULL CHECK(finalized_at >= 0),
                revision INTEGER NOT NULL CHECK(revision > 0),
                tombstone_declared_at INTEGER NOT NULL
                    CHECK(tombstone_declared_at >= 0),
                tombstone_reason TEXT,
                export_declared_at INTEGER CHECK(export_declared_at >= 0),
                export_reference TEXT,
                CHECK(
                    (export_declared_at IS NULL AND export_reference IS NULL)
                    OR
                    (export_declared_at IS NOT NULL
                        AND export_reference IS NOT NULL)
                )
            )
            """
        )
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS account_deletion_jobs_stage_did
            ON account_deletion_jobs(stage, did)
            """
        )
        try await migrateLegacyDeletedAccountsLocked()
    }

    public func beginDeletion(
        did: String,
        declaration: AccountLifecycleDeclaration,
        now: Date
    ) async throws -> AccountDeletionJob {
        guard AccountControlIdentifiers.isDID(did),
              declaration.tombstone?.isCanonicalValue ?? true,
              declaration.export?.isCanonicalValue ?? true else {
            throw AccountDeletionStoreError.invalidInput
        }
        let timestamp = try deletionTimestamp(now)
        let declaration = try canonicalDeletionDeclaration(declaration)
        return try await withConnectionGate {
            try await transaction {
                if let existing = try await deletionJobLocked(did: did) {
                    guard declarationMatches(
                        declaration,
                        tombstone: existing.tombstone,
                        export: existing.export
                    ) else {
                        throw AccountDeletionStoreError.conflict
                    }
                    return existing
                }
                if try await tombstoneLocked(did: did) != nil {
                    throw AccountDeletionStoreError.conflict
                }
                return try await beginDeletionLocked(
                    did: did,
                    declaration: declaration,
                    timestamp: timestamp,
                    permitsLegacyDeletedStatus: false
                )
            }
        }
    }

    public func deletionJob(did: String) async throws -> AccountDeletionJob? {
        guard AccountControlIdentifiers.isDID(did) else {
            throw AccountDeletionStoreError.invalidInput
        }
        return try await withConnectionGate {
            try await deletionJobLocked(did: did)
        }
    }

    public func pendingDeletionJobs(
        afterDID: String?,
        limit: Int
    ) async throws -> [AccountDeletionJob] {
        guard (1 ... Self.maximumPendingDeletionPageSize).contains(limit),
              afterDID.map(AccountControlIdentifiers.isDID) ?? true else {
            throw AccountDeletionStoreError.invalidInput
        }
        return try await withConnectionGate {
            let rows: [SQLiteRow]
            if let afterDID {
                rows = try await connection.query(
                    """
                    SELECT did
                    FROM account_deletion_jobs
                    WHERE did > ?
                    ORDER BY did
                    LIMIT ?
                    """,
                    [.text(afterDID), .integer(limit)]
                )
            } else {
                rows = try await connection.query(
                    """
                    SELECT did
                    FROM account_deletion_jobs
                    ORDER BY did
                    LIMIT ?
                    """,
                    [.integer(limit)]
                )
            }
            var result: [AccountDeletionJob] = []
            result.reserveCapacity(rows.count)
            var previous = afterDID
            for row in rows {
                let did = try deletionRequiredText(row, "did")
                guard AccountControlIdentifiers.isDID(did),
                      previous.map({ $0 < did }) ?? true,
                      let job = try await deletionJobLocked(did: did) else {
                    throw AccountDeletionStoreError.malformedRecord
                }
                result.append(job)
                previous = did
            }
            return result
        }
    }

    public func advanceDeletion(
        did: String,
        expectedStage: AccountDeletionStage,
        expectedRevision: UInt64,
        to stage: AccountDeletionStage,
        now: Date
    ) async throws -> AccountDeletionJob {
        guard AccountControlIdentifiers.isDID(did),
              expectedRevision > 0,
              expectedRevision <= UInt64(Int.max),
              expectedStage.next == stage else {
            throw AccountDeletionStoreError.invalidStage
        }
        let timestamp = try deletionTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                guard let current = try await deletionJobLocked(did: did) else {
                    throw AccountDeletionStoreError.notFound
                }
                if current.stage == stage {
                    // Retrying the exact CAS after an uncertain commit is
                    // idempotent. A job already beyond this destination is a
                    // conflict rather than a silent success.
                    guard current.revision > expectedRevision else {
                        throw AccountDeletionStoreError.malformedRecord
                    }
                    return current
                }
                guard current.stage == expectedStage,
                      current.revision == expectedRevision else {
                    throw AccountDeletionStoreError.conflict
                }
                let revision = try advancedDeletionRevision(
                    current: current.revision,
                    proposedTimestamp: timestamp
                )
                let updated = try await connection.query(
                    """
                    UPDATE account_deletion_jobs
                    SET stage = ?, revision = ?, updated_at = ?,
                        rotation_key_generation = CASE
                            WHEN ? = 'key-material-destroyed'
                            THEN NULL
                            ELSE rotation_key_generation
                        END,
                        rotation_key_reference = CASE
                            WHEN ? = 'key-material-destroyed'
                            THEN NULL
                            ELSE rotation_key_reference
                        END
                    WHERE did = ? AND stage = ? AND revision = ?
                    RETURNING did
                    """,
                    [
                        .text(stage.rawValue), .integer(try deletionInteger(revision)),
                        .integer(try deletionInteger(revision)),
                        .text(stage.rawValue), .text(stage.rawValue),
                        .text(did),
                        .text(expectedStage.rawValue),
                        .integer(try deletionInteger(expectedRevision)),
                    ]
                )
                guard updated.count == 1,
                      try deletionRequiredText(updated[0], "did") == did else {
                    throw AccountDeletionStoreError.conflict
                }
                if stage == .keyMaterialDestroyed {
                    _ = try await connection.query(
                        """
                        DELETE FROM account_deletion_staging_keys
                        WHERE did = ?
                        """,
                        [.text(did)]
                    )
                }
                guard let advanced = try await deletionJobLocked(did: did),
                      advanced.stage == stage,
                      advanced.revision == revision else {
                    throw AccountDeletionStoreError.malformedRecord
                }
                return advanced
            }
        }
    }

    public func finalizeDeletion(
        did: String,
        expectedRevision: UInt64,
        now: Date
    ) async throws -> AccountDeletionTombstone {
        guard AccountControlIdentifiers.isDID(did),
              expectedRevision > 0,
              expectedRevision <= UInt64(Int.max) else {
            throw AccountDeletionStoreError.invalidInput
        }
        let timestamp = try deletionTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                if let existing = try await tombstoneLocked(did: did) {
                    return existing
                }
                guard let job = try await deletionJobLocked(did: did) else {
                    throw AccountDeletionStoreError.notFound
                }
                guard job.stage.isFinalizable else {
                    throw AccountDeletionStoreError.invalidStage
                }
                guard job.revision == expectedRevision else {
                    throw AccountDeletionStoreError.conflict
                }
                try await validateFinalDeletionScrubLocked(did: did)
                let revision = try advancedDeletionRevision(
                    current: job.revision,
                    proposedTimestamp: timestamp
                )
                _ = try await connection.query(
                    """
                    INSERT INTO account_deletion_tombstones(
                        did, finalized_at, revision,
                        tombstone_declared_at, tombstone_reason,
                        export_declared_at, export_reference
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        .text(did), .integer(try deletionInteger(revision)),
                        .integer(try deletionInteger(revision)),
                        .integer(
                            try deletionTimestamp(job.tombstone.declaredAt)
                        ),
                        deletionOptionalText(job.tombstone.reason),
                        try deletionOptionalTimestamp(
                            job.export?.declaredAt
                        ),
                        deletionOptionalText(job.export?.reference),
                    ]
                )
                let deleted = try await connection.query(
                    """
                    DELETE FROM accounts
                    WHERE did = ? AND status = 'deleting'
                    RETURNING did
                    """,
                    [.text(did)]
                )
                guard deleted.count == 1,
                      try deletionRequiredText(deleted[0], "did") == did,
                      let tombstone = try await tombstoneLocked(did: did) else {
                    throw AccountDeletionStoreError.malformedRecord
                }
                return tombstone
            }
        }
    }

    public func tombstone(
        did: String
    ) async throws -> AccountDeletionTombstone? {
        guard AccountControlIdentifiers.isDID(did) else {
            throw AccountDeletionStoreError.invalidInput
        }
        return try await withConnectionGate {
            try await tombstoneLocked(did: did)
        }
    }

    private func migrateLegacyDeletedAccountsLocked() async throws {
        // This migration may encounter an old control database with many
        // logically deleted accounts. Bound each materialized result even
        // though the enclosing migration transaction must process them all.
        while true {
            let rows = try await connection.query(
                """
                SELECT did, updated_at
                FROM accounts
                WHERE status = 'deleted'
                ORDER BY did
                LIMIT ?
                """,
                [.integer(Self.maximumPendingDeletionPageSize)]
            )
            guard !rows.isEmpty else { return }
            for row in rows {
                let did = try deletionRequiredText(row, "did")
                let updatedAt = try deletionRequiredInteger(row, "updated_at")
                guard AccountControlIdentifiers.isDID(did),
                      updatedAt > 0,
                      try await deletionJobLocked(did: did) == nil,
                      try await tombstoneLocked(did: did) == nil else {
                    throw AccountDeletionStoreError.malformedRecord
                }
                _ = try await beginDeletionLocked(
                    did: did,
                    declaration: .init(),
                    timestamp: try advancedDeletionInteger(
                        current: updatedAt,
                        proposed: updatedAt
                    ),
                    permitsLegacyDeletedStatus: true
                )
            }
        }
    }

    private func beginDeletionLocked(
        did: String,
        declaration: AccountLifecycleDeclaration,
        timestamp: Int,
        permitsLegacyDeletedStatus: Bool
    ) async throws -> AccountDeletionJob {
        let rows = try await connection.query(
            """
            SELECT did, status, updated_at,
                   rotation_key_generation, rotation_key_reference,
                   tombstone_declared_at, tombstone_reason,
                   export_declared_at, export_reference
            FROM accounts
            WHERE did = ?
            """,
            [.text(did)]
        )
        guard rows.count == 1, let row = rows.first else {
            throw AccountDeletionStoreError.notFound
        }
        let status: AccountControlStatus
        do {
            status = try AccountControlStatus(
                rawValue: deletionRequiredText(row, "status")
            )
        } catch {
            throw AccountDeletionStoreError.malformedRecord
        }
        guard status.isCanonicalValue,
              status != .deleting,
              status != .deleted || permitsLegacyDeletedStatus else {
            throw AccountDeletionStoreError.conflict
        }
        let currentRevision = try deletionRequiredInteger(row, "updated_at")
        guard currentRevision > 0 else {
            throw AccountDeletionStoreError.malformedRecord
        }
        // Serialize permanent deletion with the email worker's durable
        // pre-network fence. A claimed row is harmless; a row whose
        // `send_started_at` is set has already crossed into SMTP and must be
        // allowed to finish (or its lease to expire after a crash) before the
        // outbox/account rows can be scrubbed. If deletion wins the SQLite
        // write race first, the worker's fence update affects zero rows and
        // it is forbidden from starting network I/O.
        let activeEmailSends = try await connection.query(
            """
            SELECT delivery_id
            FROM account_email_delivery_outbox
            WHERE did = ?
              AND send_started_at IS NOT NULL
              AND (lease_expires_at IS NULL OR lease_expires_at > ?)
            LIMIT 1
            """,
            [.text(did), .integer(timestamp)]
        )
        guard activeEmailSends.isEmpty else {
            throw AccountDeletionStoreError.conflict
        }
        let revision = try advancedDeletionInteger(
            current: currentRevision,
            proposed: timestamp
        )
        let existingTombstone = try deletionTombstoneMetadata(row)
        let existingExport = try deletionExportMetadata(row)
        let rotationKey = try deletionRotationKeyReference(row)
        let tombstone: AccountTombstoneMetadata
        if let existingTombstone {
            guard declaration.tombstone == nil
                    || declaration.tombstone == existingTombstone else {
                throw AccountDeletionStoreError.conflict
            }
            tombstone = existingTombstone
        } else if let declared = declaration.tombstone {
            tombstone = declared
        } else {
            do {
                tombstone = try AccountTombstoneMetadata(
                    declaredAt: Date(
                        timeIntervalSince1970:
                            Double(revision) / 1_000_000
                    )
                )
            } catch {
                throw AccountDeletionStoreError.invalidInput
            }
        }
        let export: AccountExportMetadata?
        if let existingExport {
            guard declaration.export == nil
                    || declaration.export == existingExport else {
                throw AccountDeletionStoreError.conflict
            }
            export = existingExport
        } else {
            export = declaration.export
        }

        let intentRows = try await connection.query(
            """
            SELECT request_id, canonical_handle, pds_origin,
                   repository_revision
            FROM plc_account_preparation_intents
            WHERE did = ?
            """,
            [.text(did)]
        )
        guard intentRows.count <=
                AccountDeletionJob.maximumStagingKeyBindings else {
            throw AccountDeletionStoreError.malformedRecord
        }
        let stagingBindings = try intentRows.map {
            try deletionStagingBinding($0)
        }
        _ = try await connection.query(
            """
            INSERT INTO account_deletion_jobs(
                did, stage, revision, requested_at, updated_at,
                tombstone_declared_at, tombstone_reason,
                export_declared_at, export_reference,
                rotation_key_generation, rotation_key_reference
            ) VALUES (
                ?, 'control-scrubbed', ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            [
                .text(did), .integer(revision), .integer(revision),
                .integer(revision),
                .integer(try deletionTimestamp(tombstone.declaredAt)),
                deletionOptionalText(tombstone.reason),
                try deletionOptionalTimestamp(export?.declaredAt),
                deletionOptionalText(export?.reference),
                rotationKey.map {
                    SQLiteData.integer(Int($0.generation))
                } ?? .null,
                deletionOptionalText(rotationKey?.reference),
            ]
        )
        for binding in stagingBindings {
            _ = try await connection.query(
                """
                INSERT INTO account_deletion_staging_keys(
                    did, request_id, canonical_handle, pds_origin,
                    repository_revision
                ) VALUES (?, ?, ?, ?, ?)
                """,
                [
                    .text(did), .text(binding.requestID),
                    .text(binding.canonicalHandle),
                    .text(binding.pdsOrigin),
                    .text(binding.repositoryRevision),
                ]
            )
        }

        // These deletes and the lifecycle/key-reference scrub share the same
        // BEGIN IMMEDIATE transaction. No authorization path can observe the
        // account as deleting while a subject token or recovery proof remains.
        _ = try await connection.query(
            "DELETE FROM oauth_tokens WHERE subject = ?",
            [.text(did)]
        )
        _ = try await connection.query(
            "DELETE FROM oauth_control_token_families WHERE subject = ?",
            [.text(did)]
        )
        _ = try await connection.query(
            "DELETE FROM account_email_delivery_outbox WHERE did = ?",
            [.text(did)]
        )
        _ = try await connection.query(
            "DELETE FROM account_email_tokens WHERE did = ?",
            [.text(did)]
        )
        _ = try await connection.query(
            "DELETE FROM account_emails WHERE did = ?",
            [.text(did)]
        )
        _ = try await connection.query(
            "DELETE FROM plc_account_preparation_intents WHERE did = ?",
            [.text(did)]
        )
        _ = try await connection.query(
            "DELETE FROM plc_credential_key_continuity WHERE issuer = ?",
            [.text(did)]
        )
        let placeholder = "deleting-\(UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "")).invalid"
        let updated = try await connection.query(
            """
            UPDATE accounts
            SET handle = ?,
                status = 'deleting',
                updated_at = ?,
                password_verifier = NULL,
                signing_key_generation = NULL,
                signing_key_reference = NULL,
                rotation_key_generation = NULL,
                rotation_key_reference = NULL,
                public_genesis_commit_cid = NULL,
                tombstone_declared_at = ?,
                tombstone_reason = ?,
                export_declared_at = ?,
                export_reference = ?
            WHERE did = ? AND status = ? AND updated_at = ?
            RETURNING did
            """,
            [
                .text(placeholder), .integer(revision),
                .integer(try deletionTimestamp(tombstone.declaredAt)),
                deletionOptionalText(tombstone.reason),
                try deletionOptionalTimestamp(export?.declaredAt),
                deletionOptionalText(export?.reference),
                .text(did), .text(status.rawValue),
                .integer(currentRevision),
            ]
        )
        guard updated.count == 1,
              try deletionRequiredText(updated[0], "did") == did,
              let job = try await deletionJobLocked(did: did) else {
            throw AccountDeletionStoreError.conflict
        }
        // Announce the deletion in the same transaction as the scrub: the
        // batch is DID-namespaced and `beginDeletion` runs at most once per
        // DID, so the constant operation ID is safe. The firehose sequencer's
        // `deleted` marker derivation prunes this DID's prior retained
        // history atomically with the append.
        let deletionTime = Date(
            timeIntervalSince1970: Double(timestamp) / 1_000_000
        )
        _ = try await enqueueLifecycleEventBatchInTransaction(
            did: did,
            operationID: "permanent-deletion",
            items: [
                LifecycleEventItem(
                    sourceKey: PublicFirehoseSourceKey.account(
                        did: did, operationID: "permanent-deletion"
                    ),
                    kind: .account,
                    payload: try PersistedPublicFirehoseJSON.encode(
                        PublicFirehoseAccountMaterial(
                            did: did,
                            active: false,
                            status: .deleted,
                            time: PublicFirehoseTime.encode(deletionTime)
                        )
                    ),
                    carBytes: nil
                )
            ],
            now: deletionTime
        )
        return job
    }

    private func deletionJobLocked(
        did: String
    ) async throws -> AccountDeletionJob? {
        let rows = try await connection.query(
            """
            SELECT did, stage, revision, requested_at, updated_at,
                   tombstone_declared_at, tombstone_reason,
                   export_declared_at, export_reference,
                   rotation_key_generation, rotation_key_reference
            FROM account_deletion_jobs
            WHERE did = ?
            """,
            [.text(did)]
        )
        guard rows.count <= 1 else {
            throw AccountDeletionStoreError.malformedRecord
        }
        guard let row = rows.first else { return nil }
        let bindings = try await connection.query(
            """
            SELECT request_id, canonical_handle, pds_origin,
                   repository_revision
            FROM account_deletion_staging_keys
            WHERE did = ?
            ORDER BY request_id
            """,
            [.text(did)]
        )
        guard bindings.count <=
                AccountDeletionJob.maximumStagingKeyBindings else {
            throw AccountDeletionStoreError.malformedRecord
        }
        do {
            guard let stage = AccountDeletionStage(
                rawValue: try deletionRequiredText(row, "stage")
            ) else {
                throw AccountDeletionStoreError.malformedRecord
            }
            return try AccountDeletionJob(
                did: deletionRequiredText(row, "did"),
                stage: stage,
                revision: UInt64(
                    try deletionRequiredPositiveInteger(row, "revision")
                ),
                requestedAt: try deletionRequiredDate(
                    row,
                    "requested_at"
                ),
                updatedAt: try deletionRequiredDate(row, "updated_at"),
                tombstone: try deletionRequiredTombstoneMetadata(row),
                export: try deletionExportMetadata(row),
                rotationKey: try deletionRotationKeyReference(row),
                stagingKeyBindings: try bindings.map {
                    try deletionStagingBinding($0)
                }
            )
        } catch let error as AccountDeletionStoreError {
            throw error == .invalidInput ? .malformedRecord : error
        } catch {
            throw AccountDeletionStoreError.malformedRecord
        }
    }

    private func tombstoneLocked(
        did: String
    ) async throws -> AccountDeletionTombstone? {
        let rows = try await connection.query(
            """
            SELECT did, finalized_at, revision,
                   tombstone_declared_at, tombstone_reason,
                   export_declared_at, export_reference
            FROM account_deletion_tombstones
            WHERE did = ?
            """,
            [.text(did)]
        )
        guard rows.count <= 1 else {
            throw AccountDeletionStoreError.malformedRecord
        }
        guard let row = rows.first else { return nil }
        do {
            return try AccountDeletionTombstone(
                did: deletionRequiredText(row, "did"),
                finalizedAt: deletionRequiredDate(row, "finalized_at"),
                revision: UInt64(
                    try deletionRequiredPositiveInteger(row, "revision")
                ),
                tombstone: deletionRequiredTombstoneMetadata(row),
                export: deletionExportMetadata(row)
            )
        } catch let error as AccountDeletionStoreError {
            throw error == .invalidInput ? .malformedRecord : error
        } catch {
            throw AccountDeletionStoreError.malformedRecord
        }
    }

    private func validateFinalDeletionScrubLocked(did: String) async throws {
        let accounts = try await connection.query(
            """
            SELECT status, handle, password_verifier,
                   signing_key_generation, signing_key_reference,
                   rotation_key_generation, rotation_key_reference,
                   public_genesis_commit_cid
            FROM accounts
            WHERE did = ?
            """,
            [.text(did)]
        )
        guard accounts.count == 1, let account = accounts.first,
              try deletionRequiredText(account, "status") == "deleting",
              try deletionRequiredText(account, "handle")
                  .hasPrefix("deleting-"),
              try deletionRequiredText(account, "handle")
                  .hasSuffix(".invalid"),
              deletionIsNull(account, "password_verifier"),
              deletionIsNull(account, "signing_key_generation"),
              deletionIsNull(account, "signing_key_reference"),
              deletionIsNull(account, "rotation_key_generation"),
              deletionIsNull(account, "rotation_key_reference"),
              deletionIsNull(account, "public_genesis_commit_cid") else {
            throw AccountDeletionStoreError.malformedRecord
        }
        for (table, predicate) in [
            ("oauth_tokens", "subject = ?"),
            ("oauth_control_token_families", "subject = ?"),
            ("account_emails", "did = ?"),
            ("account_email_tokens", "did = ?"),
            ("account_email_delivery_outbox", "did = ?"),
            ("plc_account_preparation_intents", "did = ?"),
            ("plc_credential_key_continuity", "issuer = ?"),
            ("account_deletion_staging_keys", "did = ?"),
        ] {
            let rows = try await connection.query(
                "SELECT 1 FROM \(table) WHERE \(predicate) LIMIT 1",
                [.text(did)]
            )
            guard rows.isEmpty else {
                throw AccountDeletionStoreError.malformedRecord
            }
        }
    }

    private func deletionStagingBinding(
        _ row: SQLiteRow
    ) throws -> AccountDeletionStagingKeyBinding {
        do {
            return try AccountDeletionStagingKeyBinding(
                requestID: deletionRequiredText(row, "request_id"),
                canonicalHandle: deletionRequiredText(
                    row,
                    "canonical_handle"
                ),
                pdsOrigin: deletionRequiredText(row, "pds_origin"),
                repositoryRevision: deletionRequiredText(
                    row,
                    "repository_revision"
                )
            )
        } catch {
            throw AccountDeletionStoreError.malformedRecord
        }
    }

    private func deletionRequiredTombstoneMetadata(
        _ row: SQLiteRow
    ) throws -> AccountTombstoneMetadata {
        guard let metadata = try deletionTombstoneMetadata(row) else {
            throw AccountDeletionStoreError.malformedRecord
        }
        return metadata
    }

    private func deletionTombstoneMetadata(
        _ row: SQLiteRow
    ) throws -> AccountTombstoneMetadata? {
        let declared = try deletionOptionalDate(
            row,
            "tombstone_declared_at"
        )
        let reason = try deletionOptionalText(row, "tombstone_reason")
        guard declared != nil || reason != nil else { return nil }
        guard let declared else {
            throw AccountDeletionStoreError.malformedRecord
        }
        do {
            return try AccountTombstoneMetadata(
                declaredAt: declared,
                reason: reason
            )
        } catch {
            throw AccountDeletionStoreError.malformedRecord
        }
    }

    private func deletionExportMetadata(
        _ row: SQLiteRow
    ) throws -> AccountExportMetadata? {
        let declared = try deletionOptionalDate(row, "export_declared_at")
        let reference = try deletionOptionalText(row, "export_reference")
        guard declared != nil || reference != nil else { return nil }
        guard let declared, let reference else {
            throw AccountDeletionStoreError.malformedRecord
        }
        do {
            return try AccountExportMetadata(
                declaredAt: declared,
                reference: reference
            )
        } catch {
            throw AccountDeletionStoreError.malformedRecord
        }
    }

    private func deletionRotationKeyReference(
        _ row: SQLiteRow
    ) throws -> AccountControlKeyReference? {
        let generation = try deletionOptionalInteger(
            row,
            "rotation_key_generation"
        )
        let reference = try deletionOptionalText(
            row,
            "rotation_key_reference"
        )
        guard generation != nil || reference != nil else { return nil }
        guard let generation, generation > 0, let reference else {
            throw AccountDeletionStoreError.malformedRecord
        }
        do {
            return try AccountControlKeyReference(
                purpose: .rotation,
                generation: UInt64(generation),
                reference: reference
            )
        } catch {
            throw AccountDeletionStoreError.malformedRecord
        }
    }

    private func declarationMatches(
        _ declaration: AccountLifecycleDeclaration,
        tombstone: AccountTombstoneMetadata,
        export: AccountExportMetadata?
    ) -> Bool {
        (declaration.tombstone == nil
            || declaration.tombstone == tombstone)
            && (declaration.export == nil || declaration.export == export)
    }

    /// SQLite stores control dates at microsecond precision. Canonicalize a
    /// caller's declaration before both the first insert and idempotent retry
    /// comparison so sub-microsecond `Date` components cannot create a false
    /// conflict after a successful commit.
    private func canonicalDeletionDeclaration(
        _ declaration: AccountLifecycleDeclaration
    ) throws -> AccountLifecycleDeclaration {
        let tombstone = try declaration.tombstone.map {
            try AccountTombstoneMetadata(
                declaredAt: Date(
                    timeIntervalSince1970:
                        Double(try deletionTimestamp($0.declaredAt))
                            / 1_000_000
                ),
                reason: $0.reason
            )
        }
        let export = try declaration.export.map {
            try AccountExportMetadata(
                declaredAt: Date(
                    timeIntervalSince1970:
                        Double(try deletionTimestamp($0.declaredAt))
                            / 1_000_000
                ),
                reference: $0.reference
            )
        }
        return AccountLifecycleDeclaration(
            tombstone: tombstone,
            export: export
        )
    }

    private func deletionTimestamp(_ date: Date) throws -> Int {
        let seconds = date.timeIntervalSince1970
        guard seconds.isFinite, seconds >= 0 else {
            throw AccountDeletionStoreError.invalidInput
        }
        let value = seconds * 1_000_000
        // `Double(Int.max)` rounds to 2^63 on 64-bit platforms, which is one
        // past the largest representable Int. Require a strict bound before
        // conversion so hostile/far-future dates cannot trap the process.
        guard value.isFinite, value < Double(Int.max) else {
            throw AccountDeletionStoreError.invalidInput
        }
        return Int(value.rounded(.down))
    }

    private func advancedDeletionRevision(
        current: UInt64,
        proposedTimestamp: Int
    ) throws -> UInt64 {
        guard current <= UInt64(Int.max),
              proposedTimestamp >= 0 else {
            throw AccountDeletionStoreError.invalidInput
        }
        return UInt64(
            try advancedDeletionInteger(
                current: Int(current),
                proposed: proposedTimestamp
            )
        )
    }

    private func advancedDeletionInteger(
        current: Int,
        proposed: Int
    ) throws -> Int {
        guard current > 0,
              current < Int.max,
              proposed >= 0,
              proposed < Int.max else {
            throw AccountDeletionStoreError.unavailable
        }
        return max(current + 1, proposed)
    }

    private func deletionInteger(_ value: UInt64) throws -> Int {
        guard value > 0, value <= UInt64(Int.max) else {
            throw AccountDeletionStoreError.invalidInput
        }
        return Int(value)
    }

    private func deletionOptionalTimestamp(
        _ date: Date?
    ) throws -> SQLiteData {
        guard let date else { return .null }
        return .integer(try deletionTimestamp(date))
    }

    private func deletionOptionalText(_ value: String?) -> SQLiteData {
        value.map(SQLiteData.text) ?? .null
    }

    private func deletionRequiredText(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> String {
        guard case let .text(value) = row.column(column),
              !value.isEmpty, value.utf8.count <= 2_048,
              !value.utf8.contains(0) else {
            throw AccountDeletionStoreError.malformedRecord
        }
        return value
    }

    private func deletionOptionalText(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> String? {
        guard let value = row.column(column) else {
            throw AccountDeletionStoreError.malformedRecord
        }
        if value.isNull { return nil }
        guard case let .text(text) = value,
              text.utf8.count <= 2_048,
              !text.utf8.contains(0) else {
            throw AccountDeletionStoreError.malformedRecord
        }
        return text
    }

    private func deletionRequiredInteger(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> Int {
        guard case let .integer(value) = row.column(column) else {
            throw AccountDeletionStoreError.malformedRecord
        }
        return value
    }

    private func deletionRequiredPositiveInteger(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> Int {
        let value = try deletionRequiredInteger(row, column)
        guard value > 0 else {
            throw AccountDeletionStoreError.malformedRecord
        }
        return value
    }

    private func deletionOptionalInteger(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> Int? {
        guard let value = row.column(column) else {
            throw AccountDeletionStoreError.malformedRecord
        }
        if value.isNull { return nil }
        guard case let .integer(integer) = value else {
            throw AccountDeletionStoreError.malformedRecord
        }
        return integer
    }

    private func deletionRequiredDate(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> Date {
        let value = try deletionRequiredInteger(row, column)
        guard value >= 0 else {
            throw AccountDeletionStoreError.malformedRecord
        }
        return Date(timeIntervalSince1970: Double(value) / 1_000_000)
    }

    private func deletionOptionalDate(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> Date? {
        guard let value = row.column(column) else {
            throw AccountDeletionStoreError.malformedRecord
        }
        if value.isNull { return nil }
        guard case let .integer(raw) = value, raw >= 0 else {
            throw AccountDeletionStoreError.malformedRecord
        }
        return Date(timeIntervalSince1970: Double(raw) / 1_000_000)
    }

    private func deletionIsNull(
        _ row: SQLiteRow,
        _ column: String
    ) -> Bool {
        row.column(column)?.isNull == true
    }
}
