import Foundation
import SQLiteNIO
import SwanStorage

extension SQLiteControlDatabase: PLCAccountPreparationIntentStore {
    public func reservePLCAccountPreparationIntent(
        _ intent: PLCAccountPreparationIntent
    ) async throws -> PLCAccountPreparationReservation {
        try await withConnectionGate {
            try await transaction {
                if let existing = try await loadIntentLocked(requestID: intent.requestID) {
                    return .existing(existing)
                }
                let conflicts = try await connection.query(
                    """
                    SELECT request_id FROM plc_account_preparation_intents
                    WHERE did = ? OR canonical_handle = ? OR operation_cid = ?
                    LIMIT 1
                    """,
                    [
                        .text(intent.did), .text(intent.canonicalHandle),
                        .text(intent.operationCID),
                    ]
                )
                guard conflicts.isEmpty else {
                    throw PLCAccountPreparationStoreError.conflict
                }
                do {
                    _ = try await connection.query(
                        """
                        INSERT INTO plc_account_preparation_intents(
                            request_id, did, canonical_handle, pds_origin,
                            repository_revision, operation_cid, stage
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        [
                            .text(intent.requestID), .text(intent.did),
                            .text(intent.canonicalHandle), .text(intent.pdsOrigin),
                            .text(intent.repositoryRevision), .text(intent.operationCID),
                            .integer(intent.stage.rawValue),
                        ]
                    )
                } catch {
                    throw PLCAccountPreparationStoreError.conflict
                }
                return .created
            }
        }
    }

    public func plcAccountPreparationIntent(
        requestID: String
    ) async throws -> PLCAccountPreparationIntent? {
        guard !requestID.isEmpty, requestID.utf8.count <= 128 else {
            throw PLCAccountPreparationStoreError.invalidInput
        }
        return try await withConnectionGate {
            try await loadIntentLocked(requestID: requestID)
        }
    }

    public func advancePLCAccountPreparationIntent(
        requestID: String,
        expectedStage: PLCAccountPreparationStage,
        to stage: PLCAccountPreparationStage
    ) async throws -> PLCAccountPreparationIntent {
        guard stage > expectedStage else {
            throw PLCAccountPreparationStoreError.invalidTransition
        }
        return try await withConnectionGate {
            try await transaction {
                guard let existing = try await loadIntentLocked(requestID: requestID) else {
                    throw PLCAccountPreparationStoreError.notFound
                }
                if existing.stage == stage { return existing }
                guard existing.stage == expectedStage else {
                    throw PLCAccountPreparationStoreError.conflict
                }
                _ = try await connection.query(
                    """
                    UPDATE plc_account_preparation_intents
                    SET stage = ?
                    WHERE request_id = ? AND stage = ?
                    """,
                    [.integer(stage.rawValue), .text(requestID), .integer(expectedStage.rawValue)]
                )
                guard let advanced = try await loadIntentLocked(requestID: requestID),
                      advanced.stage == stage else {
                    throw PLCAccountPreparationStoreError.conflict
                }
                return advanced
            }
        }
    }

    private func loadIntentLocked(
        requestID: String
    ) async throws -> PLCAccountPreparationIntent? {
        let rows = try await connection.query(
            """
            SELECT request_id, did, canonical_handle, pds_origin,
                   repository_revision, operation_cid, stage
            FROM plc_account_preparation_intents WHERE request_id = ?
            """,
            [.text(requestID)]
        )
        guard rows.count <= 1 else {
            throw PLCAccountPreparationStoreError.malformedRecord
        }
        guard let row = rows.first else { return nil }
        do {
            return try PLCAccountPreparationIntent(
                requestID: try requiredText(row, "request_id"),
                did: try requiredText(row, "did"),
                canonicalHandle: try requiredText(row, "canonical_handle"),
                pdsOrigin: try requiredText(row, "pds_origin"),
                repositoryRevision: try requiredText(row, "repository_revision"),
                operationCID: try requiredText(row, "operation_cid"),
                stage: try requiredStage(row)
            )
        } catch let error as PLCAccountPreparationStoreError {
            if error == .invalidInput { throw PLCAccountPreparationStoreError.malformedRecord }
            throw error
        } catch {
            throw PLCAccountPreparationStoreError.malformedRecord
        }
    }
}

extension SQLiteAccountDatabase:
    PLCAccountPreparationJournalStore,
    PLCAccountPreparationAccountStore
{
    public func installPLCAccountPreparationJournal(
        _ journal: PLCAccountPreparationJournal
    ) async throws -> PLCAccountPreparationJournal {
        guard journal.did == accountDID else {
            throw PLCAccountPreparationStoreError.conflict
        }
        return try await withConnectionGate {
            try await transaction {
                if let existing = try await loadJournalLocked() {
                    guard existing == journal else {
                        throw PLCAccountPreparationStoreError.conflict
                    }
                    return existing
                }
                do {
                    _ = try await connection.query(
                        """
                        INSERT INTO plc_account_preparation_journal(
                            singleton, request_id, did, canonical_handle, pds_origin,
                            repository_revision, operation_cid, signed_operation_json,
                            signing_key_reference, rotation_key_reference,
                            public_genesis_commit_cid, stage
                        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        [
                            .text(journal.requestID), .text(journal.did),
                            .text(journal.canonicalHandle), .text(journal.pdsOrigin),
                            .text(journal.repositoryRevision), .text(journal.operationCID),
                            journal.signedOperationJSON.sqliteData!,
                            .text(journal.signingKey.reference),
                            .text(journal.rotationKey.reference),
                            journal.publicGenesisCommitCID.map { SQLiteData.text($0) } ?? .null,
                            .integer(journal.stage.rawValue),
                        ]
                    )
                } catch let error as PLCAccountPreparationStoreError {
                    throw error
                } catch {
                    throw PLCAccountPreparationStoreError.conflict
                }
                return journal
            }
        }
    }

    public func plcAccountPreparationJournal() async throws -> PLCAccountPreparationJournal? {
        try await withConnectionGate {
            try await loadJournalLocked()
        }
    }

    public func advancePLCAccountPreparationJournal(
        requestID: String,
        expectedStage: PLCAccountPreparationStage,
        to stage: PLCAccountPreparationStage,
        publicGenesisCommitCID: String?
    ) async throws -> PLCAccountPreparationJournal {
        guard stage > expectedStage else {
            throw PLCAccountPreparationStoreError.invalidTransition
        }
        return try await withConnectionGate {
            try await transaction {
                guard let existing = try await loadJournalLocked() else {
                    throw PLCAccountPreparationStoreError.notFound
                }
                guard existing.requestID == requestID else {
                    throw PLCAccountPreparationStoreError.conflict
                }
                if existing.stage == stage {
                    guard publicGenesisCommitCID == nil
                            || existing.publicGenesisCommitCID == publicGenesisCommitCID else {
                        throw PLCAccountPreparationStoreError.conflict
                    }
                    return existing
                }
                guard existing.stage == expectedStage else {
                    throw PLCAccountPreparationStoreError.conflict
                }
                let advanced = try existing.advancing(
                    to: stage,
                    publicGenesisCommitCID: publicGenesisCommitCID
                )
                _ = try await connection.query(
                    """
                    UPDATE plc_account_preparation_journal
                    SET stage = ?, public_genesis_commit_cid = ?
                    WHERE singleton = 1 AND request_id = ? AND stage = ?
                    """,
                    [
                        .integer(stage.rawValue),
                        advanced.publicGenesisCommitCID.map { SQLiteData.text($0) } ?? .null,
                        .text(requestID), .integer(expectedStage.rawValue),
                    ]
                )
                guard let stored = try await loadJournalLocked(), stored == advanced else {
                    throw PLCAccountPreparationStoreError.conflict
                }
                return stored
            }
        }
    }

    private func loadJournalLocked() async throws -> PLCAccountPreparationJournal? {
        let rows = try await connection.query(
            """
            SELECT request_id, did, canonical_handle, pds_origin,
                   repository_revision, operation_cid, signed_operation_json,
                   signing_key_reference, rotation_key_reference,
                   public_genesis_commit_cid, stage
            FROM plc_account_preparation_journal
            """
        )
        guard rows.count <= 1 else {
            throw PLCAccountPreparationStoreError.malformedRecord
        }
        guard let row = rows.first else { return nil }
        do {
            return try PLCAccountPreparationJournal(
                requestID: try requiredText(row, "request_id"),
                did: try requiredText(row, "did"),
                canonicalHandle: try requiredText(row, "canonical_handle"),
                pdsOrigin: try requiredText(row, "pds_origin"),
                repositoryRevision: try requiredText(row, "repository_revision"),
                operationCID: try requiredText(row, "operation_cid"),
                signedOperationJSON: try requiredBlob(row, "signed_operation_json"),
                signingKey: try AccountControlKeyReference(
                    purpose: .signing,
                    generation: 1,
                    reference: try requiredText(row, "signing_key_reference")
                ),
                rotationKey: try AccountControlKeyReference(
                    purpose: .rotation,
                    generation: 1,
                    reference: try requiredText(row, "rotation_key_reference")
                ),
                publicGenesisCommitCID: try optionalText(row, "public_genesis_commit_cid"),
                stage: try requiredStage(row)
            )
        } catch let error as PLCAccountPreparationStoreError {
            if error == .invalidInput { throw PLCAccountPreparationStoreError.malformedRecord }
            throw error
        } catch {
            throw PLCAccountPreparationStoreError.malformedRecord
        }
    }
}

/// Caches per-account actors for one preparation service lifetime. This opener
/// creates no account registry row and therefore cannot make a pending
/// identity reachable through normal authorization lookup.
public actor SQLitePLCAccountPreparationStoreOpener:
    PLCAccountPreparationAccountStoreOpener
{
    private let dataDirectory: URL
    private var databases: [String: SQLiteAccountDatabase] = [:]
    private var closed = false

    public init(dataDirectory: URL) {
        self.dataDirectory = dataDirectory
    }

    public func openPLCAccountPreparationStore(
        did: String
    ) async throws -> any PLCAccountPreparationAccountStore {
        guard !closed else { throw PLCAccountPreparationStoreError.unavailable }
        if let existing = databases[did] { return existing }
        do {
            let database = try await SQLiteAccountDatabase(
                dataDirectory: dataDirectory,
                did: did
            )
            databases[did] = database
            return database
        } catch {
            throw PLCAccountPreparationStoreError.unavailable
        }
    }

    public func close() async throws {
        guard !closed else { return }
        closed = true
        let values = Array(databases.values)
        databases.removeAll()
        for database in values {
            try await database.close()
        }
    }
}

private func requiredText(_ row: SQLiteRow, _ column: String) throws -> String {
    guard let value = row.column(column)?.string, !value.isEmpty else {
        throw PLCAccountPreparationStoreError.malformedRecord
    }
    return value
}

private func optionalText(_ row: SQLiteRow, _ column: String) throws -> String? {
    guard let value = row.column(column) else {
        throw PLCAccountPreparationStoreError.malformedRecord
    }
    if value.isNull { return nil }
    guard let string = value.string, !string.isEmpty else {
        throw PLCAccountPreparationStoreError.malformedRecord
    }
    return string
}

private func requiredBlob(_ row: SQLiteRow, _ column: String) throws -> Data {
    guard let value = row.column(column),
          case let .blob(blob) = value,
          blob.readableBytes > 0 else {
        throw PLCAccountPreparationStoreError.malformedRecord
    }
    return Data(buffer: blob)
}

private func requiredStage(_ row: SQLiteRow) throws -> PLCAccountPreparationStage {
    guard let raw = row.column("stage")?.integer,
          let stage = PLCAccountPreparationStage(rawValue: Int(raw)) else {
        throw PLCAccountPreparationStoreError.malformedRecord
    }
    return stage
}
