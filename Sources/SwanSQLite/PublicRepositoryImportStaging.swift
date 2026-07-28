import Crypto
import Foundation
import Petrel
import SQLiteNIO
import SwanPublicRepository
import SwanStorage

private struct SQLiteStagedCARFrameSink: PublicRepositoryCARFrameSink {
    let database: SQLiteAccountDatabase
    let sessionID: String
    let now: @Sendable () async -> Int64

    func receiveHeader(rootCID: CID, receivedByteCount: Int) async throws {
        try await database.stagePublicRepositoryCARHeader(
            sessionID: sessionID,
            rootCID: rootCID,
            receivedByteCount: receivedByteCount,
            now: await now()
        )
    }

    func receiveBlock(
        _ block: PublicRepositoryBlock,
        receivedByteCount: Int,
        frameCount: Int
    ) async throws {
        try await database.stagePublicRepositoryCARBlock(
            sessionID: sessionID,
            block: block,
            receivedByteCount: receivedByteCount,
            frameCount: frameCount,
            now: await now()
        )
    }
}

private struct SQLiteStagedPublicRepositoryBlockSource: PublicRepositoryBlockSource {
    let database: SQLiteAccountDatabase
    let sessionID: String
    let now: @Sendable () async -> Int64

    func block(for cid: CID) async throws -> Data? {
        try await database.stagedPublicRepositoryBlock(
            sessionID: sessionID, cid: cid, now: await now()
        )
    }
}

private struct SQLiteStagedPublicRepositoryProjectionSink: PublicRepositoryReachableProjectionSink {
    let database: SQLiteAccountDatabase
    let sessionID: String
    let now: @Sendable () async -> Int64

    func recordReachableBlock(
        cid: CID,
        kind: PublicRepositoryReachableBlockKind
    ) async throws {
        try await database.stagePublicRepositoryReachableBlock(
            sessionID: sessionID, cid: cid, kind: kind, now: await now()
        )
    }

    func recordRepositoryIndex(
        path: PublicRepositoryPath,
        recordCID: CID
    ) async throws {
        try await database.stagePublicRepositoryRecordIndex(
            sessionID: sessionID, path: path, recordCID: recordCID,
            now: await now()
        )
    }
}

private struct ExpiryCheckingCARByteSource: PublicRepositoryCARByteSource {
    let source: any PublicRepositoryCARByteSource
    let database: SQLiteAccountDatabase
    let sessionID: String
    let now: @Sendable () async -> Int64

    func read(maximumBytes: Int) async throws -> Data? {
        try await database.requireActivePublicRepositoryImportSession(
            id: sessionID, now: await now()
        )
        let bytes = try await source.read(maximumBytes: maximumBytes)
        try await database.requireActivePublicRepositoryImportSession(
            id: sessionID, now: await now()
        )
        return bytes
    }
}

public struct SQLitePublicRepositoryImportCoordinator: Sendable {
    private let database: SQLiteAccountDatabase
    private let beforePublish: (@Sendable () async throws -> Void)?
    private let now: @Sendable () async -> Int64

    public init(database: SQLiteAccountDatabase) {
        self.database = database
        beforePublish = nil
        now = { Int64(Date().timeIntervalSince1970) }
    }

    init(
        database: SQLiteAccountDatabase,
        beforePublish: (@Sendable () async throws -> Void)?,
        now: @escaping @Sendable () async -> Int64 = {
            Int64(Date().timeIntervalSince1970)
        }
    ) {
        self.database = database
        self.beforePublish = beforePublish
        self.now = now
    }

    /// Parses and verifies outside the publication transaction. The verifier
    /// may resolve account keys, but the final SQLite transaction receives
    /// only the already verified immutable result.
    public func importRepository(
        from source: any PublicRepositoryCARByteSource,
        binding: PublicRepositoryImportBinding,
        verifier: any PublicRepositoryCommitVerifier,
        createdAt: Int64,
        expiresAt: Int64
    ) async throws -> CommittedPublicRepositoryImport {
        guard verifier.verificationIdentity == binding.verifierIdentity else {
            throw PublicRepositoryImportStagingError.bindingMismatch
        }
        guard await now() < expiresAt else {
            throw PublicRepositoryImportStagingError.expiredSession
        }
        let outcome = try await database.createPublicRepositoryImportSession(
            binding: binding, createdAt: createdAt, expiresAt: expiresAt,
            now: await now()
        )
        switch outcome {
        case let .committed(result):
            return result
        case let .staged(session):
            do {
                let limits = try session.binding.policy.limits
                let parsed = try await PublicRepositoryCAR.parseIncrementally(
                    from: ExpiryCheckingCARByteSource(
                        source: source, database: database, sessionID: session.id,
                        now: now
                    ),
                    to: SQLiteStagedCARFrameSink(
                        database: database, sessionID: session.id, now: now
                    ),
                    limits: limits
                )
                try Task.checkCancellation()
                let commitBytes = try await database.requireStagedPublicRepositoryBlock(
                    sessionID: session.id, cid: parsed.rootCID, now: await now()
                )
                let verified: VerifiedPublicRepositorySignedCommit
                do {
                    verified = try await PublicRepositoryCommitCodec.verify(
                        signedCommitBytes: commitBytes,
                        expectedCommitCID: parsed.rootCID,
                        verifier: verifier
                    )
                } catch let error as PublicRepositoryCommitError {
                    throw PublicRepositoryCARError.commit(error)
                }
                guard verified.descriptor.did == binding.accountDID else {
                    throw PublicRepositoryImportStagingError.importedCommitMismatch
                }
                try await database.requireActivePublicRepositoryImportSession(
                    id: session.id, now: await now()
                )
                try await database.beginPublicRepositoryImportVerification(
                    sessionID: session.id,
                    rootCID: parsed.rootCID,
                    receivedByteCount: parsed.receivedByteCount,
                    frameCount: parsed.frameCount,
                    now: await now()
                )
                let stagedSource = SQLiteStagedPublicRepositoryBlockSource(
                    database: database, sessionID: session.id, now: now
                )
                let stagedProjection = SQLiteStagedPublicRepositoryProjectionSink(
                    database: database, sessionID: session.id, now: now
                )
                try await database.stagePublicRepositoryReachableCommit(
                    sessionID: session.id, cid: parsed.rootCID, now: await now()
                )
                let projection: ValidatedPublicRepositoryProjection
                do {
                    projection = try await RepositoryMSTValidation.validateProjection(
                        rootCID: verified.descriptor.dataCID,
                        blocks: stagedSource,
                        projection: stagedProjection,
                        limits: limits
                    )
                } catch let error as RepositoryMSTValidationError {
                    throw PublicRepositoryCARError.repository(error)
                }
                try Task.checkCancellation()
                try await database.finishPublicRepositoryImportVerification(
                    sessionID: session.id,
                    verified: verified,
                    projection: projection,
                    now: await now()
                )
                try Task.checkCancellation()
                try await beforePublish?()
                try Task.checkCancellation()
                try await database.requireActivePublicRepositoryImportSession(
                    id: session.id, now: await now()
                )
                return try await database.publishVerifiedPublicRepositoryImport(
                    sessionID: session.id,
                    verified: verified,
                    consumedAt: max(createdAt, await now()),
                    now: await now()
                )
            } catch {
                await database.poisonPublicRepositoryImportSession(id: session.id)
                try? await database.cleanupPublicRepositoryImportSession(id: session.id)
                throw error
            }
        }
    }
}

extension SQLiteAccountDatabase: PublicRepositoryImportStagingStore {
    public func createPublicRepositoryImportSession(
        binding: PublicRepositoryImportBinding,
        createdAt: Int64,
        expiresAt: Int64,
        now: Int64
    ) async throws -> PublicRepositoryImportStartOutcome {
        guard createdAt >= 0, now >= 0, expiresAt > createdAt else {
            throw PublicRepositoryImportStagingError.invalidTimestamp
        }
        guard now < expiresAt else {
            throw PublicRepositoryImportStagingError.expiredSession
        }
        guard binding.accountDID == accountDID else {
            throw PublicRepositoryImportStagingError.bindingMismatch
        }
        return try await withConnectionGate {
            try await transaction {
                if let result = try await loadCommittedImportResult(
                    requestID: binding.requestID,
                    expectedBinding: binding
                ) {
                    return .committed(result)
                }
                let rows = try await connection.query(
                    """
                    SELECT * FROM public_repository_import_sessions
                    WHERE request_id = ?
                    """,
                    [.text(binding.requestID)]
                )
                guard rows.count <= 1 else {
                    throw PublicRepositoryImportStagingError.corruptStaging
                }
                if let row = rows.first {
                    let session = try decodeImportSession(row)
                    guard session.binding == binding else {
                        throw PublicRepositoryImportStagingError.conflictingRequestReuse
                    }
                    switch session.status {
                    case .receiving:
                        guard session.expiresAt > now else {
                            throw PublicRepositoryImportStagingError.expiredSession
                        }
                        throw PublicRepositoryImportStagingError.importInProgress
                    case .consumed:
                        guard let result = try await loadCommittedImportResult(
                            requestID: binding.requestID,
                            expectedBinding: binding
                        ) else {
                            throw PublicRepositoryImportStagingError.corruptStaging
                        }
                        return .committed(result)
                    case .verifying, .verified, .poisoned:
                        throw PublicRepositoryImportStagingError.poisonedSession
                    }
                }
                let sessionID = UUID().uuidString.lowercased()
                let policy = binding.policy
                _ = try await connection.query(
                    """
                    INSERT INTO public_repository_import_sessions(
                        session_id, request_id, request_digest, account_did,
                        expected_base_commit_cid, verifier_identity,
                        maximum_record_block_bytes, maximum_car_bytes,
                        maximum_car_blocks, maximum_mst_nodes,
                        maximum_mst_entries_per_node, maximum_cbor_nesting_depth,
                        created_at, expires_at, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'receiving')
                    """,
                    [
                        .text(sessionID), .text(binding.requestID),
                        binding.requestDigest.sqliteData!, .text(binding.accountDID),
                        .text(binding.expectedBaseCommitCID.string),
                        .text(binding.verifierIdentity),
                        .integer(policy.maximumRecordBlockBytes),
                        .integer(policy.maximumCARBytes),
                        .integer(policy.maximumCARBlocks),
                        .integer(policy.maximumMSTNodes),
                        .integer(policy.maximumMSTEntriesPerNode),
                        .integer(policy.maximumCBORNestingDepth),
                        .integer(try Self.sqliteInteger(createdAt)),
                        .integer(try Self.sqliteInteger(expiresAt)),
                    ]
                )
                return .staged(PublicRepositoryImportStagingSession(
                    id: sessionID, binding: binding, createdAt: createdAt,
                    expiresAt: expiresAt, status: .receiving, rootCID: nil,
                    receivedByteCount: 0, frameCount: 0
                ))
            }
        }
    }

    public func publicRepositoryImportSession(
        id: String
    ) async throws -> PublicRepositoryImportStagingSession {
        try await withConnectionGate {
            let rows = try await connection.query(
                "SELECT * FROM public_repository_import_sessions WHERE session_id = ?",
                [.text(id)]
            )
            guard rows.count == 1, let row = rows.first else {
                throw PublicRepositoryImportStagingError.unknownSession
            }
            return try decodeImportSession(row)
        }
    }

    func requireActivePublicRepositoryImportSession(
        id: String,
        now: Int64
    ) async throws {
        guard now >= 0 else {
            throw PublicRepositoryImportStagingError.invalidTimestamp
        }
        try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT expires_at, status FROM public_repository_import_sessions
                WHERE session_id = ?
                """,
                [.text(id)]
            )
            guard rows.count == 1, let row = rows.first else {
                throw PublicRepositoryImportStagingError.unknownSession
            }
            guard try requiredInteger(row, "expires_at") > Int(now) else {
                throw PublicRepositoryImportStagingError.expiredSession
            }
            guard let status = row.column("status")?.string,
                  status == "receiving" || status == "verifying" || status == "verified"
            else {
                throw PublicRepositoryImportStagingError.poisonedSession
            }
        }
    }

    public func poisonPublicRepositoryImportSession(id: String) async {
        try? await withConnectionGate {
            _ = try await connection.query(
                """
                UPDATE public_repository_import_sessions SET status = 'poisoned'
                WHERE session_id = ? AND status != 'consumed'
                """,
                [.text(id)]
            )
        }
    }

    public func cleanupPublicRepositoryImportSession(id: String) async throws {
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    "DELETE FROM public_repository_import_reachable WHERE session_id = ?",
                    [.text(id)]
                )
                _ = try await connection.query(
                    "DELETE FROM public_repository_import_record_index WHERE session_id = ?",
                    [.text(id)]
                )
                _ = try await connection.query(
                    "DELETE FROM public_repository_import_blocks WHERE session_id = ?",
                    [.text(id)]
                )
                _ = try await connection.query(
                    """
                    DELETE FROM public_repository_import_sessions
                    WHERE session_id = ? AND status != 'consumed'
                    """,
                    [.text(id)]
                )
            }
        }
    }

    public func recoverExpiredPublicRepositoryImportSessions(now: Int64) async throws -> Int {
        guard now >= 0 else {
            throw PublicRepositoryImportStagingError.invalidTimestamp
        }
        return try await withConnectionGate {
            try await recoverExpiredPublicRepositoryImportSessionsWithoutGate(
                now: try Self.sqliteInteger(now)
            )
        }
    }

    func recoverExpiredPublicRepositoryImportSessionsWithoutGate(
        now: Int
    ) async throws -> Int {
        try await transaction {
            let rows = try await connection.query(
                """
                DELETE FROM public_repository_import_sessions
                WHERE status != 'consumed' AND expires_at <= ?
                RETURNING session_id
                """,
                [.integer(now)]
            )
            return rows.count
        }
    }

    func stagePublicRepositoryCARHeader(
        sessionID: String,
        rootCID: CID,
        receivedByteCount: Int,
        now: Int64
    ) async throws {
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    UPDATE public_repository_import_sessions
                    SET root_cid = COALESCE(root_cid, ?),
                        received_byte_count = ?
                    WHERE session_id = ? AND status = 'receiving'
                      AND expires_at > ?
                      AND (root_cid IS NULL OR root_cid = ?)
                      AND received_byte_count <= ?
                    RETURNING session_id
                    """,
                    [
                        .text(rootCID.string), .integer(receivedByteCount),
                        .text(sessionID), .integer(try Self.sqliteInteger(now)),
                        .text(rootCID.string),
                        .integer(receivedByteCount),
                    ]
                )
                guard rows.count == 1 else {
                    throw PublicRepositoryImportStagingError.headerConflict
                }
            }
        }
    }

    func stagePublicRepositoryCARBlock(
        sessionID: String,
        block: PublicRepositoryBlock,
        receivedByteCount: Int,
        frameCount: Int,
        now: Int64
    ) async throws {
        try await withConnectionGate {
            try await transaction {
                let existing = try await connection.query(
                    """
                    SELECT bytes FROM public_repository_import_blocks
                    WHERE session_id = ? AND cid = ?
                    """,
                    [.text(sessionID), .text(block.cid.string)]
                )
                if let row = existing.first {
                    guard let value = row.column("bytes"),
                          Data(sqliteData: value) == block.bytes else {
                        throw PublicRepositoryImportStagingError.duplicateBlockConflict
                    }
                } else {
                    _ = try await connection.query(
                        """
                        INSERT INTO public_repository_import_blocks(session_id, cid, bytes)
                        VALUES (?, ?, ?)
                        """,
                        [.text(sessionID), .text(block.cid.string), block.bytes.sqliteData!]
                    )
                }
                let updated = try await connection.query(
                    """
                    UPDATE public_repository_import_sessions
                    SET received_byte_count = ?, frame_count = ?
                    WHERE session_id = ? AND status = 'receiving'
                      AND expires_at > ?
                      AND received_byte_count <= ? AND frame_count < ?
                    RETURNING session_id
                    """,
                    [
                        .integer(receivedByteCount), .integer(frameCount),
                        .text(sessionID), .integer(try Self.sqliteInteger(now)),
                        .integer(receivedByteCount),
                        .integer(frameCount),
                    ]
                )
                guard updated.count == 1 else {
                    throw PublicRepositoryImportStagingError.corruptStaging
                }
            }
        }
    }

    func stagedPublicRepositoryBlock(
        sessionID: String,
        cid: CID,
        now: Int64
    ) async throws -> Data? {
        try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT b.bytes
                FROM public_repository_import_blocks b
                JOIN public_repository_import_sessions s
                  ON s.session_id = b.session_id
                WHERE b.session_id = ? AND b.cid = ?
                  AND s.status IN ('verifying', 'verified')
                  AND s.expires_at > ?
                """,
                [.text(sessionID), .text(cid.string), .integer(try Self.sqliteInteger(now))]
            )
            guard rows.count <= 1 else {
                throw PublicRepositoryImportStagingError.corruptStaging
            }
            guard let value = rows.first?.column("bytes"),
                  let bytes = Data(sqliteData: value) else { return nil }
            do {
                try PublicRepositoryCID.validate(cid, blockBytes: bytes)
            } catch {
                throw PublicRepositoryImportStagingError.corruptStaging
            }
            return bytes
        }
    }

    func requireStagedPublicRepositoryBlock(
        sessionID: String,
        cid: CID,
        now: Int64
    ) async throws -> Data {
        // Commit lookup occurs before the session enters verifying.
        try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT b.bytes FROM public_repository_import_blocks b
                JOIN public_repository_import_sessions s
                  ON s.session_id = b.session_id
                WHERE b.session_id = ? AND b.cid = ? AND s.status = 'receiving'
                  AND s.expires_at > ?
                """,
                [.text(sessionID), .text(cid.string), .integer(try Self.sqliteInteger(now))]
            )
            guard rows.count == 1, let value = rows.first?.column("bytes"),
                  let bytes = Data(sqliteData: value) else {
                throw PublicRepositoryCARError.missingCommit
            }
            return bytes
        }
    }

    func beginPublicRepositoryImportVerification(
        sessionID: String,
        rootCID: CID,
        receivedByteCount: Int,
        frameCount: Int,
        now: Int64
    ) async throws {
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    "DELETE FROM public_repository_import_reachable WHERE session_id = ?",
                    [.text(sessionID)]
                )
                _ = try await connection.query(
                    "DELETE FROM public_repository_import_record_index WHERE session_id = ?",
                    [.text(sessionID)]
                )
                let rows = try await connection.query(
                    """
                    UPDATE public_repository_import_sessions
                    SET status = 'verifying'
                    WHERE session_id = ? AND status = 'receiving'
                      AND expires_at > ?
                      AND root_cid = ? AND received_byte_count = ? AND frame_count = ?
                    RETURNING session_id
                    """,
                    [
                        .text(sessionID), .integer(try Self.sqliteInteger(now)),
                        .text(rootCID.string),
                        .integer(receivedByteCount), .integer(frameCount),
                    ]
                )
                guard rows.count == 1 else {
                    throw PublicRepositoryImportStagingError.corruptStaging
                }
            }
        }
    }

    func stagePublicRepositoryReachableCommit(
        sessionID: String, cid: CID, now: Int64
    ) async throws {
        try await stageReachable(sessionID: sessionID, cid: cid, kind: "commit", now: now)
    }

    func stagePublicRepositoryReachableBlock(
        sessionID: String,
        cid: CID,
        kind: PublicRepositoryReachableBlockKind,
        now: Int64
    ) async throws {
        try await stageReachable(
            sessionID: sessionID, cid: cid, kind: kind.rawValue, now: now
        )
    }

    private func stageReachable(
        sessionID: String,
        cid: CID,
        kind: String,
        now: Int64
    ) async throws {
        try await withConnectionGate {
            let rows = try await connection.query(
                """
                INSERT INTO public_repository_import_reachable(session_id, cid, kind)
                SELECT ?, ?, ? WHERE EXISTS (
                    SELECT 1 FROM public_repository_import_sessions
                    WHERE session_id = ? AND status = 'verifying'
                      AND expires_at > ?
                )
                ON CONFLICT(session_id, cid) DO UPDATE SET kind = excluded.kind
                RETURNING cid
                """,
                [
                    .text(sessionID), .text(cid.string), .text(kind), .text(sessionID),
                    .integer(try Self.sqliteInteger(now)),
                ]
            )
            guard rows.count == 1 else {
                throw PublicRepositoryImportStagingError.verificationRequired
            }
        }
    }

    func stagePublicRepositoryRecordIndex(
        sessionID: String,
        path: PublicRepositoryPath,
        recordCID: CID,
        now: Int64
    ) async throws {
        try await withConnectionGate {
            let rows = try await connection.query(
                """
                INSERT INTO public_repository_import_record_index(
                    session_id, collection, rkey, record_cid
                )
                SELECT ?, ?, ?, ? WHERE EXISTS (
                    SELECT 1 FROM public_repository_import_sessions
                    WHERE session_id = ? AND status = 'verifying'
                      AND expires_at > ?
                )
                ON CONFLICT(session_id, collection, rkey)
                DO UPDATE SET record_cid = excluded.record_cid
                RETURNING record_cid
                """,
                [
                    .text(sessionID), .text(path.collection),
                    .text(path.recordKey), .text(recordCID.string),
                    .text(sessionID), .integer(try Self.sqliteInteger(now)),
                ]
            )
            guard rows.count == 1 else {
                throw PublicRepositoryImportStagingError.verificationRequired
            }
        }
    }

    func finishPublicRepositoryImportVerification(
        sessionID: String,
        verified: VerifiedPublicRepositorySignedCommit,
        projection: ValidatedPublicRepositoryProjection,
        now: Int64
    ) async throws {
        try await withConnectionGate {
            try await transaction {
                let reachableRows = try await connection.query(
                    """
                    SELECT cid, kind FROM public_repository_import_reachable
                    WHERE session_id = ? AND EXISTS (
                        SELECT 1 FROM public_repository_import_sessions
                        WHERE session_id = ? AND expires_at > ?
                    ) ORDER BY kind, cid
                    """,
                    [
                        .text(sessionID), .text(sessionID),
                        .integer(try Self.sqliteInteger(now)),
                    ]
                )
                let indexRows = try await connection.query(
                    """
                    SELECT collection, rkey, record_cid
                    FROM public_repository_import_record_index
                    WHERE session_id = ? ORDER BY collection, rkey, record_cid
                    """,
                    [.text(sessionID)]
                )
                let commitCount = reachableRows.count(where: {
                    requiredText($0, "kind") == "commit"
                })
                let mstCount = reachableRows.count(where: {
                    requiredText($0, "kind") == "mst"
                })
                let recordBlockCount = reachableRows.count(where: {
                    requiredText($0, "kind") == "record"
                })
                guard commitCount == 1,
                      reachableRows.contains(where: {
                          requiredText($0, "kind") == "commit"
                              && requiredText($0, "cid") == verified.commitCID.string
                      }),
                      mstCount == projection.mstBlockCount,
                      recordBlockCount == projection.recordBlockCount,
                      indexRows.count == projection.recordCount,
                      reachableRows.count
                        == projection.mstBlockCount + projection.recordBlockCount + 1
                else {
                    throw PublicRepositoryImportStagingError.corruptStaging
                }
                let projectionDigest = Self.verifiedProjectionDigest(
                    verified: verified,
                    reachableRows: reachableRows,
                    indexRows: indexRows
                )
                let rows = try await connection.query(
                    """
                    UPDATE public_repository_import_sessions
                    SET status = 'verified', verified_commit_cid = ?,
                        verified_data_cid = ?, verified_revision = ?,
                        reachable_block_count = ?, record_count = ?,
                        commit_block_count = ?, mst_block_count = ?,
                        record_block_count = ?, index_count = ?,
                        verified_projection_digest = ?
                    WHERE session_id = ? AND status = 'verifying' AND root_cid = ?
                    RETURNING session_id
                    """,
                    [
                        .text(verified.commitCID.string),
                        .text(verified.descriptor.dataCID.string),
                        .text(verified.descriptor.revision.value),
                        .integer(reachableRows.count), .integer(projection.recordCount),
                        .integer(commitCount), .integer(mstCount),
                        .integer(recordBlockCount), .integer(indexRows.count),
                        projectionDigest.sqliteData!,
                        .text(sessionID), .text(verified.commitCID.string),
                    ]
                )
                guard rows.count == 1 else {
                    throw PublicRepositoryImportStagingError.corruptStaging
                }
            }
        }
    }

    func publishVerifiedPublicRepositoryImport(
        sessionID: String,
        verified: VerifiedPublicRepositorySignedCommit,
        consumedAt: Int64,
        now: Int64
    ) async throws -> CommittedPublicRepositoryImport {
        try await withConnectionGate {
            try await transaction {
                let sessionRows = try await connection.query(
                    "SELECT * FROM public_repository_import_sessions WHERE session_id = ?",
                    [.text(sessionID)]
                )
                guard sessionRows.count == 1, let sessionRow = sessionRows.first else {
                    throw PublicRepositoryImportStagingError.unknownSession
                }
                let session = try decodeImportSession(sessionRow)
                guard session.expiresAt > now else {
                    throw PublicRepositoryImportStagingError.expiredSession
                }
                guard session.status == .verified,
                      session.rootCID == verified.commitCID,
                      session.binding.accountDID == accountDID,
                      requiredText(sessionRow, "verified_commit_cid") == verified.commitCID.string,
                      requiredText(sessionRow, "verified_data_cid") == verified.descriptor.dataCID.string,
                      requiredText(sessionRow, "verified_revision") == verified.descriptor.revision.value
                else {
                    throw PublicRepositoryImportStagingError.importedCommitMismatch
                }
                let reachableRows = try await connection.query(
                    """
                    SELECT cid, kind FROM public_repository_import_reachable
                    WHERE session_id = ? ORDER BY kind, cid
                    """,
                    [.text(sessionID)]
                )
                let indexRows = try await connection.query(
                    """
                    SELECT collection, rkey, record_cid
                    FROM public_repository_import_record_index
                    WHERE session_id = ? ORDER BY collection, rkey, record_cid
                    """,
                    [.text(sessionID)]
                )
                let commitCount = reachableRows.count(where: {
                    requiredText($0, "kind") == "commit"
                })
                let mstCount = reachableRows.count(where: {
                    requiredText($0, "kind") == "mst"
                })
                let recordBlockCount = reachableRows.count(where: {
                    requiredText($0, "kind") == "record"
                })
                guard try requiredInteger(sessionRow, "reachable_block_count")
                        == reachableRows.count,
                      try requiredInteger(sessionRow, "record_count") == indexRows.count,
                      try requiredInteger(sessionRow, "commit_block_count") == commitCount,
                      try requiredInteger(sessionRow, "mst_block_count") == mstCount,
                      try requiredInteger(sessionRow, "record_block_count")
                        == recordBlockCount,
                      try requiredInteger(sessionRow, "index_count") == indexRows.count,
                      commitCount == 1,
                      reachableRows.contains(where: {
                          requiredText($0, "kind") == "commit"
                              && requiredText($0, "cid") == verified.commitCID.string
                      }),
                      requiredData(sessionRow, "verified_projection_digest")
                        == Self.verifiedProjectionDigest(
                            verified: verified,
                            reachableRows: reachableRows,
                            indexRows: indexRows
                        )
                else {
                    throw PublicRepositoryImportStagingError.corruptStaging
                }
                let stagedCommitRows = try await connection.query(
                    """
                    SELECT bytes FROM public_repository_import_blocks
                    WHERE session_id = ? AND cid = ?
                    """,
                    [.text(sessionID), .text(verified.commitCID.string)]
                )
                guard stagedCommitRows.count == 1,
                      let commitValue = stagedCommitRows.first?.column("bytes"),
                      Data(sqliteData: commitValue) == verified.signedCommitBytes else {
                    throw PublicRepositoryImportStagingError.corruptStaging
                }
                for row in reachableRows {
                    let cid = try parseImportCID(requiredText(row, "cid"))
                    let bodyRows = try await connection.query(
                        """
                        SELECT bytes FROM public_repository_import_blocks
                        WHERE session_id = ? AND cid = ?
                        """,
                        [.text(sessionID), .text(cid.string)]
                    )
                    guard bodyRows.count == 1,
                          let bodyValue = bodyRows.first?.column("bytes"),
                          let body = Data(sqliteData: bodyValue) else {
                        throw PublicRepositoryImportStagingError.corruptStaging
                    }
                    do {
                        try PublicRepositoryCID.validate(cid, blockBytes: body)
                    } catch {
                        throw PublicRepositoryImportStagingError.corruptStaging
                    }
                }
                guard let current = try await loadPublicRepositoryStateWithoutGate() else {
                    throw PublicRepositoryImportStagingError.repositoryNotInstalled
                }
                guard current.did == accountDID,
                      current.commitCID == session.binding.expectedBaseCommitCID else {
                    throw PublicRepositoryImportStagingError.commitCASConflict
                }
                let currentRevision = try PublicRepositoryTID(current.revision)
                guard currentRevision < verified.descriptor.revision,
                      verified.descriptor.did == accountDID else {
                    throw PublicRepositoryImportStagingError.importedCommitMismatch
                }

                _ = try await connection.query(
                    """
                    INSERT INTO public_repository_blocks(cid, bytes)
                    SELECT r.cid, b.bytes
                    FROM public_repository_import_reachable r
                    JOIN public_repository_import_blocks b
                      ON b.session_id = r.session_id AND b.cid = r.cid
                    WHERE r.session_id = ?
                    ON CONFLICT(cid) DO NOTHING
                    """,
                    [.text(sessionID)]
                )
                let conflicts = try await connection.query(
                    """
                    SELECT r.cid
                    FROM public_repository_import_reachable r
                    JOIN public_repository_import_blocks b
                      ON b.session_id = r.session_id AND b.cid = r.cid
                    JOIN public_repository_blocks l ON l.cid = r.cid
                    WHERE r.session_id = ? AND l.bytes != b.bytes LIMIT 1
                    """,
                    [.text(sessionID)]
                )
                guard conflicts.isEmpty else {
                    throw PublicRepositoryImportStagingError.corruptRepository
                }
                _ = try await connection.query("DELETE FROM public_repository_record_index")
                let installedIndex = try await connection.query(
                    """
                    INSERT INTO public_repository_record_index(collection, rkey, record_cid)
                    SELECT collection, rkey, record_cid
                    FROM public_repository_import_record_index
                    WHERE session_id = ?
                    RETURNING collection
                    """,
                    [.text(sessionID)]
                )
                guard installedIndex.count == indexRows.count else {
                    throw PublicRepositoryImportStagingError.corruptStaging
                }
                let advanced = try await connection.query(
                    """
                    UPDATE public_repository_state
                    SET revision = ?, commit_cid = ?, data_cid = ?
                    WHERE singleton = 1 AND did = ? AND commit_cid = ? AND revision = ?
                    RETURNING singleton
                    """,
                    [
                        .text(verified.descriptor.revision.value),
                        .text(verified.commitCID.string),
                        .text(verified.descriptor.dataCID.string),
                        .text(accountDID), .text(current.commitCID.string),
                        .text(current.revision),
                    ]
                )
                guard advanced.count == 1 else {
                    throw PublicRepositoryImportStagingError.commitCASConflict
                }
                let reachableCount = try requiredInteger(sessionRow, "reachable_block_count")
                let recordCount = try requiredInteger(sessionRow, "record_count")
                let integrityDigest = Self.importResultIntegrityDigest(
                    binding: session.binding,
                    revision: verified.descriptor.revision.value,
                    commitCID: verified.commitCID.string,
                    dataCID: verified.descriptor.dataCID.string,
                    reachableBlockCount: reachableCount,
                    recordCount: recordCount,
                    consumedAt: consumedAt
                )
                let policy = session.binding.policy
                let insertedResult = try await connection.query(
                    """
                    INSERT INTO public_repository_import_results(
                        request_id, request_digest, account_did,
                        expected_base_commit_cid, verifier_identity,
                        maximum_record_block_bytes, maximum_car_bytes,
                        maximum_car_blocks, maximum_mst_nodes,
                        maximum_mst_entries_per_node, maximum_cbor_nesting_depth,
                        revision,
                        commit_cid, data_cid, reachable_block_count, record_count,
                        consumed_at, integrity_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    RETURNING request_id
                    """,
                    [
                        .text(session.binding.requestID),
                        session.binding.requestDigest.sqliteData!,
                        .text(accountDID),
                        .text(session.binding.expectedBaseCommitCID.string),
                        .text(session.binding.verifierIdentity),
                        .integer(policy.maximumRecordBlockBytes),
                        .integer(policy.maximumCARBytes),
                        .integer(policy.maximumCARBlocks),
                        .integer(policy.maximumMSTNodes),
                        .integer(policy.maximumMSTEntriesPerNode),
                        .integer(policy.maximumCBORNestingDepth),
                        .text(verified.descriptor.revision.value),
                        .text(verified.commitCID.string),
                        .text(verified.descriptor.dataCID.string),
                        .integer(reachableCount), .integer(recordCount),
                        .integer(try Self.sqliteInteger(consumedAt)),
                        integrityDigest.sqliteData!,
                    ]
                )
                guard insertedResult.count == 1 else {
                    throw PublicRepositoryImportStagingError.corruptStaging
                }
                let stagedBlockCountRows = try await connection.query(
                    """
                    SELECT COUNT(*) AS count FROM public_repository_import_blocks
                    WHERE session_id = ?
                    """,
                    [.text(sessionID)]
                )
                guard stagedBlockCountRows.count == 1,
                      let stagedBlockCountRow = stagedBlockCountRows.first else {
                    throw PublicRepositoryImportStagingError.corruptStaging
                }
                let stagedBlockCount = try requiredInteger(
                    stagedBlockCountRow, "count"
                )
                let deletedReachable = try await connection.query(
                    """
                    DELETE FROM public_repository_import_reachable
                    WHERE session_id = ? RETURNING cid
                    """,
                    [.text(sessionID)]
                )
                guard deletedReachable.count == reachableRows.count else {
                    throw PublicRepositoryImportStagingError.corruptStaging
                }
                let deletedIndex = try await connection.query(
                    """
                    DELETE FROM public_repository_import_record_index
                    WHERE session_id = ? RETURNING collection
                    """,
                    [.text(sessionID)]
                )
                guard deletedIndex.count == indexRows.count else {
                    throw PublicRepositoryImportStagingError.corruptStaging
                }
                let deletedBlocks = try await connection.query(
                    """
                    DELETE FROM public_repository_import_blocks
                    WHERE session_id = ? RETURNING cid
                    """,
                    [.text(sessionID)]
                )
                guard deletedBlocks.count == stagedBlockCount else {
                    throw PublicRepositoryImportStagingError.corruptStaging
                }
                let deletedSession = try await connection.query(
                    """
                    DELETE FROM public_repository_import_sessions
                    WHERE session_id = ? AND status = 'verified'
                    RETURNING session_id
                    """,
                    [.text(sessionID)]
                )
                guard deletedSession.count == 1 else {
                    throw PublicRepositoryImportStagingError.corruptStaging
                }
                return CommittedPublicRepositoryImport(
                    requestID: session.binding.requestID,
                    requestDigest: session.binding.requestDigest,
                    verifierIdentity: session.binding.verifierIdentity,
                    state: try PublicRepositoryState(
                        did: accountDID,
                        revision: verified.descriptor.revision.value,
                        commitCID: verified.commitCID,
                        dataCID: verified.descriptor.dataCID
                    ),
                    reachableBlockCount: reachableCount,
                    recordCount: recordCount
                )
            }
        }
    }

    private func loadCommittedImportResult(
        requestID: String,
        expectedBinding: PublicRepositoryImportBinding
    ) async throws -> CommittedPublicRepositoryImport? {
        do {
            return try await loadCommittedImportResultUnchecked(
                requestID: requestID,
                expectedBinding: expectedBinding
            )
        } catch let error as PublicRepositoryImportStagingError {
            throw error
        } catch {
            throw PublicRepositoryImportStagingError.corruptStaging
        }
    }

    private func loadCommittedImportResultUnchecked(
        requestID: String,
        expectedBinding: PublicRepositoryImportBinding
    ) async throws -> CommittedPublicRepositoryImport? {
        let rows = try await connection.query(
            "SELECT * FROM public_repository_import_results WHERE request_id = ?",
            [.text(requestID)]
        )
        guard rows.count <= 1 else {
            throw PublicRepositoryImportStagingError.corruptStaging
        }
        guard let row = rows.first else { return nil }
        guard requiredData(row, "request_digest") == expectedBinding.requestDigest,
              requiredText(row, "account_did") == expectedBinding.accountDID,
              requiredText(row, "expected_base_commit_cid")
                == expectedBinding.expectedBaseCommitCID.string,
              requiredText(row, "verifier_identity") == expectedBinding.verifierIdentity,
              try resultPolicy(row) == expectedBinding.policy
        else {
            throw PublicRepositoryImportStagingError.conflictingRequestReuse
        }
        let revision = requiredText(row, "revision")
        let commitCID = try parseImportCID(requiredText(row, "commit_cid"))
        let dataCID = try parseImportCID(requiredText(row, "data_cid"))
        let reachableBlockCount = try requiredInteger(row, "reachable_block_count")
        let recordCount = try requiredInteger(row, "record_count")
        let consumedAt = try requiredInteger(row, "consumed_at")
        let expectedIntegrity = Self.importResultIntegrityDigest(
            binding: expectedBinding,
            revision: revision,
            commitCID: commitCID.string,
            dataCID: dataCID.string,
            reachableBlockCount: reachableBlockCount,
            recordCount: recordCount,
            consumedAt: Int64(consumedAt)
        )
        guard requiredData(row, "integrity_digest") == expectedIntegrity else {
            throw PublicRepositoryImportStagingError.corruptStaging
        }
        let commitRows = try await connection.query(
            "SELECT bytes FROM public_repository_blocks WHERE cid = ?",
            [.text(commitCID.string)]
        )
        let dataRows = try await connection.query(
            "SELECT bytes FROM public_repository_blocks WHERE cid = ?",
            [.text(dataCID.string)]
        )
        guard commitRows.count == 1, dataRows.count == 1,
              let commitValue = commitRows.first?.column("bytes"),
              let commitBytes = Data(sqliteData: commitValue),
              let dataValue = dataRows.first?.column("bytes"),
              let dataBytes = Data(sqliteData: dataValue) else {
            throw PublicRepositoryImportStagingError.corruptRepository
        }
        do {
            let structural = try PublicRepositoryCommitCodec.structurallyValidate(
                signedCommitBytes: commitBytes, expectedCommitCID: commitCID
            )
            guard structural.descriptor.did == expectedBinding.accountDID,
                  structural.descriptor.revision.value == revision,
                  structural.descriptor.dataCID == dataCID else {
                throw PublicRepositoryImportStagingError.corruptRepository
            }
            try PublicRepositoryCID.validate(dataCID, blockBytes: dataBytes)
            let repository = try await RepositoryMSTValidation.validate(
                rootCID: dataCID,
                blocks: SQLitePublicRepositoryBlockSource(connection: connection),
                limits: try expectedBinding.policy.limits
            )
            guard repository.leaves.count == recordCount,
                  repository.reachableMSTBlocks.count
                    + repository.reachableRecordCIDs.count + 1 == reachableBlockCount
            else {
                throw PublicRepositoryImportStagingError.corruptRepository
            }
        } catch let error as PublicRepositoryImportStagingError {
            throw error
        } catch {
            throw PublicRepositoryImportStagingError.corruptRepository
        }
        return CommittedPublicRepositoryImport(
            requestID: requestID,
            requestDigest: expectedBinding.requestDigest,
            verifierIdentity: expectedBinding.verifierIdentity,
            state: try PublicRepositoryState(
                did: expectedBinding.accountDID,
                revision: revision,
                commitCID: commitCID,
                dataCID: dataCID
            ),
            reachableBlockCount: reachableBlockCount,
            recordCount: recordCount
        )
    }

    private func decodeImportSession(
        _ row: SQLiteRow
    ) throws -> PublicRepositoryImportStagingSession {
        do {
            return try decodeImportSessionUnchecked(row)
        } catch let error as PublicRepositoryImportStagingError {
            throw error
        } catch {
            throw PublicRepositoryImportStagingError.corruptStaging
        }
    }

    private func decodeImportSessionUnchecked(
        _ row: SQLiteRow
    ) throws -> PublicRepositoryImportStagingSession {
        let policy = PublicRepositoryImportPolicy(
            limits: try PublicRepositoryLimits(
                maximumRecordBlockBytes: requiredInteger(row, "maximum_record_block_bytes"),
                maximumCARBytes: requiredInteger(row, "maximum_car_bytes"),
                maximumCARBlocks: requiredInteger(row, "maximum_car_blocks"),
                maximumMSTNodes: requiredInteger(row, "maximum_mst_nodes"),
                maximumMSTEntriesPerNode: requiredInteger(row, "maximum_mst_entries_per_node"),
                maximumCBORNestingDepth: requiredInteger(row, "maximum_cbor_nesting_depth")
            )
        )
        let binding = try PublicRepositoryImportBinding(
            requestID: requiredText(row, "request_id"),
            requestDigest: requiredData(row, "request_digest"),
            accountDID: requiredText(row, "account_did"),
            expectedBaseCommitCID: try parseImportCID(
                requiredText(row, "expected_base_commit_cid")
            ),
            verifierIdentity: requiredText(row, "verifier_identity"),
            policy: policy
        )
        guard let status = PublicRepositoryImportStagingStatus(
            rawValue: requiredText(row, "status")
        ) else {
            throw PublicRepositoryImportStagingError.corruptStaging
        }
        let root: CID?
        if let value = row.column("root_cid"), case let .text(text) = value {
            root = try parseImportCID(text)
        } else {
            root = nil
        }
        return PublicRepositoryImportStagingSession(
            id: requiredText(row, "session_id"),
            binding: binding,
            createdAt: Int64(try requiredInteger(row, "created_at")),
            expiresAt: Int64(try requiredInteger(row, "expires_at")),
            status: status,
            rootCID: root,
            receivedByteCount: try requiredInteger(row, "received_byte_count"),
            frameCount: try requiredInteger(row, "frame_count")
        )
    }

    private func parseImportCID(_ value: String) throws -> CID {
        guard let cid = try? CID.parse(value) else {
            throw PublicRepositoryImportStagingError.corruptStaging
        }
        do {
            try PublicRepositoryCID.validate(cid)
            return cid
        } catch {
            throw PublicRepositoryImportStagingError.corruptStaging
        }
    }

    private func requiredText(_ row: SQLiteRow, _ name: String) -> String {
        guard case let .text(value)? = row.column(name) else { return "" }
        return value
    }

    private func requiredData(_ row: SQLiteRow, _ name: String) -> Data {
        guard let value = row.column(name), let data = Data(sqliteData: value) else {
            return Data()
        }
        return data
    }

    private func requiredInteger(_ row: SQLiteRow, _ name: String) throws -> Int {
        guard case let .integer(value)? = row.column(name),
              let result = Int(exactly: value) else {
            throw PublicRepositoryImportStagingError.corruptStaging
        }
        return result
    }

    private func resultPolicy(_ row: SQLiteRow) throws -> PublicRepositoryImportPolicy {
        PublicRepositoryImportPolicy(limits: try PublicRepositoryLimits(
            maximumRecordBlockBytes: requiredInteger(row, "maximum_record_block_bytes"),
            maximumCARBytes: requiredInteger(row, "maximum_car_bytes"),
            maximumCARBlocks: requiredInteger(row, "maximum_car_blocks"),
            maximumMSTNodes: requiredInteger(row, "maximum_mst_nodes"),
            maximumMSTEntriesPerNode: requiredInteger(row, "maximum_mst_entries_per_node"),
            maximumCBORNestingDepth: requiredInteger(row, "maximum_cbor_nesting_depth")
        ))
    }

    private static func importResultIntegrityDigest(
        binding: PublicRepositoryImportBinding,
        revision: String,
        commitCID: String,
        dataCID: String,
        reachableBlockCount: Int,
        recordCount: Int,
        consumedAt: Int64
    ) -> Data {
        var encoded = Data("swan.public-repository.import-result.v1".utf8)
        func append(_ value: Data) {
            var length = UInt64(value.count).bigEndian
            withUnsafeBytes(of: &length) { encoded.append(contentsOf: $0) }
            encoded.append(value)
        }
        func append(_ value: String) { append(Data(value.utf8)) }
        func append(_ value: Int64) {
            var fixed = UInt64(bitPattern: value).bigEndian
            withUnsafeBytes(of: &fixed) { encoded.append(contentsOf: $0) }
        }
        append(binding.requestID)
        append(binding.requestDigest)
        append(binding.accountDID)
        append(binding.expectedBaseCommitCID.string)
        append(binding.verifierIdentity)
        let policy = binding.policy
        append(Int64(policy.maximumRecordBlockBytes))
        append(Int64(policy.maximumCARBytes))
        append(Int64(policy.maximumCARBlocks))
        append(Int64(policy.maximumMSTNodes))
        append(Int64(policy.maximumMSTEntriesPerNode))
        append(Int64(policy.maximumCBORNestingDepth))
        append(revision)
        append(commitCID)
        append(dataCID)
        append(Int64(reachableBlockCount))
        append(Int64(recordCount))
        append(consumedAt)
        return Data(SHA256.hash(data: encoded))
    }

    private static func verifiedProjectionDigest(
        verified: VerifiedPublicRepositorySignedCommit,
        reachableRows: [SQLiteRow],
        indexRows: [SQLiteRow]
    ) -> Data {
        var encoded = Data("swan.public-repository.verified-projection.v1".utf8)
        func append(_ value: String) {
            let bytes = Data(value.utf8)
            var length = UInt64(bytes.count).bigEndian
            withUnsafeBytes(of: &length) { encoded.append(contentsOf: $0) }
            encoded.append(bytes)
        }
        append(verified.commitCID.string)
        append(verified.descriptor.dataCID.string)
        append(verified.descriptor.revision.value)
        for row in reachableRows {
            append(row.column("kind")?.string ?? "")
            append(row.column("cid")?.string ?? "")
        }
        for row in indexRows {
            append(row.column("collection")?.string ?? "")
            append(row.column("rkey")?.string ?? "")
            append(row.column("record_cid")?.string ?? "")
        }
        return Data(SHA256.hash(data: encoded))
    }

    private static func sqliteInteger(_ value: Int64) throws -> Int {
        guard let result = Int(exactly: value) else {
            throw PublicRepositoryImportStagingError.invalidTimestamp
        }
        return result
    }
}
