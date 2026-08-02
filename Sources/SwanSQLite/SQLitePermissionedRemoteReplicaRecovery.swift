import Crypto
import Foundation
import Petrel
import SQLiteNIO
import SwanSpaces
import SwanStorage

/// One durable staging object serves as both the DRISL scratch index and the
/// bounded record sink. It contains only a database actor and a session ID;
/// no repository-wide values are retained in process memory.
public struct SQLitePermissionedRemoteReplicaRecoveryStaging:
    SpaceCARRecoveryIndex, SpaceCARRecoveryRecordSink, Sendable
{
    private let database: SQLiteAccountDatabase
    private let sessionID: String
    private let now: @Sendable () -> Int64

    public init(
        database: SQLiteAccountDatabase,
        sessionID: String,
        now: @escaping @Sendable () -> Int64 = {
            Int64(Date().timeIntervalSince1970)
        }
    ) {
        self.database = database
        self.sessionID = sessionID
        self.now = now
    }

    public func receiveRoots(commit: CID, index: CID) async throws {
        try await database.stagePermissionedRemoteReplicaRoots(
            sessionID: sessionID,
            commit: commit,
            index: index,
            now: now()
        )
    }

    public func receiveCommit(cid: CID, body: Data) async throws {
        try await database.stagePermissionedRemoteReplicaCommit(
            sessionID: sessionID,
            cid: cid,
            body: body,
            now: now()
        )
    }

    public func insert(_ entry: SpaceCARRecoveryIndexEntry) async throws {
        try await database.stagePermissionedRemoteReplicaIndexEntry(
            sessionID: sessionID,
            entry: entry,
            now: now()
        )
    }

    public func nextUnconsumedLexicographicEntry() async throws
        -> SpaceCARRecoveryIndexEntry?
    {
        try await database
            .nextUnconsumedPermissionedRemoteReplicaIndexEntry(
                sessionID: sessionID,
                now: now()
            )
    }

    public func consumeEntries(forCID cid: CID) async throws -> Int {
        try await database.consumePermissionedRemoteReplicaIndexEntries(
            sessionID: sessionID,
            cid: cid,
            now: now()
        )
    }

    public func beginRecord(cid: CID, byteCount: Int) async throws {
        try await database.beginPermissionedRemoteReplicaRecord(
            sessionID: sessionID,
            cid: cid,
            byteCount: byteCount,
            now: now()
        )
    }

    public func appendRecordChunk(
        cid: CID,
        chunkIndex: Int,
        bytes: Data
    ) async throws {
        try await database.appendPermissionedRemoteReplicaRecordChunk(
            sessionID: sessionID,
            cid: cid,
            chunkIndex: chunkIndex,
            bytes: bytes,
            now: now()
        )
    }

    public func completeRecord(
        cid: CID,
        byteCount: Int,
        chunkCount: Int
    ) async throws {
        try await database.completePermissionedRemoteReplicaRecord(
            sessionID: sessionID,
            cid: cid,
            byteCount: byteCount,
            chunkCount: chunkCount,
            now: now()
        )
    }
}

extension SQLiteAccountDatabase:
    PermissionedRemoteReplicaPublicationAuthorizingStore
{
    public func permissionedRemoteReplicaHead(
        target: PermissionedRemoteReplicaTarget
    ) async throws -> PermissionedRemoteReplicaHead? {
        guard target.receiverDID == accountDID else {
            throw PermissionedRemoteReplicaRecoveryError.receiverMismatch
        }
        return try await withConnectionGate {
            try await loadPermissionedRemoteReplicaHead(target: target)
        }
    }

    public func createPermissionedRemoteReplicaImportSession(
        binding: PermissionedRemoteReplicaImportBinding,
        createdAt: Int64,
        expiresAt: Int64,
        now: Int64
    ) async throws -> PermissionedRemoteReplicaImportStartOutcome {
        guard createdAt >= 0, now >= 0, expiresAt > createdAt else {
            throw PermissionedRemoteReplicaRecoveryError.invalidTimestamp
        }
        guard now < expiresAt else {
            throw PermissionedRemoteReplicaRecoveryError.expiredSession
        }
        guard binding.target.receiverDID == accountDID else {
            throw PermissionedRemoteReplicaRecoveryError.receiverMismatch
        }
        return try await withConnectionGate {
            try await transaction {
                if let committed = try await loadPermissionedRemoteReplicaResult(
                    requestID: binding.requestID,
                    expectedBinding: binding
                ) {
                    return .committed(committed)
                }
                let existingRows = try await connection.query(
                    """
                    SELECT *
                    FROM permissioned_remote_replica_import_sessions
                    WHERE request_id = ?
                    """,
                    [.text(binding.requestID)]
                )
                guard existingRows.count <= 1 else {
                    throw PermissionedRemoteReplicaRecoveryError.corruptStaging
                }
                if let row = existingRows.first {
                    let existing = try decodePermissionedRemoteReplicaSession(row)
                    guard existing.binding == binding else {
                        throw PermissionedRemoteReplicaRecoveryError
                            .conflictingRequestReuse
                    }
                    switch existing.status {
                    case .receiving, .verifying, .verified, .preparing:
                        throw PermissionedRemoteReplicaRecoveryError
                            .importInProgress
                    case .poisoned:
                        throw PermissionedRemoteReplicaRecoveryError
                            .poisonedSession
                    case .consumed:
                        throw PermissionedRemoteReplicaRecoveryError
                            .corruptStaging
                    }
                }

                let activeRows = try await connection.query(
                    """
                    SELECT 1
                    FROM permissioned_remote_replica_import_sessions
                    WHERE receiver_did = ? AND space_uri = ?
                      AND repository_did = ?
                      AND (
                        status IN (
                            'receiving', 'verifying', 'verified', 'preparing'
                        )
                        OR (
                            status = 'poisoned'
                            AND prepared_generation IS NOT NULL
                        )
                      )
                    LIMIT 1
                    """,
                    [
                        .text(accountDID),
                        .text(binding.target.space.rawValue),
                        .text(binding.target.repositoryDID),
                    ]
                )
                guard activeRows.isEmpty else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .importInProgress
                }

                let current = try await loadPermissionedRemoteReplicaHead(
                    target: binding.target
                )
                if let expected = binding.expectedBase {
                    guard current == expected else {
                        throw PermissionedRemoteReplicaRecoveryError
                            .targetCASConflict
                    }
                } else {
                    guard current == nil else {
                        throw PermissionedRemoteReplicaRecoveryError
                            .targetCASConflict
                    }
                }

                let sessionID = UUID().uuidString.lowercased()
                let expected = binding.expectedBase
                let freshness = binding.freshnessWitness
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_remote_replica_import_sessions(
                        session_id, request_id, request_digest, source_origin,
                        receiver_did, space_uri, repository_did,
                        expected_base_generation,
                        expected_base_wire_revision,
                        expected_base_history_floor,
                        expected_base_lthash,
                        expected_base_commitment,
                        expected_base_marker,
                        freshness_wire_revision,
                        freshness_commitment,
                        verifier_identity, profile_id,
                        maximum_car_bytes, maximum_record_bytes,
                        maximum_index_entries, maximum_unique_blocks,
                        status, created_at, expires_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?,
                        'receiving', ?, ?
                    )
                    """,
                    [
                        .text(sessionID),
                        .text(binding.requestID),
                        binding.requestDigest.sqliteData!,
                        .text(binding.sourceOrigin),
                        .text(accountDID),
                        .text(binding.target.space.rawValue),
                        .text(binding.target.repositoryDID),
                        expected.map { .integer(Int($0.generation)) } ?? .null,
                        expected.map {
                            .text($0.wireRevision.toString())
                        } ?? .null,
                        expected.map {
                            .text($0.historyFloorWireRevision.toString())
                        } ?? .null,
                        expected?.ltHash.sqliteData ?? .null,
                        expected?.commitment.sqliteData ?? .null,
                        expected?.stateMarker.sqliteData ?? .null,
                        freshness.map {
                            .text($0.wireRevision.toString())
                        } ?? .null,
                        freshness?.commitment.sqliteData ?? .null,
                        .text(binding.verifierIdentity),
                        .text(binding.profileID),
                        .integer(binding.limits.maximumCARBytes),
                        .integer(binding.limits.maximumRecordBytes),
                        .integer(binding.limits.maximumIndexEntries),
                        .integer(binding.limits.maximumUniqueBlocks),
                        .integer(try remoteReplicaSQLiteInteger(createdAt)),
                        .integer(try remoteReplicaSQLiteInteger(expiresAt)),
                    ]
                )
                return .staged(PermissionedRemoteReplicaImportSession(
                    id: sessionID,
                    binding: binding,
                    createdAt: createdAt,
                    expiresAt: expiresAt,
                    status: .receiving
                ))
            }
        }
    }

    public func permissionedRemoteReplicaImportSession(
        id: String
    ) async throws -> PermissionedRemoteReplicaImportSession {
        try await withConnectionGate {
            try await loadPermissionedRemoteReplicaSession(id: id)
        }
    }

    public func stagePermissionedRemoteReplicaRoots(
        sessionID: String,
        commit: CID,
        index: CID,
        now: Int64
    ) async throws {
        guard commit != index else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        try await withConnectionGate {
            try await transaction {
                let session = try await requireActiveRemoteReplicaSession(
                    id: sessionID, now: now, allowed: [.receiving]
                )
                try validateRemoteReplicaCID(commit)
                try validateRemoteReplicaCID(index)
                let rows = try await connection.query(
                    """
                    SELECT commit_root_cid, index_root_cid
                    FROM permissioned_remote_replica_import_sessions
                    WHERE session_id = ?
                    """,
                    [.text(sessionID)]
                )
                guard rows.count == 1, let row = rows.first else {
                    throw PermissionedRemoteReplicaRecoveryError.unknownSession
                }
                let oldCommit = row.column("commit_root_cid")?.string
                let oldIndex = row.column("index_root_cid")?.string
                guard (oldCommit == nil && oldIndex == nil)
                    || (oldCommit == commit.string && oldIndex == index.string)
                else {
                    throw PermissionedRemoteReplicaRecoveryError.corruptStaging
                }
                if oldCommit == nil {
                    let updated = try await connection.query(
                        """
                        UPDATE permissioned_remote_replica_import_sessions
                        SET commit_root_cid = ?, index_root_cid = ?
                        WHERE session_id = ? AND status = 'receiving'
                        RETURNING session_id
                        """,
                        [
                            .text(commit.string), .text(index.string),
                            .text(session.id),
                        ]
                    )
                    guard updated.count == 1 else {
                        throw PermissionedRemoteReplicaRecoveryError
                            .invalidStatus
                    }
                }
            }
        }
    }

    public func stagePermissionedRemoteReplicaCommit(
        sessionID: String,
        cid: CID,
        body: Data,
        now: Int64
    ) async throws {
        guard !body.isEmpty,
              body.count <= SpaceCARRecoveryLimits.absoluteMaximumCommitBytes,
              CID.fromDAGCBOR(body) == cid else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        try await withConnectionGate {
            try await transaction {
                _ = try await requireActiveRemoteReplicaSession(
                    id: sessionID, now: now, allowed: [.receiving]
                )
                let rows = try await connection.query(
                    """
                    SELECT commit_root_cid, verified_commit_body
                    FROM permissioned_remote_replica_import_sessions
                    WHERE session_id = ?
                    """,
                    [.text(sessionID)]
                )
                guard rows.count == 1, let row = rows.first,
                      row.column("commit_root_cid")?.string == cid.string else {
                    throw PermissionedRemoteReplicaRecoveryError.corruptStaging
                }
                if let value = row.column("verified_commit_body"),
                   !value.isNull
                {
                    guard Data(sqliteData: value) == body else {
                        throw PermissionedRemoteReplicaRecoveryError
                            .duplicateBlockConflict
                    }
                    return
                }
                let digest = Data(SHA256.hash(data: body))
                let updated = try await connection.query(
                    """
                    UPDATE permissioned_remote_replica_import_sessions
                    SET verified_commit_body = ?,
                        verified_commit_body_digest = ?
                    WHERE session_id = ? AND status = 'receiving'
                    RETURNING session_id
                    """,
                    [
                        body.sqliteData!, digest.sqliteData!,
                        .text(sessionID),
                    ]
                )
                guard updated.count == 1 else {
                    throw PermissionedRemoteReplicaRecoveryError.invalidStatus
                }
            }
        }
    }

    public func stagePermissionedRemoteReplicaIndexEntry(
        sessionID: String,
        entry: SpaceCARRecoveryIndexEntry,
        now: Int64
    ) async throws {
        try validateRemoteReplicaCID(entry.cid)
        try await withConnectionGate {
            try await transaction {
                let session = try await requireActiveRemoteReplicaSession(
                    id: sessionID, now: now, allowed: [.receiving]
                )
                let path = try remoteReplicaPath(
                    entry.path,
                    target: session.binding.target
                )
                let countRows = try await connection.query(
                    """
                    SELECT COUNT(*) AS count
                    FROM permissioned_remote_replica_import_index
                    WHERE session_id = ?
                    """,
                    [.text(sessionID)]
                )
                let count = remoteReplicaInteger(
                    countRows.first, "count"
                )
                guard count < session.binding.limits.maximumIndexEntries else {
                    throw SpaceCARStreamingError.indexEntryLimitExceeded
                }
                let inserted = try await connection.query(
                    """
                    INSERT INTO permissioned_remote_replica_import_index(
                        session_id, path, collection, rkey, cid, consumed
                    ) VALUES (?, ?, ?, ?, ?, 0)
                    ON CONFLICT(session_id, path) DO NOTHING
                    RETURNING path
                    """,
                    [
                        .text(sessionID), Data(entry.path.utf8).sqliteData!,
                        .text(path.collection), .text(path.rkey),
                        .text(entry.cid.string),
                    ]
                )
                guard inserted.count == 1 else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .duplicateIndexEntry
                }
            }
        }
    }

    public func nextUnconsumedPermissionedRemoteReplicaIndexEntry(
        sessionID: String,
        now: Int64
    ) async throws -> SpaceCARRecoveryIndexEntry? {
        try await withConnectionGate {
            _ = try await requireActiveRemoteReplicaSession(
                id: sessionID, now: now, allowed: [.receiving]
            )
            let rows = try await connection.query(
                """
                SELECT path, cid
                FROM permissioned_remote_replica_import_index
                WHERE session_id = ? AND consumed = 0
                ORDER BY path
                LIMIT 1
                """,
                [.text(sessionID)]
            )
            guard let row = rows.first else { return nil }
            guard let pathData = remoteReplicaData(row, "path"),
                  let path = String(data: pathData, encoding: .utf8),
                  let cidRaw = row.column("cid")?.string,
                  let cid = try? CID.parse(cidRaw) else {
                throw PermissionedRemoteReplicaRecoveryError.corruptStaging
            }
            try validateRemoteReplicaCID(cid)
            return SpaceCARRecoveryIndexEntry(path: path, cid: cid)
        }
    }

    public func consumePermissionedRemoteReplicaIndexEntries(
        sessionID: String,
        cid: CID,
        now: Int64
    ) async throws -> Int {
        try await withConnectionGate {
            try await transaction {
                _ = try await requireActiveRemoteReplicaSession(
                    id: sessionID, now: now, allowed: [.receiving]
                )
                let countRows = try await connection.query(
                    """
                    SELECT COUNT(*) AS count
                    FROM permissioned_remote_replica_import_index
                    WHERE session_id = ? AND cid = ? AND consumed = 0
                    """,
                    [.text(sessionID), .text(cid.string)]
                )
                let count = remoteReplicaInteger(
                    countRows.first, "count"
                )
                guard count > 0,
                      count <= SpaceCARRecoveryLimits
                        .absoluteMaximumIndexEntries else {
                    throw SpaceCARStreamingError.invalidRecordOrder
                }
                _ = try await connection.query(
                    """
                    UPDATE permissioned_remote_replica_import_index
                    SET consumed = 1
                    WHERE session_id = ? AND cid = ? AND consumed = 0
                    """,
                    [.text(sessionID), .text(cid.string)]
                )
                let changedRows = try await connection.query(
                    "SELECT changes() AS count"
                )
                guard remoteReplicaInteger(
                    changedRows.first, "count"
                ) == count else {
                    throw SpaceCARStreamingError.invalidRecordOrder
                }
                return count
            }
        }
    }

    public func beginPermissionedRemoteReplicaRecord(
        sessionID: String,
        cid: CID,
        byteCount: Int,
        now: Int64
    ) async throws {
        try validateRemoteReplicaCID(cid)
        try await withConnectionGate {
            try await transaction {
                let session = try await requireActiveRemoteReplicaSession(
                    id: sessionID, now: now, allowed: [.receiving]
                )
                guard byteCount > 0,
                      byteCount <= session.binding.limits.maximumRecordBytes
                else {
                    throw SpaceCARStreamingError.recordBodyLimitExceeded
                }
                let blockCountRows = try await connection.query(
                    """
                    SELECT COUNT(*) AS count
                    FROM permissioned_remote_replica_import_blocks
                    WHERE session_id = ?
                    """,
                    [.text(sessionID)]
                )
                let blockCount = remoteReplicaInteger(
                    blockCountRows.first, "count"
                )
                guard blockCount
                    < session.binding.limits.maximumUniqueBlocks else {
                    throw SpaceCARStreamingError.uniqueBlockLimitExceeded
                }
                let inserted = try await connection.query(
                    """
                    INSERT INTO permissioned_remote_replica_import_blocks(
                        session_id, cid, byte_count, chunk_count, complete
                    ) VALUES (?, ?, ?, 0, 0)
                    ON CONFLICT(session_id, cid) DO NOTHING
                    RETURNING cid
                    """,
                    [
                        .text(sessionID), .text(cid.string),
                        .integer(byteCount),
                    ]
                )
                guard inserted.count == 1 else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .duplicateBlockConflict
                }
            }
        }
    }

    public func appendPermissionedRemoteReplicaRecordChunk(
        sessionID: String,
        cid: CID,
        chunkIndex: Int,
        bytes: Data,
        now: Int64
    ) async throws {
        guard !bytes.isEmpty,
              bytes.count <= SpaceCARRecoveryLimits.maximumChunkBytes,
              (0 ..< 16).contains(chunkIndex) else {
            throw PermissionedRemoteReplicaRecoveryError.invalidChunk
        }
        try await withConnectionGate {
            try await transaction {
                _ = try await requireActiveRemoteReplicaSession(
                    id: sessionID, now: now, allowed: [.receiving]
                )
                let rows = try await connection.query(
                    """
                    SELECT byte_count, chunk_count, complete,
                           COALESCE((
                               SELECT SUM(length(bytes))
                               FROM permissioned_remote_replica_import_block_chunks
                               WHERE session_id = ? AND cid = ?
                           ), 0) AS staged_bytes
                    FROM permissioned_remote_replica_import_blocks
                    WHERE session_id = ? AND cid = ?
                    """,
                    [
                        .text(sessionID), .text(cid.string),
                        .text(sessionID), .text(cid.string),
                    ]
                )
                guard rows.count == 1, let row = rows.first else {
                    throw PermissionedRemoteReplicaRecoveryError.incompleteBlock
                }
                let expectedIndex = remoteReplicaInteger(
                    row, "chunk_count"
                )
                let declaredBytes = remoteReplicaInteger(
                    row, "byte_count"
                )
                let stagedBytes = remoteReplicaInteger(
                    row, "staged_bytes"
                )
                guard remoteReplicaInteger(row, "complete") == 0,
                      chunkIndex == expectedIndex,
                      stagedBytes <= declaredBytes - bytes.count else {
                    throw PermissionedRemoteReplicaRecoveryError.invalidChunk
                }
                _ = try await connection.query(
                    """
                    INSERT INTO
                        permissioned_remote_replica_import_block_chunks(
                            session_id, cid, chunk_index, bytes
                        ) VALUES (?, ?, ?, ?)
                    """,
                    [
                        .text(sessionID), .text(cid.string),
                        .integer(chunkIndex), bytes.sqliteData!,
                    ]
                )
                let advanced = try await connection.query(
                    """
                    UPDATE permissioned_remote_replica_import_blocks
                    SET chunk_count = chunk_count + 1
                    WHERE session_id = ? AND cid = ?
                      AND chunk_count = ? AND complete = 0
                    RETURNING cid
                    """,
                    [
                        .text(sessionID), .text(cid.string),
                        .integer(chunkIndex),
                    ]
                )
                guard advanced.count == 1 else {
                    throw PermissionedRemoteReplicaRecoveryError.invalidChunk
                }
            }
        }
    }

    public func completePermissionedRemoteReplicaRecord(
        sessionID: String,
        cid: CID,
        byteCount: Int,
        chunkCount: Int,
        now: Int64
    ) async throws {
        try await withConnectionGate {
            try await transaction {
                _ = try await requireActiveRemoteReplicaSession(
                    id: sessionID, now: now, allowed: [.receiving]
                )
                let rows = try await connection.query(
                    """
                    SELECT byte_count, chunk_count, complete,
                           COALESCE((
                               SELECT SUM(length(bytes))
                               FROM permissioned_remote_replica_import_block_chunks
                               WHERE session_id = ? AND cid = ?
                           ), 0) AS staged_bytes
                    FROM permissioned_remote_replica_import_blocks
                    WHERE session_id = ? AND cid = ?
                    """,
                    [
                        .text(sessionID), .text(cid.string),
                        .text(sessionID), .text(cid.string),
                    ]
                )
                guard rows.count == 1, let row = rows.first,
                      remoteReplicaInteger(row, "complete") == 0,
                      remoteReplicaInteger(row, "byte_count") == byteCount,
                      remoteReplicaInteger(row, "chunk_count") == chunkCount,
                      remoteReplicaInteger(row, "staged_bytes") == byteCount,
                      chunkCount > 0 else {
                    throw PermissionedRemoteReplicaRecoveryError.incompleteBlock
                }
                let updated = try await connection.query(
                    """
                    UPDATE permissioned_remote_replica_import_blocks
                    SET complete = 1
                    WHERE session_id = ? AND cid = ? AND complete = 0
                    RETURNING cid
                    """,
                    [.text(sessionID), .text(cid.string)]
                )
                guard updated.count == 1 else {
                    throw PermissionedRemoteReplicaRecoveryError.incompleteBlock
                }
            }
        }
    }

    public func markPermissionedRemoteReplicaImportVerified(
        sessionID: String,
        verification: VerifiedStreamingSpaceCARRecovery,
        now: Int64
    ) async throws {
        try await withConnectionGate {
            try await transaction {
                _ = try await requireActiveRemoteReplicaSession(
                    id: sessionID, now: now, allowed: [.receiving]
                )
                let claimed = try await connection.query(
                    """
                    UPDATE permissioned_remote_replica_import_sessions
                    SET status = 'verifying'
                    WHERE session_id = ? AND status = 'receiving'
                    RETURNING session_id
                    """,
                    [.text(sessionID)]
                )
                guard claimed.count == 1 else {
                    throw PermissionedRemoteReplicaRecoveryError.invalidStatus
                }
            }
            do {
                let session = try await requireActiveRemoteReplicaSession(
                    id: sessionID, now: now, allowed: [.verifying]
                )
                let validation = try await readTransaction {
                    try await validateStagedRemoteReplica(
                        sessionID: sessionID,
                        binding: session.binding
                    )
                }
                guard validation.commitRoot == verification.commitRootCID,
                      validation.indexRoot == verification.indexRootCID,
                      validation.wireRevision == verification.wireRevision,
                      validation.ltHash == verification.ltHash,
                      validation.commitment == verification.commitment,
                      validation.recordCount == verification.recordCount,
                      validation.uniqueBlockCount
                        == verification.uniqueBlockCount,
                      validation.commitBodyDigest
                        == verification.commitBodyDigest,
                      verification.receivedByteCount > 0,
                      verification.receivedByteCount
                        <= session.binding.limits.maximumCARBytes else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptStaging
                }
                if let freshness = session.binding.freshnessWitness {
                    guard freshness.wireRevision
                            == verification.wireRevision,
                          freshness.commitment == verification.commitment else {
                        throw PermissionedRemoteReplicaRecoveryError
                            .freshnessMismatch
                    }
                }
                try await transaction {
                    _ = try await requireActiveRemoteReplicaSession(
                        id: sessionID, now: now, allowed: [.verifying]
                    )
                    let updated = try await connection.query(
                        """
                        UPDATE permissioned_remote_replica_import_sessions
                        SET status = 'verified',
                            verified_wire_revision = ?,
                            verified_lthash = ?,
                            verified_commitment = ?,
                            verified_record_count = ?,
                            verified_unique_block_count = ?,
                            verified_received_byte_count = ?,
                            verified_projection_digest = ?
                        WHERE session_id = ? AND status = 'verifying'
                        RETURNING session_id
                        """,
                        [
                            .text(verification.wireRevision.toString()),
                            verification.ltHash.sqliteData!,
                            verification.commitment.sqliteData!,
                            .integer(verification.recordCount),
                            .integer(verification.uniqueBlockCount),
                            .integer(verification.receivedByteCount),
                            validation.projectionDigest.sqliteData!,
                            .text(sessionID),
                        ]
                    )
                    guard updated.count == 1 else {
                        throw PermissionedRemoteReplicaRecoveryError
                            .invalidStatus
                    }
                }
            } catch {
                try? await transaction {
                    _ = try await connection.query(
                        """
                        UPDATE permissioned_remote_replica_import_sessions
                        SET status = 'poisoned'
                        WHERE session_id = ? AND status = 'verifying'
                        """,
                        [.text(sessionID)]
                    )
                }
                throw error
            }
        }
    }

    public func publishVerifiedPermissionedRemoteReplicaRecovery(
        sessionID: String,
        consumedAt: Int64,
        now: Int64
    ) async throws -> CommittedPermissionedRemoteReplicaRecovery {
        try await publishVerifiedPermissionedRemoteReplicaRecoveryCore(
            sessionID: sessionID,
            consumedAt: consumedAt,
            now: now,
            publicationAuthorization: nil
        )
    }

    public func publishVerifiedPermissionedRemoteReplicaRecovery(
        sessionID: String,
        consumedAt: Int64,
        now: Int64,
        publicationAuthorization:
            @escaping PermissionedRemoteReplicaPublicationAuthorization
    ) async throws -> CommittedPermissionedRemoteReplicaRecovery {
        try await publishVerifiedPermissionedRemoteReplicaRecoveryCore(
            sessionID: sessionID,
            consumedAt: consumedAt,
            now: now,
            publicationAuthorization: publicationAuthorization
        )
    }

    private func publishVerifiedPermissionedRemoteReplicaRecoveryCore(
        sessionID: String,
        consumedAt: Int64,
        now: Int64,
        publicationAuthorization:
            PermissionedRemoteReplicaPublicationAuthorization?
    ) async throws -> CommittedPermissionedRemoteReplicaRecovery {
        guard consumedAt >= 0, now >= 0 else {
            throw PermissionedRemoteReplicaRecoveryError.invalidTimestamp
        }
        return try await withConnectionGate {
            let session = try await requireActiveRemoteReplicaSession(
                id: sessionID, now: now, allowed: [.verified]
            )
            let validation = try await readTransaction {
                try await validateStagedRemoteReplica(
                    sessionID: sessionID,
                    binding: session.binding
                )
            }
            try await requireVerifiedRemoteReplicaProjection(
                sessionID: sessionID,
                validation: validation
            )
            let current = try await loadPermissionedRemoteReplicaHead(
                target: session.binding.target
            )
            try requireRemoteReplicaExpectedBase(
                session.binding.expectedBase,
                current: current
            )
            let currentProjection: RemoteReplicaProjectionValidation?
            if let current {
                currentProjection = try await readTransaction {
                    try await validateRemoteReplicaGeneration(
                        target: session.binding.target,
                        generation: current.generation,
                        expectedCommitment: current.commitment
                    )
                }
            } else {
                currentProjection = nil
            }
            try await requireRemoteReplicaHighWater(
                target: session.binding.target,
                wireRevision: validation.wireRevision,
                commitment: validation.commitment
            )
            if let current,
               validation.wireRevision == current.wireRevision
            {
                guard validation.commitment == current.commitment else {
                    throw PermissionedRemoteReplicaRecoveryError.equivocation
                }
                guard let currentProjection,
                      currentProjection.indexRoot == validation.indexRoot,
                      currentProjection.projectionDigest
                        == validation.projectionDigest,
                      currentProjection.recordCount
                        == validation.recordCount,
                      currentProjection.uniqueBlockCount
                        == validation.uniqueBlockCount else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptReplica
                }
                let finalize: @Sendable () async throws
                    -> CommittedPermissionedRemoteReplicaRecovery = {
                    try await self.finalizeExistingRemoteReplicaRecovery(
                        session: session,
                        validation: validation,
                        head: current,
                        committedAt: consumedAt
                    )
                }
                let result: CommittedPermissionedRemoteReplicaRecovery
                if let publicationAuthorization {
                    result = try await publicationAuthorization(finalize)
                } else {
                    result = try await finalize()
                }
                try await cleanupRemoteReplicaImportSessionBatched(
                    sessionID: sessionID,
                    requiredStatus: .consumed
                )
                return result
            }
            if let current,
               validation.wireRevision < current.wireRevision
            {
                throw PermissionedRemoteReplicaRecoveryError.staleRecovery
            }

            let generation = (current?.generation ?? 0) + 1
            guard generation > 0, generation <= UInt64(Int.max) else {
                throw PermissionedRemoteReplicaRecoveryError
                    .targetCASConflict
            }
            try await transaction {
                let reloaded = try await requireActiveRemoteReplicaSession(
                    id: sessionID, now: now, allowed: [.verified]
                )
                let latest = try await loadPermissionedRemoteReplicaHead(
                    target: reloaded.binding.target
                )
                try requireRemoteReplicaExpectedBase(
                    reloaded.binding.expectedBase,
                    current: latest
                )
                let claimed = try await connection.query(
                    """
                    UPDATE permissioned_remote_replica_import_sessions
                    SET status = 'preparing', prepared_generation = ?,
                        prepared_projection_digest = ?
                    WHERE session_id = ? AND status = 'verified'
                    RETURNING session_id
                    """,
                    [
                        .integer(Int(generation)),
                        validation.projectionDigest.sqliteData!,
                        .text(sessionID),
                    ]
                )
                guard claimed.count == 1 else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .invalidStatus
                }
                try await testingHooks.afterRemoteReplicaMutatingSQL?(0)
            }

            do {
                try await prepareRemoteReplicaGenerationBatched(
                    sessionID: sessionID,
                    target: session.binding.target,
                    generation: generation,
                    now: now
                )
                let prepared = try await readTransaction {
                    try await validateRemoteReplicaGeneration(
                        target: session.binding.target,
                        generation: generation,
                        expectedCommitment: validation.commitment
                    )
                }
                guard prepared.indexRoot == validation.indexRoot,
                      prepared.projectionDigest
                        == validation.projectionDigest,
                      prepared.recordCount == validation.recordCount,
                      prepared.uniqueBlockCount
                        == validation.uniqueBlockCount else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptStaging
                }
                let marker = remoteReplicaStateMarker(
                    target: session.binding.target,
                    generation: generation,
                    wireRevision: validation.wireRevision,
                    historyFloor: validation.wireRevision,
                    commitment: validation.commitment
                )
                let head = try PermissionedRemoteReplicaHead(
                    target: session.binding.target,
                    generation: generation,
                    wireRevision: validation.wireRevision,
                    historyFloorWireRevision: validation.wireRevision,
                    ltHash: validation.ltHash,
                    commitment: validation.commitment,
                    stateMarker: marker
                )
                let finalize: @Sendable () async throws
                    -> CommittedPermissionedRemoteReplicaRecovery = {
                    try await self.finalizePreparedRemoteReplicaRecovery(
                        sessionID: sessionID,
                        now: now,
                        generation: generation,
                        prepared: prepared,
                        head: head,
                        validation: validation,
                        committedAt: consumedAt
                    )
                }
                let result: CommittedPermissionedRemoteReplicaRecovery
                if let publicationAuthorization {
                    result = try await publicationAuthorization(finalize)
                } else {
                    result = try await finalize()
                }
                try await cleanupRemoteReplicaImportSessionBatched(
                    sessionID: sessionID,
                    requiredStatus: .consumed
                )
                try await cleanupObsoleteRemoteReplicaGenerationsBatched(
                    target: session.binding.target,
                    liveGeneration: generation
                )
                return result
            } catch {
                try? await transaction {
                    _ = try await connection.query(
                        """
                        UPDATE permissioned_remote_replica_import_sessions
                        SET status = 'poisoned'
                        WHERE session_id = ? AND status = 'preparing'
                          AND prepared_generation = ?
                        """,
                        [.text(sessionID), .integer(Int(generation))]
                    )
                }
                try? await cleanupUnpublishedRemoteReplicaGenerationBatched(
                    sessionID: sessionID,
                    target: session.binding.target,
                    generation: generation
                )
                throw error
            }
        }
    }

    /// Runs the same-revision result finalization in its own short account
    /// transaction.  The publication-authorization capability wraps this
    /// helper, so validation and staging never hold the control-plane lease.
    private func finalizeExistingRemoteReplicaRecovery(
        session: PermissionedRemoteReplicaImportSession,
        validation: StagedPermissionedRemoteReplicaValidation,
        head: PermissionedRemoteReplicaHead,
        committedAt: Int64
    ) async throws -> CommittedPermissionedRemoteReplicaRecovery {
        try await transaction {
            try await finalizeRemoteReplicaResult(
                session: session,
                validation: validation,
                head: head,
                committedAt: committedAt,
                requiredStatus: .verified
            )
        }
    }

    /// Installs a prepared generation and records its result in one short
    /// account transaction.  All potentially large preparation and cleanup
    /// work remains outside the publication-authorization callback.
    private func finalizePreparedRemoteReplicaRecovery(
        sessionID: String,
        now: Int64,
        generation: UInt64,
        prepared: RemoteReplicaProjectionValidation,
        head: PermissionedRemoteReplicaHead,
        validation: StagedPermissionedRemoteReplicaValidation,
        committedAt: Int64
    ) async throws -> CommittedPermissionedRemoteReplicaRecovery {
        try await transaction {
            let preparing = try await requireActiveRemoteReplicaSession(
                id: sessionID,
                now: now,
                allowed: [.preparing]
            )
            let preparationRows = try await connection.query(
                """
                SELECT prepared_generation,
                       prepared_projection_digest
                FROM permissioned_remote_replica_import_sessions
                WHERE session_id = ?
                """,
                [.text(sessionID)]
            )
            guard preparationRows.count == 1,
                  let preparation = preparationRows.first,
                  remoteReplicaInteger(
                      preparation, "prepared_generation"
                  ) == Int(generation),
                  remoteReplicaData(
                      preparation,
                      "prepared_projection_digest"
                  ) == prepared.projectionDigest else {
                throw PermissionedRemoteReplicaRecoveryError.corruptStaging
            }
            let latest = try await loadPermissionedRemoteReplicaHead(
                target: preparing.binding.target
            )
            try requireRemoteReplicaExpectedBase(
                preparing.binding.expectedBase,
                current: latest
            )
            try await requireRemoteReplicaHighWater(
                target: preparing.binding.target,
                wireRevision: validation.wireRevision,
                commitment: validation.commitment
            )
            try await installRemoteReplicaHead(
                head,
                replacing: latest,
                installedAt: committedAt
            )
            try await testingHooks.afterRemoteReplicaMutatingSQL?(4)
            let committed = try await finalizeRemoteReplicaResult(
                session: preparing,
                validation: validation,
                head: head,
                committedAt: committedAt,
                requiredStatus: .preparing
            )
            try await testingHooks.afterRemoteReplicaMutatingSQL?(5)
            return committed
        }
    }

    public func poisonPermissionedRemoteReplicaImportSession(id: String) async {
        try? await withConnectionGate {
            _ = try await connection.query(
                """
                UPDATE permissioned_remote_replica_import_sessions
                SET status = 'poisoned'
                WHERE session_id = ?
                  AND status IN ('receiving', 'verifying', 'preparing')
                """,
                [.text(id)]
            )
        }
    }

    public func cleanupPermissionedRemoteReplicaImportSession(
        id: String
    ) async throws {
        try await withConnectionGate {
            let session = try await loadPermissionedRemoteReplicaSession(id: id)
            guard session.status != .verified else {
                throw PermissionedRemoteReplicaRecoveryError.invalidStatus
            }
            var cleanupStatus = session.status
            if [.receiving, .verifying, .preparing].contains(cleanupStatus) {
                let claimedCount = try await transaction {
                    let claimed = try await connection.query(
                        """
                        UPDATE permissioned_remote_replica_import_sessions
                        SET status = 'poisoned'
                        WHERE session_id = ? AND status = ?
                        RETURNING session_id
                        """,
                        [.text(id), .text(cleanupStatus.rawValue)]
                    )
                    guard claimed.count <= 1 else {
                        throw PermissionedRemoteReplicaRecoveryError
                            .corruptStaging
                    }
                    return claimed.count
                }
                if claimedCount == 1 {
                    cleanupStatus = .poisoned
                } else {
                    let reloaded =
                        try await loadPermissionedRemoteReplicaSession(id: id)
                    guard [.poisoned, .consumed].contains(
                        reloaded.status
                    ) else {
                        throw PermissionedRemoteReplicaRecoveryError
                            .invalidStatus
                    }
                    cleanupStatus = reloaded.status
                }
            }
            if cleanupStatus == .poisoned,
               let generation =
                try await preparedRemoteReplicaGeneration(sessionID: id)
            {
                try await cleanupUnpublishedRemoteReplicaGenerationBatched(
                    sessionID: id,
                    target: session.binding.target,
                    generation: generation
                )
            }
            try await cleanupRemoteReplicaImportSessionBatched(
                sessionID: id,
                requiredStatus: cleanupStatus
            )
        }
    }

    public func recoverExpiredPermissionedRemoteReplicaImportSessions(
        now: Int64
    ) async throws -> Int {
        guard now >= 0 else {
            throw PermissionedRemoteReplicaRecoveryError.invalidTimestamp
        }
        return try await withConnectionGate {
            try await recoverExpiredPermissionedRemoteReplicaImportSessionsWithoutGate(
                now: now
            )
        }
    }

    func recoverExpiredPermissionedRemoteReplicaImportSessionsWithoutGate(
        now: Int64
    ) async throws -> Int {
        guard now >= 0 else {
            throw PermissionedRemoteReplicaRecoveryError.invalidTimestamp
        }
        var removed = 0
        while true {
            let page = try await connection.query(
                """
                SELECT session_id, request_id, receiver_did,
                       space_uri, repository_did, status,
                       prepared_generation
                FROM permissioned_remote_replica_import_sessions
                WHERE status IN ('poisoned', 'consumed')
                   OR expires_at <= ?
                ORDER BY session_id
                LIMIT ?
                """,
                [
                    .integer(try remoteReplicaSQLiteInteger(now)),
                    .integer(
                        PermissionedRemoteReplicaRecoveryBudgets
                            .maximumRowsPerPass
                    ),
                ]
            )
            guard page.count
                    <= PermissionedRemoteReplicaRecoveryBudgets
                        .maximumRowsPerPass else {
                throw PermissionedRemoteReplicaRecoveryError.corruptStaging
            }
            guard !page.isEmpty else { break }
            for row in page {
                let sessionID = remoteReplicaText(row, "session_id")
                guard var status = PermissionedRemoteReplicaImportStatus(
                    rawValue: remoteReplicaText(row, "status")
                ), !sessionID.isEmpty else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptStaging
                }
                if [.receiving, .verifying, .verified, .preparing]
                    .contains(status)
                {
                    let claimedCount = try await transaction {
                        let claimed = try await connection.query(
                            """
                            UPDATE
                                permissioned_remote_replica_import_sessions
                            SET status = 'poisoned'
                            WHERE session_id = ? AND status = ?
                              AND expires_at <= ?
                            RETURNING session_id
                            """,
                            [
                                .text(sessionID), .text(status.rawValue),
                                .integer(
                                    try remoteReplicaSQLiteInteger(now)
                                ),
                            ]
                        )
                        guard claimed.count <= 1 else {
                            throw PermissionedRemoteReplicaRecoveryError
                                .corruptStaging
                        }
                        return claimed.count
                    }
                    guard claimedCount == 1 else {
                        continue
                    }
                    status = .poisoned
                }
                if status == .consumed {
                    let results = try await connection.query(
                        """
                        SELECT 1
                        FROM permissioned_remote_replica_import_results
                        WHERE request_id = ?
                        LIMIT 2
                        """,
                        [.text(remoteReplicaText(row, "request_id"))]
                    )
                    guard results.count == 1 else {
                        throw PermissionedRemoteReplicaRecoveryError
                            .corruptStaging
                    }
                } else if status == .poisoned,
                          let rawGeneration =
                    row.column("prepared_generation")?.integer
                {
                    guard rawGeneration > 0 else {
                        throw PermissionedRemoteReplicaRecoveryError
                            .corruptStaging
                    }
                    let target = try PermissionedRemoteReplicaTarget(
                        receiverDID: remoteReplicaText(
                            row, "receiver_did"
                        ),
                        space: try SpaceURI(
                            remoteReplicaText(row, "space_uri")
                        ),
                        repositoryDID: remoteReplicaText(
                            row, "repository_did"
                        )
                    )
                    try await
                        cleanupUnpublishedRemoteReplicaGenerationBatched(
                            sessionID: sessionID,
                            target: target,
                            generation: UInt64(rawGeneration)
                        )
                }
                try await cleanupRemoteReplicaImportSessionBatched(
                    sessionID: sessionID,
                    requiredStatus: status
                )
                removed += 1
            }
        }
        try await cleanupObsoleteRemoteReplicaGenerationsAtStartup()
        return removed
    }

    /// Reconstructs only one bounded record body for a remote-replica read.
    public func permissionedRemoteReplicaRecord(
        target: PermissionedRemoteReplicaTarget,
        collection: String,
        rkey: String
    ) async throws -> Data? {
        guard target.receiverDID == accountDID else {
            throw PermissionedRemoteReplicaRecoveryError.receiverMismatch
        }
        _ = try SpaceRecordURI(
            space: target.space,
            author: target.repositoryDID,
            collection: collection,
            rkey: rkey
        )
        return try await withConnectionGate {
            try await readTransaction {
                guard let head = try await loadPermissionedRemoteReplicaHead(
                    target: target
                ) else { return nil }
                let rows = try await connection.query(
                    """
                    SELECT records.cid, blocks.byte_count,
                           blocks.chunk_count, chunks.chunk_index,
                           chunks.bytes
                    FROM permissioned_remote_replica_records AS records
                    JOIN permissioned_remote_replica_blocks AS blocks
                      ON blocks.space_uri = records.space_uri
                     AND blocks.repository_did = records.repository_did
                     AND blocks.generation = records.generation
                     AND blocks.cid = records.cid
                    JOIN permissioned_remote_replica_block_chunks AS chunks
                      ON chunks.space_uri = records.space_uri
                     AND chunks.repository_did = records.repository_did
                     AND chunks.generation = records.generation
                     AND chunks.cid = records.cid
                    WHERE records.space_uri = ?
                      AND records.repository_did = ?
                      AND records.generation = ?
                      AND records.collection = ? AND records.rkey = ?
                    ORDER BY chunks.chunk_index
                    LIMIT ?
                    """,
                    [
                        .text(target.space.rawValue),
                        .text(target.repositoryDID),
                        .integer(Int(head.generation)),
                        .text(collection), .text(rkey),
                        .integer(
                            PermissionedRemoteReplicaRecoveryBudgets
                                .maximumChunksPerRecord + 1
                        ),
                    ]
                )
                guard !rows.isEmpty else { return nil }
                guard rows.count
                        <= PermissionedRemoteReplicaRecoveryBudgets
                            .maximumChunksPerRecord,
                      let expectedCID = try? CID.parse(
                          remoteReplicaText(rows[0], "cid")
                      ) else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptReplica
                }
                try validateLiveRemoteReplicaCID(expectedCID)
                let byteCount = remoteReplicaInteger(
                    rows[0], "byte_count"
                )
                let chunkCount = remoteReplicaInteger(
                    rows[0], "chunk_count"
                )
                guard chunkCount == rows.count, byteCount > 0 else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptReplica
                }
                var output = Data()
                var hasher = SHA256()
                var expectedIndex = 0
                for row in rows {
                    guard remoteReplicaText(row, "cid")
                            == expectedCID.string,
                          remoteReplicaInteger(row, "byte_count")
                            == byteCount,
                          remoteReplicaInteger(row, "chunk_count")
                            == chunkCount,
                          remoteReplicaInteger(row, "chunk_index")
                            == expectedIndex,
                          let bytes = remoteReplicaData(row, "bytes"),
                          !bytes.isEmpty,
                          bytes.count
                            <= SpaceCARRecoveryLimits.maximumChunkBytes,
                          output.count
                            <= SpaceCARRecoveryLimits
                                .absoluteMaximumRecordBytes - bytes.count else {
                        throw PermissionedRemoteReplicaRecoveryError
                            .corruptReplica
                    }
                    output.append(bytes)
                    hasher.update(data: bytes)
                    expectedIndex += 1
                }
                guard output.count == byteCount,
                      CID(
                        codec: .dagCBOR,
                        multihash: .init(
                            algorithm: Multihash.sha256Code,
                            length: Multihash.sha256Length,
                            digest: Data(hasher.finalize())
                        )
                      ) == expectedCID else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptReplica
                }
                return output
            }
        }
    }

    private func requireVerifiedRemoteReplicaProjection(
        sessionID: String,
        validation: StagedPermissionedRemoteReplicaValidation
    ) async throws {
        let rows = try await connection.query(
            """
            SELECT status, verified_wire_revision, verified_lthash,
                   verified_commitment, verified_record_count,
                   verified_unique_block_count,
                   verified_projection_digest
            FROM permissioned_remote_replica_import_sessions
            WHERE session_id = ?
            """,
            [.text(sessionID)]
        )
        guard rows.count == 1, let row = rows.first,
              remoteReplicaText(row, "status") == "verified",
              remoteReplicaText(row, "verified_wire_revision")
                == validation.wireRevision.toString(),
              remoteReplicaData(row, "verified_lthash")
                == validation.ltHash,
              remoteReplicaData(row, "verified_commitment")
                == validation.commitment,
              remoteReplicaInteger(row, "verified_record_count")
                == validation.recordCount,
              remoteReplicaInteger(row, "verified_unique_block_count")
                == validation.uniqueBlockCount,
              remoteReplicaData(row, "verified_projection_digest")
                == validation.projectionDigest else {
            throw PermissionedRemoteReplicaRecoveryError
                .verificationRequired
        }
    }

    private func requireRemoteReplicaExpectedBase(
        _ expected: PermissionedRemoteReplicaHead?,
        current: PermissionedRemoteReplicaHead?
    ) throws {
        guard expected == current else {
            throw PermissionedRemoteReplicaRecoveryError.targetCASConflict
        }
    }

    private func requireRemoteReplicaHighWater(
        target: PermissionedRemoteReplicaTarget,
        wireRevision: TID,
        commitment: Data
    ) async throws {
        let rows = try await connection.query(
            """
            SELECT wire_revision, commitment
            FROM permissioned_space_writers
            WHERE space_uri = ? AND repo_did = ?
            LIMIT 2
            """,
            [.text(target.space.rawValue), .text(target.repositoryDID)]
        )
        guard rows.count <= 1 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        guard let row = rows.first else { return }
        guard let highWater = try? TID(tidString:
            remoteReplicaText(row, "wire_revision")
        ), let highWaterCommitment = remoteReplicaData(
            row, "commitment"
        ), highWaterCommitment.count == 32 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        if wireRevision < highWater {
            throw PermissionedRemoteReplicaRecoveryError.staleRecovery
        }
        if wireRevision == highWater,
           commitment != highWaterCommitment
        {
            throw PermissionedRemoteReplicaRecoveryError.equivocation
        }
    }

    private func installRemoteReplicaHead(
        _ head: PermissionedRemoteReplicaHead,
        replacing current: PermissionedRemoteReplicaHead?,
        installedAt: Int64
    ) async throws {
        if let current {
            let updated = try await connection.query(
                """
                UPDATE permissioned_remote_replica_state
                SET generation = ?, wire_revision = ?,
                    history_floor_wire_revision = ?,
                    lthash = ?, commitment = ?, state_marker = ?,
                    installed_at = ?
                WHERE space_uri = ? AND repository_did = ?
                  AND receiver_did = ? AND generation = ?
                  AND wire_revision = ? AND commitment = ?
                  AND state_marker = ?
                RETURNING generation
                """,
                [
                    .integer(Int(head.generation)),
                    .text(head.wireRevision.toString()),
                    .text(head.historyFloorWireRevision.toString()),
                    head.ltHash.sqliteData!,
                    head.commitment.sqliteData!,
                    head.stateMarker.sqliteData!,
                    .integer(try remoteReplicaSQLiteInteger(installedAt)),
                    .text(head.target.space.rawValue),
                    .text(head.target.repositoryDID),
                    .text(accountDID),
                    .integer(Int(current.generation)),
                    .text(current.wireRevision.toString()),
                    current.commitment.sqliteData!,
                    current.stateMarker.sqliteData!,
                ]
            )
            guard updated.count == 1 else {
                throw PermissionedRemoteReplicaRecoveryError
                    .targetCASConflict
            }
        } else {
            let inserted = try await connection.query(
                """
                INSERT INTO permissioned_remote_replica_state(
                    receiver_did, space_uri, repository_did,
                    generation, wire_revision,
                    history_floor_wire_revision, lthash,
                    commitment, state_marker, installed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                RETURNING generation
                """,
                [
                    .text(accountDID),
                    .text(head.target.space.rawValue),
                    .text(head.target.repositoryDID),
                    .integer(Int(head.generation)),
                    .text(head.wireRevision.toString()),
                    .text(head.historyFloorWireRevision.toString()),
                    head.ltHash.sqliteData!,
                    head.commitment.sqliteData!,
                    head.stateMarker.sqliteData!,
                    .integer(try remoteReplicaSQLiteInteger(installedAt)),
                ]
            )
            guard inserted.count == 1 else {
                throw PermissionedRemoteReplicaRecoveryError
                    .targetCASConflict
            }
        }
    }

    private func finalizeRemoteReplicaResult(
        session: PermissionedRemoteReplicaImportSession,
        validation: StagedPermissionedRemoteReplicaValidation,
        head: PermissionedRemoteReplicaHead,
        committedAt: Int64,
        requiredStatus: PermissionedRemoteReplicaImportStatus
    ) async throws -> CommittedPermissionedRemoteReplicaRecovery {
        let integrity = remoteReplicaResultIntegrityDigest(
            binding: session.binding,
            head: head,
            commitRoot: validation.commitRoot.string,
            indexRoot: validation.indexRoot.string,
            recordCount: validation.recordCount,
            uniqueBlockCount: validation.uniqueBlockCount,
            committedAt: committedAt
        )
        let bindingDigest = permissionedRemoteReplicaBindingDigest(
            session.binding
        )
        let inserted = try await connection.query(
            """
            INSERT INTO permissioned_remote_replica_import_results(
                request_id, request_digest, binding_digest, source_origin,
                receiver_did, space_uri, repository_did,
                base_generation, installed_generation,
                installed_wire_revision, installed_history_floor,
                installed_lthash, installed_commitment,
                installed_marker, commit_root_cid, index_root_cid,
                record_count, unique_block_count,
                verifier_identity, profile_id, committed_at,
                integrity_digest
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?
            )
            RETURNING request_id
            """,
            [
                .text(session.binding.requestID),
                session.binding.requestDigest.sqliteData!,
                bindingDigest.sqliteData!,
                .text(session.binding.sourceOrigin),
                .text(accountDID),
                .text(head.target.space.rawValue),
                .text(head.target.repositoryDID),
                session.binding.expectedBase.map {
                    .integer(Int($0.generation))
                } ?? .null,
                .integer(Int(head.generation)),
                .text(head.wireRevision.toString()),
                .text(head.historyFloorWireRevision.toString()),
                head.ltHash.sqliteData!,
                head.commitment.sqliteData!,
                head.stateMarker.sqliteData!,
                .text(validation.commitRoot.string),
                .text(validation.indexRoot.string),
                .integer(validation.recordCount),
                .integer(validation.uniqueBlockCount),
                .text(session.binding.verifierIdentity),
                .text(session.binding.profileID),
                .integer(try remoteReplicaSQLiteInteger(committedAt)),
                integrity.sqliteData!,
            ]
        )
        guard inserted.count == 1 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        let consumed = try await connection.query(
            """
            UPDATE permissioned_remote_replica_import_sessions
            SET status = 'consumed'
            WHERE session_id = ? AND status = ?
            RETURNING session_id
            """,
            [.text(session.id), .text(requiredStatus.rawValue)]
        )
        guard consumed.count == 1 else {
            throw PermissionedRemoteReplicaRecoveryError.invalidStatus
        }
        return CommittedPermissionedRemoteReplicaRecovery(
            requestID: session.binding.requestID,
            requestDigest: session.binding.requestDigest,
            verifierIdentity: session.binding.verifierIdentity,
            head: head,
            commitRootCID: validation.commitRoot.string,
            indexRootCID: validation.indexRoot.string,
            recordCount: validation.recordCount,
            uniqueBlockCount: validation.uniqueBlockCount,
            committedAt: committedAt
        )
    }

    private func prepareRemoteReplicaGenerationBatched(
        sessionID: String,
        target: PermissionedRemoteReplicaTarget,
        generation: UInt64,
        now: Int64
    ) async throws {
        let preexisting = try await connection.query(
            """
            SELECT
              (SELECT COUNT(*)
               FROM permissioned_remote_replica_blocks
               WHERE space_uri = ? AND repository_did = ?
                 AND generation = ?) AS blocks,
              (SELECT COUNT(*)
               FROM permissioned_remote_replica_block_chunks
               WHERE space_uri = ? AND repository_did = ?
                 AND generation = ?) AS chunks,
              (SELECT COUNT(*)
               FROM permissioned_remote_replica_records
               WHERE space_uri = ? AND repository_did = ?
                 AND generation = ?) AS records
            """,
            [
                .text(target.space.rawValue), .text(target.repositoryDID),
                .integer(Int(generation)),
                .text(target.space.rawValue), .text(target.repositoryDID),
                .integer(Int(generation)),
                .text(target.space.rawValue), .text(target.repositoryDID),
                .integer(Int(generation)),
            ]
        )
        guard preexisting.count == 1, let existing = preexisting.first,
              remoteReplicaInteger(existing, "blocks") == 0,
              remoteReplicaInteger(existing, "chunks") == 0,
              remoteReplicaInteger(existing, "records") == 0 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }

        var lastBlockCID = ""
        while true {
            let page = try await connection.query(
                """
                SELECT cid
                FROM permissioned_remote_replica_import_blocks
                WHERE session_id = ? AND complete = 1 AND cid > ?
                ORDER BY cid
                LIMIT ?
                """,
                [
                    .text(sessionID), .text(lastBlockCID),
                    .integer(
                        PermissionedRemoteReplicaRecoveryBudgets
                            .maximumRowsPerPass
                    ),
                ]
            )
            guard page.count
                <= PermissionedRemoteReplicaRecoveryBudgets
                    .maximumRowsPerPass else {
                throw PermissionedRemoteReplicaRecoveryError.corruptStaging
            }
            guard let upperCID = page.last?.column("cid")?.string else {
                break
            }
            let lowerCID = lastBlockCID
            try await transaction {
                _ = try await requireActiveRemoteReplicaSession(
                    id: sessionID,
                    now: now,
                    allowed: [.preparing]
                )
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_remote_replica_blocks(
                        space_uri, repository_did, cid, byte_count,
                        chunk_count, generation
                    )
                    SELECT ?, ?, cid, byte_count, chunk_count, ?
                    FROM permissioned_remote_replica_import_blocks
                    WHERE session_id = ? AND complete = 1
                      AND cid > ? AND cid <= ?
                    ORDER BY cid
                    """,
                    [
                        .text(target.space.rawValue),
                        .text(target.repositoryDID),
                        .integer(Int(generation)),
                        .text(sessionID), .text(lowerCID), .text(upperCID),
                    ]
                )
                try await requireRemoteReplicaChangeCount(page.count)
                try await testingHooks.afterRemoteReplicaMutatingSQL?(1)
            }
            lastBlockCID = upperCID
        }

        var lastChunkCID = ""
        var lastChunkIndex = -1
        while true {
            let page = try await connection.query(
                """
                SELECT cid, chunk_index
                FROM permissioned_remote_replica_import_block_chunks
                WHERE session_id = ?
                  AND (
                    cid > ? OR (cid = ? AND chunk_index > ?)
                  )
                ORDER BY cid, chunk_index
                LIMIT ?
                """,
                [
                    .text(sessionID),
                    .text(lastChunkCID), .text(lastChunkCID),
                    .integer(lastChunkIndex),
                    .integer(
                        PermissionedRemoteReplicaRecoveryBudgets
                            .maximumRowsPerPass
                    ),
                ]
            )
            guard page.count
                <= PermissionedRemoteReplicaRecoveryBudgets
                    .maximumRowsPerPass else {
                throw PermissionedRemoteReplicaRecoveryError.corruptStaging
            }
            guard let last = page.last,
                  let upperCID = last.column("cid")?.string else {
                break
            }
            let upperIndex = remoteReplicaInteger(last, "chunk_index")
            let lowerCID = lastChunkCID
            let lowerIndex = lastChunkIndex
            try await transaction {
                _ = try await requireActiveRemoteReplicaSession(
                    id: sessionID,
                    now: now,
                    allowed: [.preparing]
                )
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_remote_replica_block_chunks(
                        space_uri, repository_did, generation,
                        cid, chunk_index, bytes
                    )
                    SELECT ?, ?, ?, cid, chunk_index, bytes
                    FROM permissioned_remote_replica_import_block_chunks
                    WHERE session_id = ?
                      AND (
                        cid > ? OR (cid = ? AND chunk_index > ?)
                      )
                      AND (
                        cid < ? OR (cid = ? AND chunk_index <= ?)
                      )
                    ORDER BY cid, chunk_index
                    """,
                    [
                        .text(target.space.rawValue),
                        .text(target.repositoryDID),
                        .integer(Int(generation)), .text(sessionID),
                        .text(lowerCID), .text(lowerCID),
                        .integer(lowerIndex),
                        .text(upperCID), .text(upperCID),
                        .integer(upperIndex),
                    ]
                )
                try await requireRemoteReplicaChangeCount(page.count)
                try await testingHooks.afterRemoteReplicaMutatingSQL?(2)
            }
            lastChunkCID = upperCID
            lastChunkIndex = upperIndex
        }

        var lastCollection = ""
        var lastRKey = ""
        while true {
            let page = try await connection.query(
                """
                SELECT collection, rkey
                FROM permissioned_remote_replica_import_index
                WHERE session_id = ? AND consumed = 1
                  AND (
                    collection > ?
                    OR (collection = ? AND rkey > ?)
                  )
                ORDER BY collection, rkey
                LIMIT ?
                """,
                [
                    .text(sessionID),
                    .text(lastCollection), .text(lastCollection),
                    .text(lastRKey),
                    .integer(
                        PermissionedRemoteReplicaRecoveryBudgets
                            .maximumRowsPerPass
                    ),
                ]
            )
            guard page.count
                <= PermissionedRemoteReplicaRecoveryBudgets
                    .maximumRowsPerPass else {
                throw PermissionedRemoteReplicaRecoveryError.corruptStaging
            }
            guard let last = page.last,
                  let upperCollection = last.column("collection")?.string,
                  let upperRKey = last.column("rkey")?.string else {
                break
            }
            let lowerCollection = lastCollection
            let lowerRKey = lastRKey
            try await transaction {
                _ = try await requireActiveRemoteReplicaSession(
                    id: sessionID,
                    now: now,
                    allowed: [.preparing]
                )
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_remote_replica_records(
                        space_uri, repository_did, collection, rkey,
                        cid, generation
                    )
                    SELECT ?, ?, collection, rkey, cid, ?
                    FROM permissioned_remote_replica_import_index
                    WHERE session_id = ? AND consumed = 1
                      AND (
                        collection > ?
                        OR (collection = ? AND rkey > ?)
                      )
                      AND (
                        collection < ?
                        OR (collection = ? AND rkey <= ?)
                      )
                    ORDER BY collection, rkey
                    """,
                    [
                        .text(target.space.rawValue),
                        .text(target.repositoryDID),
                        .integer(Int(generation)), .text(sessionID),
                        .text(lowerCollection), .text(lowerCollection),
                        .text(lowerRKey),
                        .text(upperCollection), .text(upperCollection),
                        .text(upperRKey),
                    ]
                )
                try await requireRemoteReplicaChangeCount(page.count)
                try await testingHooks.afterRemoteReplicaMutatingSQL?(3)
            }
            lastCollection = upperCollection
            lastRKey = upperRKey
        }
    }

    private func requireRemoteReplicaChangeCount(
        _ expected: Int
    ) async throws {
        let rows = try await connection.query(
            "SELECT changes() AS count"
        )
        guard remoteReplicaInteger(rows.first, "count") == expected else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
    }

    private func preparedRemoteReplicaGeneration(
        sessionID: String
    ) async throws -> UInt64? {
        let rows = try await connection.query(
            """
            SELECT prepared_generation
            FROM permissioned_remote_replica_import_sessions
            WHERE session_id = ?
            """,
            [.text(sessionID)]
        )
        guard rows.count == 1, let row = rows.first else {
            throw PermissionedRemoteReplicaRecoveryError.unknownSession
        }
        guard let raw = row.column("prepared_generation") else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        if raw.isNull { return nil }
        guard case let .integer(value) = raw, value > 0 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        return UInt64(value)
    }

    private func cleanupRemoteReplicaImportSessionBatched(
        sessionID: String,
        requiredStatus: PermissionedRemoteReplicaImportStatus
    ) async throws {
        let bindings: [SQLiteData] = [
            .text(sessionID), .text(requiredStatus.rawValue),
        ]
        let statements = [
            """
            DELETE FROM permissioned_remote_replica_import_block_chunks
            WHERE rowid IN (
                SELECT chunks.rowid
                FROM permissioned_remote_replica_import_block_chunks
                    AS chunks
                JOIN permissioned_remote_replica_import_sessions AS sessions
                  ON sessions.session_id = chunks.session_id
                WHERE chunks.session_id = ? AND sessions.status = ?
                ORDER BY chunks.rowid
                LIMIT ?
            )
            """,
            """
            DELETE FROM permissioned_remote_replica_import_index
            WHERE rowid IN (
                SELECT entries.rowid
                FROM permissioned_remote_replica_import_index AS entries
                JOIN permissioned_remote_replica_import_sessions AS sessions
                  ON sessions.session_id = entries.session_id
                WHERE entries.session_id = ? AND sessions.status = ?
                ORDER BY entries.rowid
                LIMIT ?
            )
            """,
            """
            DELETE FROM permissioned_remote_replica_import_blocks
            WHERE rowid IN (
                SELECT blocks.rowid
                FROM permissioned_remote_replica_import_blocks AS blocks
                JOIN permissioned_remote_replica_import_sessions AS sessions
                  ON sessions.session_id = blocks.session_id
                WHERE blocks.session_id = ? AND sessions.status = ?
                ORDER BY blocks.rowid
                LIMIT ?
            )
            """,
        ]
        for statement in statements {
            while try await deleteRemoteReplicaRowsBatch(
                statement,
                bindings: bindings
            ) > 0 {}
        }
        try await transaction {
            let deleted = try await connection.query(
                """
                DELETE FROM permissioned_remote_replica_import_sessions
                WHERE session_id = ? AND status = ?
                  AND NOT EXISTS (
                    SELECT 1
                    FROM permissioned_remote_replica_import_block_chunks
                    WHERE session_id = ?
                  )
                  AND NOT EXISTS (
                    SELECT 1
                    FROM permissioned_remote_replica_import_index
                    WHERE session_id = ?
                  )
                  AND NOT EXISTS (
                    SELECT 1
                    FROM permissioned_remote_replica_import_blocks
                    WHERE session_id = ?
                  )
                RETURNING session_id
                """,
                [
                    .text(sessionID), .text(requiredStatus.rawValue),
                    .text(sessionID), .text(sessionID), .text(sessionID),
                ]
            )
            guard deleted.count <= 1 else {
                throw PermissionedRemoteReplicaRecoveryError.corruptStaging
            }
            if deleted.isEmpty {
                let remaining = try await connection.query(
                    """
                    SELECT status
                    FROM permissioned_remote_replica_import_sessions
                    WHERE session_id = ?
                    LIMIT 2
                    """,
                    [.text(sessionID)]
                )
                guard remaining.isEmpty else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .invalidStatus
                }
            }
        }
    }

    private func cleanupUnpublishedRemoteReplicaGenerationBatched(
        sessionID: String,
        target: PermissionedRemoteReplicaTarget,
        generation: UInt64
    ) async throws {
        guard target.receiverDID == accountDID,
              generation > 0, generation <= UInt64(Int.max) else {
            throw PermissionedRemoteReplicaRecoveryError.receiverMismatch
        }
        guard try await remoteReplicaGenerationCleanupOwnershipMatches(
            sessionID: sessionID,
            target: target,
            generation: generation
        ) else {
            // A concurrent recovery worker already removed this poisoned
            // owner. Its generation cleanup necessarily preceded deletion of
            // the owner row, so this cleanup is idempotently complete.
            return
        }
        try await requireRemoteReplicaGenerationUnpublished(
            target: target,
            generation: generation
        )
        let generationValue = Int(generation)
        let bindings: [SQLiteData] = [
            .text(target.space.rawValue), .text(target.repositoryDID),
            .integer(generationValue),
            .text(target.receiverDID), .text(target.space.rawValue),
            .text(target.repositoryDID), .integer(generationValue),
            .text(sessionID), .text(target.receiverDID),
            .text(target.space.rawValue), .text(target.repositoryDID),
            .integer(generationValue),
        ]
        let statements = [
            """
            DELETE FROM permissioned_remote_replica_records
            WHERE rowid IN (
                SELECT records.rowid
                FROM permissioned_remote_replica_records AS records
                WHERE records.space_uri = ?
                  AND records.repository_did = ?
                  AND records.generation = ?
                  AND NOT EXISTS (
                    SELECT 1
                    FROM permissioned_remote_replica_state AS state
                    WHERE state.receiver_did = ?
                      AND state.space_uri = ?
                      AND state.repository_did = ?
                      AND state.generation = ?
                  )
                  AND EXISTS (
                    SELECT 1
                    FROM permissioned_remote_replica_import_sessions
                        AS owner
                    WHERE owner.session_id = ?
                      AND owner.receiver_did = ?
                      AND owner.space_uri = ?
                      AND owner.repository_did = ?
                      AND owner.status = 'poisoned'
                      AND owner.prepared_generation = ?
                  )
                ORDER BY records.rowid
                LIMIT ?
            )
            """,
            """
            DELETE FROM permissioned_remote_replica_block_chunks
            WHERE rowid IN (
                SELECT chunks.rowid
                FROM permissioned_remote_replica_block_chunks AS chunks
                WHERE chunks.space_uri = ?
                  AND chunks.repository_did = ?
                  AND chunks.generation = ?
                  AND NOT EXISTS (
                    SELECT 1
                    FROM permissioned_remote_replica_state AS state
                    WHERE state.receiver_did = ?
                      AND state.space_uri = ?
                      AND state.repository_did = ?
                      AND state.generation = ?
                  )
                  AND EXISTS (
                    SELECT 1
                    FROM permissioned_remote_replica_import_sessions
                        AS owner
                    WHERE owner.session_id = ?
                      AND owner.receiver_did = ?
                      AND owner.space_uri = ?
                      AND owner.repository_did = ?
                      AND owner.status = 'poisoned'
                      AND owner.prepared_generation = ?
                  )
                ORDER BY chunks.rowid
                LIMIT ?
            )
            """,
            """
            DELETE FROM permissioned_remote_replica_blocks
            WHERE rowid IN (
                SELECT blocks.rowid
                FROM permissioned_remote_replica_blocks AS blocks
                WHERE blocks.space_uri = ?
                  AND blocks.repository_did = ?
                  AND blocks.generation = ?
                  AND NOT EXISTS (
                    SELECT 1
                    FROM permissioned_remote_replica_state AS state
                    WHERE state.receiver_did = ?
                      AND state.space_uri = ?
                      AND state.repository_did = ?
                      AND state.generation = ?
                  )
                  AND EXISTS (
                    SELECT 1
                    FROM permissioned_remote_replica_import_sessions
                        AS owner
                    WHERE owner.session_id = ?
                      AND owner.receiver_did = ?
                      AND owner.space_uri = ?
                      AND owner.repository_did = ?
                      AND owner.status = 'poisoned'
                      AND owner.prepared_generation = ?
                  )
                ORDER BY blocks.rowid
                LIMIT ?
            )
            """,
        ]
        for statement in statements {
            while try await deleteRemoteReplicaRowsBatch(
                statement,
                bindings: bindings
            ) > 0 {}
        }
        try await requireRemoteReplicaGenerationUnpublished(
            target: target,
            generation: generation
        )
    }

    private func cleanupObsoleteRemoteReplicaGenerationsBatched(
        target: PermissionedRemoteReplicaTarget,
        liveGeneration: UInt64
    ) async throws {
        guard target.receiverDID == accountDID,
              liveGeneration > 0,
              liveGeneration <= UInt64(Int.max) else {
            throw PermissionedRemoteReplicaRecoveryError.receiverMismatch
        }
        guard try await remoteReplicaLiveGenerationMatches(
            target: target,
            generation: liveGeneration
        ) else { return }
        let liveValue = Int(liveGeneration)
        let bindings: [SQLiteData] = [
            .text(target.space.rawValue), .text(target.repositoryDID),
            .integer(liveValue),
            .text(target.receiverDID), .text(target.space.rawValue),
            .text(target.repositoryDID), .integer(liveValue),
        ]
        let statements = [
            """
            DELETE FROM permissioned_remote_replica_records
            WHERE rowid IN (
                SELECT records.rowid
                FROM permissioned_remote_replica_records AS records
                WHERE records.space_uri = ?
                  AND records.repository_did = ?
                  AND records.generation < ?
                  AND EXISTS (
                    SELECT 1
                    FROM permissioned_remote_replica_state AS state
                    WHERE state.receiver_did = ?
                      AND state.space_uri = ?
                      AND state.repository_did = ?
                      AND state.generation = ?
                  )
                ORDER BY records.rowid
                LIMIT ?
            )
            """,
            """
            DELETE FROM permissioned_remote_replica_block_chunks
            WHERE rowid IN (
                SELECT chunks.rowid
                FROM permissioned_remote_replica_block_chunks AS chunks
                WHERE chunks.space_uri = ?
                  AND chunks.repository_did = ?
                  AND chunks.generation < ?
                  AND EXISTS (
                    SELECT 1
                    FROM permissioned_remote_replica_state AS state
                    WHERE state.receiver_did = ?
                      AND state.space_uri = ?
                      AND state.repository_did = ?
                      AND state.generation = ?
                  )
                ORDER BY chunks.rowid
                LIMIT ?
            )
            """,
            """
            DELETE FROM permissioned_remote_replica_blocks
            WHERE rowid IN (
                SELECT blocks.rowid
                FROM permissioned_remote_replica_blocks AS blocks
                WHERE blocks.space_uri = ?
                  AND blocks.repository_did = ?
                  AND blocks.generation < ?
                  AND EXISTS (
                    SELECT 1
                    FROM permissioned_remote_replica_state AS state
                    WHERE state.receiver_did = ?
                      AND state.space_uri = ?
                      AND state.repository_did = ?
                      AND state.generation = ?
                  )
                ORDER BY blocks.rowid
                LIMIT ?
            )
            """,
        ]
        for statement in statements {
            while try await deleteRemoteReplicaRowsBatch(
                statement,
                bindings: bindings
            ) > 0 {}
        }
    }

    private func cleanupObsoleteRemoteReplicaGenerationsAtStartup()
        async throws
    {
        var lastSpace = ""
        var lastRepository = ""
        while true {
            let page = try await connection.query(
                """
                SELECT receiver_did, space_uri, repository_did, generation
                FROM permissioned_remote_replica_state
                WHERE space_uri > ?
                   OR (space_uri = ? AND repository_did > ?)
                ORDER BY space_uri, repository_did
                LIMIT ?
                """,
                [
                    .text(lastSpace), .text(lastSpace),
                    .text(lastRepository),
                    .integer(
                        PermissionedRemoteReplicaRecoveryBudgets
                            .maximumRowsPerPass
                    ),
                ]
            )
            guard page.count
                    <= PermissionedRemoteReplicaRecoveryBudgets
                        .maximumRowsPerPass else {
                throw PermissionedRemoteReplicaRecoveryError.corruptReplica
            }
            guard let last = page.last else { return }
            for row in page {
                let receiverDID = remoteReplicaText(row, "receiver_did")
                let generation = remoteReplicaInteger(row, "generation")
                guard receiverDID == accountDID, generation > 0 else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptReplica
                }
                let target = try PermissionedRemoteReplicaTarget(
                    receiverDID: receiverDID,
                    space: try SpaceURI(
                        remoteReplicaText(row, "space_uri")
                    ),
                    repositoryDID: remoteReplicaText(
                        row, "repository_did"
                    )
                )
                try await cleanupObsoleteRemoteReplicaGenerationsBatched(
                    target: target,
                    liveGeneration: UInt64(generation)
                )
            }
            lastSpace = remoteReplicaText(last, "space_uri")
            lastRepository = remoteReplicaText(last, "repository_did")
            guard !lastSpace.isEmpty, !lastRepository.isEmpty else {
                throw PermissionedRemoteReplicaRecoveryError.corruptReplica
            }
        }
    }

    private func deleteRemoteReplicaRowsBatch(
        _ statement: String,
        bindings: [SQLiteData]
    ) async throws -> Int {
        try await transaction {
            _ = try await connection.query(
                statement,
                bindings + [
                    .integer(
                        PermissionedRemoteReplicaRecoveryBudgets
                            .maximumRowsPerPass
                    ),
                ]
            )
            let rows = try await connection.query(
                "SELECT changes() AS count"
            )
            let changed = remoteReplicaInteger(rows.first, "count")
            guard (0 ... PermissionedRemoteReplicaRecoveryBudgets
                .maximumRowsPerPass).contains(changed) else {
                throw PermissionedRemoteReplicaRecoveryError.corruptReplica
            }
            return changed
        }
    }

    private func requireRemoteReplicaGenerationUnpublished(
        target: PermissionedRemoteReplicaTarget,
        generation: UInt64
    ) async throws {
        let rows = try await connection.query(
            """
            SELECT generation
            FROM permissioned_remote_replica_state
            WHERE receiver_did = ? AND space_uri = ?
              AND repository_did = ? AND generation = ?
            LIMIT 1
            """,
            [
                .text(target.receiverDID),
                .text(target.space.rawValue),
                .text(target.repositoryDID),
                .integer(Int(generation)),
            ]
        )
        guard rows.isEmpty else {
            throw PermissionedRemoteReplicaRecoveryError.targetCASConflict
        }
    }

    private func remoteReplicaGenerationCleanupOwnershipMatches(
        sessionID: String,
        target: PermissionedRemoteReplicaTarget,
        generation: UInt64
    ) async throws -> Bool {
        let rows = try await connection.query(
            """
            SELECT 1
            FROM permissioned_remote_replica_import_sessions
            WHERE session_id = ? AND receiver_did = ?
              AND space_uri = ? AND repository_did = ?
              AND status = 'poisoned' AND prepared_generation = ?
            LIMIT 2
            """,
            [
                .text(sessionID), .text(target.receiverDID),
                .text(target.space.rawValue),
                .text(target.repositoryDID), .integer(Int(generation)),
            ]
        )
        guard rows.count <= 1 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        return rows.count == 1
    }

    private func remoteReplicaLiveGenerationMatches(
        target: PermissionedRemoteReplicaTarget,
        generation: UInt64
    ) async throws -> Bool {
        let rows = try await connection.query(
            """
            SELECT 1
            FROM permissioned_remote_replica_state
            WHERE receiver_did = ? AND space_uri = ?
              AND repository_did = ? AND generation = ?
            LIMIT 2
            """,
            [
                .text(target.receiverDID),
                .text(target.space.rawValue),
                .text(target.repositoryDID),
                .integer(Int(generation)),
            ]
        )
        guard rows.count <= 1 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        return rows.count == 1
    }

    /// Revalidates a prepared or live generation without materializing the
    /// repository. Every result set is bounded either by the fixed row-page
    /// budget or by the fixed per-record chunk budget.
    private func validateRemoteReplicaGeneration(
        target: PermissionedRemoteReplicaTarget,
        generation: UInt64,
        expectedCommitment: Data
    ) async throws -> RemoteReplicaProjectionValidation {
        guard generation > 0, generation <= UInt64(Int.max),
              expectedCommitment.count == 32 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        let generationValue = Int(generation)
        let recordCountRows = try await connection.query(
            """
            SELECT COUNT(*) AS count
            FROM permissioned_remote_replica_records
            WHERE space_uri = ? AND repository_did = ?
              AND generation = ?
            """,
            [
                .text(target.space.rawValue),
                .text(target.repositoryDID),
                .integer(generationValue),
            ]
        )
        let recordCount = remoteReplicaInteger(
            recordCountRows.first, "count"
        )
        guard recordCount >= 0,
              recordCount
                <= SpaceCARRecoveryLimits.absoluteMaximumIndexEntries else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }

        var indexHasher = SHA256()
        let indexPrefix: Data
        do {
            indexPrefix = try SpaceCARCodec.streamingIndexPrefix(
                recordCount: recordCount
            )
        } catch {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        indexHasher.update(data: indexPrefix)
        var ltHash = LtHash()
        var projectionHasher = SHA256()
        projectionHasher.update(data: Data(
            "swan.permissioned.remote-replica.projection.v1".utf8
        ))
        var recordsSeen = 0
        var lastPathLength = -1
        var lastPath = Data()
        while recordsSeen < recordCount {
            let page = try await connection.query(
                """
                SELECT collection, rkey, cid,
                       CAST(collection || '/' || rkey AS BLOB) AS path
                FROM permissioned_remote_replica_records
                WHERE space_uri = ? AND repository_did = ?
                  AND generation = ?
                  AND (
                    length(CAST(collection || '/' || rkey AS BLOB)),
                    CAST(collection || '/' || rkey AS BLOB)
                  ) > (?, ?)
                ORDER BY
                  length(CAST(collection || '/' || rkey AS BLOB)),
                  CAST(collection || '/' || rkey AS BLOB)
                LIMIT ?
                """,
                [
                    .text(target.space.rawValue),
                    .text(target.repositoryDID),
                    .integer(generationValue),
                    .integer(lastPathLength),
                    lastPath.sqliteData!,
                    .integer(
                        PermissionedRemoteReplicaRecoveryBudgets
                            .maximumRowsPerPass
                    ),
                ]
            )
            guard !page.isEmpty,
                  page.count
                    <= PermissionedRemoteReplicaRecoveryBudgets
                        .maximumRowsPerPass else {
                throw PermissionedRemoteReplicaRecoveryError.corruptReplica
            }
            for row in page {
                guard let pathBytes = remoteReplicaData(row, "path"),
                      let path = String(data: pathBytes, encoding: .utf8),
                      Data(path.utf8) == pathBytes,
                      pathBytes.count > lastPathLength
                        || (
                            pathBytes.count == lastPathLength
                                && lastPath
                                    .lexicographicallyPrecedes(pathBytes)
                        ),
                      let cid = try? CID.parse(
                          remoteReplicaText(row, "cid")
                      ) else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptReplica
                }
                try validateLiveRemoteReplicaCID(cid)
                let parsed = try liveRemoteReplicaPath(
                    path,
                    target: target
                )
                guard parsed.collection
                        == remoteReplicaText(row, "collection"),
                      parsed.rkey == remoteReplicaText(row, "rkey") else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptReplica
                }
                let encodedEntry: Data
                do {
                    encodedEntry = try SpaceCARCodec.streamingIndexEntry(
                        path: path,
                        cid: cid
                    )
                } catch {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptReplica
                }
                indexHasher.update(data: encodedEntry)
                ltHash.add(element: "\(path)/\(cid.string)")
                remoteReplicaDigestAppend(
                    pathBytes, to: &projectionHasher
                )
                remoteReplicaDigestAppend(
                    Data(cid.string.utf8), to: &projectionHasher
                )
                lastPathLength = pathBytes.count
                lastPath = pathBytes
                recordsSeen += 1
            }
        }
        guard recordsSeen == recordCount,
              ltHash.commitment == expectedCommitment else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        let indexRoot = CID(
            codec: .dagCBOR,
            multihash: .init(
                algorithm: Multihash.sha256Code,
                length: Multihash.sha256Length,
                digest: Data(indexHasher.finalize())
            )
        )

        let blockCountRows = try await connection.query(
            """
            SELECT COUNT(*) AS count
            FROM permissioned_remote_replica_blocks
            WHERE space_uri = ? AND repository_did = ?
              AND generation = ?
            """,
            [
                .text(target.space.rawValue),
                .text(target.repositoryDID),
                .integer(generationValue),
            ]
        )
        let uniqueBlockCount = remoteReplicaInteger(
            blockCountRows.first, "count"
        )
        guard uniqueBlockCount >= 0,
              uniqueBlockCount
                <= SpaceCARRecoveryLimits.absoluteMaximumUniqueBlocks else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        var blocksSeen = 0
        var lastBlockCID = ""
        while blocksSeen < uniqueBlockCount {
            let page = try await connection.query(
                """
                SELECT cid, byte_count, chunk_count
                FROM permissioned_remote_replica_blocks
                WHERE space_uri = ? AND repository_did = ?
                  AND generation = ? AND cid > ?
                ORDER BY cid
                LIMIT ?
                """,
                [
                    .text(target.space.rawValue),
                    .text(target.repositoryDID),
                    .integer(generationValue),
                    .text(lastBlockCID),
                    .integer(
                        PermissionedRemoteReplicaRecoveryBudgets
                            .maximumRowsPerPass
                    ),
                ]
            )
            guard !page.isEmpty,
                  page.count
                    <= PermissionedRemoteReplicaRecoveryBudgets
                        .maximumRowsPerPass else {
                throw PermissionedRemoteReplicaRecoveryError.corruptReplica
            }
            for block in page {
                guard let expectedCID = try? CID.parse(
                    remoteReplicaText(block, "cid")
                ), expectedCID.string > lastBlockCID else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptReplica
                }
                try validateLiveRemoteReplicaCID(expectedCID)
                let byteCount = remoteReplicaInteger(
                    block, "byte_count"
                )
                let chunkCount = remoteReplicaInteger(
                    block, "chunk_count"
                )
                guard (1 ... SpaceCARRecoveryLimits
                    .absoluteMaximumRecordBytes).contains(byteCount),
                      (1 ... PermissionedRemoteReplicaRecoveryBudgets
                        .maximumChunksPerRecord).contains(chunkCount) else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptReplica
                }
                let chunks = try await connection.query(
                    """
                    SELECT chunk_index, bytes
                    FROM permissioned_remote_replica_block_chunks
                    WHERE space_uri = ? AND repository_did = ?
                      AND generation = ? AND cid = ?
                    ORDER BY chunk_index
                    LIMIT ?
                    """,
                    [
                        .text(target.space.rawValue),
                        .text(target.repositoryDID),
                        .integer(generationValue),
                        .text(expectedCID.string),
                        .integer(
                            PermissionedRemoteReplicaRecoveryBudgets
                                .maximumChunksPerRecord + 1
                        ),
                    ]
                )
                guard chunks.count == chunkCount else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptReplica
                }
                var bodyHasher = SHA256()
                var total = 0
                for (expectedIndex, chunk) in chunks.enumerated() {
                    guard remoteReplicaInteger(chunk, "chunk_index")
                            == expectedIndex,
                          let bytes = remoteReplicaData(chunk, "bytes"),
                          !bytes.isEmpty,
                          bytes.count
                            <= PermissionedRemoteReplicaRecoveryBudgets
                                .maximumChunkBytes,
                          total <= byteCount - bytes.count else {
                        throw PermissionedRemoteReplicaRecoveryError
                            .corruptReplica
                    }
                    bodyHasher.update(data: bytes)
                    total += bytes.count
                }
                let calculatedCID = CID(
                    codec: .dagCBOR,
                    multihash: .init(
                        algorithm: Multihash.sha256Code,
                        length: Multihash.sha256Length,
                        digest: Data(bodyHasher.finalize())
                    )
                )
                guard total == byteCount,
                      calculatedCID == expectedCID else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptReplica
                }
                lastBlockCID = expectedCID.string
                blocksSeen += 1
            }
        }
        guard blocksSeen == uniqueBlockCount else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }

        let missing = try await connection.query(
            """
            SELECT 1
            FROM permissioned_remote_replica_records AS records
            LEFT JOIN permissioned_remote_replica_blocks AS blocks
              ON blocks.space_uri = records.space_uri
             AND blocks.repository_did = records.repository_did
             AND blocks.generation = records.generation
             AND blocks.cid = records.cid
            WHERE records.space_uri = ? AND records.repository_did = ?
              AND records.generation = ? AND blocks.cid IS NULL
            LIMIT 1
            """,
            [
                .text(target.space.rawValue),
                .text(target.repositoryDID),
                .integer(generationValue),
            ]
        )
        let extra = try await connection.query(
            """
            SELECT 1
            FROM permissioned_remote_replica_blocks AS blocks
            LEFT JOIN permissioned_remote_replica_records AS records
              ON records.space_uri = blocks.space_uri
             AND records.repository_did = blocks.repository_did
             AND records.generation = blocks.generation
             AND records.cid = blocks.cid
            WHERE blocks.space_uri = ? AND blocks.repository_did = ?
              AND blocks.generation = ? AND records.cid IS NULL
            LIMIT 1
            """,
            [
                .text(target.space.rawValue),
                .text(target.repositoryDID),
                .integer(generationValue),
            ]
        )
        let orphanChunks = try await connection.query(
            """
            SELECT 1
            FROM permissioned_remote_replica_block_chunks AS chunks
            LEFT JOIN permissioned_remote_replica_blocks AS blocks
              ON blocks.space_uri = chunks.space_uri
             AND blocks.repository_did = chunks.repository_did
             AND blocks.generation = chunks.generation
             AND blocks.cid = chunks.cid
            WHERE chunks.space_uri = ? AND chunks.repository_did = ?
              AND chunks.generation = ? AND blocks.cid IS NULL
            LIMIT 1
            """,
            [
                .text(target.space.rawValue),
                .text(target.repositoryDID),
                .integer(generationValue),
            ]
        )
        guard missing.isEmpty, extra.isEmpty, orphanChunks.isEmpty else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        return RemoteReplicaProjectionValidation(
            indexRoot: indexRoot,
            ltHash: ltHash.serialized,
            commitment: ltHash.commitment,
            projectionDigest: Data(projectionHasher.finalize()),
            recordCount: recordCount,
            uniqueBlockCount: uniqueBlockCount
        )
    }

    private func loadPermissionedRemoteReplicaSession(
        id: String
    ) async throws -> PermissionedRemoteReplicaImportSession {
        let rows = try await connection.query(
            """
            SELECT *
            FROM permissioned_remote_replica_import_sessions
            WHERE session_id = ?
            """,
            [.text(id)]
        )
        guard rows.count == 1, let row = rows.first else {
            throw PermissionedRemoteReplicaRecoveryError.unknownSession
        }
        return try decodePermissionedRemoteReplicaSession(row)
    }

    private func requireActiveRemoteReplicaSession(
        id: String,
        now: Int64,
        allowed: Set<PermissionedRemoteReplicaImportStatus>
    ) async throws -> PermissionedRemoteReplicaImportSession {
        guard now >= 0 else {
            throw PermissionedRemoteReplicaRecoveryError.invalidTimestamp
        }
        let session = try await loadPermissionedRemoteReplicaSession(id: id)
        guard session.expiresAt > now else {
            throw PermissionedRemoteReplicaRecoveryError.expiredSession
        }
        guard allowed.contains(session.status) else {
            if session.status == .poisoned {
                throw PermissionedRemoteReplicaRecoveryError.poisonedSession
            }
            throw PermissionedRemoteReplicaRecoveryError.invalidStatus
        }
        return session
    }

    private func decodePermissionedRemoteReplicaSession(
        _ row: SQLiteRow
    ) throws -> PermissionedRemoteReplicaImportSession {
        let target = try PermissionedRemoteReplicaTarget(
            receiverDID: remoteReplicaText(row, "receiver_did"),
            space: try SpaceURI(
                remoteReplicaText(row, "space_uri")
            ),
            repositoryDID: remoteReplicaText(row, "repository_did")
        )
        let expected: PermissionedRemoteReplicaHead?
        if let generation = row.column("expected_base_generation")?.integer {
            guard generation > 0 else {
                throw PermissionedRemoteReplicaRecoveryError.corruptStaging
            }
            expected = try PermissionedRemoteReplicaHead(
                target: target,
                generation: UInt64(generation),
                wireRevision: try TID(tidString:
                    remoteReplicaText(row, "expected_base_wire_revision")
                ),
                historyFloorWireRevision: try TID(tidString:
                    remoteReplicaText(row, "expected_base_history_floor")
                ),
                ltHash: try requiredRemoteReplicaData(
                    row, "expected_base_lthash"
                ),
                commitment: try requiredRemoteReplicaData(
                    row, "expected_base_commitment"
                ),
                stateMarker: try requiredRemoteReplicaData(
                    row, "expected_base_marker"
                )
            )
        } else {
            expected = nil
        }
        let freshness: PermissionedRemoteReplicaFreshnessWitness?
        if let revision = row.column("freshness_wire_revision")?.string {
            freshness = try PermissionedRemoteReplicaFreshnessWitness(
                wireRevision: try TID(tidString: revision),
                commitment: try requiredRemoteReplicaData(
                    row, "freshness_commitment"
                )
            )
        } else {
            freshness = nil
        }
        let limits = try SpaceCARRecoveryLimits(
            maximumCARBytes: remoteReplicaInteger(
                row, "maximum_car_bytes"
            ),
            maximumRecordBytes: remoteReplicaInteger(
                row, "maximum_record_bytes"
            ),
            maximumIndexEntries: remoteReplicaInteger(
                row, "maximum_index_entries"
            ),
            maximumUniqueBlocks: remoteReplicaInteger(
                row, "maximum_unique_blocks"
            )
        )
        let source = try PermissionedRemoteReplicaSourceIdentity(
            persistedOrigin: remoteReplicaText(row, "source_origin"),
            repositoryDID: target.repositoryDID,
            verifierIdentity: remoteReplicaText(row, "verifier_identity")
        )
        let binding = try PermissionedRemoteReplicaImportBinding(
            requestID: remoteReplicaText(row, "request_id"),
            requestDigest: requiredRemoteReplicaData(row, "request_digest"),
            source: source,
            target: target,
            expectedBase: expected,
            freshnessWitness: freshness,
            profileID: remoteReplicaText(row, "profile_id"),
            limits: limits
        )
        guard let status = PermissionedRemoteReplicaImportStatus(
            rawValue: remoteReplicaText(row, "status")
        ) else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        return PermissionedRemoteReplicaImportSession(
            id: remoteReplicaText(row, "session_id"),
            binding: binding,
            createdAt: Int64(remoteReplicaInteger(row, "created_at")),
            expiresAt: Int64(remoteReplicaInteger(row, "expires_at")),
            status: status
        )
    }

    private func loadPermissionedRemoteReplicaHead(
        target: PermissionedRemoteReplicaTarget
    ) async throws -> PermissionedRemoteReplicaHead? {
        let rows = try await connection.query(
            """
            SELECT *
            FROM permissioned_remote_replica_state
            WHERE space_uri = ? AND repository_did = ?
            """,
            [.text(target.space.rawValue), .text(target.repositoryDID)]
        )
        guard rows.count <= 1 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        guard let row = rows.first else { return nil }
        guard remoteReplicaText(row, "receiver_did")
            == target.receiverDID else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        let generation = remoteReplicaInteger(row, "generation")
        guard generation > 0 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        guard let wireRevision = try? TID(tidString:
                remoteReplicaText(row, "wire_revision")
              ),
              let floor = try? TID(tidString:
                remoteReplicaText(row, "history_floor_wire_revision")
              ),
              let ltHash = remoteReplicaData(row, "lthash"),
              let commitment = remoteReplicaData(row, "commitment"),
              let marker = remoteReplicaData(row, "state_marker") else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        let expectedMarker = remoteReplicaStateMarker(
            target: target,
            generation: UInt64(generation),
            wireRevision: wireRevision,
            historyFloor: floor,
            commitment: commitment
        )
        guard ltHash.count == LtHash.byteCount,
              Data(SHA256.hash(data: ltHash)) == commitment,
              marker == expectedMarker else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        do {
            return try PermissionedRemoteReplicaHead(
                target: target,
                generation: UInt64(generation),
                wireRevision: wireRevision,
                historyFloorWireRevision: floor,
                ltHash: ltHash,
                commitment: commitment,
                stateMarker: marker
            )
        } catch {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
    }

    private func validateStagedRemoteReplica(
        sessionID: String,
        binding: PermissionedRemoteReplicaImportBinding
    ) async throws -> StagedPermissionedRemoteReplicaValidation {
        let sessionRows = try await connection.query(
            """
            SELECT commit_root_cid, index_root_cid,
                   verified_commit_body, verified_commit_body_digest
            FROM permissioned_remote_replica_import_sessions
            WHERE session_id = ?
            """,
            [.text(sessionID)]
        )
        guard sessionRows.count == 1, let sessionRow = sessionRows.first,
              let commitRaw = sessionRow.column("commit_root_cid")?.string,
              let indexRaw = sessionRow.column("index_root_cid")?.string,
              let commitRoot = try? CID.parse(commitRaw),
              let indexRoot = try? CID.parse(indexRaw) else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        try validateRemoteReplicaCID(commitRoot)
        try validateRemoteReplicaCID(indexRoot)
        let commitBody = try requiredRemoteReplicaData(
            sessionRow, "verified_commit_body"
        )
        guard CID.fromDAGCBOR(commitBody) == commitRoot else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        let commitDigest = Data(SHA256.hash(data: commitBody))
        guard commitDigest == remoteReplicaData(
            sessionRow, "verified_commit_body_digest"
        ) else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        let envelope: SpaceCommitEnvelope
        do {
            envelope = try SpaceCARCodec.structurallyValidateRecoveryCommit(
                commitBody,
                space: binding.target.space,
                author: binding.target.repositoryDID
            )
        } catch {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        let wireRevision: TID
        do {
            wireRevision = try TID(tidString: envelope.context.rev)
        } catch {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }

        let indexCountRows = try await connection.query(
            """
            SELECT COUNT(*) AS count
            FROM permissioned_remote_replica_import_index
            WHERE session_id = ?
            """,
            [.text(sessionID)]
        )
        let recordCount = remoteReplicaInteger(
            indexCountRows.first, "count"
        )
        guard recordCount >= 0,
              recordCount <= binding.limits.maximumIndexEntries else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        var indexHasher = SHA256()
        let prefix = try SpaceCARCodec.streamingIndexPrefix(
            recordCount: recordCount
        )
        indexHasher.update(data: prefix)
        var ltHash = LtHash()
        var projectionHasher = SHA256()
        projectionHasher.update(data: Data(
            "swan.permissioned.remote-replica.projection.v1".utf8
        ))
        var indexedRowsSeen = 0
        var lastPathLength = -1
        var lastPath = Data()
        while indexedRowsSeen < recordCount {
            let page = try await connection.query(
                """
                SELECT path, collection, rkey, cid, consumed
                FROM permissioned_remote_replica_import_index
                WHERE session_id = ?
                  AND (
                    length(path) > ?
                    OR (length(path) = ? AND path > ?)
                  )
                ORDER BY length(path), path
                LIMIT ?
                """,
                [
                    .text(sessionID),
                    .integer(lastPathLength),
                    .integer(lastPathLength),
                    lastPath.sqliteData!,
                    .integer(
                        PermissionedRemoteReplicaRecoveryBudgets
                            .maximumRowsPerPass
                    ),
                ]
            )
            guard !page.isEmpty,
                  page.count
                    <= PermissionedRemoteReplicaRecoveryBudgets
                        .maximumRowsPerPass else {
                throw PermissionedRemoteReplicaRecoveryError.corruptStaging
            }
            for row in page {
                guard remoteReplicaInteger(row, "consumed") == 1,
                      let pathBytes = remoteReplicaData(row, "path"),
                      let path = String(data: pathBytes, encoding: .utf8),
                      Data(path.utf8) == pathBytes,
                      pathBytes.count > lastPathLength
                        || (
                            pathBytes.count == lastPathLength
                                && lastPath
                                    .lexicographicallyPrecedes(pathBytes)
                        ),
                      let cid = try? CID.parse(
                          remoteReplicaText(row, "cid")
                      ) else {
                    throw PermissionedRemoteReplicaRecoveryError.corruptStaging
                }
                let parsed = try remoteReplicaPath(
                    path, target: binding.target
                )
                guard parsed.collection
                        == remoteReplicaText(row, "collection"),
                      parsed.rkey == remoteReplicaText(row, "rkey") else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptStaging
                }
                let entry = try SpaceCARCodec.streamingIndexEntry(
                    path: path, cid: cid
                )
                indexHasher.update(data: entry)
                ltHash.add(element: "\(path)/\(cid.string)")
                remoteReplicaDigestAppend(
                    pathBytes, to: &projectionHasher
                )
                remoteReplicaDigestAppend(
                    Data(cid.string.utf8), to: &projectionHasher
                )
                lastPathLength = pathBytes.count
                lastPath = pathBytes
                indexedRowsSeen += 1
            }
        }
        guard indexedRowsSeen == recordCount else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        let calculatedIndex = CID(
            codec: .dagCBOR,
            multihash: .init(
                algorithm: Multihash.sha256Code,
                length: Multihash.sha256Length,
                digest: Data(indexHasher.finalize())
            )
        )
        guard calculatedIndex == indexRoot,
              ltHash.commitment == envelope.commitment else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }

        let blockCountRows = try await connection.query(
            """
            SELECT COUNT(*) AS count
            FROM permissioned_remote_replica_import_blocks
            WHERE session_id = ?
            """,
            [.text(sessionID)]
        )
        let uniqueBlockCount = remoteReplicaInteger(
            blockCountRows.first, "count"
        )
        guard uniqueBlockCount >= 0,
              uniqueBlockCount <= binding.limits.maximumUniqueBlocks else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        var blocksSeen = 0
        var lastBlockCID = ""
        while blocksSeen < uniqueBlockCount {
            let blockPage = try await connection.query(
                """
                SELECT cid, byte_count, chunk_count, complete
                FROM permissioned_remote_replica_import_blocks
                WHERE session_id = ? AND cid > ?
                ORDER BY cid
                LIMIT ?
                """,
                [
                    .text(sessionID), .text(lastBlockCID),
                    .integer(
                        PermissionedRemoteReplicaRecoveryBudgets
                            .maximumRowsPerPass
                    ),
                ]
            )
            guard !blockPage.isEmpty,
                  blockPage.count
                    <= PermissionedRemoteReplicaRecoveryBudgets
                        .maximumRowsPerPass else {
                throw PermissionedRemoteReplicaRecoveryError.corruptStaging
            }
            for block in blockPage {
                guard remoteReplicaInteger(block, "complete") == 1,
                      let expectedCID = try? CID.parse(
                          remoteReplicaText(block, "cid")
                      ),
                      expectedCID.string > lastBlockCID else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .incompleteBlock
                }
                let byteCount = remoteReplicaInteger(
                    block, "byte_count"
                )
                let chunkCount = remoteReplicaInteger(
                    block, "chunk_count"
                )
                guard chunkCount > 0,
                      chunkCount
                        <= PermissionedRemoteReplicaRecoveryBudgets
                            .maximumChunksPerRecord else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .incompleteBlock
                }
                let chunks = try await connection.query(
                    """
                    SELECT chunk_index, bytes
                    FROM permissioned_remote_replica_import_block_chunks
                    WHERE session_id = ? AND cid = ?
                    ORDER BY chunk_index
                    LIMIT ?
                    """,
                    [
                        .text(sessionID), .text(expectedCID.string),
                        .integer(
                            PermissionedRemoteReplicaRecoveryBudgets
                                .maximumChunksPerRecord + 1
                        ),
                    ]
                )
                guard chunks.count == chunkCount else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .incompleteBlock
                }
                var hasher = SHA256()
                var total = 0
                for (expectedIndex, chunk) in chunks.enumerated() {
                    guard remoteReplicaInteger(chunk, "chunk_index")
                            == expectedIndex,
                          let bytes = remoteReplicaData(chunk, "bytes"),
                          !bytes.isEmpty,
                          bytes.count
                            <= PermissionedRemoteReplicaRecoveryBudgets
                                .maximumChunkBytes,
                          total <= byteCount - bytes.count else {
                        throw PermissionedRemoteReplicaRecoveryError
                            .invalidChunk
                    }
                    hasher.update(data: bytes)
                    total += bytes.count
                }
                let calculated = CID(
                    codec: .dagCBOR,
                    multihash: .init(
                        algorithm: Multihash.sha256Code,
                        length: Multihash.sha256Length,
                        digest: Data(hasher.finalize())
                    )
                )
                guard total == byteCount, calculated == expectedCID else {
                    throw PermissionedRemoteReplicaRecoveryError
                        .corruptStaging
                }
                lastBlockCID = expectedCID.string
                blocksSeen += 1
            }
        }
        guard blocksSeen == uniqueBlockCount else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        let missingRows = try await connection.query(
            """
            SELECT 1
            FROM permissioned_remote_replica_import_index AS idx
            LEFT JOIN permissioned_remote_replica_import_blocks AS blocks
              ON blocks.session_id = idx.session_id
             AND blocks.cid = idx.cid AND blocks.complete = 1
            WHERE idx.session_id = ? AND blocks.cid IS NULL
            LIMIT 1
            """,
            [.text(sessionID)]
        )
        let extraRows = try await connection.query(
            """
            SELECT 1
            FROM permissioned_remote_replica_import_blocks AS blocks
            LEFT JOIN permissioned_remote_replica_import_index AS idx
              ON idx.session_id = blocks.session_id
             AND idx.cid = blocks.cid
            WHERE blocks.session_id = ? AND idx.cid IS NULL
            LIMIT 1
            """,
            [.text(sessionID)]
        )
        let orphanChunkRows = try await connection.query(
            """
            SELECT 1
            FROM permissioned_remote_replica_import_block_chunks AS chunks
            LEFT JOIN permissioned_remote_replica_import_blocks AS blocks
              ON blocks.session_id = chunks.session_id
             AND blocks.cid = chunks.cid
            WHERE chunks.session_id = ? AND blocks.cid IS NULL
            LIMIT 1
            """,
            [.text(sessionID)]
        )
        guard missingRows.isEmpty, extraRows.isEmpty,
              orphanChunkRows.isEmpty else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        return StagedPermissionedRemoteReplicaValidation(
            commitRoot: commitRoot,
            indexRoot: indexRoot,
            wireRevision: wireRevision,
            ltHash: ltHash.serialized,
            commitment: ltHash.commitment,
            commitBodyDigest: commitDigest,
            projectionDigest: Data(projectionHasher.finalize()),
            recordCount: recordCount,
            uniqueBlockCount: uniqueBlockCount
        )
    }

    private func loadPermissionedRemoteReplicaResult(
        requestID: String,
        expectedBinding: PermissionedRemoteReplicaImportBinding
    ) async throws -> CommittedPermissionedRemoteReplicaRecovery? {
        let rows = try await connection.query(
            """
            SELECT *
            FROM permissioned_remote_replica_import_results
            WHERE request_id = ?
            """,
            [.text(requestID)]
        )
        guard rows.count <= 1 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        guard let row = rows.first else { return nil }
        guard remoteReplicaData(row, "request_digest")
                == expectedBinding.requestDigest,
              remoteReplicaData(row, "binding_digest")
                == permissionedRemoteReplicaBindingDigest(expectedBinding),
              remoteReplicaText(row, "source_origin")
                == expectedBinding.sourceOrigin,
              remoteReplicaText(row, "receiver_did")
                == expectedBinding.target.receiverDID,
              remoteReplicaText(row, "space_uri")
                == expectedBinding.target.space.rawValue,
              remoteReplicaText(row, "repository_did")
                == expectedBinding.target.repositoryDID,
              remoteReplicaText(row, "verifier_identity")
                == expectedBinding.verifierIdentity,
              remoteReplicaText(row, "profile_id")
                == expectedBinding.profileID else {
            throw PermissionedRemoteReplicaRecoveryError
                .conflictingRequestReuse
        }
        let storedBase = row.column("base_generation")?.integer
        let storedBaseGeneration = storedBase.flatMap {
            $0 >= 0 ? UInt64($0) : nil
        }
        guard storedBaseGeneration
            == expectedBinding.expectedBase?.generation else {
            throw PermissionedRemoteReplicaRecoveryError
                .conflictingRequestReuse
        }
        let target = expectedBinding.target
        let head = try PermissionedRemoteReplicaHead(
            target: target,
            generation: UInt64(remoteReplicaInteger(
                row, "installed_generation"
            )),
            wireRevision: try TID(tidString:
                remoteReplicaText(row, "installed_wire_revision")
            ),
            historyFloorWireRevision: try TID(tidString:
                remoteReplicaText(row, "installed_history_floor")
            ),
            ltHash: try requiredRemoteReplicaData(
                row, "installed_lthash"
            ),
            commitment: try requiredRemoteReplicaData(
                row, "installed_commitment"
            ),
            stateMarker: try requiredRemoteReplicaData(
                row, "installed_marker"
            )
        )
        let commitRoot = remoteReplicaText(row, "commit_root_cid")
        let indexRoot = remoteReplicaText(row, "index_root_cid")
        guard let commitCID = try? CID.parse(commitRoot),
              let indexCID = try? CID.parse(indexRoot) else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        try validateRemoteReplicaCID(commitCID)
        try validateRemoteReplicaCID(indexCID)
        let recordCount = remoteReplicaInteger(row, "record_count")
        let uniqueBlockCount = remoteReplicaInteger(
            row, "unique_block_count"
        )
        let committedAt = Int64(remoteReplicaInteger(row, "committed_at"))
        let expectedIntegrity = remoteReplicaResultIntegrityDigest(
            binding: expectedBinding,
            head: head,
            commitRoot: commitRoot,
            indexRoot: indexRoot,
            recordCount: recordCount,
            uniqueBlockCount: uniqueBlockCount,
            committedAt: committedAt
        )
        guard remoteReplicaData(row, "integrity_digest")
            == expectedIntegrity else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        return CommittedPermissionedRemoteReplicaRecovery(
            requestID: requestID,
            requestDigest: expectedBinding.requestDigest,
            verifierIdentity: expectedBinding.verifierIdentity,
            head: head,
            commitRootCID: commitRoot,
            indexRootCID: indexRoot,
            recordCount: recordCount,
            uniqueBlockCount: uniqueBlockCount,
            committedAt: committedAt
        )
    }

    private func remoteReplicaPath(
        _ path: String,
        target: PermissionedRemoteReplicaTarget
    ) throws -> (collection: String, rkey: String) {
        let components = path.split(
            separator: "/",
            omittingEmptySubsequences: false
        )
        guard components.count == 2 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        let uri = try SpaceRecordURI(
            space: target.space,
            author: target.repositoryDID,
            collection: String(components[0]),
            rkey: String(components[1])
        )
        return (uri.collection, uri.rkey)
    }

    private func validateRemoteReplicaCID(_ cid: CID) throws {
        guard cid.codec == .dagCBOR,
              cid.bytes.count == 36,
              cid.multihash.algorithm == Multihash.sha256Code,
              cid.multihash.length == Multihash.sha256Length,
              cid.multihash.digest.count == Int(Multihash.sha256Length)
        else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
    }

    private func validateLiveRemoteReplicaCID(_ cid: CID) throws {
        guard cid.codec == .dagCBOR,
              cid.bytes.count == 36,
              cid.multihash.algorithm == Multihash.sha256Code,
              cid.multihash.length == Multihash.sha256Length,
              cid.multihash.digest.count == Int(Multihash.sha256Length)
        else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
    }

    private func liveRemoteReplicaPath(
        _ path: String,
        target: PermissionedRemoteReplicaTarget
    ) throws -> (collection: String, rkey: String) {
        do {
            return try remoteReplicaPath(path, target: target)
        } catch {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
    }

    private func remoteReplicaStateMarker(
        target: PermissionedRemoteReplicaTarget,
        generation: UInt64,
        wireRevision: TID,
        historyFloor: TID,
        commitment: Data
    ) -> Data {
        var hasher = SHA256()
        hasher.update(data: Data(
            "swan.permissioned.remote-replica.state.v1".utf8
        ))
        remoteReplicaDigestAppend(
            Data(target.receiverDID.utf8), to: &hasher
        )
        remoteReplicaDigestAppend(
            Data(target.space.rawValue.utf8), to: &hasher
        )
        remoteReplicaDigestAppend(
            Data(target.repositoryDID.utf8), to: &hasher
        )
        var fixedGeneration = generation.bigEndian
        withUnsafeBytes(of: &fixedGeneration) {
            hasher.update(data: Data($0))
        }
        remoteReplicaDigestAppend(
            Data(wireRevision.toString().utf8), to: &hasher
        )
        remoteReplicaDigestAppend(
            Data(historyFloor.toString().utf8), to: &hasher
        )
        remoteReplicaDigestAppend(commitment, to: &hasher)
        return Data(hasher.finalize())
    }

    private func remoteReplicaResultIntegrityDigest(
        binding: PermissionedRemoteReplicaImportBinding,
        head: PermissionedRemoteReplicaHead,
        commitRoot: String,
        indexRoot: String,
        recordCount: Int,
        uniqueBlockCount: Int,
        committedAt: Int64
    ) -> Data {
        var hasher = SHA256()
        hasher.update(data: Data(
            "swan.permissioned.remote-replica.result.v1".utf8
        ))
        let values = [
            binding.requestID,
            binding.sourceOrigin,
            binding.target.receiverDID,
            binding.target.space.rawValue,
            binding.target.repositoryDID,
            binding.verifierIdentity,
            binding.profileID,
            head.wireRevision.toString(),
            head.historyFloorWireRevision.toString(),
            commitRoot,
            indexRoot,
        ]
        remoteReplicaDigestAppend(binding.requestDigest, to: &hasher)
        for value in values {
            remoteReplicaDigestAppend(Data(value.utf8), to: &hasher)
        }
        remoteReplicaDigestAppend(head.ltHash, to: &hasher)
        remoteReplicaDigestAppend(head.commitment, to: &hasher)
        remoteReplicaDigestAppend(head.stateMarker, to: &hasher)
        let integers = [
            Int64(binding.expectedBase?.generation ?? 0),
            Int64(head.generation),
            Int64(recordCount),
            Int64(uniqueBlockCount),
            committedAt,
        ]
        for integer in integers {
            var fixed = UInt64(bitPattern: integer).bigEndian
            withUnsafeBytes(of: &fixed) {
                hasher.update(data: Data($0))
            }
        }
        return Data(hasher.finalize())
    }

    /// The request digest is supplied by the caller and is useful for
    /// correlating a replay, but it is not a storage-authenticated
    /// description of the binding. This digest is computed inside the
    /// SQLite boundary and covers every field that affects recovery
    /// semantics, including the complete local CAS base, signed freshness
    /// witness, and resource limits. A durable result can therefore be
    /// replayed only with the exact same binding, not merely the same request
    /// ID and base generation.
    private func permissionedRemoteReplicaBindingDigest(
        _ binding: PermissionedRemoteReplicaImportBinding
    ) -> Data {
        var hasher = SHA256()
        hasher.update(data: Data(
            "swan.permissioned.remote-replica.binding.v1".utf8
        ))
        func append(_ value: Data) {
            remoteReplicaDigestAppend(value, to: &hasher)
        }

        append(Data(binding.requestID.utf8))
        append(binding.requestDigest)
        append(Data(binding.sourceOrigin.utf8))
        append(Data(binding.target.receiverDID.utf8))
        append(Data(binding.target.space.rawValue.utf8))
        append(Data(binding.target.repositoryDID.utf8))
        append(Data(binding.verifierIdentity.utf8))
        append(Data(binding.profileID.utf8))

        if let expectedBase = binding.expectedBase {
            append(Data("base-present".utf8))
            append(Data(expectedBase.target.receiverDID.utf8))
            append(Data(expectedBase.target.space.rawValue.utf8))
            append(Data(expectedBase.target.repositoryDID.utf8))
            append(Data(String(expectedBase.generation).utf8))
            append(Data(expectedBase.wireRevision.toString().utf8))
            append(Data(expectedBase.historyFloorWireRevision.toString().utf8))
            append(expectedBase.ltHash)
            append(expectedBase.commitment)
            append(expectedBase.stateMarker)
        } else {
            append(Data("base-none".utf8))
        }

        if let freshnessWitness = binding.freshnessWitness {
            append(Data("freshness-present".utf8))
            append(Data(freshnessWitness.wireRevision.toString().utf8))
            append(freshnessWitness.commitment)
        } else {
            append(Data("freshness-none".utf8))
        }

        append(Data(String(binding.limits.maximumCARBytes).utf8))
        append(Data(String(binding.limits.maximumRecordBytes).utf8))
        append(Data(String(binding.limits.maximumIndexEntries).utf8))
        append(Data(String(binding.limits.maximumUniqueBlocks).utf8))
        return Data(hasher.finalize())
    }

    private func remoteReplicaDigestAppend(
        _ value: Data,
        to hasher: inout SHA256
    ) {
        var length = UInt64(value.count).bigEndian
        withUnsafeBytes(of: &length) {
            hasher.update(data: Data($0))
        }
        hasher.update(data: value)
    }

    private func remoteReplicaText(
        _ row: SQLiteRow,
        _ column: String
    ) -> String {
        row.column(column)?.string ?? ""
    }

    private func remoteReplicaData(
        _ row: SQLiteRow,
        _ column: String
    ) -> Data? {
        guard let value = row.column(column), !value.isNull else {
            return nil
        }
        return Data(sqliteData: value)
    }

    private func requiredRemoteReplicaData(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> Data {
        guard let data = remoteReplicaData(row, column) else {
            throw PermissionedRemoteReplicaRecoveryError.corruptStaging
        }
        return data
    }

    private func remoteReplicaInteger(
        _ row: SQLiteRow?,
        _ column: String
    ) -> Int {
        guard case let .integer(value)? = row?.column(column),
              let result = Int(exactly: value) else {
            return -1
        }
        return result
    }

    private func remoteReplicaInteger(
        _ row: SQLiteRow,
        _ column: String
    ) -> Int {
        remoteReplicaInteger(Optional(row), column)
    }

    private func remoteReplicaSQLiteInteger(_ value: Int64) throws -> Int {
        guard let result = Int(exactly: value) else {
            throw PermissionedRemoteReplicaRecoveryError.invalidTimestamp
        }
        return result
    }
}

private struct StagedPermissionedRemoteReplicaValidation: Sendable {
    let commitRoot: CID
    let indexRoot: CID
    let wireRevision: TID
    let ltHash: Data
    let commitment: Data
    let commitBodyDigest: Data
    let projectionDigest: Data
    let recordCount: Int
    let uniqueBlockCount: Int
}

private struct RemoteReplicaProjectionValidation: Sendable {
    let indexRoot: CID
    let ltHash: Data
    let commitment: Data
    let projectionDigest: Data
    let recordCount: Int
    let uniqueBlockCount: Int
}
