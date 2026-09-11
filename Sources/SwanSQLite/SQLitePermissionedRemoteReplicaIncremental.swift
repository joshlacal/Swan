import Crypto
import Foundation
import Petrel
import SQLiteNIO
import SwanSpaces
import SwanStorage

private struct PermissionedRemoteReplicaIncrementalRollback: Error {
    let outcome: PermissionedRemoteReplicaIncrementalApplyOutcome
}

extension SQLiteAccountDatabase: PermissionedRemoteReplicaIncrementalStore {
    public func permissionedRemoteReplicaIncrementalBaseState(
        target: PermissionedRemoteReplicaTarget
    ) async throws -> PermissionedRemoteReplicaIncrementalBaseState? {
        guard target.receiverDID == accountDID else {
            throw PermissionedRemoteReplicaRecoveryError.receiverMismatch
        }
        return try await withConnectionGate {
            try await writerReadTransaction {
                try await requireRemoteReplicaSpaceOpen(target.space)
                guard let head = try await incrementalHead(target: target) else {
                    return nil
                }
                let count = try await incrementalRecordCount(
                    target: target,
                    generation: head.generation
                )
                guard try await incrementalProjectionMatches(
                    head: head,
                    expectedCount: count
                ) else {
                    throw PermissionedRemoteReplicaRecoveryError.corruptReplica
                }
                return try PermissionedRemoteReplicaIncrementalBaseState(
                    head: head,
                    recordCount: count
                )
            }
        }
    }

    public func applyVerifiedPermissionedRemoteReplicaBatch(
        _ batch: PermissionedRemoteReplicaIncrementalBatch,
        appliedAt: Int64
    ) async throws -> PermissionedRemoteReplicaIncrementalApplyOutcome {
        guard batch.target.receiverDID == accountDID, appliedAt >= 0 else {
            return .integrityFailure
        }
        return try await withConnectionGate {
            do {
                return try await transaction {
                try await requireRemoteReplicaSpaceOpen(batch.target.space)
                let bindingDigest = incrementalBatchDigest(batch)
                guard bindingDigest == batch.requestDigest else {
                    throw PermissionedRemoteReplicaIncrementalRollback(
                        outcome: .integrityFailure
                    )
                }
                let progress = try await incrementalProgress(
                    target: batch.target
                )
                if let replay = try await incrementalReplay(
                    requestID: batch.requestID,
                    target: batch.target
                ) {
                    guard replay.requestSequence == batch.requestSequence,
                          replay.requestDigest == batch.requestDigest,
                          replay.batchDigest == bindingDigest,
                          replay.expectedGeneration
                            == batch.expectedHead.generation,
                          replay.expectedRevision
                            == batch.expectedHead.wireRevision,
                          replay.expectedCommitment
                            == batch.expectedHead.commitment,
                          replay.expectedMarker
                            == batch.expectedHead.stateMarker else {
                        throw PermissionedRemoteReplicaIncrementalRollback(
                            outcome: .conflictingReplay
                        )
                    }
                    return .exactDuplicate(replay.result)
                }
                guard batch.requestSequence > progress.replayFloor else {
                    throw PermissionedRemoteReplicaIncrementalRollback(
                        outcome: .staleOrReordered
                    )
                }

                guard let current = try await incrementalHead(
                    target: batch.target
                ) else {
                    throw PermissionedRemoteReplicaIncrementalRollback(
                        outcome: .fullCARRecoveryRequired
                    )
                }
                guard current == batch.expectedHead else {
                    throw PermissionedRemoteReplicaIncrementalRollback(
                        outcome: .casConflict
                    )
                }
                if try await incrementalReplay(
                    requestSequence: batch.requestSequence,
                    target: batch.target
                ) != nil {
                    throw PermissionedRemoteReplicaIncrementalRollback(
                        outcome: .conflictingReplay
                    )
                }
                guard progress.highWatermark < UInt64.max,
                      batch.requestSequence == progress.highWatermark + 1 else {
                    throw PermissionedRemoteReplicaIncrementalRollback(
                        outcome: .staleOrReordered
                    )
                }
                guard batch.terminalHead.wireRevision
                        > current.wireRevision else {
                    if batch.terminalHead.wireRevision
                            == current.wireRevision,
                       batch.terminalHead.commitment != current.commitment {
                        throw PermissionedRemoteReplicaIncrementalRollback(
                            outcome: .integrityFailure
                        )
                    }
                    throw PermissionedRemoteReplicaIncrementalRollback(
                        outcome: .staleOrReordered
                    )
                }
                guard try await incrementalProjectionMatches(
                    head: current,
                    expectedCount: nil
                ) else {
                    throw PermissionedRemoteReplicaIncrementalRollback(
                        outcome: .integrityFailure
                    )
                }
                guard batch.terminalHead.operationCount
                        == batch.operations.count,
                      batch.terminalHead.operationDigest
                        == PermissionedRemoteReplicaIncrementalOperationWitness
                            .digest(batch.operations) else {
                    throw PermissionedRemoteReplicaIncrementalRollback(
                        outcome: .integrityFailure
                    )
                }

                var ltHash: LtHash
                do {
                    ltHash = try LtHash(serialized: current.ltHash)
                } catch {
                    throw PermissionedRemoteReplicaIncrementalRollback(
                        outcome: .integrityFailure
                    )
                }
                let generation = current.generation
                var previousOperationRevision = current.wireRevision
                for (expectedIndex, operation) in batch.operations.enumerated() {
                    guard operation.operationIndex == expectedIndex,
                          operation.wireRevision > current.wireRevision,
                          operation.wireRevision >= previousOperationRevision,
                          operation.wireRevision
                            <= batch.terminalHead.wireRevision else {
                        throw PermissionedRemoteReplicaIncrementalRollback(
                            outcome: .staleOrReordered
                        )
                    }
                    previousOperationRevision = operation.wireRevision
                    guard operation.uri.space == batch.target.space,
                          operation.uri.author
                            == batch.target.repositoryDID else {
                        throw PermissionedRemoteReplicaIncrementalRollback(
                            outcome: .integrityFailure
                        )
                    }
                    let existingCID = try await incrementalRecordCID(
                        target: batch.target,
                        generation: generation,
                        uri: operation.uri
                    )
                    switch operation.action {
                    case .create:
                        guard existingCID == nil,
                              operation.previousCID == nil,
                              let cid = operation.cid,
                              let value = operation.value,
                              incrementalCanonicalRecord(
                                value, cid: cid
                              ) else {
                            throw PermissionedRemoteReplicaIncrementalRollback(
                                outcome: .integrityFailure
                            )
                        }
                        try await ensureIncrementalBlock(
                            target: batch.target,
                            generation: generation,
                            cid: cid,
                            value: value
                        )
                        let inserted = try await connection.query(
                            """
                            INSERT INTO permissioned_remote_replica_records(
                                space_uri, repository_did, collection, rkey,
                                cid, generation
                            ) VALUES (?, ?, ?, ?, ?, ?)
                            RETURNING cid
                            """,
                            [
                                .text(batch.target.space.rawValue),
                                .text(batch.target.repositoryDID),
                                .text(operation.uri.collection),
                                .text(operation.uri.rkey), .text(cid.string),
                                .integer(Int(generation)),
                            ]
                        )
                        guard inserted.count == 1 else {
                            throw PermissionedRemoteReplicaIncrementalRollback(
                                outcome: .casConflict
                            )
                        }
                        ltHash.add(element: incrementalElement(
                            uri: operation.uri, cid: cid.string
                        ))

                    case .update:
                        guard let oldCID = existingCID,
                              let previousCID = operation.previousCID,
                              oldCID == previousCID.string,
                              let cid = operation.cid,
                              let value = operation.value,
                              incrementalCanonicalRecord(
                                value, cid: cid
                              ) else {
                            throw PermissionedRemoteReplicaIncrementalRollback(
                                outcome: .integrityFailure
                            )
                        }
                        try await ensureIncrementalBlock(
                            target: batch.target,
                            generation: generation,
                            cid: cid,
                            value: value
                        )
                        let updated = try await connection.query(
                            """
                            UPDATE permissioned_remote_replica_records
                            SET cid = ?
                            WHERE space_uri = ? AND repository_did = ?
                              AND generation = ? AND collection = ?
                              AND rkey = ? AND cid = ?
                            RETURNING cid
                            """,
                            [
                                .text(cid.string),
                                .text(batch.target.space.rawValue),
                                .text(batch.target.repositoryDID),
                                .integer(Int(generation)),
                                .text(operation.uri.collection),
                                .text(operation.uri.rkey), .text(oldCID),
                            ]
                        )
                        guard updated.count == 1 else {
                            throw PermissionedRemoteReplicaIncrementalRollback(
                                outcome: .casConflict
                            )
                        }
                        ltHash.remove(element: incrementalElement(
                            uri: operation.uri, cid: oldCID
                        ))
                        ltHash.add(element: incrementalElement(
                            uri: operation.uri, cid: cid.string
                        ))
                        try await removeIncrementalBlockIfUnreferenced(
                            target: batch.target,
                            generation: generation,
                            cid: oldCID
                        )

                    case .delete:
                        guard let oldCID = existingCID,
                              let previousCID = operation.previousCID,
                              oldCID == previousCID.string,
                              operation.cid == nil,
                              operation.value == nil else {
                            throw PermissionedRemoteReplicaIncrementalRollback(
                                outcome: .integrityFailure
                            )
                        }
                        let deleted = try await connection.query(
                            """
                            DELETE FROM permissioned_remote_replica_records
                            WHERE space_uri = ? AND repository_did = ?
                              AND generation = ? AND collection = ?
                              AND rkey = ? AND cid = ?
                            RETURNING cid
                            """,
                            [
                                .text(batch.target.space.rawValue),
                                .text(batch.target.repositoryDID),
                                .integer(Int(generation)),
                                .text(operation.uri.collection),
                                .text(operation.uri.rkey), .text(oldCID),
                            ]
                        )
                        guard deleted.count == 1 else {
                            throw PermissionedRemoteReplicaIncrementalRollback(
                                outcome: .casConflict
                            )
                        }
                        ltHash.remove(element: incrementalElement(
                            uri: operation.uri, cid: oldCID
                        ))
                        try await removeIncrementalBlockIfUnreferenced(
                            target: batch.target,
                            generation: generation,
                            cid: oldCID
                        )
                    }
                }

                guard previousOperationRevision
                        == batch.terminalHead.wireRevision else {
                    throw PermissionedRemoteReplicaIncrementalRollback(
                        outcome: .integrityFailure
                    )
                }

                let count = try await incrementalRecordCount(
                    target: batch.target,
                    generation: generation
                )
                let logicalBytes = try await incrementalLogicalBytes(
                    target: batch.target,
                    generation: generation
                )
                guard count == batch.terminalHead.recordCount,
                      logicalBytes
                        <= SpaceCARRecoveryLimits
                            .absoluteMaximumLogicalRestoredBytes,
                      ltHash.serialized == batch.terminalHead.ltHash,
                      ltHash.commitment == batch.terminalHead.commitment,
                      Data(SHA256.hash(data: batch.terminalHead.ltHash))
                        == batch.terminalHead.commitment else {
                    throw PermissionedRemoteReplicaIncrementalRollback(
                        outcome: .integrityFailure
                    )
                }
                let marker = incrementalStateMarker(
                    target: batch.target,
                    generation: generation,
                    wireRevision: batch.terminalHead.wireRevision,
                    historyFloor: current.historyFloorWireRevision,
                    commitment: batch.terminalHead.commitment
                )
                let installedHead: PermissionedRemoteReplicaHead
                do {
                    installedHead = try PermissionedRemoteReplicaHead(
                        target: batch.target,
                        generation: generation,
                        wireRevision: batch.terminalHead.wireRevision,
                        historyFloorWireRevision:
                            current.historyFloorWireRevision,
                        ltHash: batch.terminalHead.ltHash,
                        commitment: batch.terminalHead.commitment,
                        stateMarker: marker
                    )
                } catch {
                    throw PermissionedRemoteReplicaIncrementalRollback(
                        outcome: .integrityFailure
                    )
                }
                let advanced = try await connection.query(
                    """
                    UPDATE permissioned_remote_replica_state
                    SET wire_revision = ?, lthash = ?, commitment = ?,
                        state_marker = ?, installed_at = ?
                    WHERE receiver_did = ? AND space_uri = ?
                      AND repository_did = ? AND generation = ?
                      AND wire_revision = ? AND lthash = ?
                      AND commitment = ? AND state_marker = ?
                    RETURNING wire_revision
                    """,
                    [
                        .text(installedHead.wireRevision.toString()),
                        installedHead.ltHash.sqliteData!,
                        installedHead.commitment.sqliteData!,
                        installedHead.stateMarker.sqliteData!,
                        .integer(Int(appliedAt)),
                        .text(batch.target.receiverDID),
                        .text(batch.target.space.rawValue),
                        .text(batch.target.repositoryDID),
                        .integer(Int(current.generation)),
                        .text(current.wireRevision.toString()),
                        current.ltHash.sqliteData!,
                        current.commitment.sqliteData!,
                        current.stateMarker.sqliteData!,
                    ]
                )
                guard advanced.count == 1 else {
                    throw PermissionedRemoteReplicaIncrementalRollback(
                        outcome: .casConflict
                    )
                }
                try await advanceWriterHighWaterWithoutGate(
                    space: batch.target.space,
                    repository: batch.target.repositoryDID,
                    wireRevision: installedHead.wireRevision.toString(),
                    commitment: installedHead.commitment,
                    updatedAt: appliedAt
                )

                let result = AppliedPermissionedRemoteReplicaIncrementalBatch(
                    requestID: batch.requestID,
                    requestSequence: batch.requestSequence,
                    requestDigest: batch.requestDigest,
                    head: installedHead,
                    recordCount: count,
                    appliedAt: appliedAt
                )
                try await persistIncrementalResult(
                    batch: batch,
                    batchDigest: bindingDigest,
                    result: result
                )
                try await advanceIncrementalProgress(
                    target: batch.target,
                    from: progress,
                    through: batch.requestSequence
                )
                try await pruneIncrementalResults(
                    target: batch.target,
                    progress: IncrementalProgress(
                        replayFloor: progress.replayFloor,
                        highWatermark: batch.requestSequence
                    )
                )
                return .applied(result)
                }
            } catch let rollback as PermissionedRemoteReplicaIncrementalRollback {
                return rollback.outcome
            }
        }
    }
}

private extension SQLiteAccountDatabase {
    struct IncrementalReplay: Sendable {
        let requestSequence: UInt64
        let requestDigest: Data
        let batchDigest: Data
        let expectedGeneration: UInt64
        let expectedRevision: TID
        let expectedCommitment: Data
        let expectedMarker: Data
        let result: AppliedPermissionedRemoteReplicaIncrementalBatch
    }

    struct IncrementalProgress: Sendable, Equatable {
        let replayFloor: UInt64
        let highWatermark: UInt64
    }

    static var maximumRetainedIncrementalResultRows: UInt64 { 10_000 }

    func incrementalProgress(
        target: PermissionedRemoteReplicaTarget
    ) async throws -> IncrementalProgress {
        let rows = try await connection.query(
            """
            SELECT replay_floor, high_watermark
            FROM permissioned_remote_replica_incremental_progress
            WHERE receiver_did = ? AND space_uri = ? AND repository_did = ?
            LIMIT 2
            """,
            [
                .text(target.receiverDID), .text(target.space.rawValue),
                .text(target.repositoryDID),
            ]
        )
        guard rows.count <= 1 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        guard let row = rows.first else {
            let retained = try await connection.query(
                """
                SELECT COUNT(*) AS count
                FROM permissioned_remote_replica_incremental_results
                WHERE receiver_did = ? AND space_uri = ? AND repository_did = ?
                """,
                [
                    .text(target.receiverDID), .text(target.space.rawValue),
                    .text(target.repositoryDID),
                ]
            )
            guard retained.first?.column("count")?.integer == 0 else {
                throw PermissionedRemoteReplicaRecoveryError.corruptReplica
            }
            return IncrementalProgress(replayFloor: 0, highWatermark: 0)
        }
        guard let replayFloor = incrementalUInt64(row, "replay_floor"),
              let highWatermark = incrementalUInt64(row, "high_watermark"),
              replayFloor <= highWatermark else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        let retained = try await connection.query(
            """
            SELECT COUNT(*) AS count,
                   MIN(request_sequence) AS minimum_sequence,
                   MAX(request_sequence) AS maximum_sequence
            FROM permissioned_remote_replica_incremental_results
            WHERE receiver_did = ? AND space_uri = ? AND repository_did = ?
            """,
            [
                .text(target.receiverDID), .text(target.space.rawValue),
                .text(target.repositoryDID),
            ]
        )
        guard let aggregate = retained.first,
              let retainedCount = aggregate.column("count")?.integer,
              retainedCount >= 0 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        let distance = highWatermark - replayFloor
        guard distance <= Self.maximumRetainedIncrementalResultRows,
              UInt64(retainedCount) == distance else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        if distance == 0 {
            guard incrementalData(aggregate, "minimum_sequence") == nil,
                  incrementalData(aggregate, "maximum_sequence") == nil else {
                throw PermissionedRemoteReplicaRecoveryError.corruptReplica
            }
        } else {
            guard replayFloor < UInt64.max,
                  incrementalUInt64(aggregate, "minimum_sequence")
                    == replayFloor + 1,
                  incrementalUInt64(aggregate, "maximum_sequence")
                    == highWatermark else {
                throw PermissionedRemoteReplicaRecoveryError.corruptReplica
            }
        }
        return IncrementalProgress(
            replayFloor: replayFloor,
            highWatermark: highWatermark
        )
    }

    func advanceIncrementalProgress(
        target: PermissionedRemoteReplicaTarget,
        from progress: IncrementalProgress,
        through requestSequence: UInt64
    ) async throws {
        let rows = try await connection.query(
            """
            INSERT INTO permissioned_remote_replica_incremental_progress(
                receiver_did, space_uri, repository_did,
                replay_floor, high_watermark
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(receiver_did, space_uri, repository_did) DO UPDATE SET
                high_watermark = excluded.high_watermark
            WHERE replay_floor = ? AND high_watermark = ?
            RETURNING high_watermark
            """,
            [
                .text(target.receiverDID), .text(target.space.rawValue),
                .text(target.repositoryDID),
                incrementalSequenceData(progress.replayFloor).sqliteData!,
                incrementalSequenceData(requestSequence).sqliteData!,
                incrementalSequenceData(progress.replayFloor).sqliteData!,
                incrementalSequenceData(progress.highWatermark).sqliteData!,
            ]
        )
        guard rows.count == 1 else {
            throw PermissionedRemoteReplicaIncrementalRollback(
                outcome: .casConflict
            )
        }
    }

    func incrementalHead(
        target: PermissionedRemoteReplicaTarget
    ) async throws -> PermissionedRemoteReplicaHead? {
        let rows = try await connection.query(
            """
            SELECT receiver_did, generation, wire_revision,
                   history_floor_wire_revision, lthash, commitment,
                   state_marker
            FROM permissioned_remote_replica_state
            WHERE space_uri = ? AND repository_did = ?
            LIMIT 2
            """,
            [.text(target.space.rawValue), .text(target.repositoryDID)]
        )
        guard rows.count <= 1 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        guard let row = rows.first else { return nil }
        guard row.column("receiver_did")?.string == target.receiverDID,
              let generationValue = row.column("generation")?.integer,
              generationValue > 0,
              let revisionRaw = row.column("wire_revision")?.string,
              let revision = try? TID(tidString: revisionRaw),
              revision.toString() == revisionRaw,
              let floorRaw = row.column("history_floor_wire_revision")?.string,
              let floor = try? TID(tidString: floorRaw),
              floor.toString() == floorRaw,
              let ltHash = incrementalData(row, "lthash"),
              let commitment = incrementalData(row, "commitment"),
              let marker = incrementalData(row, "state_marker"),
              Data(SHA256.hash(data: ltHash)) == commitment,
              marker == incrementalStateMarker(
                target: target,
                generation: UInt64(generationValue),
                wireRevision: revision,
                historyFloor: floor,
                commitment: commitment
              ) else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        return try PermissionedRemoteReplicaHead(
            target: target,
            generation: UInt64(generationValue),
            wireRevision: revision,
            historyFloorWireRevision: floor,
            ltHash: ltHash,
            commitment: commitment,
            stateMarker: marker
        )
    }

    func incrementalProjectionMatches(
        head: PermissionedRemoteReplicaHead,
        expectedCount: Int?
    ) async throws -> Bool {
        let count = try await incrementalRecordCount(
            target: head.target,
            generation: head.generation
        )
        if let expectedCount, count != expectedCount { return false }
        guard try await incrementalLogicalBytes(
            target: head.target,
            generation: head.generation
        ) <= SpaceCARRecoveryLimits.absoluteMaximumLogicalRestoredBytes else {
            return false
        }
        var rebuilt = LtHash()
        var lastCollection = ""
        var lastRkey = ""
        var seen = 0
        while seen < count {
            let rows = try await connection.query(
                """
                SELECT collection, rkey, cid
                FROM permissioned_remote_replica_records
                WHERE space_uri = ? AND repository_did = ?
                  AND generation = ?
                  AND (collection > ? OR (collection = ? AND rkey > ?))
                ORDER BY collection, rkey
                LIMIT ?
                """,
                [
                    .text(head.target.space.rawValue),
                    .text(head.target.repositoryDID),
                    .integer(Int(head.generation)),
                    .text(lastCollection), .text(lastCollection),
                    .text(lastRkey),
                    .integer(
                        PermissionedRemoteReplicaRecoveryBudgets
                            .maximumRowsPerPass
                    ),
                ]
            )
            guard !rows.isEmpty,
                  rows.count <= PermissionedRemoteReplicaRecoveryBudgets
                    .maximumRowsPerPass else { return false }
            for row in rows {
                guard let collection = row.column("collection")?.string,
                      let rkey = row.column("rkey")?.string,
                      let cidRaw = row.column("cid")?.string,
                      let cid = try? CID.parse(cidRaw),
                      cid.string == cidRaw,
                      (collection, rkey) > (lastCollection, lastRkey),
                      (try? SpaceRecordURI(
                        space: head.target.space,
                        author: head.target.repositoryDID,
                        collection: collection,
                        rkey: rkey
                      )) != nil else { return false }
                let blockRows = try await connection.query(
                    """
                    SELECT byte_count, chunk_count
                    FROM permissioned_remote_replica_blocks
                    WHERE space_uri = ? AND repository_did = ?
                      AND generation = ? AND cid = ?
                    LIMIT 2
                    """,
                    [
                        .text(head.target.space.rawValue),
                        .text(head.target.repositoryDID),
                        .integer(Int(head.generation)), .text(cidRaw),
                    ]
                )
                guard blockRows.count == 1,
                      let byteCount = blockRows[0]
                        .column("byte_count")?.integer,
                      let chunkCount = blockRows[0]
                        .column("chunk_count")?.integer,
                      (1 ... SpaceCARRecoveryLimits
                        .absoluteMaximumRecordBytes).contains(byteCount),
                      (1 ... PermissionedRemoteReplicaRecoveryBudgets
                        .maximumChunksPerRecord).contains(chunkCount) else {
                    return false
                }
                let value = try await incrementalBlockBytes(
                    target: head.target,
                    generation: head.generation,
                    cid: cid,
                    chunkCount: chunkCount
                )
                guard value.count == byteCount,
                      incrementalCanonicalRecord(value, cid: cid) else {
                    return false
                }
                rebuilt.add(element: "\(collection)/\(rkey)/\(cidRaw)")
                lastCollection = collection
                lastRkey = rkey
                seen += 1
            }
        }
        return seen == count && rebuilt.serialized == head.ltHash
            && rebuilt.commitment == head.commitment
    }

    func incrementalRecordCount(
        target: PermissionedRemoteReplicaTarget,
        generation: UInt64
    ) async throws -> Int {
        let rows = try await connection.query(
            """
            SELECT COUNT(*) AS count
            FROM permissioned_remote_replica_records
            WHERE space_uri = ? AND repository_did = ? AND generation = ?
            """,
            [
                .text(target.space.rawValue), .text(target.repositoryDID),
                .integer(Int(generation)),
            ]
        )
        guard let count = rows.first?.column("count")?.integer,
              (0 ... SpaceCARRecoveryLimits.absoluteMaximumIndexEntries)
                .contains(count) else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        return count
    }

    /// Counts record edges, not unique blocks: multiple paths pointing to one
    /// CID consume logical restored bytes independently, matching full-CAR
    /// recovery admission and preventing alias amplification across batches.
    func incrementalLogicalBytes(
        target: PermissionedRemoteReplicaTarget,
        generation: UInt64
    ) async throws -> Int {
        let rows = try await connection.query(
            """
            SELECT COUNT(*) AS edge_count,
                   COALESCE(SUM(blocks.byte_count), 0) AS logical_bytes
            FROM permissioned_remote_replica_records AS records
            JOIN permissioned_remote_replica_blocks AS blocks
              ON blocks.space_uri = records.space_uri
             AND blocks.repository_did = records.repository_did
             AND blocks.generation = records.generation
             AND blocks.cid = records.cid
            WHERE records.space_uri = ? AND records.repository_did = ?
              AND records.generation = ?
            """,
            [
                .text(target.space.rawValue), .text(target.repositoryDID),
                .integer(Int(generation)),
            ]
        )
        let durableRecordCount = try await incrementalRecordCount(
            target: target,
            generation: generation
        )
        guard let row = rows.first,
              let edgeCount = row.column("edge_count")?.integer,
              edgeCount == durableRecordCount,
              let bytes = row.column("logical_bytes")?.integer,
              bytes >= 0 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        return bytes
    }

    func incrementalRecordCID(
        target: PermissionedRemoteReplicaTarget,
        generation: UInt64,
        uri: SpaceRecordURI
    ) async throws -> String? {
        let rows = try await connection.query(
            """
            SELECT cid FROM permissioned_remote_replica_records
            WHERE space_uri = ? AND repository_did = ? AND generation = ?
              AND collection = ? AND rkey = ?
            LIMIT 2
            """,
            [
                .text(target.space.rawValue), .text(target.repositoryDID),
                .integer(Int(generation)), .text(uri.collection),
                .text(uri.rkey),
            ]
        )
        guard rows.count <= 1 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        guard let raw = rows.first?.column("cid")?.string else { return nil }
        guard let cid = try? CID.parse(raw), cid.string == raw else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        return raw
    }

    func ensureIncrementalBlock(
        target: PermissionedRemoteReplicaTarget,
        generation: UInt64,
        cid: CID,
        value: Data
    ) async throws {
        let chunkSize = PermissionedRemoteReplicaRecoveryBudgets
            .maximumChunkBytes
        let chunkCount = (value.count + chunkSize - 1) / chunkSize
        guard !value.isEmpty,
              chunkCount > 0,
              chunkCount <= PermissionedRemoteReplicaRecoveryBudgets
                .maximumChunksPerRecord else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        let rows = try await connection.query(
            """
            SELECT byte_count, chunk_count
            FROM permissioned_remote_replica_blocks
            WHERE space_uri = ? AND repository_did = ? AND generation = ?
              AND cid = ?
            LIMIT 2
            """,
            [
                .text(target.space.rawValue), .text(target.repositoryDID),
                .integer(Int(generation)), .text(cid.string),
            ]
        )
        guard rows.count <= 1 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        if let row = rows.first {
            guard row.column("byte_count")?.integer == value.count,
                  row.column("chunk_count")?.integer == chunkCount,
                  try await incrementalBlockBytes(
                    target: target, generation: generation, cid: cid,
                    chunkCount: chunkCount
                  ) == value else {
                throw PermissionedRemoteReplicaRecoveryError.corruptReplica
            }
            return
        }
        _ = try await connection.query(
            """
            INSERT INTO permissioned_remote_replica_blocks(
                space_uri, repository_did, cid, byte_count,
                chunk_count, generation
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                .text(target.space.rawValue), .text(target.repositoryDID),
                .text(cid.string), .integer(value.count),
                .integer(chunkCount), .integer(Int(generation)),
            ]
        )
        for index in 0 ..< chunkCount {
            let start = index * chunkSize
            let end = min(value.count, start + chunkSize)
            let bytes = Data(value[start ..< end])
            _ = try await connection.query(
                """
                INSERT INTO permissioned_remote_replica_block_chunks(
                    space_uri, repository_did, generation, cid,
                    chunk_index, bytes
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    .text(target.space.rawValue),
                    .text(target.repositoryDID), .integer(Int(generation)),
                    .text(cid.string), .integer(index), bytes.sqliteData!,
                ]
            )
        }
    }

    func incrementalBlockBytes(
        target: PermissionedRemoteReplicaTarget,
        generation: UInt64,
        cid: CID,
        chunkCount: Int
    ) async throws -> Data {
        let rows = try await connection.query(
            """
            SELECT chunk_index, bytes
            FROM permissioned_remote_replica_block_chunks
            WHERE space_uri = ? AND repository_did = ? AND generation = ?
              AND cid = ?
            ORDER BY chunk_index
            LIMIT ?
            """,
            [
                .text(target.space.rawValue), .text(target.repositoryDID),
                .integer(Int(generation)), .text(cid.string),
                .integer(
                    PermissionedRemoteReplicaRecoveryBudgets
                        .maximumChunksPerRecord + 1
                ),
            ]
        )
        guard rows.count == chunkCount else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        var result = Data()
        for (index, row) in rows.enumerated() {
            guard row.column("chunk_index")?.integer == index,
                  let bytes = incrementalData(row, "bytes"),
                  !bytes.isEmpty,
                  bytes.count <= PermissionedRemoteReplicaRecoveryBudgets
                    .maximumChunkBytes else {
                throw PermissionedRemoteReplicaRecoveryError.corruptReplica
            }
            result.append(bytes)
        }
        return result
    }

    func removeIncrementalBlockIfUnreferenced(
        target: PermissionedRemoteReplicaTarget,
        generation: UInt64,
        cid: String
    ) async throws {
        _ = try await connection.query(
            """
            DELETE FROM permissioned_remote_replica_blocks
            WHERE space_uri = ? AND repository_did = ? AND generation = ?
              AND cid = ?
              AND NOT EXISTS (
                SELECT 1 FROM permissioned_remote_replica_records
                WHERE space_uri = ? AND repository_did = ?
                  AND generation = ? AND cid = ?
              )
            """,
            [
                .text(target.space.rawValue), .text(target.repositoryDID),
                .integer(Int(generation)), .text(cid),
                .text(target.space.rawValue), .text(target.repositoryDID),
                .integer(Int(generation)), .text(cid),
            ]
        )
    }

    func persistIncrementalResult(
        batch: PermissionedRemoteReplicaIncrementalBatch,
        batchDigest: Data,
        result: AppliedPermissionedRemoteReplicaIncrementalBatch
    ) async throws {
        let integrity = incrementalResultIntegrity(
            requestID: batch.requestID,
            requestSequence: batch.requestSequence,
            requestDigest: batch.requestDigest,
            batchDigest: batchDigest,
            expectedHead: batch.expectedHead,
            operationCount: batch.operations.count,
            result: result
        )
        let inserted = try await connection.query(
            """
            INSERT INTO permissioned_remote_replica_incremental_results(
                request_id, request_sequence, request_digest, batch_digest,
                receiver_did, space_uri, repository_did,
                expected_generation, expected_wire_revision,
                expected_commitment, expected_marker,
                installed_generation, installed_wire_revision,
                installed_history_floor, installed_lthash,
                installed_commitment, installed_marker,
                record_count, operation_count, applied_at, integrity_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING request_sequence
            """,
            [
                .text(batch.requestID),
                incrementalSequenceData(batch.requestSequence).sqliteData!,
                batch.requestDigest.sqliteData!, batchDigest.sqliteData!,
                .text(batch.target.receiverDID),
                .text(batch.target.space.rawValue),
                .text(batch.target.repositoryDID),
                .integer(Int(batch.expectedHead.generation)),
                .text(batch.expectedHead.wireRevision.toString()),
                batch.expectedHead.commitment.sqliteData!,
                batch.expectedHead.stateMarker.sqliteData!,
                .integer(Int(result.head.generation)),
                .text(result.head.wireRevision.toString()),
                .text(result.head.historyFloorWireRevision.toString()),
                result.head.ltHash.sqliteData!,
                result.head.commitment.sqliteData!,
                result.head.stateMarker.sqliteData!,
                .integer(result.recordCount),
                .integer(batch.operations.count),
                .integer(Int(result.appliedAt)),
                integrity.sqliteData!,
            ]
        )
        guard inserted.count == 1 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
    }

    func incrementalReplay(
        requestID: String,
        target: PermissionedRemoteReplicaTarget
    ) async throws -> IncrementalReplay? {
        let rows = try await connection.query(
            """
            SELECT * FROM permissioned_remote_replica_incremental_results
            WHERE receiver_did = ? AND space_uri = ? AND repository_did = ?
              AND request_id = ? LIMIT 2
            """,
            [
                .text(target.receiverDID), .text(target.space.rawValue),
                .text(target.repositoryDID), .text(requestID),
            ]
        )
        guard rows.count <= 1 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        guard let row = rows.first else { return nil }
        guard let requestSequence = incrementalUInt64(
                row, "request_sequence"
              ),
              let requestDigest = incrementalData(row, "request_digest"),
              let batchDigest = incrementalData(row, "batch_digest"),
              let expectedGenerationValue = row.column(
                "expected_generation"
              )?.integer,
              expectedGenerationValue > 0,
              let expectedRevisionRaw = row.column(
                "expected_wire_revision"
              )?.string,
              let expectedRevision = try? TID(
                tidString: expectedRevisionRaw
              ),
              let expectedCommitment = incrementalData(
                row, "expected_commitment"
              ),
              let expectedMarker = incrementalData(row, "expected_marker"),
              let installedGenerationValue = row.column(
                "installed_generation"
              )?.integer,
              installedGenerationValue > 0,
              let installedRevisionRaw = row.column(
                "installed_wire_revision"
              )?.string,
              let installedRevision = try? TID(
                tidString: installedRevisionRaw
              ),
              let floorRaw = row.column("installed_history_floor")?.string,
              let floor = try? TID(tidString: floorRaw),
              let ltHash = incrementalData(row, "installed_lthash"),
              let commitment = incrementalData(row, "installed_commitment"),
              let marker = incrementalData(row, "installed_marker"),
              let count = row.column("record_count")?.integer,
              let operationCount = row.column("operation_count")?.integer,
              (1 ... SpaceWriteLimits.maximumOperations)
                .contains(operationCount),
              let appliedAtValue = row.column("applied_at")?.integer,
              appliedAtValue >= 0 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        let head = try PermissionedRemoteReplicaHead(
            target: target,
            generation: UInt64(installedGenerationValue),
            wireRevision: installedRevision,
            historyFloorWireRevision: floor,
            ltHash: ltHash,
            commitment: commitment,
            stateMarker: marker
        )
        let result = AppliedPermissionedRemoteReplicaIncrementalBatch(
            requestID: requestID,
            requestSequence: requestSequence,
            requestDigest: requestDigest,
            head: head,
            recordCount: count,
            appliedAt: Int64(appliedAtValue)
        )
        let expectedHead = try PermissionedRemoteReplicaHead(
            target: target,
            generation: UInt64(expectedGenerationValue),
            wireRevision: expectedRevision,
            historyFloorWireRevision: floor,
            // Only the expected commitment/marker are replay-binding facts;
            // the complete expected LtHash is already covered by batchDigest.
            ltHash: Data(repeating: 0, count: LtHash.byteCount),
            commitment: expectedCommitment,
            stateMarker: expectedMarker
        )
        let integrity = incrementalResultIntegrity(
            requestID: requestID,
            requestSequence: requestSequence,
            requestDigest: requestDigest,
            batchDigest: batchDigest,
            expectedHead: expectedHead,
            operationCount: operationCount,
            result: result
        )
        guard incrementalData(row, "integrity_digest") == integrity else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        return IncrementalReplay(
            requestSequence: requestSequence,
            requestDigest: requestDigest,
            batchDigest: batchDigest,
            expectedGeneration: UInt64(expectedGenerationValue),
            expectedRevision: expectedRevision,
            expectedCommitment: expectedCommitment,
            expectedMarker: expectedMarker,
            result: result
        )
    }

    func incrementalReplay(
        requestSequence: UInt64,
        target: PermissionedRemoteReplicaTarget
    ) async throws -> IncrementalReplay? {
        let rows = try await connection.query(
            """
            SELECT request_id
            FROM permissioned_remote_replica_incremental_results
            WHERE receiver_did = ? AND space_uri = ? AND repository_did = ?
              AND request_sequence = ?
            LIMIT 2
            """,
            [
                .text(target.receiverDID), .text(target.space.rawValue),
                .text(target.repositoryDID),
                incrementalSequenceData(requestSequence).sqliteData!,
            ]
        )
        guard rows.count <= 1 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        guard let requestID = rows.first?.column("request_id")?.string else {
            return nil
        }
        return try await incrementalReplay(
            requestID: requestID,
            target: target
        )
    }

    func pruneIncrementalResults(
        target: PermissionedRemoteReplicaTarget,
        progress: IncrementalProgress
    ) async throws {
        let retentionLimit = testingHooks
            .incrementalReplayRetentionOperationLimit ?? 10_000
        guard (1 ... 10_000).contains(retentionLimit) else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        let candidates = try await connection.query(
            """
            SELECT older.request_sequence
            FROM permissioned_remote_replica_incremental_results AS older
            WHERE older.receiver_did = ? AND older.space_uri = ?
              AND older.repository_did = ?
              AND (
                SELECT COALESCE(SUM(newer.operation_count), 0)
                FROM permissioned_remote_replica_incremental_results AS newer
                WHERE newer.receiver_did = older.receiver_did
                  AND newer.space_uri = older.space_uri
                  AND newer.repository_did = older.repository_did
                  AND newer.request_sequence >= older.request_sequence
              ) > ?
            ORDER BY older.request_sequence
            """,
            [
                .text(target.receiverDID), .text(target.space.rawValue),
                .text(target.repositoryDID), .integer(retentionLimit),
            ]
        )
        guard !candidates.isEmpty else { return }
        let sequences = candidates.compactMap {
            incrementalUInt64($0, "request_sequence")
        }
        guard sequences.count == candidates.count,
              let newFloor = sequences.last else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        guard newFloor > progress.replayFloor,
              newFloor <= progress.highWatermark else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        let advanced = try await connection.query(
            """
            UPDATE permissioned_remote_replica_incremental_progress
            SET replay_floor = ?
            WHERE receiver_did = ? AND space_uri = ? AND repository_did = ?
              AND replay_floor = ? AND high_watermark = ?
            RETURNING replay_floor
            """,
            [
                incrementalSequenceData(newFloor).sqliteData!,
                .text(target.receiverDID), .text(target.space.rawValue),
                .text(target.repositoryDID),
                incrementalSequenceData(progress.replayFloor).sqliteData!,
                incrementalSequenceData(progress.highWatermark).sqliteData!,
            ]
        )
        guard advanced.count == 1 else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        _ = try await connection.query(
            """
            DELETE FROM permissioned_remote_replica_incremental_results
            WHERE receiver_did = ? AND space_uri = ? AND repository_did = ?
              AND request_sequence <= ?
            """,
            [
                .text(target.receiverDID), .text(target.space.rawValue),
                .text(target.repositoryDID),
                incrementalSequenceData(newFloor).sqliteData!,
            ]
        )
    }

    func incrementalBatchDigest(
        _ batch: PermissionedRemoteReplicaIncrementalBatch
    ) -> Data {
        var hasher = SHA256()
        hasher.update(data: Data(
            "swan.permissioned.remote-replica.incremental.batch.v2".utf8
        ))
        incrementalDigestAppend(Data(batch.target.receiverDID.utf8), &hasher)
        incrementalDigestAppend(Data(batch.target.space.rawValue.utf8), &hasher)
        incrementalDigestAppend(Data(batch.target.repositoryDID.utf8), &hasher)
        incrementalDigestAppend(
            incrementalSequenceData(batch.requestSequence), &hasher
        )
        incrementalDigestAppend(
            Data(String(batch.expectedHead.generation).utf8), &hasher
        )
        incrementalDigestAppend(
            Data(batch.expectedHead.wireRevision.toString().utf8), &hasher
        )
        incrementalDigestAppend(
            Data(
                batch.expectedHead.historyFloorWireRevision.toString().utf8
            ),
            &hasher
        )
        incrementalDigestAppend(batch.expectedHead.ltHash, &hasher)
        incrementalDigestAppend(batch.expectedHead.commitment, &hasher)
        incrementalDigestAppend(batch.expectedHead.stateMarker, &hasher)
        incrementalDigestAppend(
            Data(batch.terminalHead.wireRevision.toString().utf8), &hasher
        )
        incrementalDigestAppend(batch.terminalHead.ltHash, &hasher)
        incrementalDigestAppend(batch.terminalHead.commitment, &hasher)
        incrementalDigestAppend(
            Data(String(batch.terminalHead.recordCount).utf8), &hasher
        )
        incrementalDigestAppend(
            Data(String(batch.terminalHead.operationCount).utf8), &hasher
        )
        incrementalDigestAppend(
            batch.terminalHead.operationDigest, &hasher
        )
        incrementalDigestAppend(
            Data(String(batch.operations.count).utf8), &hasher
        )
        for operation in batch.operations {
            incrementalDigestAppend(
                Data(String(operation.operationIndex).utf8), &hasher
            )
            incrementalDigestAppend(
                Data(operation.wireRevision.toString().utf8), &hasher
            )
            incrementalDigestAppend(Data(operation.action.rawValue.utf8), &hasher)
            incrementalDigestAppend(Data(operation.uri.rawValue.utf8), &hasher)
            incrementalDigestAppend(
                operation.cid.map { Data($0.string.utf8) } ?? Data(),
                &hasher
            )
            incrementalDigestAppend(
                operation.previousCID.map { Data($0.string.utf8) } ?? Data(),
                &hasher
            )
            incrementalDigestAppend(operation.value ?? Data(), &hasher)
        }
        return Data(hasher.finalize())
    }

    func incrementalResultIntegrity(
        requestID: String,
        requestSequence: UInt64,
        requestDigest: Data,
        batchDigest: Data,
        expectedHead: PermissionedRemoteReplicaHead,
        operationCount: Int,
        result: AppliedPermissionedRemoteReplicaIncrementalBatch
    ) -> Data {
        var hasher = SHA256()
        hasher.update(data: Data(
            "swan.permissioned.remote-replica.incremental.result.v2".utf8
        ))
        let values = [
            requestID,
            expectedHead.target.receiverDID,
            expectedHead.target.space.rawValue,
            expectedHead.target.repositoryDID,
            String(expectedHead.generation),
            expectedHead.wireRevision.toString(),
            String(result.head.generation),
            result.head.wireRevision.toString(),
            result.head.historyFloorWireRevision.toString(),
            String(result.recordCount),
            String(operationCount),
            String(result.appliedAt),
        ]
        incrementalDigestAppend(requestDigest, &hasher)
        incrementalDigestAppend(batchDigest, &hasher)
        incrementalDigestAppend(
            incrementalSequenceData(requestSequence), &hasher
        )
        incrementalDigestAppend(expectedHead.commitment, &hasher)
        incrementalDigestAppend(expectedHead.stateMarker, &hasher)
        incrementalDigestAppend(result.head.ltHash, &hasher)
        incrementalDigestAppend(result.head.commitment, &hasher)
        incrementalDigestAppend(result.head.stateMarker, &hasher)
        for value in values {
            incrementalDigestAppend(Data(value.utf8), &hasher)
        }
        return Data(hasher.finalize())
    }

    func incrementalStateMarker(
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
        incrementalDigestAppend(Data(target.receiverDID.utf8), &hasher)
        incrementalDigestAppend(Data(target.space.rawValue.utf8), &hasher)
        incrementalDigestAppend(Data(target.repositoryDID.utf8), &hasher)
        var fixedGeneration = generation.bigEndian
        withUnsafeBytes(of: &fixedGeneration) {
            hasher.update(data: Data($0))
        }
        incrementalDigestAppend(Data(wireRevision.toString().utf8), &hasher)
        incrementalDigestAppend(Data(historyFloor.toString().utf8), &hasher)
        incrementalDigestAppend(commitment, &hasher)
        return Data(hasher.finalize())
    }

    func incrementalDigestAppend(_ value: Data, _ hasher: inout SHA256) {
        var length = UInt64(value.count).bigEndian
        withUnsafeBytes(of: &length) { hasher.update(data: Data($0)) }
        hasher.update(data: value)
    }

    func incrementalCanonicalRecord(_ value: Data, cid: CID) -> Bool {
        (try? SpaceCARCodec.validateCanonicalRecord(
            value, expectedCID: cid.string
        )) != nil
    }

    func incrementalElement(uri: SpaceRecordURI, cid: String) -> String {
        "\(uri.collection)/\(uri.rkey)/\(cid)"
    }

    func incrementalData(_ row: SQLiteRow, _ name: String) -> Data? {
        row.column(name).flatMap(Data.init(sqliteData:))
    }

    func incrementalSequenceData(_ value: UInt64) -> Data {
        var bigEndian = value.bigEndian
        return withUnsafeBytes(of: &bigEndian) { Data($0) }
    }

    func incrementalUInt64(_ row: SQLiteRow, _ name: String) -> UInt64? {
        guard let data = incrementalData(row, name), data.count == 8 else {
            return nil
        }
        return data.reduce(UInt64(0)) { partial, byte in
            (partial << 8) | UInt64(byte)
        }
    }
}
