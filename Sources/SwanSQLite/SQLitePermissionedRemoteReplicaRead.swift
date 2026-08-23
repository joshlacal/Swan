import Crypto
import Foundation
import Petrel
import SQLiteNIO
import SwanSpaces
import SwanStorage

/// One durable remote-replica record snapshot reconstructed from the
/// receiver's block store. `revision` is intentionally absent: remote-replica
/// state tracks a wire TID, not the server-side UInt64 revision, so a
/// `SpaceRecord` would misrepresent it.
public struct PermissionedRemoteReplicaRecordSnapshot: Sendable, Equatable {
    public let uri: SpaceRecordURI
    public let cid: String
    public let value: Data

    public init(uri: SpaceRecordURI, cid: String, value: Data) {
        self.uri = uri
        self.cid = cid
        self.value = value
    }
}

extension SQLiteAccountDatabase {
    /// Enumerates every durable remote-replica record for one target
    /// (receiver/space/repository), reconstructing each value from its block
    /// chunks and revalidating the dag-cbor CID. Ordering is stable by
    /// (collection, rkey). This is an additive, read-only companion to the
    /// existing single-record `permissionedRemoteReplicaRecord` API.
    public func permissionedRemoteReplicaRecords(
        target: PermissionedRemoteReplicaTarget,
        collection: String? = nil
    ) async throws -> [PermissionedRemoteReplicaRecordSnapshot] {
        guard target.receiverDID == accountDID else {
            throw PermissionedRemoteReplicaRecoveryError.receiverMismatch
        }
        if let collection {
            _ = try SpaceRecordURI(
                space: target.space,
                author: target.repositoryDID,
                collection: collection,
                rkey: "2"
            )
        }
        return try await withConnectionGate {
            try await writerReadTransaction {
                guard let head = try await loadPermissionedRemoteReplicaHead(
                    target: target
                ) else { return [] }
                let pageSize = PermissionedRemoteReplicaRecoveryBudgets
                    .maximumRowsPerPass
                var snapshots: [PermissionedRemoteReplicaRecordSnapshot] = []
                var lastCollection = ""
                var lastRkey = ""
                while true {
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
                            .text(target.space.rawValue),
                            .text(target.repositoryDID),
                            .integer(Int(head.generation)),
                            .text(lastCollection),
                            .text(lastCollection),
                            .text(lastRkey),
                            .integer(pageSize),
                        ]
                    )
                    guard !rows.isEmpty,
                          rows.count <= pageSize,
                          snapshots.count + rows.count
                            <= SpaceCARRecoveryLimits.absoluteMaximumIndexEntries
                    else {
                        throw PermissionedRemoteReplicaRecoveryError
                            .corruptReplica
                    }
                    var advanced = false
                    for row in rows {
                        guard let collectionName = row.column("collection")?.string,
                              let rkey = row.column("rkey")?.string,
                              let cidRaw = row.column("cid")?.string,
                              let cid = try? CID.parse(cidRaw),
                              cid.string == cidRaw,
                              (try? SpaceRecordURI(
                                space: target.space,
                                author: target.repositoryDID,
                                collection: collectionName,
                                rkey: rkey
                              )) != nil,
                              collection == nil || collectionName == collection,
                              (collectionName, rkey) > (lastCollection, lastRkey)
                        else {
                            throw PermissionedRemoteReplicaRecoveryError
                                .corruptReplica
                        }
                        let value = try await remoteReplicaRecordValue(
                            target: target,
                            generation: head.generation,
                            cid: cid
                        )
                        snapshots.append(
                            PermissionedRemoteReplicaRecordSnapshot(
                                uri: try SpaceRecordURI(
                                    space: target.space,
                                    author: target.repositoryDID,
                                    collection: collectionName,
                                    rkey: rkey
                                ),
                                cid: cidRaw,
                                value: value
                            )
                        )
                        lastCollection = collectionName
                        lastRkey = rkey
                        advanced = true
                    }
                    if rows.count < pageSize || !advanced { break }
                }
                return snapshots
            }
        }
    }

    /// Reassembles one record value from its block chunks and revalidates the
    /// canonical dag-cbor CID, mirroring the single-record read.
    private func remoteReplicaRecordValue(
        target: PermissionedRemoteReplicaTarget,
        generation: UInt64,
        cid: CID
    ) async throws -> Data {
        let chunkRows = try await connection.query(
            """
            SELECT blocks.byte_count, blocks.chunk_count,
                   chunks.chunk_index, chunks.bytes
            FROM permissioned_remote_replica_blocks AS blocks
            JOIN permissioned_remote_replica_block_chunks AS chunks
              ON chunks.space_uri = blocks.space_uri
             AND chunks.repository_did = blocks.repository_did
             AND chunks.generation = blocks.generation
             AND chunks.cid = blocks.cid
            WHERE blocks.space_uri = ? AND blocks.repository_did = ?
              AND blocks.generation = ? AND blocks.cid = ?
            ORDER BY chunks.chunk_index
            LIMIT ?
            """,
            [
                .text(target.space.rawValue),
                .text(target.repositoryDID),
                .integer(Int(generation)),
                .text(cid.string),
                .integer(
                    PermissionedRemoteReplicaRecoveryBudgets
                        .maximumChunksPerRecord + 1
                ),
            ]
        )
        guard !chunkRows.isEmpty,
              chunkRows.count
                <= PermissionedRemoteReplicaRecoveryBudgets
                    .maximumChunksPerRecord,
              let byteCount = chunkRows[0].column("byte_count")?.integer,
              let chunkCount = chunkRows[0].column("chunk_count")?.integer,
              (1 ... SpaceCARRecoveryLimits.absoluteMaximumRecordBytes)
                .contains(byteCount),
              (1 ... PermissionedRemoteReplicaRecoveryBudgets
                .maximumChunksPerRecord).contains(chunkCount)
        else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        var output = Data()
        var hasher = SHA256()
        var expectedIndex = 0
        for row in chunkRows {
            guard let bytes = row.column("bytes").flatMap(Data.init(sqliteData:)),
                  remoteReplicaSnapshotInteger(row, "byte_count") == byteCount,
                  remoteReplicaSnapshotInteger(row, "chunk_count") == chunkCount,
                  remoteReplicaSnapshotInteger(row, "chunk_index")
                    == expectedIndex,
                  !bytes.isEmpty,
                  bytes.count
                    <= SpaceCARRecoveryLimits.maximumChunkBytes,
                  output.count
                    <= SpaceCARRecoveryLimits
                        .absoluteMaximumRecordBytes - bytes.count
            else {
                throw PermissionedRemoteReplicaRecoveryError.corruptReplica
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
              ) == cid else {
            throw PermissionedRemoteReplicaRecoveryError.corruptReplica
        }
        return output
    }

    private func remoteReplicaSnapshotInteger(
        _ row: SQLiteRow,
        _ column: String
    ) -> Int? {
        row.column(column)?.integer
    }
}
