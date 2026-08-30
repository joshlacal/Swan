import Foundation
import NIOCore
import Petrel
import SQLiteNIO
import PetrelRepo
import SwanStorage

extension SQLiteAccountDatabase {
    /// Validates the live MST and externalizes traversal order into TEMP
    /// tables. Memory is bounded by one decoded node or record body; queue,
    /// duplicate detection, record encounter order, and index comparison are
    /// all SQLite-backed inside the caller's snapshot transaction.
    func writeBoundedPublicRepositoryCAR(
        state: PublicRepositoryState,
        commit: StructurallyValidatedPublicRepositorySignedCommit,
        to sink: any PublicRepositoryCARByteSink
    ) async throws {
        let limits = PublicRepositoryLimits.standard
        try await populatePublicExportReachabilityTables(state: state, limits: limits)
        do {
            let missing = try await connection.query(
                """
                SELECT collection, rkey, record_cid
                FROM temp.swan_public_export_index
                EXCEPT
                SELECT collection, rkey, record_cid
                FROM public_repository_record_index
                LIMIT 1
                """
            )
            let extra = try await connection.query(
                """
                SELECT collection, rkey, record_cid
                FROM public_repository_record_index
                EXCEPT
                SELECT collection, rkey, record_cid
                FROM temp.swan_public_export_index
                LIMIT 1
                """
            )
            guard missing.isEmpty, extra.isEmpty else {
                throw PublicRepositoryReadError.unavailable(reason: .projectionMismatch)
            }

            let stream = SQLitePublicRepositoryExportStream(
                connection: connection,
                commit: PublicRepositoryBlock(
                    cid: commit.commitCID, bytes: commit.signedCommitBytes
                )
            )
            _ = try await PublicRepositoryCAR.write(
                rootCID: commit.commitCID,
                blocks: stream,
                to: sink,
                limits: limits
            )
            try await resetPublicExportTables()
        } catch {
            try? await resetPublicExportTables()
            throw error
        }
    }

    /// The single canonical reachability walk shared between export and GC so definitions cannot drift.
    func populatePublicExportReachabilityTables(
        state: PublicRepositoryState,
        limits: PublicRepositoryLimits = .standard
    ) async throws {
        try await resetPublicExportTables()
        try await enqueuePublicExportNode(
            cid: state.dataCID,
            level: 0,
            lower: nil,
            upper: nil,
            expectedLayer: nil,
            isRoot: true
        )

        var reachableBytes = 0
        var nodeCount = 0
        while let row = try await nextPublicExportWork() {
            try Task.checkCancellation()
            let sequence = try publicExportInteger(row, "sequence")
            let cid = try publicExportCID(row, "cid")
            let level = try publicExportInteger(row, "level")
            let lower = row.column("lower_bound")?.string
            let upper = row.column("upper_bound")?.string
            let expectedLayer = row.column("expected_layer")?.integer
            let isRoot = try publicExportInteger(row, "is_root") == 1
            _ = try await connection.query(
                "DELETE FROM temp.swan_public_export_work WHERE sequence = ?",
                [.integer(sequence)]
            )

            nodeCount += 1
            guard nodeCount <= limits.maximumMSTNodes else {
                throw RepositoryMSTValidationError.nodeLimitExceeded
            }
            let bytes = try await publicExportBlock(cid)
            reachableBytes = try publicExportAdding(
                bytes.count, to: reachableBytes, maximum: limits.maximumCARBytes
            )
            let node = try RepositoryMSTCodec.decode(bytes)
            guard node.entries.count <= limits.maximumMSTEntriesPerNode else {
                throw RepositoryMSTValidationError.entryLimitExceeded
            }
            let leaves = try RepositoryMSTCodec.reconstructedLeaves(from: node)
            let layer: Int
            if let first = leaves.first {
                layer = first.path.keyDepth
                guard (0...128).contains(layer),
                      expectedLayer == nil || layer == expectedLayer,
                      leaves.allSatisfy({
                          $0.path.keyDepth == layer
                      }) else {
                    throw RepositoryMSTValidationError.invalidLayer
                }
            } else if isRoot {
                guard node.leftTreeCID == nil,
                      bytes == PublicRepositoryGenesisCodec.canonicalEmptyMST else {
                    throw RepositoryMSTValidationError.invalidEmptyTopology
                }
                layer = 0
            } else {
                guard let expectedLayer, expectedLayer > 0,
                      node.leftTreeCID != nil else {
                    throw RepositoryMSTValidationError.invalidEmptyTopology
                }
                layer = expectedLayer
            }
            _ = try await connection.query(
                """
                INSERT INTO temp.swan_public_export_nodes(cid, encounter_order)
                VALUES (?, ?)
                """,
                [.text(cid.string), .integer(sequence)]
            )

            if leaves.isEmpty {
                if let left = node.leftTreeCID {
                    try await enqueuePublicExportNode(
                        cid: left, level: level + 1, lower: lower, upper: upper,
                        expectedLayer: layer - 1, isRoot: false
                    )
                }
                continue
            }
            for leaf in leaves {
                let key = leaf.path.mstKey
                guard (lower == nil || lower! < key),
                      (upper == nil || key < upper!) else {
                    throw RepositoryMSTValidationError.subtreeOutOfRange
                }
                _ = try await connection.query(
                    """
                    INSERT INTO temp.swan_public_export_index(
                        collection, rkey, record_cid
                    ) VALUES (?, ?, ?)
                    """,
                    [
                        .text(leaf.path.collection), .text(leaf.path.recordKey),
                        .text(leaf.recordCID.string),
                    ]
                )
                _ = try await connection.query(
                    """
                    INSERT OR IGNORE INTO temp.swan_public_export_records(cid)
                    VALUES (?)
                    """,
                    [.text(leaf.recordCID.string)]
                )
                _ = try await connection.query(
                    """
                    INSERT OR IGNORE INTO temp.swan_public_export_expectations(
                        cid, collection
                    ) VALUES (?, ?)
                    """,
                    [.text(leaf.recordCID.string), .text(leaf.path.collection)]
                )
            }
            guard layer > 0 ||
                    (node.leftTreeCID == nil &&
                     leaves.allSatisfy { $0.rightTreeCID == nil }) else {
                throw RepositoryMSTValidationError.invalidLayer
            }
            if let left = node.leftTreeCID {
                try await enqueuePublicExportNode(
                    cid: left, level: level + 1, lower: lower,
                    upper: leaves[0].path.mstKey,
                    expectedLayer: layer - 1, isRoot: false
                )
            }
            for index in leaves.indices {
                guard let right = leaves[index].rightTreeCID else { continue }
                try await enqueuePublicExportNode(
                    cid: right,
                    level: level + 1,
                    lower: leaves[index].path.mstKey,
                    upper: index + 1 < leaves.count
                        ? leaves[index + 1].path.mstKey : upper,
                    expectedLayer: layer - 1,
                    isRoot: false
                )
            }
        }

        var recordSequence = 0
        while true {
            let records = try await connection.query(
                """
                SELECT sequence, cid
                FROM temp.swan_public_export_records
                WHERE sequence > ?
                ORDER BY sequence
                LIMIT 1
                """,
                [.integer(recordSequence)]
            )
            guard let row = records.first else { break }
            recordSequence = try publicExportInteger(row, "sequence")
            try Task.checkCancellation()
            let cid = try publicExportCID(row, "cid")
            let bytes = try await publicExportBlock(cid)
            guard bytes.count <= limits.maximumRecordBlockBytes else {
                throw RepositoryMSTValidationError.recordBlockTooLarge
            }
            reachableBytes = try publicExportAdding(
                bytes.count, to: reachableBytes, maximum: limits.maximumCARBytes
            )
            let expectations = try await connection.query(
                """
                SELECT collection
                FROM temp.swan_public_export_expectations
                WHERE cid = ?
                LIMIT 2
                """,
                [.text(cid.string)]
            )
            guard expectations.count == 1 else {
                throw RepositoryMSTValidationError.missingRecordBlock
            }
            for expectation in expectations {
                let collection = try publicExportText(expectation, "collection")
                do {
                    try RepositoryMSTValidation.validateRecordBlock(
                        bytes,
                        for: PublicRepositoryPath(
                            collection: collection, recordKey: "validation"
                        ),
                        limits: limits
                    )
                } catch {
                    throw RepositoryMSTValidationError.invalidRecordBlock
                }
            }
        }
    }

    /// Reclaims unreachable blocks when quota pressure triggers it or on database open.
    func garbageCollectPublicRepositoryBlocksInTransaction(
        state: PublicRepositoryState,
        reductionOnly: Bool = false
    ) async throws {
        let quota = publicRepositoryBlockQuota
        let countAndBytes = try await measurePublicRepositoryBlocksInTransaction()
        guard countAndBytes.count > quota.maximumTotalBlocks || countAndBytes.bytes > quota.maximumTotalBytes else {
            return
        }

        try await populatePublicExportReachabilityTables(state: state, limits: .standard)
        do {
            while true {
                let deleted = try await connection.query(
                    """
                    DELETE FROM public_repository_blocks
                    WHERE cid IN (
                        SELECT b.cid FROM public_repository_blocks AS b
                        WHERE b.cid != ?
                          AND b.cid NOT IN (SELECT cid FROM temp.swan_public_export_nodes)
                          AND b.cid NOT IN (SELECT cid FROM temp.swan_public_export_records)
                        LIMIT 1000
                    )
                    RETURNING cid
                    """,
                    [.text(state.commitCID.string)]
                )
                guard !deleted.isEmpty else { break }
            }
            try await resetPublicExportTables()
        } catch {
            try? await resetPublicExportTables()
            throw error
        }
        let remeasured = try await measurePublicRepositoryBlocksInTransaction()
        if remeasured.count > quota.maximumTotalBlocks || remeasured.bytes > quota.maximumTotalBytes {
            let reducedExceededDimension =
                (!((countAndBytes.count > quota.maximumTotalBlocks))
                  || remeasured.count < countAndBytes.count)
                && (!((countAndBytes.bytes > quota.maximumTotalBytes))
                  || remeasured.bytes < countAndBytes.bytes)
            if !(reductionOnly && reducedExceededDimension) {
                throw PublicRepositoryMutationStoreError.blockQuotaExceeded
            }
        }
    }

    func garbageCollectPublicRepositoryBlocksWithoutGate(state: PublicRepositoryState) async throws {
        try await transaction {
            try await garbageCollectPublicRepositoryBlocksInTransaction(state: state)
        }
    }

    func measurePublicRepositoryBlocksInTransaction() async throws -> (count: Int, bytes: Int) {
        let rows = try await connection.query(
            "SELECT block_count, total_bytes FROM public_repository_block_usage WHERE singleton = 1"
        )
        if let row = rows.first,
           let count = row.column("block_count")?.integer,
           let bytes = row.column("total_bytes")?.integer {
            return (count, bytes)
        }
        let fallbackRows = try await connection.query(
            "SELECT COUNT(*) AS block_count, COALESCE(SUM(length(bytes)), 0) AS total_bytes FROM public_repository_blocks"
        )
        let count = fallbackRows.first?.column("block_count")?.integer ?? 0
        let bytes = fallbackRows.first?.column("total_bytes")?.integer ?? 0
        _ = try await connection.query(
            """
            INSERT INTO public_repository_block_usage(singleton, block_count, total_bytes)
            VALUES (1, ?, ?)
            ON CONFLICT(singleton) DO UPDATE SET
                block_count = excluded.block_count,
                total_bytes = excluded.total_bytes
            """,
            [.integer(count), .integer(bytes)]
        )
        return (count, bytes)
    }

    private func resetPublicExportTables() async throws {
        for statement in [
            "DROP TABLE IF EXISTS temp.swan_public_export_work",
            "DROP TABLE IF EXISTS temp.swan_public_export_references",
            "DROP TABLE IF EXISTS temp.swan_public_export_nodes",
            "DROP TABLE IF EXISTS temp.swan_public_export_records",
            "DROP TABLE IF EXISTS temp.swan_public_export_expectations",
            "DROP TABLE IF EXISTS temp.swan_public_export_index",
            """
            CREATE TEMP TABLE swan_public_export_work(
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                level INTEGER NOT NULL,
                cid TEXT NOT NULL,
                lower_bound TEXT,
                upper_bound TEXT,
                expected_layer INTEGER,
                is_root INTEGER NOT NULL
            )
            """,
            """
            CREATE TEMP TABLE swan_public_export_references(
                cid TEXT PRIMARY KEY
            )
            """,
            """
            CREATE TEMP TABLE swan_public_export_nodes(
                cid TEXT PRIMARY KEY,
                encounter_order INTEGER NOT NULL UNIQUE
            )
            """,
            """
            CREATE TEMP TABLE swan_public_export_records(
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                cid TEXT NOT NULL UNIQUE
            )
            """,
            """
            CREATE TEMP TABLE swan_public_export_expectations(
                cid TEXT NOT NULL,
                collection TEXT NOT NULL,
                PRIMARY KEY(cid, collection)
            )
            """,
            """
            CREATE TEMP TABLE swan_public_export_index(
                collection TEXT NOT NULL,
                rkey TEXT NOT NULL,
                record_cid TEXT NOT NULL,
                PRIMARY KEY(collection, rkey)
            )
            """,
        ] {
            _ = try await connection.query(statement)
        }
    }

    private func enqueuePublicExportNode(
        cid: CID,
        level: Int,
        lower: String?,
        upper: String?,
        expectedLayer: Int?,
        isRoot: Bool
    ) async throws {
        let existing = try await connection.query(
            "SELECT 1 FROM temp.swan_public_export_references WHERE cid = ?",
            [.text(cid.string)]
        )
        guard existing.isEmpty else {
            throw RepositoryMSTValidationError.repeatedNode
        }
        _ = try await connection.query(
            "INSERT INTO temp.swan_public_export_references(cid) VALUES (?)",
            [.text(cid.string)]
        )
        _ = try await connection.query(
            """
            INSERT INTO temp.swan_public_export_work(
                level, cid, lower_bound, upper_bound, expected_layer, is_root
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                .integer(level), .text(cid.string),
                lower.map(SQLiteData.text) ?? .null,
                upper.map(SQLiteData.text) ?? .null,
                expectedLayer.map(SQLiteData.integer) ?? .null,
                .integer(isRoot ? 1 : 0),
            ]
        )
    }

    private func nextPublicExportWork() async throws -> SQLiteRow? {
        try await connection.query(
            """
            SELECT sequence, level, cid, lower_bound, upper_bound,
                   expected_layer, is_root
            FROM temp.swan_public_export_work
            ORDER BY level ASC, sequence ASC
            LIMIT 1
            """
        ).first
    }

    private func publicExportBlock(_ cid: CID) async throws -> Data {
        guard let bytes = try await SQLitePublicRepositoryBlockSource(
            connection: connection
        ).block(for: cid) else {
            throw RepositoryMSTValidationError.missingBlock
        }
        return bytes
    }
}

private final class SQLitePublicRepositoryExportStream:
    PublicRepositoryCARBlockStream,
    @unchecked Sendable
{
    private let connection: SQLiteConnection
    private var commit: PublicRepositoryBlock?
    private var nodeOrder = -1
    private var recordOrder = 0
    private var readingRecords = false

    init(connection: SQLiteConnection, commit: PublicRepositoryBlock) {
        self.connection = connection
        self.commit = commit
    }

    func nextBlock() async throws -> PublicRepositoryBlock? {
        if let commit {
            self.commit = nil
            return commit
        }
        if !readingRecords {
            let rows = try await connection.query(
                """
                SELECT n.encounter_order, b.cid, b.bytes
                FROM temp.swan_public_export_nodes AS n
                JOIN public_repository_blocks AS b ON b.cid = n.cid
                WHERE n.encounter_order > ?
                ORDER BY n.encounter_order ASC
                LIMIT 1
                """,
                [.integer(nodeOrder)]
            )
            if let row = rows.first {
                nodeOrder = try publicExportInteger(row, "encounter_order")
                return try publicExportBlock(row)
            }
            readingRecords = true
        }
        let rows = try await connection.query(
            """
            SELECT r.sequence, b.cid, b.bytes
            FROM temp.swan_public_export_records AS r
            JOIN public_repository_blocks AS b ON b.cid = r.cid
            WHERE r.sequence > ?
            ORDER BY r.sequence ASC
            LIMIT 1
            """,
            [.integer(recordOrder)]
        )
        guard let row = rows.first else { return nil }
        recordOrder = try publicExportInteger(row, "sequence")
        return try publicExportBlock(row)
    }
}

private func publicExportBlock(_ row: SQLiteRow) throws -> PublicRepositoryBlock {
    guard let value = row.column("bytes"),
          let bytes = Data(sqliteData: value) else {
        throw PublicRepositoryReadError.unavailable(reason: .blockMaterializationFailed)
    }
    return PublicRepositoryBlock(
        cid: try publicExportCID(row, "cid"),
        bytes: bytes
    )
}

private func publicExportText(_ row: SQLiteRow, _ column: String) throws -> String {
    guard let value = row.column(column)?.string, !value.isEmpty else {
        throw PublicRepositoryReadError.unavailable(reason: .storageFailure)
    }
    return value
}

private func publicExportInteger(_ row: SQLiteRow, _ column: String) throws -> Int {
    guard let value = row.column(column)?.integer else {
        throw PublicRepositoryReadError.unavailable(reason: .storageFailure)
    }
    return value
}

private func publicExportCID(_ row: SQLiteRow, _ column: String) throws -> CID {
    do {
        let cid = try CID.parse(publicExportText(row, column))
        try PublicRepositoryCID.validate(cid)
        return cid
    } catch {
        throw PublicRepositoryReadError.unavailable(reason: .storageFailure)
    }
}

private func publicExportAdding(
    _ amount: Int,
    to total: Int,
    maximum: Int
) throws -> Int {
    let (next, overflow) = total.addingReportingOverflow(amount)
    guard !overflow, next <= maximum else {
        throw RepositoryMSTValidationError.reachableRepositoryByteLimitExceeded
    }
    return next
}
