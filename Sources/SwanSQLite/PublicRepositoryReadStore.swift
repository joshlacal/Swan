import Foundation
import Petrel
import SQLiteNIO
import SwanPublicRepository
import SwanStorage

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

struct SQLitePublicRepositoryFileIdentity: Sendable, Equatable {
    let device: UInt64
    let inode: UInt64
}

/// Process-local authority to serve one exact public repository generation.
/// It is minted only after the full projection, PLC identity, control intent,
/// and signed head have all been authenticated.
struct SQLiteVerifiedPublicRepositoryGeneration: Sendable {
    let id: UUID
    let description: PublicRepositoryReadDescription
    let controlAccount: AccountControlAccount
    let repositoryVerificationIdentity: String
    let dataVersion: Int64
    let fileIdentity: SQLitePublicRepositoryFileIdentity
}

struct SQLitePublicRepositoryRecordRead: Sendable {
    let state: PublicRepositoryState
    let record: PublicRepositoryReadRecord?
}

struct SQLitePublicRepositoryPageRead: Sendable {
    let state: PublicRepositoryState
    let page: PublicRepositoryReadPage
}

extension SQLiteAccountDatabase {
    /// Returns the DID bound to this managed account database. Replication
    /// callers use this before any network fetch so a valid-but-different DID
    /// cannot cause public blobs to be adopted into the wrong account.
    public func publicRepositoryDID() -> String {
        accountDID
    }

    /// Returns the canonical raw-CID references embedded in the installed
    /// public records. Record bytes are decoded one at a time under the
    /// connection gate; callers receive identifiers only, never a materialized
    /// repository projection. Raw CIDs are the AT Protocol blob namespace,
    /// while DAG-CBOR links remain repository blocks and are ignored by the
    /// codec projection.
    public func publicRepositoryBlobCIDs() async throws -> [CID] {
        try await withConnectionGate {
            try await readTransaction {
                // Reject oversized or malformed index projections before the
                // optional promoter decodes any record block. The preflight
                // itself is a bounded keyset walk and never selects values.
                try await preflightPublicReadProjectionWithoutGate()
                var cidsByString: [String: CID] = [:]
                var lastCollection: String?
                var lastRecordKey: String?
                var scannedRecords = 0
                while true {
                    try Task.checkCancellation()
                    let rows: [SQLiteRow]
                    if let lastCollection, let lastRecordKey {
                        rows = try await connection.query(
                            """
                            SELECT collection, rkey, record_cid
                            FROM public_repository_record_index
                            WHERE collection > ?
                               OR (collection = ? AND rkey > ?)
                            ORDER BY collection ASC, rkey ASC
                            LIMIT ?
                            """,
                            [
                                .text(lastCollection),
                                .text(lastCollection),
                                .text(lastRecordKey),
                                .integer(
                                    PublicRepositoryReadLimits
                                        .blobPromotionPageSize
                                ),
                            ]
                        )
                    } else {
                        rows = try await connection.query(
                            """
                            SELECT collection, rkey, record_cid
                            FROM public_repository_record_index
                            ORDER BY collection ASC, rkey ASC
                            LIMIT ?
                            """,
                            [
                                .integer(
                                    PublicRepositoryReadLimits
                                        .blobPromotionPageSize
                                ),
                            ]
                        )
                    }
                    if rows.isEmpty { break }
                    guard rows.count <= PublicRepositoryReadLimits
                        .maximumBlobPromotionIndexEntries - scannedRecords else {
                        throw PublicRepositoryReadError.resourceLimitExceeded
                    }
                    scannedRecords += rows.count
                    for row in rows {
                        let collection = try publicReadRequiredText(
                            row, "collection"
                        )
                        let rkey = try publicReadRequiredText(row, "rkey")
                        let path = try PublicRepositoryPath(
                            collection: collection, recordKey: rkey
                        )
                        let recordCID = try publicReadCID(
                            try publicReadRequiredText(row, "record_cid")
                        )
                        let bytes = try await blockBytesWithoutGate(recordCID)
                        let value = try RepositoryMSTValidation.decodeRecordBlock(
                            bytes, for: path
                        )
                        let record = try PublicRepositoryRecordCodec.publicRecord(
                            from: value, collection: collection
                        )
                        for cid in PublicRepositoryRecordCodec.publicBlobCIDs(
                            in: record
                        ) {
                            if cidsByString[cid.string] == nil {
                                guard cidsByString.count < PublicRepositoryReadLimits
                                    .maximumBlobPromotionUniqueCIDs else {
                                    throw PublicRepositoryReadError
                                        .resourceLimitExceeded
                                }
                                cidsByString[cid.string] = cid
                            }
                        }
                        lastCollection = collection
                        lastRecordKey = rkey
                    }
                    if rows.count < PublicRepositoryReadLimits.blobPromotionPageSize {
                        break
                    }
                }
                return cidsByString.keys.sorted().compactMap { cidsByString[$0] }
            }
        }
    }

    func admitPublicRepositoryGeneration(
        account: AccountControlAccount,
        identityVerifier: any PublicPLCGenesisVerifying
    ) async throws -> SQLiteVerifiedPublicRepositoryGeneration {
        try await withConnectionGate {
            try await readTransaction {
                let fileIdentity = try publicRepositoryFileIdentityWithoutGate()
                let dataVersion = try await publicRepositoryDataVersionWithoutGate()
                guard let state = try await loadPublicRepositoryStateWithoutGate() else {
                    throw PublicRepositoryReadError.unavailable
                }
                try await verifyProjectionWithoutGate(state: state)
                let rows = try await connection.query(
                    """
                    SELECT DISTINCT collection
                    FROM public_repository_record_index
                    ORDER BY collection ASC
                    """
                )
                let collections = try rows.map {
                    try publicReadRequiredText($0, "collection")
                }
                let identityRows = try await connection.query(
                    """
                    SELECT canonical_handle, pds_origin,
                           request_id, operation_signing_did_key,
                           operation_rotation_did_key, operation_signature,
                           signing_key_reference, rotation_key_reference,
                           public_genesis_commit_cid, stage
                    FROM plc_account_preparation_journal
                    """
                )
                let identityRow = identityRows.first
                let storedSigningReference = try identityRow.map {
                    try publicReadRequiredText($0, "signing_key_reference")
                }
                let storedRotationReference = try identityRow.map {
                    try publicReadRequiredText($0, "rotation_key_reference")
                }
                let storedGenesisCID = try identityRow.map {
                    try publicReadRequiredText($0, "public_genesis_commit_cid")
                }
                guard identityRows.count == 1,
                      let identityRow,
                      try publicReadRequiredInteger(identityRow, "stage")
                        == PLCAccountPreparationStage.submitted.rawValue,
                      let storedGenesisCID,
                      let signingKey = account.signingKey,
                      let rotationKey = account.rotationKey,
                      account.publicGenesisCommitCID == storedGenesisCID else {
                    throw PublicRepositoryReadError.unavailable
                }
                let plcHandle = try publicReadRequiredText(
                    identityRow, "canonical_handle"
                )
                let signingDIDKey = try publicReadRequiredText(
                    identityRow, "operation_signing_did_key"
                )
                let genesisOperationCID = try identityVerifier.verifyGenesis(
                    facts: PublicPLCGenesisFacts(
                        signingDIDKey: signingDIDKey,
                    rotationDIDKey: try publicReadRequiredText(
                        identityRow, "operation_rotation_did_key"
                    ),
                    canonicalHandle: plcHandle,
                    pdsOrigin: try publicReadRequiredText(identityRow, "pds_origin"),
                    signature: try publicReadRequiredText(
                        identityRow, "operation_signature"
                    )
                    ),
                    expectedDID: account.did
                )
                let history = try await publicPLCOperationHistoryWithoutGate()
                let identity: PublicRepositoryReadIdentity
                if history.isEmpty {
                    guard signingKey.reference == storedSigningReference,
                          rotationKey.reference == storedRotationReference else {
                        throw PublicRepositoryReadError.unavailable
                    }
                    identity = try PublicRepositoryReadIdentity(
                        canonicalHandle: plcHandle,
                        pdsOrigin: try publicReadRequiredText(identityRow, "pds_origin"),
                        signingDIDKey: signingDIDKey,
                        handleIsCorrect: plcHandle == account.canonicalHandle,
                        preparationRequestID: try publicReadRequiredText(
                            identityRow, "request_id"
                        ),
                        genesisOperationCID: genesisOperationCID
                    )
                } else {
                    guard let historyVerifier = identityVerifier
                        as? any PublicPLCIdentityVerifying else {
                        throw PublicRepositoryReadError.unavailable
                    }
                    let terminal = try historyVerifier.verifyIdentityHistory(
                        history,
                        expectedDID: account.did
                    )
                    guard storedSigningReference == "account-signing:1",
                          storedRotationReference == "account-rotation:1",
                          terminal.genesisOperationCID == genesisOperationCID,
                          signingKey.generation == terminal.keyGeneration,
                          rotationKey.generation == terminal.keyGeneration,
                          signingKey.reference
                            == "\(signingKey.purpose.rawValue):\(terminal.keyGeneration)",
                          rotationKey.reference
                            == "\(rotationKey.purpose.rawValue):\(terminal.keyGeneration)" else {
                        throw PublicRepositoryReadError.unavailable
                    }
                    identity = try PublicRepositoryReadIdentity(
                        canonicalHandle: terminal.canonicalHandle,
                        pdsOrigin: terminal.pdsOrigin,
                        signingDIDKey: terminal.signingDIDKey,
                        handleIsCorrect: terminal.canonicalHandle == account.canonicalHandle,
                        preparationRequestID: try publicReadRequiredText(
                            identityRow, "request_id"
                        ),
                        genesisOperationCID: terminal.genesisOperationCID,
                        terminalOperationCID: terminal.terminalOperationCID
                    )
                }
                guard let repositoryAuthenticator = identityVerifier
                    as? any PublicPLCRepositoryAuthenticating else {
                    throw PublicRepositoryReadError.unavailable
                }
                let commitBytes = try await blockBytesWithoutGate(
                    state.commitCID
                )
                let authentication = try await repositoryAuthenticator
                    .authenticateRepositoryCommit(
                        signedCommitBytes: commitBytes,
                        expectedCommitCID: state.commitCID,
                        expectedDID: accountDID,
                        signingDIDKey: identity.signingDIDKey
                    )
                guard authentication.commitCID == state.commitCID,
                      authentication.descriptor.did == state.did,
                      authentication.descriptor.revision.value
                        == state.revision,
                      authentication.descriptor.dataCID == state.dataCID else {
                    throw PublicRepositoryReadError.unavailable
                }
                let description = try PublicRepositoryReadDescription(
                    did: accountDID,
                    canonicalHandle: account.canonicalHandle,
                    status: account.status,
                    state: state,
                    collections: collections,
                    identity: identity
                )
                guard try await publicRepositoryDataVersionWithoutGate()
                        == dataVersion,
                      try publicRepositoryFileIdentityWithoutGate()
                        == fileIdentity else {
                    throw PublicRepositoryReadError.unavailable
                }
                return SQLiteVerifiedPublicRepositoryGeneration(
                    id: UUID(),
                    description: description,
                    controlAccount: account,
                    repositoryVerificationIdentity:
                        authentication.verificationIdentity,
                    dataVersion: dataVersion,
                    fileIdentity: fileIdentity
                )
            }
        }
    }

    func preflightPublicReadProjectionWithoutGate() async throws {
        var recordCount = 0
        var collectionCount = 0
        var collectionBytes = 0
        var lastCollection: String?
        var lastRecordKey: String?

        while true {
            try Task.checkCancellation()
            let rows: [SQLiteRow]
            if let lastCollection, let lastRecordKey {
                rows = try await connection.query(
                    """
                    SELECT collection, rkey
                    FROM public_repository_record_index
                    WHERE collection > ?
                       OR (collection = ? AND rkey > ?)
                    ORDER BY collection ASC, rkey ASC
                    LIMIT ?
                    """,
                    [
                        .text(lastCollection),
                        .text(lastCollection),
                        .text(lastRecordKey),
                        .integer(
                            PublicRepositoryReadLimits
                                .projectionPreflightPageSize
                        ),
                    ]
                )
            } else {
                rows = try await connection.query(
                    """
                    SELECT collection, rkey
                    FROM public_repository_record_index
                    ORDER BY collection ASC, rkey ASC
                    LIMIT ?
                    """,
                    [
                        .integer(
                            PublicRepositoryReadLimits
                                .projectionPreflightPageSize
                        ),
                    ]
                )
            }
            if rows.isEmpty { break }

            for row in rows {
                recordCount += 1
                guard recordCount <= PublicRepositoryReadLimits
                    .maximumGenerationIndexEntries else {
                    throw PublicRepositoryReadError.resourceLimitExceeded
                }
                let collection = try publicReadRequiredText(row, "collection")
                let recordKey = try publicReadRequiredText(row, "rkey")
                _ = try PublicRepositoryPath(
                    collection: collection, recordKey: recordKey
                )
                if collection != lastCollection {
                    collectionCount += 1
                    let collectionByteCount = collection.utf8.count
                    guard collectionCount <= PublicRepositoryReadLimits
                        .maximumDescribeRepoCollections,
                        collectionByteCount <= Int(
                            PublicRepositoryReadLimits
                                .maximumDescribeRepoCollectionBytes
                        ),
                        collectionBytes <= PublicRepositoryReadLimits
                            .maximumDescribeRepoCollectionBytes
                            - collectionByteCount else {
                        throw PublicRepositoryReadError.resourceLimitExceeded
                    }
                    collectionBytes += collectionByteCount
                    lastCollection = collection
                }
                lastRecordKey = recordKey
            }
            if rows.count < PublicRepositoryReadLimits
                .projectionPreflightPageSize {
                break
            }
        }
    }

    /// Compatibility entry point for storage-level callers. Production
    /// request routing uses the admitted generation methods below and never
    /// repeats the full projection walk.
    func readPublicRepositoryDescription(
        account: AccountControlAccount,
        identityVerifier: any PublicPLCGenesisVerifying
    ) async throws -> PublicRepositoryReadDescription {
        let generation = try await admitPublicRepositoryGeneration(
            account: account,
            identityVerifier: identityVerifier
        )
        return generation.description
    }

    func readPublicRepositoryDescription(
        generation: SQLiteVerifiedPublicRepositoryGeneration
    ) async throws -> PublicRepositoryReadDescription {
        try await withConnectionGate {
            try await readTransaction {
                _ = try await requirePublicRepositoryGenerationWithoutGate(
                    generation
                )
                return generation.description
            }
        }
    }

    func readPublicRepositoryRecord(
        path: PublicRepositoryPath,
        expectedCID: CID?,
        generation: SQLiteVerifiedPublicRepositoryGeneration
    ) async throws -> SQLitePublicRepositoryRecordRead {
        try await withConnectionGate {
            try await readTransaction {
                let state = try await requirePublicRepositoryGenerationWithoutGate(
                    generation
                )
                let tree = try RepositoryMST.load(
                    rootCID: state.dataCID,
                    blocks: SQLitePublicRepositoryBlockSource(
                        connection: connection
                    )
                )
                let cid: CID?
                do {
                    cid = try await tree.get(path)
                } catch {
                    throw PublicRepositoryReadError.unavailable
                }
                guard let cid,
                      expectedCID == nil || expectedCID == cid else {
                    try await recheckPublicRepositoryGenerationWithoutGate(
                        generation,
                        expectedState: state
                    )
                    return SQLitePublicRepositoryRecordRead(
                        state: state,
                        record: nil
                    )
                }
                // Check SQLite's scalar length before selecting the BLOB. A
                // corrupt or hostile record index must not make the single
                // record endpoint materialize an over-budget body merely to
                // reject it in `PublicRepositoryReadRecord`.
                let byteCount = try await
                    publicRepositoryRecordBlockByteCountWithoutGate(cid)
                let bytes = try await blockBytesWithoutGate(cid)
                guard bytes.count == byteCount else {
                    throw PublicRepositoryReadError.unavailable
                }
                let record = try PublicRepositoryReadRecord(
                    path: path,
                    cid: cid,
                    canonicalBytes: bytes
                )
                try await recheckPublicRepositoryGenerationWithoutGate(
                    generation,
                    expectedState: state
                )
                return SQLitePublicRepositoryRecordRead(
                    state: state,
                    record: record
                )
            }
        }
    }

    func readPublicRepositoryRecords(
        collection: String,
        limit: Int,
        cursor: String?,
        reverse: Bool,
        generation: SQLiteVerifiedPublicRepositoryGeneration
    ) async throws -> SQLitePublicRepositoryPageRead {
        guard (1...100).contains(limit) else {
            throw PublicRepositoryReadError.invalidLimit
        }
        if let cursor {
            _ = try PublicRepositoryPath(
                collection: collection, recordKey: cursor
            )
        }
        return try await withConnectionGate {
            try await readTransaction {
                let state = try await requirePublicRepositoryGenerationWithoutGate(
                    generation
                )
                let tree = try RepositoryMST.load(
                    rootCID: state.dataCID,
                    blocks: SQLitePublicRepositoryBlockSource(
                        connection: connection
                    )
                )
                let mstPage: RepositoryMSTPage
                do {
                    mstPage = try await tree.page(
                        collection: collection,
                        limit: limit,
                        cursor: cursor,
                        reverse: reverse
                    )
                } catch {
                    throw PublicRepositoryReadError.unavailable
                }
                var records: [PublicRepositoryReadRecord] = []
                records.reserveCapacity(mstPage.leaves.count)
                var aggregateRecordBytes = 0
                for leaf in mstPage.leaves {
                    // Ask SQLite for the scalar length before materializing a
                    // record body. This keeps canonical record Data at or
                    // below the aggregate anonymous-read budget even when the
                    // next indexed block is itself near the per-record limit.
                    let byteCount =
                        try await publicRepositoryRecordBlockByteCountWithoutGate(
                            leaf.recordCID
                        )
                    let (nextAggregate, overflow) =
                        aggregateRecordBytes.addingReportingOverflow(
                            byteCount
                        )
                    // A short page is valid AT Protocol pagination. Stop before
                    // fetching the first body that would exceed the anonymous
                    // JSON allocation budget and return the last emitted key as
                    // the continuation cursor.
                    guard !overflow,
                          nextAggregate <= PublicRepositoryJSONReadLimits
                            .maximumAggregateRecordBlockBytes else {
                        break
                    }
                    let bytes = try await blockBytesWithoutGate(
                        leaf.recordCID
                    )
                    guard bytes.count == byteCount else {
                        throw PublicRepositoryReadError.unavailable
                    }
                    records.append(try PublicRepositoryReadRecord(
                        path: leaf.path,
                        cid: leaf.recordCID,
                        canonicalBytes: bytes
                    ))
                    aggregateRecordBytes = nextAggregate
                }
                let page = try PublicRepositoryReadPage(
                    records: records,
                    cursor: records.last?.path.recordKey
                )
                try await recheckPublicRepositoryGenerationWithoutGate(
                    generation,
                    expectedState: state
                )
                return SQLitePublicRepositoryPageRead(
                    state: state,
                    page: page
                )
            }
        }
    }

    /// Returns only SQLite's scalar body length. Callers use this before
    /// selecting the BLOB so an over-budget page never transiently
    /// materializes the first excluded record.
    private func publicRepositoryRecordBlockByteCountWithoutGate(
        _ cid: CID
    ) async throws -> Int {
        let rows = try await connection.query(
            """
            SELECT length(bytes) AS byte_count
            FROM public_repository_blocks
            WHERE cid = ?
            """,
            [.text(cid.string)]
        )
        guard rows.count == 1,
              let byteCount = rows[0].column("byte_count")?.integer,
              (1...PublicRepositoryLimits.standard.maximumRecordBlockBytes)
                .contains(byteCount) else {
            throw PublicRepositoryReadError.unavailable
        }
        return byteCount
    }

    func preparePublicRepositoryCAR(
        lease: PublicRepositorySpoolLease,
        generation: SQLiteVerifiedPublicRepositoryGeneration
    ) async throws -> PublicRepositoryReadCAR {
        let handle = try SQLiteProtectedPaths.makeUnlinkedPublicCARSpool(
            in: dataDirectory
        )
        do {
            let state = try await withConnectionGate {
                try await readTransaction {
                    let state = try await
                        requirePublicRepositoryGenerationWithoutGate(generation)
                    let commitBytes = try await blockBytesWithoutGate(
                        state.commitCID
                    )
                    let commit = try structurallyValidatedCommit(
                        signedCommitBytes: commitBytes,
                        expectedCommitCID: state.commitCID
                    )
                    guard commit.descriptor.did == state.did,
                          commit.descriptor.revision.value == state.revision,
                          commit.descriptor.dataCID == state.dataCID else {
                        throw PublicRepositoryReadError.unavailable
                    }
                    let sink = PublicRepositoryFileSink(handle: handle)
                    try await writeBoundedPublicRepositoryCAR(
                        state: state,
                        commit: commit,
                        to: sink
                    )
                    try handle.synchronize()
                    try handle.seek(toOffset: 0)
                    try await recheckPublicRepositoryGenerationWithoutGate(
                        generation,
                        expectedState: state
                    )
                    return state
                }
            }
            return PublicRepositoryReadCAR(
                state: state,
                spool: PublicRepositoryCARSpool(fileHandle: handle, lease: lease)
            )
        } catch {
            try? handle.close()
            lease.release()
            throw error
        }
    }

    /// Storage-test compatibility for exercising the spool in isolation.
    /// Runtime HTTP code must use the generation-bound overload above.
    func preparePublicRepositoryCAR(
        lease: PublicRepositorySpoolLease
    ) async throws -> PublicRepositoryReadCAR {
        let handle = try SQLiteProtectedPaths.makeUnlinkedPublicCARSpool(
            in: dataDirectory
        )
        do {
            let state = try await withConnectionGate {
                try await readTransaction {
                    guard let state =
                            try await loadPublicRepositoryStateWithoutGate()
                    else {
                        throw PublicRepositoryReadError.unavailable
                    }
                    let commitBytes = try await blockBytesWithoutGate(
                        state.commitCID
                    )
                    let commit = try structurallyValidatedCommit(
                        signedCommitBytes: commitBytes,
                        expectedCommitCID: state.commitCID
                    )
                    guard commit.descriptor.did == state.did,
                          commit.descriptor.revision.value == state.revision,
                          commit.descriptor.dataCID == state.dataCID else {
                        throw PublicRepositoryReadError.unavailable
                    }
                    let sink = PublicRepositoryFileSink(handle: handle)
                    try await writeBoundedPublicRepositoryCAR(
                        state: state,
                        commit: commit,
                        to: sink
                    )
                    try handle.synchronize()
                    try handle.seek(toOffset: 0)
                    return state
                }
            }
            return PublicRepositoryReadCAR(
                state: state,
                spool: PublicRepositoryCARSpool(
                    fileHandle: handle,
                    lease: lease
                )
            )
        } catch {
            try? handle.close()
            lease.release()
            throw error
        }
    }

    private func requirePublicRepositoryGenerationWithoutGate(
        _ generation: SQLiteVerifiedPublicRepositoryGeneration
    ) async throws -> PublicRepositoryState {
        guard generation.controlAccount.did == accountDID,
              generation.description.did == accountDID,
              generation.description.status == .active,
              !generation.repositoryVerificationIdentity.isEmpty,
              try publicRepositoryFileIdentityWithoutGate()
                == generation.fileIdentity,
              try await publicRepositoryDataVersionWithoutGate()
                == generation.dataVersion,
              let state = try await loadPublicRepositoryStateWithoutGate(),
              state == generation.description.state else {
            throw PublicRepositoryReadError.unavailable
        }
        return state
    }

    private func recheckPublicRepositoryGenerationWithoutGate(
        _ generation: SQLiteVerifiedPublicRepositoryGeneration,
        expectedState: PublicRepositoryState
    ) async throws {
        guard try publicRepositoryFileIdentityWithoutGate()
                == generation.fileIdentity,
              try await publicRepositoryDataVersionWithoutGate()
                == generation.dataVersion,
              let state = try await loadPublicRepositoryStateWithoutGate(),
              state == expectedState,
              state == generation.description.state else {
            throw PublicRepositoryReadError.unavailable
        }
    }

    private func publicRepositoryDataVersionWithoutGate() async throws -> Int64 {
        let rows = try await connection.query("PRAGMA data_version")
        guard rows.count == 1,
              let value = rows[0].column("data_version")?.integer,
              let dataVersion = Int64(exactly: value) else {
            throw PublicRepositoryReadError.unavailable
        }
        return dataVersion
    }

    private func publicRepositoryFileIdentityWithoutGate() throws
        -> SQLitePublicRepositoryFileIdentity
    {
        let descriptorIdentity = try publicRepositoryDatabaseDescriptorIdentity()
        let path = SQLiteLayout.accountDatabase(
            in: dataDirectory,
            did: accountDID
        ).path
        var metadata = stat()
        let result = path.withCString { pointer in
            #if canImport(Darwin)
            Darwin.lstat(pointer, &metadata)
            #else
            Glibc.lstat(pointer, &metadata)
            #endif
        }
        guard result == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(),
              (metadata.st_mode & 0o777) == 0o600,
              metadata.st_nlink == 1 else {
            throw PublicRepositoryReadError.unavailable
        }
        let pathIdentity = SQLitePublicRepositoryFileIdentity(
            device: UInt64(metadata.st_dev),
            inode: UInt64(metadata.st_ino)
        )
        guard pathIdentity == descriptorIdentity else {
            throw PublicRepositoryReadError.unavailable
        }
        return descriptorIdentity
    }
}

private func publicReadRequiredInteger(
    _ row: SQLiteRow,
    _ column: String
) throws -> Int {
    guard let value = row.column(column)?.integer,
          value >= Int64(Int.min), value <= Int64(Int.max) else {
        throw PublicRepositoryReadError.unavailable
    }
    return Int(value)
}

private func publicReadRequiredText(
    _ row: SQLiteRow,
    _ column: String
) throws -> String {
    guard let value = row.column(column)?.string, !value.isEmpty else {
        throw PublicRepositoryReadError.unavailable
    }
    return value
}

private func publicReadCID(_ value: String) throws -> CID {
    do {
        let cid = try CID.parse(value)
        try PublicRepositoryCID.validate(cid)
        return cid
    } catch {
        throw PublicRepositoryReadError.unavailable
    }
}

private final class PublicRepositoryFileSink:
    PublicRepositoryCARByteSink,
    @unchecked Sendable
{
    private let handle: FileHandle

    init(handle: FileHandle) {
        self.handle = handle
    }

    func write(_ bytes: Data) async throws {
        try Task.checkCancellation()
        try handle.write(contentsOf: bytes)
    }
}
