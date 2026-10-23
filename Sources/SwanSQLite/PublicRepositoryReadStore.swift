import Foundation
import Petrel
import SQLiteNIO
import PetrelRepo
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
        try await withReadConnectionGate {
            try await readTransaction {
                // Reject oversized or malformed index projections before the
                // optional promoter decodes any record block. The preflight
                // itself is a bounded keyset walk and never selects values.
                try await preflightPublicReadProjectionWithoutGate(connection: readConnection)
                var cidsByString: [String: CID] = [:]
                var lastCollection: String?
                var lastRecordKey: String?
                var scannedRecords = 0
                while true {
                    try Task.checkCancellation()
                    let rows: [SQLiteRow]
                    if let lastCollection, let lastRecordKey {
                        rows = try await readConnection.query(
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
                        rows = try await readConnection.query(
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
                            row, "collection", reason: .recordIndexMalformed
                        )
                        let rkey = try publicReadRequiredText(
                            row, "rkey", reason: .recordIndexMalformed
                        )
                        let path = try PublicRepositoryPath(
                            collection: collection, recordKey: rkey
                        )
                        let recordCID = try publicReadCID(
                            try publicReadRequiredText(
                                row, "record_cid", reason: .recordIndexMalformed
                            ),
                            reason: .recordIndexMalformed
                        )
                        let bytes = try await blockBytesWithoutGate(recordCID, connection: readConnection)
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

    /// Checks one raw blob CID against the authenticated public repository
    /// projection while the caller already owns the SQLite connection gate.
    /// Permissioned promotion uses this to distinguish a staged public upload
    /// from a blob that is also still reachable through a public record. The
    /// walk is keyset-paged and uses the same projection limits as the public
    /// read/promoter path; it never retains record values or the full CID set.
    func publicRepositoryContainsBlobCIDWithoutGate(
        _ cid: String,
        connection: SQLiteConnection? = nil
    ) async throws -> Bool {
        let conn = connection ?? self.connection
        try await preflightPublicReadProjectionWithoutGate(connection: conn)
        var lastCollection: String?
        var lastRecordKey: String?
        var scannedRecords = 0
        while true {
            try Task.checkCancellation()
            let rows: [SQLiteRow]
            if let lastCollection, let lastRecordKey {
                rows = try await conn.query(
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
                        .integer(PublicRepositoryReadLimits.blobPromotionPageSize),
                    ]
                )
            } else {
                rows = try await conn.query(
                    """
                    SELECT collection, rkey, record_cid
                    FROM public_repository_record_index
                    ORDER BY collection ASC, rkey ASC
                    LIMIT ?
                    """,
                    [.integer(PublicRepositoryReadLimits.blobPromotionPageSize)]
                )
            }
            if rows.isEmpty { return false }
            guard rows.count <= PublicRepositoryReadLimits
                .maximumBlobPromotionIndexEntries - scannedRecords else {
                throw PublicRepositoryReadError.resourceLimitExceeded
            }
            scannedRecords += rows.count
            for row in rows {
                let collection = try publicReadRequiredText(
                    row, "collection", reason: .recordIndexMalformed
                )
                let recordKey = try publicReadRequiredText(
                    row, "rkey", reason: .recordIndexMalformed
                )
                let path = try PublicRepositoryPath(
                    collection: collection, recordKey: recordKey
                )
                let recordCID = try publicReadCID(
                    try publicReadRequiredText(
                        row, "record_cid", reason: .recordIndexMalformed
                    ),
                    reason: .recordIndexMalformed
                )
                let bytes = try await blockBytesWithoutGate(recordCID, connection: conn)
                let value = try RepositoryMSTValidation.decodeRecordBlock(
                    bytes, for: path
                )
                let record = try PublicRepositoryRecordCodec.publicRecord(
                    from: value, collection: collection
                )
                if PublicRepositoryRecordCodec.publicBlobCIDs(in: record)
                    .contains(where: { $0.string == cid }) {
                    return true
                }
                lastCollection = collection
                lastRecordKey = recordKey
            }
            if rows.count < PublicRepositoryReadLimits.blobPromotionPageSize {
                return false
            }
        }
    }

    func admitPublicRepositoryGeneration(
        account: AccountControlAccount,
        identityVerifier: any PublicPLCGenesisVerifying
    ) async throws -> SQLiteVerifiedPublicRepositoryGeneration {
        try await withConnectionGate {
            try await writerReadTransaction {
                let fileIdentity = try publicRepositoryFileIdentityWithoutGate()
                let dataVersion = try await publicRepositoryDataVersionWithoutGate(connection: connection)
                guard let state = try await loadPublicRepositoryStateWithoutGate() else {
                    throw PublicRepositoryReadError.unavailable(
                        reason: .repositoryStateMissing
                    )
                }
                // The named variant classifies its own failures — projection
                // mismatch, block corruption, malformed index row, bound
                // violation, cancellation — so admission does not have to guess
                // from the outside. `verifyProjectionWithoutGate` keeps its
                // `corruptRepository` contract for direct maintenance callers.
                try await namedProjectionVerificationWithoutGate(state: state)
                let rows = try await connection.query(
                    """
                    SELECT DISTINCT collection
                    FROM public_repository_record_index
                    ORDER BY collection ASC
                    """
                )
                let collections = try rows.map {
                    try publicReadRequiredText(
                        $0, "collection", reason: .recordIndexMalformed
                    )
                }
                let identityRows = try await connection.query(
                    """
                    SELECT canonical_handle, pds_origin,
                           request_id, operation_signing_did_key,
                           operation_rotation_did_key, operation_signature, operation_kem_did_key,
                           signing_key_reference, rotation_key_reference,
                           public_genesis_commit_cid, stage
                    FROM plc_account_preparation_journal
                    """
                )
                let identityRow = identityRows.first
                let storedSigningReference = try identityRow.map {
                    try publicReadRequiredText(
                        $0, "signing_key_reference",
                        reason: .identityFactsMalformed
                    )
                }
                let storedRotationReference = try identityRow.map {
                    try publicReadRequiredText(
                        $0, "rotation_key_reference",
                        reason: .identityFactsMalformed
                    )
                }
                let storedGenesisCID = try identityRow.map {
                    try publicReadRequiredText(
                        $0, "public_genesis_commit_cid",
                        reason: .identityFactsMalformed
                    )
                }
                // Split deliberately: a single compound guard here is what made
                // the 2026-08-12 outage undiagnosable from the journal.
                guard identityRows.count == 1, let identityRow else {
                    throw PublicRepositoryReadError.unavailable(
                        reason: .identityRowCount
                    )
                }
                guard try publicReadRequiredInteger(
                    identityRow, "stage", reason: .identityFactsMalformed
                )
                    == PLCAccountPreparationStage.submitted.rawValue else {
                    throw PublicRepositoryReadError.unavailable(
                        reason: .identityStageNotSubmitted
                    )
                }
                guard let storedGenesisCID,
                      account.publicGenesisCommitCID == storedGenesisCID else {
                    throw PublicRepositoryReadError.unavailable(
                        reason: .genesisCIDMismatch
                    )
                }
                guard let signingKey = account.signingKey,
                      let rotationKey = account.rotationKey else {
                    throw PublicRepositoryReadError.unavailable(
                        reason: .missingKeyMaterial
                    )
                }
                let plcHandle = try publicReadRequiredText(
                    identityRow, "canonical_handle",
                    reason: .identityFactsMalformed
                )
                let signingDIDKey = try publicReadRequiredText(
                    identityRow, "operation_signing_did_key",
                    reason: .identityFactsMalformed
                )
                let genesisOperationCID = try identityVerifier.verifyGenesis(
                    facts: PublicPLCGenesisFacts(
                        signingDIDKey: signingDIDKey,
                    rotationDIDKey: try publicReadRequiredText(
                        identityRow, "operation_rotation_did_key",
                        reason: .identityFactsMalformed
                    ),
                    canonicalHandle: plcHandle,
                    pdsOrigin: try publicReadRequiredText(
                        identityRow, "pds_origin",
                        reason: .identityFactsMalformed
                    ),
                    signature: try publicReadRequiredText(
                        identityRow, "operation_signature",
                        reason: .identityFactsMalformed
                    ),
                    kemDIDKey: identityRow.column("operation_kem_did_key")?.string
                    ),
                    expectedDID: account.did
                )
                let history = try await publicPLCOperationHistoryWithoutGate()
                let identity: PublicRepositoryReadIdentity
                if history.isEmpty {
                    guard signingKey.reference == storedSigningReference,
                          rotationKey.reference == storedRotationReference else {
                        throw PublicRepositoryReadError.unavailable(reason: .keyReferenceMismatch)
                    }
                    identity = try PublicRepositoryReadIdentity(
                        canonicalHandle: plcHandle,
                        pdsOrigin: try publicReadRequiredText(
                            identityRow, "pds_origin",
                            reason: .identityFactsMalformed
                        ),
                        signingDIDKey: signingDIDKey,
                        handleIsCorrect: plcHandle == account.canonicalHandle,
                        preparationRequestID: try publicReadRequiredText(
                            identityRow, "request_id",
                            reason: .identityFactsMalformed
                        ),
                        genesisOperationCID: genesisOperationCID
                    )
                } else {
                    guard let historyVerifier = identityVerifier
                        as? any PublicPLCIdentityVerifying else {
                        throw PublicRepositoryReadError.unavailable(reason: .historyVerifierUnavailable)
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
                        throw PublicRepositoryReadError.unavailable(reason: .terminalIdentityMismatch)
                    }
                    identity = try PublicRepositoryReadIdentity(
                        canonicalHandle: terminal.canonicalHandle,
                        pdsOrigin: terminal.pdsOrigin,
                        signingDIDKey: terminal.signingDIDKey,
                        handleIsCorrect: terminal.canonicalHandle == account.canonicalHandle,
                        preparationRequestID: try publicReadRequiredText(
                            identityRow, "request_id",
                            reason: .identityFactsMalformed
                        ),
                        genesisOperationCID: terminal.genesisOperationCID,
                        terminalOperationCID: terminal.terminalOperationCID
                    )
                }
                guard let repositoryAuthenticator = identityVerifier
                    as? any PublicPLCRepositoryAuthenticating else {
                    throw PublicRepositoryReadError.unavailable(reason: .repositoryAuthenticatorUnavailable)
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
                    throw PublicRepositoryReadError.unavailable(reason: .commitAuthenticationFailed)
                }
                let description = try PublicRepositoryReadDescription(
                    did: accountDID,
                    canonicalHandle: account.canonicalHandle,
                    status: account.status,
                    state: state,
                    collections: collections,
                    identity: identity
                )
                // Both pins are re-read before the generation is minted, but
                // they are not equally load-bearing and must not be read as if
                // they were.
                //
                // `data_version` cannot move here: this whole admission runs
                // inside one `readTransaction`, and SQLite freezes the pragma
                // for the life of a read transaction that has already read —
                // it advances only once the snapshot is released. The guard is
                // kept because it stops being dead the moment admission is
                // split across transactions, and because it is now demoted:
                // `.generationPinStale` is change detection, so it is never
                // recorded in the re-admission negative cache and the next read
                // simply admits again.
                //
                // The `fileIdentity` re-check is live. `lstat` is not
                // transaction-scoped, so the account database file really can
                // be swapped underneath an in-flight admission, and that is a
                // genuine disagreement rather than a race.
                guard try await publicRepositoryDataVersionWithoutGate(connection: connection)
                    == dataVersion else {
                    throw PublicRepositoryReadError.unavailable(
                        reason: .generationPinStale
                    )
                }
                guard try publicRepositoryFileIdentityWithoutGate()
                    == fileIdentity else {
                    throw PublicRepositoryReadError.unavailable(
                        reason: .fileIdentityMismatch
                    )
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

    func preflightPublicReadProjectionWithoutGate(connection: SQLiteConnection? = nil) async throws {
        let conn = connection ?? self.connection
        var recordCount = 0
        var collectionCount = 0
        var collectionBytes = 0
        var lastCollection: String?
        var lastRecordKey: String?

        while true {
            try Task.checkCancellation()
            let rows: [SQLiteRow]
            if let lastCollection, let lastRecordKey {
                rows = try await conn.query(
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
                rows = try await conn.query(
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
                let collection = try publicReadRequiredText(
                    row, "collection", reason: .recordIndexMalformed
                )
                let recordKey = try publicReadRequiredText(
                    row, "rkey", reason: .recordIndexMalformed
                )
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
            try await writerReadTransaction {
                _ = try await requirePublicRepositoryGenerationWithoutGate(
                    generation,
                    connection: connection
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
            try await writerReadTransaction {
                let state = try await requirePublicRepositoryGenerationWithoutGate(
                    generation,
                    connection: connection
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
                    throw PublicRepositoryReadError.unavailable(reason: .blockMaterializationFailed)
                }
                guard let cid,
                      expectedCID == nil || expectedCID == cid else {
                    try await recheckPublicRepositoryGenerationWithoutGate(
                        generation,
                        expectedState: state,
                        connection: connection
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
                let bytes = try await blockBytesWithoutGate(cid, connection: connection)
                guard bytes.count == byteCount else {
                    throw PublicRepositoryReadError.unavailable(reason: .blockMaterializationFailed)
                }
                let record = try PublicRepositoryReadRecord(
                    path: path,
                    cid: cid,
                    canonicalBytes: bytes
                )
                try await recheckPublicRepositoryGenerationWithoutGate(
                    generation,
                    expectedState: state,
                    connection: connection
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
            try await writerReadTransaction {
                let state = try await requirePublicRepositoryGenerationWithoutGate(
                    generation,
                    connection: connection
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
                    throw PublicRepositoryReadError.unavailable(reason: .blockMaterializationFailed)
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
                        leaf.recordCID,
                        connection: connection
                    )
                    guard bytes.count == byteCount else {
                        throw PublicRepositoryReadError.unavailable(reason: .blockMaterializationFailed)
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
                    expectedState: state,
                    connection: connection
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
            throw PublicRepositoryReadError.unavailable(reason: .blockMaterializationFailed)
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
                try await writerReadTransaction {
                    let state = try await
                        requirePublicRepositoryGenerationWithoutGate(
                            generation,
                            connection: connection
                        )
                    let commitBytes = try await blockBytesWithoutGate(
                        state.commitCID,
                        connection: connection
                    )
                    let commit = try structurallyValidatedCommit(
                        signedCommitBytes: commitBytes,
                        expectedCommitCID: state.commitCID
                    )
                    guard commit.descriptor.did == state.did,
                          commit.descriptor.revision.value == state.revision,
                          commit.descriptor.dataCID == state.dataCID else {
                        throw PublicRepositoryReadError.unavailable(reason: .repositoryStateMismatch)
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
                        expectedState: state,
                        connection: connection
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
                try await writerReadTransaction {
                    guard let state =
                            try await loadPublicRepositoryStateWithoutGate(connection: connection)
                    else {
                        throw PublicRepositoryReadError.unavailable(reason: .repositoryStateMissing)
                    }
                    let commitBytes = try await blockBytesWithoutGate(
                        state.commitCID,
                        connection: connection
                    )
                    let commit = try structurallyValidatedCommit(
                        signedCommitBytes: commitBytes,
                        expectedCommitCID: state.commitCID
                    )
                    guard commit.descriptor.did == state.did,
                          commit.descriptor.revision.value == state.revision,
                          commit.descriptor.dataCID == state.dataCID else {
                        throw PublicRepositoryReadError.unavailable(reason: .repositoryStateMismatch)
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
        _ generation: SQLiteVerifiedPublicRepositoryGeneration,
        connection: SQLiteConnection? = nil
    ) async throws -> PublicRepositoryState {
        let conn = connection ?? self.connection
        // Three independent pins, reported independently. `data_version` is
        // the only one that moves on an unrelated commit from any other
        // connection to this database, so callers must be able to tell it
        // apart from a genuine identity or repository-state failure.
        guard generation.controlAccount.did == accountDID,
              generation.description.did == accountDID,
              generation.description.status == .active,
              !generation.repositoryVerificationIdentity.isEmpty else {
            throw PublicRepositoryReadError.unavailable(
                reason: .generationIdentityMismatch
            )
        }
        guard try publicRepositoryFileIdentityWithoutGate()
            == generation.fileIdentity else {
            throw PublicRepositoryReadError.unavailable(
                reason: .fileIdentityMismatch
            )
        }
        guard try await publicRepositoryDataVersionWithoutGate(connection: conn)
            == generation.dataVersion else {
            throw PublicRepositoryReadError.unavailable(
                reason: .generationPinStale
            )
        }
        guard let state = try await loadPublicRepositoryStateWithoutGate(connection: conn) else {
            throw PublicRepositoryReadError.unavailable(
                reason: .repositoryStateMissing
            )
        }
        guard state == generation.description.state else {
            throw PublicRepositoryReadError.unavailable(
                reason: .repositoryStateMismatch
            )
        }
        return state
    }

    private func recheckPublicRepositoryGenerationWithoutGate(
        _ generation: SQLiteVerifiedPublicRepositoryGeneration,
        expectedState: PublicRepositoryState,
        connection: SQLiteConnection? = nil
    ) async throws {
        let conn = connection ?? self.connection
        guard try publicRepositoryFileIdentityWithoutGate()
            == generation.fileIdentity else {
            throw PublicRepositoryReadError.unavailable(
                reason: .fileIdentityMismatch
            )
        }
        guard try await publicRepositoryDataVersionWithoutGate(connection: conn)
            == generation.dataVersion else {
            throw PublicRepositoryReadError.unavailable(
                reason: .generationPinStale
            )
        }
        guard let state = try await loadPublicRepositoryStateWithoutGate(connection: conn) else {
            throw PublicRepositoryReadError.unavailable(
                reason: .repositoryStateMissing
            )
        }
        guard state == expectedState,
              state == generation.description.state else {
            throw PublicRepositoryReadError.unavailable(
                reason: .repositoryStateMismatch
            )
        }
    }

    private func publicRepositoryDataVersionWithoutGate(connection: SQLiteConnection? = nil) async throws -> Int64 {
        let conn = connection ?? self.connection
        let rows = try await conn.query("PRAGMA data_version")
        guard rows.count == 1,
              let value = rows[0].column("data_version")?.integer,
              let dataVersion = Int64(exactly: value) else {
            throw PublicRepositoryReadError.unavailable(reason: .storageFailure)
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
            throw PublicRepositoryReadError.unavailable(reason: .fileIdentityMismatch)
        }
        let pathIdentity = SQLitePublicRepositoryFileIdentity(
            device: UInt64(metadata.st_dev),
            inode: UInt64(metadata.st_ino)
        )
        guard pathIdentity == descriptorIdentity else {
            throw PublicRepositoryReadError.unavailable(reason: .fileIdentityMismatch)
        }
        return descriptorIdentity
    }
}

private func publicReadRequiredInteger(
    _ row: SQLiteRow,
    _ column: String,
    reason: PublicReadUnavailableReason
) throws -> Int {
    guard let value = row.column(column)?.integer,
          value >= Int64(Int.min), value <= Int64(Int.max) else {
        throw PublicRepositoryReadError.unavailable(reason: reason)
    }
    return Int(value)
}

private func publicReadRequiredText(
    _ row: SQLiteRow,
    _ column: String,
    reason: PublicReadUnavailableReason
) throws -> String {
    guard let value = row.column(column)?.string, !value.isEmpty else {
        throw PublicRepositoryReadError.unavailable(reason: reason)
    }
    return value
}

private func publicReadCID(
    _ value: String,
    reason: PublicReadUnavailableReason
) throws -> CID {
    do {
        let cid = try CID.parse(value)
        try PublicRepositoryCID.validate(cid)
        return cid
    } catch {
        throw PublicRepositoryReadError.unavailable(reason: reason)
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
