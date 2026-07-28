import Foundation
import Petrel
import SQLiteNIO
import SwanPublicRepository
import SwanStorage

extension SQLiteAccountDatabase {
    func readPublicRepositoryDescription(
        account: AccountControlAccount,
        identityVerifier: any PublicPLCGenesisVerifying
    ) async throws -> PublicRepositoryReadDescription {
        try await withConnectionGate {
            try await transaction {
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
                      let signingKey = account.signingKey,
                      let rotationKey = account.rotationKey,
                      signingKey.reference == storedSigningReference,
                      rotationKey.reference == storedRotationReference,
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
                let identity = try PublicRepositoryReadIdentity(
                    canonicalHandle: plcHandle,
                    pdsOrigin: try publicReadRequiredText(identityRow, "pds_origin"),
                    signingDIDKey: signingDIDKey,
                    handleIsCorrect: plcHandle == account.canonicalHandle,
                    preparationRequestID: try publicReadRequiredText(
                        identityRow, "request_id"
                    ),
                    genesisOperationCID: genesisOperationCID
                )
                return try PublicRepositoryReadDescription(
                    did: accountDID,
                    canonicalHandle: account.canonicalHandle,
                    status: account.status,
                    state: state,
                    collections: collections,
                    identity: identity
                )
            }
        }
    }

    func readPublicRepositoryRecord(
        path: PublicRepositoryPath,
        expectedCID: CID?
    ) async throws -> PublicRepositoryReadRecord? {
        try await withConnectionGate {
            try await transaction { () async throws -> PublicRepositoryReadRecord? in
                guard let state = try await loadPublicRepositoryStateWithoutGate() else {
                    throw PublicRepositoryReadError.unavailable
                }
                try await verifyProjectionWithoutGate(state: state)
                let rows = try await connection.query(
                    """
                    SELECT record_cid
                    FROM public_repository_record_index
                    WHERE collection = ? AND rkey = ?
                    """,
                    [.text(path.collection), .text(path.recordKey)]
                )
                guard rows.count <= 1 else {
                    throw PublicRepositoryReadError.unavailable
                }
                guard let row = rows.first else { return nil }
                let cid = try publicReadCID(
                    try publicReadRequiredText(row, "record_cid")
                )
                guard expectedCID == nil || expectedCID == cid else { return nil }
                let bytes = try await blockBytesWithoutGate(cid)
                return try PublicRepositoryReadRecord(
                    path: path, cid: cid, canonicalBytes: bytes
                )
            }
        }
    }

    func readPublicRepositoryRecords(
        collection: String,
        limit: Int,
        cursor: String?,
        reverse: Bool
    ) async throws -> PublicRepositoryReadPage {
        guard (1...100).contains(limit) else {
            throw PublicRepositoryReadError.invalidLimit
        }
        if let cursor {
            _ = try PublicRepositoryPath(
                collection: collection, recordKey: cursor
            )
        }
        return try await withConnectionGate {
            try await transaction {
                guard let state = try await loadPublicRepositoryStateWithoutGate() else {
                    throw PublicRepositoryReadError.unavailable
                }
                try await verifyProjectionWithoutGate(state: state)
                // Pinned actor-store semantics paginate "before" by default
                // and "after" when reverse=true.
                let comparator = reverse ? ">" : "<"
                let ordering = reverse ? "ASC" : "DESC"
                let rows: [SQLiteRow]
                if let cursor {
                    rows = try await connection.query(
                        """
                        SELECT rkey, record_cid
                        FROM public_repository_record_index
                        WHERE collection = ? AND rkey \(comparator) ?
                        ORDER BY rkey \(ordering)
                        LIMIT ?
                        """,
                        [.text(collection), .text(cursor), .integer(limit)]
                    )
                } else {
                    rows = try await connection.query(
                        """
                        SELECT rkey, record_cid
                        FROM public_repository_record_index
                        WHERE collection = ?
                        ORDER BY rkey \(ordering)
                        LIMIT ?
                        """,
                        [.text(collection), .integer(limit)]
                    )
                }
                var records: [PublicRepositoryReadRecord] = []
                for row in rows.prefix(limit) {
                    let path = try PublicRepositoryPath(
                        collection: collection,
                        recordKey: try publicReadRequiredText(row, "rkey")
                    )
                    let cid = try publicReadCID(
                        try publicReadRequiredText(row, "record_cid")
                    )
                    records.append(try PublicRepositoryReadRecord(
                        path: path,
                        cid: cid,
                        canonicalBytes: try await blockBytesWithoutGate(cid)
                    ))
                }
                return try PublicRepositoryReadPage(
                    records: records,
                    cursor: records.last?.path.recordKey
                )
            }
        }
    }

    func preparePublicRepositoryCAR(
        lease: PublicRepositorySpoolLease
    ) async throws -> PublicRepositoryReadCAR {
        let handle = try SQLiteProtectedPaths.makeUnlinkedPublicCARSpool(
            in: dataDirectory
        )
        do {
            let state = try await withConnectionGate {
                try await transaction {
                    guard let state = try await loadPublicRepositoryStateWithoutGate() else {
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
                spool: PublicRepositoryCARSpool(fileHandle: handle, lease: lease)
            )
        } catch {
            try? handle.close()
            lease.release()
            throw error
        }
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
