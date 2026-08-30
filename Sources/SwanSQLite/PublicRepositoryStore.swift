import Crypto
import Foundation
import Petrel
import SQLiteNIO
import PetrelFirehose
import PetrelRepo
import SwanStorage

struct SQLitePublicRepositoryBlockSource: PublicRepositoryBlockSource {
    let connection: SQLiteConnection

    func block(for cid: CID) async throws -> Data? {
        switch try await boundedPublicRepositoryBlock(connection: connection, cid: cid) {
        case .missing:
            return nil
        case .oversized:
            throw PublicRepositoryMutationStoreError.corruptRepository
        case let .bytes(bytes):
            do {
                try PublicRepositoryCID.validate(cid, blockBytes: bytes)
            } catch {
                throw PublicRepositoryMutationStoreError.corruptRepository
            }
            return bytes
        }
    }
}

enum BoundedPublicRepositoryBlockRead {
    case missing
    case oversized
    case bytes(Data)
}

/// `CASE` is deliberate: SQLite can answer `length(BLOB)` from the record
/// header and does not return the BLOB value at all when it exceeds the bound.
/// Keeping the size check and value projection in one statement also avoids a
/// check/use race with another connection.
func boundedPublicRepositoryBlock(
    connection: SQLiteConnection,
    cid: CID
) async throws -> BoundedPublicRepositoryBlockRead {
    let rows = try await connection.query(
        """
        SELECT length(bytes) AS byte_count,
               CASE WHEN length(bytes) <= ? THEN bytes ELSE NULL END AS bounded_bytes
        FROM public_repository_blocks
        WHERE cid = ?
        """,
        [
            .integer(PublicRepositoryLimits.maximumPersistedBlockBytes),
            .text(cid.string),
        ]
    )
    guard rows.count <= 1 else {
        throw PublicRepositoryMutationStoreError.corruptRepository
    }
    guard let row = rows.first else { return .missing }
    guard case let .integer(byteCount) = row.column("byte_count"),
          byteCount >= 0 else {
        throw PublicRepositoryMutationStoreError.corruptRepository
    }
    guard byteCount <= PublicRepositoryLimits.maximumPersistedBlockBytes else {
        return .oversized
    }
    guard let value = row.column("bounded_bytes"),
          let bytes = Data(sqliteData: value),
          bytes.count == byteCount else {
        throw PublicRepositoryMutationStoreError.corruptRepository
    }
    return .bytes(bytes)
}

/// Admission only needs to prove that the durable index is exactly the
/// projection of the authenticated MST. Keep that projection in SQLite's
/// connection-local TEMP schema rather than retaining every MST block and
/// leaf in a `ValidatedPublicRepositoryMST` value.
private struct SQLitePublicRepositoryProjectionSink:
    PublicRepositoryReachableProjectionSink
{
    let connection: SQLiteConnection

    func recordReachableBlock(
        cid: CID,
        kind: PublicRepositoryReachableBlockKind
    ) async throws {
        // The validator authenticates each block before this callback. The
        // public admission comparison needs only the record-path projection;
        // block bodies and their identifiers must not accumulate in Swift.
        _ = cid
        _ = kind
    }

    func recordRepositoryIndex(
        path: PublicRepositoryPath,
        recordCID: CID
    ) async throws {
        _ = try await connection.query(
            """
            INSERT INTO temp.swan_public_verified_index(
                collection, rkey, record_cid
            ) VALUES (?, ?, ?)
            """,
            [
                .text(path.collection), .text(path.recordKey),
                .text(recordCID.string),
            ]
        )
    }
}

/// The durable outbox decision for one repository mutation: final event kind,
/// JSON payload, CAR bytes, and source key. The source transaction owns this
/// decision; the sequencer never reinterprets a persisted row.
enum PublicFirehoseSourceDecision: Sendable, Equatable {
    case commit(payload: Data, car: Data, sourceKey: String)
    case sync(payload: Data, car: Data, sourceKey: String)

    var kind: PublicFirehoseEventKind {
        switch self {
        case .commit: .commit
        case .sync: .sync
        }
    }

    var payload: Data {
        switch self {
        case let .commit(payload, _, _): payload
        case let .sync(payload, _, _): payload
        }
    }

    var car: Data {
        switch self {
        case let .commit(_, car, _): car
        case let .sync(_, car, _): car
        }
    }

    var sourceKey: String {
        switch self {
        case let .commit(_, _, sourceKey): sourceKey
        case let .sync(_, _, sourceKey): sourceKey
        }
    }
}

enum PublicFirehoseSourceDecisionMaker {
    /// Sorted keys make repeated encodes byte-identical. JSONEncoder's default
    /// key order is not stable across calls, and the outbox replay path
    /// compares stored payload bytes exactly.
    private static let payloadEncoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }()

    /// Preflights the exact complete commit frame at the largest legal
    /// sequence so the check is not smaller than a later real frame due to
    /// integer encoding width. Oversize shapes degrade to `#sync`; malformed
    /// durable material is an internal invariant violation.
    static func decide(
        accountDID: String,
        commitCID: CID,
        commitMaterial: PublicFirehoseCommitMaterial,
        syncMaterial: PublicFirehoseSyncMaterial,
        diffCAR: Data,
        commitOnlyCAR: Data
    ) throws -> PublicFirehoseSourceDecision {
        do {
            _ = try FirehoseFrameEncoder.commitFrame(
                seq: FirehoseFrameLimits.maximumSequence,
                material: commitMaterial,
                diffCAR: diffCAR
            )
            return .commit(
                payload: try payloadEncoder.encode(commitMaterial),
                car: diffCAR,
                sourceKey: PublicFirehoseSourceKey.commit(
                    did: accountDID,
                    commitCID: commitCID.string
                )
            )
        } catch FirehoseFrameEncoderError.tooManyOperations,
                FirehoseFrameEncoderError.blocksTooLarge,
                FirehoseFrameEncoderError.frameTooLarge {
            do {
                _ = try FirehoseFrameEncoder.syncFrame(
                    seq: FirehoseFrameLimits.maximumSequence,
                    material: syncMaterial,
                    commitCAR: commitOnlyCAR
                )
            } catch {
                throw PublicRepositoryMutationStoreError.corruptRepository
            }
            return .sync(
                payload: try payloadEncoder.encode(syncMaterial),
                car: commitOnlyCAR,
                sourceKey: PublicFirehoseSourceKey.syncOversize(
                    did: accountDID,
                    commitCID: commitCID.string
                )
            )
        } catch {
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
    }
}

/// The lifecycle-generation snapshot that a commit's firehose outbox row is
/// stamped with. Produced by the pre-activation authorization fence so the
/// row's generation is the same one observed by the control-plane
/// transaction that authorized the account.
public struct PublicFirehoseCommitContext: Sendable, Equatable {
    public let lifecycleGeneration: Int64

    public init(lifecycleGeneration: Int64) {
        self.lifecycleGeneration = lifecycleGeneration
    }
}

/// Pure in-memory firehose values built before the repository transaction
/// starts. These use immutable prepared data only; they must not open SQLite
/// or perform network I/O.
private struct PreparedPublicFirehoseMaterial {
    let eventTimeString: String
    let eventMicros: Int64
    let ops: [PublicFirehoseRepoOp]
    let diffCAR: Data
    let commitOnlyCAR: Data
}

extension SQLiteAccountDatabase: PublicRepositoryMutationStore {
    public func loadPublicRepositoryState() async throws -> PublicRepositoryState? {
        try await withReadConnectionGate {
            try await loadPublicRepositoryStateWithoutGate(connection: readConnection)
        }
    }

    public func verifyPublicRepositoryProjection() async throws {
        try await withConnectionGate {
            guard let state = try await loadPublicRepositoryStateWithoutGate() else {
                throw PublicRepositoryMutationStoreError.repositoryNotInstalled
            }
            try await verifyProjectionWithoutGate(state: state)
        }
    }

    public func block(for cid: CID) async throws -> Data? {
        do {
            try PublicRepositoryCID.validate(cid)
        } catch {
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
        return try await withReadConnectionGate {
            switch try await boundedPublicRepositoryBlock(connection: readConnection, cid: cid) {
            case .missing:
                return nil
            case .oversized:
                throw PublicRepositoryMutationStoreError.corruptRepository
            case let .bytes(bytes):
                do {
                    try PublicRepositoryCID.validate(cid, blockBytes: bytes)
                } catch {
                    throw PublicRepositoryMutationStoreError.corruptRepository
                }
                return bytes
            }
        }
    }

    public func publicRepositoryRecordCID(
        for path: PublicRepositoryPath
    ) async throws -> CID? {
        try await withReadConnectionGate {
            try await readTransaction {
                guard let state = try await loadPublicRepositoryStateWithoutGate(connection: readConnection) else {
                    throw PublicRepositoryMutationStoreError.repositoryNotInstalled
                }
                let rows = try await readConnection.query(
                    """
                    SELECT collection, rkey, record_cid
                    FROM public_repository_record_index
                    WHERE collection = ? AND rkey = ?
                    """,
                    [.text(path.collection), .text(path.recordKey)]
                )
                guard rows.count <= 1 else {
                    throw PublicRepositoryMutationStoreError.corruptRepository
                }
                let indexedCID = try rows.first.map(decodeIndexCID)
                let mstCID: CID?
                do {
                    let tree = try RepositoryMST.load(
                        rootCID: state.dataCID,
                        blocks: SQLitePublicRepositoryBlockSource(connection: readConnection)
                    )
                    mstCID = try await tree.get(path)
                } catch {
                    throw PublicRepositoryMutationStoreError.corruptRepository
                }
                guard indexedCID == mstCID else {
                    throw PublicRepositoryMutationStoreError.corruptRepository
                }
                return indexedCID
            }
        }
    }

    public func reservePublicRepositoryRevision(
        _ request: PublicRepositoryMutationRequest,
        wallClockMicroseconds: UInt64
    ) async throws -> PublicRepositoryMutationReservationOutcome {
        try await withConnectionGate {
            try await transaction {
                var mutatingSQLIndex = 0
                guard let state = try await loadPublicRepositoryStateWithoutGate() else {
                    throw PublicRepositoryMutationStoreError.repositoryNotInstalled
                }
                let rows = try await connection.query(
                    """
                    SELECT request_id, request_digest, base_commit_cid, base_revision,
                           next_revision, status, committed_commit_cid,
                           committed_data_cid, committed_projection,
                           committed_projection_digest, integrity_digest
                    FROM public_repository_mutation_requests
                    WHERE request_id = ?
                    """,
                    [.text(request.id)]
                )
                guard rows.count <= 1 else {
                    throw PublicRepositoryMutationStoreError.corruptRepository
                }
                if let row = rows.first {
                    return try await decodeExistingRequest(
                        row,
                        request: request,
                        repositoryDID: state.did
                    )
                }
                guard request.baseCommitCID == state.commitCID else {
                    throw PublicRepositoryMutationStoreError.commitCASConflict
                }

                let current = try Self.decodeAllocatableRevision(state.revision)
                let allocatorRows = try await connection.query(
                    """
                    SELECT highest_value FROM public_repository_revision_allocator
                    WHERE singleton = 1
                    """
                )
                guard allocatorRows.count <= 1 else {
                    throw PublicRepositoryMutationStoreError.corruptRepository
                }
                let durableHighest: UInt64
                if let row = allocatorRows.first,
                   case let .integer(value)? = row.column("highest_value"),
                   value >= 0 {
                    durableHighest = UInt64(value)
                } else if allocatorRows.isEmpty {
                    durableHighest = current
                } else {
                    throw PublicRepositoryMutationStoreError.corruptRepository
                }
                guard wallClockMicroseconds <= Self.maximumRevisionMicroseconds else {
                    throw PublicRepositoryMutationStoreError.revisionExhausted
                }
                let wallValue = wallClockMicroseconds << 10
                let floor = max(current, durableHighest)
                guard floor < UInt64(Int64.max) else {
                    throw PublicRepositoryMutationStoreError.revisionExhausted
                }
                let nextValue = max(wallValue, floor + 1)
                guard nextValue <= UInt64(Int64.max) else {
                    throw PublicRepositoryMutationStoreError.revisionExhausted
                }
                let nextRevision = Self.encodeRevision(nextValue)
                let integrityDigest = Self.requestIntegrityDigest(
                    requestID: request.id,
                    requestDigest: request.canonicalDigest,
                    baseCommitCID: request.baseCommitCID.string,
                    baseRevision: state.revision,
                    nextRevision: nextRevision,
                    status: "reserved",
                    committedCommitCID: nil,
                    committedDataCID: nil,
                    projection: nil
                )
                try await pruneTerminalPublicRepositoryMutationRequestsWithoutGate(
                    nowMicroseconds: wallClockMicroseconds
                )

                _ = try await connection.query(
                    """
                    INSERT INTO public_repository_revision_allocator(singleton, highest_value)
                    VALUES (1, ?)
                    ON CONFLICT(singleton) DO UPDATE SET highest_value = excluded.highest_value
                    """,
                    [.integer(Int(nextValue))]
                )
                try await publicRepositorySQLDidMutate(index: &mutatingSQLIndex)
                _ = try await connection.query(
                    """
                    INSERT INTO public_repository_mutation_requests(
                        request_id, request_digest, base_commit_cid, base_revision,
                        next_revision, status, integrity_digest, created_at
                    ) VALUES (?, ?, ?, ?, ?, 'reserved', ?, ?)
                    """,
                    [
                        .text(request.id),
                        request.canonicalDigest.sqliteData!,
                        .text(request.baseCommitCID.string),
                        .text(state.revision),
                        .text(nextRevision),
                        integrityDigest.sqliteData!,
                        .integer(Int(wallClockMicroseconds)),
                    ]
                )
                try await publicRepositorySQLDidMutate(index: &mutatingSQLIndex)
                return .reserved(try PublicRepositoryMutationReservation(
                    request: request,
                    repositoryDID: state.did,
                    baseRevision: state.revision,
                    nextRevision: nextRevision
                ))
            }
        }
    }

    public func applyPublicRepositoryMutation(
        reservation: PublicRepositoryMutationReservation,
        prepared: PreparedPublicRepositoryMutation
    ) async throws -> CommittedPublicRepositoryMutation {
        try await applyPublicRepositoryMutation(
            reservation: reservation,
            prepared: prepared,
            firehose: nil
        )
    }

    /// Commits a prepared repository mutation. `firehose: nil` (the default)
    /// commits without enqueuing any public firehose outbox row; a non-nil
    /// context enqueues the commit's event stamped with the context's
    /// lifecycle generation. The generation must be snapshotted by the
    /// control-plane authorization transaction, never guessed by the caller.
    public func applyPublicRepositoryMutation(
        reservation: PublicRepositoryMutationReservation,
        prepared: PreparedPublicRepositoryMutation,
        firehose: PublicFirehoseCommitContext? = nil
    ) async throws -> CommittedPublicRepositoryMutation {
        guard reservation.repositoryDID == accountDID else {
            throw PublicRepositoryMutationStoreError.ownershipMismatch
        }
        // Build every pure in-memory firehose value before entering the
        // repository transaction. These use immutable prepared data and
        // in-memory actors only; they must not open SQLite or perform
        // network I/O.
        let firehoseMaterial: PreparedPublicFirehoseMaterial?
        if let firehose {
            let eventTime = Date()
            let eventTimeString = PublicFirehoseTime.encode(eventTime)
            let eventMicros = try PublicFirehoseTime.microseconds(eventTime)
            let firehoseOps = prepared.recordResults.map { result in
                let action: PublicFirehoseRepoAction = switch result.action {
                case .create: .create
                case .update: .update
                case .delete: .delete
                }
                return PublicFirehoseRepoOp(
                    action: action,
                    path: "\(result.path.collection)/\(result.path.recordKey)",
                    cid: result.recordCID?.string,
                    prev: result.previousRecordCID?.string
                )
            }
            let diffCAR = try await PublicFirehoseDiffCAR.build(
                commitCID: prepared.state.commitCID,
                commitBytes: prepared.signedCommit.signedCommitBytes,
                newBlocks: prepared.newBlocks
            )
            let commitOnlyCAR = try await PublicFirehoseDiffCAR.commitOnly(
                commitCID: prepared.state.commitCID,
                commitBytes: prepared.signedCommit.signedCommitBytes
            )
            firehoseMaterial = PreparedPublicFirehoseMaterial(
                eventTimeString: eventTimeString,
                eventMicros: eventMicros,
                ops: firehoseOps,
                diffCAR: diffCAR,
                commitOnlyCAR: commitOnlyCAR
            )
        } else {
            firehoseMaterial = nil
        }
        return try await withConnectionGate {
            try await transaction {
                var mutatingSQLIndex = 0
                let requestRows = try await connection.query(
                    """
                    SELECT request_id, request_digest, base_commit_cid, base_revision,
                           next_revision, status, committed_commit_cid,
                           committed_data_cid, committed_projection,
                           committed_projection_digest, integrity_digest
                    FROM public_repository_mutation_requests
                    WHERE request_id = ?
                    """,
                    [.text(reservation.request.id)]
                )
                guard requestRows.count == 1, let requestRow = requestRows.first else {
                    throw PublicRepositoryMutationStoreError.reservationMismatch
                }
                let decoded = try await decodeExistingRequest(
                    requestRow,
                    request: reservation.request,
                    repositoryDID: accountDID
                )
                let storedBase = try requiredText(requestRow, "base_revision")
                let storedNext = try requiredText(requestRow, "next_revision")
                guard storedBase == reservation.baseRevision,
                      storedNext == reservation.nextRevision else {
                    throw PublicRepositoryMutationStoreError.reservationMismatch
                }
                if case let .committed(result) = decoded {
                    guard prepared.state == result.state,
                          prepared.recordResults == result.recordResults else {
                        throw PublicRepositoryMutationStoreError.conflictingRequestReuse
                    }
                    return result
                }

                guard let current = try await loadPublicRepositoryStateWithoutGate(),
                      current.did == accountDID,
                      current.commitCID == reservation.request.baseCommitCID,
                      current.revision == reservation.baseRevision else {
                    throw PublicRepositoryMutationStoreError.commitCASConflict
                }
                try await promoteValidatedPublicBlobReferencesWithoutGate(
                    prepared.publicBlobCIDs,
                    typedReferences: prepared.publicTypedBlobReferences
                )
                try validate(prepared: prepared, reservation: reservation, current: current)

                let projection = try await validatedProjection(
                    prepared.recordResults
                )
                let committedIntegrityDigest = Self.requestIntegrityDigest(
                    requestID: reservation.request.id,
                    requestDigest: reservation.request.canonicalDigest,
                    baseCommitCID: reservation.request.baseCommitCID.string,
                    baseRevision: reservation.baseRevision,
                    nextRevision: reservation.nextRevision,
                    status: "committed",
                    committedCommitCID: prepared.state.commitCID.string,
                    committedDataCID: prepared.state.dataCID.string,
                    projection: projection
                )
                for cid in prepared.newBlocks.cids {
                    guard let bytes = try await prepared.newBlocks.block(for: cid) else {
                        throw PublicRepositoryMutationStoreError.preparedMutationMismatch
                    }
                    try PublicRepositoryCID.validate(cid, blockBytes: bytes)
                    switch try await boundedPublicRepositoryBlock(
                        connection: connection, cid: cid
                    ) {
                    case .missing:
                        _ = try await connection.query(
                            "INSERT INTO public_repository_blocks(cid, bytes) VALUES (?, ?)",
                            [.text(cid.string), bytes.sqliteData!]
                        )
                        try await publicRepositorySQLDidMutate(index: &mutatingSQLIndex)
                    case .oversized:
                        throw PublicRepositoryMutationStoreError.corruptRepository
                    case let .bytes(existingBytes):
                        guard existingBytes == bytes else {
                            throw PublicRepositoryMutationStoreError.corruptRepository
                        }
                    }
                }

                try await refuseGrowthPastPublicReadCeilingWithoutGate(
                    prepared.recordResults
                )

                for result in prepared.recordResults {
                    switch result.action {
                    case .create, .update:
                        guard let recordCID = result.recordCID else {
                            throw PublicRepositoryMutationStoreError.preparedMutationMismatch
                        }
                        _ = try await connection.query(
                            """
                            INSERT INTO public_repository_record_index(
                                collection, rkey, record_cid
                            ) VALUES (?, ?, ?)
                            ON CONFLICT(collection, rkey)
                            DO UPDATE SET record_cid = excluded.record_cid
                            """,
                            [
                                .text(result.path.collection),
                                .text(result.path.recordKey),
                                .text(recordCID.string),
                            ]
                        )
                        try await publicRepositorySQLDidMutate(index: &mutatingSQLIndex)
                    case .delete:
                        _ = try await connection.query(
                            """
                            DELETE FROM public_repository_record_index
                            WHERE collection = ? AND rkey = ?
                            """,
                            [.text(result.path.collection), .text(result.path.recordKey)]
                        )
                        try await publicRepositorySQLDidMutate(index: &mutatingSQLIndex)
                    }
                }

                let advanced = try await connection.query(
                    """
                    UPDATE public_repository_state
                    SET revision = ?, commit_cid = ?, data_cid = ?
                    WHERE singleton = 1 AND did = ? AND revision = ? AND commit_cid = ?
                    RETURNING singleton
                    """,
                    [
                        .text(prepared.state.revision),
                        .text(prepared.state.commitCID.string),
                        .text(prepared.state.dataCID.string),
                        .text(accountDID),
                        .text(current.revision),
                        .text(current.commitCID.string),
                    ]
                )
                guard advanced.count == 1 else {
                    throw PublicRepositoryMutationStoreError.commitCASConflict
                }
                try await publicRepositorySQLDidMutate(index: &mutatingSQLIndex)
                let marked = try await connection.query(
                    """
                    UPDATE public_repository_mutation_requests
                    SET status = 'committed', committed_commit_cid = ?,
                        committed_data_cid = ?, committed_projection = ?,
                        committed_projection_digest = ?, integrity_digest = ?
                    WHERE request_id = ? AND status = 'reserved'
                    RETURNING request_id
                    """,
                    [
                        .text(prepared.state.commitCID.string),
                        .text(prepared.state.dataCID.string),
                        projection.sqliteData!,
                        Data(SHA256.hash(data: projection)).sqliteData!,
                        committedIntegrityDigest.sqliteData!,
                        .text(reservation.request.id),
                    ]
                )
                guard marked.count == 1 else {
                    throw PublicRepositoryMutationStoreError.reservationMismatch
                }
                try await publicRepositorySQLDidMutate(index: &mutatingSQLIndex)
                try await garbageCollectPublicRepositoryBlocksInTransaction(state: prepared.state)

                // The stored event kind is final: the source transaction owns
                // the commit-versus-sync decision and the sequencer must never
                // reinterpret a persisted row.
                if let firehose, let firehoseMaterial {
                    let commitMaterial = PublicFirehoseCommitMaterial(
                        did: accountDID,
                        rev: prepared.state.revision,
                        since: prepared.sinceRevision,
                        commitCID: prepared.state.commitCID.string,
                        prevDataCID: current.dataCID.string,
                        ops: firehoseMaterial.ops,
                        time: firehoseMaterial.eventTimeString
                    )
                    let syncMaterial = PublicFirehoseSyncMaterial(
                        did: accountDID,
                        rev: prepared.state.revision,
                        commitCID: prepared.state.commitCID.string,
                        time: firehoseMaterial.eventTimeString
                    )
                    let decision = try PublicFirehoseSourceDecisionMaker.decide(
                        accountDID: accountDID,
                        commitCID: prepared.state.commitCID,
                        commitMaterial: commitMaterial,
                        syncMaterial: syncMaterial,
                        diffCAR: firehoseMaterial.diffCAR,
                        commitOnlyCAR: firehoseMaterial.commitOnlyCAR
                    )

                    let inserted = try await enqueuePublicFirehoseEventInTransaction(
                        sourceKey: decision.sourceKey,
                        kind: decision.kind,
                        lifecycleGeneration: firehose.lifecycleGeneration,
                        payload: decision.payload,
                        carBytes: decision.car,
                        createdAt: firehoseMaterial.eventMicros
                    )
                    guard inserted else {
                        throw PublicRepositoryMutationStoreError.corruptRepository
                    }
                    try await publicRepositorySQLDidMutate(index: &mutatingSQLIndex)
                }
                return CommittedPublicRepositoryMutation(
                    state: prepared.state,
                    recordResults: prepared.recordResults
                )
            }
        }
    }

    public func abandonPublicRepositoryReservation(
        _ reservation: PublicRepositoryMutationReservation
    ) async throws {
        guard reservation.repositoryDID == accountDID else {
            throw PublicRepositoryMutationStoreError.ownershipMismatch
        }
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    "SELECT status, base_commit_cid, base_revision, next_revision, request_digest FROM public_repository_mutation_requests WHERE request_id = ?",
                    [.text(reservation.request.id)]
                )
                guard let row = rows.first,
                      try requiredText(row, "status") == "reserved" else { return }
                guard let digestValue = row.column("request_digest"),
                      let digest = Data(sqliteData: digestValue),
                      digest.count == 32 else {
                    throw PublicRepositoryMutationStoreError.corruptRepository
                }
                let baseCID = try requiredText(row, "base_commit_cid")
                let baseRevision = try requiredText(row, "base_revision")
                let nextRevision = try requiredText(row, "next_revision")
                let integrity = Self.requestIntegrityDigest(
                    requestID: reservation.request.id, requestDigest: digest,
                    baseCommitCID: baseCID, baseRevision: baseRevision,
                    nextRevision: nextRevision, status: "abandoned",
                    committedCommitCID: nil, committedDataCID: nil,
                    projection: nil
                )
                _ = try await connection.query(
                    "UPDATE public_repository_mutation_requests SET status = 'abandoned', integrity_digest = ? WHERE request_id = ? AND status = 'reserved'",
                    [integrity.sqliteData!, .text(reservation.request.id)]
                )
            }
        }
    }

    private func publicRepositorySQLDidMutate(index: inout Int) async throws {
        index += 1
        try await testingHooks.afterPublicRepositoryMutatingSQL?(index)
    }

    /// Recheck blob reachability and publish every referenced CID while the
    /// repository mutation's SQLite transaction is holding the same database
    /// serialization boundary used by permissioned promotion. The HTTP layer
    /// performs the richer metadata validation before signing; this final
    /// fence prevents a concurrent permissioned write from removing the last
    /// reference after that check but before the public record is committed.
    ///
    /// This is also the only place a public edge is created for an upload.
    /// `com.atproto.repo.uploadBlob` stages its bytes and does not publish
    /// them, precisely so an upload that is never committed — or is committed
    /// to a *permissioned* record — is never anonymously readable. Promotion
    /// therefore has to be here, inside the commit, so a rejected or
    /// abandoned mutation leaves the blob exactly as private as it arrived.
    private func promoteValidatedPublicBlobReferencesWithoutGate(
        _ cids: [CID],
        typedReferences: [PublicTypedBlobReference]
    ) async throws {
        for cid in cids {
            // A CID is a payload primary key, so this is at most one row even
            // when the blob holds both a staged and a public edge.
            let rows = try await connection.query(
                """
                SELECT blob_payloads.byte_count, blob_payloads.mime_type
                FROM blob_payloads
                WHERE blob_payloads.cid = ?
                  AND EXISTS (
                      SELECT 1 FROM blob_namespace_references
                      WHERE blob_namespace_references.cid = blob_payloads.cid
                        AND namespace_kind IN ('public', 'staged')
                        AND space_uri = ''
                  )
                LIMIT 2
                """,
                [.text(cid.string)]
            )
            guard rows.count == 1 else {
                throw PublicRepositoryMutationStoreError.publicBlobNotReachable
            }
            let row = rows[0]
            guard let byteCount = row.column("byte_count")?.integer,
                  byteCount >= 0 else {
                throw PublicRepositoryMutationStoreError.publicBlobNotReachable
            }
            let mimeType = row.column("mime_type").flatMap {
                $0.isNull ? nil : $0.string
            }
            for typed in typedReferences where typed.cid == cid {
                guard mimeType == typed.mimeType, byteCount == typed.size else {
                    throw PublicRepositoryMutationStoreError.publicBlobNotReachable
                }
            }

            // Consume the staged edge first so the account is not charged for
            // both edges at once; a blob already public stages nothing and
            // this deletes nothing.
            _ = try await connection.query(
                """
                DELETE FROM blob_namespace_references
                WHERE cid = ? AND namespace_kind = 'staged' AND space_uri = ''
                """,
                [.text(cid.string)]
            )
            try await admitBlobQuotaWithoutGate(
                cid: cid.string,
                byteCount: byteCount,
                references: [(namespaceKind: "public", spaceURI: "")]
            )
            _ = try await connection.query(
                """
                INSERT INTO blob_namespace_references(
                    cid, namespace_kind, space_uri, created_at
                ) VALUES (?, 'public', '', ?)
                ON CONFLICT(cid, namespace_kind, space_uri) DO NOTHING
                """,
                [
                    .text(cid.string),
                    .integer(Int(Date().timeIntervalSince1970)),
                ]
            )
        }
    }

    private static let maximumRevisionMicroseconds = UInt64(Int64.max) >> 10
    private static let revisionAlphabet = Array("234567abcdefghijklmnopqrstuvwxyz".utf8)

    private static func encodeRevision(_ raw: UInt64) -> String {
        var value = raw
        var bytes = Array(repeating: UInt8(ascii: "2"), count: 13)
        for index in stride(from: 12, through: 0, by: -1) {
            bytes[index] = revisionAlphabet[Int(value & 31)]
            value >>= 5
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func decodeAllocatableRevision(_ revision: String) throws -> UInt64 {
        _ = try PublicRepositoryTID(revision)
        var value: UInt64 = 0
        for byte in revision.utf8 {
            guard let digit = revisionAlphabet.firstIndex(of: byte) else {
                throw PublicRepositoryMutationStoreError.corruptRepository
            }
            let (shifted, overflow) = value.multipliedReportingOverflow(by: 32)
            let (next, addOverflow) = shifted.addingReportingOverflow(UInt64(digit))
            guard !overflow, !addOverflow, next <= UInt64(Int64.max) else {
                throw PublicRepositoryMutationStoreError.revisionExhausted
            }
            value = next
        }
        return value
    }

    private static func requestIntegrityDigest(
        requestID: String,
        requestDigest: Data,
        baseCommitCID: String,
        baseRevision: String,
        nextRevision: String,
        status: String,
        committedCommitCID: String?,
        committedDataCID: String?,
        projection: Data?
    ) -> Data {
        var bytes = Data("swan.public-repository-request.v1\u{0}".utf8)
        func append(_ value: Data?) {
            if let value {
                bytes.append(1)
                var length = UInt64(value.count).bigEndian
                withUnsafeBytes(of: &length) { bytes.append(contentsOf: $0) }
                bytes.append(value)
            } else {
                bytes.append(0)
            }
        }
        append(Data(requestID.utf8))
        append(requestDigest)
        append(Data(baseCommitCID.utf8))
        append(Data(baseRevision.utf8))
        append(Data(nextRevision.utf8))
        append(Data(status.utf8))
        append(committedCommitCID.map { Data($0.utf8) })
        append(committedDataCID.map { Data($0.utf8) })
        append(projection)
        return Data(SHA256.hash(data: bytes))
    }

    func loadPublicRepositoryStateWithoutGate(connection: SQLiteConnection? = nil) async throws -> PublicRepositoryState? {
        let conn = connection ?? self.connection
        let rows = try await conn.query(
            """
            SELECT did, revision, commit_cid, data_cid
            FROM public_repository_state WHERE singleton = 1
            """
        )
        guard rows.count <= 1 else {
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
        guard let row = rows.first else { return nil }
        do {
            let did = try requiredText(row, "did")
            guard did == accountDID else {
                throw PublicRepositoryMutationStoreError.corruptRepository
            }
            let state = try PublicRepositoryState(
                did: did,
                revision: try requiredText(row, "revision"),
                commitCID: try parseCID(try requiredText(row, "commit_cid")),
                dataCID: try parseCID(try requiredText(row, "data_cid"))
            )
            let commitBytes = try await blockBytesWithoutGate(state.commitCID)
            _ = try await blockBytesWithoutGate(state.dataCID)
            let commit = try structurallyValidatedCommit(
                signedCommitBytes: commitBytes,
                expectedCommitCID: state.commitCID
            )
            guard commit.descriptor.did == state.did,
                  commit.descriptor.revision.value == state.revision,
                  commit.descriptor.dataCID == state.dataCID else {
                throw PublicRepositoryMutationStoreError.corruptRepository
            }
            return state
        } catch let error as PublicRepositoryMutationStoreError {
            throw error
        } catch {
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
    }

    /// Historical contract, preserved exactly for direct maintenance callers:
    /// a projection or block failure surfaces as `corruptRepository`, while a
    /// bound violation or a malformed record-index row surfaces as its own
    /// `PublicRepositoryReadError`. Generation admission calls
    /// ``namedProjectionVerificationWithoutGate`` instead, which keeps the
    /// distinction the read-path diagnostics need.
    func verifyProjectionWithoutGate(
        state: PublicRepositoryState
    ) async throws {
        do {
            try await namedProjectionVerificationWithoutGate(state: state)
        } catch let error as PublicRepositoryReadError {
            switch error.unavailableReason {
            case .projectionMismatch, .blockMaterializationFailed,
                 .storageFailure:
                throw PublicRepositoryMutationStoreError.corruptRepository
            default:
                throw error
            }
        }
    }

    /// The same verification, reporting *which* check failed.
    ///
    /// One condition, one classifier: block corruption reached through the
    /// projection walk reports `.blockMaterializationFailed` here, the same
    /// name it gets when admission reads the commit block directly. A cancelled
    /// request is rethrown untouched — a caller hanging up is not a repository
    /// fault, and reporting it as one is precisely the misattribution this
    /// diagnostic work exists to remove.
    func namedProjectionVerificationWithoutGate(
        state: PublicRepositoryState
    ) async throws {
        do {
            // Keep this guard here as well as in generation admission: this
            // storage-level API is also callable directly by maintenance and
            // must not bypass the public projection bound.
            try await preflightPublicReadProjectionWithoutGate()
            _ = try await connection.query(
                "DROP TABLE IF EXISTS temp.swan_public_verified_index"
            )
            _ = try await connection.query(
                """
                CREATE TEMP TABLE swan_public_verified_index(
                    collection TEXT NOT NULL,
                    rkey TEXT NOT NULL,
                    record_cid TEXT NOT NULL,
                    PRIMARY KEY(collection, rkey)
                ) WITHOUT ROWID
                """
            )
            let projection = try await RepositoryMSTValidation.validateProjection(
                rootCID: state.dataCID,
                blocks: SQLitePublicRepositoryBlockSource(connection: connection),
                projection: SQLitePublicRepositoryProjectionSink(
                    connection: connection
                )
            )
            guard projection.recordCount <= PublicRepositoryReadLimits
                .maximumGenerationIndexEntries else {
                throw PublicRepositoryReadError.resourceLimitExceeded
            }
            let missing = try await connection.query(
                """
                SELECT collection, rkey, record_cid
                FROM temp.swan_public_verified_index
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
                FROM temp.swan_public_verified_index
                LIMIT 1
                """
            )
            guard missing.isEmpty, extra.isEmpty else {
                throw PublicRepositoryReadError.unavailable(
                    reason: .projectionMismatch
                )
            }
            _ = try await connection.query(
                "DROP TABLE temp.swan_public_verified_index"
            )
        } catch is CancellationError {
            _ = try? await connection.query(
                "DROP TABLE IF EXISTS temp.swan_public_verified_index"
            )
            throw CancellationError()
        } catch let error as PublicRepositoryReadError {
            _ = try? await connection.query(
                "DROP TABLE IF EXISTS temp.swan_public_verified_index"
            )
            throw error
        } catch let error as PublicRepositoryMutationStoreError {
            _ = try? await connection.query(
                "DROP TABLE IF EXISTS temp.swan_public_verified_index"
            )
            // Reached only through the block source during the projection walk.
            guard error == .corruptRepository else { throw error }
            throw PublicRepositoryReadError.unavailable(
                reason: .blockMaterializationFailed
            )
        } catch RepositoryMSTValidationError.recordLimitExceeded {
            _ = try? await connection.query(
                "DROP TABLE IF EXISTS temp.swan_public_verified_index"
            )
            // The MST carries more records than the read surface admits. Only
            // reachable when the tree and the index disagree — the preflight
            // above raises the same bound first for a consistent repository —
            // but it is a static bound on the account's own data, not the
            // storage fault the generic branch below would report.
            throw PublicRepositoryReadError.resourceLimitExceeded
        } catch {
            _ = try? await connection.query(
                "DROP TABLE IF EXISTS temp.swan_public_verified_index"
            )
            throw PublicRepositoryReadError.unavailable(
                reason: .storageFailure
            )
        }
    }

    private func decodeExistingRequest(
        _ row: SQLiteRow,
        request: PublicRepositoryMutationRequest,
        repositoryDID: String
    ) async throws -> PublicRepositoryMutationReservationOutcome {
        let storedRequestID = try requiredText(row, "request_id")
        guard let digestValue = row.column("request_digest"),
              let storedRequestDigest = Data(sqliteData: digestValue),
              storedRequestDigest.count == 32 else {
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
        let storedBaseCommitCID = try requiredText(row, "base_commit_cid")
        let baseRevision = try requiredText(row, "base_revision")
        let nextRevision = try requiredText(row, "next_revision")
        _ = try Self.decodeAllocatableRevision(baseRevision)
        _ = try Self.decodeAllocatableRevision(nextRevision)
        let reservation = try PublicRepositoryMutationReservation(
            request: request,
            repositoryDID: repositoryDID,
            baseRevision: baseRevision,
            nextRevision: nextRevision
        )
        let status = try requiredText(row, "status")
        let committedCommitString = row.column("committed_commit_cid")?.string
        let committedDataString = row.column("committed_data_cid")?.string
        let projection = row.column("committed_projection").flatMap(Data.init(sqliteData:))
        guard let integrityValue = row.column("integrity_digest"),
              let storedIntegrity = Data(sqliteData: integrityValue),
              storedIntegrity == Self.requestIntegrityDigest(
                  requestID: storedRequestID,
                  requestDigest: storedRequestDigest,
                  baseCommitCID: storedBaseCommitCID,
                  baseRevision: baseRevision,
                  nextRevision: nextRevision,
                  status: status,
                  committedCommitCID: committedCommitString,
                  committedDataCID: committedDataString,
                  projection: projection
              ) else {
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
        guard storedRequestID == request.id,
              storedRequestDigest == request.canonicalDigest,
              storedBaseCommitCID == request.baseCommitCID.string else {
            throw PublicRepositoryMutationStoreError.conflictingRequestReuse
        }
        switch status {
        case "reserved":
            guard committedCommitString == nil,
                  committedDataString == nil,
                  projection == nil,
                  row.column("committed_projection_digest").flatMap(Data.init(sqliteData:)) == nil
            else {
                throw PublicRepositoryMutationStoreError.corruptRepository
            }
            return .reserved(reservation)
        case "committed":
            guard let projection,
                  let digestValue = row.column("committed_projection_digest"),
                  let digest = Data(sqliteData: digestValue),
                  digest.count == 32,
                  digest == Data(SHA256.hash(data: projection)) else {
                throw PublicRepositoryMutationStoreError.corruptRepository
            }
            let state = try PublicRepositoryState(
                did: repositoryDID,
                revision: nextRevision,
                commitCID: try parseCID(try requiredText(row, "committed_commit_cid")),
                dataCID: try parseCID(try requiredText(row, "committed_data_cid"))
            )
            let commitBytes = try await blockBytesWithoutGate(state.commitCID)
            _ = try await blockBytesWithoutGate(state.dataCID)
            let commit = try structurallyValidatedCommit(
                signedCommitBytes: commitBytes,
                expectedCommitCID: state.commitCID
            )
            guard commit.descriptor.did == state.did,
                  commit.descriptor.revision.value == state.revision,
                  commit.descriptor.dataCID == state.dataCID else {
                throw PublicRepositoryMutationStoreError.corruptRepository
            }
            return .committed(CommittedPublicRepositoryMutation(
                state: state,
                recordResults: try decodeProjection(projection)
            ))
        case "abandoned":
            throw PublicRepositoryMutationStoreError.reservationMismatch
        default:
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
    }

    func blockBytesWithoutGate(_ cid: CID, connection: SQLiteConnection? = nil) async throws -> Data {
        let conn = connection ?? self.connection
        let bytes: Data
        switch try await boundedPublicRepositoryBlock(connection: conn, cid: cid) {
        case .missing, .oversized:
            throw PublicRepositoryMutationStoreError.corruptRepository
        case let .bytes(value):
            bytes = value
        }
        do {
            try PublicRepositoryCID.validate(cid, blockBytes: bytes)
        } catch {
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
        return bytes
    }

    func structurallyValidatedCommit(
        signedCommitBytes: Data,
        expectedCommitCID: CID
    ) throws -> StructurallyValidatedPublicRepositorySignedCommit {
        do {
            return try PublicRepositoryCommitCodec.structurallyValidate(
                signedCommitBytes: signedCommitBytes,
                expectedCommitCID: expectedCommitCID
            )
        } catch {
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
    }

    /// Refuses a commit that would push the live record index past the bound
    /// the public read surface enforces.
    ///
    /// Every public read admits a generation, and admission runs
    /// `preflightPublicReadProjectionWithoutGate`, which refuses any account
    /// whose `public_repository_record_index` exceeds
    /// `PublicRepositoryReadLimits.maximumGenerationIndexEntries`. Nothing on
    /// the write path used to count, so ordinary `createRecord` traffic could
    /// walk an account past that bound and permanently break `getRecord`,
    /// `listRecords`, `getLatestCommit` and `getRepo` while writes kept
    /// returning 200. No attacker is required and the account cannot read its
    /// way back out.
    ///
    /// Two properties this deliberately has:
    ///
    /// - **Only growth is refused.** `validatedProjection` has already proved
    ///   every `.create` path is absent from the index and every `.delete`
    ///   path is present, so `growth` is exact. A batch that shrinks or holds
    ///   the count is admitted unconditionally, which is what keeps a
    ///   repository that somehow ended up over the ceiling — an import, an
    ///   older build, an operator repair — able to shrink back under it. A
    ///   check that refused deletes on a full repository would be a trap with
    ///   no exit.
    /// - **No count on the common path.** Update-only and delete-only commits
    ///   never run the query at all.
    ///
    /// `COUNT(*)` rather than a maintained counter column: SQLite answers it
    /// from the covering `(collection, rkey)` primary-key index — measured at
    /// a median of 0.66 ms over a full 100,000-row index, against a commit
    /// that has already rebuilt an MST path, signed a commit and written CAR
    /// bytes. A counter column would need a table rebuild on a live PDS and
    /// would add a drift surface between the counter and the index that the
    /// projection verification would then have to check as well. It is also
    /// not available to this lane: the schema is declared in `SwanSQLite.swift`.
    private func refuseGrowthPastPublicReadCeilingWithoutGate(
        _ results: [PublicRepositoryMutationRecordResult]
    ) async throws {
        var growth = 0
        for result in results {
            switch result.action {
            case .create: growth += 1
            case .delete: growth -= 1
            case .update: break
            }
        }
        guard growth > 0 else { return }
        let rows = try await connection.query(
            "SELECT COUNT(*) AS row_count FROM public_repository_record_index"
        )
        guard rows.count == 1,
              case let .integer(liveRecords) = rows[0].column("row_count"),
              liveRecords >= 0 else {
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
        guard liveRecords <= PublicRepositoryReadLimits
            .maximumGenerationIndexEntries - growth else {
            // The same error the read path raises for the same bound. The
            // mutation error enum lives in `SwanStorage` and gains no case for
            // this; the HTTP layer maps anything it does not recognise to an
            // unavailable answer, which is the correct client-visible outcome
            // for a repository at capacity and widens no error body.
            throw PublicRepositoryReadError.resourceLimitExceeded
        }
    }

    private func validate(
        prepared: PreparedPublicRepositoryMutation,
        reservation: PublicRepositoryMutationReservation,
        current: PublicRepositoryState
    ) throws {
        guard prepared.baseCommitCID == current.commitCID,
              prepared.sinceRevision == current.revision,
              prepared.state.did == accountDID,
              prepared.state.revision == reservation.nextRevision,
              prepared.signedCommit.descriptor.did == accountDID,
              prepared.signedCommit.descriptor.revision.value == reservation.nextRevision,
              prepared.signedCommit.descriptor.dataCID == prepared.state.dataCID,
              prepared.signedCommit.commitCID == prepared.state.commitCID,
              prepared.newBlocks.cids.contains(prepared.state.commitCID)
        else {
            throw PublicRepositoryMutationStoreError.preparedMutationMismatch
        }
    }

    private func validatedProjection(
        _ results: [PublicRepositoryMutationRecordResult]
    ) async throws -> Data {
        var seen = Set<PublicRepositoryPath>()
        for result in results {
            guard seen.insert(result.path).inserted else {
                throw PublicRepositoryMutationStoreError.preparedMutationMismatch
            }
            let rows = try await connection.query(
                """
                SELECT collection, rkey, record_cid
                FROM public_repository_record_index
                WHERE collection = ? AND rkey = ?
                """,
                [.text(result.path.collection), .text(result.path.recordKey)]
            )
            let current = try rows.first.map(decodeIndexCID)
            switch result.action {
            case .create:
                guard current == nil, result.previousRecordCID == nil,
                      result.recordCID != nil else {
                    throw PublicRepositoryMutationStoreError.preparedMutationMismatch
                }
            case .update:
                guard current != nil, current == result.previousRecordCID,
                      result.recordCID != nil else {
                    throw PublicRepositoryMutationStoreError.preparedMutationMismatch
                }
            case .delete:
                guard current != nil, current == result.previousRecordCID,
                      result.recordCID == nil else {
                    throw PublicRepositoryMutationStoreError.preparedMutationMismatch
                }
            }
        }
        return try encodeProjection(results)
    }

    private func decodeIndexCID(_ row: SQLiteRow) throws -> CID {
        do {
            _ = try PublicRepositoryPath(
                collection: try requiredText(row, "collection"),
                recordKey: try requiredText(row, "rkey")
            )
            return try parseCID(try requiredText(row, "record_cid"))
        } catch {
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
    }

    private func parseCID(_ string: String) throws -> CID {
        let cid = try CID.parse(string)
        try PublicRepositoryCID.validate(cid)
        guard cid.string == string else {
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
        return cid
    }

    private func requiredText(_ row: SQLiteRow, _ column: String) throws -> String {
        guard let value = row.column(column)?.string else {
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
        return value
    }

    private func encodeProjection(
        _ results: [PublicRepositoryMutationRecordResult]
    ) throws -> Data {
        let values: [[String: Any]] = results.map {
            let action: String = switch $0.action {
            case .create: "create"
            case .update: "update"
            case .delete: "delete"
            }
            return [
                "action": action,
                "collection": $0.path.collection,
                "rkey": $0.path.recordKey,
                "recordCID": $0.recordCID?.string as Any,
                "previousCID": $0.previousRecordCID?.string as Any,
            ]
        }
        return try JSONSerialization.data(withJSONObject: values, options: [.sortedKeys])
    }

    private func decodeProjection(
        _ data: Data
    ) throws -> [PublicRepositoryMutationRecordResult] {
        do {
            guard let values = try JSONSerialization.jsonObject(with: data) as? [[String: Any]]
            else {
                throw PublicRepositoryMutationStoreError.corruptRepository
            }
            var seen = Set<PublicRepositoryPath>()
            var results: [PublicRepositoryMutationRecordResult] = []
            for value in values {
                guard let actionString = value["action"] as? String,
                      let collection = value["collection"] as? String,
                      let rkey = value["rkey"] as? String else {
                    throw PublicRepositoryMutationStoreError.corruptRepository
                }
                let action: PublicRepositoryMutationAction = switch actionString {
                case "create": .create
                case "update": .update
                case "delete": .delete
                default: throw PublicRepositoryMutationStoreError.corruptRepository
                }
                let recordCID = try (value["recordCID"] as? String).map(parseCID)
                let previousCID = try (value["previousCID"] as? String).map(parseCID)
                let path = try PublicRepositoryPath(
                    collection: collection,
                    recordKey: rkey
                )
                guard seen.insert(path).inserted else {
                    throw PublicRepositoryMutationStoreError.corruptRepository
                }
                switch action {
                case .create:
                    guard recordCID != nil, previousCID == nil else {
                        throw PublicRepositoryMutationStoreError.corruptRepository
                    }
                case .update:
                    guard recordCID != nil, previousCID != nil else {
                        throw PublicRepositoryMutationStoreError.corruptRepository
                    }
                case .delete:
                    guard recordCID == nil, previousCID != nil else {
                        throw PublicRepositoryMutationStoreError.corruptRepository
                    }
                }
                results.append(PublicRepositoryMutationRecordResult(
                    action: action,
                    path: path,
                    recordCID: recordCID,
                    previousRecordCID: previousCID
                ))
            }
            return results
        } catch let error as PublicRepositoryMutationStoreError {
            throw error
        } catch {
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
    }
    public func setPublicRepositoryBlockQuota(_ quota: PublicRepositoryBlockQuota) {
        self.publicRepositoryBlockQuota = quota
    }

    func pruneTerminalPublicRepositoryMutationRequestsWithoutGate(nowMicroseconds: UInt64) async throws {
        let oneDayMicros: UInt64 = 24 * 60 * 60 * 1_000_000
        let cutoffMicros = nowMicroseconds > oneDayMicros ? nowMicroseconds - oneDayMicros : 0
        let maxTerminalRows = 100_000

        // 1. Prune terminal receipts older than 24 hours in 1,000-row batches
        if cutoffMicros > 0 {
            while true {
                let pruned = try await connection.query(
                    """
                    DELETE FROM public_repository_mutation_requests
                    WHERE request_id IN (
                        SELECT request_id FROM public_repository_mutation_requests
                        WHERE status IN ('committed', 'abandoned')
                          AND created_at > 0
                          AND created_at < ?
                        LIMIT 1000
                    )
                    RETURNING request_id
                    """,
                    [.integer(Int(cutoffMicros))]
                )
                guard !pruned.isEmpty else { break }
            }
        }
        // 2. Prune terminal receipts beyond 100,000 rows in 1,000-row batches
        while true {
            let countRows = try await connection.query(
                """
                SELECT COUNT(*) AS count FROM public_repository_mutation_requests
                WHERE status IN ('committed', 'abandoned')
                """
            )
            guard let count = countRows.first?.column("count")?.integer,
                  count > maxTerminalRows else { break }
            let excess = count - maxTerminalRows
            let batchLimit = min(excess, 1000)
            let pruned = try await connection.query(
                """
                DELETE FROM public_repository_mutation_requests
                WHERE request_id IN (
                    SELECT request_id FROM public_repository_mutation_requests
                    WHERE status IN ('committed', 'abandoned')
                    ORDER BY created_at ASC, request_id ASC
                    LIMIT ?
                )
                RETURNING request_id
                """,
                [.integer(batchLimit)]
            )
            guard !pruned.isEmpty else { break }
        }
    }
}
