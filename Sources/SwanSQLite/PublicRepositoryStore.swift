import Crypto
import Foundation
import Petrel
import SQLiteNIO
import SwanPublicRepository
import SwanStorage

struct SQLitePublicRepositoryBlockSource: PublicRepositoryBlockSource {
    let connection: SQLiteConnection

    func block(for cid: CID) async throws -> Data? {
        let rows = try await connection.query(
            "SELECT bytes FROM public_repository_blocks WHERE cid = ?",
            [.text(cid.string)]
        )
        guard rows.count <= 1 else {
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
        guard let row = rows.first,
              let value = row.column("bytes"),
              let bytes = Data(sqliteData: value) else {
            return nil
        }
        do {
            try PublicRepositoryCID.validate(cid, blockBytes: bytes)
        } catch {
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
        return bytes
    }
}

extension SQLiteAccountDatabase: PublicRepositoryMutationStore {
    public func loadPublicRepositoryState() async throws -> PublicRepositoryState? {
        try await withConnectionGate {
            try await loadPublicRepositoryStateWithoutGate()
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
        return try await withConnectionGate {
            let rows = try await connection.query(
                "SELECT bytes FROM public_repository_blocks WHERE cid = ?",
                [.text(cid.string)]
            )
            guard rows.count <= 1 else {
                throw PublicRepositoryMutationStoreError.corruptRepository
            }
            guard let row = rows.first,
                  let value = row.column("bytes"),
                  let bytes = Data(sqliteData: value)
            else { return nil }
            do {
                try PublicRepositoryCID.validate(cid, blockBytes: bytes)
            } catch {
                throw PublicRepositoryMutationStoreError.corruptRepository
            }
            return bytes
        }
    }

    public func publicRepositoryRecordCID(
        for path: PublicRepositoryPath
    ) async throws -> CID? {
        try await withConnectionGate {
            guard let state = try await loadPublicRepositoryStateWithoutGate() else {
                throw PublicRepositoryMutationStoreError.repositoryNotInstalled
            }
            let rows = try await connection.query(
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
                    blocks: SQLitePublicRepositoryBlockSource(connection: connection)
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
                        next_revision, status, integrity_digest
                    ) VALUES (?, ?, ?, ?, ?, 'reserved', ?)
                    """,
                    [
                        .text(request.id),
                        request.canonicalDigest.sqliteData!,
                        .text(request.baseCommitCID.string),
                        .text(state.revision),
                        .text(nextRevision),
                        integrityDigest.sqliteData!,
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
        guard reservation.repositoryDID == accountDID else {
            throw PublicRepositoryMutationStoreError.ownershipMismatch
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
                    let existing = try await connection.query(
                        "SELECT bytes FROM public_repository_blocks WHERE cid = ?",
                        [.text(cid.string)]
                    )
                    if let row = existing.first {
                        guard let value = row.column("bytes"),
                              Data(sqliteData: value) == bytes else {
                            throw PublicRepositoryMutationStoreError.corruptRepository
                        }
                    } else {
                        _ = try await connection.query(
                            "INSERT INTO public_repository_blocks(cid, bytes) VALUES (?, ?)",
                            [.text(cid.string), bytes.sqliteData!]
                        )
                        try await publicRepositorySQLDidMutate(index: &mutatingSQLIndex)
                    }
                }

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
                let digest = Data(sqliteData: row.column("request_digest")!)!
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

    func loadPublicRepositoryStateWithoutGate() async throws -> PublicRepositoryState? {
        let rows = try await connection.query(
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

    func verifyProjectionWithoutGate(
        state: PublicRepositoryState
    ) async throws {
        do {
            let repository = try await RepositoryMSTValidation.validate(
                rootCID: state.dataCID,
                blocks: SQLitePublicRepositoryBlockSource(connection: connection)
            )
            let indexRows = try await connection.query(
                """
                SELECT collection, rkey, record_cid
                FROM public_repository_record_index
                """
            )
            var index: [PublicRepositoryPath: CID] = [:]
            for row in indexRows {
                let path = try PublicRepositoryPath(
                    collection: try requiredText(row, "collection"),
                    recordKey: try requiredText(row, "rkey")
                )
                guard index[path] == nil else {
                    throw PublicRepositoryMutationStoreError.corruptRepository
                }
                index[path] = try parseCID(try requiredText(row, "record_cid"))
            }
            let mstIndex = Dictionary(
                uniqueKeysWithValues: repository.leaves.map { ($0.path, $0.recordCID) }
            )
            guard index == mstIndex else {
                throw PublicRepositoryMutationStoreError.corruptRepository
            }
        } catch let error as PublicRepositoryMutationStoreError {
            throw error
        } catch {
            throw PublicRepositoryMutationStoreError.corruptRepository
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

    func blockBytesWithoutGate(_ cid: CID) async throws -> Data {
        let rows = try await connection.query(
            "SELECT bytes FROM public_repository_blocks WHERE cid = ?",
            [.text(cid.string)]
        )
        guard rows.count == 1,
              let value = rows[0].column("bytes"),
              let bytes = Data(sqliteData: value) else {
            throw PublicRepositoryMutationStoreError.corruptRepository
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
}
