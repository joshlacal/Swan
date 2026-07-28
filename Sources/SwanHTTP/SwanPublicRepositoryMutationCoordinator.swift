import Foundation
import Petrel
import SwanPublicRepository
import SwanStorage

public enum PublicRepositoryMutationCoordinatorError: Error, Sendable, Equatable {
    case repositoryNotFound
    case inactiveAccount
    case invalidSwap
    case unavailable
}

public struct PublicRepositoryMutationResult: Sendable, Equatable {
    public let state: PublicRepositoryState
    public let action: PublicRepositoryMutationAction
    public let path: PublicRepositoryPath
    public let recordCID: CID?
    public let isNoOp: Bool

    public init(
        state: PublicRepositoryState,
        action: PublicRepositoryMutationAction,
        path: PublicRepositoryPath,
        recordCID: CID?,
        isNoOp: Bool = false
    ) {
        self.state = state
        self.action = action
        self.path = path
        self.recordCID = recordCID
        self.isNoOp = isNoOp
    }
}

/// Storage-facing public mutation orchestration. It deliberately accepts a
/// mutation store and a key provider, never a database handle or private key.
public enum SwanPublicRepositoryMutationCoordinator {
    public static func applyBatch(
        store: any PublicRepositoryMutationStore,
        did: String,
        batch: PublicRepositoryWriteBatch,
        requestID: String,
        bodyDigest: Data,
        signerProvider: any PublicRepositoryMutationSignerProvider,
        now: @Sendable () -> UInt64 = currentWallClockMicroseconds
    ) async throws -> CommittedPublicRepositoryMutation {
        var attempts = 0
        let callerSuppliedSwap = batch.expectedCommitCID != nil
        while true {
            attempts += 1
            guard let current = try await store.loadPublicRepositoryState() else { throw PublicRepositoryMutationCoordinatorError.repositoryNotFound }
            let request = try PublicRepositoryMutationRequest(id: requestID, canonicalDigest: bodyDigest, baseCommitCID: current.commitCID)
            switch try await store.reservePublicRepositoryRevision(request, wallClockMicroseconds: now()) {
            case let .committed(committed): return committed
            case let .reserved(reservation):
                do {
                    let prepared = try await PublicRepositoryEngine.apply(
                        repositoryDID: did, currentState: current, blocks: store,
                        revision: reservation.nextRevision, batch: batch,
                        signer: try await signerProvider.signer(for: did)
                    )
                    return try await store.applyPublicRepositoryMutation(reservation: reservation, prepared: prepared)
                } catch let error as PublicRepositoryMutationStoreError where error == .commitCASConflict && !callerSuppliedSwap && attempts < 2 {
                    try? await store.abandonPublicRepositoryReservation(reservation)
                    continue
                } catch {
                    try? await store.abandonPublicRepositoryReservation(reservation)
                    throw map(error)
                }
            }
        }
    }

    public static func put(
        store: any PublicRepositoryMutationStore,
        did: String,
        path: PublicRepositoryPath,
        record: PublicRecord,
        swapRecord: CID?,
        swapCommit: CID?,
        requestID: String,
        bodyDigest: Data,
        signerProvider: any PublicRepositoryMutationSignerProvider,
        now: @Sendable () -> UInt64 = currentWallClockMicroseconds
    ) async throws -> PublicRepositoryMutationResult {
        let prepared = try PublicRepositoryRecordCodec.prepare(record, for: path)
        guard let initial = try await store.loadPublicRepositoryState() else {
            throw PublicRepositoryMutationCoordinatorError.repositoryNotFound
        }
        let current = try await store.publicRepositoryRecordCID(for: path)
        // Pinned behavior: a same-CID put is a no-op before either swap check.
        if current == prepared.cid {
            return PublicRepositoryMutationResult(
                state: initial, action: .update, path: path, recordCID: current, isNoOp: true
            )
        }
        // A record swap is meaningful only when the selected path already
        // exists. Do not turn a caller's failed create CAS into an
        // unconditional create by silently dropping the supplied swap.
        if current == nil, swapRecord != nil {
            throw PublicRepositoryMutationCoordinatorError.invalidSwap
        }
        return try await applyWithRetry(
            store: store,
            did: did,
            path: path,
            batch: .init(
                writes: current == nil
                    ? [.create(path: path, record: record)]
                    : [.update(path: path, record: record, expectedRecordCID: swapRecord)],
                expectedCommitCID: swapCommit
            ),
            requestID: requestID,
            bodyDigest: bodyDigest,
            signerProvider: signerProvider,
            now: now,
            action: current == nil ? .create : .update
        )
    }

    public static func delete(
        store: any PublicRepositoryMutationStore,
        did: String,
        path: PublicRepositoryPath,
        swapRecord: CID?,
        swapCommit: CID?,
        requestID: String,
        bodyDigest: Data,
        signerProvider: any PublicRepositoryMutationSignerProvider,
        now: @Sendable () -> UInt64 = currentWallClockMicroseconds
    ) async throws -> PublicRepositoryMutationResult? {
        guard try await store.loadPublicRepositoryState() != nil else {
            throw PublicRepositoryMutationCoordinatorError.repositoryNotFound
        }
        let current = try await store.publicRepositoryRecordCID(for: path)
        // Pinned behavior: deleting an absent record is a no-op before swaps.
        guard current != nil else { return nil }
        return try await applyWithRetry(
            store: store,
            did: did,
            path: path,
            batch: .init(
                writes: [.delete(path: path, expectedRecordCID: swapRecord)],
                expectedCommitCID: swapCommit
            ),
            requestID: requestID,
            bodyDigest: bodyDigest,
            signerProvider: signerProvider,
            now: now,
            action: .delete
        )
    }

    private static func applyWithRetry(
        store: any PublicRepositoryMutationStore,
        did: String,
        path: PublicRepositoryPath,
        batch: PublicRepositoryWriteBatch,
        requestID: String,
        bodyDigest: Data,
        signerProvider: any PublicRepositoryMutationSignerProvider,
        now: @Sendable () -> UInt64,
        action: PublicRepositoryMutationAction
    ) async throws -> PublicRepositoryMutationResult {
        let callerSuppliedSwap = batch.expectedCommitCID != nil
            || batch.writes.contains { $0.expectedRecordCID != nil }
        var attempts = 0
        while true {
            attempts += 1
            guard let current = try await store.loadPublicRepositoryState() else {
                throw PublicRepositoryMutationCoordinatorError.repositoryNotFound
            }
            let request = try PublicRepositoryMutationRequest(
                id: requestID,
                canonicalDigest: bodyDigest,
                baseCommitCID: current.commitCID
            )
            let outcome = try await store.reservePublicRepositoryRevision(
                request, wallClockMicroseconds: now()
            )
            switch outcome {
            case let .committed(committed):
                return try result(committed, path: path, action: action)
            case let .reserved(reservation):
                do {
                    let signer = try await signerProvider.signer(for: did)
                    let prepared = try await PublicRepositoryEngine.apply(
                        repositoryDID: did,
                        currentState: current,
                        blocks: store,
                        revision: reservation.nextRevision,
                        batch: batch,
                        signer: signer
                    )
                    let committed = try await store.applyPublicRepositoryMutation(
                        reservation: reservation, prepared: prepared
                    )
                    return try result(committed, path: path, action: action)
                } catch let error as PublicRepositoryMutationStoreError {
                    guard error == .commitCASConflict,
                          !callerSuppliedSwap,
                          attempts < 2 else {
                        try? await store.abandonPublicRepositoryReservation(reservation)
                        throw map(error)
                    }
                    try? await store.abandonPublicRepositoryReservation(reservation)
                } catch {
                    try? await store.abandonPublicRepositoryReservation(reservation)
                    throw map(error)
                }
            }
        }
    }

    private static func result(
        _ committed: CommittedPublicRepositoryMutation,
        path: PublicRepositoryPath,
        action: PublicRepositoryMutationAction
    ) throws -> PublicRepositoryMutationResult {
        let recordCID = committed.recordResults.first(where: { $0.path == path })?.recordCID
        return PublicRepositoryMutationResult(
            state: committed.state, action: action, path: path, recordCID: recordCID
        )
    }

    private static func map(_ error: Error) -> PublicRepositoryMutationCoordinatorError {
        if let error = error as? PublicRepositoryMutationStoreError,
           error == .commitCASConflict {
            return .unavailable
        }
        if let error = error as? PublicRepositoryEngineError {
            switch error {
            case .commitCIDMismatch, .recordCIDMismatch:
                return .invalidSwap
            default:
                return .unavailable
            }
        }
        return .unavailable
    }

    public static func currentWallClockMicroseconds() -> UInt64 {
        let seconds = Date().timeIntervalSince1970
        guard seconds.isFinite, seconds >= 0 else { return 0 }
        return UInt64(seconds * 1_000_000)
    }
}
