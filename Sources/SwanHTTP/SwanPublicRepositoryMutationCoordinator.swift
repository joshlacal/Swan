import Foundation
import Petrel
import PetrelRepo
import SwanStorage

public enum PublicRepositoryMutationCoordinatorError: Error, Sendable, Equatable {
    case repositoryNotFound
    case inactiveAccount
    case invalidSwap
    case invalidBlobReference
    case recordAlreadyExists
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
            let attemptRequestID = attempts == 1 ? requestID : "\(requestID):retry-\(attempts)"
            let request = try PublicRepositoryMutationRequest(id: attemptRequestID, canonicalDigest: bodyDigest, baseCommitCID: current.commitCID)
            switch try await store.reservePublicRepositoryRevision(request, wallClockMicroseconds: now()) {
            case let .committed(committed): return committed
            case let .reserved(reservation):
                do {
                    return try await applyReserved(
                        store: store,
                        did: did,
                        current: current,
                        reservation: reservation,
                        batch: batch,
                        signerProvider: signerProvider
                    )
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

    public static func create(
        store: any PublicRepositoryMutationStore,
        did: String,
        path: PublicRepositoryPath,
        record: PublicRecord,
        swapCommit: CID?,
        requestID: String,
        bodyDigest: Data,
        signerProvider: any PublicRepositoryMutationSignerProvider,
        now: @Sendable () -> UInt64 = currentWallClockMicroseconds
    ) async throws -> PublicRepositoryMutationResult {
        guard try await store.loadPublicRepositoryState() != nil else {
            throw PublicRepositoryMutationCoordinatorError.repositoryNotFound
        }
        let current = try await store.publicRepositoryRecordCID(for: path)
        if current != nil {
            throw PublicRepositoryMutationCoordinatorError.recordAlreadyExists
        }
        return try await applyWithRetry(
            store: store,
            did: did,
            path: path,
            batch: .init(
                writes: [.create(path: path, record: record)],
                expectedCommitCID: swapCommit
            ),
            requestID: requestID,
            bodyDigest: bodyDigest,
            signerProvider: signerProvider,
            now: now,
            action: .create
        )
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
            let attemptRequestID = attempts == 1 ? requestID : "\(requestID):retry-\(attempts)"
            let request = try PublicRepositoryMutationRequest(
                id: attemptRequestID,
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
                    let committed = try await applyReserved(
                        store: store,
                        did: did,
                        current: current,
                        reservation: reservation,
                        batch: batch,
                        signerProvider: signerProvider
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

    /// A stale generation is rejected before account-database mutation, so
    /// the same durable reservation can be safely re-signed once with freshly
    /// resolved key material. This is deliberately bounded and does not
    /// abandon the reservation between signer attempts.
    private static func applyReserved(
        store: any PublicRepositoryMutationStore,
        did: String,
        current: PublicRepositoryState,
        reservation: PublicRepositoryMutationReservation,
        batch: PublicRepositoryWriteBatch,
        signerProvider: any PublicRepositoryMutationSignerProvider
    ) async throws -> CommittedPublicRepositoryMutation {
        var signerAttempts = 0
        while true {
            signerAttempts += 1
            let resolved = try await signerProvider.signer(for: did)
            guard resolved.generation > 0 else {
                throw PublicRepositoryMutationCoordinatorError.unavailable
            }
            let prepared = try await PublicRepositoryEngine.apply(
                repositoryDID: did,
                currentState: current,
                blocks: store,
                revision: reservation.nextRevision,
                batch: batch,
                signer: resolved.signer,
                signingGeneration: resolved.generation
            )
            do {
                return try await store.applyPublicRepositoryMutation(
                    reservation: reservation,
                    prepared: prepared
                )
            } catch let error as PublicRepositoryMutationPublicationError
                where error == .staleSigningGeneration && signerAttempts < 2
            {
                continue
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
        if let error = error as? PublicRepositoryMutationStoreError,
           error == .publicBlobNotReachable {
            return .invalidBlobReference
        }
        if let error = error as? PublicRepositoryEngineError {
            switch error {
            case .commitCIDMismatch, .recordCIDMismatch:
                return .invalidSwap
            case .recordAlreadyExists:
                return .recordAlreadyExists
            default:
                return .unavailable
            }
        }
        // A deactivation that lands between the route's `status == .active`
        // check and the publication fence. The fence used to answer this by
        // committing without emitting a firehose event, which left the
        // repository ahead of every relay's view of it with nothing to
        // reconcile from; it now refuses, and the client sees the same 403
        // `AccountInactive` a write to an already-inactive account would
        // deserve rather than a 200 for a write no relay will ever hear.
        if let error = error as? AccountControlStoreError,
           error == .invalidTransition {
            return .inactiveAccount
        }
        return .unavailable
    }

    public static func currentWallClockMicroseconds() -> UInt64 {
        let seconds = Date().timeIntervalSince1970
        guard seconds.isFinite, seconds >= 0 else { return 0 }
        return UInt64(seconds * 1_000_000)
    }
}
