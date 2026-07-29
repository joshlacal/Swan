import Foundation
import SwanStorage

/// Narrow capability injected into operator-facing account control. Concrete
/// implementations must durably complete or resume every permanent-deletion
/// stage before returning the terminal tombstone.
public protocol AccountPermanentDeletionCoordinating: Sendable {
    func beginAndResume(
        did: String,
        declaration: AccountLifecycleDeclaration,
        now: Date
    ) async throws -> AccountDeletionTombstone
}

/// Revokes the selected DID from every live request-selection surface and
/// waits for any already-authorized, escaping storage leases to drain. A
/// deletion coordinator must obtain this proof before PLC tombstoning, key
/// destruction, or account-data unlinking.
public protocol AccountPermanentDeletionQuiescing: Sendable {
    func quiesceAccount(did: String) async throws
}

/// Later runtime composition supplies the concrete PLC client. The operation
/// must be idempotent because a crash can occur after the remote directory
/// accepts the tombstone but before control.sqlite advances its stage.
public protocol AccountPermanentDeletionPLCTombstoner: Sendable {
    func tombstonePLCIdentity(
        did: String,
        rotationKey: AccountKeyReference
    ) async throws
}

/// Later runtime composition owns exact account-database and CAS paths. This
/// operation must be idempotent and must remove only the selected DID's
/// account database, repository material, and blob ownership.
public protocol AccountPermanentDeletionDataDestroyer: Sendable {
    func destroyAccountData(did: String) async throws
}

/// Coordinates the non-transactional half of permanent deletion without
/// performing network or filesystem I/O inside a control.sqlite transaction.
/// Each completed external side effect is followed by one monotonic durable
/// stage transition, so restart resumes from the last committed boundary.
public actor AccountPermanentDeletionCoordinator:
    AccountPermanentDeletionCoordinating
{
    private struct BeginRequest: Sendable, Equatable {
        let declaration: AccountLifecycleDeclaration
        let now: Date
    }

    private struct BeginFlight: Sendable {
        let id: UUID
        let request: BeginRequest
        let task: Task<AccountDeletionTombstone, any Error>
    }

    private let controlStore: any AccountDeletionControlStore
    private let keyStore: any AccountKeyDestructionStore
    private let quiescer: any AccountPermanentDeletionQuiescing
    private let plcTombstoner:
        any AccountPermanentDeletionPLCTombstoner
    private let dataDestroyer:
        any AccountPermanentDeletionDataDestroyer
    private var beginFlightsByDID: [String: BeginFlight] = [:]

    public init(
        controlStore: any AccountDeletionControlStore,
        keyStore: any AccountKeyDestructionStore,
        quiescer: any AccountPermanentDeletionQuiescing,
        plcTombstoner:
            any AccountPermanentDeletionPLCTombstoner,
        dataDestroyer:
            any AccountPermanentDeletionDataDestroyer
    ) {
        self.controlStore = controlStore
        self.keyStore = keyStore
        self.quiescer = quiescer
        self.plcTombstoner = plcTombstoner
        self.dataDestroyer = dataDestroyer
    }

    public func beginAndResume(
        did: String,
        declaration: AccountLifecycleDeclaration,
        now: Date
    ) async throws -> AccountDeletionTombstone {
        let request = BeginRequest(declaration: declaration, now: now)
        if let flight = beginFlightsByDID[did] {
            // A simultaneous request with different retained metadata cannot
            // silently inherit the first operator's deletion declaration.
            guard flight.request == request else {
                throw AccountDeletionStoreError.conflict
            }
            return try await flight.task.value
        }

        let flightID = UUID()
        let task = Task {
            try await self.performBeginAndResume(
                did: did,
                declaration: declaration,
                now: now
            )
        }
        beginFlightsByDID[did] = BeginFlight(
            id: flightID,
            request: request,
            task: task
        )
        do {
            let tombstone = try await task.value
            clearBeginFlight(did: did, id: flightID)
            return tombstone
        } catch {
            clearBeginFlight(did: did, id: flightID)
            throw error
        }
    }

    private func performBeginAndResume(
        did: String,
        declaration: AccountLifecycleDeclaration,
        now: Date
    ) async throws -> AccountDeletionTombstone {
        if let terminal = try await controlStore.tombstone(did: did) {
            guard terminal.tombstone == declaration.tombstone,
                  terminal.export == declaration.export else {
                throw AccountDeletionStoreError.conflict
            }
            return terminal
        }
        _ = try await controlStore.beginDeletion(
            did: did,
            declaration: declaration,
            now: now
        )
        return try await resume(did: did, now: now)
    }

    private func clearBeginFlight(did: String, id: UUID) {
        guard beginFlightsByDID[did]?.id == id else { return }
        beginFlightsByDID.removeValue(forKey: did)
    }

    public func resume(
        did: String,
        now: Date
    ) async throws -> AccountDeletionTombstone {
        if let tombstone = try await controlStore.tombstone(did: did) {
            return tombstone
        }
        guard var job = try await controlStore.deletionJob(did: did) else {
            throw AccountDeletionStoreError.notFound
        }

        // Reassert quiescence on every restart before resuming any external
        // side effect. The concrete runtime must make this idempotent and
        // fail closed if a live database/body lease cannot be drained.
        try await quiescer.quiesceAccount(did: did)

        // There are exactly four canonical stages. Keep this as a bounded
        // state machine rather than an open-ended retry loop.
        for _ in 0 ..< AccountDeletionStage.allCases.count {
            switch job.stage {
            case .controlScrubbed:
                // PLC tombstoning precedes key erasure because the concrete
                // PLC client may need the account rotation key.
                guard let controlRotationKey = job.rotationKey else {
                    throw AccountDeletionStoreError.malformedRecord
                }
                let rotationKey = try AccountKeyReference(
                    accountDID: did,
                    purpose: .rotation,
                    generation: controlRotationKey.generation
                )
                try await plcTombstoner.tombstonePLCIdentity(
                    did: did,
                    rotationKey: rotationKey
                )
                job = try await controlStore.advanceDeletion(
                    did: did,
                    expectedStage: .controlScrubbed,
                    expectedRevision: job.revision,
                    to: .plcTombstoned,
                    now: now
                )
            case .plcTombstoned:
                _ = try await keyStore.destroyAccountKeyMaterial(
                    try AccountKeyDestructionRequest(
                        accountDID: did,
                        stagingBindings: job.stagingKeyBindings
                    )
                )
                job = try await controlStore.advanceDeletion(
                    did: did,
                    expectedStage: .plcTombstoned,
                    expectedRevision: job.revision,
                    to: .keyMaterialDestroyed,
                    now: now
                )
            case .keyMaterialDestroyed:
                try await dataDestroyer.destroyAccountData(did: did)
                job = try await controlStore.advanceDeletion(
                    did: did,
                    expectedStage: .keyMaterialDestroyed,
                    expectedRevision: job.revision,
                    to: .accountDataDestroyed,
                    now: now
                )
            case .accountDataDestroyed:
                return try await controlStore.finalizeDeletion(
                    did: did,
                    expectedRevision: job.revision,
                    now: now
                )
            }
        }
        throw AccountDeletionStoreError.malformedRecord
    }
}
