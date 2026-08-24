import Foundation
import SwanPublicFirehose
import PetrelRepo
import SwanStorage

public enum PublicLifecycleEmitterError: Error, Equatable {
    case accountUnavailable(String)
    case missingRepositoryHead(String)
    case missingCommitBlock(String)
}

struct PublicLifecycleEmitterHooks: Sendable {
    var beforeActivationAuthorization: (@Sendable () async -> Void)?
    var beforeReactivationAuthorization: (@Sendable () async -> Void)?
    var beforeManualAuthorization: (@Sendable () async -> Void)?
}

/// The durable lifecycle emitter for confirmed PLC account operations.
///
/// Every emission is idempotent by exact source key: the control-side batch
/// insert returns the stored batch on an exact retry without advancing the
/// generation counter, and the account-side `#sync` insert deduplicates on the
/// `source_key UNIQUE` constraint. A caller that crashes between an
/// operation's completion and its emission can therefore retry the operation
/// and converge without duplicate generations or rows.
///
/// Every head `#sync` — activation, reactivation and manual alike — is
/// inserted inside `withActiveAccountFirehoseAuthorization`, which reads the
/// lifecycle generation in the same control transaction that proves the
/// account still authorizes publication. A lifecycle transition therefore
/// linearizes either before the fence (the emission fails and publishes
/// nothing) or after the sync row is durable (the sequencer orders the row
/// ahead of the transition's own batch). Without the fence a deactivation can
/// drain its `#account(active:false)` while the sync insert is still in
/// flight, and the sequencer — which has no pending batch left to order
/// against — then appends a superseded head announcement behind it.
public struct SQLitePublicLifecycleEmitter: PublicLifecycleEventEmitting {
    private let control: SQLiteControlDatabase
    private let accounts: any PublicFirehoseAccountDatabaseSource
    private let hooks: PublicLifecycleEmitterHooks

    public init(
        control: SQLiteControlDatabase,
        accounts: any PublicFirehoseAccountDatabaseSource
    ) {
        self.control = control
        self.accounts = accounts
        hooks = .init()
    }

    init(
        control: SQLiteControlDatabase,
        accounts: any PublicFirehoseAccountDatabaseSource,
        hooks: PublicLifecycleEmitterHooks
    ) {
        self.control = control
        self.accounts = accounts
        self.hooks = hooks
    }

    public func emitActivation(
        did: String, operationID: String, plcOperationCID: String,
        handle: String?, materialTime: Date, now: Date
    ) async throws {
        let time = PublicFirehoseTime.encode(materialTime)
        let identity = LifecycleEventItem(
            sourceKey: PublicFirehoseSourceKey.identity(did: did, plcOperationCID: plcOperationCID),
            kind: .identity,
            payload: try PersistedPublicFirehoseJSON.encode(
                PublicFirehoseIdentityMaterial(did: did, handle: handle, time: time)
            ),
            carBytes: nil
        )
        let account = LifecycleEventItem(
            sourceKey: PublicFirehoseSourceKey.account(did: did, operationID: operationID),
            kind: .account,
            payload: try PersistedPublicFirehoseJSON.encode(
                PublicFirehoseAccountMaterial(did: did, active: true, status: nil, time: time)
            ),
            carBytes: nil
        )
        _ = try await control.enqueueLifecycleEventBatch(
            did: did, operationID: operationID, items: [identity, account], now: now
        )
        do {
            await hooks.beforeActivationAuthorization?()
            try await control.withActiveAccountFirehoseAuthorization(did: did) {
                generation in
                try await enqueueHeadSync(
                    did: did,
                    sourceKey: PublicFirehoseSourceKey.syncActivation(
                        did: did, operationID: operationID
                    ),
                    lifecycleGeneration: generation,
                    materialTime: materialTime,
                    now: now
                )
            }
        } catch let error as AccountControlStoreError {
            if case .notFound = error {
                throw PublicLifecycleEmitterError.accountUnavailable(did)
            }
            throw error
        }
    }

    public func emitRotationIdentity(
        did: String, plcOperationCID: String, handle: String?,
        materialTime: Date, now: Date
    ) async throws {
        let time = PublicFirehoseTime.encode(materialTime)
        let identity = LifecycleEventItem(
            sourceKey: PublicFirehoseSourceKey.identity(did: did, plcOperationCID: plcOperationCID),
            kind: .identity,
            payload: try PersistedPublicFirehoseJSON.encode(
                PublicFirehoseIdentityMaterial(did: did, handle: handle, time: time)
            ),
            carBytes: nil
        )
        _ = try await control.enqueueLifecycleEventBatch(
            did: did, operationID: plcOperationCID, items: [identity], now: now
        )
    }

    public func emitReactivationSync(did: String, operationID: String, now: Date) async throws {
        do {
            await hooks.beforeReactivationAuthorization?()
            try await control.withActiveAccountFirehoseAuthorization(did: did) {
                generation in
                try await enqueueHeadSync(
                    did: did,
                    sourceKey: PublicFirehoseSourceKey.syncReactivation(
                        did: did, operationID: operationID
                    ),
                    lifecycleGeneration: generation,
                    materialTime: now,
                    now: now
                )
            }
        } catch let error as AccountControlStoreError {
            if case .notFound = error {
                throw PublicLifecycleEmitterError.accountUnavailable(did)
            }
            throw error
        }
    }

    public func emitManualSync(did: String, requestUUID: String, now: Date) async throws {
        do {
            await hooks.beforeManualAuthorization?()
            try await control.withActiveAccountFirehoseAuthorization(did: did) {
                generation in
                try await enqueueHeadSync(
                    did: did,
                    sourceKey: PublicFirehoseSourceKey.syncManual(
                        did: did, requestUUID: requestUUID
                    ),
                    lifecycleGeneration: generation,
                    materialTime: now,
                    now: now,
                    authoritativeManualRetry: true
                )
            }
        } catch let error as AccountControlStoreError {
            if case .notFound = error {
                throw PublicLifecycleEmitterError.accountUnavailable(did)
            }
            throw error
        }
    }

    private func enqueueHeadSync(
        did: String, sourceKey: String, lifecycleGeneration: Int64,
        materialTime: Date, now: Date,
        authoritativeManualRetry: Bool = false
    ) async throws {
        guard let account = try await accounts.publicFirehoseAccountDatabases()
            .first(where: { $0.did == did }) else {
            throw PublicLifecycleEmitterError.accountUnavailable(did)
        }
        guard let state = try await account.database.loadPublicRepositoryState() else {
            throw PublicLifecycleEmitterError.missingRepositoryHead(did)
        }
        guard let commitBytes = try await account.database.block(for: state.commitCID) else {
            throw PublicLifecycleEmitterError.missingCommitBlock(did)
        }
        let car = try await PublicFirehoseDiffCAR.commitOnly(
            commitCID: state.commitCID, commitBytes: commitBytes
        )
        let material = PublicFirehoseSyncMaterial(
            did: did,
            rev: state.revision,
            commitCID: state.commitCID.string,
            time: PublicFirehoseTime.encode(materialTime)
        )
        let payload = try PersistedPublicFirehoseJSON.encode(material)
        if authoritativeManualRetry {
            _ = try await account.database.enqueueAuthoritativeManualSyncEvent(
                sourceKey: sourceKey,
                lifecycleGeneration: lifecycleGeneration,
                payload: payload,
                carBytes: car,
                now: now
            )
        } else {
            _ = try await account.database.enqueuePublicFirehoseEvent(
                sourceKey: sourceKey,
                kind: .sync,
                lifecycleGeneration: lifecycleGeneration,
                payload: payload,
                carBytes: car,
                now: now
            )
        }
    }
}
