import Foundation
import SwanPublicFirehose
import SwanPublicRepository
import SwanStorage

public enum PublicLifecycleEmitterError: Error, Equatable {
    case accountUnavailable(String)
    case missingRepositoryHead(String)
    case missingCommitBlock(String)
}

/// The durable lifecycle emitter for confirmed PLC account operations.
///
/// Every emission is idempotent by exact source key: the control-side batch
/// insert returns the stored batch on an exact retry without advancing the
/// generation counter, and the account-side `#sync` insert deduplicates on the
/// `source_key UNIQUE` constraint. A caller that crashes between an
/// operation's completion and its emission can therefore retry the operation
/// and converge without duplicate generations or rows.
public struct SQLitePublicLifecycleEmitter: PublicLifecycleEventEmitting {
    private let control: SQLiteControlDatabase
    private let accounts: any PublicFirehoseAccountDatabaseSource

    public init(
        control: SQLiteControlDatabase,
        accounts: any PublicFirehoseAccountDatabaseSource
    ) {
        self.control = control
        self.accounts = accounts
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
        let batch = try await control.enqueueLifecycleEventBatch(
            did: did, operationID: operationID, items: [identity, account], now: now
        )
        try await enqueueHeadSync(
            did: did,
            sourceKey: PublicFirehoseSourceKey.syncActivation(did: did, operationID: operationID),
            lifecycleGeneration: batch.generation,
            materialTime: materialTime,
            now: now
        )
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
        let generation = try await control.currentLifecycleGeneration(did: did)
        try await enqueueHeadSync(
            did: did,
            sourceKey: PublicFirehoseSourceKey.syncReactivation(did: did, operationID: operationID),
            lifecycleGeneration: generation,
            materialTime: now,
            now: now
        )
    }

    public func emitManualSync(did: String, requestUUID: String, now: Date) async throws {
        let generation = try await control.currentLifecycleGeneration(did: did)
        try await enqueueHeadSync(
            did: did,
            sourceKey: PublicFirehoseSourceKey.syncManual(did: did, requestUUID: requestUUID),
            lifecycleGeneration: generation,
            materialTime: now,
            now: now
        )
    }

    private func enqueueHeadSync(
        did: String, sourceKey: String, lifecycleGeneration: Int64,
        materialTime: Date, now: Date
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
        _ = try await account.database.enqueuePublicFirehoseEvent(
            sourceKey: sourceKey,
            kind: .sync,
            lifecycleGeneration: lifecycleGeneration,
            payload: try PersistedPublicFirehoseJSON.encode(material),
            carBytes: car,
            now: now
        )
    }
}
