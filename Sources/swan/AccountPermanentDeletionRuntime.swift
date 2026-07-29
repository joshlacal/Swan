import Foundation
import SwanAccounts
import SwanSQLite
import SwanStorage

/// One process-local quiescence/data-erasure adapter. It removes the DID from
/// the live directory, waits for SQLite/blob leases to drain, and then retains
/// the cross-process exclusive lifecycle lease until exact data destruction
/// completes.
actor ServeAccountPermanentDeletionStorageRuntime:
    AccountPermanentDeletionQuiescing,
    AccountPermanentDeletionDataDestroyer
{
    private let liveDirectory: SQLitePreMigratedAccountDirectory?
    private let deletionStore: SQLiteAccountDataDeletionStore
    private var leases: [String: SQLiteAccountDataDeletionLease] = [:]

    init(
        dataDirectory: URL,
        liveDirectory: SQLitePreMigratedAccountDirectory?
    ) throws {
        self.liveDirectory = liveDirectory
        deletionStore = try SQLiteAccountDataDeletionStore(
            dataDirectory: dataDirectory
        )
    }

    func quiesceAccount(did: String) async throws {
        if let liveDirectory {
            try await liveDirectory.revokeAndDrainAccount(did: did)
        }
        guard leases[did] == nil else { return }
        leases[did] = try deletionStore.acquireExclusiveLease(did: did)
    }

    func destroyAccountData(did: String) throws {
        guard let lease = leases[did] else {
            throw AccountDeletionStoreError.unavailable
        }
        do {
            try lease.destroyAccountData()
            lease.release()
            leases.removeValue(forKey: did)
        } catch {
            // Retain the exclusive lease across an in-process retry. A process
            // crash releases it, after which startup recovery reacquires it.
            throw error
        }
    }
}

struct ServeAccountPermanentDeletionRuntime {
    let coordinator: AccountPermanentDeletionCoordinator

    init(
        controlStore: SQLiteControlDatabase,
        dataDirectory: URL,
        keyStore: FileAccountKeyStore,
        plcConfiguration: PLCClientConfiguration,
        liveDirectory: SQLitePreMigratedAccountDirectory?
    ) throws {
        let storage = try ServeAccountPermanentDeletionStorageRuntime(
            dataDirectory: dataDirectory,
            liveDirectory: liveDirectory
        )
        coordinator = AccountPermanentDeletionCoordinator(
            controlStore: controlStore,
            keyStore: keyStore,
            quiescer: storage,
            plcTombstoner:
                PLCDirectoryAccountPermanentDeletionTombstoner(
                    keyStore: keyStore,
                    plcClient: try PLCDirectoryClient(
                        configuration: plcConfiguration
                    )
                ),
            dataDestroyer: storage
        )
    }

    /// Completes every bounded page before either public or management
    /// listeners are constructed. Any unprovable PLC/quiescence/data step is
    /// therefore a startup failure, never a partially available server.
    func resumePendingJobs(
        controlStore: any AccountDeletionControlStore,
        now: @Sendable () -> Date = { Date() }
    ) async throws {
        try await resumePendingDeletionJobsBeforeServe(
            fetch: { afterDID, limit in
                try await controlStore.pendingDeletionJobs(
                    afterDID: afterDID,
                    limit: limit
                )
            },
            resume: { did, resumedAt in
                _ = try await coordinator.resume(
                    did: did,
                    now: resumedAt
                )
            },
            now: now
        )
    }
}

/// Pending jobs disappear after successful finalization. Always pop the first
/// bounded page instead of advancing a lexical cursor: a concurrent operator
/// process can insert a lower DID while startup recovery is awaiting PLC or
/// filesystem work, and a monotonic cursor would otherwise skip that job
/// before the listeners start.
func resumePendingDeletionJobsBeforeServe(
    pageLimit: Int = 100,
    fetch: @Sendable (
        _ afterDID: String?,
        _ limit: Int
    ) async throws -> [AccountDeletionJob],
    resume: @Sendable (
        _ did: String,
        _ now: Date
    ) async throws -> Void,
    now: @Sendable () -> Date = { Date() }
) async throws {
    guard (1 ... 100).contains(pageLimit) else {
        throw AccountDeletionStoreError.invalidInput
    }
    while true {
        let jobs = try await fetch(nil, pageLimit)
        guard !jobs.isEmpty else { return }
        for job in jobs {
            try await resume(job.did, now())
        }
    }
}
