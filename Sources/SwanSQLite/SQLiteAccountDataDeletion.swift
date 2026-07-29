import Foundation
import SwanCore
import SwanStorage

/// Descriptor-anchored destructive capability for one exact account. Callers
/// receive it only after the exclusive lifecycle lease proves that no updated
/// Swan process still has the account database open.
public final class SQLiteAccountDataDeletionLease:
    @unchecked Sendable
{
    private let lock = NSLock()
    private let did: String
    private var accountDirectoryDescriptor: Int32
    private var lifecycleLockDescriptor: Int32
    private var destructionCompleted = false

    init(
        did: String,
        accountDirectoryDescriptor: Int32,
        lifecycleLockDescriptor: Int32
    ) {
        self.did = did
        self.accountDirectoryDescriptor = accountDirectoryDescriptor
        self.lifecycleLockDescriptor = lifecycleLockDescriptor
    }

    deinit { release() }

    /// Idempotent for crash-resume orchestration. The lifecycle lock remains
    /// held after successful unlink until this lease is released or deallocated.
    public func destroyAccountData() throws {
        lock.lock()
        defer { lock.unlock() }
        guard accountDirectoryDescriptor >= 0,
              lifecycleLockDescriptor >= 0 else {
            throw SwanError.unavailable(
                "account data deletion lease is unavailable"
            )
        }
        guard !destructionCompleted else { return }
        try SQLiteProtectedPaths.destroyAccountData(
            accountDirectoryDescriptor: accountDirectoryDescriptor,
            did: did
        )
        destructionCompleted = true
    }

    public func release() {
        lock.lock()
        let accountDescriptor = accountDirectoryDescriptor
        let lifecycleDescriptor = lifecycleLockDescriptor
        accountDirectoryDescriptor = -1
        lifecycleLockDescriptor = -1
        lock.unlock()
        SQLiteProtectedPaths.closeAccountLifecycleLock(
            lifecycleDescriptor
        )
        SQLiteProtectedPaths.closeDirectory(accountDescriptor)
    }
}

/// Opens no SQLite connection and accepts no caller-provided path component.
/// The DID is hashed into the canonical account shard before every descriptor
/// is opened with `O_NOFOLLOW`.
public struct SQLiteAccountDataDeletionStore: Sendable {
    private let dataDirectory: URL

    public init(dataDirectory: URL) throws {
        guard dataDirectory.isFileURL else {
            throw SwanError.unavailable(
                "account data deletion root is unavailable"
            )
        }
        self.dataDirectory = dataDirectory.standardizedFileURL
    }

    public func acquireExclusiveLease(
        did: String
    ) throws -> SQLiteAccountDataDeletionLease {
        guard AccountControlIdentifiers.isDID(did) else {
            throw SwanError.unavailable(
                "account data deletion target is unavailable"
            )
        }
        let root = try SQLiteProtectedPaths.openExistingRoot(
            dataDirectory
        )
        let account: Int32
        do {
            account = try SQLiteProtectedPaths.openExistingAccountDirectory(
                rootDescriptor: root,
                did: did
            )
        } catch {
            SQLiteProtectedPaths.closeDirectory(root)
            throw error
        }
        SQLiteProtectedPaths.closeDirectory(root)
        do {
            let lifecycle = try SQLiteProtectedPaths
                .openAccountLifecycleLock(
                    accountDirectoryDescriptor: account,
                    did: did,
                    exclusive: true
                )
            return SQLiteAccountDataDeletionLease(
                did: did,
                accountDirectoryDescriptor: account,
                lifecycleLockDescriptor: lifecycle
            )
        } catch {
            SQLiteProtectedPaths.closeDirectory(account)
            throw error
        }
    }
}
