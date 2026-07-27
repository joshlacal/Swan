import Crypto
import Foundation
import SwanCore

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Descriptor-validated, owner-only filesystem placement for SQLite data.
/// SQLiteNIO accepts paths rather than file descriptors; macOS SQLite cannot
/// open a database through `/dev/fd/<directory-fd>/name`. We therefore retain
/// directory descriptors for validation and sidecar operations while opening
/// the corresponding absolute path. Every writable directory is exact-0700
/// and owned by the current EUID, so another local user cannot replace that
/// verified path between validation and SQLite's open.
enum SQLiteProtectedPaths {
    private static let ownerOnlyDirectoryMode: mode_t = 0o700
    private static let ownerOnlyFileMode: mode_t = 0o600

    static func openRoot(_ url: URL) throws -> Int32 {
        let path = url.standardizedFileURL.path
        let descriptor: Int32
        if FileManager.default.fileExists(atPath: path) {
            descriptor = try openExistingDirectory(path: path)
            do {
                try requireOwnerOnlyDirectory(descriptor)
            } catch {
                _ = close(descriptor)
                throw error
            }
            return descriptor
        }

        try FileManager.default.createDirectory(
            at: URL(fileURLWithPath: path),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: NSNumber(value: Int(ownerOnlyDirectoryMode))]
        )
        descriptor = try openExistingDirectory(path: path)
        do {
            try requireOwnerOnlyDirectory(descriptor)
        } catch {
            _ = close(descriptor)
            throw error
        }
        return descriptor
    }

    static func openAccountDirectory(rootDescriptor: Int32, did: String) throws -> Int32 {
        let digest = Hex.encode(SHA256.hash(data: Data(did.utf8)))
        let actors = try openOrCreateDirectory(parent: rootDescriptor, name: "actors")
        do {
            let prefix = try openOrCreateDirectory(parent: actors, name: String(digest.prefix(2)))
            _ = close(actors)
            return prefix
        } catch {
            _ = close(actors)
            throw error
        }
    }

    static func openDatabaseFile(
        parentDescriptor: Int32,
        name: String,
        resolvedPath: String
    ) throws -> String {
        guard validDatabaseFilename(name) else {
            throw SwanError.unavailable("SQLite database path is unavailable")
        }
        let descriptor = name.withCString { path in
            openat(parentDescriptor, path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, ownerOnlyFileMode)
        }
        guard descriptor >= 0 else {
            throw SwanError.unavailable("SQLite database path is unavailable")
        }
        defer { _ = close(descriptor) }
        try requireOwnerOnlyRegularFile(descriptor)
        return resolvedPath
    }

    /// SQLite creates its WAL and shared-memory sidecars itself. They still
    /// live below a descriptor-anchored owner-only directory, but normalize
    /// their modes immediately after connection setup so the complete
    /// database family has the same owner-only contract as the main file.
    static func hardenSQLiteFiles(
        parentDescriptor: Int32,
        databaseName: String
    ) throws {
        guard validDatabaseFilename(databaseName) else {
            throw SwanError.unavailable("SQLite database path is unavailable")
        }
        for name in [databaseName, "\(databaseName)-wal", "\(databaseName)-shm"] {
            let descriptor = name.withCString { path in
                openat(parentDescriptor, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
            }
            if descriptor < 0 {
                guard errno == ENOENT else {
                    throw SwanError.unavailable("SQLite database path is unavailable")
                }
                continue
            }
            defer { _ = close(descriptor) }

            var metadata = stat()
            guard fstat(descriptor, &metadata) == 0,
                  (metadata.st_mode & S_IFMT) == S_IFREG,
                  metadata.st_uid == geteuid(),
                  fchmod(descriptor, ownerOnlyFileMode) == 0 else {
                throw SwanError.unavailable("SQLite database path is unavailable")
            }
        }
    }

    /// Allocates a single owner-only regular file below a dedicated private
    /// directory for permissioned CAR recovery spools. The generated name is
    /// not derived from a DID, space, record, or CID, and `O_EXCL|O_NOFOLLOW`
    /// prevents accidental reuse or symlink traversal. The caller owns
    /// deletion once the response completes or fails.
    static func makePrivateCARSpoolURL(in dataDirectory: URL) throws -> URL {
        let root = try openRoot(dataDirectory)
        defer { _ = close(root) }
        let spoolDirectory = try openOrCreateDirectory(
            parent: root,
            name: "permissioned-car-spool"
        )
        defer { _ = close(spoolDirectory) }

        for _ in 0 ..< 16 {
            let name = "car-\(UUID().uuidString.lowercased()).spool"
            let descriptor = name.withCString { path in
                openat(
                    spoolDirectory,
                    path,
                    O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    ownerOnlyFileMode
                )
            }
            if descriptor < 0 {
                guard errno == EEXIST else {
                    throw SwanError.unavailable("permissioned CAR spool is unavailable")
                }
                continue
            }
            do {
                try requireOwnerOnlyRegularFile(descriptor)
                guard fchmod(descriptor, ownerOnlyFileMode) == 0 else {
                    throw SwanError.unavailable("permissioned CAR spool is unavailable")
                }
                _ = close(descriptor)
                return dataDirectory.standardizedFileURL
                    .appending(path: "permissioned-car-spool")
                    .appending(path: name)
            } catch {
                _ = close(descriptor)
                _ = name.withCString { unlinkat(spoolDirectory, $0, 0) }
                throw error
            }
        }
        throw SwanError.unavailable("permissioned CAR spool is unavailable")
    }

    // MARK: Permissioned blob CAS

    /// Creates one immutable content-addressed payload below the already
    /// descriptor-validated account directory.  `digestHex` is never a path
    /// supplied by a client: callers derive it from a validated CID or a
    /// legacy SHA-256 migration record.  Existing entries are never
    /// overwritten; a later descriptor verification decides whether they are
    /// usable.
    @discardableResult
    static func createPrivateBlob(
        accountDirectoryDescriptor: Int32,
        accountNamespace: String,
        digestHex: String,
        payload: Data
    ) throws -> Bool {
        let (directory, filename) = try privateBlobLocation(
            accountDirectoryDescriptor: accountDirectoryDescriptor,
            accountNamespace: accountNamespace,
            digestHex: digestHex
        )
        defer { _ = close(directory) }

        let descriptor = filename.withCString { path in
            openat(
                directory,
                path,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                ownerOnlyFileMode
            )
        }
        if descriptor < 0 {
            guard errno == EEXIST else {
                throw SwanError.unavailable("permissioned blob storage is unavailable")
            }
            return false
        }

        do {
            try requireOwnerOnlyRegularFile(descriptor)
            try writeAll(payload, to: descriptor)
            guard fsync(descriptor) == 0,
                  fchmod(descriptor, ownerOnlyFileMode) == 0 else {
                throw SwanError.unavailable("permissioned blob storage is unavailable")
            }
            _ = close(descriptor)
            return true
        } catch {
            _ = close(descriptor)
            _ = filename.withCString { unlinkat(directory, $0, 0) }
            throw error
        }
    }

    /// Opens an immutable blob through the same directory descriptors used to
    /// create it.  The returned FD is still at an arbitrary offset only if a
    /// caller changes it; its owner must validate contents and seek before
    /// streaming.  No filesystem path leaves this API.
    static func openPrivateBlob(
        accountDirectoryDescriptor: Int32,
        accountNamespace: String,
        digestHex: String
    ) throws -> Int32 {
        let (directory, filename) = try privateBlobLocation(
            accountDirectoryDescriptor: accountDirectoryDescriptor,
            accountNamespace: accountNamespace,
            digestHex: digestHex
        )
        defer { _ = close(directory) }
        let descriptor = filename.withCString { path in
            openat(directory, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw SwanError.unavailable("permissioned blob storage is unavailable")
        }
        do {
            try requireOwnerOnlyRegularFile(descriptor)
            return descriptor
        } catch {
            _ = close(descriptor)
            throw error
        }
    }

    /// Unlinks only the deterministic regular-file entry under the private
    /// CAS directory.  Callers invoke this while their SQLite transaction has
    /// proved that no public or space namespace still reaches the digest.
    static func removePrivateBlob(
        accountDirectoryDescriptor: Int32,
        accountNamespace: String,
        digestHex: String
    ) throws {
        let (directory, filename) = try privateBlobLocation(
            accountDirectoryDescriptor: accountDirectoryDescriptor,
            accountNamespace: accountNamespace,
            digestHex: digestHex
        )
        defer { _ = close(directory) }
        let descriptor = filename.withCString { path in
            openat(directory, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        if descriptor < 0 {
            guard errno == ENOENT else {
                throw SwanError.unavailable("permissioned blob storage is unavailable")
            }
            return
        }
        defer { _ = close(descriptor) }
        try requireOwnerOnlyRegularFile(descriptor)
        guard filename.withCString({ unlinkat(directory, $0, 0) }) == 0 else {
            throw SwanError.unavailable("permissioned blob storage is unavailable")
        }
    }

    /// Acquires a process-wide advisory lock for one private CAS digest.  The
    /// in-process coordinator in `SQLiteAccountDatabase` covers Swift actors
    /// in the same process; this descriptor-backed lock extends that ordering
    /// to another Swan process sharing the account database.  The lock file is
    /// deliberately retained after a blob is reclaimed: deleting a lock file
    /// would reintroduce a name-replacement race at the precise boundary this
    /// API protects.
    static func openPrivateBlobLifecycleLock(
        accountDirectoryDescriptor: Int32,
        accountNamespace: String,
        digestHex: String
    ) throws -> Int32 {
        let (directory, filename) = try privateBlobLocation(
            accountDirectoryDescriptor: accountDirectoryDescriptor,
            accountNamespace: accountNamespace,
            digestHex: digestHex
        )
        defer { _ = close(directory) }
        let lockName = "\(filename).lock"
        let descriptor = lockName.withCString { path in
            openat(
                directory,
                path,
                O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
                ownerOnlyFileMode
            )
        }
        guard descriptor >= 0 else {
            throw SwanError.unavailable("permissioned blob storage is unavailable")
        }
        do {
            var metadata = stat()
            guard fchmod(descriptor, ownerOnlyFileMode) == 0,
                  fstat(descriptor, &metadata) == 0,
                  (metadata.st_mode & S_IFMT) == S_IFREG,
                  metadata.st_uid == geteuid(),
                  metadata.st_nlink == 1,
                  (metadata.st_mode & 0o777) == ownerOnlyFileMode,
                  fsync(descriptor) == 0 else {
                throw SwanError.unavailable("permissioned blob storage is unavailable")
            }
            while flock(descriptor, LOCK_EX) != 0 {
                guard errno == EINTR else {
                    throw SwanError.unavailable("permissioned blob storage is unavailable")
                }
            }
            return descriptor
        } catch {
            _ = close(descriptor)
            throw error
        }
    }

    static func closePrivateBlobLifecycleLock(_ descriptor: Int32) {
        guard descriptor >= 0 else { return }
        while flock(descriptor, LOCK_UN) != 0, errno == EINTR {}
        _ = close(descriptor)
    }

    static func closeDirectory(_ descriptor: Int32) {
        guard descriptor >= 0 else { return }
        _ = close(descriptor)
    }

    private static func openExistingDirectory(path: String) throws -> Int32 {
        let descriptor = path.withCString { path in
            open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw SwanError.unavailable("SQLite data directory is unavailable")
        }
        return descriptor
    }

    private static func openOrCreateDirectory(parent: Int32, name: String) throws -> Int32 {
        guard validDirectoryComponent(name) else {
            throw SwanError.unavailable("SQLite data directory is unavailable")
        }
        let created = name.withCString { path in
            mkdirat(parent, path, ownerOnlyDirectoryMode)
        }
        if created != 0, errno != EEXIST {
            throw SwanError.unavailable("SQLite data directory is unavailable")
        }
        let descriptor = name.withCString { path in
            openat(parent, path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw SwanError.unavailable("SQLite data directory is unavailable")
        }
        do {
            try requireOwnerOnlyDirectory(descriptor)
            return descriptor
        } catch {
            _ = close(descriptor)
            throw error
        }
    }

    private static func requireOwnerOnlyDirectory(_ descriptor: Int32) throws {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFDIR,
              metadata.st_uid == geteuid(),
              (metadata.st_mode & 0o777) == ownerOnlyDirectoryMode else {
            throw SwanError.unavailable("SQLite data directory is unavailable")
        }
    }

    private static func requireOwnerOnlyRegularFile(_ descriptor: Int32) throws {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(),
              (metadata.st_mode & 0o777) == ownerOnlyFileMode else {
            throw SwanError.unavailable("SQLite database path is unavailable")
        }
    }

    private static func privateBlobLocation(
        accountDirectoryDescriptor: Int32,
        accountNamespace: String,
        digestHex: String
    ) throws -> (directory: Int32, filename: String) {
        guard validBlobDigest(accountNamespace), validBlobDigest(digestHex) else {
            throw SwanError.unavailable("permissioned blob storage is unavailable")
        }
        let root = try openOrCreateDirectory(
            parent: accountDirectoryDescriptor,
            name: "permissioned-blob-cas"
        )
        do {
            let account = try openOrCreateDirectory(
                parent: root,
                name: accountNamespace
            )
            do {
                let shard = try openOrCreateDirectory(
                    parent: account,
                    name: String(digestHex.prefix(2))
                )
                _ = close(account)
                _ = close(root)
                return (shard, "\(digestHex).blob")
            } catch {
                _ = close(account)
                throw error
            }
        } catch {
            _ = close(root)
            throw error
        }
    }

    private static func writeAll(_ payload: Data, to descriptor: Int32) throws {
        var offset = 0
        while offset < payload.count {
            let wrote: Int
            do {
                wrote = try payload.withUnsafeBytes { bytes in
                    guard let base = bytes.baseAddress else { return 0 }
                    let result = write(
                        descriptor,
                        base.advanced(by: offset),
                        payload.count - offset
                    )
                    guard result >= 0 else {
                        throw SwanError.unavailable("permissioned blob storage is unavailable")
                    }
                    return result
                }
            } catch {
                throw error
            }
            guard wrote > 0 else {
                throw SwanError.unavailable("permissioned blob storage is unavailable")
            }
            offset += wrote
        }
    }

    private static func validDirectoryComponent(_ value: String) -> Bool {
        !value.isEmpty && !value.contains("/") && value != "." && value != ".."
    }

    private static func validDatabaseFilename(_ value: String) -> Bool {
        value == "control.sqlite" || (value.hasSuffix(".sqlite") && !value.contains("/"))
    }

    private static func validBlobDigest(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy {
            ($0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9"))
                || ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "f"))
        }
    }
}
