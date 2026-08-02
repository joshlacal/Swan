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
    private static let accountLifecycleLockFilenamePrefix =
        ".swan-account-lifecycle-"
    private static let accountDeletionInventoryBatchLimit = 256

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

    static func openExistingRoot(_ url: URL) throws -> Int32 {
        let descriptor = try openExistingDirectory(path: url.standardizedFileURL.path)
        do {
            try requireOwnerOnlyDirectory(descriptor)
            return descriptor
        } catch {
            _ = close(descriptor)
            throw error
        }
    }

    static func duplicateOwnerOnlyDirectory(_ descriptor: Int32) throws -> Int32 {
        let duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard duplicate >= 0 else {
            throw SwanError.unavailable("SQLite directory descriptor is unavailable")
        }
        do {
            try requireOwnerOnlyDirectory(duplicate)
            return duplicate
        } catch {
            _ = close(duplicate)
            throw error
        }
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

    static func openExistingAccountDirectory(
        rootDescriptor: Int32,
        did: String
    ) throws -> Int32 {
        let digest = Hex.encode(SHA256.hash(data: Data(did.utf8)))
        let actors = try openExistingDirectory(parent: rootDescriptor, name: "actors")
        do {
            let prefix = try openExistingDirectory(
                parent: actors,
                name: String(digest.prefix(2))
            )
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

    static func openExistingDatabaseFile(
        parentDescriptor: Int32,
        name: String,
        resolvedPath: String
    ) throws -> String {
        guard validDatabaseFilename(name) else {
            throw SwanError.unavailable("SQLite database path is unavailable")
        }
        let descriptor = name.withCString { path in
            openat(parentDescriptor, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw SwanError.unavailable("SQLite database path is unavailable")
        }
        defer { _ = close(descriptor) }
        try requireOwnerOnlyRegularFile(descriptor)
        return resolvedPath
    }

    /// Opens the database inode through its pinned parent and returns a held
    /// descriptor. Restore staging connects through the platform's exact-file
    /// descriptor alias, so renaming the unpublished root cannot redirect the
    /// main database open.
    static func openDatabaseFileDescriptor(
        parentDescriptor: Int32,
        name: String,
        create: Bool
    ) throws -> Int32 {
        guard validDatabaseFilename(name) else {
            throw SwanError.unavailable("SQLite database path is unavailable")
        }
        let flags = create
            ? O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW
            : O_RDONLY | O_CLOEXEC | O_NOFOLLOW
        let descriptor = name.withCString {
            openat(parentDescriptor, $0, flags, ownerOnlyFileMode)
        }
        guard descriptor >= 0 else {
            throw SwanError.unavailable("SQLite database path is unavailable")
        }
        do {
            try requireOwnerOnlyRegularFile(descriptor)
            return descriptor
        } catch {
            _ = close(descriptor)
            throw error
        }
    }

    static func databasePath(for descriptor: Int32) throws -> String {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1 else {
            throw SwanError.unavailable("SQLite database descriptor is unavailable")
        }
        #if canImport(Darwin)
        return "/dev/fd/\(descriptor)"
        #else
        return "/proc/self/fd/\(descriptor)"
        #endif
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

    /// Creates an owner-only anonymous regular file for public repository CAR
    /// streaming. The directory entry is removed before the descriptor leaves
    /// this function, so later path replacement or symlink attacks cannot
    /// affect the bytes drained by HTTP.
    static func makeUnlinkedPublicCARSpool(
        in dataDirectory: URL
    ) throws -> FileHandle {
        let root = try openRoot(dataDirectory)
        defer { _ = close(root) }
        let spoolDirectory = try openOrCreateDirectory(
            parent: root,
            name: "public-car-spool"
        )
        defer { _ = close(spoolDirectory) }

        for _ in 0..<16 {
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
                    throw SwanError.unavailable("public CAR spool is unavailable")
                }
                continue
            }
            do {
                try requireOwnerOnlyRegularFile(descriptor)
                guard fchmod(descriptor, ownerOnlyFileMode) == 0,
                      name.withCString({
                          unlinkat(spoolDirectory, $0, 0)
                      }) == 0 else {
                    throw SwanError.unavailable("public CAR spool is unavailable")
                }
                return FileHandle(
                    fileDescriptor: descriptor,
                    closeOnDealloc: true
                )
            } catch {
                _ = close(descriptor)
                _ = name.withCString { unlinkat(spoolDirectory, $0, 0) }
                throw error
            }
        }
        throw SwanError.unavailable("public CAR spool is unavailable")
    }

    /// Creates an owner-only anonymous regular file for a permissioned
    /// recovery CAR. Keeping only the open descriptor prevents path
    /// replacement and makes process crashes reclaim in-flight private data
    /// automatically.
    static func makeUnlinkedPermissionedCARSpool(
        in dataDirectory: URL
    ) throws -> FileHandle {
        let root = try openRoot(dataDirectory)
        defer { _ = close(root) }
        let spoolDirectory = try openOrCreateDirectory(
            parent: root,
            name: "permissioned-car-spool"
        )
        defer { _ = close(spoolDirectory) }

        for _ in 0..<16 {
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
                    throw SwanError.unavailable(
                        "permissioned CAR spool is unavailable"
                    )
                }
                continue
            }
            do {
                try requireOwnerOnlyRegularFile(descriptor)
                guard fchmod(descriptor, ownerOnlyFileMode) == 0,
                      name.withCString({
                          unlinkat(spoolDirectory, $0, 0)
                      }) == 0
                else {
                    throw SwanError.unavailable(
                        "permissioned CAR spool is unavailable"
                    )
                }
                return FileHandle(
                    fileDescriptor: descriptor,
                    closeOnDealloc: true
                )
            } catch {
                _ = close(descriptor)
                _ = name.withCString { unlinkat(spoolDirectory, $0, 0) }
                throw error
            }
        }
        throw SwanError.unavailable(
            "permissioned CAR spool is unavailable"
        )
    }

    /// Creates an owner-only anonymous staging file for a public blob upload.
    /// The file is unlinked before its descriptor leaves this function, so a
    /// request body can never be reached through a pathname or confused with
    /// a public CAS reference before its digest has been verified.
    static func makeUnlinkedPublicBlobSpool(
        in dataDirectory: URL
    ) throws -> FileHandle {
        let root = try openRoot(dataDirectory)
        defer { _ = close(root) }
        let spoolDirectory = try openOrCreateDirectory(
            parent: root,
            name: "public-blob-spool"
        )
        defer { _ = close(spoolDirectory) }

        for _ in 0 ..< 16 {
            let name = "blob-\(UUID().uuidString.lowercased()).spool"
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
                    throw SwanError.unavailable("public blob staging is unavailable")
                }
                continue
            }
            do {
                try requireOwnerOnlyRegularFile(descriptor)
                guard fchmod(descriptor, ownerOnlyFileMode) == 0,
                      name.withCString({ unlinkat(spoolDirectory, $0, 0) }) == 0
                else {
                    throw SwanError.unavailable("public blob staging is unavailable")
                }
                return FileHandle(
                    fileDescriptor: descriptor,
                    closeOnDealloc: true
                )
            } catch {
                _ = close(descriptor)
                _ = name.withCString { unlinkat(spoolDirectory, $0, 0) }
                throw error
            }
        }
        throw SwanError.unavailable("public blob staging is unavailable")
    }

    /// Descriptor-backed restore cannot rely on its display URL. Stage the
    /// anonymous blob directly below the already-pinned account directory and
    /// unlink it before returning.
    static func makeUnlinkedPortableRestoreBlobSpool(
        accountDirectoryDescriptor: Int32
    ) throws -> FileHandle {
        for _ in 0 ..< 16 {
            let name = ".restore-blob-\(UUID().uuidString.lowercased()).spool"
            let descriptor = name.withCString { path in
                openat(
                    accountDirectoryDescriptor,
                    path,
                    O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    ownerOnlyFileMode
                )
            }
            if descriptor < 0 {
                guard errno == EEXIST else {
                    throw SwanError.unavailable("portable blob staging is unavailable")
                }
                continue
            }
            do {
                try requireOwnerOnlyRegularFile(descriptor)
                guard fchmod(descriptor, ownerOnlyFileMode) == 0,
                      name.withCString({
                          unlinkat(accountDirectoryDescriptor, $0, 0)
                      }) == 0 else {
                    throw SwanError.unavailable(
                        "portable blob staging is unavailable"
                    )
                }
                return FileHandle(
                    fileDescriptor: descriptor,
                    closeOnDealloc: true
                )
            } catch {
                _ = close(descriptor)
                _ = name.withCString {
                    unlinkat(accountDirectoryDescriptor, $0, 0)
                }
                throw error
            }
        }
        throw SwanError.unavailable("portable blob staging is unavailable")
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

    /// Copies a verified anonymous upload spool into its content-addressed
    /// CAS entry without materializing the payload. The source descriptor is
    /// never reopened by path, and the copy re-hashes the bytes as it writes
    /// them so an unexpected in-process mutation cannot publish a wrong CID.
    @discardableResult
    static func createPrivateBlobFromFile(
        accountDirectoryDescriptor: Int32,
        accountNamespace: String,
        digestHex: String,
        sourceDescriptor: Int32,
        expectedLength: Int,
        expectedDigest: Data
    ) throws -> Bool {
        guard expectedLength >= 0, expectedDigest.count == 32 else {
            throw SwanError.unavailable("permissioned blob storage is unavailable")
        }
        var sourceMetadata = stat()
        guard fstat(sourceDescriptor, &sourceMetadata) == 0,
              (sourceMetadata.st_mode & S_IFMT) == S_IFREG,
              sourceMetadata.st_uid == geteuid(),
              (sourceMetadata.st_mode & 0o777) == ownerOnlyFileMode,
              sourceMetadata.st_size >= 0,
              sourceMetadata.st_size <= off_t(Int.max),
              Int(sourceMetadata.st_size) == expectedLength,
              lseek(sourceDescriptor, 0, SEEK_SET) == 0 else {
            throw SwanError.unavailable("permissioned blob storage is unavailable")
        }

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
            var digest = SHA256()
            var copied = 0
            var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
            while copied < expectedLength {
                let requested = min(buffer.count, expectedLength - copied)
                let readCount = buffer.withUnsafeMutableBytes { bytes -> Int in
                    guard let base = bytes.baseAddress else { return -1 }
                    return read(sourceDescriptor, base, requested)
                }
                guard readCount > 0 else {
                    throw SwanError.unavailable("permissioned blob storage is unavailable")
                }
                let chunk = Data(buffer[0 ..< readCount])
                digest.update(data: chunk)
                try writeAll(chunk, to: descriptor)
                copied += readCount
            }
            guard copied == expectedLength,
                  Data(digest.finalize()) == expectedDigest,
                  fsync(descriptor) == 0,
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

    /// Every managed account database holds a shared lease for its entire
    /// lifetime. Permanent deletion must first remove the database from live
    /// routing, close it, and then acquire the exclusive form. A second Swan
    /// process therefore makes deletion fail closed rather than unlinking a
    /// database it can still serve.
    static func openAccountLifecycleLock(
        accountDirectoryDescriptor: Int32,
        did: String,
        exclusive: Bool
    ) throws -> Int32 {
        let accountDigest = Hex.encode(
            SHA256.hash(data: Data(did.utf8))
        )
        guard validBlobDigest(accountDigest) else {
            throw SwanError.unavailable(
                "account lifecycle lease is unavailable"
            )
        }
        let lockFilename =
            "\(accountLifecycleLockFilenamePrefix)\(accountDigest).lock"
        let descriptor = lockFilename.withCString { path in
            openat(
                accountDirectoryDescriptor,
                path,
                O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
                ownerOnlyFileMode
            )
        }
        guard descriptor >= 0 else {
            throw SwanError.unavailable(
                "account lifecycle lease is unavailable"
            )
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
                throw SwanError.unavailable(
                    "account lifecycle lease is unavailable"
                )
            }
            let operation = (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB
            while flock(descriptor, operation) != 0 {
                guard errno == EINTR else {
                    throw SwanError.unavailable(
                        "account lifecycle lease is unavailable"
                    )
                }
            }
            return descriptor
        } catch {
            _ = close(descriptor)
            throw error
        }
    }

    static func closeAccountLifecycleLock(_ descriptor: Int32) {
        guard descriptor >= 0 else { return }
        while flock(descriptor, LOCK_UN) != 0, errno == EINTR {}
        _ = close(descriptor)
    }

    /// Removes only the exact DID-derived database family and private/public
    /// CAS namespace below a held, descriptor-validated account shard. The
    /// lifecycle lock entry is deliberately retained so its inode can never
    /// be replaced while another process still holds an older lease.
    static func destroyAccountData(
        accountDirectoryDescriptor: Int32,
        did: String
    ) throws {
        let accountDigest = Hex.encode(
            SHA256.hash(data: Data(did.utf8))
        )
        guard validBlobDigest(accountDigest) else {
            throw SwanError.unavailable(
                "account data deletion target is unavailable"
            )
        }

        // CAS comes first. An unexpected symlink or object type therefore
        // leaves the authoritative SQLite database intact and the durable
        // deletion stage retryable.
        try destroyAccountCASNamespace(
            accountDirectoryDescriptor: accountDirectoryDescriptor,
            accountDigest: accountDigest
        )

        let databaseName = "\(accountDigest).sqlite"
        for name in [
            databaseName,
            "\(databaseName)-wal",
            "\(databaseName)-shm",
        ] {
            let descriptor = name.withCString {
                openat(
                    accountDirectoryDescriptor,
                    $0,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW
                )
            }
            if descriptor < 0 {
                guard errno == ENOENT else {
                    throw SwanError.unavailable(
                        "account data deletion target is unavailable"
                    )
                }
                continue
            }
            defer { _ = close(descriptor) }
            do {
                var metadata = stat()
                guard fstat(descriptor, &metadata) == 0,
                      (metadata.st_mode & S_IFMT) == S_IFREG,
                      metadata.st_uid == geteuid(),
                      metadata.st_nlink == 1,
                      (metadata.st_mode & 0o777) == ownerOnlyFileMode else {
                    throw SwanError.unavailable(
                        "account data deletion target is unavailable"
                    )
                }
                guard name.withCString({
                    unlinkat(accountDirectoryDescriptor, $0, 0)
                }) == 0 else {
                    throw SwanError.unavailable(
                        "account data deletion target is unavailable"
                    )
                }
            } catch {
                throw error
            }
        }
        guard fsync(accountDirectoryDescriptor) == 0 else {
            throw SwanError.unavailable(
                "account data deletion could not be synchronized"
            )
        }
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

    private static func openExistingDirectory(
        parent: Int32,
        name: String
    ) throws -> Int32 {
        guard validDirectoryComponent(name) else {
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

    private static func destroyAccountCASNamespace(
        accountDirectoryDescriptor: Int32,
        accountDigest: String
    ) throws {
        let casRootName = "permissioned-blob-cas"
        let casRoot = casRootName.withCString {
            openat(
                accountDirectoryDescriptor,
                $0,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
            )
        }
        if casRoot < 0 {
            guard errno == ENOENT else {
                throw SwanError.unavailable(
                    "account CAS deletion target is unavailable"
                )
            }
            return
        }
        defer { _ = close(casRoot) }
        try requireOwnerOnlyDirectory(casRoot)

        let account = accountDigest.withCString {
            openat(
                casRoot,
                $0,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
            )
        }
        if account < 0 {
            guard errno == ENOENT else {
                throw SwanError.unavailable(
                    "account CAS deletion target is unavailable"
                )
            }
            return
        }
        defer { _ = close(account) }
        try requireOwnerOnlyDirectory(account)

        while true {
            let shardBatch = try directoryEntryNameBatch(
                account,
                limit: accountDeletionInventoryBatchLimit
            )
            guard !shardBatch.isEmpty else { break }
            for shardName in shardBatch {
                guard shardName.utf8.count == 2,
                      shardName.utf8.allSatisfy(isLowercaseHex) else {
                    throw SwanError.unavailable(
                        "account CAS deletion target is unavailable"
                    )
                }
                let shard = shardName.withCString {
                    openat(
                        account,
                        $0,
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
                    )
                }
                guard shard >= 0 else {
                    throw SwanError.unavailable(
                        "account CAS deletion target is unavailable"
                    )
                }
                do {
                    defer { _ = close(shard) }
                    try requireOwnerOnlyDirectory(shard)
                    while true {
                        let filenameBatch = try directoryEntryNameBatch(
                            shard,
                            limit: accountDeletionInventoryBatchLimit
                        )
                        guard !filenameBatch.isEmpty else { break }
                        for filename in filenameBatch {
                            guard validCASFilename(filename) else {
                                throw SwanError.unavailable(
                                    "account CAS deletion target is unavailable"
                                )
                            }
                            let descriptor = filename.withCString {
                                openat(
                                    shard,
                                    $0,
                                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW
                                )
                            }
                            guard descriptor >= 0 else {
                                throw SwanError.unavailable(
                                    "account CAS deletion target is unavailable"
                                )
                            }
                            var metadata = stat()
                            guard fstat(descriptor, &metadata) == 0,
                                  (metadata.st_mode & S_IFMT) == S_IFREG,
                                  metadata.st_uid == geteuid(),
                                  metadata.st_nlink == 1,
                                  (metadata.st_mode & 0o777)
                                    == ownerOnlyFileMode else {
                                _ = close(descriptor)
                                throw SwanError.unavailable(
                                    "account CAS deletion target is unavailable"
                                )
                            }
                            _ = close(descriptor)
                            guard filename.withCString({
                                unlinkat(shard, $0, 0)
                            }) == 0 else {
                                throw SwanError.unavailable(
                                    "account CAS deletion target is unavailable"
                                )
                            }
                        }
                    }
                    guard fsync(shard) == 0 else {
                        throw SwanError.unavailable(
                            "account CAS deletion could not be synchronized"
                        )
                    }
                    guard shardName.withCString({
                        unlinkat(account, $0, AT_REMOVEDIR)
                    }) == 0 else {
                        throw SwanError.unavailable(
                            "account CAS deletion target is unavailable"
                        )
                    }
                } catch {
                    throw error
                }
            }
        }
        guard fsync(account) == 0,
              accountDigest.withCString({
                  unlinkat(casRoot, $0, AT_REMOVEDIR)
              }) == 0,
              fsync(casRoot) == 0 else {
            throw SwanError.unavailable(
                "account CAS deletion could not be synchronized"
            )
        }
    }

    /// Inventories at most one bounded page. Deletion restarts the descriptor
    /// iterator after unlinking that page, so memory is independent of the
    /// total number of blobs and partial progress remains crash-retryable.
    private static func directoryEntryNameBatch(
        _ descriptor: Int32,
        limit: Int
    ) throws -> [String] {
        guard limit > 0 else {
            throw SwanError.unavailable(
                "account deletion inventory is unavailable"
            )
        }
        let inventoryDescriptor = openat(
            descriptor,
            ".",
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard inventoryDescriptor >= 0,
              let directory = fdopendir(inventoryDescriptor) else {
            if inventoryDescriptor >= 0 {
                _ = close(inventoryDescriptor)
            }
            throw SwanError.unavailable(
                "account deletion inventory is unavailable"
            )
        }
        defer { _ = closedir(directory) }
        var names: [String] = []
        names.reserveCapacity(limit)
        while names.count < limit {
            errno = 0
            guard let entry = readdir(directory) else {
                guard errno == 0 else {
                    throw SwanError.unavailable(
                        "account deletion inventory is unavailable"
                    )
                }
                break
            }
            var storage = entry.pointee.d_name
            let capacity = MemoryLayout.size(ofValue: storage)
            let name = withUnsafePointer(to: &storage) {
                $0.withMemoryRebound(
                    to: CChar.self,
                    capacity: capacity
                ) {
                    String(cString: $0)
                }
            }
            if name != ".", name != ".." {
                guard validDirectoryComponent(name),
                      name.utf8.count <= 255 else {
                    throw SwanError.unavailable(
                        "account deletion inventory is unavailable"
                    )
                }
                names.append(name)
            }
        }
        return names
    }

    private static func validCASFilename(_ value: String) -> Bool {
        let digest: Substring
        if value.hasSuffix(".blob.lock") {
            digest = value.dropLast(".blob.lock".count)
        } else if value.hasSuffix(".blob") {
            digest = value.dropLast(".blob".count)
        } else {
            return false
        }
        return digest.utf8.count == 64
            && digest.utf8.allSatisfy(isLowercaseHex)
    }

    private static func isLowercaseHex(_ byte: UInt8) -> Bool {
        (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
            || (byte >= UInt8(ascii: "a")
                && byte <= UInt8(ascii: "f"))
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
