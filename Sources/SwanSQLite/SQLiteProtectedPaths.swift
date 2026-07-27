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

    private static func validDirectoryComponent(_ value: String) -> Bool {
        !value.isEmpty && !value.contains("/") && value != "." && value != ".."
    }

    private static func validDatabaseFilename(_ value: String) -> Bool {
        value == "control.sqlite" || (value.hasSuffix(".sqlite") && !value.contains("/"))
    }
}
