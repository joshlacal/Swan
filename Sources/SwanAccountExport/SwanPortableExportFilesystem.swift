import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc

// Glibc's Swift overlay does not currently declare renameat2 even though the
// symbol is exported by the Linux libc used by the Swift 6.1/Jammy image.
// Keep the declaration local and retain RENAME_NOREPLACE so publication never
// overwrites a pre-existing export target.
@_silgen_name("renameat2")
private func swanRenameAt2(
    _ oldDirectory: Int32,
    _ oldPath: UnsafePointer<CChar>,
    _ newDirectory: Int32,
    _ newPath: UnsafePointer<CChar>,
    _ flags: UInt32
) -> Int32

private let swanRenameNoReplace: UInt32 = 1
#endif

/// A preflighted archive destination whose parent directory remains anchored
/// by descriptor until publication completes.
public final class SwanPortableExportDestination: @unchecked Sendable {
    public let url: URL

    let parentDescriptor: Int32
    let outputName: String
    private let parentURL: URL
    private let parentDevice: dev_t
    private let parentInode: ino_t

    public init(_ outputURL: URL) throws {
        let output = outputURL.standardizedFileURL
        let name = output.lastPathComponent
        guard output.path != "/",
              SwanPortableExportFilesystem.isSafeComponent(name),
              name != SwanPortableExportFilesystem.cleanupQuarantineName else {
            throw SwanPortableExportError.invalidPlacement
        }
        let parent = output.deletingLastPathComponent()
        let descriptor = parent.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw SwanPortableExportError.invalidPlacement
        }
        var metadata = stat()
        do {
            guard fstat(descriptor, &metadata) == 0,
                  (metadata.st_mode & S_IFMT) == S_IFDIR,
                  metadata.st_uid == geteuid(),
                  (metadata.st_mode & 0o077) == 0 else {
                throw SwanPortableExportError.invalidPlacement
            }
            try Self.requireAbsent(name, in: descriptor)
        } catch {
            _ = close(descriptor)
            throw error
        }
        url = output
        outputName = name
        parentURL = parent
        parentDescriptor = descriptor
        parentDevice = metadata.st_dev
        parentInode = metadata.st_ino
    }

    deinit {
        _ = close(parentDescriptor)
    }

    func requireCurrentParentAndAbsentTarget() throws {
        let descriptor = try reopenCurrentParent()
        _ = close(descriptor)
        try Self.requireAbsent(outputName, in: parentDescriptor)
    }

    func requireCurrentParentAndInstalledTarget() throws {
        let descriptor = try reopenCurrentParent()
        _ = close(descriptor)
        var metadata = stat()
        guard outputName.withCString({
            fstatat(parentDescriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW)
        }) == 0,
        (metadata.st_mode & S_IFMT) == S_IFDIR,
        metadata.st_uid == geteuid(),
        (metadata.st_mode & 0o777) == 0o700 else {
            throw SwanPortableExportError.publicationFailed
        }
    }

    private func reopenCurrentParent() throws -> Int32 {
        let descriptor = parentURL.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw SwanPortableExportError.publicationFailed
        }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_dev == parentDevice,
              metadata.st_ino == parentInode,
              metadata.st_uid == geteuid(),
              (metadata.st_mode & S_IFMT) == S_IFDIR,
              (metadata.st_mode & 0o077) == 0 else {
            _ = close(descriptor)
            throw SwanPortableExportError.publicationFailed
        }
        return descriptor
    }

    private static func requireAbsent(_ name: String, in parent: Int32) throws {
        var metadata = stat()
        if name.withCString({
            fstatat(parent, $0, &metadata, AT_SYMLINK_NOFOLLOW)
        }) == 0 {
            throw SwanPortableExportError.invalidPlacement
        }
        guard errno == ENOENT else {
            throw SwanPortableExportError.invalidPlacement
        }
    }
}

struct SwanPortableExportPublicationFile: Sendable {
    let path: String
    let data: Data
}

enum SwanPortableExportFilesystem {
    /// Online cleanup cannot portably unlink an open inode atomically on both
    /// Darwin and Linux. A scrubbed tree is therefore moved into this single
    /// reserved slot and retained for quiesced operator recovery.
    static let cleanupQuarantineName = ".swan-cleanup-quarantine"
    static let cleanupQuarantinedTreeName = "tree"
    static let maximumArtifactBytes = 512 * 1_024 * 1_024
    static let maximumArchiveBytes = 1_024 * 1_024 * 1_024

    struct Entries {
        var files = Set<String>()
        var directories = Set<String>()
    }

    static func openArchiveRoot(_ url: URL) throws -> Int32 {
        let descriptor = url.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw SwanPortableExportError.invalidPlacement
        }
        do {
            try requireOwnerOnlyDirectory(descriptor)
            return descriptor
        } catch {
            _ = close(descriptor)
            throw error
        }
    }

    static func openExistingOwnerOnlyDirectory(_ url: URL) throws -> Int32 {
        try openArchiveRoot(url)
    }

    static func requireCurrentOwnerOnlyDirectory(
        _ url: URL,
        matches expectedDescriptor: Int32
    ) throws {
        let currentDescriptor = try openExistingOwnerOnlyDirectory(url)
        defer { _ = close(currentDescriptor) }
        var expected = stat()
        var current = stat()
        guard fstat(expectedDescriptor, &expected) == 0,
              fstat(currentDescriptor, &current) == 0,
              expected.st_dev == current.st_dev,
              expected.st_ino == current.st_ino else {
            throw SwanPortableExportError.publicationFailed
        }
    }

    /// Rejects a destination parent that is the verified source directory or
    /// one of its descendants. The target itself is required absent, so this
    /// is the only possible source/target ancestry after collision checks.
    static func requireNotWithin(
        directory: Int32,
        ancestor: Int32
    ) throws {
        var ancestorMetadata = stat()
        guard fstat(ancestor, &ancestorMetadata) == 0 else {
            throw SwanPortableExportError.invalidPlacement
        }
        var current = openat(
            directory,
            ".",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        guard current >= 0 else {
            throw SwanPortableExportError.invalidPlacement
        }
        defer { _ = close(current) }

        for _ in 0 ..< 1_024 {
            var currentMetadata = stat()
            guard fstat(current, &currentMetadata) == 0 else {
                throw SwanPortableExportError.invalidPlacement
            }
            guard currentMetadata.st_dev != ancestorMetadata.st_dev
                    || currentMetadata.st_ino != ancestorMetadata.st_ino else {
                throw SwanPortableExportError.invalidPlacement
            }
            let parent = openat(
                current,
                "..",
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
            )
            guard parent >= 0 else {
                throw SwanPortableExportError.invalidPlacement
            }
            var parentMetadata = stat()
            guard fstat(parent, &parentMetadata) == 0 else {
                _ = close(parent)
                throw SwanPortableExportError.invalidPlacement
            }
            if currentMetadata.st_dev == parentMetadata.st_dev,
               currentMetadata.st_ino == parentMetadata.st_ino {
                _ = close(parent)
                return
            }
            _ = close(current)
            current = parent
        }
        throw SwanPortableExportError.invalidPlacement
    }

    static func openOwnerOnlyDirectory(parent: Int32, name: String) throws -> Int32 {
        try openDirectory(parent: parent, name: name)
    }

    static func requireCurrentChildDirectory(
        parent: Int32,
        name: String,
        matches expectedDescriptor: Int32
    ) throws {
        let currentDescriptor = try openDirectory(parent: parent, name: name)
        defer { _ = close(currentDescriptor) }
        var expected = stat()
        var current = stat()
        guard fstat(expectedDescriptor, &expected) == 0,
              fstat(currentDescriptor, &current) == 0,
              expected.st_dev == current.st_dev,
              expected.st_ino == current.st_ino else {
            throw SwanPortableExportError.publicationFailed
        }
    }

    static func currentChildDirectoryMatches(
        parent: Int32,
        name: String,
        expectedDescriptor: Int32
    ) throws -> Bool {
        guard isSafeComponent(name) else {
            throw SwanPortableExportError.invalidPlacement
        }
        var expected = stat()
        var current = stat()
        guard fstat(expectedDescriptor, &expected) == 0 else {
            throw SwanPortableExportError.publicationFailed
        }
        if name.withCString({
            fstatat(parent, $0, &current, AT_SYMLINK_NOFOLLOW)
        }) != 0 {
            guard errno == ENOENT else {
                throw SwanPortableExportError.publicationFailed
            }
            return false
        }
        return (current.st_mode & S_IFMT) == S_IFDIR
            && current.st_dev == expected.st_dev
            && current.st_ino == expected.st_ino
    }

    static func openOrCreateOwnerOnlyDirectory(
        parent: Int32,
        name: String
    ) throws -> (descriptor: Int32, created: Bool) {
        guard isSafeComponent(name) else {
            throw SwanPortableExportError.invalidPlacement
        }
        var metadata = stat()
        if name.withCString({
            fstatat(parent, $0, &metadata, AT_SYMLINK_NOFOLLOW)
        }) == 0 {
            return (try openDirectory(parent: parent, name: name), false)
        }
        guard errno == ENOENT else {
            throw SwanPortableExportError.invalidPlacement
        }
        if name.withCString({ mkdirat(parent, $0, 0o700) }) == 0 {
            return (try openDirectory(parent: parent, name: name), true)
        }
        guard errno == EEXIST else {
            throw SwanPortableExportError.publicationFailed
        }
        return (try openDirectory(parent: parent, name: name), false)
    }

    static func entryExists(parent: Int32, name: String) throws -> Bool {
        guard isSafeComponent(name) else {
            throw SwanPortableExportError.invalidPlacement
        }
        var metadata = stat()
        if name.withCString({
            fstatat(parent, $0, &metadata, AT_SYMLINK_NOFOLLOW)
        }) == 0 {
            return true
        }
        guard errno == ENOENT else {
            throw SwanPortableExportError.invalidPlacement
        }
        return false
    }

    static func createStagingDirectory(parent: Int32, name: String) throws -> Int32 {
        guard isSafeComponent(name),
              flock(parent, LOCK_EX | LOCK_NB) == 0,
              try !entryExists(parent: parent, name: cleanupQuarantineName),
              name.withCString({ mkdirat(parent, $0, 0o700) }) == 0 else {
            throw SwanPortableExportError.publicationFailed
        }
        // Do not unlink by name if opening fails: a same-UID actor could swap
        // the freshly created path before cleanup. An empty residue is safer
        // than deleting an unrelated replacement.
        return try openDirectory(parent: parent, name: name)
    }

    static func write(
        _ data: Data,
        path: String,
        root: Int32
    ) throws {
        try write(
            data,
            path: path,
            root: root,
            synchronizeCreatedDirectoryParent: synchronizeParent
        )
    }

    static func write(
        _ data: Data,
        path: String,
        root: Int32,
        synchronizeCreatedDirectoryParent: @Sendable (Int32) throws -> Void
    ) throws {
        let components = try pathComponents(path)
        var openedDirectories: [Int32] = []
        var createdDirectoryParents: [Int32] = []
        var current = root
        defer {
            for descriptor in openedDirectories.reversed() {
                _ = close(descriptor)
            }
        }
        for component in components.dropLast() {
            let created = component.withCString { mkdirat(current, $0, 0o700) }
            guard created == 0 || errno == EEXIST else {
                throw SwanPortableExportError.publicationFailed
            }
            let child = try openDirectory(parent: current, name: component)
            if created == 0 {
                createdDirectoryParents.append(current)
            }
            openedDirectories.append(child)
            current = child
        }
        let filename = components.last!
        let descriptor = filename.withCString {
            openat(
                current,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                0o600
            )
        }
        guard descriptor >= 0 else {
            throw SwanPortableExportError.publicationFailed
        }
        var shouldClose = true
        defer {
            if shouldClose { _ = close(descriptor) }
        }
        var metadata = stat()
        guard fchmod(descriptor, 0o600) == 0,
              fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              (metadata.st_mode & 0o777) == 0o600 else {
            throw SwanPortableExportError.publicationFailed
        }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = systemWrite(
                    descriptor,
                    bytes.baseAddress!.advanced(by: offset),
                    bytes.count - offset
                )
                if count < 0, errno == EINTR { continue }
                guard count > 0 else {
                    throw SwanPortableExportError.publicationFailed
                }
                offset += count
            }
        }
        guard fsync(descriptor) == 0, close(descriptor) == 0 else {
            throw SwanPortableExportError.publicationFailed
        }
        shouldClose = false
        guard fsync(current) == 0 else {
            throw SwanPortableExportError.publicationFailed
        }
        for descriptor in createdDirectoryParents.reversed() {
            try synchronizeCreatedDirectoryParent(descriptor)
        }
    }

    /// Opens a new owner-only regular file below `root` without exposing a
    /// pathname to the caller.  The returned writer is intentionally
    /// descriptor-backed so a portable export can copy arbitrarily large CAR
    /// and blob bodies in bounded chunks instead of first assembling `Data`.
    static func openStreamingWriter(
        path: String,
        root: Int32,
        synchronizeCreatedDirectoryParent:
            @escaping @Sendable (Int32) throws -> Void = {
                try SwanPortableExportFilesystem.synchronizeParent($0)
            }
    ) throws -> StreamingWriter {
        let components = try pathComponents(path)
        var openedDirectories: [Int32] = []
        var createdDirectoryParents: [Int32] = []
        var current = root
        do {
            for component in components.dropLast() {
                let created = component.withCString { mkdirat(current, $0, 0o700) }
                guard created == 0 || errno == EEXIST else {
                    throw SwanPortableExportError.publicationFailed
                }
                let child = try openDirectory(parent: current, name: component)
                if created == 0 { createdDirectoryParents.append(current) }
                openedDirectories.append(child)
                current = child
            }
            let filename = components.last!
            let descriptor = filename.withCString {
                openat(
                    current,
                    $0,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0o600
                )
            }
            guard descriptor >= 0 else {
                throw SwanPortableExportError.publicationFailed
            }
            var metadata = stat()
            guard fchmod(descriptor, 0o600) == 0,
                  fstat(descriptor, &metadata) == 0,
                  (metadata.st_mode & S_IFMT) == S_IFREG,
                  metadata.st_uid == geteuid(),
                  metadata.st_nlink == 1,
                  (metadata.st_mode & 0o777) == 0o600 else {
                _ = ftruncate(descriptor, 0)
                _ = fsync(descriptor)
                _ = close(descriptor)
                throw SwanPortableExportError.publicationFailed
            }
            return StreamingWriter(
                descriptor: descriptor,
                parentDescriptor: current,
                filename: filename,
                openedDirectories: openedDirectories,
                createdDirectoryParents: createdDirectoryParents,
                synchronizeCreatedDirectoryParent:
                    synchronizeCreatedDirectoryParent
            )
        } catch {
            for descriptor in openedDirectories.reversed() { _ = close(descriptor) }
            throw error
        }
    }

    /// Opens an existing owner-only regular file for bounded streaming reads.
    static func openStreamingReader(path: String, root: Int32) throws -> Int32 {
        let components = try pathComponents(path)
        var openedDirectories: [Int32] = []
        var current = root
        do {
            for component in components.dropLast() {
                let child = try openDirectory(parent: current, name: component)
                openedDirectories.append(child)
                current = child
            }
            let descriptor = components.last!.withCString {
                openat(current, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
            }
            guard descriptor >= 0 else {
                throw SwanPortableExportError.invalidArchive
            }
            var metadata = stat()
            guard fstat(descriptor, &metadata) == 0,
                  (metadata.st_mode & S_IFMT) == S_IFREG,
                  metadata.st_uid == geteuid(),
                  metadata.st_nlink == 1,
                  (metadata.st_mode & 0o777) == 0o600 else {
                _ = close(descriptor)
                throw SwanPortableExportError.invalidArchive
            }
            for directory in openedDirectories.reversed() { _ = close(directory) }
            return descriptor
        } catch {
            for descriptor in openedDirectories.reversed() { _ = close(descriptor) }
            throw error
        }
    }

    static func fileByteCount(
        path: String,
        root: Int32,
        maximumBytes: Int
    ) throws -> Int {
        guard maximumBytes >= 0 else {
            throw SwanPortableExportError.invalidArchive
        }
        let descriptor = try openStreamingReader(path: path, root: root)
        defer { _ = close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_size >= 0,
              metadata.st_size <= off_t(maximumBytes) else {
            throw SwanPortableExportError.invalidArchive
        }
        return Int(metadata.st_size)
    }

    /// Copies one descriptor-confined regular file with a fixed 64 KiB
    /// resident window. Source identity and length are rechecked after EOF;
    /// the destination writer removes a partial file on every failure.
    static func copyStreaming(
        path: String,
        sourceRoot: Int32,
        destinationRoot: Int32,
        expectedByteCount: Int,
        maximumBytes: Int,
        synchronizeCreatedDirectoryParent:
            @escaping @Sendable (Int32) throws -> Void = {
                try SwanPortableExportFilesystem.synchronizeParent($0)
            }
    ) throws {
        guard expectedByteCount >= 0,
              expectedByteCount <= maximumBytes else {
            throw SwanPortableExportError.invalidArchive
        }
        let source = try openStreamingReader(path: path, root: sourceRoot)
        defer { _ = close(source) }
        var initial = stat()
        guard fstat(source, &initial) == 0,
              initial.st_size == off_t(expectedByteCount) else {
            throw SwanPortableExportError.invalidArchive
        }
        let writer = try openStreamingWriter(
            path: path,
            root: destinationRoot,
            synchronizeCreatedDirectoryParent:
                synchronizeCreatedDirectoryParent
        )
        do {
            var remaining = expectedByteCount
            while remaining > 0 {
                try Task.checkCancellation()
                var chunk = Data(count: min(64 * 1_024, remaining))
                let count = try chunk.withUnsafeMutableBytes { bytes -> Int in
                    while true {
                        let result = systemRead(source, bytes.baseAddress!, bytes.count)
                        if result < 0, errno == EINTR { continue }
                        guard result > 0 else {
                            throw SwanPortableExportError.invalidArchive
                        }
                        return result
                    }
                }
                chunk.count = count
                try writer.write(chunk)
                remaining -= count
            }
            var extra: UInt8 = 0
            let extraCount = withUnsafeMutablePointer(to: &extra) {
                systemRead(source, $0, 1)
            }
            var final = stat()
            guard extraCount == 0,
                  fstat(source, &final) == 0,
                  stableRegularFile(initial: initial, final: final) else {
                throw SwanPortableExportError.invalidArchive
            }
            try writer.finish()
        } catch {
            writer.abort()
            throw error
        }
    }

    /// A descriptor-backed export file.  It owns the descriptor and removes a
    /// partial file if the producer fails or is cancelled.
    final class StreamingWriter: @unchecked Sendable {
        private let descriptor: Int32
        private let parentDescriptor: Int32
        private let filename: String
        private let openedDirectories: [Int32]
        private let createdDirectoryParents: [Int32]
        private let synchronizeCreatedDirectoryParent:
            @Sendable (Int32) throws -> Void
        private var finished = false
        private var descriptorClosed = false
        private var directoriesClosed = false

        init(
            descriptor: Int32,
            parentDescriptor: Int32,
            filename: String,
            openedDirectories: [Int32],
            createdDirectoryParents: [Int32],
            synchronizeCreatedDirectoryParent:
                @escaping @Sendable (Int32) throws -> Void
        ) {
            self.descriptor = descriptor
            self.parentDescriptor = parentDescriptor
            self.filename = filename
            self.openedDirectories = openedDirectories
            self.createdDirectoryParents = createdDirectoryParents
            self.synchronizeCreatedDirectoryParent =
                synchronizeCreatedDirectoryParent
        }

        deinit {
            if !finished { abort() }
        }

        func write(_ data: Data) throws {
            guard !finished else { throw SwanPortableExportError.publicationFailed }
            try data.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let count = systemWrite(
                        descriptor,
                        bytes.baseAddress!.advanced(by: offset),
                        bytes.count - offset
                    )
                    if count < 0, errno == EINTR { continue }
                    guard count > 0 else {
                        throw SwanPortableExportError.publicationFailed
                    }
                    offset += count
                }
            }
        }

        func finish() throws {
            guard !finished else { return }
            guard fsync(descriptor) == 0 else {
                throw SwanPortableExportError.publicationFailed
            }
            guard close(descriptor) == 0 else {
                throw SwanPortableExportError.publicationFailed
            }
            descriptorClosed = true
            guard fsync(parentDescriptor) == 0 else {
                throw SwanPortableExportError.publicationFailed
            }
            for directory in createdDirectoryParents.reversed() {
                try synchronizeCreatedDirectoryParent(directory)
            }
            finished = true
            closeOpenedDirectories()
        }

        func abort() {
            guard !finished else { return }
            finished = true
            if !descriptorClosed {
                _ = ftruncate(descriptor, 0)
                _ = fsync(descriptor)
                _ = close(descriptor)
            }
            closeOpenedDirectories()
        }

        private func closeOpenedDirectories() {
            guard !directoriesClosed else { return }
            directoriesClosed = true
            for directory in openedDirectories.reversed() { _ = close(directory) }
        }

    }

    static func read(
        path: String,
        root: Int32,
        maximumBytes: Int,
        afterReadBeforeFinalValidation: (@Sendable () throws -> Void)? = nil
    ) throws -> Data {
        guard maximumBytes >= 0 else {
            throw SwanPortableExportError.invalidArchive
        }
        let components = try pathComponents(path)
        var openedDirectories: [Int32] = []
        var current = root
        defer {
            for descriptor in openedDirectories.reversed() {
                _ = close(descriptor)
            }
        }
        for component in components.dropLast() {
            let child = try openDirectory(parent: current, name: component)
            openedDirectories.append(child)
            current = child
        }
        let descriptor = components.last!.withCString {
            openat(current, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw SwanPortableExportError.invalidArchive
        }
        defer { _ = close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              (metadata.st_mode & 0o777) == 0o600,
              metadata.st_size >= 0,
              metadata.st_size <= off_t(maximumBytes) else {
            throw SwanPortableExportError.invalidArchive
        }
        let expectedCount = Int(metadata.st_size)
        var data = Data(count: expectedCount)
        try data.withUnsafeMutableBytes { bytes in
            var offset = 0
            while offset < expectedCount {
                let count = systemRead(
                    descriptor,
                    bytes.baseAddress!.advanced(by: offset),
                    expectedCount - offset
                )
                if count < 0, errno == EINTR { continue }
                guard count > 0 else {
                    throw SwanPortableExportError.invalidArchive
                }
                offset += count
            }
        }
        try afterReadBeforeFinalValidation?()
        guard descriptorPrefixMatches(
            descriptor: descriptor,
            expected: data
        ) else {
            throw SwanPortableExportError.invalidArchive
        }
        var extra: UInt8 = 0
        let extraCount = withUnsafeMutablePointer(to: &extra) {
            systemPread(
                descriptor,
                $0,
                1,
                off_t(expectedCount)
            )
        }
        var final = stat()
        guard extraCount == 0,
              fstat(descriptor, &final) == 0,
              stableRegularFile(initial: metadata, final: final) else {
            throw SwanPortableExportError.invalidArchive
        }
        return data
    }

    static func entries(
        root: Int32,
        maximumEntries: Int = SwanPortableExportManifest.maximumFileCount + 8
    ) throws -> Entries {
        guard maximumEntries >= 0 else {
            throw SwanPortableExportError.invalidArchive
        }
        var entries = Entries()
        try collectEntries(
            root: root,
            prefix: "",
            entries: &entries,
            maximumEntries: maximumEntries,
            depth: 0
        )
        return entries
    }

    /// Scrubs the pinned tree through descriptors and moves one directory entry
    /// into a fixed quarantine slot. There is deliberately no online unlink:
    /// Darwin and unprivileged Linux have no portable atomic unlink-by-open-FD,
    /// so a pathname unlink could delete a same-UID replacement after an inode
    /// check. A populated or mismatched quarantine poisons this parent until a
    /// trusted operator recovers it while the service is quiesced.
    static func removeTree(
        parent: Int32,
        matching expectedDescriptor: Int32,
        afterEntryResolvedBeforeRemoval: (@Sendable (String) throws -> Void)? = nil,
        afterQuarantineMoveBeforeValidation: (@Sendable () throws -> Void)? = nil
    ) throws {
        var expected = stat()
        guard fstat(expectedDescriptor, &expected) == 0,
              (expected.st_mode & S_IFMT) == S_IFDIR,
              expected.st_uid == geteuid() else {
            throw SwanPortableExportError.publicationFailed
        }
        guard try !entryExists(parent: parent, name: cleanupQuarantineName),
              cleanupQuarantineName.withCString({ mkdirat(parent, $0, 0o700) }) == 0
        else {
            // An existing durable marker already blocks this parent. Do not
            // mutate it or attempt any online recovery.
            throw SwanPortableExportError.publicationFailed
        }
        let quarantine = try openDirectory(
            parent: parent,
            name: cleanupQuarantineName
        )
        defer { _ = close(quarantine) }
        guard fsync(quarantine) == 0, fsync(parent) == 0 else {
            throw SwanPortableExportError.publicationFailed
        }
        try scrubTree(root: expectedDescriptor)
        var matchingNames: [String] = []
        for name in try directoryEntryNames(parent) {
            var current = stat()
            guard name.withCString({
                fstatat(parent, $0, &current, AT_SYMLINK_NOFOLLOW)
            }) == 0 else {
                throw SwanPortableExportError.publicationFailed
            }
            if current.st_dev == expected.st_dev,
               current.st_ino == expected.st_ino {
                matchingNames.append(name)
            }
        }
        guard matchingNames.count == 1 else {
            throw SwanPortableExportError.publicationFailed
        }
        // Resolve once more before the final adversarial interval. The callback
        // exists only for proving that the subsequent no-replace move preserves
        // (at worst relocates) a raced replacement rather than unlinking it.
        matchingNames.removeAll(keepingCapacity: true)
        for name in try directoryEntryNames(parent) {
            var current = stat()
            guard name.withCString({
                fstatat(parent, $0, &current, AT_SYMLINK_NOFOLLOW)
            }) == 0 else {
                throw SwanPortableExportError.publicationFailed
            }
            if current.st_dev == expected.st_dev,
               current.st_ino == expected.st_ino {
                matchingNames.append(name)
            }
        }
        guard matchingNames.count == 1 else {
            throw SwanPortableExportError.publicationFailed
        }
        let sourceName = matchingNames[0]
        try afterEntryResolvedBeforeRemoval?(sourceName)
        try renameExclusively(
            sourceParent: parent,
            source: sourceName,
            destinationParent: quarantine,
            destination: cleanupQuarantinedTreeName
        )
        try afterQuarantineMoveBeforeValidation?()
        guard try currentChildDirectoryMatches(
            parent: quarantine,
            name: cleanupQuarantinedTreeName,
            expectedDescriptor: expectedDescriptor
        ) else {
            throw SwanPortableExportError.publicationFailed
        }
        guard fsync(expectedDescriptor) == 0,
              fsync(quarantine) == 0,
              fsync(parent) == 0 else {
            throw SwanPortableExportError.publicationFailed
        }
    }

    /// Removes payload bytes without pathname deletion. Directory/file names and
    /// extended attributes are intentionally retained as sensitive metadata in
    /// the owner-only quarantine; online code must neither inspect nor reclaim
    /// them. Quiesced operator recovery owns their eventual removal.
    private static func scrubTree(root: Int32) throws {
        try requireOwnerOnlyDirectory(root)
        var rootMetadata = stat()
        guard fstat(root, &rootMetadata) == 0 else {
            throw SwanPortableExportError.publicationFailed
        }
        for name in try directoryEntryNames(root) {
            var metadata = stat()
            guard name.withCString({
                fstatat(root, $0, &metadata, AT_SYMLINK_NOFOLLOW)
            }) == 0,
            metadata.st_uid == geteuid() else {
                throw SwanPortableExportError.publicationFailed
            }
            if (metadata.st_mode & S_IFMT) == S_IFDIR {
                let child = name.withCString {
                    openat(root, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
                }
                guard child >= 0 else {
                    throw SwanPortableExportError.publicationFailed
                }
                var opened = stat()
                guard fstat(child, &opened) == 0,
                      opened.st_dev == rootMetadata.st_dev,
                      opened.st_dev == metadata.st_dev,
                      opened.st_ino == metadata.st_ino,
                      (opened.st_mode & S_IFMT) == S_IFDIR,
                      opened.st_uid == geteuid() else {
                    _ = close(child)
                    throw SwanPortableExportError.publicationFailed
                }
                do {
                    try scrubTree(root: child)
                    _ = close(child)
                } catch {
                    _ = close(child)
                    throw error
                }
            } else {
                guard (metadata.st_mode & S_IFMT) == S_IFREG else {
                    throw SwanPortableExportError.publicationFailed
                }
                let file = name.withCString {
                    openat(root, $0, O_WRONLY | O_CLOEXEC | O_NOFOLLOW)
                }
                guard file >= 0 else {
                    throw SwanPortableExportError.publicationFailed
                }
                var opened = stat()
                guard fstat(file, &opened) == 0,
                      opened.st_dev == rootMetadata.st_dev,
                      opened.st_dev == metadata.st_dev,
                      opened.st_ino == metadata.st_ino,
                      (opened.st_mode & S_IFMT) == S_IFREG,
                      opened.st_uid == geteuid(),
                      opened.st_nlink == 1,
                      ftruncate(file, 0) == 0,
                      fsync(file) == 0 else {
                    _ = close(file)
                    throw SwanPortableExportError.publicationFailed
                }
                _ = close(file)
            }
        }
        guard fsync(root) == 0 else {
            throw SwanPortableExportError.publicationFailed
        }
    }

    static func renameExclusively(
        parent: Int32,
        source: String,
        destination: String
    ) throws {
        guard try !entryExists(
            parent: parent,
            name: cleanupQuarantineName
        ) else {
            throw SwanPortableExportError.publicationFailed
        }
        try renameExclusively(
            sourceParent: parent,
            source: source,
            destinationParent: parent,
            destination: destination
        )
    }

    private static func renameExclusively(
        sourceParent: Int32,
        source: String,
        destinationParent: Int32,
        destination: String
    ) throws {
        let result = source.withCString { sourcePath in
            destination.withCString { destinationPath in
                #if canImport(Darwin)
                renameatx_np(
                    sourceParent,
                    sourcePath,
                    destinationParent,
                    destinationPath,
                    UInt32(RENAME_EXCL)
                )
                #else
                swanRenameAt2(
                    sourceParent,
                    sourcePath,
                    destinationParent,
                    destinationPath,
                    swanRenameNoReplace
                )
                #endif
            }
        }
        guard result == 0 else {
            throw SwanPortableExportError.publicationFailed
        }
    }

    static func synchronizeParent(_ parent: Int32) throws {
        guard fsync(parent) == 0 else {
            throw SwanPortableExportError.publicationFailed
        }
    }

    /// Flushes a completed owner-only tree bottom-up without following links.
    /// SQLite/key-store handles must already be closed before this is called.
    static func synchronizeTree(root: Int32) throws {
        try requireOwnerOnlyDirectory(root)
        for name in try directoryEntryNames(root) {
            var metadata = stat()
            guard name.withCString({
                fstatat(root, $0, &metadata, AT_SYMLINK_NOFOLLOW)
            }) == 0,
            metadata.st_uid == geteuid() else {
                throw SwanPortableExportError.publicationFailed
            }
            switch metadata.st_mode & S_IFMT {
            case S_IFDIR:
                let child = try openDirectory(parent: root, name: name)
                do {
                    try synchronizeTree(root: child)
                } catch {
                    _ = close(child)
                    throw error
                }
                guard close(child) == 0 else {
                    throw SwanPortableExportError.publicationFailed
                }
            case S_IFREG:
                let descriptor = name.withCString {
                    openat(root, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
                }
                guard descriptor >= 0 else {
                    throw SwanPortableExportError.publicationFailed
                }
                var current = stat()
                let valid = fstat(descriptor, &current) == 0
                    && (current.st_mode & S_IFMT) == S_IFREG
                    && current.st_uid == geteuid()
                    && current.st_nlink == 1
                    && (current.st_mode & 0o777) == 0o600
                guard valid, fsync(descriptor) == 0 else {
                    _ = close(descriptor)
                    throw SwanPortableExportError.publicationFailed
                }
                guard close(descriptor) == 0 else {
                    throw SwanPortableExportError.publicationFailed
                }
            default:
                throw SwanPortableExportError.publicationFailed
            }
        }
        try synchronizeParent(root)
    }

    static func requireOwnerOnlyDirectory(_ descriptor: Int32) throws {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFDIR,
              metadata.st_uid == geteuid(),
              (metadata.st_mode & 0o777) == 0o700 else {
            throw SwanPortableExportError.invalidPlacement
        }
    }

    static func expectedDirectories(for files: Set<String>) throws -> Set<String> {
        var output = Set<String>()
        for path in files {
            let components = try pathComponents(path)
            // The frozen portable layout has at most four components, and an
            // operator backup adds the `portable/` container. Keep a little
            // explicit format headroom while validating depth before joining
            // prefixes so a small manifest cannot amplify into quadratic,
            // multi-gigabyte cumulative strings.
            guard components.count <= 8 else {
                throw SwanPortableExportError.invalidManifest
            }
            guard components.count > 1 else { continue }
            for end in 1 ..< components.count {
                output.insert(components[..<end].joined(separator: "/"))
            }
        }
        return output
    }

    static func isSafeComponent(_ value: String) -> Bool {
        !value.isEmpty && value != "." && value != ".."
            && value.utf8.count <= 255 && !value.contains("/")
            && !value.contains("\u{0}")
    }

    private static func requireAbsent(parent: Int32, name: String) throws {
        var metadata = stat()
        if name.withCString({
            fstatat(parent, $0, &metadata, AT_SYMLINK_NOFOLLOW)
        }) == 0 {
            throw SwanPortableExportError.publicationFailed
        }
        guard errno == ENOENT else {
            throw SwanPortableExportError.publicationFailed
        }
    }

    private static func pathComponents(_ path: String) throws -> [String] {
        guard SwanPortableExportPath.isSafeRelative(path) else {
            throw SwanPortableExportError.invalidManifest
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
            .map(String.init)
        guard components.allSatisfy(isSafeComponent) else {
            throw SwanPortableExportError.invalidManifest
        }
        return components
    }

    /// Same-inode writes are not detected by identity/length alone. Compare
    /// nanosecond mtime and ctime as well; an attacker can restore mtime, but
    /// cannot restore ctime after writing or changing timestamps.
    private static func stableRegularFile(initial: stat, final: stat) -> Bool {
        guard final.st_dev == initial.st_dev,
              final.st_ino == initial.st_ino,
              final.st_size == initial.st_size,
              final.st_mode == initial.st_mode,
              final.st_uid == initial.st_uid,
              final.st_gid == initial.st_gid,
              final.st_nlink == initial.st_nlink,
              (final.st_mode & S_IFMT) == S_IFREG,
              final.st_uid == geteuid(),
              final.st_nlink == 1,
              (final.st_mode & 0o777) == 0o600 else {
            return false
        }
#if canImport(Darwin)
        return final.st_mtimespec.tv_sec == initial.st_mtimespec.tv_sec
            && final.st_mtimespec.tv_nsec == initial.st_mtimespec.tv_nsec
            && final.st_ctimespec.tv_sec == initial.st_ctimespec.tv_sec
            && final.st_ctimespec.tv_nsec == initial.st_ctimespec.tv_nsec
#else
        return final.st_mtim.tv_sec == initial.st_mtim.tv_sec
            && final.st_mtim.tv_nsec == initial.st_mtim.tv_nsec
            && final.st_ctim.tv_sec == initial.st_ctim.tv_sec
            && final.st_ctim.tv_nsec == initial.st_ctim.tv_nsec
#endif
    }

    /// Revalidates the exact bytes already consumed through the same pinned
    /// descriptor. Some Linux filesystems do not expose a same-size rewrite
    /// through timestamp metadata soon enough for an immediate final `fstat`.
    /// Keep the second pass bounded and compare against the resident result
    /// instead of trusting metadata as a content-integrity signal.
    private static func descriptorPrefixMatches(
        descriptor: Int32,
        expected: Data
    ) -> Bool {
        guard !expected.isEmpty else { return true }
        var scratch = Data(count: min(64 * 1_024, expected.count))
        return expected.withUnsafeBytes { expectedBytes in
            var offset = 0
            while offset < expected.count {
                let requested = min(scratch.count, expected.count - offset)
                let count = scratch.withUnsafeMutableBytes { scratchBytes in
                    while true {
                        let result = systemPread(
                            descriptor,
                            scratchBytes.baseAddress!,
                            requested,
                            off_t(offset)
                        )
                        if result < 0, errno == EINTR { continue }
                        return result
                    }
                }
                let matches = scratch.withUnsafeBytes { scratchBytes in
                    memcmp(
                        scratchBytes.baseAddress!,
                        expectedBytes.baseAddress!.advanced(by: offset),
                        requested
                    ) == 0
                }
                guard count == requested, matches else {
                    return false
                }
                offset += requested
            }
            return true
        }
    }

    private static func openDirectory(parent: Int32, name: String) throws -> Int32 {
        guard isSafeComponent(name) else {
            throw SwanPortableExportError.invalidArchive
        }
        let descriptor = name.withCString {
            openat(parent, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw SwanPortableExportError.invalidArchive
        }
        do {
            try requireOwnerOnlyDirectory(descriptor)
            return descriptor
        } catch {
            _ = close(descriptor)
            throw error
        }
    }

    private static func collectEntries(
        root: Int32,
        prefix: String,
        entries: inout Entries,
        maximumEntries: Int,
        depth: Int
    ) throws {
        // Generated archives are only a few levels deep. Reject a hostile
        // tree before recursive descent can consume the process stack.
        guard depth <= 256 else {
            throw SwanPortableExportError.invalidArchive
        }
        let remaining = maximumEntries - entries.files.count - entries.directories.count
        guard remaining >= 0 else {
            throw SwanPortableExportError.invalidArchive
        }
        for name in try directoryEntryNames(root, maximumCount: remaining) {
            guard entries.files.count + entries.directories.count < maximumEntries else {
                throw SwanPortableExportError.invalidArchive
            }
            let path = prefix.isEmpty ? name : "\(prefix)/\(name)"
            var metadata = stat()
            guard name.withCString({
                fstatat(root, $0, &metadata, AT_SYMLINK_NOFOLLOW)
            }) == 0,
            metadata.st_uid == geteuid() else {
                throw SwanPortableExportError.invalidArchive
            }
            switch metadata.st_mode & S_IFMT {
            case S_IFDIR:
                let child = try openDirectory(parent: root, name: name)
                defer { _ = close(child) }
                entries.directories.insert(path)
                try collectEntries(
                    root: child,
                    prefix: path,
                    entries: &entries,
                    maximumEntries: maximumEntries,
                    depth: depth + 1
                )
            case S_IFREG:
                guard metadata.st_nlink == 1,
                      (metadata.st_mode & 0o777) == 0o600 else {
                    throw SwanPortableExportError.invalidArchive
                }
                entries.files.insert(path)
            default:
                throw SwanPortableExportError.invalidArchive
            }
        }
    }

    private static func directoryEntryNames(
        _ descriptor: Int32,
        maximumCount: Int? = nil
    ) throws -> [String] {
        let inventoryDescriptor = openat(
            descriptor,
            ".",
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard inventoryDescriptor >= 0,
              let directory = fdopendir(inventoryDescriptor) else {
            if inventoryDescriptor >= 0 { _ = close(inventoryDescriptor) }
            throw SwanPortableExportError.invalidArchive
        }
        defer { _ = closedir(directory) }
        var names: [String] = []
        while true {
            errno = 0
            guard let entry = readdir(directory) else {
                guard errno == 0 else {
                    throw SwanPortableExportError.invalidArchive
                }
                break
            }
            var storage = entry.pointee.d_name
            let capacity = MemoryLayout.size(ofValue: storage)
            let name = withUnsafePointer(to: &storage) {
                $0.withMemoryRebound(to: CChar.self, capacity: capacity) {
                    String(cString: $0)
                }
            }
            if name != ".", name != ".." {
                guard isSafeComponent(name) else {
                    throw SwanPortableExportError.invalidArchive
                }
                if let maximumCount, names.count >= maximumCount {
                    throw SwanPortableExportError.invalidArchive
                }
                names.append(name)
            }
        }
        return names
    }

    private static func systemRead(
        _ descriptor: Int32,
        _ buffer: UnsafeMutableRawPointer,
        _ count: Int
    ) -> Int {
        #if canImport(Darwin)
        Darwin.read(descriptor, buffer, count)
        #else
        Glibc.read(descriptor, buffer, count)
        #endif
    }

    private static func systemPread(
        _ descriptor: Int32,
        _ buffer: UnsafeMutableRawPointer,
        _ count: Int,
        _ offset: off_t
    ) -> Int {
        #if canImport(Darwin)
        Darwin.pread(descriptor, buffer, count, offset)
        #else
        Glibc.pread(descriptor, buffer, count, offset)
        #endif
    }

    private static func systemWrite(
        _ descriptor: Int32,
        _ buffer: UnsafeRawPointer,
        _ count: Int
    ) -> Int {
        #if canImport(Darwin)
        Darwin.write(descriptor, buffer, count)
        #else
        Glibc.write(descriptor, buffer, count)
        #endif
    }
}
