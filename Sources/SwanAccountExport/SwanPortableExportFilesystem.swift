import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
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
              SwanPortableExportFilesystem.isSafeComponent(name) else {
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

    static func createStagingDirectory(parent: Int32, name: String) throws -> Int32 {
        guard isSafeComponent(name),
              name.withCString({ mkdirat(parent, $0, 0o700) }) == 0 else {
            throw SwanPortableExportError.publicationFailed
        }
        do {
            return try openDirectory(parent: parent, name: name)
        } catch {
            _ = name.withCString { unlinkat(parent, $0, AT_REMOVEDIR) }
            throw error
        }
    }

    static func write(
        _ data: Data,
        path: String,
        root: Int32
    ) throws {
        let components = try pathComponents(path)
        var openedDirectories: [Int32] = []
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
    }

    static func read(
        path: String,
        root: Int32,
        maximumBytes: Int
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
        var extra: UInt8 = 0
        let extraCount = withUnsafeMutablePointer(to: &extra) {
            systemRead(descriptor, $0, 1)
        }
        guard extraCount == 0 else {
            throw SwanPortableExportError.invalidArchive
        }
        return data
    }

    static func entries(root: Int32) throws -> Entries {
        var entries = Entries()
        try collectEntries(root: root, prefix: "", entries: &entries)
        return entries
    }

    static func removeTree(parent: Int32, name: String) {
        guard isSafeComponent(name) else { return }
        let descriptor = name.withCString {
            openat(parent, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        if descriptor >= 0 {
            if let names = try? directoryEntryNames(descriptor) {
                for child in names {
                    var metadata = stat()
                    if child.withCString({
                        fstatat(descriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW)
                    }) == 0,
                    (metadata.st_mode & S_IFMT) == S_IFDIR {
                        removeTree(parent: descriptor, name: child)
                    } else {
                        _ = child.withCString { unlinkat(descriptor, $0, 0) }
                    }
                }
            }
            _ = close(descriptor)
        }
        _ = name.withCString { unlinkat(parent, $0, AT_REMOVEDIR) }
    }

    static func renameExclusively(
        parent: Int32,
        source: String,
        destination: String
    ) throws {
        let result = source.withCString { sourcePath in
            destination.withCString { destinationPath in
                #if canImport(Darwin)
                renameatx_np(
                    parent,
                    sourcePath,
                    parent,
                    destinationPath,
                    UInt32(RENAME_EXCL)
                )
                #else
                renameat2(
                    parent,
                    sourcePath,
                    parent,
                    destinationPath,
                    UInt32(RENAME_NOREPLACE)
                )
                #endif
            }
        }
        guard result == 0, fsync(parent) == 0 else {
            throw SwanPortableExportError.publicationFailed
        }
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
        entries: inout Entries
    ) throws {
        for name in try directoryEntryNames(root) {
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
                try collectEntries(root: child, prefix: path, entries: &entries)
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

    private static func directoryEntryNames(_ descriptor: Int32) throws -> [String] {
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
