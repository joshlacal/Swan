import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Coordinates the server with offline full-service snapshots. A server
/// retains a shared lease for its lifetime; a snapshot takes an exclusive
/// lease before inspecting or copying any database or key material.
public final class SwanServiceDirectoryLease: @unchecked Sendable {
    private let descriptor: Int32

    public init(dataDirectory: URL) throws {
        try FileManager.default.createDirectory(at: dataDirectory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let path = dataDirectory.appendingPathComponent(".swan-service.lock").path
        let descriptor = open(path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard descriptor >= 0 else { throw SwanError.unavailable("service directory lease is unavailable") }
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              info.st_uid == geteuid(), info.st_mode & mode_t(0o777) == mode_t(0o600),
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              flock(descriptor, LOCK_SH | LOCK_NB) == 0 else {
            close(descriptor)
            throw SwanError.unavailable("service directory is reserved for an offline snapshot")
        }
        self.descriptor = descriptor
    }

    deinit { _ = flock(descriptor, LOCK_UN); close(descriptor) }
}
