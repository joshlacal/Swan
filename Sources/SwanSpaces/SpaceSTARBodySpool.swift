import Foundation
import SwanCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// A single-use private STAR record-pair spool. SQLite adopts an owner-only
/// descriptor after unlinking its pathname. The metadata prefix is separate
/// so the HTTP handler can bind its response MAC to the exact snapshot commit.
public final class SpaceSTARBodySpool: @unchecked Sendable {
    public static let maximumChunkBytes = 64 * 1_024
    public let bodyByteCount: Int
    private let handle: FileHandle
    private let lease: SpaceCARSpoolLease?
    private let lock = NSLock()
    private enum State { case available, streaming, cleaned }
    private var state: State = .available

    package init(fileHandle: FileHandle, bodyByteCount: Int, lease: SpaceCARSpoolLease? = nil) throws {
        guard (0...SpaceSTARLimits.standard.maximumArchiveBytes).contains(bodyByteCount) else {
            throw SpaceSTARError.limitExceeded
        }
        self.handle = fileHandle
        self.bodyByteCount = bodyByteCount
        self.lease = lease
    }

    deinit { cleanup() }

    public var isCleanedUp: Bool { lock.withLock { state == .cleaned } }

    public func streamBody(
        maximumChunkBytes: Int = SpaceSTARBodySpool.maximumChunkBytes,
        consume: (Data) async throws -> Void
    ) async throws {
        let admitted = lock.withLock {
            guard state == .available else { return false }
            state = .streaming
            return true
        }
        guard admitted else { throw Self.unavailable }
        defer { cleanup() }
        guard (1...Self.maximumChunkBytes).contains(maximumChunkBytes) else {
            throw SpaceSTARError.limitExceeded
        }
        var offset = 0
        var buffer = Data(count: maximumChunkBytes)
        while offset < bodyByteCount {
            try Task.checkCancellation()
            let count = try read(offset: offset, maximumBytes: min(maximumChunkBytes, bodyByteCount - offset), into: &buffer)
            guard count > 0 else { throw Self.unavailable }
            offset += count
            try await consume(count == buffer.count ? buffer : Data(buffer.prefix(count)))
        }
        try Task.checkCancellation()
        var endProbe = Data(count: 1)
        guard try read(offset: bodyByteCount, maximumBytes: 1, into: &endProbe) == 0 else { throw Self.unavailable }
    }

    /// `pread` avoids Foundation autorelease retention across async writes.
    /// The lock protects the descriptor from concurrent cleanup/reuse.
    private func read(offset: Int, maximumBytes: Int, into buffer: inout Data) throws -> Int {
        try lock.withLock {
            guard state == .streaming else { throw Self.unavailable }
            return try buffer.withUnsafeMutableBytes { bytes in
                guard let address = bytes.baseAddress else { throw Self.unavailable }
                while true {
                    #if canImport(Darwin)
                    let result = Darwin.pread(handle.fileDescriptor, address, maximumBytes, off_t(offset))
                    #elseif canImport(Glibc)
                    let result = Glibc.pread(handle.fileDescriptor, address, maximumBytes, off_t(offset))
                    #else
                    let result = -1
                    #endif
                    if result >= 0 { return result }
                    guard errno == EINTR else { throw Self.unavailable }
                }
            }
        }
    }

    public func cleanup() {
        let released = lock.withLock {
            guard state != .cleaned else { return false }
            state = .cleaned
            try? handle.close()
            return true
        }
        if released { lease?.release() }
    }

    private static var unavailable: SwanError { .unavailable("permissioned STAR spool is unavailable") }
}
