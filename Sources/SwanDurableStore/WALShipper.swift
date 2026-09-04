import Foundation
import SQLiteNIO

/// Ships committed SQLite WAL frames for one database file to the vault.
///
/// Reads the `-wal` file directly. Safe because Swan has exactly one writing
/// connection per database and the shipper runs inside that actor's write
/// path after `COMMIT` returns, so every frame up to the last commit frame is
/// complete on disk. The vault validates SQLite's own checksum chain, so the
/// shipper only has to walk frames and honour salts.
///
/// WAL layout (SQLite file format §WAL): 32-byte header
/// (magic, version, page size, checkpoint seq, salt[8], checksum[8]) then
/// frames of 24-byte header (page no, db size after commit or 0, salt[8],
/// checksum[8]) + page.
public actor WALShipper {
    public enum Failure: Error, Equatable {
        case walHeaderInvalid
        case pageSizeMismatch(local: UInt32, vault: UInt32)
        /// The local WAL restarted (salt changed) while frames from the previous
        /// WAL were still unshipped: an autocheckpoint ran without a barrier.
        /// Recovery is a fresh snapshot upload.
        case unshippedFramesLost
        case notAttached
        /// `PRAGMA wal_checkpoint(TRUNCATE)` could not complete because a
        /// reader holds the WAL; retry later.
        case checkpointBlocked
    }

    public let database: String
    public let fileURL: URL
    private let client: VaultClient
    private var salt: Data?
    private var nextFrame: UInt32 = 1
    private var nextSeq: UInt64 = 1
    private var pageSize: UInt32 = 0
    private var attached = false

    public init(client: VaultClient, database: String, fileURL: URL) {
        self.client = client
        self.database = database
        self.fileURL = fileURL
    }

    /// Adopts the vault's view of this database. Returns `false` when the vault
    /// has never seen it (caller must `bootstrap` first).
    @discardableResult
    public func attach() async throws -> Bool {
        guard let manifest = try await client.manifest(database: database) else { return false }
        adopt(manifest)
        return true
    }

    /// First contact: checkpoint the local WAL into the main file (so the
    /// image alone is the full state) and upload it as the base snapshot.
    /// Requires that no other transaction is in flight; Swan bootstrap calls
    /// this before installing the barrier.
    public func bootstrap() async throws {
        try await Self.truncateCheckpoint(fileURL)
        let image = try Data(contentsOf: fileURL, options: .mappedIfSafe)
        let manifest = try await client.putSnapshot(database: database, image: image)
        adopt(manifest)
    }

    /// The commit barrier body. Ships every complete commit not yet at the
    /// vault. Idempotent: a repeat call with nothing new is a no-op.
    public func ship() async throws {
        guard attached else { throw Failure.notAttached }
        let walURL = URL(fileURLWithPath: fileURL.path + "-wal")
        guard let wal = try? Data(contentsOf: walURL, options: .mappedIfSafe), wal.count >= 32 else { return }
        let header = try WALHeader(wal)
        if pageSize != 0, header.pageSize != pageSize {
            throw Failure.pageSizeMismatch(local: header.pageSize, vault: pageSize)
        }
        let frameLength = 24 + Int(header.pageSize)
        let reset = header.salt != salt
        if reset {
            // A salt change is only legitimate when everything from the old
            // WAL was already shipped; otherwise an autocheckpoint dropped
            // frames we never sent.
            if salt != nil, nextFrame > 1, try previousWALHadUnshippedFrames(wal: wal, frameLength: frameLength) {
                throw Failure.unshippedFramesLost
            }
            nextFrame = 1
        }
        let totalFrames = (wal.count - 32) / frameLength
        var lastCommit: UInt32 = 0
        var index = Int(nextFrame) - 1
        while index < totalFrames {
            let offset = 32 + index * frameLength
            guard wal[offset + 8 ..< offset + 16] == header.salt else { break }
            let commitSize = wal.readUInt32BE(at: offset + 4)
            if commitSize != 0 { lastCommit = UInt32(index + 1) }
            index += 1
        }
        guard lastCommit >= nextFrame else { return }
        let start = 32 + (Int(nextFrame) - 1) * frameLength
        let end = 32 + Int(lastCommit) * frameLength
        let descriptor = VaultClient.SegmentDescriptor(
            seq: nextSeq,
            pageSize: header.pageSize,
            firstFrame: nextFrame,
            frameCount: lastCommit - nextFrame + 1,
            salt: header.salt,
            bigEndian: header.bigEndian,
            resetHeaderChecksum: reset ? header.checksum : nil
        )
        _ = try await client.postSegment(database: database, descriptor, frames: wal.subdata(in: start ..< end))
        salt = header.salt
        pageSize = header.pageSize
        nextFrame = lastCommit + 1
        nextSeq += 1
    }

    /// Once everything is acknowledged, fold the local WAL back into the main
    /// file. `SQLITE_BUSY` from an open reader is not an error; try later.
    public func checkpointIfShipped() async throws {
        guard attached else { return }
        let walURL = URL(fileURLWithPath: fileURL.path + "-wal")
        guard let wal = try? Data(contentsOf: walURL, options: .mappedIfSafe), wal.count >= 32 else { return }
        let header = try WALHeader(wal)
        let frameLength = 24 + Int(header.pageSize)
        let totalFrames = (wal.count - 32) / frameLength
        guard header.salt == salt, Int(nextFrame) - 1 >= totalFrames else { return }
        try await Self.truncateCheckpoint(fileURL)
    }

    /// Rebuild the local database file from the vault (cold start after tvOS
    /// purged the cache). Applies the same page loop the vault's `compact` uses.
    public static func restore(client: VaultClient, database: String, to fileURL: URL) async throws {
        guard let manifest = try await client.manifest(database: database) else { return }
        var image = try await client.snapshot(database: database)
        let pageSize = Int(manifest.pageSize)
        var finalPages = image.count / pageSize
        for meta in manifest.segments {
            let segment = try await client.segment(database: database, seq: meta.seq)
            let frameLength = 24 + pageSize
            var offset = 0
            while offset + frameLength <= segment.count {
                let pageNumber = Int(segment.readUInt32BE(at: offset))
                let end = pageNumber * pageSize
                if image.count < end { image.append(Data(count: end - image.count)) }
                image.replaceSubrange(end - pageSize ..< end, with: segment[offset + 24 ..< offset + frameLength])
                offset += frameLength
            }
            finalPages = Int(meta.dbPages)
        }
        image = image.prefix(finalPages * pageSize)
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        for suffix in ["-wal", "-shm"] { try? FileManager.default.removeItem(atPath: fileURL.path + suffix) }
        try image.write(to: fileURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }

    // MARK: Internals

    private func adopt(_ manifest: VaultClient.Manifest) {
        salt = manifest.salt.flatMap { Data(hex: $0) }
        nextFrame = manifest.nextFrame
        nextSeq = manifest.nextSeq
        pageSize = manifest.pageSize
        attached = true
    }

    /// After a WAL restart SQLite reuses the file; frames beyond the header may
    /// still carry the previous salt. If any of those sit at or beyond our
    /// `nextFrame`, they were never shipped.
    private func previousWALHadUnshippedFrames(wal: Data, frameLength: Int) throws -> Bool {
        guard let previous = salt else { return false }
        let totalFrames = (wal.count - 32) / frameLength
        var index = Int(nextFrame) - 1
        while index < totalFrames {
            let offset = 32 + index * frameLength
            if wal[offset + 8 ..< offset + 16] == previous, wal.readUInt32BE(at: offset + 4) != 0 { return true }
            index += 1
        }
        return false
    }

    private static func truncateCheckpoint(_ fileURL: URL) async throws {
        let connection = try await SQLiteConnection.open(storage: .file(path: fileURL.path))
        do {
            let rows = try await connection.query("PRAGMA wal_checkpoint(TRUNCATE)")
            try await connection.close()
            if let busy = rows.first?.column("busy")?.integer, busy != 0 {
                throw Failure.checkpointBlocked
            }
        } catch {
            try? await connection.close()
            throw error
        }
    }
}

struct WALHeader {
    let pageSize: UInt32
    let salt: Data
    let checksum: (UInt32, UInt32)
    let bigEndian: Bool

    init(_ wal: Data) throws {
        let magic = wal.readUInt32BE(at: 0)
        guard magic == 0x377F_0682 || magic == 0x377F_0683 else { throw WALShipper.Failure.walHeaderInvalid }
        bigEndian = magic == 0x377F_0683
        pageSize = wal.readUInt32BE(at: 8)
        guard pageSize >= 512, pageSize <= 65536, pageSize & (pageSize - 1) == 0 else { throw WALShipper.Failure.walHeaderInvalid }
        salt = wal.subdata(in: 16 ..< 24)
        checksum = (wal.readUInt32BE(at: 24), wal.readUInt32BE(at: 28))
    }
}

extension Data {
    func readUInt32BE(at offset: Int) -> UInt32 {
        let base = startIndex + offset
        return UInt32(self[base]) << 24 | UInt32(self[base + 1]) << 16 | UInt32(self[base + 2]) << 8 | UInt32(self[base + 3])
    }

    init?(hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index ..< next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}
