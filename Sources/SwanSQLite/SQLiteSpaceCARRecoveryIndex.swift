import Foundation
import Petrel
import SQLiteNIO
import SwanSpaces

private let sqliteSpaceCARRecoveryAdmission =
    SQLiteSpaceCARRecoveryAdmission(maximumConcurrentRecoveries: 2)

private final class SQLiteSpaceCARRecoveryAdmission: @unchecked Sendable {
    private let maximumConcurrentRecoveries: Int
    private let lock = NSLock()
    private var activeLeaseIDs = Set<UUID>()

    init(maximumConcurrentRecoveries: Int) {
        precondition(maximumConcurrentRecoveries > 0)
        self.maximumConcurrentRecoveries = maximumConcurrentRecoveries
    }

    func reserve() -> SQLiteSpaceCARRecoveryLease? {
        lock.withLock {
            guard activeLeaseIDs.count < maximumConcurrentRecoveries else {
                return nil
            }
            let id = UUID()
            activeLeaseIDs.insert(id)
            return SQLiteSpaceCARRecoveryLease(admission: self, id: id)
        }
    }

    fileprivate func release(_ id: UUID) {
        _ = lock.withLock {
            activeLeaseIDs.remove(id)
        }
    }
}

private final class SQLiteSpaceCARRecoveryLease: @unchecked Sendable {
    private weak var admission: SQLiteSpaceCARRecoveryAdmission?
    private let id: UUID
    private let lock = NSLock()
    private var released = false

    init(admission: SQLiteSpaceCARRecoveryAdmission, id: UUID) {
        self.admission = admission
        self.id = id
    }

    deinit { release() }

    func release() {
        let target = lock.withLock {
            guard !released else {
                return nil as SQLiteSpaceCARRecoveryAdmission?
            }
            released = true
            return admission
        }
        target?.release(id)
    }
}

/// Disposable, owner-only staging for a streaming permissioned CAR recovery.
/// It stores only DRISL paths, CIDs, and consumption state; record values are
/// verified one at a time and never enter SQLite.
public actor SQLiteSpaceCARRecoveryIndex: SpaceCARRecoveryIndex {
    private let connection: SQLiteConnection
    private let directoryURL: URL
    private let admissionLease: SQLiteSpaceCARRecoveryLease
    private var cleanupStarted = false
    private var connectionClosed = false
    private var cleanedUp = false

    private init(
        connection: SQLiteConnection,
        directoryURL: URL,
        admissionLease: SQLiteSpaceCARRecoveryLease
    ) {
        self.connection = connection
        self.directoryURL = directoryURL
        self.admissionLease = admissionLease
    }

    public static func create(
        temporaryParentURL: URL = FileManager.default.temporaryDirectory
    ) async throws -> SQLiteSpaceCARRecoveryIndex {
        guard let admissionLease =
            sqliteSpaceCARRecoveryAdmission.reserve()
        else {
            throw SpaceCARStreamingError.stagingUnavailable
        }
        var transferredLease = false
        defer {
            if !transferredLease {
                admissionLease.release()
            }
        }
        let directoryURL = temporaryParentURL.appending(
            path: "swan-space-recovery-\(UUID().uuidString)",
            directoryHint: .isDirectory
        )
        do {
            try FileManager.default.createDirectory(
                at: directoryURL,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw SpaceCARStreamingError.stagingUnavailable
        }
        let databaseURL = directoryURL.appending(path: "index.sqlite")
        let opened: SQLiteConnection
        do {
            opened = try await SQLiteConnection.open(
                storage: .file(path: databaseURL.path)
            )
        } catch {
            try? FileManager.default.removeItem(at: directoryURL)
            throw SpaceCARStreamingError.stagingUnavailable
        }
        do {
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: databaseURL.path
            )
            _ = try await opened.query("PRAGMA journal_mode=OFF")
            _ = try await opened.query("PRAGMA synchronous=OFF")
            _ = try await opened.query("PRAGMA locking_mode=EXCLUSIVE")
            _ = try await opened.query(
                """
                CREATE TABLE recovery_index (
                    path BLOB PRIMARY KEY NOT NULL,
                    cid BLOB NOT NULL,
                    consumed INTEGER NOT NULL DEFAULT 0
                        CHECK(consumed IN (0, 1))
                ) WITHOUT ROWID
                """
            )
            _ = try await opened.query(
                """
                CREATE INDEX recovery_index_consumption_order
                ON recovery_index(consumed, path)
                """
            )
            _ = try await opened.query(
                """
                CREATE INDEX recovery_index_cid_consumption
                ON recovery_index(cid, consumed)
                """
            )
            _ = try await opened.query(
                """
                CREATE TABLE recovery_consumptions (
                    cid BLOB PRIMARY KEY NOT NULL,
                    path_count INTEGER NOT NULL CHECK(path_count > 0)
                ) WITHOUT ROWID
                """
            )
            // The scratch database is private to this one verifier. Keep its
            // entire short lifetime in one transaction so a hostile 100k-entry
            // DRISL cannot force 100k durable autocommit cycles. Reads and
            // consumption updates use this same connection and see the staged
            // rows; cleanup rolls the transaction back before closing it.
            _ = try await opened.query("BEGIN IMMEDIATE")
            // Swan targets POSIX macOS/Linux for this profile. Unlink the
            // owner-only scratch directory after SQLite has opened and locked
            // the database; the live connection retains its descriptor, while
            // cancellation or a process crash can no longer orphan private
            // recovery metadata by pathname.
            try FileManager.default.removeItem(at: directoryURL)
            let index = SQLiteSpaceCARRecoveryIndex(
                connection: opened,
                directoryURL: directoryURL,
                admissionLease: admissionLease
            )
            transferredLease = true
            return index
        } catch {
            try? await opened.close()
            try? FileManager.default.removeItem(at: directoryURL)
            throw SpaceCARStreamingError.stagingUnavailable
        }
    }

    public var isCleanedUp: Bool {
        cleanedUp
    }

    public func insert(_ entry: SpaceCARRecoveryIndexEntry) async throws {
        try requireOpen()
        do {
            let path = Data(entry.path.utf8)
            let rows = try await connection.query(
                """
                INSERT INTO recovery_index(path, cid, consumed)
                VALUES (?, ?, 0)
                ON CONFLICT(path) DO NOTHING
                RETURNING consumed
                """,
                [path.sqliteData!, entry.cid.bytes.sqliteData!]
            )
            guard rows.count == 1 else {
                throw SpaceCARStreamingError.duplicateIndexEntry
            }
        } catch let error as SpaceCARStreamingError {
            throw error
        } catch {
            throw SpaceCARStreamingError.stagingUnavailable
        }
    }

    public func nextUnconsumedLexicographicEntry() async throws
        -> SpaceCARRecoveryIndexEntry?
    {
        try requireOpen()
        do {
            let rows = try await connection.query(
                """
                SELECT path, cid
                FROM recovery_index
                WHERE consumed = 0
                ORDER BY path ASC
                LIMIT 1
                """
            )
            guard let row = rows.first else { return nil }
            return try decodeEntry(row)
        } catch let error as SpaceCARStreamingError {
            throw error
        } catch {
            throw SpaceCARStreamingError.stagingUnavailable
        }
    }

    public func consumeEntries(forCID cid: CID) async throws -> Int {
        try requireOpen()
        do {
            let countRows = try await connection.query(
                """
                INSERT OR IGNORE INTO recovery_consumptions(cid, path_count)
                SELECT ?, COUNT(*)
                FROM recovery_index
                WHERE cid = ? AND consumed = 0
                HAVING COUNT(*) > 0
                RETURNING path_count
                """,
                [cid.bytes.sqliteData!, cid.bytes.sqliteData!]
            )
            guard countRows.count == 1,
                  let changed = countRows[0]
                    .column("path_count")?.integer,
                  changed > 0,
                  changed
                    <= SpaceCARRecoveryLimits.absoluteMaximumIndexEntries
            else {
                throw SpaceCARStreamingError.invalidRecordOrder
            }
            _ = try await connection.query(
                """
                UPDATE recovery_index
                SET consumed = 1
                WHERE cid = ? AND consumed = 0
                """,
                [cid.bytes.sqliteData!]
            )
            return Int(changed)
        } catch let error as SpaceCARStreamingError {
            throw error
        } catch {
            throw SpaceCARStreamingError.stagingUnavailable
        }
    }

    /// Test-only visibility into the logical size of the unlinked scratch
    /// database. The pathname is deliberately unavailable after `create`, so
    /// page count is the only portable way to prove max-cardinality staging
    /// does not amplify beyond its admission budget.
    func testingScratchDatabaseByteCount() async throws -> Int {
        try requireOpen()
        do {
            let countRows = try await connection.query("PRAGMA page_count")
            let sizeRows = try await connection.query("PRAGMA page_size")
            guard countRows.count == 1,
                  sizeRows.count == 1,
                  let pageCount = countRows[0].column("page_count")?.integer,
                  let pageSize = sizeRows[0].column("page_size")?.integer,
                  pageCount >= 0,
                  pageSize > 0
            else {
                throw SpaceCARStreamingError.stagingUnavailable
            }
            let (bytes, overflow) = pageCount.multipliedReportingOverflow(
                by: pageSize
            )
            guard !overflow else {
                throw SpaceCARStreamingError.stagingUnavailable
            }
            return bytes
        } catch let error as SpaceCARStreamingError {
            throw error
        } catch {
            throw SpaceCARStreamingError.stagingUnavailable
        }
    }

    /// Idempotently closes SQLite before deleting the owner-only directory.
    /// SwanCARConsumer calls this on success, failure, and cancellation.
    public func cleanup() async {
        guard !cleanedUp else { return }
        cleanupStarted = true
        if !connectionClosed {
            _ = try? await connection.query("ROLLBACK")
            do {
                try await connection.close()
                connectionClosed = true
            } catch {}
        }
        if FileManager.default.fileExists(atPath: directoryURL.path) {
            try? FileManager.default.removeItem(at: directoryURL)
        }
        cleanedUp =
            connectionClosed
                && !FileManager.default.fileExists(atPath: directoryURL.path)
        if connectionClosed {
            admissionLease.release()
        }
    }

    private func requireOpen() throws {
        guard !cleanupStarted, !connectionClosed else {
            throw SpaceCARStreamingError.stagingUnavailable
        }
    }

    private func decodeEntry(
        _ row: SQLiteRow
    ) throws -> SpaceCARRecoveryIndexEntry {
        guard let pathValue = row.column("path"),
              let pathBytes = Data(sqliteData: pathValue),
              let path = String(data: pathBytes, encoding: .utf8),
              Data(path.utf8) == pathBytes,
              let cidValue = row.column("cid"),
              let cidBytes = Data(sqliteData: cidValue)
        else {
            throw SpaceCARStreamingError.stagingUnavailable
        }
        let cid: CID
        do {
            cid = try CID(bytes: cidBytes)
        } catch {
            throw SpaceCARStreamingError.stagingUnavailable
        }
        guard cid.bytes == cidBytes else {
            throw SpaceCARStreamingError.stagingUnavailable
        }
        return SpaceCARRecoveryIndexEntry(path: path, cid: cid)
    }
}
