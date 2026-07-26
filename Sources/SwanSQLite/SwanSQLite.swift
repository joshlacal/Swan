import Crypto
import Foundation
import SQLiteNIO
import SwanCore
import SwanSpaces
import SwanStorage

/// Stable filesystem placement for per-account SQLite/WAL databases. The
/// control database contains registry and OAuth control-plane data only;
/// repository facts remain in the account database.
public enum SQLiteLayout {
    public static func controlDatabase(in dataDirectory: URL) -> URL {
        dataDirectory.appending(path: "control.sqlite")
    }

    public static func accountDatabase(in dataDirectory: URL, did: String) -> URL {
        let digest = Hex.encode(SHA256.hash(data: Data(did.utf8)))
        return dataDirectory
            .appending(path: "actors")
            .appending(path: String(digest.prefix(2)))
            .appending(path: "\(digest).sqlite")
    }

    public static let controlMigrations = [
        "CREATE TABLE IF NOT EXISTS accounts (did TEXT PRIMARY KEY, handle TEXT UNIQUE NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS oauth_tokens (digest BLOB PRIMARY KEY, family_id TEXT NOT NULL, subject TEXT NOT NULL, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS oauth_client_metadata (client_id TEXT PRIMARY KEY, document BLOB NOT NULL, expires_at INTEGER NOT NULL)",
    ]

    public static let accountMigrations = [
        "PRAGMA journal_mode=WAL",
        "PRAGMA foreign_keys=ON",
        "CREATE TABLE IF NOT EXISTS public_records (uri TEXT PRIMARY KEY, value BLOB NOT NULL, revision INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS space_records (space_uri TEXT NOT NULL, uri TEXT NOT NULL, value BLOB NOT NULL, revision INTEGER NOT NULL, PRIMARY KEY(space_uri, uri))",
        "CREATE TABLE IF NOT EXISTS space_oplog (space_uri TEXT NOT NULL, revision INTEGER NOT NULL, operation BLOB NOT NULL, commitment BLOB NOT NULL, PRIMARY KEY(space_uri, revision))",
        "CREATE TABLE IF NOT EXISTS space_outbox (id TEXT PRIMARY KEY, space_uri TEXT NOT NULL, revision INTEGER NOT NULL, payload BLOB NOT NULL, attempts INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS blob_refs (cid TEXT NOT NULL, namespace TEXT NOT NULL, PRIMARY KEY(cid, namespace))",
    ]
}

public struct PersistedOutboxEvent: Sendable, Equatable {
    public let id: UUID
    public let space: SpaceURI
    public let revision: UInt64
    public let payload: Data
    public let attempts: Int
}

/// The concrete SQLite/WAL boundary. Its actor is a coordination aid, while
/// `BEGIN IMMEDIATE` makes the oplog/outbox write atomic even if another Swan
/// process later opens the same file.
public actor SQLiteAccountDatabase {
    private let connection: SQLiteConnection

    public init(dataDirectory: URL, did: String) async throws {
        let databaseURL = SQLiteLayout.accountDatabase(in: dataDirectory, did: did)
        try FileManager.default.createDirectory(
            at: databaseURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        connection = try await SQLiteConnection.open(storage: .file(path: databaseURL.path))
        try await migrate()
    }

    /// Service lifecycle owns shutdown explicitly; deinit cannot safely launch
    /// a task that captures an actor instance under Swift 6 isolation rules.
    public func close() async throws { try await connection.close() }

    public func migrate() async throws {
        for statement in SQLiteLayout.accountMigrations {
            _ = try await connection.query(statement)
        }
    }

    /// Stores both the committed operation and its notification intent in one
    /// transaction. Dispatch must happen after this method returns; it is never
    /// awaited while SQLite holds the transaction.
    public func appendOplogAndOutbox(
        space: SpaceURI,
        revision: UInt64,
        operation: Data,
        commitment: Data,
        notificationPayload: Data,
        eventID: UUID = UUID()
    ) async throws -> PersistedOutboxEvent {
        _ = try await connection.query("BEGIN IMMEDIATE")
        do {
            _ = try await connection.query(
                "INSERT INTO space_oplog(space_uri, revision, operation, commitment) VALUES (?, ?, ?, ?)",
                [
                    .text(space.rawValue), .integer(Int(revision)),
                    .text(operation.base64EncodedString()), .text(commitment.base64EncodedString()),
                ]
            )
            _ = try await connection.query(
                "INSERT INTO space_outbox(id, space_uri, revision, payload, attempts) VALUES (?, ?, ?, ?, 0)",
                [
                    .text(eventID.uuidString), .text(space.rawValue), .integer(Int(revision)),
                    .text(notificationPayload.base64EncodedString()),
                ]
            )
            _ = try await connection.query("COMMIT")
        } catch {
            _ = try? await connection.query("ROLLBACK")
            throw error
        }
        return PersistedOutboxEvent(id: eventID, space: space, revision: revision, payload: notificationPayload, attempts: 0)
    }

    public func pendingOutbox(limit: Int = 100) async throws -> [PersistedOutboxEvent] {
        let rows = try await connection.query(
            "SELECT id, space_uri, revision, payload, attempts FROM space_outbox ORDER BY revision ASC LIMIT ?",
            [.integer(limit)]
        )
        return try rows.compactMap { row in
            guard let id = row.column("id")?.string.flatMap(UUID.init(uuidString:)),
                  let spaceRaw = row.column("space_uri")?.string,
                  let revision = row.column("revision")?.integer,
                  let encodedPayload = row.column("payload")?.string,
                  let payload = Data(base64Encoded: encodedPayload),
                  let attempts = row.column("attempts")?.integer else { return nil }
            return PersistedOutboxEvent(
                id: id, space: try SpaceURI(spaceRaw), revision: UInt64(revision), payload: payload, attempts: attempts
            )
        }
    }

    public func markDelivered(_ id: UUID) async throws {
        _ = try await connection.query("DELETE FROM space_outbox WHERE id = ?", [.text(id.uuidString)])
    }

    public func markAttempt(_ id: UUID) async throws {
        _ = try await connection.query("UPDATE space_outbox SET attempts = attempts + 1 WHERE id = ?", [.text(id.uuidString)])
    }
}
