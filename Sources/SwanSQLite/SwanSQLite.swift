import Crypto
import Foundation
import Petrel
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

    /// Connection-local configuration must run outside a migration write
    /// transaction (`foreign_keys` and `journal_mode` are not safely changed
    /// inside one). Schema DDL below is serialized separately with
    /// `BEGIN IMMEDIATE` by `SQLiteControlDatabase`.
    public static let controlConnectionPragmas = [
        "PRAGMA busy_timeout=5000",
        "PRAGMA journal_mode=WAL",
        "PRAGMA foreign_keys=ON",
    ]

    public static let controlMigrations = controlConnectionPragmas + [
        "CREATE TABLE IF NOT EXISTS accounts (did TEXT PRIMARY KEY, handle TEXT UNIQUE NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS oauth_tokens (digest BLOB PRIMARY KEY, family_id TEXT NOT NULL, subject TEXT NOT NULL, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS oauth_client_metadata (client_id TEXT PRIMARY KEY, document BLOB NOT NULL, expires_at INTEGER NOT NULL)",
        """
        CREATE TABLE IF NOT EXISTS oauth_control_client_metadata (
            client_id TEXT PRIMARY KEY,
            document BLOB NOT NULL,
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_token_families (
            family_id TEXT PRIMARY KEY,
            subject TEXT NOT NULL,
            issuer TEXT NOT NULL,
            client_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            scopes BLOB NOT NULL,
            dpop_jkt TEXT,
            client_assertion_key_id TEXT,
            client_assertion_algorithm TEXT,
            client_assertion_jkt TEXT,
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
            revoked_at INTEGER CHECK(revoked_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_par_requests (
            request_digest BLOB PRIMARY KEY CHECK(length(request_digest) = 32),
            issuer TEXT NOT NULL,
            client_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            scopes BLOB NOT NULL,
            dpop_jkt TEXT,
            client_assertion_key_id TEXT,
            client_assertion_algorithm TEXT,
            client_assertion_jkt TEXT,
            state TEXT NOT NULL,
            state_digest BLOB NOT NULL CHECK(length(state_digest) = 32),
            code_challenge_method TEXT NOT NULL CHECK(code_challenge_method = 'S256'),
            code_challenge_s256 TEXT NOT NULL,
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
            consumed_at INTEGER CHECK(consumed_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_par_state_replays (
            state_digest BLOB PRIMARY KEY CHECK(length(state_digest) = 32),
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_authorization_codes (
            code_digest BLOB PRIMARY KEY CHECK(length(code_digest) = 32),
            family_id TEXT NOT NULL REFERENCES oauth_control_token_families(family_id) ON DELETE CASCADE,
            code_challenge_method TEXT NOT NULL CHECK(code_challenge_method = 'S256'),
            code_challenge_s256 TEXT NOT NULL,
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
            reuse_expires_at INTEGER NOT NULL CHECK(reuse_expires_at >= 0),
            consumed_at INTEGER CHECK(consumed_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_access_tokens (
            token_digest BLOB PRIMARY KEY CHECK(length(token_digest) = 32),
            family_id TEXT NOT NULL REFERENCES oauth_control_token_families(family_id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_refresh_tokens (
            token_digest BLOB PRIMARY KEY CHECK(length(token_digest) = 32),
            family_id TEXT NOT NULL REFERENCES oauth_control_token_families(family_id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
            used_at INTEGER CHECK(used_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_dpop_replays (
            jti_digest BLOB PRIMARY KEY CHECK(length(jti_digest) = 32),
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS oauth_control_client_assertion_replays (
            jti_digest BLOB PRIMARY KEY CHECK(length(jti_digest) = 32),
            client_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
        )
        """,
        "CREATE INDEX IF NOT EXISTS oauth_control_access_token_expiry ON oauth_control_access_tokens(expires_at)",
        "CREATE INDEX IF NOT EXISTS oauth_control_refresh_token_expiry ON oauth_control_refresh_tokens(expires_at)",
        "CREATE INDEX IF NOT EXISTS oauth_control_family_expiry ON oauth_control_token_families(expires_at)",
    ]

    public static let accountMigrations = [
        "PRAGMA journal_mode=WAL",
        "PRAGMA foreign_keys=ON",
        // These four tables are retained for compatibility with the initial
        // alpha sketch. Durable repository APIs below use the explicitly
        // namespaced public_repository_* and permissioned_* tables.
        "CREATE TABLE IF NOT EXISTS public_records (uri TEXT PRIMARY KEY, value BLOB NOT NULL, revision INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS space_records (space_uri TEXT NOT NULL, uri TEXT NOT NULL, value BLOB NOT NULL, revision INTEGER NOT NULL, PRIMARY KEY(space_uri, uri))",
        "CREATE TABLE IF NOT EXISTS space_oplog (space_uri TEXT NOT NULL, revision INTEGER NOT NULL, operation BLOB NOT NULL, commitment BLOB NOT NULL, PRIMARY KEY(space_uri, revision))",
        "CREATE TABLE IF NOT EXISTS space_outbox (id TEXT PRIMARY KEY, space_uri TEXT NOT NULL, revision INTEGER NOT NULL, payload BLOB NOT NULL, attempts INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS blob_refs (cid TEXT NOT NULL, namespace TEXT NOT NULL, PRIMARY KEY(cid, namespace))",
        """
        CREATE TABLE IF NOT EXISTS public_repository_records (
            uri TEXT PRIMARY KEY,
            value BLOB NOT NULL,
            cid TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_repository_state (
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision >= 0),
            wire_revision TEXT NOT NULL,
            lthash BLOB NOT NULL CHECK(length(lthash) = 2048),
            current_commit BLOB NOT NULL,
            PRIMARY KEY(space_uri, author_did)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_records (
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            value BLOB NOT NULL,
            cid TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision > 0),
            PRIMARY KEY(space_uri, author_did, collection, rkey)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_oplog (
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision > 0),
            operation_index INTEGER NOT NULL CHECK(operation_index >= 0),
            wire_revision TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('create', 'update', 'delete')),
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            value BLOB,
            cid TEXT,
            previous_cid TEXT,
            commitment BLOB NOT NULL,
            PRIMARY KEY(space_uri, author_did, revision, operation_index),
            CHECK(
                (action IN ('create', 'update') AND value IS NOT NULL AND cid IS NOT NULL)
                OR (action = 'delete' AND value IS NULL AND cid IS NULL)
            ),
            CHECK(
                (action = 'create' AND previous_cid IS NULL)
                OR (action IN ('update', 'delete') AND previous_cid IS NOT NULL)
            )
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_requests (
            request_id TEXT PRIMARY KEY,
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            base_revision INTEGER NOT NULL CHECK(base_revision >= 0),
            final_revision INTEGER NOT NULL CHECK(final_revision >= base_revision),
            event_id TEXT NOT NULL UNIQUE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_outbox (
            id TEXT PRIMARY KEY,
            space_uri TEXT NOT NULL,
            author_did TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision >= 0),
            payload BLOB NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
            created_at INTEGER NOT NULL
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS permissioned_space_outbox_pending
        ON permissioned_space_outbox(created_at, id)
        """,
        """
        CREATE TABLE IF NOT EXISTS blob_payloads (
            cid TEXT PRIMARY KEY,
            payload BLOB NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS blob_namespace_references (
            cid TEXT NOT NULL REFERENCES blob_payloads(cid) ON DELETE CASCADE,
            namespace_kind TEXT NOT NULL CHECK(namespace_kind IN ('public', 'space')),
            space_uri TEXT NOT NULL,
            PRIMARY KEY(cid, namespace_kind, space_uri),
            CHECK(
                (namespace_kind = 'public' AND space_uri = '')
                OR (namespace_kind = 'space' AND length(space_uri) > 0)
            )
        )
        """,
    ]
}

public enum SQLiteRepositoryError: Error, Sendable, Equatable {
    case duplicateRequest(UUID)
    case corruptDatabase(String)
    case revisionOutOfRange(UInt64)
}

/// A canonical public-repository record URI. Permissioned space record URIs
/// use `SpaceRecordURI` and cannot be passed to the public APIs accidentally.
public struct PublicRecordURI: Sendable, Hashable, CustomStringConvertible {
    public let rawValue: String
    public let authority: String
    public let collection: String
    public let rkey: String

    public init(_ rawValue: String) throws {
        guard rawValue.hasPrefix("at://"),
              !rawValue.contains("?"),
              !rawValue.contains("#")
        else {
            throw SwanError.invalidIdentifier(rawValue)
        }
        let fields = rawValue.dropFirst(5).split(
            separator: "/",
            omittingEmptySubsequences: false
        )
        guard fields.count == 3, fields.allSatisfy({ !$0.isEmpty }) else {
            throw SwanError.invalidIdentifier(rawValue)
        }
        let authority = String(fields[0])
        let collection = String(fields[1])
        let rkey = String(fields[2])
        // Reuse the canonical DID, NSID, and record-key validation already
        // enforced by the permissioned URI domain.
        _ = try SpaceURI(
            authority: authority,
            spaceType: collection,
            skey: rkey
        )
        self.rawValue = rawValue
        self.authority = authority
        self.collection = collection
        self.rkey = rkey
    }

    public var description: String { rawValue }
}

public struct PersistedPublicRecord: Sendable, Equatable {
    public let uri: PublicRecordURI
    public let value: Data
    public let cid: String
    public let revision: UInt64
}

public struct PersistedSpaceRecord: Sendable, Equatable {
    public let uri: SpaceRecordURI
    public let value: Data
    public let cid: String
    public let revision: UInt64
}

/// SQLite accepts an already-derived CID because canonical DAG-CBOR/CID
/// construction belongs to SwanSpaces. Identifiers remain typed at this API.
public enum SQLiteSpaceWrite: Sendable, Equatable {
    case put(uri: SpaceRecordURI, value: Data, cid: String)
    case delete(uri: SpaceRecordURI)

    fileprivate var uri: SpaceRecordURI {
        switch self {
        case let .put(uri, _, _), let .delete(uri): uri
        }
    }
}

public struct PersistedOplogCursor: Sendable, Hashable, Comparable {
    public let revision: UInt64
    public let index: UInt64

    public init(revision: UInt64, index: UInt64) {
        self.revision = revision
        self.index = index
    }

    public static func < (lhs: Self, rhs: Self) -> Bool {
        (lhs.revision, lhs.index) < (rhs.revision, rhs.index)
    }
}

public enum PersistedRepoAction: String, Sendable, Equatable {
    case create
    case update
    case delete
}

public struct PersistedSpaceOplogEntry: Sendable, Equatable {
    public let cursor: PersistedOplogCursor
    public let wireRevision: TID
    public let action: PersistedRepoAction
    public let write: SQLiteSpaceWrite
    public let cid: String?
    public let previousCID: String?
    public let commitment: Data

    public var revision: UInt64 { cursor.revision }
    public var index: UInt64 { cursor.index }
}

public struct PersistedRepositoryState: Sendable, Equatable {
    public let space: SpaceURI
    public let author: String
    public let revision: UInt64
    public let wireRevision: TID
    public let ltHash: Data
    /// Opaque current commit CID/value supplied by SwanSpaces.
    public let commit: Data

    public var commitment: Data { Data(SHA256.hash(data: ltHash)) }
}

public struct PersistedRepositorySnapshot: Sendable, Equatable {
    public let state: PersistedRepositoryState
    public let records: [PersistedSpaceRecord]
}

public enum PersistedOplogRead: Sendable, Equatable {
    case incremental([PersistedSpaceOplogEntry])
    /// The cursor predates retained operations. These durable facts are the
    /// input SwanSpaces needs to construct a fresh full-recovery CAR.
    case fullRecoveryRequired(PersistedRepositorySnapshot)
}

public struct PersistedRepositoryCommit: Sendable, Equatable {
    public let state: PersistedRepositoryState
    public let entries: [PersistedSpaceOplogEntry]
    public let outbox: PersistedOutboxEvent
}

public struct PersistedOutboxEvent: Sendable, Equatable {
    public let id: UUID
    public let space: SpaceURI
    public let author: String
    public let revision: UInt64
    public let payload: Data
    public let attempts: Int
}

private actor SQLiteConnectionGate {
    private var isHeld = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        if !isHeld {
            isHeld = true
            return
        }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        if waiters.isEmpty {
            isHeld = false
        } else {
            waiters.removeFirst().resume()
        }
    }
}

struct SQLiteTestingHooks: Sendable {
    var beforeApplyCommit: (@Sendable () async throws -> Void)?
    var afterSnapshotStateRead: (@Sendable () async -> Void)?

    init(
        beforeApplyCommit: (@Sendable () async throws -> Void)? = nil,
        afterSnapshotStateRead: (@Sendable () async -> Void)? = nil
    ) {
        self.beforeApplyCommit = beforeApplyCommit
        self.afterSnapshotStateRead = afterSnapshotStateRead
    }
}

/// The concrete SQLite/WAL boundary. Its actor is a coordination aid, while
/// `BEGIN IMMEDIATE` makes the oplog/outbox write atomic even if another Swan
/// process later opens the same file.
public actor SQLiteAccountDatabase: BlobStore {
    private let connection: SQLiteConnection
    private let connectionGate = SQLiteConnectionGate()
    private let accountDID: String
    private let oplogRetention: Int
    private var testingHooks = SQLiteTestingHooks()

    public init(
        dataDirectory: URL,
        did: String,
        oplogRetention: Int = 10_000
    ) async throws {
        guard oplogRetention > 0 else {
            throw SwanError.malformed("oplog retention must be positive")
        }
        _ = try SpaceURI(
            authority: did,
            spaceType: "app.swan.account",
            skey: "self"
        )
        let databaseURL = SQLiteLayout.accountDatabase(in: dataDirectory, did: did)
        try FileManager.default.createDirectory(
            at: databaseURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        self.accountDID = did
        self.oplogRetention = oplogRetention
        connection = try await SQLiteConnection.open(storage: .file(path: databaseURL.path))
        do {
            try await migrateWithoutGate()
        } catch {
            try? await connection.close()
            throw error
        }
    }

    /// Service lifecycle owns shutdown explicitly; deinit cannot safely launch
    /// a task that captures an actor instance under Swift 6 isolation rules.
    public func close() async throws {
        try await withConnectionGate {
            try await connection.close()
        }
    }

    public func migrate() async throws {
        try await withConnectionGate {
            try await migrateWithoutGate()
        }
    }

    func installTestingHooks(_ hooks: SQLiteTestingHooks) {
        testingHooks = hooks
    }

    private func migrateWithoutGate() async throws {
        for statement in SQLiteLayout.accountMigrations {
            _ = try await connection.query(statement)
        }
    }

    // MARK: Public repository namespace

    public func putPublicRecord(
        uri: PublicRecordURI,
        value: Data,
        cid: String,
        revision: UInt64
    ) async throws {
        guard uri.authority == accountDID else {
            throw SwanError.unauthorized(
                "public record belongs to another account"
            )
        }
        guard !cid.isEmpty else { throw SwanError.malformed("record CID is empty") }
        let storedRevision = try sqliteRevision(revision)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    """
                    INSERT INTO public_repository_records(uri, value, cid, revision)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(uri) DO UPDATE SET
                        value = excluded.value,
                        cid = excluded.cid,
                        revision = excluded.revision
                    """,
                    [.text(uri.rawValue), blob(value), .text(cid), .integer(storedRevision)]
                )
            }
        }
    }

    public func publicRecord(_ uri: PublicRecordURI) async throws -> PersistedPublicRecord? {
        guard uri.authority == accountDID else {
            throw SwanError.unauthorized(
                "public record belongs to another account"
            )
        }
        return try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT value, cid, revision
                FROM public_repository_records
                WHERE uri = ?
                """,
                [.text(uri.rawValue)]
            )
            guard let row = rows.first else { return nil }
            return PersistedPublicRecord(
                uri: uri,
                value: try requiredBlob(row, "value"),
                cid: try requiredText(row, "cid"),
                revision: try requiredRevision(row, "revision")
            )
        }
    }

    // MARK: Permissioned repository namespace

    /// Atomically performs revision CAS, replay reservation, record mutations,
    /// state/oplog persistence, retention, and notification enqueueing. It
    /// performs no network I/O.
    public func apply(
        space: SpaceURI,
        author: String,
        expectedRevision: UInt64,
        requestID: UUID,
        wireRevision: TID,
        writes: [SQLiteSpaceWrite],
        commit: Data,
        notificationPayload: Data,
        eventID: UUID = UUID()
    ) async throws -> PersistedRepositoryCommit {
        try requireAccount(author)
        guard !writes.isEmpty else {
            throw SwanError.malformed("repository batch must contain a write")
        }
        guard !commit.isEmpty else {
            throw SwanError.malformed("current commit must not be empty")
        }
        for write in writes {
            guard write.uri.space == space, write.uri.author == author else {
                throw SwanError.unauthorized("record belongs to another repository")
            }
            if case let .put(_, _, cid) = write, cid.isEmpty {
                throw SwanError.malformed("record CID is empty")
            }
        }
        _ = try sqliteRevision(expectedRevision)

        return try await withConnectionGate {
            try await transaction {
            let duplicate = try await connection.query(
                "SELECT 1 FROM permissioned_space_requests WHERE request_id = ?",
                [.text(requestID.uuidString)]
            )
            guard duplicate.isEmpty else {
                throw SQLiteRepositoryError.duplicateRequest(requestID)
            }

            let current = try await loadState(space: space, author: author)
            let actualRevision = current?.revision ?? 0
            guard expectedRevision == actualRevision else {
                throw SwanError.conflict(
                    expected: expectedRevision,
                    actual: actualRevision
                )
            }
            if let current, wireRevision <= current.wireRevision {
                throw SwanError.malformed(
                    "wire revision must advance"
                )
            }

            var ltHash = try LtHash(
                serialized: current?.ltHash ?? Data(repeating: 0, count: LtHash.byteCount)
            )
            guard actualRevision < UInt64(Int.max) else {
                throw SQLiteRepositoryError.revisionOutOfRange(actualRevision)
            }
            let revision = actualRevision + 1
            let storedRevision = try sqliteRevision(revision)
            var entries: [PersistedSpaceOplogEntry] = []

            for (operationIndex, write) in writes.enumerated() {
                let uri = write.uri
                let old = try await loadRecord(uri)
                let action: PersistedRepoAction
                let previousCID = old?.cid
                let newCID: String? = switch write {
                case let .put(_, _, cid): cid
                case .delete: nil
                }

                switch write {
                case let .put(_, value, cid):
                    action = old == nil ? .create : .update
                    if let old {
                        ltHash.remove(element: ltHashElement(for: old))
                    }
                    ltHash.add(
                        element: "\(uri.collection)/\(uri.rkey)/\(cid)"
                    )
                    _ = try await connection.query(
                        """
                        INSERT INTO permissioned_space_records(
                            space_uri, author_did, collection, rkey,
                            value, cid, revision
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(space_uri, author_did, collection, rkey)
                        DO UPDATE SET
                            value = excluded.value,
                            cid = excluded.cid,
                            revision = excluded.revision
                        """,
                        [
                            .text(space.rawValue), .text(author),
                            .text(uri.collection), .text(uri.rkey),
                            blob(value), .text(cid), .integer(storedRevision),
                        ]
                    )
                case .delete:
                    action = .delete
                    guard let old else {
                        throw SwanError.malformed("cannot delete a missing record")
                    }
                    ltHash.remove(element: ltHashElement(for: old))
                    _ = try await connection.query(
                        """
                        DELETE FROM permissioned_space_records
                        WHERE space_uri = ? AND author_did = ?
                          AND collection = ? AND rkey = ?
                        """,
                        [
                            .text(space.rawValue), .text(author),
                            .text(uri.collection), .text(uri.rkey),
                        ]
                    )
                }

                let commitment = ltHash.commitment
                try await insertOplog(
                    space: space,
                    author: author,
                    revision: storedRevision,
                    operationIndex: operationIndex,
                    wireRevision: wireRevision,
                    action: action,
                    previousCID: previousCID,
                    write: write,
                    commitment: commitment
                )
                entries.append(
                    PersistedSpaceOplogEntry(
                        cursor: PersistedOplogCursor(
                            revision: revision,
                            index: UInt64(operationIndex)
                        ),
                        wireRevision: wireRevision,
                        action: action,
                        write: write,
                        cid: newCID,
                        previousCID: previousCID,
                        commitment: commitment
                    )
                )
            }

            let storedFinalRevision = try sqliteRevision(revision)
            _ = try await connection.query(
                """
                INSERT INTO permissioned_repository_state(
                    space_uri, author_did, revision, wire_revision,
                    lthash, current_commit
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(space_uri, author_did) DO UPDATE SET
                    revision = excluded.revision,
                    wire_revision = excluded.wire_revision,
                    lthash = excluded.lthash,
                    current_commit = excluded.current_commit
                """,
                [
                    .text(space.rawValue), .text(author),
                    .integer(storedFinalRevision),
                    .text(wireRevision.toString()), blob(ltHash.serialized),
                    blob(commit),
                ]
            )

            _ = try await connection.query(
                """
                INSERT INTO permissioned_space_requests(
                    request_id, space_uri, author_did,
                    base_revision, final_revision, event_id
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    .text(requestID.uuidString), .text(space.rawValue),
                    .text(author), .integer(try sqliteRevision(expectedRevision)),
                    .integer(storedFinalRevision), .text(eventID.uuidString),
                ]
            )

            let createdAt = Int(Date().timeIntervalSince1970 * 1_000_000)
            _ = try await connection.query(
                """
                INSERT INTO permissioned_space_outbox(
                    id, space_uri, author_did, revision,
                    payload, attempts, created_at
                ) VALUES (?, ?, ?, ?, ?, 0, ?)
                """,
                [
                    .text(eventID.uuidString), .text(space.rawValue),
                    .text(author), .integer(storedFinalRevision),
                    blob(notificationPayload), .integer(createdAt),
                ]
            )

            try await testingHooks.beforeApplyCommit?()

            let cutoffRows = try await connection.query(
                """
                SELECT revision
                FROM permissioned_space_oplog
                WHERE space_uri = ? AND author_did = ?
                ORDER BY revision DESC, operation_index DESC
                LIMIT 1 OFFSET ?
                """,
                [
                    .text(space.rawValue), .text(author),
                    .integer(oplogRetention - 1),
                ]
            )
            if let cutoffRow = cutoffRows.first {
                let oldestRetainedRevision = try requiredRevision(
                    cutoffRow,
                    "revision"
                )
                _ = try await connection.query(
                    """
                    DELETE FROM permissioned_space_oplog
                    WHERE space_uri = ? AND author_did = ? AND revision < ?
                    """,
                    [
                        .text(space.rawValue), .text(author),
                        .integer(try sqliteRevision(oldestRetainedRevision)),
                    ]
                )
            }

            let state = PersistedRepositoryState(
                space: space,
                author: author,
                revision: revision,
                wireRevision: wireRevision,
                ltHash: ltHash.serialized,
                commit: commit
            )
            let outbox = PersistedOutboxEvent(
                id: eventID,
                space: space,
                author: author,
                revision: revision,
                payload: notificationPayload,
                attempts: 0
            )
            return PersistedRepositoryCommit(
                state: state,
                entries: entries,
                outbox: outbox
            )
            }
        }
    }

    public func repositorySnapshot(
        space: SpaceURI,
        author: String
    ) async throws -> PersistedRepositorySnapshot? {
        try requireAccount(author)
        return try await withConnectionGate {
            try await readTransaction {
                try await repositorySnapshotWithoutTransaction(
                    space: space,
                    author: author
                )
            }
        }
    }

    private func repositorySnapshotWithoutTransaction(
        space: SpaceURI,
        author: String
    ) async throws -> PersistedRepositorySnapshot? {
        guard let state = try await loadState(space: space, author: author) else {
            return nil
        }
        await testingHooks.afterSnapshotStateRead?()
        let rows = try await connection.query(
            """
            SELECT collection, rkey, value, cid, revision
            FROM permissioned_space_records
            WHERE space_uri = ? AND author_did = ?
            ORDER BY collection, rkey
            """,
            [.text(space.rawValue), .text(author)]
        )
        let records = try rows.map {
            try decodeRecord($0, space: space, author: author)
        }
        return PersistedRepositorySnapshot(state: state, records: records)
    }

    public func spaceRecord(
        _ uri: SpaceRecordURI
    ) async throws -> PersistedSpaceRecord? {
        try requireAccount(uri.author)
        return try await withConnectionGate {
            try await loadRecord(uri)
        }
    }

    public func spaceOplog(
        space: SpaceURI,
        author: String,
        since requestedRevision: UInt64
    ) async throws -> PersistedOplogRead {
        try requireAccount(author)
        return try await withConnectionGate {
            try await readTransaction {
                try await spaceOplogWithoutTransaction(
                    space: space,
                    author: author,
                    afterRevision: requestedRevision,
                    afterIndex: nil
                )
            }
        }
    }

    /// Cursor-precise variant for adapters that page within one commit.
    public func spaceOplog(
        space: SpaceURI,
        author: String,
        after cursor: PersistedOplogCursor?
    ) async throws -> PersistedOplogRead {
        try requireAccount(author)
        return try await withConnectionGate {
            try await readTransaction {
                try await spaceOplogWithoutTransaction(
                    space: space,
                    author: author,
                    afterRevision: cursor?.revision ?? 0,
                    afterIndex: cursor?.index
                )
            }
        }
    }

    private func spaceOplogWithoutTransaction(
        space: SpaceURI,
        author: String,
        afterRevision requestedRevision: UInt64,
        afterIndex requestedIndex: UInt64?
    ) async throws -> PersistedOplogRead {
        guard let state = try await loadState(space: space, author: author) else {
            return .incremental([])
        }
        guard requestedRevision < state.revision
                || (requestedRevision == state.revision && requestedIndex != nil)
        else {
            return .incremental([])
        }
        let oldestRows = try await connection.query(
            """
            SELECT MIN(revision) AS oldest_revision
            FROM permissioned_space_oplog
            WHERE space_uri = ? AND author_did = ?
            """,
            [.text(space.rawValue), .text(author)]
        )
        let oldest: UInt64?
        if let row = oldestRows.first,
           let value = row.column("oldest_revision"),
           !value.isNull {
            oldest = try revision(value, column: "oldest_revision")
        } else {
            oldest = nil
        }
        guard let oldest else {
            guard let snapshot = try await repositorySnapshotWithoutTransaction(
                space: space,
                author: author
            ) else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "repository state has no snapshot"
                )
            }
            return .fullRecoveryRequired(snapshot)
        }
        let cursorPredatesRetention = if requestedIndex != nil {
            requestedRevision < oldest
        } else {
            oldest > 0 && requestedRevision < oldest - 1
        }
        if cursorPredatesRetention {
            guard let snapshot = try await repositorySnapshotWithoutTransaction(
                space: space,
                author: author
            ) else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "repository state has no snapshot"
                )
            }
            return .fullRecoveryRequired(snapshot)
        }

        let rows: [SQLiteRow]
        if let requestedIndex {
            rows = try await connection.query(
                """
                SELECT revision, operation_index, wire_revision, action,
                       collection, rkey, value, cid, previous_cid, commitment
                FROM permissioned_space_oplog
                WHERE space_uri = ? AND author_did = ?
                  AND (
                    revision > ?
                    OR (revision = ? AND operation_index > ?)
                  )
                ORDER BY revision, operation_index
                """,
                [
                    .text(space.rawValue), .text(author),
                    .integer(try sqliteRevision(requestedRevision)),
                    .integer(try sqliteRevision(requestedRevision)),
                    .integer(try sqliteRevision(requestedIndex)),
                ]
            )
        } else {
            rows = try await connection.query(
                """
                SELECT revision, operation_index, wire_revision, action,
                       collection, rkey, value, cid, previous_cid, commitment
                FROM permissioned_space_oplog
                WHERE space_uri = ? AND author_did = ? AND revision > ?
                ORDER BY revision, operation_index
                """,
                [
                    .text(space.rawValue), .text(author),
                    .integer(try sqliteRevision(requestedRevision)),
                ]
            )
        }
        return .incremental(
            try rows.map {
                try decodeOplog($0, space: space, author: author)
            }
        )
    }

    // MARK: Durable blob namespace

    public func put(
        _ data: Data,
        namespace: BlobNamespace
    ) async throws -> BlobReference {
        try await putBlob(data, namespace: namespace)
    }

    public func data(for reference: BlobReference) async throws -> Data {
        try await blobData(for: reference)
    }

    public func publicData(cid: String) async throws -> Data? {
        try await publicBlobData(cid: cid)
    }

    public func remove(_ reference: BlobReference) async throws {
        try await removeBlobReference(reference)
    }

    public func putBlob(
        _ data: Data,
        namespace: BlobNamespace
    ) async throws -> BlobReference {
        let cid = "sha256:\(Hex.encode(SHA256.hash(data: data)))"
        let columns = blobNamespaceColumns(namespace)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    """
                    INSERT INTO blob_payloads(cid, payload)
                    VALUES (?, ?)
                    ON CONFLICT(cid) DO UPDATE SET payload = excluded.payload
                    """,
                    [.text(cid), blob(data)]
                )
                _ = try await connection.query(
                    """
                    INSERT INTO blob_namespace_references(
                        cid, namespace_kind, space_uri
                    ) VALUES (?, ?, ?)
                    ON CONFLICT(cid, namespace_kind, space_uri) DO NOTHING
                    """,
                    [
                        .text(cid), .text(columns.kind),
                        .text(columns.spaceURI),
                    ]
                )
            }
        }
        return BlobReference(cid: cid, namespace: namespace)
    }

    public func blobData(for reference: BlobReference) async throws -> Data {
        let columns = blobNamespaceColumns(reference.namespace)
        return try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT payload
                FROM blob_payloads
                JOIN blob_namespace_references USING(cid)
                WHERE cid = ? AND namespace_kind = ? AND space_uri = ?
                """,
                [
                    .text(reference.cid), .text(columns.kind),
                    .text(columns.spaceURI),
                ]
            )
            guard let row = rows.first else {
                throw SwanError.unauthorized(
                    "blob is not reachable in this namespace"
                )
            }
            let payload = try requiredBlob(row, "payload")
            guard blobCID(payload) == reference.cid else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "blob payload does not match CID"
                )
            }
            return payload
        }
    }

    public func publicBlobData(cid: String) async throws -> Data? {
        try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT payload
                FROM blob_payloads
                JOIN blob_namespace_references USING(cid)
                WHERE cid = ? AND namespace_kind = 'public' AND space_uri = ''
                """,
                [.text(cid)]
            )
            guard let row = rows.first else { return nil }
            let payload = try requiredBlob(row, "payload")
            guard blobCID(payload) == cid else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "blob payload does not match CID"
                )
            }
            return payload
        }
    }

    public func removeBlobReference(_ reference: BlobReference) async throws {
        let columns = blobNamespaceColumns(reference.namespace)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    """
                    DELETE FROM blob_namespace_references
                    WHERE cid = ? AND namespace_kind = ? AND space_uri = ?
                    """,
                    [
                        .text(reference.cid), .text(columns.kind),
                        .text(columns.spaceURI),
                    ]
                )
                _ = try await connection.query(
                    """
                    DELETE FROM blob_payloads
                    WHERE cid = ?
                      AND NOT EXISTS (
                        SELECT 1 FROM blob_namespace_references
                        WHERE blob_namespace_references.cid = blob_payloads.cid
                      )
                    """,
                    [.text(reference.cid)]
                )
            }
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
        try requireAccount(space.authority)
        let storedRevision = try sqliteRevision(revision)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    "INSERT INTO space_oplog(space_uri, revision, operation, commitment) VALUES (?, ?, ?, ?)",
                    [
                        .text(space.rawValue), .integer(storedRevision),
                        blob(operation), blob(commitment),
                    ]
                )
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_space_outbox(
                        id, space_uri, author_did, revision,
                        payload, attempts, created_at
                    ) VALUES (?, ?, ?, ?, ?, 0, ?)
                    """,
                    [
                        .text(eventID.uuidString), .text(space.rawValue),
                        .text(space.authority), .integer(storedRevision),
                        blob(notificationPayload),
                        .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
                    ]
                )
            }
        }
        return PersistedOutboxEvent(
            id: eventID,
            space: space,
            author: space.authority,
            revision: revision,
            payload: notificationPayload,
            attempts: 0
        )
    }

    public func pendingOutbox(limit: Int = 100) async throws -> [PersistedOutboxEvent] {
        guard limit >= 0 else {
            throw SwanError.malformed("outbox limit must not be negative")
        }
        return try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT id, space_uri, author_did, revision, payload, attempts
                FROM permissioned_space_outbox
                ORDER BY created_at, id
                LIMIT ?
                """,
                [.integer(limit)]
            )
            return try rows.map { row in
                guard let id = row.column("id")?.string.flatMap(UUID.init(uuidString:)),
                      let spaceRaw = row.column("space_uri")?.string,
                      let author = row.column("author_did")?.string,
                      let attempts = row.column("attempts")?.integer else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "invalid outbox row"
                    )
                }
                return PersistedOutboxEvent(
                    id: id,
                    space: try SpaceURI(spaceRaw),
                    author: author,
                    revision: try requiredRevision(row, "revision"),
                    payload: try requiredBlob(row, "payload"),
                    attempts: attempts
                )
            }
        }
    }

    public func markDelivered(_ id: UUID) async throws {
        try await withConnectionGate {
            _ = try await connection.query(
                "DELETE FROM permissioned_space_outbox WHERE id = ?",
                [.text(id.uuidString)]
            )
        }
    }

    public func markAttempt(_ id: UUID) async throws {
        try await withConnectionGate {
            _ = try await connection.query(
                """
                UPDATE permissioned_space_outbox
                SET attempts = attempts + 1
                WHERE id = ? AND attempts < ?
                """,
                [.text(id.uuidString), .integer(Int.max)]
            )
        }
    }

    // MARK: Transaction and decoding helpers

    private func withConnectionGate<T: Sendable>(
        _ body: () async throws -> T
    ) async throws -> T {
        await connectionGate.acquire()
        do {
            let result = try await body()
            await connectionGate.release()
            return result
        } catch {
            await connectionGate.release()
            throw error
        }
    }

    private func transaction<T: Sendable>(
        _ body: () async throws -> T
    ) async throws -> T {
        _ = try await connection.query("BEGIN IMMEDIATE")
        do {
            let result = try await body()
            _ = try await connection.query("COMMIT")
            return result
        } catch {
            _ = try? await connection.query("ROLLBACK")
            throw error
        }
    }

    private func readTransaction<T: Sendable>(
        _ body: () async throws -> T
    ) async throws -> T {
        _ = try await connection.query("BEGIN")
        do {
            let result = try await body()
            _ = try await connection.query("COMMIT")
            return result
        } catch {
            _ = try? await connection.query("ROLLBACK")
            throw error
        }
    }

    private func requireAccount(_ author: String) throws {
        guard author == accountDID else {
            throw SwanError.unauthorized(
                "repository author belongs to another account"
            )
        }
    }

    private func loadState(
        space: SpaceURI,
        author: String
    ) async throws -> PersistedRepositoryState? {
        let rows = try await connection.query(
            """
            SELECT revision, wire_revision, lthash, current_commit
            FROM permissioned_repository_state
            WHERE space_uri = ? AND author_did = ?
            """,
            [.text(space.rawValue), .text(author)]
        )
        guard let row = rows.first else { return nil }
        let ltHash = try requiredBlob(row, "lthash")
        guard ltHash.count == LtHash.byteCount else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid LtHash byte count"
            )
        }
        return PersistedRepositoryState(
            space: space,
            author: author,
            revision: try requiredRevision(row, "revision"),
            wireRevision: try requiredTID(row, "wire_revision"),
            ltHash: ltHash,
            commit: try requiredBlob(row, "current_commit")
        )
    }

    private func loadRecord(
        _ uri: SpaceRecordURI
    ) async throws -> PersistedSpaceRecord? {
        let rows = try await connection.query(
            """
            SELECT collection, rkey, value, cid, revision
            FROM permissioned_space_records
            WHERE space_uri = ? AND author_did = ?
              AND collection = ? AND rkey = ?
            """,
            [
                .text(uri.space.rawValue), .text(uri.author),
                .text(uri.collection), .text(uri.rkey),
            ]
        )
        guard let row = rows.first else { return nil }
        return try decodeRecord(row, space: uri.space, author: uri.author)
    }

    private func decodeRecord(
        _ row: SQLiteRow,
        space: SpaceURI,
        author: String
    ) throws -> PersistedSpaceRecord {
        let uri = try SpaceRecordURI(
            space: space,
            author: author,
            collection: requiredText(row, "collection"),
            rkey: requiredText(row, "rkey")
        )
        return PersistedSpaceRecord(
            uri: uri,
            value: try requiredBlob(row, "value"),
            cid: try requiredText(row, "cid"),
            revision: try requiredRevision(row, "revision")
        )
    }

    private func insertOplog(
        space: SpaceURI,
        author: String,
        revision: Int,
        operationIndex: Int,
        wireRevision: TID,
        action: PersistedRepoAction,
        previousCID: String?,
        write: SQLiteSpaceWrite,
        commitment: Data
    ) async throws {
        let value: SQLiteData
        let cid: SQLiteData
        switch write {
        case let .put(_, bytes, recordCID):
            value = blob(bytes)
            cid = .text(recordCID)
        case .delete:
            value = .null
            cid = .null
        }
        _ = try await connection.query(
            """
            INSERT INTO permissioned_space_oplog(
                space_uri, author_did, revision, operation_index,
                wire_revision, action, collection, rkey,
                value, cid, previous_cid, commitment
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                .text(space.rawValue), .text(author), .integer(revision),
                .integer(operationIndex), .text(wireRevision.toString()),
                .text(action.rawValue),
                .text(write.uri.collection),
                .text(write.uri.rkey), value, cid,
                previousCID.map(SQLiteData.text) ?? .null,
                blob(commitment),
            ]
        )
    }

    private func decodeOplog(
        _ row: SQLiteRow,
        space: SpaceURI,
        author: String
    ) throws -> PersistedSpaceOplogEntry {
        let uri = try SpaceRecordURI(
            space: space,
            author: author,
            collection: requiredText(row, "collection"),
            rkey: requiredText(row, "rkey")
        )
        let write: SQLiteSpaceWrite
        let actionRaw = try requiredText(row, "action")
        guard let action = PersistedRepoAction(rawValue: actionRaw) else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid oplog action"
            )
        }
        switch action {
        case .create, .update:
            write = .put(
                uri: uri,
                value: try requiredBlob(row, "value"),
                cid: try requiredText(row, "cid")
            )
        case .delete:
            write = .delete(uri: uri)
        }
        let cid = row.column("cid")?.string
        let previousCID = row.column("previous_cid")?.string
        switch action {
        case .create where previousCID != nil:
            throw SQLiteRepositoryError.corruptDatabase(
                "create oplog entry has a previous CID"
            )
        case .update where previousCID == nil:
            throw SQLiteRepositoryError.corruptDatabase(
                "update oplog entry has no previous CID"
            )
        case .delete where previousCID == nil:
            throw SQLiteRepositoryError.corruptDatabase(
                "delete oplog entry has no previous CID"
            )
        default:
            break
        }
        return PersistedSpaceOplogEntry(
            cursor: PersistedOplogCursor(
                revision: try requiredRevision(row, "revision"),
                index: try requiredRevision(row, "operation_index")
            ),
            wireRevision: try requiredTID(row, "wire_revision"),
            action: action,
            write: write,
            cid: cid,
            previousCID: previousCID,
            commitment: try requiredBlob(row, "commitment")
        )
    }

    private func ltHashElement(for record: PersistedSpaceRecord) -> String {
        "\(record.uri.collection)/\(record.uri.rkey)/\(record.cid)"
    }

    private func blobNamespaceColumns(
        _ namespace: BlobNamespace
    ) -> (kind: String, spaceURI: String) {
        switch namespace {
        case .public:
            ("public", "")
        case let .space(space):
            ("space", space.rawValue)
        }
    }

    private func blobCID(_ payload: Data) -> String {
        "sha256:\(Hex.encode(SHA256.hash(data: payload)))"
    }

    private func sqliteRevision(_ revision: UInt64) throws -> Int {
        guard revision <= UInt64(Int.max) else {
            throw SQLiteRepositoryError.revisionOutOfRange(revision)
        }
        return Int(revision)
    }

    private func requiredRevision(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> UInt64 {
        guard let value = row.column(column) else {
            throw SQLiteRepositoryError.corruptDatabase(
                "missing \(column)"
            )
        }
        return try revision(value, column: column)
    }

    private func revision(
        _ data: SQLiteData,
        column: String
    ) throws -> UInt64 {
        guard case let .integer(value) = data, value >= 0 else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid \(column)"
            )
        }
        return UInt64(value)
    }

    private func requiredBlob(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> Data {
        guard let value = row.column(column),
              let data = Data(sqliteData: value)
        else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid \(column)"
            )
        }
        return data
    }

    private func requiredText(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> String {
        guard let value = row.column(column)?.string else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid \(column)"
            )
        }
        return value
    }

    private func requiredTID(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> TID {
        let value = try requiredText(row, column)
        guard let tid = try? TID(tidString: value) else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid \(column)"
            )
        }
        return tid
    }

    private func blob(_ data: Data) -> SQLiteData {
        // SQLiteNIO's Foundation conformance binds Data as a native BLOB.
        data.sqliteData!
    }
}
