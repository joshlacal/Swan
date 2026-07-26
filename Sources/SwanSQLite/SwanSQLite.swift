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
    /// `BEGIN IMMEDIATE` by the owning SQLite database actor.
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

    public static let accountConnectionPragmas = [
        "PRAGMA journal_mode=WAL",
        "PRAGMA foreign_keys=ON",
    ]

    public static let accountMigrations = accountConnectionPragmas + [
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
        CREATE TABLE IF NOT EXISTS permissioned_repository_migrations (
            version INTEGER PRIMARY KEY CHECK(version > 0),
            applied_at INTEGER NOT NULL CHECK(applied_at >= 0)
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
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            available_at INTEGER NOT NULL CHECK(available_at >= 0),
            lease_token TEXT,
            lease_expires_at INTEGER,
            CHECK(
                (lease_token IS NULL AND lease_expires_at IS NULL)
                OR (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL
                    AND lease_expires_at >= 0)
            )
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS permissioned_space_outbox_pending
        ON permissioned_space_outbox(created_at, id)
        """,
        /// Authority-owned `com.atproto.simplespace` facts.  These stay in
        /// the authority's account database, never in a member's repository
        /// database or the cross-account control store.
        """
        CREATE TABLE IF NOT EXISTS permissioned_simple_space_authorities (
            space_uri TEXT PRIMARY KEY,
            owner_did TEXT NOT NULL,
            policy TEXT NOT NULL CHECK(policy IN ('public', 'member-list', 'managing-app')),
            app_access TEXT NOT NULL CHECK(app_access IN ('open', 'allow-list')),
            managing_app TEXT,
            is_deleted INTEGER NOT NULL CHECK(is_deleted IN (0, 1)),
            revision INTEGER NOT NULL CHECK(revision > 0),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            updated_at INTEGER NOT NULL CHECK(updated_at >= created_at),
            CHECK(
                (policy = 'managing-app' AND managing_app IS NOT NULL AND length(managing_app) > 0)
                OR (policy != 'managing-app' AND managing_app IS NULL)
            )
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_simple_space_members (
            space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
            member_did TEXT NOT NULL,
            PRIMARY KEY(space_uri, member_did)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_simple_space_clients (
            space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
            client_id TEXT NOT NULL,
            PRIMARY KEY(space_uri, client_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_simple_space_managing_app_decisions (
            space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
            user_did TEXT NOT NULL,
            PRIMARY KEY(space_uri, user_did)
        )
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
    /// Deterministic repository-state marker. Reader-specific commit envelopes
    /// and their IKM/signatures/content bindings are never stored here.
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

/// The facade-level oplog view retains every protocol fact SQLite persisted.
/// In particular, a single repository revision may contain several ordered
/// operations, and a delete deliberately has a null new CID but a previous
/// CID. Collapsing this into the legacy in-memory oplog loses wire semantics.
public struct DurableSpaceOplogEntry: Sendable, Equatable {
    public let cursor: PersistedOplogCursor
    public let wireRevision: TID
    public let action: PersistedRepoAction
    public let write: SpaceWrite
    public let cid: String?
    public let previousCID: String?
    public let commitment: Data

    public var revision: UInt64 { cursor.revision }
    public var index: UInt64 { cursor.index }

    public init(
        cursor: PersistedOplogCursor,
        wireRevision: TID,
        action: PersistedRepoAction,
        write: SpaceWrite,
        cid: String?,
        previousCID: String?,
        commitment: Data
    ) {
        self.cursor = cursor
        self.wireRevision = wireRevision
        self.action = action
        self.write = write
        self.cid = cid
        self.previousCID = previousCID
        self.commitment = commitment
    }
}

public enum DurableSpaceSyncResponse: Sendable, Equatable {
    case incremental([DurableSpaceOplogEntry])
    case fullSnapshot(revision: UInt64, records: [SpaceRecord], commitment: Data)
}

/// Current durable repository facts. A never-written repository has revision
/// zero and no wire revision; after its first commit all values are recovered
/// from SQLite's deterministic state marker and records, not an actor cache.
public struct DurableSpaceRepositoryState: Sendable, Equatable {
    public let space: SpaceURI
    public let author: String
    public let revision: UInt64
    public let wireRevision: TID?
    public let ltHash: Data
    public let commitment: Data

    public init(
        space: SpaceURI,
        author: String,
        revision: UInt64,
        wireRevision: TID?,
        ltHash: Data,
        commitment: Data
    ) {
        self.space = space
        self.author = author
        self.revision = revision
        self.wireRevision = wireRevision
        self.ltHash = ltHash
        self.commitment = commitment
    }
}

/// Authority facts recovered from the authority account's SQLite database.
/// `revision` advances only when a lifecycle, policy, membership, client, or
/// managing-app decision actually changes; duplicate mutations are explicit
/// no-ops and therefore retain the prior revision.
public struct DurableSimpleSpaceState: Sendable, Equatable {
    public let space: SimpleSpace
    public let revision: UInt64

    public init(space: SimpleSpace, revision: UInt64) {
        self.space = space
        self.revision = revision
    }
}

public struct PersistedOutboxEvent: Sendable, Equatable {
    public let id: UUID
    public let space: SpaceURI
    public let author: String
    public let revision: UInt64
    public let payload: Data
    public let attempts: Int
}

/// A durable lease held by one delivery worker. The token is deliberately
/// separate from the notification passed to a transport: transports need an
/// idempotency key, but never authority to acknowledge a database event.
public struct PersistedOutboxLease: Sendable, Equatable {
    public let event: PersistedOutboxEvent
    public let token: UUID
    public let expiresAt: Date

    public init(event: PersistedOutboxEvent, token: UUID, expiresAt: Date) {
        self.event = event
        self.token = token
        self.expiresAt = expiresAt
    }
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

private struct LoadedSimpleSpaceAuthority: Sendable {
    let state: DurableSimpleSpaceState
    let managingAppAllowedUsers: Set<String>
}

/// The concrete SQLite/WAL boundary. Its actor is a coordination aid, while
/// `BEGIN IMMEDIATE` makes the oplog/outbox write atomic even if another Swan
/// process later opens the same file.
public actor SQLiteAccountDatabase: BlobStore {
    private static let permissionedRepositoryStorageMigrationVersion = 1
    private static let permissionedOutboxLeaseMigrationVersion = 2

    private let connection: SQLiteConnection
    private let connectionGate = SQLiteConnectionGate()
    private let accountDID: String
    private let oplogRetention: Int
    private var testingHooks = SQLiteTestingHooks()
    private var activeWriteTransactions = 0

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

    /// Test-only probe used to prove an injected delivery transport is called
    /// after the lease transaction has committed. It intentionally exposes no
    /// SQLite connection or row data.
    func hasActiveWriteTransactionForTesting() -> Bool {
        activeWriteTransactions > 0
    }

    private func migrateWithoutGate() async throws {
        // Keep connection-local PRAGMAs outside the transaction, then make
        // schema installation and data upgrades one cross-process write.
        for statement in SQLiteLayout.accountConnectionPragmas {
            _ = try await connection.query(statement)
        }
        try await transaction {
            for statement in SQLiteLayout.accountMigrations.dropFirst(
                SQLiteLayout.accountConnectionPragmas.count
            ) {
                _ = try await connection.query(statement)
            }
            try await migratePermissionedRepositoryStorageIfNeeded()
            try await migratePermissionedOutboxLeasesIfNeeded()
        }
    }

    /// Upgrades rows written before the persistence API owned its state marker
    /// and outbox-body construction. The sentinel is committed with the row
    /// rewrites: reopening a current database must validate tampering rather
    /// than silently repair it.
    private func migratePermissionedRepositoryStorageIfNeeded() async throws {
        let version = Self.permissionedRepositoryStorageMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        let stateRows = try await connection.query(
            """
            SELECT space_uri, author_did, revision, wire_revision, lthash,
                   current_commit
            FROM permissioned_repository_state
            ORDER BY space_uri, author_did
            """
        )
        for row in stateRows {
            let spaceRaw = try requiredText(row, "space_uri")
            let author = try requiredText(row, "author_did")
            let space = try migrationSpace(
                rawValue: spaceRaw,
                author: author,
                table: "permissioned repository state"
            )
            let revision = try requiredRevision(row, "revision")
            let wireRevision = try requiredTID(row, "wire_revision")
            let ltHash = try requiredBlob(row, "lthash")
            guard ltHash.count == LtHash.byteCount else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "invalid LtHash byte count"
                )
            }
            // Legacy callers supplied arbitrary commit bytes. They are
            // intentionally not interpreted, but a non-BLOB row is malformed.
            _ = try requiredBlob(row, "current_commit")
            let marker = try repositoryStateMarker(
                space: space,
                author: author,
                revision: revision,
                wireRevision: wireRevision,
                commitment: Data(SHA256.hash(data: ltHash))
            )
            _ = try await connection.query(
                """
                UPDATE permissioned_repository_state
                SET current_commit = ?
                WHERE space_uri = ? AND author_did = ?
                """,
                [blob(marker), .text(spaceRaw), .text(author)]
            )
        }

        let outboxRows = try await connection.query(
            """
            SELECT id, space_uri, author_did, revision, payload, attempts,
                   created_at
            FROM permissioned_space_outbox
            ORDER BY created_at, id
            """
        )
        for row in outboxRows {
            let idRaw = try requiredText(row, "id")
            guard let eventID = UUID(uuidString: idRaw) else {
                throw SQLiteRepositoryError.corruptDatabase("invalid outbox id")
            }
            let spaceRaw = try requiredText(row, "space_uri")
            let author = try requiredText(row, "author_did")
            _ = try migrationSpace(
                rawValue: spaceRaw,
                author: author,
                table: "permissioned outbox"
            )
            _ = try requiredRevision(row, "revision")
            _ = try requiredBlob(row, "payload")
            _ = try requiredNonnegativeInteger(row, "attempts")
            _ = try requiredInteger(row, "created_at")
            _ = try await connection.query(
                "UPDATE permissioned_space_outbox SET payload = ? WHERE id = ?",
                [blob(opaqueNotificationPayload(eventID: eventID)), .text(idRaw)]
            )
        }

        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(version),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    /// Adds durable delivery scheduling and lease columns without widening the
    /// control database. The marker/payload migration is version 1; this
    /// version is intentionally separate so an upgraded database is never
    /// silently rewritten after a later integrity failure.
    private func migratePermissionedOutboxLeasesIfNeeded() async throws {
        let version = Self.permissionedOutboxLeaseMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        try await addAccountColumnIfMissing(
            table: "permissioned_space_outbox",
            column: "available_at",
            definition: "INTEGER NOT NULL DEFAULT 0"
        )
        try await addAccountColumnIfMissing(
            table: "permissioned_space_outbox",
            column: "lease_token",
            definition: "TEXT"
        )
        try await addAccountColumnIfMissing(
            table: "permissioned_space_outbox",
            column: "lease_expires_at",
            definition: "INTEGER"
        )
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS permissioned_space_outbox_available
            ON permissioned_space_outbox(available_at, created_at, id)
            """
        )

        let rows = try await connection.query(
            """
            SELECT id, payload, attempts, created_at, available_at,
                   lease_token, lease_expires_at
            FROM permissioned_space_outbox
            ORDER BY created_at, id
            """
        )
        for row in rows {
            let idRaw = try requiredText(row, "id")
            guard let eventID = UUID(uuidString: idRaw) else {
                throw SQLiteRepositoryError.corruptDatabase("invalid outbox id")
            }
            let payload = try requiredBlob(row, "payload")
            guard payload == opaqueNotificationPayload(eventID: eventID) else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "invalid opaque notification payload"
                )
            }
            _ = try requiredNonnegativeInteger(row, "attempts")
            let createdAt = try requiredNonnegativeInteger(row, "created_at")
            let availableAt = try requiredNonnegativeInteger(row, "available_at")
            let lease = try decodeOutboxLease(row)
            if lease.token == nil {
                // Rows written before this migration initially receive a zero
                // default. Make that explicit as immediately eligible at their
                // original enqueue time, without changing an intentional
                // positive retry deadline.
                if availableAt == 0 && createdAt > 0 {
                    _ = try await connection.query(
                        "UPDATE permissioned_space_outbox SET available_at = ? WHERE id = ?",
                        [.integer(createdAt), .text(idRaw)]
                    )
                }
            }
        }

        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(version),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    private func addAccountColumnIfMissing(
        table: String,
        column: String,
        definition: String
    ) async throws {
        let rows = try await connection.query("PRAGMA table_info(\(table))")
        if rows.contains(where: { $0.column("name")?.string == column }) {
            return
        }
        _ = try await connection.query(
            "ALTER TABLE \(table) ADD COLUMN \(column) \(definition)"
        )
    }

    private func migrationSpace(
        rawValue: String,
        author: String,
        table: String
    ) throws -> SpaceURI {
        guard author == accountDID,
              let space = try? SpaceURI(rawValue),
              space.rawValue == rawValue
        else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid \(table) ownership"
            )
        }
        return space
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
        eventID: UUID = UUID()
    ) async throws -> PersistedRepositoryCommit {
        try requireAccount(author)
        guard !writes.isEmpty else {
            throw SwanError.malformed("repository batch must contain a write")
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
            let marker = try repositoryStateMarker(
                space: space,
                author: author,
                revision: revision,
                wireRevision: wireRevision,
                commitment: ltHash.commitment
            )
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
                    blob(marker),
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
            let notificationPayload = opaqueNotificationPayload(eventID: eventID)
            _ = try await connection.query(
                """
                INSERT INTO permissioned_space_outbox(
                    id, space_uri, author_did, revision,
                    payload, attempts, created_at, available_at,
                    lease_token, lease_expires_at
                ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, NULL, NULL)
                """,
                [
                    .text(eventID.uuidString), .text(space.rawValue),
                    .text(author), .integer(storedFinalRevision),
                    blob(notificationPayload), .integer(createdAt),
                    .integer(createdAt),
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
                commit: marker
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
            try await readTransaction {
                guard try await loadState(space: uri.space, author: uri.author) != nil else {
                    return nil
                }
                return try await loadRecord(uri)
            }
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

    // MARK: Durable simple-space authority

    /// Creates one authority-owned simple space. The authority/account and
    /// OAuth management checks run while the insert transaction is held, so a
    /// stale caller cannot race a policy mutation into a foreign account.
    public func createSimpleSpace(
        space: SpaceURI,
        owner: String,
        configuration: SimpleSpaceConfiguration,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try validateSimpleSpaceConfiguration(configuration)
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space, owner: owner)
                try requireAuthorityManagement(space: space, authorization: authorization)
                let existing = try await connection.query(
                    "SELECT 1 FROM permissioned_simple_space_authorities WHERE space_uri = ?",
                    [.text(space.rawValue)]
                )
                guard existing.isEmpty else {
                    throw SwanError.conflict(expected: 0, actual: 1)
                }
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_simple_space_authorities(
                        space_uri, owner_did, policy, app_access, managing_app,
                        is_deleted, revision, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 0, 1, ?, ?)
                    """,
                    [
                        .text(space.rawValue), .text(owner),
                        .text(configuration.policy.rawValue),
                        .text(simpleSpaceAppAccessName(configuration.appAccess)),
                        configuration.managingApp.map(SQLiteData.text) ?? .null,
                        .integer(timestamp), .integer(timestamp),
                    ]
                )
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_simple_space_members(space_uri, member_did)
                    VALUES (?, ?)
                    """,
                    [.text(space.rawValue), .text(owner)]
                )
                try await replaceSimpleSpaceClients(
                    space: space,
                    appAccess: configuration.appAccess
                )
                return try await requiredSimpleSpace(space).state
            }
        }
    }

    /// Reads authority facts from the account database. This local storage API
    /// deliberately has no public HTTP surface. Full authority facts expose
    /// membership and the client allow-list, so only the managing authority
    /// can retrieve them; there is no accidentally-public projection yet.
    public func simpleSpace(
        _ space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws -> DurableSimpleSpaceState? {
        try requireAuthorityAccount(space: space)
        return try await withConnectionGate {
            try await readTransaction {
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization
                )
                return try await loadSimpleSpace(space)?.state
            }
        }
    }

    public func updateSimpleSpace(
        space: SpaceURI,
        configuration: SimpleSpaceConfiguration,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try validateSimpleSpaceConfiguration(configuration)
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space)
                try requireAuthorityManagement(space: space, authorization: authorization)
                let stored = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(stored.state)
                guard stored.state.space.configuration != configuration else {
                    return stored.state
                }
                let previous = stored.state.space.configuration
                let nextRevision = try nextSimpleSpaceRevision(stored.state.revision)
                _ = try await connection.query(
                    """
                    UPDATE permissioned_simple_space_authorities
                    SET policy = ?, app_access = ?, managing_app = ?,
                        revision = ?,
                        updated_at = CASE WHEN updated_at > ? THEN updated_at ELSE ? END
                    WHERE space_uri = ?
                    """,
                    [
                        .text(configuration.policy.rawValue),
                        .text(simpleSpaceAppAccessName(configuration.appAccess)),
                        configuration.managingApp.map(SQLiteData.text) ?? .null,
                        .integer(try sqliteRevision(nextRevision)),
                        .integer(timestamp), .integer(timestamp),
                        .text(space.rawValue),
                    ]
                )
                try await replaceSimpleSpaceClients(
                    space: space,
                    appAccess: configuration.appAccess
                )
                // A decision belongs to one managing app identity. Never
                // transfer it when the policy is disabled or the app changes.
                if previous.policy != .managingApp
                    || configuration.policy != .managingApp
                    || previous.managingApp != configuration.managingApp {
                    _ = try await connection.query(
                        "DELETE FROM permissioned_simple_space_managing_app_decisions WHERE space_uri = ?",
                        [.text(space.rawValue)]
                    )
                }
                return try await requiredSimpleSpace(space).state
            }
        }
    }

    public func addSimpleSpaceMember(
        space: SpaceURI,
        member: String,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        guard isValidSimpleSpaceDID(member) else {
            throw SwanError.invalidIdentifier(member)
        }
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space)
                try requireAuthorityManagement(space: space, authorization: authorization)
                let stored = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(stored.state)
                guard !stored.state.space.members.contains(member) else {
                    return stored.state
                }
                _ = try await connection.query(
                    "INSERT INTO permissioned_simple_space_members(space_uri, member_did) VALUES (?, ?)",
                    [.text(space.rawValue), .text(member)]
                )
                try await touchSimpleSpace(space: space, revision: stored.state.revision, timestamp: timestamp)
                return try await requiredSimpleSpace(space).state
            }
        }
    }

    public func removeSimpleSpaceMember(
        space: SpaceURI,
        member: String,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        guard isValidSimpleSpaceDID(member) else {
            throw SwanError.invalidIdentifier(member)
        }
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space)
                try requireAuthorityManagement(space: space, authorization: authorization)
                let stored = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(stored.state)
                guard member != stored.state.space.owner else {
                    throw SwanError.malformed("a space owner cannot be removed")
                }
                guard stored.state.space.members.contains(member) else {
                    return stored.state
                }
                _ = try await connection.query(
                    "DELETE FROM permissioned_simple_space_members WHERE space_uri = ? AND member_did = ?",
                    [.text(space.rawValue), .text(member)]
                )
                try await touchSimpleSpace(space: space, revision: stored.state.revision, timestamp: timestamp)
                return try await requiredSimpleSpace(space).state
            }
        }
    }

    /// Changes a single client restriction without accepting a mutable
    /// allow-list from an untrusted caller. Open policies cannot accumulate
    /// latent client rows that might become active on a later policy switch.
    public func setSimpleSpaceClientAccess(
        space: SpaceURI,
        clientID: String,
        allowed: Bool,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try validateSimpleSpaceAppIdentifier(clientID)
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space)
                try requireAuthorityManagement(space: space, authorization: authorization)
                let stored = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(stored.state)
                guard case .allowList = stored.state.space.configuration.appAccess else {
                    throw SwanError.malformed("client restrictions require an allow-list policy")
                }
                let currentlyAllowed: Bool
                if case let .allowList(clients) = stored.state.space.configuration.appAccess {
                    currentlyAllowed = clients.contains(clientID)
                } else {
                    currentlyAllowed = false
                }
                guard currentlyAllowed != allowed else { return stored.state }
                if allowed {
                    _ = try await connection.query(
                        "INSERT INTO permissioned_simple_space_clients(space_uri, client_id) VALUES (?, ?)",
                        [.text(space.rawValue), .text(clientID)]
                    )
                } else {
                    _ = try await connection.query(
                        "DELETE FROM permissioned_simple_space_clients WHERE space_uri = ? AND client_id = ?",
                        [.text(space.rawValue), .text(clientID)]
                    )
                }
                try await touchSimpleSpace(space: space, revision: stored.state.revision, timestamp: timestamp)
                return try await requiredSimpleSpace(space).state
            }
        }
    }

    /// Records the managing app's result for a user. The app identity is an
    /// explicit, already-validated service context, not an ambient boolean;
    /// client-attestation verification remains a separate policy component
    /// for this alpha.
    public func setSimpleSpaceManagingAppAccess(
        space: SpaceURI,
        user: String,
        allowed: Bool,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        guard isValidSimpleSpaceDID(user) else {
            throw SwanError.invalidIdentifier(user)
        }
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space)
                let stored = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(stored.state)
                guard case let .service(subject, audience) = authorization,
                      audience == space.authority,
                      let managingApp = stored.state.space.configuration.managingApp,
                      subject == managingApp
                else {
                    throw SwanError.unauthorized("wrong managing app")
                }
                guard stored.state.space.configuration.policy == .managingApp,
                      stored.state.space.configuration.managingApp == managingApp
                else {
                    throw SwanError.unauthorized("wrong managing app")
                }
                let currentlyAllowed = stored.managingAppAllowedUsers.contains(user)
                guard currentlyAllowed != allowed else { return stored.state }
                if allowed {
                    _ = try await connection.query(
                        "INSERT INTO permissioned_simple_space_managing_app_decisions(space_uri, user_did) VALUES (?, ?)",
                        [.text(space.rawValue), .text(user)]
                    )
                } else {
                    _ = try await connection.query(
                        "DELETE FROM permissioned_simple_space_managing_app_decisions WHERE space_uri = ? AND user_did = ?",
                        [.text(space.rawValue), .text(user)]
                    )
                }
                try await touchSimpleSpace(space: space, revision: stored.state.revision, timestamp: timestamp)
                return try await requiredSimpleSpace(space).state
            }
        }
    }

    /// Deletion is an authenticated, idempotent lifecycle transition. It
    /// leaves authority facts as a tombstone, so subsequent reads and
    /// credential issuance fail closed instead of allowing silent recreation.
    public func deleteSimpleSpace(
        space: SpaceURI,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space)
                try requireAuthorityManagement(space: space, authorization: authorization)
                let stored = try await requiredSimpleSpace(space)
                guard !stored.state.space.isDeleted else { return stored.state }
                let nextRevision = try nextSimpleSpaceRevision(stored.state.revision)
                _ = try await connection.query(
                    """
                    UPDATE permissioned_simple_space_authorities
                    SET is_deleted = 1, revision = ?,
                        updated_at = CASE WHEN updated_at > ? THEN updated_at ELSE ? END
                    WHERE space_uri = ?
                    """,
                    [
                        .integer(try sqliteRevision(nextRevision)),
                        .integer(timestamp), .integer(timestamp),
                        .text(space.rawValue),
                    ]
                )
                return try await requiredSimpleSpace(space).state
            }
        }
    }

    /// Evaluates persisted policy facts in a read transaction before the
    /// caller mints a transient read credential. The supplied authorization
    /// context is already verified by the OAuth/delegation layer, but it must
    /// still name the user for whom a credential is being minted. It never
    /// mutates membership or carries policy state in memory across a restart.
    public func authorizeSimpleSpaceRead(
        space: SpaceURI,
        user: String,
        clientID: String?,
        authorization: AuthorizationContext
    ) async throws {
        guard isValidSimpleSpaceDID(user) else {
            throw SwanError.invalidIdentifier(user)
        }
        if let clientID { try validateSimpleSpaceAppIdentifier(clientID) }
        try requireAuthorityAccount(space: space)
        try await withConnectionGate {
            try await readTransaction {
                try requireSimpleSpaceCredentialRequester(
                    space: space,
                    user: user,
                    authorization: authorization
                )
                let stored = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(stored.state)
                switch stored.state.space.configuration.appAccess {
                case .open:
                    break
                case let .allowList(clients):
                    guard let clientID, clients.contains(clientID) else {
                        throw SwanError.unauthorized("app is not authorized for this space")
                    }
                }
                switch stored.state.space.configuration.policy {
                case .public:
                    break
                case .memberList:
                    guard stored.state.space.members.contains(user) else {
                        throw SwanError.unauthorized("user is not a space member")
                    }
                case .managingApp:
                    guard stored.managingAppAllowedUsers.contains(user) else {
                        throw SwanError.unauthorized("managing app denied user access")
                    }
                }
            }
        }
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
        eventID: UUID = UUID()
    ) async throws -> PersistedOutboxEvent {
        try requireAccount(space.authority)
        let storedRevision = try sqliteRevision(revision)
        let notificationPayload = opaqueNotificationPayload(eventID: eventID)
        let createdAt = try outboxTimestamp(Date())
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
                    payload, attempts, created_at, available_at,
                    lease_token, lease_expires_at
                ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, NULL, NULL)
                """,
                [
                    .text(eventID.uuidString), .text(space.rawValue),
                        .text(space.authority), .integer(storedRevision),
                        blob(notificationPayload),
                        .integer(createdAt), .integer(createdAt),
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

    /// Atomically claims the oldest notification that is eligible for delivery.
    /// An expired lease is eligible again after a process crash. This method
    /// contains only SQLite work: callers must invoke a transport only after it
    /// returns and complete or fail the lease with the exact token below.
    public func leaseNextOutbox(
        now: Date = Date(),
        leaseDuration: TimeInterval
    ) async throws -> PersistedOutboxLease? {
        let nowTimestamp = try outboxTimestamp(now)
        let leaseExpiry = try outboxTimestamp(
            now.addingTimeInterval(try validOutboxInterval(leaseDuration, name: "lease duration"))
        )
        return try await withConnectionGate {
            try await transaction {
                let token = UUID()
                let rows = try await connection.query(
                    """
                    SELECT id, space_uri, author_did, revision, payload, attempts,
                           lease_token, lease_expires_at
                    FROM permissioned_space_outbox
                    WHERE available_at <= ?
                      AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                    ORDER BY available_at, created_at, id
                    LIMIT 1
                    """,
                    [.integer(nowTimestamp), .integer(nowTimestamp)]
                )
                guard let row = rows.first else { return nil }
                let event = try decodeOutboxEvent(row)
                _ = try decodeOutboxLease(row)
                _ = try await connection.query(
                    """
                    UPDATE permissioned_space_outbox
                    SET lease_token = ?, lease_expires_at = ?
                    WHERE id = ?
                    """,
                    [
                        .text(token.uuidString), .integer(leaseExpiry),
                        .text(event.id.uuidString),
                    ]
                )
                return PersistedOutboxLease(
                    event: event,
                    token: token,
                    expiresAt: Date(timeIntervalSince1970: Double(leaseExpiry) / 1_000_000)
                )
            }
        }
    }

    /// Deletes an event only if the caller still owns its durable lease. A
    /// stale worker can therefore never acknowledge an event reclaimed by a
    /// later worker after its lease expired.
    @discardableResult
    public func completeOutboxLease(
        eventID: UUID,
        token: UUID
    ) async throws -> Bool {
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT id, space_uri, author_did, revision, payload, attempts,
                           lease_token, lease_expires_at
                    FROM permissioned_space_outbox
                    WHERE id = ?
                    """,
                    [.text(eventID.uuidString)]
                )
                guard let row = rows.first else { return false }
                _ = try decodeOutboxEvent(row)
                let lease = try decodeOutboxLease(row)
                guard lease.token == token
                else {
                    return false
                }
                _ = try await connection.query(
                    "DELETE FROM permissioned_space_outbox WHERE id = ? AND lease_token = ?",
                    [.text(eventID.uuidString), .text(token.uuidString)]
                )
                return true
            }
        }
    }

    /// Records a failed delivery only while the same lease is current, then
    /// clears that lease and makes the opaque event eligible at `retryAt`.
    /// Returning `nil` means another worker reclaimed or completed the event.
    @discardableResult
    public func failOutboxLease(
        eventID: UUID,
        token: UUID,
        retryAt: Date
    ) async throws -> Int? {
        let retryTimestamp = try outboxTimestamp(retryAt)
        return try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT id, space_uri, author_did, revision, payload, attempts,
                           lease_token, lease_expires_at
                    FROM permissioned_space_outbox
                    WHERE id = ?
                    """,
                    [.text(eventID.uuidString)]
                )
                guard let row = rows.first else { return nil }
                let event = try decodeOutboxEvent(row)
                let lease = try decodeOutboxLease(row)
                guard lease.token == token
                else {
                    return nil
                }
                guard event.attempts < Int.max else {
                    throw SQLiteRepositoryError.corruptDatabase("outbox attempts overflow")
                }
                let nextAttempts = event.attempts + 1
                _ = try await connection.query(
                    """
                    UPDATE permissioned_space_outbox
                    SET attempts = ?, available_at = ?,
                        lease_token = NULL, lease_expires_at = NULL
                    WHERE id = ? AND lease_token = ?
                    """,
                    [
                        .integer(nextAttempts), .integer(retryTimestamp),
                        .text(eventID.uuidString), .text(token.uuidString),
                    ]
                )
                return nextAttempts
            }
        }
    }

    public func pendingOutbox(limit: Int = 100) async throws -> [PersistedOutboxEvent] {
        guard limit >= 0 else {
            throw SwanError.malformed("outbox limit must not be negative")
        }
        return try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT id, space_uri, author_did, revision, payload, attempts,
                       lease_token, lease_expires_at
                FROM permissioned_space_outbox
                ORDER BY created_at, id
                LIMIT ?
                """,
                [.integer(limit)]
            )
            return try rows.map { row in
                _ = try decodeOutboxLease(row)
                return try decodeOutboxEvent(row)
            }
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
        activeWriteTransactions += 1
        do {
            let result = try await body()
            _ = try await connection.query("COMMIT")
            activeWriteTransactions -= 1
            return result
        } catch {
            _ = try? await connection.query("ROLLBACK")
            activeWriteTransactions -= 1
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

    private func requireAuthorityAccount(
        space: SpaceURI,
        owner: String? = nil
    ) throws {
        guard space.authority == accountDID else {
            throw SwanError.unauthorized(
                "simple-space authority belongs to another account"
            )
        }
        if let owner {
            guard owner == space.authority,
                  isValidSimpleSpaceDID(owner)
            else {
                throw SwanError.unauthorized(
                    "only the authority DID may own this simple space"
                )
            }
        }
    }

    private func requireAuthorityManagement(
        space: SpaceURI,
        authorization: AuthorizationContext
    ) throws {
        try SpaceAuthorizationPolicy.require(
            space: space,
            author: space.authority,
            uri: nil,
            authorization: authorization,
            permission: .manage
        )
    }

    /// A credential request is made on behalf of its eventual reader. The
    /// authority must not allow an arbitrary authenticated account to mint a
    /// credential for a member merely by naming that member in the request.
    /// Service authentication is deliberately excluded: it is used only by
    /// the separately modeled managing-app decision endpoint.
    private func requireSimpleSpaceCredentialRequester(
        space: SpaceURI,
        user: String,
        authorization: AuthorizationContext
    ) throws {
        switch authorization {
        case let .accountOAuth(subject, _):
            guard subject == user else {
                throw SwanError.unauthorized(
                    "credential requester does not match the requested user"
                )
            }
        case let .spaceCredential(grant):
            guard grant.subject == user, grant.space == space else {
                throw SwanError.unauthorized(
                    "delegated credential does not match the requested user"
                )
            }
            try grant.allows(.read)
        case let .spaceSelfRead(subject, grantSpace):
            guard subject == user, grantSpace == space else {
                throw SwanError.unauthorized(
                    "self-read grant does not match the requested user"
                )
            }
        case .public, .service:
            throw SwanError.unauthorized(
                "credential issuance requires a user OAuth or delegated grant"
            )
        }
    }

    private func requireActiveSimpleSpace(
        _ state: DurableSimpleSpaceState
    ) throws {
        guard !state.space.isDeleted else {
            throw SwanError.unauthorized("space deleted")
        }
    }

    private func validateSimpleSpaceConfiguration(
        _ configuration: SimpleSpaceConfiguration
    ) throws {
        switch configuration.appAccess {
        case .open:
            break
        case let .allowList(clients):
            for client in clients {
                try validateSimpleSpaceAppIdentifier(client)
            }
        }
        switch configuration.policy {
        case .managingApp:
            guard let managingApp = configuration.managingApp else {
                throw SwanError.malformed("managing-app spaces require a managing app")
            }
            try validateSimpleSpaceAppIdentifier(managingApp)
        case .public, .memberList:
            guard configuration.managingApp == nil else {
                throw SwanError.malformed("only managing-app spaces may name a managing app")
            }
        }
    }

    private func validateSimpleSpaceAppIdentifier(
        _ identifier: String
    ) throws {
        guard !identifier.isEmpty,
              identifier.utf8.count <= 2_048,
              identifier.unicodeScalars.allSatisfy({
                  $0.value >= 0x20 && $0.value != 0x7F
              })
        else {
            throw SwanError.invalidIdentifier(identifier)
        }
    }

    /// `SpaceURI` intentionally keeps its lexical helpers file-private. Use
    /// its public throwing initializer as the one source of truth instead of
    /// copying a relaxed DID regular expression into the persistence layer.
    private func isValidSimpleSpaceDID(_ did: String) -> Bool {
        (try? SpaceURI(
            authority: did,
            spaceType: "app.swan.validation",
            skey: "did"
        )) != nil
    }

    private func simpleSpaceTimestamp(_ date: Date) throws -> Int {
        let microseconds = date.timeIntervalSince1970 * 1_000_000
        guard microseconds.isFinite,
              microseconds >= 0,
              microseconds <= Double(Int.max)
        else {
            throw SwanError.malformed("simple-space timestamp is out of range")
        }
        return Int(microseconds)
    }

    private func simpleSpaceAppAccessName(
        _ appAccess: SimpleSpaceAppAccess
    ) -> String {
        switch appAccess {
        case .open: "open"
        case .allowList: "allow-list"
        }
    }

    private func requiredSimpleSpace(
        _ space: SpaceURI
    ) async throws -> LoadedSimpleSpaceAuthority {
        guard let stored = try await loadSimpleSpace(space) else {
            throw SwanError.malformed("space not found")
        }
        return stored
    }

    private func loadSimpleSpace(
        _ expectedSpace: SpaceURI
    ) async throws -> LoadedSimpleSpaceAuthority? {
        let rows = try await connection.query(
            """
            SELECT space_uri, owner_did, policy, app_access, managing_app,
                   is_deleted, revision, created_at, updated_at
            FROM permissioned_simple_space_authorities
            WHERE space_uri = ?
            """,
            [.text(expectedSpace.rawValue)]
        )
        guard let row = rows.first else { return nil }
        guard rows.count == 1 else {
            throw SQLiteRepositoryError.corruptDatabase(
                "duplicate simple-space authority state"
            )
        }
        let spaceRaw = try requiredText(row, "space_uri")
        guard let space = try? SpaceURI(spaceRaw),
              space == expectedSpace,
              space.rawValue == spaceRaw,
              space.authority == accountDID
        else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space authority ownership"
            )
        }
        let owner = try requiredText(row, "owner_did")
        guard owner == space.authority, isValidSimpleSpaceDID(owner) else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space owner"
            )
        }
        let policyRaw = try requiredText(row, "policy")
        guard let policy = SimpleSpacePolicy(rawValue: policyRaw) else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space policy"
            )
        }
        let appAccessRaw = try requiredText(row, "app_access")
        guard appAccessRaw == "open" || appAccessRaw == "allow-list" else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space app access"
            )
        }
        let managingApp: String?
        if let value = row.column("managing_app"), !value.isNull {
            managingApp = try requiredText(row, "managing_app")
            try validateSimpleSpaceAppIdentifier(managingApp!)
        } else {
            managingApp = nil
        }
        let deleted = try requiredInteger(row, "is_deleted")
        guard deleted == 0 || deleted == 1 else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space deleted state"
            )
        }
        let revision = try requiredRevision(row, "revision")
        guard revision > 0 else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space revision"
            )
        }
        let createdAt = try requiredNonnegativeInteger(row, "created_at")
        let updatedAt = try requiredNonnegativeInteger(row, "updated_at")
        guard updatedAt >= createdAt else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space timestamps"
            )
        }

        let memberRows = try await connection.query(
            """
            SELECT member_did
            FROM permissioned_simple_space_members
            WHERE space_uri = ?
            ORDER BY member_did
            """,
            [.text(space.rawValue)]
        )
        var members = Set<String>()
        for memberRow in memberRows {
            let member = try requiredText(memberRow, "member_did")
            guard isValidSimpleSpaceDID(member), members.insert(member).inserted else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "invalid simple-space member"
                )
            }
        }

        let clientRows = try await connection.query(
            """
            SELECT client_id
            FROM permissioned_simple_space_clients
            WHERE space_uri = ?
            ORDER BY client_id
            """,
            [.text(space.rawValue)]
        )
        var clients = Set<String>()
        for clientRow in clientRows {
            let clientID = try requiredText(clientRow, "client_id")
            try validateSimpleSpaceAppIdentifier(clientID)
            guard clients.insert(clientID).inserted else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "duplicate simple-space client"
                )
            }
        }
        let appAccess: SimpleSpaceAppAccess
        switch appAccessRaw {
        case "open":
            guard clients.isEmpty else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "open simple space has client restrictions"
                )
            }
            appAccess = .open
        case "allow-list":
            appAccess = .allowList(clients)
        default:
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space app access"
            )
        }
        let configuration: SimpleSpaceConfiguration
        do {
            configuration = try SimpleSpaceConfiguration(
                policy: policy,
                appAccess: appAccess,
                managingApp: managingApp
            )
            try validateSimpleSpaceConfiguration(configuration)
        } catch {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space configuration"
            )
        }

        let managingDecisionRows = try await connection.query(
            """
            SELECT user_did
            FROM permissioned_simple_space_managing_app_decisions
            WHERE space_uri = ?
            ORDER BY user_did
            """,
            [.text(space.rawValue)]
        )
        var managingAppAllowedUsers = Set<String>()
        for decisionRow in managingDecisionRows {
            let user = try requiredText(decisionRow, "user_did")
            guard isValidSimpleSpaceDID(user),
                  managingAppAllowedUsers.insert(user).inserted
            else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "invalid simple-space managing-app decision"
                )
            }
        }
        guard policy == .managingApp || managingAppAllowedUsers.isEmpty else {
            throw SQLiteRepositoryError.corruptDatabase(
                "non-managing simple space has app decisions"
            )
        }
        let snapshot: SimpleSpace
        do {
            snapshot = try SimpleSpace(
                uri: space,
                owner: owner,
                configuration: configuration,
                members: members,
                isDeleted: deleted == 1
            )
        } catch {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid simple-space authority state"
            )
        }
        return LoadedSimpleSpaceAuthority(
            state: DurableSimpleSpaceState(space: snapshot, revision: revision),
            managingAppAllowedUsers: managingAppAllowedUsers
        )
    }

    private func replaceSimpleSpaceClients(
        space: SpaceURI,
        appAccess: SimpleSpaceAppAccess
    ) async throws {
        _ = try await connection.query(
            "DELETE FROM permissioned_simple_space_clients WHERE space_uri = ?",
            [.text(space.rawValue)]
        )
        guard case let .allowList(clients) = appAccess else { return }
        for clientID in clients.sorted() {
            _ = try await connection.query(
                "INSERT INTO permissioned_simple_space_clients(space_uri, client_id) VALUES (?, ?)",
                [.text(space.rawValue), .text(clientID)]
            )
        }
    }

    private func touchSimpleSpace(
        space: SpaceURI,
        revision: UInt64,
        timestamp: Int
    ) async throws {
        let nextRevision = try nextSimpleSpaceRevision(revision)
        _ = try await connection.query(
            """
            UPDATE permissioned_simple_space_authorities
            SET revision = ?,
                updated_at = CASE WHEN updated_at > ? THEN updated_at ELSE ? END
            WHERE space_uri = ?
            """,
            [
                .integer(try sqliteRevision(nextRevision)),
                .integer(timestamp), .integer(timestamp), .text(space.rawValue),
            ]
        )
    }

    private func nextSimpleSpaceRevision(_ revision: UInt64) throws -> UInt64 {
        guard revision < UInt64(Int.max) else {
            throw SQLiteRepositoryError.revisionOutOfRange(revision)
        }
        return revision + 1
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
        let revision = try requiredRevision(row, "revision")
        let wireRevision = try requiredTID(row, "wire_revision")
        let marker = try requiredBlob(row, "current_commit")
        let expectedMarker = try repositoryStateMarker(
            space: space,
            author: author,
            revision: revision,
            wireRevision: wireRevision,
            commitment: Data(SHA256.hash(data: ltHash))
        )
        guard marker == expectedMarker else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid deterministic repository state marker"
            )
        }
        return PersistedRepositoryState(
            space: space,
            author: author,
            revision: revision,
            wireRevision: wireRevision,
            ltHash: ltHash,
            commit: marker
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

    private func repositoryStateMarker(
        space: SpaceURI,
        author: String,
        revision: UInt64,
        wireRevision: TID,
        commitment: Data
    ) throws -> Data {
        guard revision <= UInt64(Int.max) else {
            throw SQLiteRepositoryError.revisionOutOfRange(revision)
        }
        return try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "author", value: author),
            (key: "commitment", value: commitment),
            (key: "revision", value: Int(revision)),
            (key: "space", value: space.rawValue),
            (key: "wireRevision", value: wireRevision.toString()),
        ]))
    }

    private func decodeOutboxEvent(
        _ row: SQLiteRow
    ) throws -> PersistedOutboxEvent {
        guard let id = row.column("id")?.string.flatMap(UUID.init(uuidString:)),
              let spaceRaw = row.column("space_uri")?.string,
              let author = row.column("author_did")?.string
        else {
            throw SQLiteRepositoryError.corruptDatabase("invalid outbox row")
        }
        guard author == accountDID,
              let space = try? SpaceURI(spaceRaw),
              space.rawValue == spaceRaw
        else {
            throw SQLiteRepositoryError.corruptDatabase("invalid outbox ownership")
        }
        let payload = try requiredBlob(row, "payload")
        guard payload == opaqueNotificationPayload(eventID: id) else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid opaque notification payload"
            )
        }
        return PersistedOutboxEvent(
            id: id,
            space: space,
            author: author,
            revision: try requiredRevision(row, "revision"),
            payload: payload,
            attempts: try requiredNonnegativeInteger(row, "attempts")
        )
    }

    private func decodeOutboxLease(
        _ row: SQLiteRow
    ) throws -> (token: UUID?, expiresAt: Int?) {
        let token = row.column("lease_token")
        let expiry = row.column("lease_expires_at")
        switch (token, expiry) {
        case (.some(.null), .some(.null)):
            return (nil, nil)
        case let (.some(.text(rawToken)), .some(.integer(rawExpiry))):
            guard let token = UUID(uuidString: rawToken), rawExpiry >= 0 else {
                throw SQLiteRepositoryError.corruptDatabase("invalid outbox lease")
            }
            return (token, rawExpiry)
        default:
            throw SQLiteRepositoryError.corruptDatabase("invalid outbox lease")
        }
    }

    private func validOutboxInterval(
        _ interval: TimeInterval,
        name: String
    ) throws -> TimeInterval {
        // Lease and retry scheduling are intentionally bounded. Long-lived
        // leases would turn a stopped worker into an avoidable availability
        // failure, while unbounded doubles could overflow SQLite timestamps.
        guard interval.isFinite, interval > 0, interval <= 86_400 else {
            throw SwanError.malformed("\(name) must be between zero and one day")
        }
        return interval
    }

    private func outboxTimestamp(_ date: Date) throws -> Int {
        let microseconds = date.timeIntervalSince1970 * 1_000_000
        guard microseconds.isFinite,
              microseconds >= 0,
              microseconds <= Double(Int.max)
        else {
            throw SwanError.malformed("outbox timestamp is out of range")
        }
        return Int(microseconds.rounded(.down))
    }

    private func opaqueNotificationPayload(eventID: UUID) -> Data {
        Data(eventID.uuidString.lowercased().utf8)
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

    private func requiredNonnegativeInteger(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> Int {
        let value = try requiredInteger(row, column)
        guard value >= 0 else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid \(column)"
            )
        }
        return value
    }

    private func requiredInteger(
        _ row: SQLiteRow,
        _ column: String
    ) throws -> Int {
        guard let value = row.column(column), case let .integer(integer) = value else {
            throw SQLiteRepositoryError.corruptDatabase(
                "invalid \(column)"
            )
        }
        return integer
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

/// Permissioned-repository facade backed solely by `SQLiteAccountDatabase`.
///
/// The actor holds immutable routing dependencies only; records, revisions,
/// oplog entries, and commit facts are read from SQLite for every operation.
/// Reader-specific commit envelopes are deliberately never persisted.
public actor DurableSpaceRepository {
    private let database: SQLiteAccountDatabase
    private let space: SpaceURI
    private let author: String

    public init(
        database: SQLiteAccountDatabase,
        space: SpaceURI,
        author: String
    ) throws {
        // Reuse the domain's strict DID grammar without fabricating any
        // repository state for this facade.
        _ = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.swan.repository",
            rkey: "state"
        )
        self.database = database
        self.space = space
        self.author = author
    }

    public func record(
        _ uri: SpaceRecordURI,
        authorization: AuthorizationContext
    ) async throws -> SpaceRecord? {
        try requireRepositoryURI(uri)
        try requireRead(uri: uri, authorization: authorization)
        return try await database.spaceRecord(uri).map(record(from:))
    }

    /// Applies one write with an exact SQLite revision CAS, a caller-selected
    /// replay key, and a monotonically advancing wire TID.
    public func apply(
        _ write: SpaceWrite,
        expectedRevision: UInt64,
        requestID: UUID,
        wireRevision: TID,
        authorization: AuthorizationContext
    ) async throws -> DurableSpaceOplogEntry {
        let entries = try await applyAtomically(
            [write],
            expectedRevision: expectedRevision,
            requestID: requestID,
            wireRevision: wireRevision,
            authorization: authorization
        )
        guard entries.count == 1, let entry = entries.first else {
            throw SQLiteRepositoryError.corruptDatabase(
                "single repository write produced an invalid oplog result"
            )
        }
        return entry
    }

    /// Preflights every write against a mutable copy of one expected SQLite
    /// snapshot, then hands the same expected revision to SQLite for the
    /// authoritative CAS. The mutable copy gives an atomic create → update or
    /// create → delete batch the same permission and LtHash semantics SQLite
    /// will commit, while the source of that copy remains the expected durable
    /// snapshot rather than facade-owned repository state.
    public func applyAtomically(
        _ writes: [SpaceWrite],
        expectedRevision: UInt64,
        requestID: UUID,
        wireRevision: TID,
        authorization: AuthorizationContext
    ) async throws -> [DurableSpaceOplogEntry] {
        guard !writes.isEmpty else { return [] }
        guard expectedRevision < UInt64(Int.max) else {
            throw SQLiteRepositoryError.revisionOutOfRange(expectedRevision)
        }

        let snapshot = try await database.repositorySnapshot(
            space: space,
            author: author
        )
        let actualRevision = snapshot?.state.revision ?? 0
        guard actualRevision == expectedRevision else {
            throw SwanError.conflict(expected: expectedRevision, actual: actualRevision)
        }
        let finalRevision = expectedRevision + 1

        var expectedRecords: [SpaceRecordURI: PersistedSpaceRecord] = [:]
        for record in snapshot?.records ?? [] {
            expectedRecords[record.uri] = record
        }
        var nextLtHash = try LtHash(
            serialized: snapshot?.state.ltHash
                ?? Data(repeating: 0, count: LtHash.byteCount)
        )
        var sqliteWrites: [SQLiteSpaceWrite] = []

        for write in writes {
            let uri = uri(for: write)
            try requireRepositoryURI(uri)
            let expectedRecord = expectedRecords[uri]
            switch write {
            case let .put(uri, value):
                let permission: SpacePermission = expectedRecord == nil ? .create : .update
                try requireWrite(
                    uri: uri,
                    authorization: authorization,
                    permission: permission
                )
                let cid = CID.fromDAGCBOR(value).string
                if let expectedRecord {
                    nextLtHash.remove(element: ltHashElement(for: expectedRecord))
                }
                nextLtHash.add(element: "\(uri.collection)/\(uri.rkey)/\(cid)")
                sqliteWrites.append(.put(uri: uri, value: value, cid: cid))
                expectedRecords[uri] = PersistedSpaceRecord(
                    uri: uri,
                    value: value,
                    cid: cid,
                    revision: finalRevision
                )
            case let .delete(uri):
                try requireWrite(
                    uri: uri,
                    authorization: authorization,
                    permission: .delete
                )
                guard let expectedRecord else {
                    throw SwanError.malformed("cannot delete a missing record")
                }
                nextLtHash.remove(element: ltHashElement(for: expectedRecord))
                sqliteWrites.append(.delete(uri: uri))
                expectedRecords.removeValue(forKey: uri)
            }
        }

        let eventID = UUID()
        let persisted = try await database.apply(
            space: space,
            author: author,
            expectedRevision: expectedRevision,
            requestID: requestID,
            wireRevision: wireRevision,
            writes: sqliteWrites,
            eventID: eventID
        )
        return persisted.entries.map(oplogEntry(from:))
    }

    /// Returns ordered incremental operations when retained, or a durable full
    /// snapshot after an oplog gap. Recovery only reads SQLite; it does not
    /// mutate or replace local repository state.
    public func sync(
        since requestedRevision: UInt64,
        authorization: AuthorizationContext
    ) async throws -> DurableSpaceSyncResponse {
        try requireRead(uri: nil, authorization: authorization)
        switch try await database.spaceOplog(
            space: space,
            author: author,
            since: requestedRevision
        ) {
        case let .incremental(entries):
            return .incremental(entries.map(oplogEntry(from:)))
        case let .fullRecoveryRequired(snapshot):
            return .fullSnapshot(
                revision: snapshot.state.revision,
                records: snapshot.records.map(record(from:)),
                commitment: snapshot.state.commitment
            )
        }
    }

    public func currentState(
        authorization: AuthorizationContext
    ) async throws -> DurableSpaceRepositoryState {
        try requireRead(uri: nil, authorization: authorization)
        let snapshot = try await database.repositorySnapshot(
            space: space,
            author: author
        )
        if let snapshot {
            return state(from: snapshot.state)
        }
        let ltHash = LtHash()
        return DurableSpaceRepositoryState(
            space: space,
            author: author,
            revision: 0,
            wireRevision: nil,
            ltHash: ltHash.serialized,
            commitment: ltHash.commitment
        )
    }

    public func snapshot(
        authorization: AuthorizationContext
    ) async throws -> [SpaceRecord] {
        try requireRead(uri: nil, authorization: authorization)
        return try await database.repositorySnapshot(
            space: space,
            author: author
        )?.records.map(record(from:)) ?? []
    }

    /// Builds a new, reader-specific commit envelope and complete CAR for each
    /// request. SQLite holds a deterministic state marker only, never IKM,
    /// context signatures, or reader content bindings.
    public func exportCAR(
        rev: String,
        signingKey: P256.Signing.PrivateKey,
        authorization: AuthorizationContext
    ) async throws -> SpaceCAR {
        try requireRead(uri: nil, authorization: authorization)
        let snapshot = try await database.repositorySnapshot(
            space: space,
            author: author
        )
        let ltHash = try LtHash(
            serialized: snapshot?.state.ltHash
                ?? Data(repeating: 0, count: LtHash.byteCount)
        )
        let commit = try SpaceCommitCodec.createReaderEnvelope(
            space: space,
            author: author,
            rev: rev,
            commitment: ltHash.commitment,
            key: signingKey
        )
        return try SpaceCARCodec.encode(
            commit: commit,
            records: snapshot?.records.map(record(from:)) ?? []
        )
    }

    private func requireRepositoryURI(_ uri: SpaceRecordURI) throws {
        guard uri.space == space, uri.author == author else {
            throw SwanError.unauthorized("record belongs to another repository")
        }
    }

    private func requireRead(
        uri: SpaceRecordURI?,
        authorization: AuthorizationContext
    ) throws {
        try SpaceAuthorizationPolicy.require(
            space: space,
            author: author,
            uri: uri,
            authorization: authorization,
            permission: .read
        )
    }

    private func requireWrite(
        uri: SpaceRecordURI,
        authorization: AuthorizationContext,
        permission: SpacePermission
    ) throws {
        if case .service = authorization {
            throw SwanError.unauthorized(
                "service authentication cannot write a permissioned repository"
            )
        }
        try SpaceAuthorizationPolicy.require(
            space: space,
            author: author,
            uri: uri,
            authorization: authorization,
            permission: permission
        )
    }

    private func uri(for write: SpaceWrite) -> SpaceRecordURI {
        switch write {
        case let .put(uri, _), let .delete(uri): uri
        }
    }

    private func record(from persisted: PersistedSpaceRecord) -> SpaceRecord {
        SpaceRecord(
            uri: persisted.uri,
            value: persisted.value,
            cid: persisted.cid,
            revision: persisted.revision
        )
    }

    private func oplogEntry(
        from persisted: PersistedSpaceOplogEntry
    ) -> DurableSpaceOplogEntry {
        let write: SpaceWrite
        switch persisted.write {
        case let .put(uri, value, _):
            write = .put(uri: uri, value: value)
        case let .delete(uri):
            write = .delete(uri: uri)
        }
        return DurableSpaceOplogEntry(
            cursor: persisted.cursor,
            wireRevision: persisted.wireRevision,
            action: persisted.action,
            write: write,
            cid: persisted.cid,
            previousCID: persisted.previousCID,
            commitment: persisted.commitment
        )
    }

    private func state(from persisted: PersistedRepositoryState) -> DurableSpaceRepositoryState {
        DurableSpaceRepositoryState(
            space: persisted.space,
            author: persisted.author,
            revision: persisted.revision,
            wireRevision: persisted.wireRevision,
            ltHash: persisted.ltHash,
            commitment: persisted.commitment
        )
    }

    private func ltHashElement(for record: PersistedSpaceRecord) -> String {
        "\(record.uri.collection)/\(record.uri.rkey)/\(record.cid)"
    }
}

/// SQLite-backed `com.atproto.simplespace` authority facade. It retains no
/// authority, membership, client, or managing-app decisions in actor memory:
/// every operation delegates to the authority account database. A member's
/// repository can still be hosted in a different account database; this
/// facade simply refuses to create authority state anywhere but the DID named
/// by `SpaceURI.authority`.
public actor DurableSimpleSpaceAuthority {
    private let database: SQLiteAccountDatabase
    private let credentials: HMACSpaceCredentialAuthority

    public init(
        database: SQLiteAccountDatabase,
        credentialSecret: Data
    ) throws {
        guard credentialSecret.count >= 16 else {
            throw SwanError.malformed("simple-space credential secret is too short")
        }
        self.database = database
        credentials = HMACSpaceCredentialAuthority(key: credentialSecret)
    }

    public func create(
        space: SpaceURI,
        owner: String,
        configuration: SimpleSpaceConfiguration,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try await database.createSimpleSpace(
            space: space,
            owner: owner,
            configuration: configuration,
            authorization: authorization,
            now: now
        )
    }

    public func space(
        _ space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws -> DurableSimpleSpaceState? {
        try await database.simpleSpace(space, authorization: authorization)
    }

    public func update(
        space: SpaceURI,
        configuration: SimpleSpaceConfiguration,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try await database.updateSimpleSpace(
            space: space,
            configuration: configuration,
            authorization: authorization,
            now: now
        )
    }

    public func addMember(
        space: SpaceURI,
        member: String,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try await database.addSimpleSpaceMember(
            space: space,
            member: member,
            authorization: authorization,
            now: now
        )
    }

    public func removeMember(
        space: SpaceURI,
        member: String,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try await database.removeSimpleSpaceMember(
            space: space,
            member: member,
            authorization: authorization,
            now: now
        )
    }

    public func setClientAccess(
        space: SpaceURI,
        clientID: String,
        allowed: Bool,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try await database.setSimpleSpaceClientAccess(
            space: space,
            clientID: clientID,
            allowed: allowed,
            authorization: authorization,
            now: now
        )
    }

    public func setManagingAppAccess(
        space: SpaceURI,
        user: String,
        allowed: Bool,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try await database.setSimpleSpaceManagingAppAccess(
            space: space,
            user: user,
            allowed: allowed,
            authorization: authorization,
            now: now
        )
    }

    public func delete(
        space: SpaceURI,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try await database.deleteSimpleSpace(
            space: space,
            authorization: authorization,
            now: now
        )
    }

    /// Credentials remain transient reader artifacts. SQLite records the
    /// policy facts that permitted issuance, never the credential envelope,
    /// nonce, MAC, or its two-hour expiry.
    public func issueReadCredential(
        space: SpaceURI,
        user: String,
        clientID: String?,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> SignedSpaceCredential {
        try await database.authorizeSimpleSpaceRead(
            space: space,
            user: user,
            clientID: clientID,
            authorization: authorization
        )
        let grant = SpaceGrant(
            subject: user,
            space: space,
            permissions: [.read],
            expiresAt: now.addingTimeInterval(2 * 60 * 60),
            clientID: clientID
        )
        return try credentials.issue(SpaceCredential(grant: grant, issuedAt: now))
    }
}
