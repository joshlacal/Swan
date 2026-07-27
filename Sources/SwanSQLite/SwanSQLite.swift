import Crypto
import Foundation
import Petrel
import SQLiteNIO
import SwanCore
import SwanPublicRepository
import SwanSpaces
import SwanStorage

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

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
            refresh_token_allowed INTEGER NOT NULL DEFAULT 1 CHECK(refresh_token_allowed IN (0, 1)),
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
            refresh_token_allowed INTEGER NOT NULL DEFAULT 1 CHECK(refresh_token_allowed IN (0, 1)),
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
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_delegation_replays (
            jti_digest BLOB PRIMARY KEY CHECK(length(jti_digest) = 32),
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

    /// Authority-owned `com.atproto.simplespace` facts. These stay in the
    /// authority's account database, never in a member repository database or
    /// the cross-account control store. Keep these statements together because
    /// the v3 schema migration must rebuild the parent and all FK children as
    /// one unit when relaxing the original policy/managing-app CHECK.
    static let simpleSpaceAuthoritySchemaStatements = [
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
            CHECK(managing_app IS NULL OR length(managing_app) > 0)
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
    ]

    /// The authority-owned synchronisation registry. These rows contain only
    /// DIDs, TIDs, LtHash commitments, opaque service-event IDs, and delivery
    /// endpoints. They never contain a record CID/value, CAR, credential, or
    /// private blob reference. Keep this separate from the member tables:
    /// writer discovery is explicitly not an access-control list.
    static let spaceNotificationSchemaStatements = [
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_writers (
            space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
            repo_did TEXT NOT NULL,
            wire_revision TEXT NOT NULL,
            commitment BLOB NOT NULL CHECK(length(commitment) = 32),
            updated_at INTEGER NOT NULL CHECK(updated_at >= 0),
            PRIMARY KEY(space_uri, repo_did)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_notification_registrations (
            space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
            endpoint TEXT NOT NULL,
            repo_did TEXT,
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
            updated_at INTEGER NOT NULL CHECK(updated_at >= 0),
            PRIMARY KEY(space_uri, endpoint),
            CHECK(length(endpoint) > 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_notification_receipts (
            issuer TEXT NOT NULL,
            event_id TEXT NOT NULL,
            space_uri TEXT NOT NULL,
            received_at INTEGER NOT NULL CHECK(received_at >= 0),
            PRIMARY KEY(issuer, event_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_recipient_tombstones (
            space_uri TEXT PRIMARY KEY,
            authority_did TEXT NOT NULL,
            deletion_event_id TEXT NOT NULL,
            closed_at INTEGER NOT NULL CHECK(closed_at >= 0)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS permissioned_space_notification_fanout (
            id TEXT PRIMARY KEY,
            source_issuer TEXT NOT NULL,
            source_event_id TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('write', 'deleted')),
            space_uri TEXT NOT NULL,
            repo_did TEXT,
            wire_revision TEXT,
            commitment BLOB,
            endpoint TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            available_at INTEGER NOT NULL CHECK(available_at >= 0),
            lease_token TEXT,
            lease_expires_at INTEGER,
            UNIQUE(source_issuer, source_event_id, kind, endpoint),
            CHECK(
                (kind = 'write' AND repo_did IS NOT NULL AND wire_revision IS NOT NULL
                    AND commitment IS NOT NULL AND length(commitment) = 32)
                OR (kind = 'deleted' AND repo_did IS NULL AND wire_revision IS NULL
                    AND commitment IS NULL)
            ),
            CHECK(
                (lease_token IS NULL AND lease_expires_at IS NULL)
                OR (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL
                    AND lease_expires_at >= 0)
            )
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS permissioned_space_writers_page
        ON permissioned_space_writers(space_uri, repo_did)
        """,
        """
        CREATE INDEX IF NOT EXISTS permissioned_space_notification_fanout_available
        ON permissioned_space_notification_fanout(available_at, created_at, id)
        """,
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
        CREATE TABLE IF NOT EXISTS public_repository_genesis (
            did TEXT PRIMARY KEY,
            revision TEXT NOT NULL,
            commit_cid TEXT NOT NULL,
            car BLOB NOT NULL,
            installed_at INTEGER NOT NULL CHECK(installed_at >= 0)
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
    ] + simpleSpaceAuthoritySchemaStatements + [
        """
        CREATE TABLE IF NOT EXISTS blob_payloads (
            cid TEXT PRIMARY KEY,
            -- `payload` is retained only to migrate pre-CAS rows. New rows
            -- carry a zero-length marker and are read from a private file.
            payload BLOB NOT NULL,
            storage_kind TEXT NOT NULL DEFAULT 'legacy-sqlite'
                CHECK(storage_kind IN ('legacy-sqlite', 'cas-v1')),
            -- Physical CAS lifecycle/reclamation is keyed by this digest,
            -- not the logical CID. A legacy sha256 label and CIDv1/raw label
            -- can legitimately name the same immutable file.
            cas_digest TEXT CHECK(cas_digest IS NULL OR length(cas_digest) = 64),
            byte_count INTEGER CHECK(byte_count >= 0),
            mime_type TEXT
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
        // This table deliberately outlives `blob_payloads` while a private
        // file is pending reclamation.  SQLite commits reachability changes
        // before any unlink; startup can then complete a crash-interrupted
        // unlink without ever restoring a reference to a missing file.
        """
        CREATE TABLE IF NOT EXISTS blob_cas_lifecycle (
            cid TEXT PRIMARY KEY,
            state TEXT NOT NULL CHECK(state IN ('creating', 'ready', 'reclaiming')),
            updated_at INTEGER NOT NULL CHECK(updated_at >= 0)
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
    case create(uri: SpaceRecordURI, value: Data, cid: String)
    case put(uri: SpaceRecordURI, value: Data, cid: String)
    case update(uri: SpaceRecordURI, value: Data, cid: String)
    case delete(uri: SpaceRecordURI)

    fileprivate var uri: SpaceRecordURI {
        switch self {
        case let .create(uri, _, _), let .put(uri, _, _),
             let .update(uri, _, _), let .delete(uri): uri
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

/// One wire-shaped permissioned oplog entry.  Unlike the write-side durable
/// entry, `value` is the live-record join result: it is absent when a later
/// write superseded this operation or when the caller requested metadata
/// only.  Historic oplog values never escape through this projection.
public struct PersistedWireOplogEntry: Sendable, Equatable {
    public let wireRevision: TID
    public let action: PersistedRepoAction
    public let uri: SpaceRecordURI
    public let cid: String?
    public let previousCID: String?
    public let value: Data?

    public init(
        wireRevision: TID,
        action: PersistedRepoAction,
        uri: SpaceRecordURI,
        cid: String?,
        previousCID: String?,
        value: Data?
    ) {
        self.wireRevision = wireRevision
        self.action = action
        self.uri = uri
        self.cid = cid
        self.previousCID = previousCID
        self.value = value
    }
}

/// Read-only result for the wire-TID incremental-sync surface.  The recovery
/// branch intentionally carries no snapshot so a caller cannot accidentally
/// turn `listRepoOps` into a full-repository export.
public enum PersistedWireOplogRead: Sendable, Equatable {
    case incremental(state: PersistedRepositoryState?, entries: [PersistedWireOplogEntry])
    case fullRecoveryRequired
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

/// A durable authority fanout intent. It is deliberately independent from
/// the writer PDS outbox: the former is created while accepting an incoming
/// service announcement, whereas the latter is created atomically with a
/// local repository commit. Neither carries any permissioned record content.
public struct PersistedSpaceNotificationFanout: Sendable, Equatable {
    public enum Kind: String, Sendable, Equatable {
        case write
        case deleted
    }

    public let id: UUID
    public let sourceIssuer: String
    public let sourceEventID: String
    public let kind: Kind
    public let space: SpaceURI
    public let repository: String?
    public let wireRevision: String?
    public let commitment: Data?
    public let endpoint: String
    public let attempts: Int

    public init(
        id: UUID,
        sourceIssuer: String,
        sourceEventID: String,
        kind: Kind,
        space: SpaceURI,
        repository: String?,
        wireRevision: String?,
        commitment: Data?,
        endpoint: String,
        attempts: Int
    ) {
        self.id = id
        self.sourceIssuer = sourceIssuer
        self.sourceEventID = sourceEventID
        self.kind = kind
        self.space = space
        self.repository = repository
        self.wireRevision = wireRevision
        self.commitment = commitment
        self.endpoint = endpoint
        self.attempts = attempts
    }
}

/// A lease for one authority fanout intent. The endpoint is exposed only to a
/// transport after it has been validated by that transport's SSRF policy; it
/// is never rendered by a public XRPC response or stored in an error string.
public struct PersistedSpaceNotificationFanoutLease: Sendable, Equatable {
    public let event: PersistedSpaceNotificationFanout
    public let token: UUID
    public let expiresAt: Date

    public init(event: PersistedSpaceNotificationFanout, token: UUID, expiresAt: Date) {
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

/// `flock` coordinates distinct processes, but advisory file locks do not
/// reliably block independently opened descriptors in the same process on all
/// supported platforms.  Keep a keyed async gate as the in-process half of
/// the blob lifecycle lock.  Each operation takes at most one key, so this
/// cannot form a lock-order cycle with SQLite's single writer.
private actor SQLiteBlobLifecycleCoordinator {
    struct Key: Hashable, Sendable {
        let dataDirectory: String
        let accountNamespace: String
        let digestHex: String
    }

    private var held: Set<Key> = []
    private var waiters: [Key: [CheckedContinuation<Void, Never>]] = [:]

    func acquire(_ key: Key) async {
        guard !held.contains(key) else {
            await withCheckedContinuation { waiters[key, default: []].append($0) }
            return
        }
        held.insert(key)
    }

    func release(_ key: Key) {
        guard let next = waiters[key]?.first else {
            held.remove(key)
            return
        }
        waiters[key]?.removeFirst()
        if waiters[key]?.isEmpty == true {
            waiters.removeValue(forKey: key)
        }
        next.resume()
    }
}

private let sqliteBlobLifecycleCoordinator = SQLiteBlobLifecycleCoordinator()

struct SQLiteTestingHooks: Sendable {
    var beforeApplyCommit: (@Sendable () async throws -> Void)?
    var afterSnapshotStateRead: (@Sendable () async -> Void)?
    var beforeBlobReferenceCommit: (@Sendable () async throws -> Void)?
    var beforeLegacyBlobMigrationCommit: (@Sendable () async throws -> Void)?
    var afterBlobReclaimCommit: (@Sendable () async throws -> Void)?

    init(
        beforeApplyCommit: (@Sendable () async throws -> Void)? = nil,
        afterSnapshotStateRead: (@Sendable () async -> Void)? = nil,
        beforeBlobReferenceCommit: (@Sendable () async throws -> Void)? = nil,
        beforeLegacyBlobMigrationCommit: (@Sendable () async throws -> Void)? = nil,
        afterBlobReclaimCommit: (@Sendable () async throws -> Void)? = nil
    ) {
        self.beforeApplyCommit = beforeApplyCommit
        self.afterSnapshotStateRead = afterSnapshotStateRead
        self.beforeBlobReferenceCommit = beforeBlobReferenceCommit
        self.beforeLegacyBlobMigrationCommit = beforeLegacyBlobMigrationCommit
        self.afterBlobReclaimCommit = afterBlobReclaimCommit
    }
}

private struct LoadedSimpleSpaceAuthority: Sendable {
    let state: DurableSimpleSpaceState
    let managingAppAllowedUsers: Set<String>
}

/// The concrete SQLite/WAL boundary. Its actor is a coordination aid, while
/// `BEGIN IMMEDIATE` makes the oplog/outbox write atomic even if another Swan
/// process later opens the same file.
public actor SQLiteAccountDatabase: BlobStore, PublicRepositoryGenesisStore {
    private static let permissionedRepositoryStorageMigrationVersion = 1
    private static let permissionedOutboxLeaseMigrationVersion = 2
    private static let simpleSpaceAuthoritySchemaMigrationVersion = 3
    private static let fileBackedBlobSchemaMigrationVersion = 4
    private static let fileBackedBlobLifecycleMigrationVersion = 5
    private static let physicalBlobCASLifecycleMigrationVersion = 6

    private let connection: SQLiteConnection
    private let connectionGate = SQLiteConnectionGate()
    private let dataDirectory: URL
    private let accountDID: String
    private let oplogRetention: Int
    private var accountDirectoryDescriptor: Int32
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
        let rootDescriptor = try SQLiteProtectedPaths.openRoot(dataDirectory)
        let accountDescriptor: Int32
        do {
            accountDescriptor = try SQLiteProtectedPaths.openAccountDirectory(
                rootDescriptor: rootDescriptor,
                did: did
            )
        } catch {
            SQLiteProtectedPaths.closeDirectory(rootDescriptor)
            throw error
        }
        let databasePath: String
        do {
            databasePath = try SQLiteProtectedPaths.openDatabaseFile(
                parentDescriptor: accountDescriptor,
                name: "\(Hex.encode(SHA256.hash(data: Data(did.utf8)))).sqlite",
                resolvedPath: SQLiteLayout.accountDatabase(in: dataDirectory, did: did)
                    .standardizedFileURL.path
            )
        } catch {
            SQLiteProtectedPaths.closeDirectory(accountDescriptor)
            SQLiteProtectedPaths.closeDirectory(rootDescriptor)
            throw error
        }
        // The account directory descriptor remains live for the database
        // lifetime. SQLite opens a revalidated absolute path because macOS
        // does not support SQLite paths through `/dev/fd`; its owner-only
        // parent directory prevents another local user from swapping it.
        SQLiteProtectedPaths.closeDirectory(rootDescriptor)
        self.dataDirectory = dataDirectory.standardizedFileURL
        self.accountDID = did
        self.oplogRetention = oplogRetention
        let openedConnection: SQLiteConnection
        do {
            openedConnection = try await SQLiteConnection.open(storage: .file(path: databasePath))
        } catch {
            SQLiteProtectedPaths.closeDirectory(accountDescriptor)
            throw error
        }
        connection = openedConnection
        accountDirectoryDescriptor = accountDescriptor
        do {
            try await migrateWithoutGate()
            try await recoverPrivateBlobLifecycle()
            try SQLiteProtectedPaths.hardenSQLiteFiles(
                parentDescriptor: accountDescriptor,
                databaseName: "\(Hex.encode(SHA256.hash(data: Data(did.utf8)))).sqlite"
            )
        } catch {
            try? await openedConnection.close()
            SQLiteProtectedPaths.closeDirectory(accountDescriptor)
            throw error
        }
    }

    /// Service lifecycle owns shutdown explicitly; deinit cannot safely launch
    /// a task that captures an actor instance under Swift 6 isolation rules.
    public func close() async throws {
        try await withConnectionGate {
            let descriptor = accountDirectoryDescriptor
            accountDirectoryDescriptor = -1
            defer { SQLiteProtectedPaths.closeDirectory(descriptor) }
            try await connection.close()
        }
    }

    public func migrate() async throws {
        try await withConnectionGate {
            try await migrateWithoutGate()
        }
        try await recoverPrivateBlobLifecycle()
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
            try await migrateFileBackedBlobSchemaIfNeeded()
            try await migrateFileBackedBlobLifecycleIfNeeded()
            try await migratePhysicalBlobCASLifecycleIfNeeded()
        }
        // SQLite cannot replace a CHECK constraint in place. This migration
        // rebuilds the simple-space parent and its FK children after the base
        // schema transaction so foreign-key enforcement can be disabled only
        // for that tightly scoped copy.
        try await migrateSimpleSpaceAuthoritySchemaIfNeeded()
        // These tables reference the current v3 authority parent. Install
        // them only after any old simple-space parent has been rebuilt; doing
        // it in the base transaction would make SQLite retarget their foreign
        // keys to the temporary v2 parent during an upgrade.
        try await transaction {
            for statement in SQLiteLayout.spaceNotificationSchemaStatements {
                _ = try await connection.query(statement)
            }
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

    /// Adds only metadata to the existing blob table.  Historical bodies stay
    /// in their legacy column until an authorized compatibility read can stage
    /// and commit them into the private CAS.  This avoids a startup-wide read
    /// of potentially very large blobs and, importantly, never changes their
    /// namespace reachability while migrating storage media.
    private func migrateFileBackedBlobSchemaIfNeeded() async throws {
        let version = Self.fileBackedBlobSchemaMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        try await addAccountColumnIfMissing(
            table: "blob_payloads",
            column: "storage_kind",
            definition: "TEXT NOT NULL DEFAULT 'legacy-sqlite'"
        )
        try await addAccountColumnIfMissing(
            table: "blob_payloads",
            column: "byte_count",
            definition: "INTEGER"
        )
        try await addAccountColumnIfMissing(
            table: "blob_payloads",
            column: "mime_type",
            definition: "TEXT"
        )

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

    /// Enrolls already-file-backed v4 rows in the durable lifecycle ledger
    /// without reading a single legacy BLOB.  Legacy rows are deliberately
    /// absent until an authorized compatibility read validates that exact
    /// payload and starts its one-CID lifecycle.
    private func migrateFileBackedBlobLifecycleIfNeeded() async throws {
        let version = Self.fileBackedBlobLifecycleMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        let timestamp = Int(Date().timeIntervalSince1970 * 1_000_000)
        let lifecycleColumns = try await connection.query(
            "PRAGMA table_info(blob_cas_lifecycle)"
        )
        // A repaired/current database may already have the v6 physical-digest
        // table while a manually restored migration marker is absent. Do not
        // attempt a legacy-CID insert into that newer shape; v6 below will
        // validate/reconcile it.
        guard lifecycleColumns.contains(where: { $0.column("name")?.string == "cid" }) else {
            _ = try await connection.query(
                """
                INSERT INTO permissioned_repository_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                [.integer(version), .integer(timestamp)]
            )
            return
        }
        _ = try await connection.query(
            """
            INSERT INTO blob_cas_lifecycle(cid, state, updated_at)
            SELECT cid, 'ready', ?
            FROM blob_payloads
            WHERE storage_kind = 'cas-v1'
            ON CONFLICT(cid) DO NOTHING
            """,
            [.integer(timestamp)]
        )
        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [.integer(version), .integer(timestamp)]
        )
    }

    /// v5 keyed lifecycle rows by logical CID. That is insufficient because
    /// the legacy `sha256:<digest>` compatibility name and the canonical raw
    /// CID can name one physical CAS file. v6 records the digest beside every
    /// CAS metadata row and rebuilds the lifecycle ledger around that physical
    /// identity, without selecting any payload BLOB.
    private func migratePhysicalBlobCASLifecycleIfNeeded() async throws {
        let version = Self.physicalBlobCASLifecycleMigrationVersion
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(version)]
        )
        guard applied.isEmpty else { return }

        try await addAccountColumnIfMissing(
            table: "blob_payloads",
            column: "cas_digest",
            definition: "TEXT"
        )

        let casRows = try await connection.query(
            "SELECT cid, cas_digest FROM blob_payloads WHERE storage_kind = 'cas-v1'"
        )
        var activeDigests = Set<String>()
        for row in casRows {
            let cid = try requiredText(row, "cid")
            let digest: String
            do {
                digest = try blobDigestHex(cid: cid, allowLegacy: true)
            } catch {
                throw SQLiteRepositoryError.corruptDatabase("invalid CAS blob CID")
            }
            if let stored = row.column("cas_digest"), !stored.isNull {
                guard stored.string == digest else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "CAS blob digest does not match CID"
                    )
                }
            }
            _ = try await connection.query(
                "UPDATE blob_payloads SET cas_digest = ? WHERE cid = ?",
                [.text(digest), .text(cid)]
            )
            activeDigests.insert(digest)
        }

        let lifecycleColumns = try await connection.query(
            "PRAGMA table_info(blob_cas_lifecycle)"
        )
        let hasLegacyCIDKey = lifecycleColumns.contains {
            $0.column("name")?.string == "cid"
        }
        var lifecycleByDigest: [String: BlobCASLifecycleState] = [:]
        if hasLegacyCIDKey {
            let lifecycleRows = try await connection.query(
                "SELECT cid, state FROM blob_cas_lifecycle"
            )
            for row in lifecycleRows {
                let cid = try requiredText(row, "cid")
                let digest: String
                do {
                    digest = try blobDigestHex(cid: cid, allowLegacy: true)
                } catch {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "invalid legacy CAS lifecycle CID"
                    )
                }
                guard let state = BlobCASLifecycleState(
                    rawValue: try requiredText(row, "state")
                ) else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "invalid legacy CAS lifecycle state"
                    )
                }
                lifecycleByDigest[digest] = lifecycleByDigest[digest] ?? state
            }
        } else {
            let lifecycleRows = try await connection.query(
                "SELECT digest_hex, state FROM blob_cas_lifecycle"
            )
            for row in lifecycleRows {
                let digest = try requiredText(row, "digest_hex")
                guard legacyBlobDigest("sha256:\(digest)") != nil,
                      let state = BlobCASLifecycleState(
                          rawValue: try requiredText(row, "state")
                      )
                else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "invalid CAS lifecycle row"
                    )
                }
                lifecycleByDigest[digest] = state
            }
        }

        // A durable CAS metadata row always wins over a stale reclaiming
        // intent. Conversely, an old ready/creating row with no metadata is
        // conservatively reclaimed on the next startup.
        for digest in activeDigests {
            lifecycleByDigest[digest] = .ready
        }
        let inactiveLifecycleDigests = lifecycleByDigest.keys.filter {
            !activeDigests.contains($0)
        }
        for digest in inactiveLifecycleDigests {
            lifecycleByDigest[digest] = .reclaiming
        }

        if hasLegacyCIDKey {
            _ = try await connection.query(
                """
                CREATE TABLE blob_cas_lifecycle_v6 (
                    digest_hex TEXT PRIMARY KEY CHECK(length(digest_hex) = 64),
                    state TEXT NOT NULL CHECK(state IN ('creating', 'ready', 'reclaiming')),
                    updated_at INTEGER NOT NULL CHECK(updated_at >= 0)
                )
                """
            )
            let timestamp = Int(Date().timeIntervalSince1970 * 1_000_000)
            for (digest, state) in lifecycleByDigest {
                _ = try await connection.query(
                    """
                    INSERT INTO blob_cas_lifecycle_v6(digest_hex, state, updated_at)
                    VALUES (?, ?, ?)
                    """,
                    [.text(digest), .text(state.rawValue), .integer(timestamp)]
                )
            }
            _ = try await connection.query("DROP TABLE blob_cas_lifecycle")
            _ = try await connection.query(
                "ALTER TABLE blob_cas_lifecycle_v6 RENAME TO blob_cas_lifecycle"
            )
        } else {
            let timestamp = Int(Date().timeIntervalSince1970 * 1_000_000)
            _ = try await connection.query("DELETE FROM blob_cas_lifecycle")
            for (digest, state) in lifecycleByDigest {
                _ = try await connection.query(
                    """
                    INSERT INTO blob_cas_lifecycle(digest_hex, state, updated_at)
                    VALUES (?, ?, ?)
                    """,
                    [.text(digest), .text(state.rawValue), .integer(timestamp)]
                )
            }
        }

        _ = try await connection.query(
            """
            INSERT INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [.integer(version), .integer(Int(Date().timeIntervalSince1970 * 1_000_000))]
        )
    }

    /// Replaces the original schema constraint which tied `managing_app` to
    /// `managing-app` policy. The pinned TypeScript `updateSpace` procedure
    /// patches those fields independently, so a policy-only change must retain
    /// a configured app and an empty update must be able to clear it. SQLite
    /// has no `ALTER CHECK`; copy the parent and every child table in one
    /// immediate transaction while foreign keys are disabled, then validate
    /// the reconstructed graph before recording the migration sentinel.
    private func migrateSimpleSpaceAuthoritySchemaIfNeeded() async throws {
        let version = Self.simpleSpaceAuthoritySchemaMigrationVersion
        _ = try await connection.query("PRAGMA foreign_keys = OFF")
        do {
            try await transaction {
                // This must be the first operation after BEGIN IMMEDIATE.
                // A different process can finish the rebuild after this
                // connection's base-schema transaction and before it reaches
                // here. Checking outside this transaction would let both
                // openers decide to rebuild the same tables.
                let applied = try await connection.query(
                    "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
                    [.integer(version)]
                )
                guard applied.isEmpty else { return }

                try await renameSimpleSpaceAuthorityTablesForMigration()
                for statement in SQLiteLayout.simpleSpaceAuthoritySchemaStatements {
                    _ = try await connection.query(statement)
                }
                try await copySimpleSpaceAuthorityTablesFromMigration()
                try await dropSimpleSpaceAuthorityMigrationTables()

                let violations = try await connection.query("PRAGMA foreign_key_check")
                guard violations.isEmpty else {
                    throw SQLiteRepositoryError.corruptDatabase(
                        "simple-space schema migration violated foreign keys"
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
            _ = try await connection.query("PRAGMA foreign_keys = ON")
        } catch {
            _ = try? await connection.query("PRAGMA foreign_keys = ON")
            throw error
        }
    }

    private func renameSimpleSpaceAuthorityTablesForMigration() async throws {
        _ = try await connection.query(
            "ALTER TABLE permissioned_simple_space_authorities RENAME TO permissioned_simple_space_authorities_schema_v2"
        )
        _ = try await connection.query(
            "ALTER TABLE permissioned_simple_space_members RENAME TO permissioned_simple_space_members_schema_v2"
        )
        _ = try await connection.query(
            "ALTER TABLE permissioned_simple_space_clients RENAME TO permissioned_simple_space_clients_schema_v2"
        )
        _ = try await connection.query(
            "ALTER TABLE permissioned_simple_space_managing_app_decisions RENAME TO permissioned_simple_space_managing_app_decisions_schema_v2"
        )
    }

    private func copySimpleSpaceAuthorityTablesFromMigration() async throws {
        _ = try await connection.query(
            """
            INSERT INTO permissioned_simple_space_authorities(
                space_uri, owner_did, policy, app_access, managing_app,
                is_deleted, revision, created_at, updated_at
            )
            SELECT space_uri, owner_did, policy, app_access, managing_app,
                   is_deleted, revision, created_at, updated_at
            FROM permissioned_simple_space_authorities_schema_v2
            """
        )
        _ = try await connection.query(
            """
            INSERT INTO permissioned_simple_space_members(space_uri, member_did)
            SELECT space_uri, member_did
            FROM permissioned_simple_space_members_schema_v2
            """
        )
        _ = try await connection.query(
            """
            INSERT INTO permissioned_simple_space_clients(space_uri, client_id)
            SELECT space_uri, client_id
            FROM permissioned_simple_space_clients_schema_v2
            """
        )
        _ = try await connection.query(
            """
            INSERT INTO permissioned_simple_space_managing_app_decisions(space_uri, user_did)
            SELECT space_uri, user_did
            FROM permissioned_simple_space_managing_app_decisions_schema_v2
            """
        )
    }

    private func dropSimpleSpaceAuthorityMigrationTables() async throws {
        // Drop children before their old parent. The new child tables already
        // reference the replacement parent, so this cannot hide a violation.
        _ = try await connection.query(
            "DROP TABLE permissioned_simple_space_managing_app_decisions_schema_v2"
        )
        _ = try await connection.query(
            "DROP TABLE permissioned_simple_space_clients_schema_v2"
        )
        _ = try await connection.query(
            "DROP TABLE permissioned_simple_space_members_schema_v2"
        )
        _ = try await connection.query(
            "DROP TABLE permissioned_simple_space_authorities_schema_v2"
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

    // MARK: Public repository genesis

    /// Installs the one immutable empty public-repository genesis for this
    /// account database. The candidate is re-derived from its CAR before any
    /// write, so callers cannot smuggle inconsistent cached fields alongside a
    /// valid byte payload. Existing state is verified again under the supplied
    /// public key before it is returned.
    public func installPublicRepositoryGenesis(
        _ candidate: PublicRepositoryGenesis,
        signingPublicKey: P256.Signing.PublicKey,
        installedAt: Date
    ) async throws -> PublicRepositoryGenesisInstallation {
        let verifiedCandidate = try verifiedPublicGenesis(
            car: candidate.car,
            signingPublicKey: signingPublicKey
        )
        let timestamp = try publicGenesisTimestamp(installedAt)
        let persistedAt = Date(timeIntervalSince1970: Double(timestamp) / 1_000_000)
        let candidateState = try PersistedPublicRepositoryGenesis(
            genesis: verifiedCandidate,
            installedAt: persistedAt
        )

        return try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT did, revision, commit_cid, car, installed_at
                    FROM public_repository_genesis
                    """
                )
                guard rows.count <= 1 else {
                    throw PublicRepositoryGenesisStoreError.corruptStoredGenesis
                }
                guard let row = rows.first else {
                    _ = try await connection.query(
                        """
                        INSERT INTO public_repository_genesis(
                            did, revision, commit_cid, car, installed_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        [
                            .text(verifiedCandidate.did),
                            .text(verifiedCandidate.revision),
                            .text(verifiedCandidate.commitCID.string),
                            blob(verifiedCandidate.car),
                            .integer(timestamp),
                        ]
                    )
                    return PublicRepositoryGenesisInstallation(
                        persisted: candidateState,
                        wasAlreadyInstalled: false
                    )
                }

                let stored = try decodeStoredPublicRepositoryGenesis(
                    row,
                    signingPublicKey: signingPublicKey
                )
                guard stored.genesis == verifiedCandidate else {
                    throw PublicRepositoryGenesisStoreError.conflictingGenesis
                }
                return PublicRepositoryGenesisInstallation(
                    persisted: stored,
                    wasAlreadyInstalled: true
                )
            }
        }
    }

    /// Loading is deliberately validation work, not a best-effort cache read:
    /// any tampered row rejects the whole operation and is never repaired from
    /// a caller-provided candidate.
    public func loadPublicRepositoryGenesis(
        did: String,
        signingPublicKey: P256.Signing.PublicKey
    ) async throws -> PersistedPublicRepositoryGenesis? {
        guard did == accountDID else {
            throw PublicRepositoryGenesisStoreError.ownershipMismatch
        }
        do {
            try PublicRepositoryGenesisCodec.validateDID(did)
        } catch {
            throw PublicRepositoryGenesisStoreError.ownershipMismatch
        }
        return try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT did, revision, commit_cid, car, installed_at
                FROM public_repository_genesis
                """
            )
            guard rows.count <= 1 else {
                throw PublicRepositoryGenesisStoreError.corruptStoredGenesis
            }
            guard let row = rows.first else { return nil }
            return try decodeStoredPublicRepositoryGenesis(
                row,
                signingPublicKey: signingPublicKey
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
            switch write {
            case let .create(_, _, cid) where cid.isEmpty,
                 let .put(_, _, cid) where cid.isEmpty,
                 let .update(_, _, cid) where cid.isEmpty:
                throw SwanError.malformed("record CID is empty")
            default:
                break
            }
        }
        _ = try sqliteRevision(expectedRevision)

        return try await withConnectionGate {
            try await transaction {
            try await requireLocalRepositorySpaceOpen(space)
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
                case let .create(_, _, cid), let .put(_, _, cid), let .update(_, _, cid): cid
                case .delete: nil
                }

                switch write {
                case let .create(_, value, cid):
                    guard old == nil else {
                        throw SwanError.malformed("cannot create an existing record")
                    }
                    action = .create
                    ltHash.add(
                        element: "\(uri.collection)/\(uri.rkey)/\(cid)"
                    )
                    _ = try await connection.query(
                        """
                        INSERT INTO permissioned_space_records(
                            space_uri, author_did, collection, rkey,
                            value, cid, revision
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        [
                            .text(space.rawValue), .text(author),
                            .text(uri.collection), .text(uri.rkey),
                            blob(value), .text(cid), .integer(storedRevision),
                        ]
                    )
                case let .put(_, value, cid), let .update(_, value, cid):
                    if case .update = write, old == nil {
                        throw SwanError.malformed("cannot update a missing record")
                    }
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
                try await requireLocalRepositorySpaceOpen(space)
                return try await repositorySnapshotWithoutTransaction(
                    space: space,
                    author: author
                )
            }
        }
    }

    /// Builds a private, bounded-memory CAR suffix from one SQLite read
    /// snapshot. The spool contains only the validated DRISL index and record
    /// blocks: a reader-specific signed commit is intentionally created later
    /// by the OAuth/account-key layer and never reaches disk here.
    ///
    /// The read transaction is held only while SQLite is read and private
    /// files are written. It is released before Hummingbird can write a byte
    /// to a client, so a slow/disconnected client cannot hold a database
    /// transaction open.
    public func prepareRepositoryCARSnapshot(
        space: SpaceURI,
        author: String
    ) async throws -> AuthorizedSpaceRepositoryCARSnapshot? {
        try requireAccount(author)
        let bodyURL = try SQLiteProtectedPaths.makePrivateCARSpoolURL(in: dataDirectory)
        do {
            let prepared = try await withConnectionGate {
                try await readTransaction {
                    try await requireLocalRepositorySpaceOpen(space)
                    return try await prepareRepositoryCARSnapshotWithoutTransaction(
                        space: space,
                        author: author,
                        bodyURL: bodyURL
                    )
                }
            }
            guard let prepared else {
                try? FileManager.default.removeItem(at: bodyURL)
                return nil
            }
            return prepared
        } catch {
            try? FileManager.default.removeItem(at: bodyURL)
            throw error
        }
    }

    private func prepareRepositoryCARSnapshotWithoutTransaction(
        space: SpaceURI,
        author: String,
        bodyURL: URL
    ) async throws -> AuthorizedSpaceRepositoryCARSnapshot? {
        guard let state = try await loadState(space: space, author: author) else {
            return nil
        }
        // Shared with the ordinary snapshot test hook so the CAR path proves
        // it remains one stable read transaction even while another WAL
        // connection commits a newer revision.
        await testingHooks.afterSnapshotStateRead?()
        let indexURL = try SQLiteProtectedPaths.makePrivateCARSpoolURL(in: dataDirectory)
        defer { try? FileManager.default.removeItem(at: indexURL) }

        let indexHandle: FileHandle
        do {
            indexHandle = try FileHandle(forWritingTo: indexURL)
        } catch {
            throw SwanError.unavailable("permissioned CAR spool is unavailable")
        }
        var indexClosed = false
        defer {
            if !indexClosed { try? indexHandle.close() }
        }

        let recordCount = try await repositoryCARRecordCount(space: space, author: author)
        var indexHash = SHA256()
        let indexPrefix = try SpaceCARCodec.streamingIndexPrefix(recordCount: recordCount)
        try writeCARSpoolData(indexPrefix, to: indexHandle)
        indexHash.update(data: indexPrefix)

        var calculatedLtHash = LtHash()
        var canonicalCursor: (length: Int, path: String)?
        var indexedCount = 0
        while let record = try await nextRepositoryCARIndexRecord(
            space: space,
            author: author,
            after: canonicalCursor
        ) {
            let path = "\(record.uri.collection)/\(record.uri.rkey)"
            let length = path.utf8.count
            if let cursor = canonicalCursor,
               length < cursor.length || (length == cursor.length && !cursor.path.utf8.lexicographicallyPrecedes(path.utf8)) {
                throw SQLiteRepositoryError.corruptDatabase("permissioned CAR index order is invalid")
            }
            let cid = try validatedRepositoryCARCID(for: record)
            let entry = try SpaceCARCodec.streamingIndexEntry(path: path, cid: cid)
            try writeCARSpoolData(entry, to: indexHandle)
            indexHash.update(data: entry)
            calculatedLtHash.add(element: "\(path)/\(cid.string)")
            canonicalCursor = (length, path)
            indexedCount += 1
        }
        guard indexedCount == recordCount,
              calculatedLtHash.commitment == state.commitment
        else {
            throw SQLiteRepositoryError.corruptDatabase("permissioned CAR snapshot does not match repository state")
        }

        try indexHandle.close()
        indexClosed = true
        let indexCID = CID(
            codec: .dagCBOR,
            multihash: .init(
                algorithm: Multihash.sha256Code,
                length: Multihash.sha256Length,
                digest: Data(indexHash.finalize())
            )
        )
        let indexSize = try repositoryCARFileSize(indexURL)

        let bodyHandle: FileHandle
        do {
            bodyHandle = try FileHandle(forWritingTo: bodyURL)
        } catch {
            throw SwanError.unavailable("permissioned CAR spool is unavailable")
        }
        var bodyClosed = false
        defer {
            if !bodyClosed { try? bodyHandle.close() }
        }

        try writeCARSpoolData(
            try SpaceCARCodec.streamingBlockPrefix(cid: indexCID, dataLength: indexSize),
            to: bodyHandle
        )
        try copyCARSpoolFile(indexURL, to: bodyHandle)

        var lexicalCursor: (collection: String, rkey: String)?
        var emittedCount = 0
        while let record = try await nextRepositoryCARRecord(
            space: space,
            author: author,
            after: lexicalCursor
        ) {
            if let cursor = lexicalCursor,
               record.uri.collection < cursor.collection ||
               (record.uri.collection == cursor.collection && record.uri.rkey <= cursor.rkey) {
                throw SQLiteRepositoryError.corruptDatabase("permissioned CAR record order is invalid")
            }
            let cid = try validatedRepositoryCARCID(for: record)
            try writeCARSpoolData(
                try SpaceCARCodec.streamingBlockPrefix(cid: cid, dataLength: record.value.count),
                to: bodyHandle
            )
            try writeCARSpoolData(record.value, to: bodyHandle)
            lexicalCursor = (record.uri.collection, record.uri.rkey)
            emittedCount += 1
        }
        guard emittedCount == recordCount else {
            throw SQLiteRepositoryError.corruptDatabase("permissioned CAR record count changed during snapshot")
        }
        try bodyHandle.close()
        bodyClosed = true

        return AuthorizedSpaceRepositoryCARSnapshot(
            state: AuthorizedSpaceRepositoryCommitState(
                space: state.space,
                author: state.author,
                wireRevision: state.wireRevision.toString(),
                commitment: state.commitment
            ),
            spool: SpaceCARBodySpool(indexCID: indexCID, bodyURL: bodyURL)
        )
    }

    private func repositoryCARRecordCount(
        space: SpaceURI,
        author: String
    ) async throws -> Int {
        let rows = try await connection.query(
            """
            SELECT COUNT(*) AS record_count
            FROM permissioned_space_records
            WHERE space_uri = ? AND author_did = ?
            """,
            [.text(space.rawValue), .text(author)]
        )
        guard let row = rows.first else {
            throw SQLiteRepositoryError.corruptDatabase("permissioned CAR count is unavailable")
        }
        let count = try requiredRevision(row, "record_count")
        guard count <= UInt64(Int.max) else {
            throw SQLiteRepositoryError.corruptDatabase("permissioned CAR record count is invalid")
        }
        return Int(count)
    }

    /// Fetches one row at a time rather than retaining an array of repository
    /// values. Canonical DAG-CBOR map order is length then UTF-8 bytes.
    private func nextRepositoryCARIndexRecord(
        space: SpaceURI,
        author: String,
        after cursor: (length: Int, path: String)?
    ) async throws -> PersistedSpaceRecord? {
        let rows: [SQLiteRow]
        if let cursor {
            rows = try await connection.query(
                """
                SELECT collection, rkey, value, cid, revision
                FROM permissioned_space_records
                WHERE space_uri = ? AND author_did = ?
                  AND (
                    length(CAST(collection || '/' || rkey AS BLOB)) > ?
                    OR (
                      length(CAST(collection || '/' || rkey AS BLOB)) = ?
                      AND collection || '/' || rkey > ?
                    )
                  )
                ORDER BY length(CAST(collection || '/' || rkey AS BLOB)), collection || '/' || rkey
                LIMIT 1
                """,
                [
                    .text(space.rawValue), .text(author),
                    .integer(cursor.length), .integer(cursor.length), .text(cursor.path),
                ]
            )
        } else {
            rows = try await connection.query(
                """
                SELECT collection, rkey, value, cid, revision
                FROM permissioned_space_records
                WHERE space_uri = ? AND author_did = ?
                ORDER BY length(CAST(collection || '/' || rkey AS BLOB)), collection || '/' || rkey
                LIMIT 1
                """,
                [.text(space.rawValue), .text(author)]
            )
        }
        guard let row = rows.first else { return nil }
        return try decodeRecord(row, space: space, author: author)
    }

    /// The proposal requires record blocks to follow lexicographic
    /// `collection/rkey` order, which is intentionally distinct from the
    /// canonical map-key order used for the DRISL index.
    private func nextRepositoryCARRecord(
        space: SpaceURI,
        author: String,
        after cursor: (collection: String, rkey: String)?
    ) async throws -> PersistedSpaceRecord? {
        let rows: [SQLiteRow]
        if let cursor {
            rows = try await connection.query(
                """
                SELECT collection, rkey, value, cid, revision
                FROM permissioned_space_records
                WHERE space_uri = ? AND author_did = ?
                  AND (collection > ? OR (collection = ? AND rkey > ?))
                ORDER BY collection, rkey
                LIMIT 1
                """,
                [
                    .text(space.rawValue), .text(author),
                    .text(cursor.collection), .text(cursor.collection), .text(cursor.rkey),
                ]
            )
        } else {
            rows = try await connection.query(
                """
                SELECT collection, rkey, value, cid, revision
                FROM permissioned_space_records
                WHERE space_uri = ? AND author_did = ?
                ORDER BY collection, rkey
                LIMIT 1
                """,
                [.text(space.rawValue), .text(author)]
            )
        }
        guard let row = rows.first else { return nil }
        return try decodeRecord(row, space: space, author: author)
    }

    private func validatedRepositoryCARCID(
        for record: PersistedSpaceRecord
    ) throws -> CID {
        let stored = try CID.parse(record.cid)
        guard CID.fromDAGCBOR(record.value) == stored else {
            throw SQLiteRepositoryError.corruptDatabase("permissioned CAR record CID does not match value")
        }
        return stored
    }

    private func repositoryCARFileSize(_ url: URL) throws -> Int {
        let values = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
        guard values.isRegularFile == true,
              let size = values.fileSize,
              size >= 0
        else {
            throw SwanError.unavailable("permissioned CAR spool is unavailable")
        }
        return size
    }

    private func writeCARSpoolData(_ data: Data, to handle: FileHandle) throws {
        var offset = 0
        while offset < data.count {
            let end = min(offset + SpaceCARBodySpool.maximumChunkBytes, data.count)
            try handle.write(contentsOf: data[offset ..< end])
            offset = end
        }
    }

    private func copyCARSpoolFile(_ source: URL, to destination: FileHandle) throws {
        let handle: FileHandle
        do {
            handle = try FileHandle(forReadingFrom: source)
        } catch {
            throw SwanError.unavailable("permissioned CAR spool is unavailable")
        }
        defer { try? handle.close() }
        while let chunk = try handle.read(upToCount: SpaceCARBodySpool.maximumChunkBytes),
              !chunk.isEmpty {
            try destination.write(contentsOf: chunk)
        }
    }

    /// Loads only the current permissioned repository state.  Sync commit
    /// creation must not read every record merely to obtain the durable LtHash
    /// commitment and wire TID.
    public func repositoryState(
        space: SpaceURI,
        author: String
    ) async throws -> PersistedRepositoryState? {
        try requireAccount(author)
        return try await withConnectionGate {
            try await readTransaction {
                try await requireLocalRepositorySpaceOpen(space)
                return try await loadState(space: space, author: author)
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
                try await requireLocalRepositorySpaceOpen(uri.space)
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
                try await requireLocalRepositorySpaceOpen(space)
                return try await spaceOplogWithoutTransaction(
                    space: space,
                    author: author,
                    afterRevision: requestedRevision,
                    afterIndex: nil
                )
            }
        }
    }

    /// Returns an incremental page after an XRPC wire-TID cursor.
    /// The reference PDS treats TIDs as its protocol cursor, while its
    /// operation ordering is still `(commit revision, operation index)`.
    /// Keep that distinction here: a batch may deliberately contain multiple
    /// operations with the same wire TID. `since` cannot resume inside that
    /// batch, so `limit` selects a terminal revision and the returned page is
    /// extended to include every operation with that revision. A page can
    /// therefore contain more than `limit` entries, but it can never silently
    /// split a batch that the next `since` cursor would skip.
    public func wireOplog(
        space: SpaceURI,
        author: String,
        since: TID?,
        limit: Int,
        includeValues: Bool
    ) async throws -> PersistedWireOplogRead {
        try requireAccount(author)
        guard (1 ... 1_000).contains(limit) else {
            throw SwanError.malformed("permissioned oplog page limit is invalid")
        }
        return try await withConnectionGate {
            try await readTransaction {
                try await requireLocalRepositorySpaceOpen(space)
                return try await wireOplogWithoutTransaction(
                    space: space,
                    author: author,
                    since: since,
                    limit: limit,
                    includeValues: includeValues
                )
            }
        }
    }

    private func wireOplogWithoutTransaction(
        space: SpaceURI,
        author: String,
        since: TID?,
        limit: Int,
        includeValues: Bool
    ) async throws -> PersistedWireOplogRead {
        guard let state = try await loadState(space: space, author: author) else {
            return .incremental(state: nil, entries: [])
        }

        if let since {
            let oldestRows = try await connection.query(
                """
                SELECT wire_revision
                FROM permissioned_space_oplog
                WHERE space_uri = ? AND author_did = ?
                ORDER BY revision, operation_index
                LIMIT 1
                """,
                [.text(space.rawValue), .text(author)]
            )
            guard let oldestRow = oldestRows.first else {
                // A state without retained history cannot safely answer an
                // incremental request from a known cursor.
                return .fullRecoveryRequired
            }
            let oldest = try requiredTID(oldestRow, "wire_revision")
            // TIDs cannot express the predecessor relationship that SQLite's
            // private numeric cursor has.  Be conservatively fail-closed: a
            // cursor older than the first retained TID gets the later full
            // CAR recovery path rather than a plausible, divergent delta.
            if since < oldest {
                return .fullRecoveryRequired
            }
        }

        // A wire TID is the only public cursor. Find the final revision in the
        // requested prefix first, then return the entire equivalence class for
        // that TID. Applying LIMIT directly to the projection would split an
        // atomic batch and make its remaining rows unreachable once a client
        // sends the last returned TID as `since`.
        let boundaryRows = try await connection.query(
            """
            SELECT wire_revision
            FROM permissioned_space_oplog
            WHERE space_uri = ? AND author_did = ?
              AND (? IS NULL OR wire_revision > ?)
            ORDER BY revision, operation_index
            LIMIT ?
            """,
            [
                .text(space.rawValue), .text(author),
                since.map { .text($0.toString()) } ?? .null,
                since.map { .text($0.toString()) } ?? .null,
                .integer(limit),
            ]
        )
        guard let boundaryRow = boundaryRows.last else {
            return .incremental(state: state, entries: [])
        }
        let boundary = try requiredTID(boundaryRow, "wire_revision")

        let rows: [SQLiteRow]
        if includeValues {
            rows = try await connection.query(
                """
                SELECT oplog.wire_revision, oplog.action, oplog.collection,
                       oplog.rkey, oplog.cid, oplog.previous_cid,
                       live.value AS current_value
                FROM permissioned_space_oplog AS oplog
                LEFT JOIN permissioned_space_records AS live
                  ON live.space_uri = oplog.space_uri
                 AND live.author_did = oplog.author_did
                 AND live.collection = oplog.collection
                 AND live.rkey = oplog.rkey
                 AND live.cid = oplog.cid
                WHERE oplog.space_uri = ? AND oplog.author_did = ?
                  AND (? IS NULL OR oplog.wire_revision > ?)
                  AND oplog.wire_revision <= ?
                ORDER BY oplog.revision, oplog.operation_index
                """,
                [
                    .text(space.rawValue), .text(author),
                    since.map { .text($0.toString()) } ?? .null,
                    since.map { .text($0.toString()) } ?? .null,
                    .text(boundary.toString()),
                ]
            )
        } else {
            rows = try await connection.query(
                """
                SELECT wire_revision, action, collection, rkey, cid,
                       previous_cid, NULL AS current_value
                FROM permissioned_space_oplog
                WHERE space_uri = ? AND author_did = ?
                  AND (? IS NULL OR wire_revision > ?)
                  AND wire_revision <= ?
                ORDER BY revision, operation_index
                """,
                [
                    .text(space.rawValue), .text(author),
                    since.map { .text($0.toString()) } ?? .null,
                    since.map { .text($0.toString()) } ?? .null,
                    .text(boundary.toString()),
                ]
            )
        }
        return .incremental(
            state: state,
            entries: try rows.map {
                try decodeWireOplog($0, space: space, author: author)
            }
        )
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
                try await requireLocalRepositorySpaceOpen(space)
                return try await spaceOplogWithoutTransaction(
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
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .create
                )
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
                    authorization: authorization,
                    operation: .update
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
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .update
                )
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

    /// Applies an XRPC `updateSpace` patch inside one authority transaction.
    /// Fetching configuration in the HTTP layer and writing it back later
    /// would race another patch and turn an omitted property into a stale
    /// reset, so the patch is resolved against the durable row while the
    /// write transaction is held.
    public func patchSimpleSpace(
        space: SpaceURI,
        patch: SimpleSpaceConfigurationPatch,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        let timestamp = try simpleSpaceTimestamp(now)
        return try await withConnectionGate {
            try await transaction {
                try requireAuthorityAccount(space: space)
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .update
                )
                let stored = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(stored.state)
                let configuration = try patch.applying(
                    to: stored.state.space.configuration
                )
                try validateSimpleSpaceConfiguration(configuration)
                guard configuration != stored.state.space.configuration else {
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
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .update
                )
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
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .update
                )
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
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .update
                )
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
                try requireAuthorityManagement(
                    space: space,
                    authorization: authorization,
                    operation: .delete
                )
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
                // The lifecycle tombstone and every registered-recipient
                // notification intent commit together.  Delivery happens
                // later through the lease worker; endpoint strings stay
                // opaque here and no record/CAR data enters the queue.
                let deletionEventID = UUID().uuidString.lowercased()
                let recipients = try await connection.query(
                    """
                    SELECT endpoint FROM permissioned_space_notification_registrations
                    WHERE space_uri = ? AND expires_at > ?
                    ORDER BY endpoint ASC
                    """,
                    [.text(space.rawValue), .integer(timestamp)]
                )
                for row in recipients {
                    let endpoint = try validNotificationEndpoint(
                        try requiredText(row, "endpoint")
                    )
                    _ = try await connection.query(
                        """
                        INSERT INTO permissioned_space_notification_fanout(
                            id, source_issuer, source_event_id, kind, space_uri,
                            repo_did, wire_revision, commitment, endpoint,
                            attempts, created_at, available_at,
                            lease_token, lease_expires_at
                        ) VALUES (?, ?, ?, 'deleted', ?, NULL, NULL, NULL, ?, 0, ?, ?, NULL, NULL)
                        ON CONFLICT(source_issuer, source_event_id, kind, endpoint) DO NOTHING
                        """,
                        [
                            .text(UUID().uuidString), .text(space.authority),
                            .text(deletionEventID), .text(space.rawValue),
                            .text(endpoint), .integer(timestamp), .integer(timestamp),
                        ]
                    )
                }
                return try await requiredSimpleSpace(space).state
            }
        }
    }

    // MARK: Authority writer set and notification registry

    /// Lists only the authority's durable writer hint after a verified space
    /// credential has bound the request to this exact space. This is not a
    /// member-list read and must never become an OAuth/public discovery path.
    public func spaceWriters(
        space: SpaceURI,
        limit: Int,
        cursor: String?,
        authorization: AuthorizationContext
    ) async throws -> [AuthorizedSpaceWriter] {
        guard (1 ... 1_000).contains(limit) else {
            throw SwanError.malformed("invalid writer page limit")
        }
        if let cursor {
            guard isValidSimpleSpaceDID(cursor) else {
                throw SwanError.malformed("invalid writer cursor")
            }
        }
        try requireAuthorityAccount(space: space)
        guard case let .spaceCredential(grant) = authorization,
              grant.space == space else {
            throw SwanError.unauthorized("space credential is required")
        }
        try grant.allows(.read)
        return try await withConnectionGate {
            try await readTransaction {
                let state = try await requiredSimpleSpace(space)
                try requireActiveSimpleSpace(state.state)
                var values: [SQLiteData] = [.text(space.rawValue)]
                var cursorClause = ""
                if let cursor {
                    cursorClause = " AND repo_did > ?"
                    values.append(.text(cursor))
                }
                values.append(.integer(limit))
                let rows = try await connection.query(
                    """
                    SELECT repo_did, wire_revision, commitment
                    FROM permissioned_space_writers
                    WHERE space_uri = ?\(cursorClause)
                    ORDER BY repo_did ASC
                    LIMIT ?
                    """,
                    values
                )
                return try rows.map { row in
                    let repository = try requiredText(row, "repo_did")
                    guard isValidSimpleSpaceDID(repository) else {
                        throw SQLiteRepositoryError.corruptDatabase("invalid writer repository")
                    }
                    let wireRevision = try requiredTID(row, "wire_revision").toString()
                    let commitment = try requiredBlob(row, "commitment")
                    guard commitment.count == 32 else {
                        throw SQLiteRepositoryError.corruptDatabase("invalid writer commitment")
                    }
                    return AuthorizedSpaceWriter(
                        space: space,
                        repository: repository,
                        wireRevision: wireRevision,
                        commitment: commitment
                    )
                }
            }
        }
    }

    /// Replaces one endpoint's subscription atomically. A registration is
    /// keyed by the delivery endpoint, matching the pinned PDS. Re-registering
    /// with a different optional repo replaces it; expiry cleanup below acts
    /// as removal without accepting a broad administration endpoint.
    public func registerSpaceNotification(
        _ registration: AuthorizedSpaceNotificationRegistration,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws {
        let endpoint = try validNotificationEndpoint(registration.endpoint)
        if let repository = registration.repository {
            guard isValidSimpleSpaceDID(repository) else {
                throw SwanError.invalidIdentifier("notification repository")
            }
        }
        let timestamp = try simpleSpaceTimestamp(now)
        let expiry = try simpleSpaceTimestamp(registration.expiresAt)
        guard expiry > timestamp,
              expiry - timestamp <= 24 * 60 * 60 * 1_000_000 else {
            throw SwanError.malformed("notification registration lifetime is invalid")
        }
        try requireAuthorityAccount(space: registration.space)
        guard case let .spaceCredential(grant) = authorization,
              grant.space == registration.space else {
            throw SwanError.unauthorized("space credential is required")
        }
        try grant.allows(.read)
        try await withConnectionGate {
            try await transaction {
                let state = try await requiredSimpleSpace(registration.space)
                try requireActiveSimpleSpace(state.state)
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_space_notification_registrations(
                        space_uri, endpoint, repo_did, expires_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(space_uri, endpoint) DO UPDATE SET
                        repo_did = excluded.repo_did,
                        expires_at = excluded.expires_at,
                        updated_at = excluded.updated_at
                    """,
                    [
                        .text(registration.space.rawValue), .text(endpoint),
                        registration.repository.map(SQLiteData.text) ?? .null,
                        .integer(expiry), .integer(timestamp),
                    ]
                )
                // A naturally expired row is a removed registration. Keep
                // cleanup inside the same transaction so a later fanout never
                // chooses a known-expired recipient.
                _ = try await connection.query(
                    "DELETE FROM permissioned_space_notification_registrations WHERE expires_at <= ?",
                    [.integer(timestamp)]
                )
            }
        }
    }

    /// Checks the durable registration immediately before a fanout transport
    /// uses it. A replaced, expired, or future removed registration turns a
    /// leased fanout row into a safe no-op rather than allowing a stale queue
    /// entry to keep sending to an endpoint after policy has changed.
    public func isSpaceNotificationRegistrationActive(
        space: SpaceURI,
        endpoint: String,
        repository: String?,
        now: Date = Date()
    ) async throws -> Bool {
        let endpoint = try validNotificationEndpoint(endpoint)
        if let repository {
            guard isValidSimpleSpaceDID(repository) else {
                throw SwanError.invalidIdentifier("notification repository")
            }
        }
        let timestamp = try simpleSpaceTimestamp(now)
        try requireAuthorityAccount(space: space)
        return try await withConnectionGate {
            try await readTransaction {
                let rows = try await connection.query(
                    """
                    SELECT repo_did, expires_at
                    FROM permissioned_space_notification_registrations
                    WHERE space_uri = ? AND endpoint = ?
                    """,
                    [.text(space.rawValue), .text(endpoint)]
                )
                guard let row = rows.first,
                      try requiredNonnegativeInteger(row, "expires_at") > timestamp else {
                    return false
                }
                let selectedRepository = row.column("repo_did")?.string
                // A repo-specific registration receives matching writes;
                // deletions (`repository == nil`) notify every still-active
                // recipient because the authority is no longer available to
                // send a later lifecycle signal.
                return repository == nil || selectedRepository == nil || selectedRepository == repository
            }
        }
    }

    /// Accepts a service-authenticated write announcement at the authority.
    /// Duplicate receipt IDs and stale TIDs are successful no-ops; an equal
    /// TID with a different commitment is a fail-closed conflict. The durable
    /// writer state and all fanout intents commit before any network delivery.
    public func receiveSpaceWriteNotification(
        _ notification: AuthorizedSpaceWriteNotification,
        now: Date = Date()
    ) async throws {
        guard notification.issuer == notification.repository,
              notification.audience == notification.space.authority,
              isValidSimpleSpaceDID(notification.repository),
              isValidSimpleSpaceDID(notification.issuer),
              (try? TID(tidString: notification.wireRevision)) != nil,
              notification.commitment.count == 32 else {
            throw SwanError.unauthorized("invalid write notification")
        }
        let eventID = try validServiceEventID(notification.eventID)
        let timestamp = try simpleSpaceTimestamp(now)
        try requireAuthorityAccount(space: notification.space)
        try await withConnectionGate {
            try await transaction {
                let state = try await requiredSimpleSpace(notification.space)
                try requireActiveSimpleSpace(state.state)
                guard state.state.space.members.contains(notification.repository) else {
                    throw SwanError.unauthorized("writer is not a space member")
                }

                let receipt = try await connection.query(
                    """
                    SELECT 1 FROM permissioned_space_notification_receipts
                    WHERE issuer = ? AND event_id = ?
                    """,
                    [.text(notification.issuer), .text(eventID)]
                )
                guard receipt.isEmpty else { return }

                let existing = try await connection.query(
                    """
                    SELECT wire_revision, commitment
                    FROM permissioned_space_writers
                    WHERE space_uri = ? AND repo_did = ?
                    """,
                    [.text(notification.space.rawValue), .text(notification.repository)]
                )
                var advancesWriter = true
                if let row = existing.first {
                    let currentRevision = try requiredTID(row, "wire_revision").toString()
                    let currentCommitment = try requiredBlob(row, "commitment")
                    guard currentCommitment.count == 32 else {
                        throw SQLiteRepositoryError.corruptDatabase("invalid writer commitment")
                    }
                    if notification.wireRevision < currentRevision {
                        advancesWriter = false
                    } else if notification.wireRevision == currentRevision {
                        guard currentCommitment == notification.commitment else {
                            throw SwanError.conflict(expected: 0, actual: 1)
                        }
                        advancesWriter = false
                    }
                }

                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_space_notification_receipts(
                        issuer, event_id, space_uri, received_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    [
                        .text(notification.issuer), .text(eventID),
                        .text(notification.space.rawValue), .integer(timestamp),
                    ]
                )
                guard advancesWriter else { return }

                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_space_writers(
                        space_uri, repo_did, wire_revision, commitment, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(space_uri, repo_did) DO UPDATE SET
                        wire_revision = excluded.wire_revision,
                        commitment = excluded.commitment,
                        updated_at = excluded.updated_at
                    """,
                    [
                        .text(notification.space.rawValue), .text(notification.repository),
                        .text(notification.wireRevision), blob(notification.commitment),
                        .integer(timestamp),
                    ]
                )

                // Do not enqueue an authority-signed `notifyWrite` fanout.
                // The pinned TypeScript receiver requires `iss == repo`, but
                // this authority has only its own key and cannot truthfully
                // sign for another member writer. Registrations remain local
                // discovery/authority state; cross-host write fanout awaits a
                // compatible upstream receiver contract. Deletion fanout is
                // separate and remains authority-signed by definition.
            }
        }
    }

    /// Records a verified deletion only on the selected local recipient
    /// account. This alpha intentionally does not invent a remote-space row:
    /// the tombstone is an isolated receipt used to reject later fanout state,
    /// not a substitute for remote operation application.
    public func receiveSpaceDeletionNotification(
        space: SpaceURI,
        issuer: String,
        audience: String,
        eventID: String,
        now: Date = Date()
    ) async throws {
        guard issuer == space.authority, audience == accountDID,
              isValidSimpleSpaceDID(issuer) else {
            throw SwanError.unauthorized("invalid space deletion notification")
        }
        let eventID = try validServiceEventID(eventID)
        let timestamp = try simpleSpaceTimestamp(now)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_space_notification_receipts(
                        issuer, event_id, space_uri, received_at
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(issuer, event_id) DO NOTHING
                    """,
                    [.text(issuer), .text(eventID), .text(space.rawValue), .integer(timestamp)]
                )
                // A recipient may retain a local repository for its own
                // writes in this remote space. Persist a closure rather than
                // creating a synthetic remote authority row or applying any
                // remote operation. All local repository read/write entry
                // points consult this tombstone, and stale writer outbox rows
                // are removed in the same transaction so a later restart
                // cannot announce a deleted repository.
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_space_recipient_tombstones(
                        space_uri, authority_did, deletion_event_id, closed_at
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(space_uri) DO NOTHING
                    """,
                    [
                        .text(space.rawValue), .text(issuer), .text(eventID),
                        .integer(timestamp),
                    ]
                )
                _ = try await connection.query(
                    "DELETE FROM permissioned_space_outbox WHERE space_uri = ?",
                    [.text(space.rawValue)]
                )
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
        namespace: BlobNamespace,
        mimeType: String? = nil
    ) async throws -> BlobReference {
        let cid = CID.fromBlob(data).string
        let digestHex = try blobDigestHex(cid: cid, allowLegacy: false)
        let byteCount = try blobByteCount(data.count)
        let storedMIMEType = safeBlobMIMEType(mimeType)
        let columns = blobNamespaceColumns(namespace)
        return try await withPrivateBlobLifecycleLock(digestHex: digestHex) {
            try await putBlobLocked(
                data,
                cid: cid,
                digestHex: digestHex,
                byteCount: byteCount,
                namespace: namespace,
                namespaceKind: columns.kind,
                spaceURI: columns.spaceURI,
                mimeType: storedMIMEType
            )
        }
    }

    public func blobData(for reference: BlobReference) async throws -> Data {
        let columns = blobNamespaceColumns(reference.namespace)
        let stored = try await blobPayload(
            cid: reference.cid,
            namespaceKind: columns.kind,
            spaceURI: columns.spaceURI
        )
        return try await materializeBlobData(stored)
    }

    public func publicBlobData(cid: String) async throws -> Data? {
        guard let stored = try await blobPayloadIfReachable(
            cid: cid,
            namespaceKind: "public",
            spaceURI: ""
        ) else {
            return nil
        }
        return try await materializeBlobData(stored)
    }

    public func removeBlobReference(_ reference: BlobReference) async throws {
        let columns = blobNamespaceColumns(reference.namespace)
        let digestHex = try blobDigestHex(cid: reference.cid, allowLegacy: true)
        try await withPrivateBlobLifecycleLock(digestHex: digestHex) {
            let needsReclamation = try await withConnectionGate {
                try await transaction {
                    let metadata = try await blobPayloadIfReachableWithoutGate(
                        cid: reference.cid,
                        namespaceKind: columns.kind,
                        spaceURI: columns.spaceURI
                    )
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
                    let remaining = try await connection.query(
                        "SELECT 1 FROM blob_namespace_references WHERE cid = ? LIMIT 1",
                        [.text(reference.cid)]
                    )
                    guard remaining.isEmpty else { return false }

                    // Reachability changes commit before a file unlink.  The
                    // durable `reclaiming` intent survives a crash between
                    // these two effects and is reconciled at startup or by
                    // this request after COMMIT.
                    _ = try await connection.query(
                        "DELETE FROM blob_payloads WHERE cid = ?",
                        [.text(reference.cid)]
                    )
                    guard metadata?.storageKind == .casV1 else { return false }
                    if try await hasFileBackedPayloadWithoutGate(digestHex: digestHex) {
                        // Another logical CID (for example a legacy sha256
                        // alias) still reaches the same physical CAS file.
                        try await setBlobLifecycleStateWithoutGate(
                            digestHex: digestHex,
                            state: .ready
                        )
                        return false
                    }
                    try await setBlobLifecycleStateWithoutGate(
                        digestHex: digestHex,
                        state: .reclaiming
                    )
                    return true
                }
            }
            if needsReclamation {
                if let hook = testingHooks.afterBlobReclaimCommit {
                    try await hook()
                }
                try await reconcilePrivateBlobLifecycleLocked(
                    digestHex: digestHex
                )
            }
        }
    }

    /// Opens only a private, exact namespace reference for the streaming
    /// permissioned blob surface.  `getBlob` passes a canonical raw CID; a
    /// legacy `sha256:` compatibility row is deliberately impossible to reach
    /// here even if it has a valid private reference.
    public func permissionedBlob(
        space: SpaceURI,
        author: String,
        cid: String
    ) async throws -> AuthorizedSpaceBlob? {
        try requireAccount(author)
        guard author == accountDID else {
            throw SwanError.unauthorized("account database ownership mismatch")
        }
        try await withConnectionGate {
            try await readTransaction {
                try await requireLocalRepositorySpaceOpen(space)
            }
        }
        _ = try canonicalRawBlobCID(cid)
        guard let stored = try await blobPayloadIfReachable(
            cid: cid,
            namespaceKind: "space",
            spaceURI: space.rawValue
        ) else {
            return nil
        }
        let body = try await fileBackedBlobBody(stored)
        return AuthorizedSpaceBlob(mimeType: stored.mimeType, body: body)
    }

    private struct StoredBlobPayload: Sendable {
        enum StorageKind: String, Sendable {
            case legacySQLite = "legacy-sqlite"
            case casV1 = "cas-v1"
        }

        let cid: String
        let storageKind: StorageKind
        let byteCount: Int
        let mimeType: String?
        let casDigest: String?
        let legacyPayload: Data?
    }

    private enum BlobCASLifecycleState: String, Sendable {
        case creating
        case ready
        case reclaiming
    }

    private enum BlobCASPreparation: Sendable {
        case existingCAS
        case staging
    }

    /// Holds both halves of the lifecycle lock over a file stage/adoption and
    /// its SQLite commit.  The async coordinator is required even though a
    /// descriptor `flock` is also held: same-process `flock` behavior for
    /// independently opened descriptors is not sufficiently portable to be
    /// the only exclusion mechanism.
    private func withPrivateBlobLifecycleLock<T: Sendable>(
        digestHex: String,
        _ body: () async throws -> T
    ) async throws -> T {
        let key = SQLiteBlobLifecycleCoordinator.Key(
            dataDirectory: dataDirectory.path,
            accountNamespace: accountBlobNamespace,
            digestHex: digestHex
        )
        await sqliteBlobLifecycleCoordinator.acquire(key)
        let descriptor: Int32
        do {
            descriptor = try SQLiteProtectedPaths.openPrivateBlobLifecycleLock(
                accountDirectoryDescriptor: accountDirectoryDescriptor,
                accountNamespace: accountBlobNamespace,
                digestHex: digestHex
            )
        } catch {
            await sqliteBlobLifecycleCoordinator.release(key)
            throw error
        }
        do {
            let result = try await body()
            SQLiteProtectedPaths.closePrivateBlobLifecycleLock(descriptor)
            await sqliteBlobLifecycleCoordinator.release(key)
            return result
        } catch {
            SQLiteProtectedPaths.closePrivateBlobLifecycleLock(descriptor)
            await sqliteBlobLifecycleCoordinator.release(key)
            throw error
        }
    }

    private func putBlobLocked(
        _ data: Data,
        cid: String,
        digestHex: String,
        byteCount: Int,
        namespace: BlobNamespace,
        namespaceKind: String,
        spaceURI: String,
        mimeType: String?
    ) async throws -> BlobReference {
        let preparation: BlobCASPreparation = try await withConnectionGate {
            try await transaction {
                switch try await blobStorageKindWithoutGate(cid: cid) {
                case .casV1:
                    try await setBlobLifecycleStateWithoutGate(
                        digestHex: digestHex,
                        state: .ready
                    )
                    return .existingCAS
                case .legacySQLite:
                    // A valid v4 legacy row uses the historical sha256 label,
                    // never a raw CID. Treat a collision as durable
                    // corruption rather than overwriting it.
                    throw SQLiteRepositoryError.corruptDatabase(
                        "raw blob CID collides with legacy storage"
                    )
                case nil:
                    // Persist the creation intent before touching the file.
                    // A crash now has no reference and recovery can reclaim
                    // either a missing or a partially staged CAS entry.
                    try await setBlobLifecycleStateWithoutGate(
                        digestHex: digestHex,
                        state: .creating
                    )
                    return .staging
                }
            }
        }

        do {
            switch preparation {
            case .existingCAS:
                try verifyPrivateBlobFile(
                    digestHex: digestHex,
                    expectedLength: byteCount
                )
            case .staging:
                let created = try SQLiteProtectedPaths.createPrivateBlob(
                    accountDirectoryDescriptor: accountDirectoryDescriptor,
                    accountNamespace: accountBlobNamespace,
                    digestHex: digestHex,
                    payload: data
                )
                if !created {
                    // An unreferenced orphan can be adopted only after a full
                    // digest/length check while this CID lock is held.
                    try verifyPrivateBlobFile(
                        digestHex: digestHex,
                        expectedLength: byteCount
                    )
                }
            }

            if let hook = testingHooks.beforeBlobReferenceCommit {
                try await hook()
            }
            try await withConnectionGate {
                try await transaction {
                    _ = try await connection.query(
                        """
                        INSERT INTO blob_payloads(
                            cid, payload, storage_kind, cas_digest, byte_count, mime_type
                        ) VALUES (?, zeroblob(0), 'cas-v1', ?, ?, ?)
                        ON CONFLICT(cid) DO NOTHING
                        """,
                        [
                            .text(cid), .text(digestHex), .integer(byteCount),
                            mimeType.map(SQLiteData.text) ?? .null,
                        ]
                    )
                    _ = try await connection.query(
                        """
                        INSERT INTO blob_namespace_references(
                            cid, namespace_kind, space_uri
                        ) VALUES (?, ?, ?)
                        ON CONFLICT(cid, namespace_kind, space_uri) DO NOTHING
                        """,
                        [.text(cid), .text(namespaceKind), .text(spaceURI)]
                    )
                    try await setBlobLifecycleStateWithoutGate(
                        digestHex: digestHex,
                        state: .ready
                    )
                }
            }
        } catch {
            if preparation == .staging {
                // Keep a durable reclaiming intent until the file has been
                // safely unlinked. If the transaction outcome is uncertain,
                // reconciliation rechecks metadata before deletion.
                try? await abandonPrivateBlobCreationLocked(
                    digestHex: digestHex
                )
            }
            throw error
        }
        return BlobReference(cid: cid, namespace: namespace)
    }

    private func blobStorageKindWithoutGate(
        cid: String
    ) async throws -> StoredBlobPayload.StorageKind? {
        let rows = try await connection.query(
            "SELECT storage_kind FROM blob_payloads WHERE cid = ?",
            [.text(cid)]
        )
        guard let row = rows.first else { return nil }
        guard let storageKind = StoredBlobPayload.StorageKind(
            rawValue: try requiredText(row, "storage_kind")
        ) else {
            throw SQLiteRepositoryError.corruptDatabase("invalid blob storage kind")
        }
        return storageKind
    }

    private func hasFileBackedPayloadWithoutGate(
        digestHex: String
    ) async throws -> Bool {
        let rows = try await connection.query(
            """
            SELECT 1
            FROM blob_payloads
            WHERE storage_kind = 'cas-v1' AND cas_digest = ?
            LIMIT 1
            """,
            [.text(digestHex)]
        )
        return !rows.isEmpty
    }

    private func blobLifecycleStateWithoutGate(
        digestHex: String
    ) async throws -> BlobCASLifecycleState? {
        let rows = try await connection.query(
            "SELECT state FROM blob_cas_lifecycle WHERE digest_hex = ?",
            [.text(digestHex)]
        )
        guard let row = rows.first else { return nil }
        guard let state = BlobCASLifecycleState(
            rawValue: try requiredText(row, "state")
        ) else {
            throw SQLiteRepositoryError.corruptDatabase("invalid blob lifecycle state")
        }
        return state
    }

    private func setBlobLifecycleStateWithoutGate(
        digestHex: String,
        state: BlobCASLifecycleState
    ) async throws {
        _ = try await connection.query(
            """
            INSERT INTO blob_cas_lifecycle(digest_hex, state, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(digest_hex) DO UPDATE SET
                state = excluded.state,
                updated_at = excluded.updated_at
            """,
            [
                .text(digestHex), .text(state.rawValue),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    private func abandonPrivateBlobCreationLocked(
        digestHex: String
    ) async throws {
        let needsReclamation = try await withConnectionGate {
            try await transaction {
                if try await hasFileBackedPayloadWithoutGate(digestHex: digestHex) {
                    try await setBlobLifecycleStateWithoutGate(
                        digestHex: digestHex,
                        state: .ready
                    )
                    return false
                }
                try await setBlobLifecycleStateWithoutGate(
                    digestHex: digestHex,
                    state: .reclaiming
                )
                return true
            }
        }
        if needsReclamation {
            try await reconcilePrivateBlobLifecycleLocked(
                digestHex: digestHex
            )
        }
    }

    private func reconcilePrivateBlobLifecycleLocked(
        digestHex: String
    ) async throws {
        let shouldUnlink = try await withConnectionGate {
            try await transaction {
                let hasPayload = try await hasFileBackedPayloadWithoutGate(
                    digestHex: digestHex
                )
                let lifecycle = try await blobLifecycleStateWithoutGate(
                    digestHex: digestHex
                )
                if hasPayload {
                    // A re-reference won the CID lock before this reconciler.
                    // Preserve its CAS and clear the stale reclaim intent.
                    if lifecycle != .ready {
                        try await setBlobLifecycleStateWithoutGate(
                            digestHex: digestHex,
                            state: .ready
                        )
                    }
                    return false
                }
                guard lifecycle != nil else { return false }
                if lifecycle != .reclaiming {
                    try await setBlobLifecycleStateWithoutGate(
                        digestHex: digestHex,
                        state: .reclaiming
                    )
                }
                return true
            }
        }
        guard shouldUnlink else { return }

        // Filesystem effects are intentionally outside the SQLite
        // transaction.  The already-committed reclaiming state makes a crash
        // here recoverable without ever pointing a live reference at a
        // missing file.
        try SQLiteProtectedPaths.removePrivateBlob(
            accountDirectoryDescriptor: accountDirectoryDescriptor,
            accountNamespace: accountBlobNamespace,
            digestHex: digestHex
        )
        try await withConnectionGate {
            try await transaction {
                guard try await hasFileBackedPayloadWithoutGate(digestHex: digestHex) == false,
                      try await blobLifecycleStateWithoutGate(digestHex: digestHex) == .reclaiming
                else {
                    return
                }
                _ = try await connection.query(
                    "DELETE FROM blob_cas_lifecycle WHERE digest_hex = ?",
                    [.text(digestHex)]
                )
            }
        }
    }

    private func recoverPrivateBlobLifecycle() async throws {
        let candidates = try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT digest_hex
                FROM blob_cas_lifecycle
                WHERE state != 'ready'
                ORDER BY digest_hex
                """
            )
            return try rows.map { try requiredText($0, "digest_hex") }
        }
        for digestHex in candidates {
            guard legacyBlobDigest("sha256:\(digestHex)") != nil else {
                throw SQLiteRepositoryError.corruptDatabase("invalid blob lifecycle digest")
            }
            try await withPrivateBlobLifecycleLock(digestHex: digestHex) {
                try await reconcilePrivateBlobLifecycleLocked(
                    digestHex: digestHex
                )
            }
        }
    }

    private func verifyPrivateBlobFile(
        digestHex: String,
        expectedLength: Int
    ) throws {
        guard let expectedDigest = legacyBlobDigest("sha256:\(digestHex)") else {
            throw SQLiteRepositoryError.corruptDatabase("invalid CAS blob digest")
        }
        let descriptor = try SQLiteProtectedPaths.openPrivateBlob(
            accountDirectoryDescriptor: accountDirectoryDescriptor,
            accountNamespace: accountBlobNamespace,
            digestHex: digestHex
        )
        do {
            let body = try SQLiteVerifiedSpaceBlobBody(
                descriptor: descriptor,
                expectedDigest: expectedDigest,
                expectedLength: expectedLength
            )
            body.discardUnstreamed()
        } catch {
            SQLiteProtectedPaths.closeDirectory(descriptor)
            throw error
        }
    }

    private func blobPayload(
        cid: String,
        namespaceKind: String,
        spaceURI: String
    ) async throws -> StoredBlobPayload {
        guard let stored = try await blobPayloadIfReachable(
            cid: cid,
            namespaceKind: namespaceKind,
            spaceURI: spaceURI
        ) else {
            throw SwanError.unauthorized("blob is not reachable in this namespace")
        }
        return stored
    }

    private func blobPayloadIfReachable(
        cid: String,
        namespaceKind: String,
        spaceURI: String
    ) async throws -> StoredBlobPayload? {
        try await withConnectionGate {
            try await blobPayloadIfReachableWithoutGate(
                cid: cid,
                namespaceKind: namespaceKind,
                spaceURI: spaceURI
            )
        }
    }

    private func blobPayloadIfReachableWithoutGate(
        cid: String,
        namespaceKind: String,
        spaceURI: String
    ) async throws -> StoredBlobPayload? {
        let rows = try await connection.query(
            """
            SELECT blob_payloads.cid, blob_payloads.payload,
                   blob_payloads.storage_kind, blob_payloads.cas_digest,
                   blob_payloads.byte_count,
                   blob_payloads.mime_type
            FROM blob_payloads
            JOIN blob_namespace_references USING(cid)
            WHERE blob_payloads.cid = ? AND namespace_kind = ? AND space_uri = ?
            """,
            [.text(cid), .text(namespaceKind), .text(spaceURI)]
        )
        guard let row = rows.first else { return nil }
        let storedCID = try requiredText(row, "cid")
        guard storedCID == cid,
              let storageKind = StoredBlobPayload.StorageKind(
                  rawValue: try requiredText(row, "storage_kind")
              )
        else {
            throw SQLiteRepositoryError.corruptDatabase("invalid blob metadata")
        }
        let storedByteCount: Int
        if let value = row.column("byte_count"), !value.isNull {
            guard let integer = value.integer, integer >= 0 else {
                throw SQLiteRepositoryError.corruptDatabase("invalid blob size")
            }
            storedByteCount = integer
        } else if storageKind == .legacySQLite {
            storedByteCount = try requiredBlob(row, "payload").count
        } else {
            throw SQLiteRepositoryError.corruptDatabase("missing blob size")
        }
        let mimeType: String?
        if let value = row.column("mime_type"), !value.isNull {
            guard let raw = value.string else {
                throw SQLiteRepositoryError.corruptDatabase("invalid blob MIME type")
            }
            mimeType = safeBlobMIMEType(raw)
        } else {
            mimeType = nil
        }
        let legacyPayload: Data?
        let casDigest: String?
        switch storageKind {
        case .legacySQLite:
            let payload = try requiredBlob(row, "payload")
            guard legacyBlobCID(payload) == storedCID,
                  payload.count == storedByteCount else {
                throw SQLiteRepositoryError.corruptDatabase(
                    "legacy blob payload does not match metadata"
                )
            }
            legacyPayload = payload
            casDigest = nil
        case .casV1:
            let digest = try blobDigestHex(cid: storedCID, allowLegacy: true)
            guard let storedDigest = row.column("cas_digest")?.string,
                  storedDigest == digest,
                  legacyBlobDigest("sha256:\(storedDigest)") != nil else {
                throw SQLiteRepositoryError.corruptDatabase("invalid CAS blob CID")
            }
            legacyPayload = nil
            casDigest = storedDigest
        }
        return StoredBlobPayload(
            cid: storedCID,
            storageKind: storageKind,
            byteCount: storedByteCount,
            mimeType: mimeType,
            casDigest: casDigest,
            legacyPayload: legacyPayload
        )
    }

    private func materializeBlobData(_ stored: StoredBlobPayload) async throws -> Data {
        switch stored.storageKind {
        case .legacySQLite:
            guard let payload = stored.legacyPayload else {
                throw SQLiteRepositoryError.corruptDatabase("missing legacy blob payload")
            }
            try await migrateLegacyBlobToCAS(stored, payload: payload)
            return payload
        case .casV1:
            let body = try await fileBackedBlobBody(stored)
            var output = Data()
            output.reserveCapacity(stored.byteCount)
            try await body.streamBody(maximumChunkBytes: 64 * 1_024) { chunk in
                output.append(chunk)
            }
            guard output.count == stored.byteCount else {
                throw SwanError.unavailable("permissioned blob storage is unavailable")
            }
            return output
        }
    }

    private func migrateLegacyBlobToCAS(
        _ stored: StoredBlobPayload,
        payload: Data
    ) async throws {
        guard stored.storageKind == .legacySQLite,
              legacyBlobCID(payload) == stored.cid,
              payload.count == stored.byteCount else {
            throw SQLiteRepositoryError.corruptDatabase("invalid legacy blob migration")
        }
        let digestHex = try blobDigestHex(cid: stored.cid, allowLegacy: true)
        try await withPrivateBlobLifecycleLock(digestHex: digestHex) {
            let preparation = try await withConnectionGate {
                try await transaction {
                    switch try await blobStorageKindWithoutGate(cid: stored.cid) {
                    case .casV1:
                        return false
                    case .legacySQLite:
                        try await setBlobLifecycleStateWithoutGate(
                            digestHex: digestHex,
                            state: .creating
                        )
                        return true
                    case nil:
                        // The last authorized reference was removed after the
                        // compatibility read began. Returning its already
                        // validated payload is fine, but do not create an
                        // unreachable replacement file.
                        return false
                    }
                }
            }
            guard preparation else { return }

            do {
                let created = try SQLiteProtectedPaths.createPrivateBlob(
                    accountDirectoryDescriptor: accountDirectoryDescriptor,
                    accountNamespace: accountBlobNamespace,
                    digestHex: digestHex,
                    payload: payload
                )
                if !created {
                    try verifyPrivateBlobFile(
                        digestHex: digestHex,
                        expectedLength: stored.byteCount
                    )
                }
                if let hook = testingHooks.beforeLegacyBlobMigrationCommit {
                    try await hook()
                }
                try await withConnectionGate {
                    try await transaction {
                        guard try await blobStorageKindWithoutGate(cid: stored.cid) == .legacySQLite else {
                            throw SQLiteRepositoryError.corruptDatabase(
                                "legacy blob changed during migration"
                            )
                        }
                        _ = try await connection.query(
                            """
                            UPDATE blob_payloads
                            SET payload = zeroblob(0), storage_kind = 'cas-v1',
                                cas_digest = ?, byte_count = ?
                            WHERE cid = ? AND storage_kind = 'legacy-sqlite'
                            """,
                            [
                                .text(digestHex), .integer(stored.byteCount),
                                .text(stored.cid),
                            ]
                        )
                        try await setBlobLifecycleStateWithoutGate(
                            digestHex: digestHex,
                            state: .ready
                        )
                    }
                }
            } catch {
                try? await abandonPrivateBlobCreationLocked(
                    digestHex: digestHex
                )
                throw error
            }
        }
    }

    private func fileBackedBlobBody(
        _ stored: StoredBlobPayload
    ) async throws -> SQLiteVerifiedSpaceBlobBody {
        guard stored.storageKind == .casV1 else {
            throw SQLiteRepositoryError.corruptDatabase("blob is not file backed")
        }
        guard let digestHex = stored.casDigest else {
            throw SQLiteRepositoryError.corruptDatabase("missing CAS blob digest")
        }
        guard let digest = legacyBlobDigest("sha256:\(digestHex)") else {
            throw SQLiteRepositoryError.corruptDatabase("invalid CAS blob digest")
        }
        let descriptor = try SQLiteProtectedPaths.openPrivateBlob(
            accountDirectoryDescriptor: accountDirectoryDescriptor,
            accountNamespace: accountBlobNamespace,
            digestHex: digestHex
        )
        do {
            return try SQLiteVerifiedSpaceBlobBody(
                descriptor: descriptor,
                expectedDigest: digest,
                expectedLength: stored.byteCount
            )
        } catch {
            SQLiteProtectedPaths.closeDirectory(descriptor)
            throw error
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
                try await requireLocalRepositorySpaceOpen(space)
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

    /// Claims one durable authority fanout intent. It deliberately mirrors the
    /// commit outbox lease API rather than sharing its table: registrations are
    /// authority-owned, while a commit outbox is owned by the writer PDS.
    public func leaseNextNotificationFanout(
        now: Date = Date(),
        leaseDuration: TimeInterval
    ) async throws -> PersistedSpaceNotificationFanoutLease? {
        let nowTimestamp = try outboxTimestamp(now)
        let leaseExpiry = try outboxTimestamp(
            now.addingTimeInterval(try validOutboxInterval(leaseDuration, name: "lease duration"))
        )
        return try await withConnectionGate {
            try await transaction {
                let token = UUID()
                let rows = try await connection.query(
                    """
                    SELECT id, source_issuer, source_event_id, kind, space_uri,
                           repo_did, wire_revision, commitment, endpoint, attempts,
                           lease_token, lease_expires_at
                    FROM permissioned_space_notification_fanout
                    WHERE available_at <= ?
                      AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                    ORDER BY available_at, created_at, id
                    LIMIT 1
                    """,
                    [.integer(nowTimestamp), .integer(nowTimestamp)]
                )
                guard let row = rows.first else { return nil }
                let event = try decodeNotificationFanout(row)
                _ = try decodeNotificationFanoutLease(row)
                _ = try await connection.query(
                    """
                    UPDATE permissioned_space_notification_fanout
                    SET lease_token = ?, lease_expires_at = ?
                    WHERE id = ?
                    """,
                    [.text(token.uuidString), .integer(leaseExpiry), .text(event.id.uuidString)]
                )
                return PersistedSpaceNotificationFanoutLease(
                    event: event,
                    token: token,
                    expiresAt: Date(timeIntervalSince1970: Double(leaseExpiry) / 1_000_000)
                )
            }
        }
    }

    @discardableResult
    public func completeNotificationFanoutLease(
        eventID: UUID,
        token: UUID
    ) async throws -> Bool {
        try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT id, source_issuer, source_event_id, kind, space_uri,
                           repo_did, wire_revision, commitment, endpoint, attempts,
                           lease_token, lease_expires_at
                    FROM permissioned_space_notification_fanout WHERE id = ?
                    """,
                    [.text(eventID.uuidString)]
                )
                guard let row = rows.first else { return false }
                _ = try decodeNotificationFanout(row)
                let lease = try decodeNotificationFanoutLease(row)
                guard lease.token == token else { return false }
                _ = try await connection.query(
                    "DELETE FROM permissioned_space_notification_fanout WHERE id = ? AND lease_token = ?",
                    [.text(eventID.uuidString), .text(token.uuidString)]
                )
                return true
            }
        }
    }

    @discardableResult
    public func failNotificationFanoutLease(
        eventID: UUID,
        token: UUID,
        retryAt: Date
    ) async throws -> Int? {
        let retryTimestamp = try outboxTimestamp(retryAt)
        return try await withConnectionGate {
            try await transaction {
                let rows = try await connection.query(
                    """
                    SELECT id, source_issuer, source_event_id, kind, space_uri,
                           repo_did, wire_revision, commitment, endpoint, attempts,
                           lease_token, lease_expires_at
                    FROM permissioned_space_notification_fanout WHERE id = ?
                    """,
                    [.text(eventID.uuidString)]
                )
                guard let row = rows.first else { return nil }
                let event = try decodeNotificationFanout(row)
                let lease = try decodeNotificationFanoutLease(row)
                guard lease.token == token else { return nil }
                guard event.attempts < Int.max else {
                    throw SQLiteRepositoryError.corruptDatabase("notification fanout attempts overflow")
                }
                let nextAttempts = event.attempts + 1
                _ = try await connection.query(
                    """
                    UPDATE permissioned_space_notification_fanout
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

    public func pendingNotificationFanout(
        limit: Int = 100
    ) async throws -> [PersistedSpaceNotificationFanout] {
        guard (0 ... 10_000).contains(limit) else {
            throw SwanError.malformed("notification fanout limit is invalid")
        }
        return try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT id, source_issuer, source_event_id, kind, space_uri,
                       repo_did, wire_revision, commitment, endpoint, attempts,
                       lease_token, lease_expires_at
                FROM permissioned_space_notification_fanout
                ORDER BY created_at, id LIMIT ?
                """,
                [.integer(limit)]
            )
            return try rows.map { row in
                _ = try decodeNotificationFanoutLease(row)
                return try decodeNotificationFanout(row)
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
        authorization: AuthorizationContext,
        operation: SimpleSpaceManagementOperation
    ) throws {
        try SpaceAuthorizationPolicy.requireManagement(
            space: space,
            authorization: authorization,
            operation: operation
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
        case let .spaceDelegation(subject, delegatedSpace):
            guard subject == user, delegatedSpace == space else {
                throw SwanError.unauthorized(
                    "delegation does not match the requested user or space"
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
            throw AuthorizedSimpleSpaceLifecycleError.notFound
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
        // `updateSpace` patches policy and managingApp independently. Retain
        // a valid configured app through a policy-only transition exactly as
        // the pinned TypeScript store does; policy evaluation consults it only
        // for `managing-app`. Its syntax remains fail-closed in every state.
        if let managingApp = configuration.managingApp {
            try validateSimpleSpaceAppIdentifier(managingApp)
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

    /// SQLite owns only a bounded opaque endpoint string. The HTTP transport
    /// performs the authoritative scheme/DNS/redirect policy immediately
    /// before use; keeping the lexical guard here prevents corrupt rows from
    /// becoming unbounded or control-character-bearing transport input.
    private func validNotificationEndpoint(_ value: String) throws -> String {
        guard !value.isEmpty,
              value.utf8.count <= 4_096,
              value.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }),
              let components = URLComponents(string: value),
              components.scheme != nil,
              components.host != nil,
              components.user == nil,
              components.password == nil,
              components.fragment == nil else {
            throw SwanError.malformed("notification endpoint is invalid")
        }
        return value
    }

    private func validServiceEventID(_ value: String) throws -> String {
        guard !value.isEmpty,
              value.utf8.count <= 256,
              value.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw SwanError.malformed("service notification event is invalid")
        }
        return value
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
            throw AuthorizedSimpleSpaceLifecycleError.notFound
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

    /// A verified authority deletion closes any local recipient repository
    /// without manufacturing remote authority state or applying remote
    /// operations. This helper is used only while an existing SQLite
    /// transaction is held, so it cannot race a deletion into a stale read or
    /// write. It intentionally does not reveal whether the receiver retained
    /// records before the closure.
    private func requireLocalRepositorySpaceOpen(_ space: SpaceURI) async throws {
        let rows = try await connection.query(
            "SELECT 1 FROM permissioned_space_recipient_tombstones WHERE space_uri = ?",
            [.text(space.rawValue)]
        )
        guard rows.isEmpty else {
            throw SwanError.unauthorized("permissioned space is closed")
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
        case let .create(_, bytes, recordCID), let .put(_, bytes, recordCID),
             let .update(_, bytes, recordCID):
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

    /// Decodes the read-side join projection.  Validate the durable action
    /// shape before HTTP has a chance to render nullable CIDs: corrupted rows
    /// must become an opaque unavailable response, not a malformed partial
    /// operation list.
    private func decodeWireOplog(
        _ row: SQLiteRow,
        space: SpaceURI,
        author: String
    ) throws -> PersistedWireOplogEntry {
        let actionRaw = try requiredText(row, "action")
        guard let action = PersistedRepoAction(rawValue: actionRaw) else {
            throw SQLiteRepositoryError.corruptDatabase("invalid oplog action")
        }
        let uri = try SpaceRecordURI(
            space: space,
            author: author,
            collection: try requiredText(row, "collection"),
            rkey: try requiredText(row, "rkey")
        )
        let cid = row.column("cid")?.string
        let previousCID = row.column("previous_cid")?.string
        let value: Data?
        if let currentValue = row.column("current_value"), !currentValue.isNull {
            guard let decoded = Data(sqliteData: currentValue) else {
                throw SQLiteRepositoryError.corruptDatabase("invalid current_value")
            }
            value = decoded
        } else {
            value = nil
        }
        switch action {
        case .create:
            guard cid != nil, previousCID == nil else {
                throw SQLiteRepositoryError.corruptDatabase("invalid create oplog entry")
            }
        case .update:
            guard cid != nil, previousCID != nil else {
                throw SQLiteRepositoryError.corruptDatabase("invalid update oplog entry")
            }
        case .delete:
            guard cid == nil, previousCID != nil, value == nil else {
                throw SQLiteRepositoryError.corruptDatabase("invalid delete oplog entry")
            }
        }
        return PersistedWireOplogEntry(
            wireRevision: try requiredTID(row, "wire_revision"),
            action: action,
            uri: uri,
            cid: cid,
            previousCID: previousCID,
            value: value
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

    private func decodeNotificationFanout(
        _ row: SQLiteRow
    ) throws -> PersistedSpaceNotificationFanout {
        guard let id = row.column("id")?.string.flatMap(UUID.init(uuidString:)),
              let issuer = row.column("source_issuer")?.string,
              let eventID = row.column("source_event_id")?.string,
              let kindRaw = row.column("kind")?.string,
              let kind = PersistedSpaceNotificationFanout.Kind(rawValue: kindRaw),
              let spaceRaw = row.column("space_uri")?.string,
              let space = try? SpaceURI(spaceRaw),
              space.rawValue == spaceRaw,
              let endpoint = row.column("endpoint")?.string else {
            throw SQLiteRepositoryError.corruptDatabase("invalid notification fanout row")
        }
        _ = try validServiceEventID(eventID)
        _ = try validNotificationEndpoint(endpoint)
        guard isValidSimpleSpaceDID(issuer) else {
            throw SQLiteRepositoryError.corruptDatabase("invalid notification fanout issuer")
        }
        let repository = row.column("repo_did")?.string
        let wireRevision = row.column("wire_revision")?.string
        let commitment = row.column("commitment").flatMap { column -> Data? in
            if case let .blob(data) = column { return Data(buffer: data) }
            return nil
        }
        switch kind {
        case .write:
            guard let repository,
                  isValidSimpleSpaceDID(repository),
                  let wireRevision,
                  (try? TID(tidString: wireRevision)) != nil,
                  let commitment,
                  commitment.count == 32 else {
                throw SQLiteRepositoryError.corruptDatabase("invalid write notification fanout")
            }
        case .deleted:
            guard repository == nil, wireRevision == nil, commitment == nil else {
                throw SQLiteRepositoryError.corruptDatabase("invalid deletion notification fanout")
            }
        }
        return PersistedSpaceNotificationFanout(
            id: id,
            sourceIssuer: issuer,
            sourceEventID: eventID,
            kind: kind,
            space: space,
            repository: repository,
            wireRevision: wireRevision,
            commitment: commitment,
            endpoint: endpoint,
            attempts: try requiredNonnegativeInteger(row, "attempts")
        )
    }

    private func decodeNotificationFanoutLease(
        _ row: SQLiteRow
    ) throws -> (token: UUID?, expiresAt: Int?) {
        let token = row.column("lease_token")
        let expiry = row.column("lease_expires_at")
        switch (token, expiry) {
        case (.some(.null), .some(.null)):
            return (nil, nil)
        case let (.some(.text(rawToken)), .some(.integer(rawExpiry))):
            guard let token = UUID(uuidString: rawToken), rawExpiry >= 0 else {
                throw SQLiteRepositoryError.corruptDatabase("invalid notification fanout lease")
            }
            return (token, rawExpiry)
        default:
            throw SQLiteRepositoryError.corruptDatabase("invalid notification fanout lease")
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

    /// Account databases share the two-hex layout shard, so the CAS must add
    /// the full DID hash before its content digest.  Otherwise two unrelated
    /// accounts that happen to share a layout prefix could race on a payload
    /// file while SQLite tracks references only in their separate databases.
    private var accountBlobNamespace: String {
        Hex.encode(SHA256.hash(data: Data(accountDID.utf8)))
    }

    private func legacyBlobCID(_ payload: Data) -> String {
        "sha256:\(Hex.encode(SHA256.hash(data: payload)))"
    }

    private func canonicalRawBlobCID(_ value: String) throws -> CID {
        let cid: CID
        do {
            cid = try CID.parse(value)
        } catch {
            throw SwanError.malformed("blob CID is invalid")
        }
        guard cid.string == value,
              cid.codec == .raw,
              cid.multihash.algorithm == Multihash.sha256Code,
              cid.multihash.length == Multihash.sha256Length,
              cid.multihash.digest.count == Int(Multihash.sha256Length) else {
            throw SwanError.malformed("blob CID is invalid")
        }
        return cid
    }

    private func blobDigestHex(cid: String, allowLegacy: Bool) throws -> String {
        if let parsed = try? canonicalRawBlobCID(cid) {
            return Hex.encode(parsed.multihash.digest)
        }
        guard allowLegacy,
              cid.utf8.count == 71,
              cid.hasPrefix("sha256:"),
              let digest = legacyBlobDigest(cid) else {
            throw SwanError.malformed("blob CID is invalid")
        }
        return Hex.encode(digest)
    }

    private func legacyBlobDigest(_ value: String) -> Data? {
        guard value.utf8.count == 71, value.hasPrefix("sha256:") else {
            return nil
        }
        let characters = Array(value.dropFirst("sha256:".count).utf8)
        guard characters.count == 64 else { return nil }
        var output = Data()
        output.reserveCapacity(32)
        for index in stride(from: 0, to: characters.count, by: 2) {
            func nibble(_ value: UInt8) -> UInt8? {
                switch value {
                case UInt8(ascii: "0") ... UInt8(ascii: "9"):
                    value - UInt8(ascii: "0")
                case UInt8(ascii: "a") ... UInt8(ascii: "f"):
                    value - UInt8(ascii: "a") + 10
                default:
                    nil
                }
            }
            guard let high = nibble(characters[index]),
                  let low = nibble(characters[index + 1]) else {
                return nil
            }
            output.append((high << 4) | low)
        }
        return output
    }

    private func blobByteCount(_ count: Int) throws -> Int {
        guard count >= 0 else {
            throw SwanError.malformed("blob size is invalid")
        }
        return count
    }

    /// Keep the original upload MIME only when it is a simple header token
    /// pair.  A database row is never allowed to introduce a line break,
    /// parameter, or other response-header syntax at the HTTP boundary.
    private func safeBlobMIMEType(_ value: String?) -> String? {
        guard let value,
              !value.isEmpty,
              value.utf8.count <= 255,
              value.utf8.allSatisfy({ byte in
                  (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
                      || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
                      || (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
                      || "!#$&^_.+-/".utf8.contains(byte)
              }),
              value.filter({ $0 == "/" }).count == 1,
              !value.hasPrefix("/"), !value.hasSuffix("/")
        else {
            return nil
        }
        return value
    }

    private func verifiedPublicGenesis(
        car: Data,
        signingPublicKey: P256.Signing.PublicKey
    ) throws -> PublicRepositoryGenesis {
        let verified: PublicRepositoryGenesis
        do {
            verified = try PublicRepositoryGenesisCodec.verify(
                car: car,
                publicKey: signingPublicKey
            )
        } catch {
            throw PublicRepositoryGenesisStoreError.corruptStoredGenesis
        }
        guard verified.did == accountDID else {
            throw PublicRepositoryGenesisStoreError.ownershipMismatch
        }
        return verified
    }

    private func decodeStoredPublicRepositoryGenesis(
        _ row: SQLiteRow,
        signingPublicKey: P256.Signing.PublicKey
    ) throws -> PersistedPublicRepositoryGenesis {
        do {
            let did = try requiredText(row, "did")
            let revision = try requiredText(row, "revision")
            let commitCID = try requiredText(row, "commit_cid")
            let car = try requiredBlob(row, "car")
            let timestamp = try requiredNonnegativeInteger(row, "installed_at")
            guard did == accountDID else {
                throw PublicRepositoryGenesisStoreError.ownershipMismatch
            }
            let verified = try verifiedPublicGenesis(
                car: car,
                signingPublicKey: signingPublicKey
            )
            guard verified.did == did,
                  verified.revision == revision,
                  verified.commitCID.string == commitCID else {
                throw PublicRepositoryGenesisStoreError.corruptStoredGenesis
            }
            return try PersistedPublicRepositoryGenesis(
                genesis: verified,
                installedAt: Date(timeIntervalSince1970: Double(timestamp) / 1_000_000)
            )
        } catch let error as PublicRepositoryGenesisStoreError {
            throw error
        } catch {
            throw PublicRepositoryGenesisStoreError.corruptStoredGenesis
        }
    }

    private func publicGenesisTimestamp(_ date: Date) throws -> Int {
        let microseconds = date.timeIntervalSince1970 * 1_000_000
        guard microseconds.isFinite,
              microseconds >= 0,
              microseconds <= Double(Int.max)
        else {
            throw PublicRepositoryGenesisStoreError.invalidTimestamp
        }
        return Int(microseconds.rounded(.down))
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

/// A one-shot, already-open descriptor for an authorized private blob.  The
/// digest check completes before this object reaches HTTP, so the response
/// cannot start successfully and later discover that a swapped/corrupt file
/// had a different CID.  It intentionally exposes neither a path nor a way
/// to seek/reopen the payload.
private final class SQLiteVerifiedSpaceBlobBody: @unchecked Sendable,
    AuthorizedSpaceBlobBody
{
    private let lock = NSLock()
    private var descriptor: Int32
    let contentLength: Int

    init(
        descriptor: Int32,
        expectedDigest: Data,
        expectedLength: Int
    ) throws {
        guard expectedLength >= 0, expectedDigest.count == 32 else {
            throw SwanError.unavailable("permissioned blob storage is unavailable")
        }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(),
              (metadata.st_mode & 0o777) == 0o600,
              metadata.st_size >= 0,
              metadata.st_size <= off_t(Int.max),
              Int(metadata.st_size) == expectedLength else {
            throw SwanError.unavailable("permissioned blob storage is unavailable")
        }

        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        var digest = SHA256()
        var readLength = 0
        while let chunk = try handle.read(upToCount: 64 * 1_024), !chunk.isEmpty {
            try Task.checkCancellation()
            digest.update(data: chunk)
            guard readLength <= expectedLength - chunk.count else {
                throw SwanError.unavailable("permissioned blob storage is unavailable")
            }
            readLength += chunk.count
        }
        guard readLength == expectedLength,
              Data(digest.finalize()) == expectedDigest,
              lseek(descriptor, 0, SEEK_SET) == 0 else {
            throw SwanError.unavailable("permissioned blob storage is unavailable")
        }

        self.descriptor = descriptor
        contentLength = expectedLength
    }

    deinit { closeDescriptor() }

    func streamBody(
        maximumChunkBytes: Int,
        consume: (Data) async throws -> Void
    ) async throws {
        guard (1 ... 64 * 1_024).contains(maximumChunkBytes) else {
            closeDescriptor()
            throw SwanError.malformed("permissioned blob chunk size is invalid")
        }
        let descriptor = takeDescriptor()
        guard descriptor >= 0 else {
            throw SwanError.unavailable("permissioned blob storage is unavailable")
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        while true {
            try Task.checkCancellation()
            guard let chunk = try handle.read(upToCount: maximumChunkBytes),
                  !chunk.isEmpty else {
                return
            }
            try await consume(chunk)
        }
    }

    /// Releases a verified descriptor that was opened only to validate an
    /// existing CAS entry before lifecycle adoption.  This keeps the verifier
    /// one-shot just like the HTTP streaming path without buffering a body.
    func discardUnstreamed() {
        closeDescriptor()
    }

    private func takeDescriptor() -> Int32 {
        lock.lock()
        defer { lock.unlock() }
        let result = descriptor
        descriptor = -1
        return result
    }

    private func closeDescriptor() {
        let descriptor = takeDescriptor()
        if descriptor >= 0 { _ = close(descriptor) }
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

    /// Applies XRPC operation kinds without collapsing them into a generic
    /// upsert before SQLite has made the revision-CAS decision.  This is the
    /// write-side counterpart to the read projections: it reads only the
    /// local durable snapshot needed to choose the expected revision and to
    /// preflight an ordered batch, then performs one no-network transaction.
    public func applyAuthorizedWrites(
        _ writes: [AuthorizedSpaceRepositoryWrite],
        requestID: UUID,
        wireRevision: TID,
        authorization: AuthorizationContext
    ) async throws -> [AuthorizedSpaceRepositoryWriteResult] {
        guard !writes.isEmpty else {
            throw SwanError.malformed("repository batch must contain a write")
        }

        let snapshot = try await database.repositorySnapshot(space: space, author: author)
        let expectedRevision = snapshot?.state.revision ?? 0
        var expectedRecords = Dictionary(
            uniqueKeysWithValues: (snapshot?.records ?? []).map { ($0.uri, $0) }
        )
        var sqliteWrites: [SQLiteSpaceWrite] = []

        for write in writes {
            let uri = write.uri
            try requireRepositoryURI(uri)
            let existing = expectedRecords[uri]
            switch write {
            case let .create(_, value):
                try requireWrite(uri: uri, authorization: authorization, permission: .create)
                guard existing == nil else {
                    throw SwanError.malformed("cannot create an existing record")
                }
                let cid = CID.fromDAGCBOR(value).string
                sqliteWrites.append(.create(uri: uri, value: value, cid: cid))
                expectedRecords[uri] = PersistedSpaceRecord(uri: uri, value: value, cid: cid, revision: expectedRevision + 1)
            case let .put(_, value):
                // A `putRecord` can be either branch when the transaction
                // reaches SQLite, so both grants are mandatory before the
                // state-dependent choice is made.
                try requireWrite(uri: uri, authorization: authorization, permission: .create)
                try requireWrite(uri: uri, authorization: authorization, permission: .update)
                let cid = CID.fromDAGCBOR(value).string
                sqliteWrites.append(.put(uri: uri, value: value, cid: cid))
                expectedRecords[uri] = PersistedSpaceRecord(uri: uri, value: value, cid: cid, revision: expectedRevision + 1)
            case let .update(_, value):
                try requireWrite(uri: uri, authorization: authorization, permission: .update)
                guard existing != nil else {
                    throw SwanError.malformed("cannot update a missing record")
                }
                let cid = CID.fromDAGCBOR(value).string
                sqliteWrites.append(.update(uri: uri, value: value, cid: cid))
                expectedRecords[uri] = PersistedSpaceRecord(uri: uri, value: value, cid: cid, revision: expectedRevision + 1)
            case .delete:
                try requireWrite(uri: uri, authorization: authorization, permission: .delete)
                guard existing != nil else {
                    throw SwanError.malformed("cannot delete a missing record")
                }
                sqliteWrites.append(.delete(uri: uri))
                expectedRecords.removeValue(forKey: uri)
            }
        }

        let persisted = try await database.apply(
            space: space,
            author: author,
            expectedRevision: expectedRevision,
            requestID: requestID,
            wireRevision: wireRevision,
            writes: sqliteWrites
        )
        return try persisted.entries.map { entry in
            let action: AuthorizedSpaceRepositoryWriteResult.Action = switch entry.action {
            case .create: .create
            case .update: .update
            case .delete: .delete
            }
            guard entry.write.uri.space == space, entry.write.uri.author == author else {
                throw SQLiteRepositoryError.corruptDatabase("write result belongs to another repository")
            }
            return AuthorizedSpaceRepositoryWriteResult(
                action: action,
                uri: entry.write.uri,
                cid: entry.cid
            )
        }
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

    /// Returns only the durable facts that an account-key backed signer needs
    /// for a fresh reader-specific commit.  A never-written repository has a
    /// zero LtHash commitment but no wire revision, so the HTTP handler emits
    /// no signed commit exactly like the pinned TypeScript PDS.
    public func currentCommitState(
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceRepositoryCommitState {
        try requireRead(uri: nil, authorization: authorization)
        if let state = try await database.repositoryState(space: space, author: author) {
            return AuthorizedSpaceRepositoryCommitState(
                space: state.space,
                author: state.author,
                wireRevision: state.wireRevision.toString(),
                commitment: state.commitment
            )
        }
        return AuthorizedSpaceRepositoryCommitState(
            space: space,
            author: author,
            wireRevision: nil,
            commitment: LtHash().commitment
        )
    }

    /// Creates a private, immutable full-recovery snapshot after applying the
    /// same aggregate read policy used by the repository endpoints. In
    /// particular, a collection-qualified OAuth scope cannot downgrade this
    /// into a partial repository export.
    public func prepareCARSnapshot(
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceRepositoryCARSnapshot? {
        try requireRead(uri: nil, authorization: authorization)
        return try await database.prepareRepositoryCARSnapshot(
            space: space,
            author: author
        )
    }

    /// Opens one already-authorized, file-backed blob body.  Blob retrieval is
    /// an aggregate repository read: a collection-qualified OAuth grant may
    /// read its individual records but cannot be repurposed into an arbitrary
    /// blob oracle.
    public func permissionedBlob(
        cid: String,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceBlob? {
        try requireRead(uri: nil, authorization: authorization)
        return try await database.permissionedBlob(
            space: space,
            author: author,
            cid: cid
        )
    }

    /// Reads the pinned wire-TID incremental oplog page.  The durable query
    /// joins values only against their matching live records; this facade
    /// preserves operation ordering and maps a retention gap to an explicit
    /// recovery requirement rather than synthesizing an incomplete delta.
    public func incrementalOplog(
        since: TID?,
        limit: Int,
        includeValues: Bool,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceRepositoryOplogRead {
        try requireRead(uri: nil, authorization: authorization)
        switch try await database.wireOplog(
            space: space,
            author: author,
            since: since,
            limit: limit,
            includeValues: includeValues
        ) {
        case let .incremental(state, entries):
            let projectedState: AuthorizedSpaceRepositoryCommitState
            if let state {
                projectedState = AuthorizedSpaceRepositoryCommitState(
                    space: state.space,
                    author: state.author,
                    wireRevision: state.wireRevision.toString(),
                    commitment: state.commitment
                )
            } else {
                projectedState = AuthorizedSpaceRepositoryCommitState(
                    space: space,
                    author: author,
                    wireRevision: nil,
                    commitment: LtHash().commitment
                )
            }
            return .incremental(
                state: projectedState,
                entries: entries.map { entry in
                    AuthorizedSpaceRepositoryOplogEntry(
                        wireRevision: entry.wireRevision.toString(),
                        collection: entry.uri.collection,
                        rkey: entry.uri.rkey,
                        cid: entry.cid,
                        previousCID: entry.previousCID,
                        value: entry.value
                    )
                }
            )
        case .fullRecoveryRequired:
            return .fullRecoveryRequired
        }
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

    /// Returns the exact page shape used by the pinned
    /// `com.atproto.space.listRecords` reader. The pinned implementation
    /// orders the default page descending by `(collection, rkey)` and flips
    /// to ascending only when `reverse` is true. Cursor syntax that cannot
    /// name a domain record is deliberately ignored, matching the reference
    /// reader's tolerant `parseListCursor` behavior.
    ///
    /// This remains a domain operation: a collection-qualified OAuth grant
    /// is checked against a synthetic, valid record URI before the durable
    /// snapshot is queried. An omitted collection therefore cannot silently
    /// downgrade an aggregate response to a censored list.
    public func listRecords(
        collection: String?,
        limit: Int,
        cursor: String?,
        reverse: Bool,
        authorization: AuthorizationContext
    ) async throws -> [SpaceRecord] {
        guard (1 ... 100).contains(limit) else {
            throw SwanError.malformed("permissioned record page limit is invalid")
        }

        let authorizationURI: SpaceRecordURI?
        if let collection {
            // The value exists only to carry the collection into the domain
            // policy. It is never queried or serialized.
            authorizationURI = try SpaceRecordURI(
                space: space,
                author: author,
                collection: collection,
                rkey: "scope"
            )
        } else {
            authorizationURI = nil
        }
        try requireRead(uri: authorizationURI, authorization: authorization)

        let allRecords = try await database.repositorySnapshot(
            space: space,
            author: author
        )?.records.map(record(from:)) ?? []
        let filtered = allRecords.filter { record in
            collection.map { record.uri.collection == $0 } ?? true
        }
        let ordered = filtered.sorted { lhs, rhs in
            if lhs.uri.collection == rhs.uri.collection {
                return reverse
                    ? lhs.uri.rkey < rhs.uri.rkey
                    : lhs.uri.rkey > rhs.uri.rkey
            }
            return reverse
                ? lhs.uri.collection < rhs.uri.collection
                : lhs.uri.collection > rhs.uri.collection
        }

        let cursorKey = cursor.flatMap(Self.parseListCursor)
        let afterCursor = ordered.filter { record in
            guard let cursorKey else { return true }
            let key = (collection: record.uri.collection, rkey: record.uri.rkey)
            if key.collection == cursorKey.collection {
                return reverse
                    ? key.rkey > cursorKey.rkey
                    : key.rkey < cursorKey.rkey
            }
            return reverse
                ? key.collection > cursorKey.collection
                : key.collection < cursorKey.collection
        }
        return Array(afterCursor.prefix(limit))
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
        case let .create(uri, value, _), let .put(uri, value, _),
             let .update(uri, value, _):
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

    private static func parseListCursor(
        _ cursor: String
    ) -> (collection: String, rkey: String)? {
        let pieces = cursor.split(separator: "/", omittingEmptySubsequences: false)
        guard pieces.count == 2,
              let URI = try? SpaceRecordURI(
                  space: try SpaceURI(
                      authority: "did:plc:abcdefghijklmnopqrstuvwx",
                      spaceType: "app.swan.cursor",
                      skey: "cursor"
                  ),
                  author: "did:plc:abcdefghijklmnopqrstuvwx",
                  collection: String(pieces[0]),
                  rkey: String(pieces[1])
              ) else {
            return nil
        }
        return (URI.collection, URI.rkey)
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
    private let credentials: HMACSpaceCredentialAuthority?

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

    /// Lifecycle-only facade used by the startup-preopened HTTP authority
    /// directory. It intentionally cannot mint credentials: that requires a
    /// separately configured secret-bearing authority instance.
    public init(lifecycleDatabase database: SQLiteAccountDatabase) {
        self.database = database
        credentials = nil
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

    public func update(
        space: SpaceURI,
        patch: SimpleSpaceConfigurationPatch,
        authorization: AuthorizationContext,
        now: Date = Date()
    ) async throws -> DurableSimpleSpaceState {
        try await database.patchSimpleSpace(
            space: space,
            patch: patch,
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
        guard let credentials else {
            throw SwanError.unavailable("credential authority is unavailable")
        }
        return try credentials.issue(SpaceCredential(grant: grant, issuedAt: now))
    }
}
