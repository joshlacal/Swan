import Foundation
import SQLiteNIO
import SwanCore
import SwanSpaces
import SwanStorage

/// A queued authority-to-repo-host `com.atproto.space.notifyCredentialsRevoked`
/// delivery (`atproto#5567`). Created inside the same SQLite transaction as
/// `removeSimpleSpaceMembers` or `deleteSimpleSpace` / conversation deletion so
/// no network call occurs under a database lock (`I6`) and restarts retry until
/// the revoked credential's clock-skew retention window elapses.
public struct PersistedSpaceCredentialRevocationNotification: Sendable, Equatable {
    public let id: UUID
    public let space: SpaceURI
    public let recipientDID: String
    public let credentialIDs: [String]
    public let retryExpiresAt: Date
    public let attempts: Int

    public init(
        id: UUID,
        space: SpaceURI,
        recipientDID: String,
        credentialIDs: [String],
        retryExpiresAt: Date,
        attempts: Int
    ) {
        self.id = id
        self.space = space
        self.recipientDID = recipientDID
        self.credentialIDs = credentialIDs
        self.retryExpiresAt = retryExpiresAt
        self.attempts = attempts
    }
}

public struct PersistedSpaceCredentialRevocationNotificationLease: Sendable, Equatable {
    public let event: PersistedSpaceCredentialRevocationNotification
    public let token: UUID
    public let expiresAt: Date

    public init(
        event: PersistedSpaceCredentialRevocationNotification,
        token: UUID,
        expiresAt: Date
    ) {
        self.event = event
        self.token = token
        self.expiresAt = expiresAt
    }
}

extension SQLiteAccountDatabase {
    static let spaceCredentialRevocationOutboxMigrationVersion = 31
    private static let maximumCredentialsPerRevocationNotification = 100
    /// Widest verifier clock skew + issued-at lead (`300 + 5 = 305 s`), matching
    /// `DurableSpaceCredentialRevocations.retention` past credential `exp`.
    private static let credentialRevocationSkewMarginMicroseconds = 305 * 1_000_000
    private static let maximumTrackedIssuedCredentialsPerSpace = 8_192

    func migrateSpaceCredentialRevocationOutboxIfNeeded() async throws {
        _ = try await connection.query(
            """
            CREATE TABLE IF NOT EXISTS permissioned_issued_space_credentials (
                space_uri TEXT NOT NULL,
                subject_did TEXT,
                jti TEXT NOT NULL CHECK(length(jti) BETWEEN 1 AND 256),
                expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
                revoked_at INTEGER CHECK(revoked_at IS NULL OR revoked_at >= 0),
                PRIMARY KEY(space_uri, jti)
            )
            """
        )
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS permissioned_issued_space_credentials_lookup
            ON permissioned_issued_space_credentials(space_uri, subject_did, expires_at)
            """
        )
        _ = try await connection.query(
            """
            CREATE TABLE IF NOT EXISTS permissioned_space_credential_revocation_notifications (
                id TEXT PRIMARY KEY,
                space_uri TEXT NOT NULL,
                recipient_did TEXT NOT NULL,
                credentials_json TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                created_at INTEGER NOT NULL CHECK(created_at >= 0),
                available_at INTEGER NOT NULL CHECK(available_at >= 0),
                retry_expires_at INTEGER NOT NULL CHECK(retry_expires_at >= 0),
                lease_token TEXT,
                lease_expires_at INTEGER,
                CHECK(
                    (lease_token IS NULL AND lease_expires_at IS NULL)
                    OR (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL
                        AND lease_expires_at >= 0)
                )
            )
            """
        )
        _ = try await connection.query(
            """
            CREATE INDEX IF NOT EXISTS permissioned_space_credential_revocation_notifications_available
            ON permissioned_space_credential_revocation_notifications(available_at, created_at, id)
            """
        )
        _ = try await connection.query(
            """
            INSERT OR IGNORE INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [
                .integer(Self.spaceCredentialRevocationOutboxMigrationVersion),
                .integer(Int(Date().timeIntervalSince1970 * 1_000_000)),
            ]
        )
    }

    public func recordIssuedSpaceCredential(
        space: SpaceURI,
        user: String?,
        credentialID: String,
        expiresAt: Date,
        now: Date = Date()
    ) async throws {
        guard space.authority == accountDID else {
            throw SwanError.unauthorized("space credential authority belongs to another account")
        }
        guard Self.isValidRevocableCredentialID(credentialID) else {
            throw SwanError.malformed("space credential ID is invalid")
        }
        if let user {
            guard isValidSimpleSpaceDID(user) else {
                throw SwanError.invalidIdentifier(user)
            }
        }
        let nowMicros = try simpleSpaceTimestamp(now)
        let expiresMicros = try simpleSpaceTimestamp(expiresAt)
        let retentionFloor = max(0, nowMicros - Self.credentialRevocationSkewMarginMicroseconds)
        try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    """
                    DELETE FROM permissioned_issued_space_credentials
                    WHERE expires_at <= ?
                    """,
                    [.integer(retentionFloor)]
                )
                let count = try await connection.query(
                    """
                    SELECT COUNT(*) AS count
                    FROM permissioned_issued_space_credentials
                    WHERE space_uri = ? AND revoked_at IS NULL
                    """,
                    [.text(space.rawValue)]
                ).first?.column("count")?.integer ?? 0
                if count >= Self.maximumTrackedIssuedCredentialsPerSpace {
                    _ = try await connection.query(
                        """
                        DELETE FROM permissioned_issued_space_credentials
                        WHERE rowid IN (
                            SELECT rowid FROM permissioned_issued_space_credentials
                            WHERE space_uri = ?
                            ORDER BY expires_at ASC, jti ASC
                            LIMIT 1
                        )
                        """,
                        [.text(space.rawValue)]
                    )
                }
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_issued_space_credentials(
                        space_uri, subject_did, jti, expires_at, revoked_at
                    ) VALUES (?, ?, ?, ?, NULL)
                    ON CONFLICT(space_uri, jti) DO UPDATE SET
                        subject_did = COALESCE(permissioned_issued_space_credentials.subject_did, excluded.subject_did),
                        expires_at = MAX(permissioned_issued_space_credentials.expires_at, excluded.expires_at)
                    """,
                    [
                        .text(space.rawValue),
                        user.map(SQLiteData.text) ?? .null,
                        .text(credentialID),
                        .integer(expiresMicros),
                    ]
                )
            }
        }
    }

    public func recentlyRevokedSpaceCredentialIDs(
        _ space: SpaceURI,
        now: Date = Date()
    ) async throws -> [String] {
        guard space.authority == accountDID else {
            throw SwanError.unauthorized("space credential authority belongs to another account")
        }
        let cutoff = max(
            0,
            (try simpleSpaceTimestamp(now)) - Self.credentialRevocationSkewMarginMicroseconds
        )
        return try await withReadConnectionGate {
            let rows = try await readConnection.query(
                """
                SELECT jti FROM permissioned_issued_space_credentials
                WHERE space_uri = ?
                  AND revoked_at IS NOT NULL
                  AND expires_at > ?
                ORDER BY jti ASC
                """,
                [.text(space.rawValue), .integer(cutoff)]
            )
            return rows.compactMap { $0.column("jti")?.string }
        }
    }

    /// Caller holds the writer connection gate and active SQLite transaction,
    /// BEFORE deleting rows from `permissioned_space_writers` or
    /// `permissioned_simple_space_members`.
    @discardableResult
    func enqueueMemberSpaceCredentialRevocationsWithoutGate(
        space: SpaceURI,
        members: [String],
        timestamp: Int
    ) async throws -> [String] {
        let targetMembers = Array(Set(members)).sorted()
        guard !targetMembers.isEmpty else { return [] }
        let activeCutoff = max(0, timestamp - Self.credentialRevocationSkewMarginMicroseconds)

        let placeholders = Array(repeating: "?", count: targetMembers.count).joined(separator: ", ")
        let queryArgs: [SQLiteData] =
            [.text(space.rawValue), .integer(activeCutoff)] + targetMembers.map(SQLiteData.text)
        let credRows = try await connection.query(
            """
            SELECT jti, expires_at
            FROM permissioned_issued_space_credentials
            WHERE space_uri = ?
              AND revoked_at IS NULL
              AND expires_at > ?
              AND subject_did IN (\(placeholders))
            ORDER BY jti ASC
            """,
            queryArgs
        )
        let activeCreds: [(jti: String, expiresAt: Int)] = credRows.compactMap { row in
            guard let jti = row.column("jti")?.string,
                  let exp = row.column("expires_at")?.integer else {
                return nil
            }
            return (jti, exp)
        }
        guard !activeCreds.isEmpty else { return [] }

        let recipients = try await collectCredentialRevocationRecipientsWithoutGate(
            space: space,
            additionalDIDs: targetMembers
        )
        try await markAndEnqueueCredentialRevocationsWithoutGate(
            space: space,
            activeCreds: activeCreds,
            recipients: recipients,
            timestamp: timestamp
        )
        return activeCreds.map(\.jti)
    }

    /// Caller holds the writer connection gate and active SQLite transaction,
    /// BEFORE deleting rows from `permissioned_space_writers`.
    @discardableResult
    func enqueueAllSpaceCredentialRevocationsWithoutGate(
        space: SpaceURI,
        timestamp: Int
    ) async throws -> [String] {
        let activeCutoff = max(0, timestamp - Self.credentialRevocationSkewMarginMicroseconds)
        let credRows = try await connection.query(
            """
            SELECT jti, expires_at, subject_did
            FROM permissioned_issued_space_credentials
            WHERE space_uri = ?
              AND revoked_at IS NULL
              AND expires_at > ?
            ORDER BY jti ASC
            """,
            [.text(space.rawValue), .integer(activeCutoff)]
        )
        var subjectDIDs: [String] = []
        let activeCreds: [(jti: String, expiresAt: Int)] = credRows.compactMap { row in
            guard let jti = row.column("jti")?.string,
                  let exp = row.column("expires_at")?.integer else {
                return nil
            }
            if let sub = row.column("subject_did")?.string, isValidSimpleSpaceDID(sub) {
                subjectDIDs.append(sub)
            }
            return (jti, exp)
        }
        guard !activeCreds.isEmpty else { return [] }

        let recipients = try await collectCredentialRevocationRecipientsWithoutGate(
            space: space,
            additionalDIDs: subjectDIDs
        )
        try await markAndEnqueueCredentialRevocationsWithoutGate(
            space: space,
            activeCreds: activeCreds,
            recipients: recipients,
            timestamp: timestamp
        )
        return activeCreds.map(\.jti)
    }

    private func collectCredentialRevocationRecipientsWithoutGate(
        space: SpaceURI,
        additionalDIDs: [String]
    ) async throws -> [String] {
        var recipients: Set<String> = [accountDID]
        for did in additionalDIDs where isValidSimpleSpaceDID(did) {
            recipients.insert(did)
        }
        let writerRows = try await connection.query(
            "SELECT repo_did FROM permissioned_space_writers WHERE space_uri = ?",
            [.text(space.rawValue)]
        )
        for row in writerRows {
            if let did = row.column("repo_did")?.string, isValidSimpleSpaceDID(did) {
                recipients.insert(did)
            }
        }
        let memberRows = try await connection.query(
            "SELECT member_did FROM permissioned_simple_space_members WHERE space_uri = ?",
            [.text(space.rawValue)]
        )
        for row in memberRows {
            if let did = row.column("member_did")?.string, isValidSimpleSpaceDID(did) {
                recipients.insert(did)
            }
        }
        return recipients.sorted()
    }

    private func markAndEnqueueCredentialRevocationsWithoutGate(
        space: SpaceURI,
        activeCreds: [(jti: String, expiresAt: Int)],
        recipients: [String],
        timestamp: Int
    ) async throws {
        for cred in activeCreds {
            _ = try await connection.query(
                """
                UPDATE permissioned_issued_space_credentials
                SET revoked_at = ?
                WHERE space_uri = ? AND jti = ? AND revoked_at IS NULL
                """,
                [.integer(timestamp), .text(space.rawValue), .text(cred.jti)]
            )
        }
        guard !recipients.isEmpty else { return }

        var index = 0
        while index < activeCreds.count {
            let end = min(index + Self.maximumCredentialsPerRevocationNotification, activeCreds.count)
            let slice = activeCreds[index ..< end]
            let ids = slice.map(\.jti)
            let maxExpires = slice.map(\.expiresAt).max() ?? timestamp
            let retryExpiresAt = maxExpires + Self.credentialRevocationSkewMarginMicroseconds
            let jsonBytes = try JSONEncoder().encode(ids)
            guard let credentialsJSON = String(data: jsonBytes, encoding: .utf8) else {
                throw SwanError.malformed("unable to encode revoked credential IDs")
            }
            for recipient in recipients {
                let id = UUID().uuidString.lowercased()
                _ = try await connection.query(
                    """
                    INSERT INTO permissioned_space_credential_revocation_notifications(
                        id, space_uri, recipient_did, credentials_json,
                        attempts, created_at, available_at, retry_expires_at,
                        lease_token, lease_expires_at
                    ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, NULL, NULL)
                    """,
                    [
                        .text(id),
                        .text(space.rawValue),
                        .text(recipient),
                        .text(credentialsJSON),
                        .integer(timestamp),
                        .integer(timestamp),
                        .integer(retryExpiresAt),
                    ]
                )
            }
            index = end
        }
    }

    public func leaseNextSpaceCredentialRevocationNotification(
        now: Date = Date(),
        leaseDuration: TimeInterval
    ) async throws -> PersistedSpaceCredentialRevocationNotificationLease? {
        guard leaseDuration.isFinite, leaseDuration > 0, leaseDuration <= 24 * 60 * 60 else {
            throw SwanError.malformed("invalid credential revocation lease duration")
        }
        let nowTimestamp = try simpleSpaceTimestamp(now)
        let leaseExpiry = try simpleSpaceTimestamp(now.addingTimeInterval(leaseDuration))
        return try await withConnectionGate {
            try await transaction {
                _ = try await connection.query(
                    """
                    DELETE FROM permissioned_space_credential_revocation_notifications
                    WHERE retry_expires_at <= ?
                    """,
                    [.integer(nowTimestamp)]
                )
                while true {
                    let token = UUID()
                    let rows = try await connection.query(
                        """
                        SELECT rowid AS queue_rowid,
                               id, space_uri, recipient_did, credentials_json,
                               retry_expires_at, attempts
                        FROM permissioned_space_credential_revocation_notifications
                        WHERE available_at <= ?
                          AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                        ORDER BY available_at, created_at, id
                        LIMIT 1
                        """,
                        [.integer(nowTimestamp), .integer(nowTimestamp)]
                    )
                    guard let row = rows.first else { return nil }
                    let event: PersistedSpaceCredentialRevocationNotification
                    do {
                        event = try Self.decodeSpaceCredentialRevocationNotification(row)
                    } catch {
                        if let rowID = row.column("queue_rowid")?.integer {
                            _ = try await connection.query(
                                "DELETE FROM permissioned_space_credential_revocation_notifications WHERE rowid = ?",
                                [.integer(rowID)]
                            )
                            continue
                        }
                        throw error
                    }
                    _ = try await connection.query(
                        """
                        UPDATE permissioned_space_credential_revocation_notifications
                        SET lease_token = ?, lease_expires_at = ?
                        WHERE id = ?
                        """,
                        [
                            .text(token.uuidString.lowercased()),
                            .integer(leaseExpiry),
                            .text(event.id.uuidString.lowercased()),
                        ]
                    )
                    return PersistedSpaceCredentialRevocationNotificationLease(
                        event: event,
                        token: token,
                        expiresAt: Date(timeIntervalSince1970: Double(leaseExpiry) / 1_000_000)
                    )
                }
            }
        }
    }

    public func pendingSpaceCredentialRevocationNotifications() async throws -> [PersistedSpaceCredentialRevocationNotification] {
        try await withConnectionGate {
            let rows = try await connection.query(
                """
                SELECT id, space_uri, recipient_did, credentials_json, retry_expires_at, attempts
                FROM permissioned_space_credential_revocation_notifications
                ORDER BY created_at ASC, rowid ASC
                """
            )
            return try rows.map(Self.decodeSpaceCredentialRevocationNotification)
        }
    }

    @discardableResult
    public func completeSpaceCredentialRevocationNotificationLease(
        eventID: UUID,
        token: UUID
    ) async throws -> Bool {
        try await withConnectionGate {
            try await transaction {
                let idString = eventID.uuidString.lowercased()
                let tokenString = token.uuidString.lowercased()
                let existing = try await connection.query(
                    """
                    SELECT 1 FROM permissioned_space_credential_revocation_notifications
                    WHERE id = ? AND lease_token = ?
                    """,
                    [.text(idString), .text(tokenString)]
                )
                guard !existing.isEmpty else { return false }
                _ = try await connection.query(
                    """
                    DELETE FROM permissioned_space_credential_revocation_notifications
                    WHERE id = ? AND lease_token = ?
                    """,
                    [.text(idString), .text(tokenString)]
                )
                return true
            }
        }
    }

    public func failSpaceCredentialRevocationNotificationLease(
        eventID: UUID,
        token: UUID,
        retryAt: Date
    ) async throws -> Int? {
        let retryTimestamp = try simpleSpaceTimestamp(retryAt)
        return try await withConnectionGate {
            try await transaction {
                let idString = eventID.uuidString.lowercased()
                let tokenString = token.uuidString.lowercased()
                let rows = try await connection.query(
                    """
                    SELECT attempts FROM permissioned_space_credential_revocation_notifications
                    WHERE id = ? AND lease_token = ?
                    """,
                    [.text(idString), .text(tokenString)]
                )
                guard let currentAttempts = rows.first?.column("attempts")?.integer else {
                    return nil
                }
                let nextAttempts = currentAttempts + 1
                _ = try await connection.query(
                    """
                    UPDATE permissioned_space_credential_revocation_notifications
                    SET attempts = ?, available_at = ?, lease_token = NULL, lease_expires_at = NULL
                    WHERE id = ? AND lease_token = ?
                    """,
                    [
                        .integer(nextAttempts),
                        .integer(retryTimestamp),
                        .text(idString),
                        .text(tokenString),
                    ]
                )
                return nextAttempts
            }
        }
    }

    private static func decodeSpaceCredentialRevocationNotification(
        _ row: SQLiteRow
    ) throws -> PersistedSpaceCredentialRevocationNotification {
        guard let rawID = row.column("id")?.string,
              let id = UUID(uuidString: rawID),
              let rawSpace = row.column("space_uri")?.string,
              let recipientDID = row.column("recipient_did")?.string,
              (try? SpaceURI(authority: recipientDID, spaceType: "com.atproto.space.defs", skey: "self")) != nil,
              !recipientDID.contains("#"),
              let rawCredentials = row.column("credentials_json")?.string,
              let credentialsData = rawCredentials.data(using: .utf8),
              let credentialIDs = try? JSONDecoder().decode([String].self, from: credentialsData),
              (1 ... maximumCredentialsPerRevocationNotification).contains(credentialIDs.count),
              credentialIDs.allSatisfy(isValidRevocableCredentialID),
              let retryExpiresMicros = row.column("retry_expires_at")?.integer,
              let attempts = row.column("attempts")?.integer,
              attempts >= 0 else {
            throw SwanError.malformed("stored space credential revocation notification is invalid")
        }
        return PersistedSpaceCredentialRevocationNotification(
            id: id,
            space: try SpaceURI(rawSpace),
            recipientDID: recipientDID,
            credentialIDs: credentialIDs,
            retryExpiresAt: Date(timeIntervalSince1970: Double(retryExpiresMicros) / 1_000_000),
            attempts: attempts
        )
    }

    private static func isValidRevocableCredentialID(_ value: String) -> Bool {
        let bytes = value.utf8
        return !bytes.isEmpty
            && bytes.count <= 256
            && bytes.allSatisfy { $0 >= 0x20 && $0 != 0x7f }
    }
}
