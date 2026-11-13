import Foundation
import SQLiteNIO
import SwanCore
import SwanSpaces

/// Account-schema v29: the October 29 2026 space `policy`.
///
/// The October 22 per-side configuration (`read_policy`, `write_policy`,
/// their managing apps and `app_access`) stays as the column encoding, and
/// three columns say which policy the row is and what it publishes. Existing
/// rows convert exactly as the reference `006-space-policy` migration does:
/// a stored managing app on either side (`read ?? write`) makes a
/// managedspace; anything else is a memberspace with `publicRead` /
/// `publicWrite` from the public sides and `allowedApps` from an allow-list.
/// Nothing is published. A space that becomes a managedspace loses its member
/// list (only the owner row Swan keeps for every policy survives) and any
/// app allow-list.
///
/// A conversion that changes who can reach the space (a one-sided managing
/// app, two different apps, a dropped allow-list or member list) is recorded,
/// with the old configuration, in `permissioned_space_policy_migration_v29`
/// and logged. ``SpacePolicyMigrationReport`` lists the same rows read-only,
/// before or after the upgrade.
extension SQLiteAccountDatabase {
    static let spacePolicyMigrationVersion = 29

    static let spacePolicyMigrationLogSchema = """
        CREATE TABLE IF NOT EXISTS permissioned_space_policy_migration_v29 (
            space_uri TEXT PRIMARY KEY,
            old_read_policy TEXT NOT NULL,
            old_read_managing_app TEXT,
            old_write_policy TEXT NOT NULL,
            old_write_managing_app TEXT,
            old_app_access TEXT NOT NULL,
            old_allowed_clients TEXT NOT NULL,
            dropped_member_count INTEGER NOT NULL CHECK(dropped_member_count >= 0),
            new_policy_type TEXT NOT NULL,
            new_managing_app TEXT,
            reasons TEXT NOT NULL,
            migrated_at INTEGER NOT NULL CHECK(migrated_at >= 0)
        )
        """

    /// Runs inside the notification migration transaction, after the v23
    /// authority rebuild, so the authority table always exists.
    func migrateSpacePolicyIfNeeded(now: Date = Date()) async throws {
        let applied = try await connection.query(
            "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
            [.integer(Self.spacePolicyMigrationVersion)]
        )
        guard applied.isEmpty else { return }
        let table = "permissioned_simple_space_authorities"
        if try await !notificationTableHasColumn(table, "policy_type") {
            _ = try await connection.query(
                """
                ALTER TABLE permissioned_simple_space_authorities
                ADD COLUMN policy_type TEXT NOT NULL DEFAULT 'memberspace'
                    CHECK(policy_type IN ('personalspace', 'memberspace', 'managedspace'))
                """
            )
        }
        if try await !notificationTableHasColumn(table, "publish_policy") {
            _ = try await connection.query(
                """
                ALTER TABLE permissioned_simple_space_authorities
                ADD COLUMN publish_policy INTEGER NOT NULL DEFAULT 0 CHECK(publish_policy IN (0, 1))
                """
            )
        }
        if try await !notificationTableHasColumn(table, "publish_members") {
            _ = try await connection.query(
                """
                ALTER TABLE permissioned_simple_space_authorities
                ADD COLUMN publish_members INTEGER NOT NULL DEFAULT 0 CHECK(publish_members IN (0, 1))
                """
            )
        }
        _ = try await connection.query(Self.spacePolicyMigrationLogSchema)
        let timestamp = Int(now.timeIntervalSince1970 * 1_000_000)
        let conversions = try await SpacePolicyMigrationReport.conversions(
            connection: connection
        )
        for conversion in conversions {
            let space = conversion.spaceURI
            if conversion.newPolicyType == SpacePolicyMigrationReport.managedType {
                _ = try await connection.query(
                    """
                    UPDATE permissioned_simple_space_authorities
                    SET policy_type = 'managedspace',
                        read_policy = 'managing-app', read_managing_app = ?,
                        write_policy = 'managing-app', write_managing_app = ?,
                        app_access = 'open', publish_policy = 0, publish_members = 0
                    WHERE space_uri = ?
                    """,
                    [
                        .text(conversion.newManagingApp ?? ""),
                        .text(conversion.newManagingApp ?? ""),
                        .text(space),
                    ]
                )
                _ = try await connection.query(
                    "DELETE FROM permissioned_simple_space_clients WHERE space_uri = ?",
                    [.text(space)]
                )
                _ = try await connection.query(
                    """
                    DELETE FROM permissioned_simple_space_members
                    WHERE space_uri = ? AND member_did != ?
                    """,
                    [.text(space), .text(conversion.owner)]
                )
            } else if conversion.newPolicyType == SpacePolicyMigrationReport.personalType {
                // A managing app the October 29 policy cannot name (not a
                // DID): no outside user can be authorized either way, so the
                // space keeps only its authority.
                _ = try await connection.query(
                    """
                    UPDATE permissioned_simple_space_authorities
                    SET policy_type = 'personalspace',
                        read_policy = 'member-list', read_managing_app = NULL,
                        write_policy = 'member-list', write_managing_app = NULL,
                        app_access = 'open', publish_policy = 0, publish_members = 0
                    WHERE space_uri = ?
                    """,
                    [.text(space)]
                )
                _ = try await connection.query(
                    "DELETE FROM permissioned_simple_space_clients WHERE space_uri = ?",
                    [.text(space)]
                )
                _ = try await connection.query(
                    """
                    DELETE FROM permissioned_simple_space_members
                    WHERE space_uri = ? AND member_did != ?
                    """,
                    [.text(space), .text(conversion.owner)]
                )
            } else {
                _ = try await connection.query(
                    """
                    UPDATE permissioned_simple_space_authorities
                    SET policy_type = 'memberspace', publish_policy = 0, publish_members = 0
                    WHERE space_uri = ?
                    """,
                    [.text(space)]
                )
            }
            guard !conversion.reasons.isEmpty else { continue }
            _ = try await connection.query(
                """
                INSERT OR REPLACE INTO permissioned_space_policy_migration_v29(
                    space_uri, old_read_policy, old_read_managing_app,
                    old_write_policy, old_write_managing_app, old_app_access,
                    old_allowed_clients, dropped_member_count, new_policy_type,
                    new_managing_app, reasons, migrated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    .text(space), .text(conversion.oldReadPolicy),
                    conversion.oldReadManagingApp.map(SQLiteData.text) ?? .null,
                    .text(conversion.oldWritePolicy),
                    conversion.oldWriteManagingApp.map(SQLiteData.text) ?? .null,
                    .text(conversion.oldAppAccess),
                    .text(conversion.oldAllowedClients.joined(separator: "\n")),
                    .integer(conversion.droppedMemberCount),
                    .text(conversion.newPolicyType),
                    conversion.newManagingApp.map(SQLiteData.text) ?? .null,
                    .text(conversion.reasons.joined(separator: ",")),
                    .integer(timestamp),
                ]
            )
            FileHandle.standardError.write(Data(
                "swan: space policy migration v29 converted \(space) to \(conversion.newPolicyType) (\(conversion.reasons.joined(separator: ","))); old configuration read=\(conversion.oldReadPolicy) readApp=\(conversion.oldReadManagingApp ?? "-") write=\(conversion.oldWritePolicy) writeApp=\(conversion.oldWriteManagingApp ?? "-") appAccess=\(conversion.oldAppAccess) clients=\(conversion.oldAllowedClients.count) droppedMembers=\(conversion.droppedMemberCount)\n".utf8
            ))
        }
        // Managing-app decisions recorded by the October 22 laboratory API
        // are no longer consulted: a managedspace asks its managing app.
        _ = try await connection.query(
            "DELETE FROM permissioned_simple_space_managing_app_decisions"
        )
        _ = try await connection.query(
            """
            INSERT OR IGNORE INTO permissioned_repository_migrations(version, applied_at)
            VALUES (?, ?)
            """,
            [.integer(Self.spacePolicyMigrationVersion), .integer(timestamp)]
        )
    }

    /// Rebuilds the configuration a v29 row stores. The October 22 columns
    /// must agree with `policy_type`, so a row edited behind Swan's back
    /// fails closed instead of widening access.
    func storedSimpleSpaceConfiguration(
        policyType: String,
        publishPolicy: Int,
        publishMembers: Int,
        readPolicy: SimpleSpacePolicy,
        readManagingApp: String?,
        writePolicy: SimpleSpacePolicy,
        writeManagingApp: String?,
        appAccess: SimpleSpaceAppAccess
    ) throws -> SimpleSpaceConfiguration {
        guard publishPolicy == 0 || publishPolicy == 1,
              publishMembers == 0 || publishMembers == 1 else {
            throw SwanError.malformed("invalid publish flags")
        }
        let policy: SpacePolicy
        switch policyType {
        case "personalspace":
            guard readPolicy == .memberList, writePolicy == .memberList,
                  readManagingApp == nil, writeManagingApp == nil,
                  appAccess == .open, publishPolicy == 0, publishMembers == 0 else {
                throw SwanError.malformed("invalid personalspace row")
            }
            policy = .personal
        case "memberspace":
            guard readPolicy != .managingApp, writePolicy != .managingApp,
                  readManagingApp == nil, writeManagingApp == nil else {
                throw SwanError.malformed("invalid memberspace row")
            }
            let allowedApps: [String]? = switch appAccess {
            case .open: nil
            case let .allowList(clients): clients.sorted()
            }
            policy = .member(try MemberSpacePolicy(
                publicRead: readPolicy == .public,
                publicWrite: writePolicy == .public,
                allowedApps: allowedApps,
                publishPolicy: publishPolicy == 1,
                publishMembers: publishMembers == 1
            ))
        case "managedspace":
            guard readPolicy == .managingApp, writePolicy == .managingApp,
                  let readManagingApp, readManagingApp == writeManagingApp,
                  appAccess == .open, publishMembers == 0 else {
                throw SwanError.malformed("invalid managedspace row")
            }
            policy = .managed(try ManagedSpacePolicy(
                managingApp: readManagingApp,
                publishPolicy: publishPolicy == 1
            ))
        default:
            throw SwanError.malformed("unknown policy type")
        }
        return SimpleSpaceConfiguration(policy: policy)
    }
}

/// A read-only listing of lossy v29 policy conversions and managed spaces
/// whose stored managing app lacks the required service fragment. Before the
/// upgrade it predicts rows from the October 22 columns; after it, it combines
/// the migration log with current invalid managed rows. It never writes or
/// migrates, and opens the database with `mode=ro`.
public enum SpacePolicyMigrationReport {
    static let personalType = "personalspace"
    static let memberType = "memberspace"
    static let managedType = "managedspace"

    public struct Entry: Sendable, Equatable {
        public let spaceURI: String
        public let owner: String
        public let oldReadPolicy: String
        public let oldReadManagingApp: String?
        public let oldWritePolicy: String
        public let oldWriteManagingApp: String?
        public let oldAppAccess: String
        public let oldAllowedClients: [String]
        public let droppedMemberCount: Int
        public let newPolicyType: String
        public let newManagingApp: String?
        public let reasons: [String]
        /// `false` for a prediction made before v29 ran, `true` for a row
        /// the migration recorded.
        public let recorded: Bool
    }

    /// Lists the lossy conversions for one account database file.
    public static func scan(databasePath: String) async throws -> [Entry] {
        let connection = try await SQLiteConnection.open(
            storage: .file(path: try SQLiteLayout.readOnlyURI(for: databasePath))
        )
        do {
            let entries = try await scan(connection: connection)
            try await connection.close()
            return entries
        } catch {
            try? await connection.close()
            throw error
        }
    }

    static func scan(connection: SQLiteConnection) async throws -> [Entry] {
        let tables = try await connection.query(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name IN (
                'permissioned_repository_migrations',
                'permissioned_simple_space_authorities',
                'permissioned_space_policy_migration_v29'
            )
            """
        )
        let names = Set(tables.compactMap { $0.column("name")?.string })
        guard names.contains("permissioned_simple_space_authorities") else { return [] }
        var applied = false
        if names.contains("permissioned_repository_migrations") {
            applied = try await !connection.query(
                "SELECT 1 FROM permissioned_repository_migrations WHERE version = ?",
                [.integer(SQLiteAccountDatabase.spacePolicyMigrationVersion)]
            ).isEmpty
        }
        if applied {
            guard names.contains("permissioned_space_policy_migration_v29") else { return [] }
            let rows = try await connection.query(
                """
                SELECT l.*, a.owner_did
                FROM permissioned_space_policy_migration_v29 l
                LEFT JOIN permissioned_simple_space_authorities a ON a.space_uri = l.space_uri
                ORDER BY l.space_uri
                """
            )
            var entries = rows.map { row in
                let clients = row.column("old_allowed_clients")?.string ?? ""
                return Entry(
                    spaceURI: row.column("space_uri")?.string ?? "",
                    owner: row.column("owner_did")?.string ?? "",
                    oldReadPolicy: row.column("old_read_policy")?.string ?? "",
                    oldReadManagingApp: row.column("old_read_managing_app")?.string,
                    oldWritePolicy: row.column("old_write_policy")?.string ?? "",
                    oldWriteManagingApp: row.column("old_write_managing_app")?.string,
                    oldAppAccess: row.column("old_app_access")?.string ?? "",
                    oldAllowedClients: clients.isEmpty ? [] : clients.components(separatedBy: "\n"),
                    droppedMemberCount: row.column("dropped_member_count")?.integer ?? 0,
                    newPolicyType: row.column("new_policy_type")?.string ?? "",
                    newManagingApp: row.column("new_managing_app")?.string,
                    reasons: (row.column("reasons")?.string ?? "").components(separatedBy: ","),
                    recorded: true
                )
            }
            let recordedSpaces = Set(entries.map(\.spaceURI))
            entries.append(contentsOf: try await conversions(connection: connection).filter {
                $0.reasons.contains("managing-app-missing-service")
                    && !recordedSpaces.contains($0.spaceURI)
            })
            return entries.sorted { $0.spaceURI < $1.spaceURI }
        }
        return try await conversions(connection: connection).filter { !$0.reasons.isEmpty }
    }

    /// Every authority row and what v29 makes of it. `reasons` is empty for
    /// a conversion that keeps exactly who can reach the space.
    static func conversions(connection: SQLiteConnection) async throws -> [Entry] {
        let rows = try await connection.query(
            """
            SELECT space_uri, owner_did, read_policy, read_managing_app,
                   write_policy, write_managing_app, app_access
            FROM permissioned_simple_space_authorities
            ORDER BY space_uri
            LIMIT ?
            """,
            [.integer(SimpleSpaceLimits.maximumSpacesPerAuthority * 2)]
        )
        var entries: [Entry] = []
        entries.reserveCapacity(rows.count)
        for row in rows {
            guard let space = row.column("space_uri")?.string,
                  let owner = row.column("owner_did")?.string,
                  let readPolicy = row.column("read_policy")?.string,
                  let writePolicy = row.column("write_policy")?.string,
                  let appAccess = row.column("app_access")?.string else {
                throw SQLiteRepositoryError.corruptDatabase("invalid simple-space authority row")
            }
            let readApp = nonEmpty(row.column("read_managing_app")?.string)
            let writeApp = nonEmpty(row.column("write_managing_app")?.string)
            let clients = try await connection.query(
                "SELECT client_id FROM permissioned_simple_space_clients WHERE space_uri = ? ORDER BY client_id",
                [.text(space)]
            ).compactMap { $0.column("client_id")?.string }
            let memberCount = try await connection.query(
                """
                SELECT COUNT(*) AS count FROM permissioned_simple_space_members
                WHERE space_uri = ? AND member_did != ?
                """,
                [.text(space), .text(owner)]
            ).first?.column("count")?.integer ?? 0

            var reasons: [String] = []
            let newType: String
            let newApp: String?
            if let managingApp = readApp ?? writeApp {
                if SpacePolicyValidation.isValidManagingApp(managingApp) {
                    newType = managedType
                    newApp = managingApp
                    if !SpacePolicyValidation.isValidManagingAppService(managingApp) {
                        reasons.append("managing-app-missing-service")
                    }
                } else {
                    newType = personalType
                    newApp = nil
                    reasons.append("managing-app-not-a-did")
                }
                if readPolicy != "managing-app" || writePolicy != "managing-app" {
                    reasons.append("one-sided-managing-app")
                }
                if let readApp, let writeApp, readApp != writeApp {
                    reasons.append("different-managing-apps")
                }
                if appAccess == "allow-list" {
                    reasons.append("allow-list-dropped")
                }
                if memberCount > 0 {
                    reasons.append("members-dropped")
                }
            } else {
                newType = memberType
                newApp = nil
            }
            entries.append(Entry(
                spaceURI: space,
                owner: owner,
                oldReadPolicy: readPolicy,
                oldReadManagingApp: readApp,
                oldWritePolicy: writePolicy,
                oldWriteManagingApp: writeApp,
                oldAppAccess: appAccess,
                oldAllowedClients: clients,
                droppedMemberCount: newType == memberType ? 0 : memberCount,
                newPolicyType: newType,
                newManagingApp: newApp,
                reasons: reasons,
                recorded: false
            ))
        }
        return entries
    }

    private static func nonEmpty(_ value: String?) -> String? {
        guard let value, !value.isEmpty else { return nil }
        return value
    }
}
