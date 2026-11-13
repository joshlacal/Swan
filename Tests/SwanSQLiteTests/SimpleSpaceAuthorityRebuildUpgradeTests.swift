import Foundation
import SQLiteNIO
import SwanCore
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

/// Upgrades through migration v23 (the simple-space authority rebuild) from
/// the exact schema an August 2026 binary wrote. Since SQLite 3.26 renaming
/// the authority table rewrites the foreign key of every other table naming
/// it, so before the fix a v18 store whose writer registry or notification
/// registrations held a row failed v23's `foreign_key_check`, leaving
/// migrations 19, 20, 25 and 26 committed and the account unopenable.
final class SimpleSpaceAuthorityRebuildUpgradeTests: XCTestCase {
    private static let alice = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let bob = "did:plc:bcdefghijklmnopqrstuvwxy"
    private static let client = "https://client.example/oauth/client-metadata.json"
    private static let manager = "did:web:manager.example"

    private var root: URL!
    private var memberSpace: SpaceURI!
    private var managedSpace: SpaceURI!
    private let owner = AuthorizationContext.accountOAuthForTesting(
        subject: SimpleSpaceAuthorityRebuildUpgradeTests.alice,
        scopes: ["atproto"]
    )

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SimpleSpaceAuthorityRebuildUpgradeTests-\(UUID().uuidString)")
        memberSpace = try SpaceURI(authority: Self.alice, spaceType: "app.bsky.bookmarks", skey: "members")
        managedSpace = try SpaceURI(authority: Self.alice, spaceType: "app.bsky.bookmarks", skey: "managed")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    private func open() async throws -> SQLiteAccountDatabase {
        try await SQLiteAccountDatabase(dataDirectory: root, did: Self.alice)
    }

    private func withDatabase(_ body: (SQLiteAccountDatabase) async throws -> Void) async throws {
        let database = try await open()
        do {
            try await body(database)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    /// Replaces the freshly created store's schema with the v18 layout, so
    /// the directory and file keep the permissions Swan created them with.
    private func resetToV18(_ connection: SQLiteConnection) async throws {
        _ = try await connection.query("PRAGMA foreign_keys = OFF")
        let tables = try await connection.query(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
        for name in tables.compactMap({ $0.column("name")?.string }) {
            _ = try await connection.query("DROP TABLE \"\(name)\"")
        }
        for statement in AccountSchemaV18Fixture.statements {
            _ = try await connection.query(statement)
        }
        for version in AccountSchemaV18Fixture.appliedMigrationVersions {
            _ = try await connection.query(
                "INSERT INTO permissioned_repository_migrations(version, applied_at) VALUES (?, 1)",
                [.integer(version)]
            )
        }
    }

    /// The two spaces, their member and client rows, and (optionally) one
    /// writer and one notification registration, in v18 column shapes.
    private func seedV18Spaces(_ connection: SQLiteConnection, withChildren: Bool) async throws {
        _ = try await connection.query(
            """
            INSERT INTO permissioned_simple_space_authorities(
                space_uri, owner_did, policy, app_access, managing_app,
                is_deleted, revision, created_at, updated_at
            ) VALUES
                (?, ?, 'member-list', 'allow-list', NULL, 0, 1, 1, 1),
                (?, ?, 'member-list', 'open', ?, 0, 1, 1, 1)
            """,
            [
                .text(memberSpace.rawValue), .text(Self.alice),
                .text(managedSpace.rawValue), .text(Self.alice), .text(Self.manager),
            ]
        )
        _ = try await connection.query(
            """
            INSERT INTO permissioned_simple_space_members(space_uri, member_did)
            VALUES (?, ?), (?, ?), (?, ?)
            """,
            [
                .text(memberSpace.rawValue), .text(Self.alice),
                .text(memberSpace.rawValue), .text(Self.bob),
                .text(managedSpace.rawValue), .text(Self.alice),
            ]
        )
        _ = try await connection.query(
            "INSERT INTO permissioned_simple_space_clients(space_uri, client_id) VALUES (?, ?)",
            [.text(memberSpace.rawValue), .text(Self.client)]
        )
        guard withChildren else { return }
        _ = try await connection.query(
            """
            INSERT INTO permissioned_space_writers(space_uri, repo_did, wire_revision, commitment, updated_at)
            VALUES (?, ?, '222222222222z', ?, 1)
            """,
            [
                .text(memberSpace.rawValue), .text(Self.bob),
                .blob(ByteBuffer(bytes: [UInt8](repeating: 7, count: 32))),
            ]
        )
        _ = try await connection.query(
            """
            INSERT INTO permissioned_space_notification_registrations(
                space_uri, endpoint, repo_did, expires_at, updated_at, service_did
            ) VALUES (?, 'https://appview.example/notify', NULL, 4102444800, 1, 'did:web:appview.example')
            """,
            [.text(memberSpace.rawValue)]
        )
    }

    private func appliedVersions(_ connection: SQLiteConnection) async throws -> Set<Int> {
        let rows = try await connection.query("SELECT version FROM permissioned_repository_migrations")
        return Set(rows.compactMap { $0.column("version")?.integer })
    }

    /// Every `(child, parent)` pair whose parent table does not exist.
    private func danglingForeignKeys(_ connection: SQLiteConnection) async throws -> [String] {
        let tables = try await connection.query(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
        let names = Set(tables.compactMap { $0.column("name")?.string })
        var dangling: [String] = []
        for name in names.sorted() {
            let references = try await connection.query("PRAGMA foreign_key_list(\"\(name)\")")
            for parent in references.compactMap({ $0.column("table")?.string }) where !names.contains(parent) {
                dangling.append("\(name) -> \(parent)")
            }
        }
        return dangling
    }

    /// `required` defaults to every migration retained by the November 12
    /// upgrade path. Versions 22 and 27 belonged only to retired notification
    /// tables, so v30 supersedes them.
    private func assertFullyMigrated(
        _ database: SQLiteAccountDatabase,
        required: Set<Int> = Set(1...30).subtracting([22, 27])
    ) async throws {
        let connection = await database.connection
        let versions = try await appliedVersions(connection)
        XCTAssertTrue(required.isSubset(of: versions), "missing \(required.subtracting(versions).sorted())")
        let violations = try await connection.query("PRAGMA foreign_key_check")
        XCTAssertTrue(violations.isEmpty)
        let dangling = try await danglingForeignKeys(connection)
        XCTAssertEqual(dangling, [])
        let legacyAlter = try await connection.query("PRAGMA legacy_alter_table")
        XCTAssertEqual(legacyAlter.first?.column("legacy_alter_table")?.integer, 0)
    }

    func testV18StoreWithWriterAndRetiredNotificationRegistrationMigratesToV30() async throws {
        try await withDatabase { database in
            let connection = await database.connection
            try await resetToV18(connection)
            try await seedV18Spaces(connection, withChildren: true)
            let violations = try await connection.query("PRAGMA foreign_key_check")
            XCTAssertTrue(violations.isEmpty)
        }

        let databasePath = SQLiteLayout.accountDatabase(in: root, did: Self.alice).path
        try await withDatabase { database in
            try await assertFullyMigrated(database)
            let connection = await database.connection
            let writers = try await connection.query(
                "SELECT repo_did FROM permissioned_space_writers WHERE space_uri = ?",
                [.text(memberSpace.rawValue)]
            )
            XCTAssertEqual(writers.compactMap { $0.column("repo_did")?.string }, [Self.bob])
            // v30 retires the pre-authorizeSpaceSync registration table.
            let retiredRegistrationTable = try await connection.query(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'permissioned_space_notification_registrations'
                """
            )
            XCTAssertTrue(retiredRegistrationTable.isEmpty)
            let registrations = try await connection.query(
                "SELECT COUNT(*) AS count FROM permissioned_space_sync_registrations"
            )
            XCTAssertEqual(registrations.first?.column("count")?.integer, 0)

            let member = try await database.simpleSpace(memberSpace, authorization: owner)
            XCTAssertEqual(
                member?.space.configuration.policy,
                .member(try MemberSpacePolicy(allowedApps: [Self.client]))
            )
            XCTAssertEqual(member.map { Set($0.space.members.keys) }, [Self.alice, Self.bob])
            let managed = try await database.simpleSpace(managedSpace, authorization: owner)
            XCTAssertEqual(
                managed?.space.configuration.policy,
                .managed(try ManagedSpacePolicy(managingApp: Self.manager))
            )
        }

        let report = try await SpacePolicyMigrationReport.scan(databasePath: databasePath)
        XCTAssertEqual(report.map(\.spaceURI), [managedSpace.rawValue])
        let entry = try XCTUnwrap(report.first)
        XCTAssertTrue(entry.recorded)
        XCTAssertEqual(entry.newPolicyType, "managedspace")
        XCTAssertEqual(entry.newManagingApp, Self.manager)
        XCTAssertEqual(entry.reasons, ["managing-app-missing-service", "one-sided-managing-app"])
    }

    /// A store an older binary already took through v23 while its writer
    /// registry and notification registrations were empty: that rebuild
    /// passed `foreign_key_check` but left both tables referencing the
    /// dropped `_schema_v2` parent. The later registration and writer
    /// rebuilds must clear that text on open, so no separate repair exists.
    func testStoreLeftWithDanglingAuthorityReferencesIsRepairedOnOpen() async throws {
        try await withDatabase { database in
            let connection = await database.connection
            try await resetToV18(connection)
            try await seedV18Spaces(connection, withChildren: false)
            // The v23 rebuild exactly as a1e6e780 and earlier ran it.
            for table in [
                "permissioned_simple_space_authorities",
                "permissioned_simple_space_members",
                "permissioned_simple_space_clients",
                "permissioned_simple_space_managing_app_decisions",
            ] {
                _ = try await connection.query("ALTER TABLE \(table) RENAME TO \(table)_schema_v2")
            }
            for statement in SQLiteLayout.simpleSpaceAuthoritySchemaStatements {
                _ = try await connection.query(statement)
            }
            _ = try await connection.query(
                """
                INSERT INTO permissioned_simple_space_authorities(
                    space_uri, owner_did, read_policy, read_managing_app,
                    write_policy, write_managing_app, app_access,
                    is_deleted, revision, created_at, updated_at
                )
                SELECT space_uri, owner_did, policy, managing_app,
                       policy, managing_app, app_access,
                       is_deleted, revision, created_at, updated_at
                FROM permissioned_simple_space_authorities_schema_v2
                """
            )
            _ = try await connection.query(
                """
                INSERT INTO permissioned_simple_space_members(space_uri, member_did, can_read, can_write)
                SELECT space_uri, member_did, 1, 1 FROM permissioned_simple_space_members_schema_v2
                """
            )
            _ = try await connection.query(
                """
                INSERT INTO permissioned_simple_space_clients(space_uri, client_id)
                SELECT space_uri, client_id FROM permissioned_simple_space_clients_schema_v2
                """
            )
            for table in [
                "permissioned_simple_space_managing_app_decisions",
                "permissioned_simple_space_clients",
                "permissioned_simple_space_members",
                "permissioned_simple_space_authorities",
            ] {
                _ = try await connection.query("DROP TABLE \(table)_schema_v2")
            }
            _ = try await connection.query(
                "INSERT INTO permissioned_repository_migrations(version, applied_at) VALUES (23, 1)"
            )
            let violations = try await connection.query("PRAGMA foreign_key_check")
            XCTAssertTrue(violations.isEmpty)
            let dangling = try await danglingForeignKeys(connection)
            XCTAssertEqual(dangling, [
                "permissioned_space_notification_registrations -> permissioned_simple_space_authorities_schema_v2",
                "permissioned_space_writers -> permissioned_simple_space_authorities_schema_v2",
            ])
        }

        try await withDatabase { database in
            try await assertFullyMigrated(database)
            let connection = await database.connection
            _ = try await connection.query(
                """
                INSERT INTO permissioned_space_writers(space_uri, repo_did, wire_revision, commitment, updated_at)
                VALUES (?, ?, '222222222222z', ?, 1)
                """,
                [
                    .text(memberSpace.rawValue), .text(Self.bob),
                    .blob(ByteBuffer(bytes: [UInt8](repeating: 7, count: 32))),
                ]
            )
            let member = try await database.simpleSpace(memberSpace, authorization: owner)
            XCTAssertEqual(member.map { Set($0.space.members.keys) }, [Self.alice, Self.bob])
        }
    }

}
