import Foundation
import Petrel
import SQLiteNIO
import SwanCore
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

/// October 29 space-policy behaviour of the SQLite authority: published
/// policy and member records, writer-set removal, PolicyMismatch, the
/// user-before-app ordering, managedspace deferral, and migration v29.
final class SpacePolicyOctober29Tests: XCTestCase {
    private static let alice = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let bob = "did:plc:bcdefghijklmnopqrstuvwxy"
    private static let carol = "did:plc:cdefghijklmnopqrstuvwxyz"

    private var root: URL!
    private var space: SpaceURI!
    private let owner = AuthorizationContext.accountOAuthForTesting(
        subject: SpacePolicyOctober29Tests.alice,
        scopes: ["atproto"]
    )

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SpacePolicyOctober29Tests-\(UUID().uuidString)")
        space = try SpaceURI(authority: Self.alice, spaceType: "app.bsky.bookmarks", skey: "policy")
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

    private func published(_ database: SQLiteAccountDatabase) async throws -> [String: String] {
        let rows = try await database.connection.query(
            """
            SELECT collection, rkey, cid FROM permissioned_space_records
            WHERE space_uri = ? AND author_did = ?
            """,
            [.text(space.rawValue), .text(Self.alice)]
        )
        var result: [String: String] = [:]
        for row in rows {
            let key = "\(row.column("collection")?.string ?? "")/\(row.column("rkey")?.string ?? "")"
            result[key] = row.column("cid")?.string
        }
        return result
    }

    private func authorRevision(_ database: SQLiteAccountDatabase) async throws -> Int {
        let rows = try await database.connection.query(
            "SELECT revision FROM permissioned_repository_state WHERE space_uri = ? AND author_did = ?",
            [.text(space.rawValue), .text(Self.alice)]
        )
        return rows.first?.column("revision")?.integer ?? 0
    }

    private func writers(_ database: SQLiteAccountDatabase) async throws -> Set<String> {
        let rows = try await database.connection.query(
            "SELECT repo_did FROM permissioned_space_writers WHERE space_uri = ?",
            [.text(space.rawValue)]
        )
        return Set(rows.compactMap { $0.column("repo_did")?.string })
    }

    private func seedWriters(_ database: SQLiteAccountDatabase, _ dids: [String]) async throws {
        for did in dids {
            _ = try await database.connection.query(
                """
                INSERT OR REPLACE INTO permissioned_space_writers(space_uri, repo_did, wire_revision, commitment, updated_at)
                VALUES (?, ?, '222222222222z', ?, 1)
                """,
                [.text(space.rawValue), .text(did), .blob(ByteBuffer(bytes: [UInt8](repeating: 7, count: 32)))]
            )
        }
    }

    func testPublishedRecordsFollowThePolicyAndMemberList() async throws {
        try await withDatabase { database in
            let policy = SpacePolicy.member(try MemberSpacePolicy(publishPolicy: true, publishMembers: true))
            _ = try await database.createSimpleSpace(
                space: space, owner: Self.alice,
                configuration: SimpleSpaceConfiguration(policy: policy), authorization: owner
            )
            let policyPath = "com.atproto.space.policy/self"
            let bobPath = "com.atproto.memberspace.member/\(Self.bob)"
            var records = try await published(database)
            // The authority's own owner row is never published.
            XCTAssertEqual(Set(records.keys), [policyPath])
            XCTAssertEqual(records[policyPath], CID.fromDAGCBOR(try policy.policyRecordValue()).string)

            _ = try await database.putSimpleSpaceMember(
                space: space, member: Self.bob, read: true, write: false, authorization: owner
            )
            records = try await published(database)
            XCTAssertEqual(Set(records.keys), [policyPath, bobPath])
            XCTAssertEqual(
                records[bobPath],
                CID.fromDAGCBOR(try SpacePolicy.memberRecordValue(read: true, write: false)).string
            )

            // An identical update writes nothing.
            let before = try await authorRevision(database)
            _ = try await database.updateSimpleSpace(
                space: space, configuration: SimpleSpaceConfiguration(policy: policy), authorization: owner
            )
            let unchanged = try await authorRevision(database)
            XCTAssertEqual(unchanged, before)

            // Turning member publication off withdraws the member records and
            // rewrites the policy record.
            let quieter = SpacePolicy.member(try MemberSpacePolicy(publicRead: true, publishPolicy: true))
            _ = try await database.updateSimpleSpace(
                space: space, configuration: SimpleSpaceConfiguration(policy: quieter), authorization: owner
            )
            records = try await published(database)
            XCTAssertEqual(Set(records.keys), [policyPath])
            XCTAssertEqual(records[policyPath], CID.fromDAGCBOR(try quieter.policyRecordValue()).string)
            let advanced = try await authorRevision(database)
            XCTAssertGreaterThan(advanced, unchanged)

            // A personalspace publishes nothing.
            _ = try await database.updateSimpleSpace(
                space: space, configuration: SimpleSpaceConfiguration(policy: .personal), authorization: owner
            )
            records = try await published(database)
            XCTAssertTrue(records.isEmpty)
        }
    }

    func testMemberChangesAndRemoveWriterDropWriters() async throws {
        try await withDatabase { database in
            _ = try await database.createSimpleSpace(
                space: space, owner: Self.alice,
                configuration: SimpleSpaceConfiguration(policy: .member(try MemberSpacePolicy())),
                authorization: owner
            )
            for member in [Self.bob, Self.carol] {
                _ = try await database.putSimpleSpaceMember(
                    space: space, member: member, read: true, write: true, authorization: owner
                )
            }
            try await seedWriters(database, [Self.bob, Self.carol])

            _ = try await database.putSimpleSpaceMember(
                space: space, member: Self.bob, read: true, write: false, authorization: owner
            )
            var current = try await writers(database)
            XCTAssertEqual(current, [Self.carol])

            _ = try await database.removeSimpleSpaceMember(
                space: space, member: Self.carol, authorization: owner
            )
            current = try await writers(database)
            XCTAssertTrue(current.isEmpty)

            try await seedWriters(database, [Self.bob])
            try await database.removeSpaceWriter(space: space, writer: Self.bob, authorization: owner)
            try await database.removeSpaceWriter(space: space, writer: Self.bob, authorization: owner)
            current = try await writers(database)
            XCTAssertTrue(current.isEmpty)

            do {
                try await database.removeSpaceWriter(
                    space: space,
                    writer: Self.bob,
                    authorization: .accountOAuthForTesting(subject: Self.bob, scopes: ["atproto"])
                )
                XCTFail("only the authority may remove a writer")
            } catch {}
        }
    }

    func testMemberMethodsRefuseOtherPoliciesAndTypeChangeDropsMembers() async throws {
        try await withDatabase { database in
            _ = try await database.createSimpleSpace(
                space: space, owner: Self.alice,
                configuration: SimpleSpaceConfiguration(policy: .member(try MemberSpacePolicy())),
                authorization: owner
            )
            _ = try await database.putSimpleSpaceMember(
                space: space, member: Self.bob, read: true, write: true, authorization: owner
            )
            let managed = SpacePolicy.managed(try ManagedSpacePolicy(managingApp: "did:web:manager.example#space"))
            _ = try await database.updateSimpleSpace(
                space: space, configuration: SimpleSpaceConfiguration(policy: managed), authorization: owner
            )
            for operation in ["put", "remove", "list"] {
                do {
                    switch operation {
                    case "put":
                        _ = try await database.putSimpleSpaceMember(
                            space: space, member: Self.bob, read: true, write: true, authorization: owner
                        )
                    case "remove":
                        _ = try await database.removeSimpleSpaceMember(
                            space: space, member: Self.bob, authorization: owner
                        )
                    default:
                        _ = try await database.simpleSpaceMemberPage(
                            space: space, limit: 10, cursor: nil, authorization: owner
                        )
                    }
                    XCTFail("\(operation) must answer PolicyMismatch")
                } catch SpacePolicyError.policyMismatch {
                }
            }
            _ = try await database.updateSimpleSpace(
                space: space,
                configuration: SimpleSpaceConfiguration(policy: .member(try MemberSpacePolicy())),
                authorization: owner
            )
            let page = try await database.simpleSpaceMemberPage(
                space: space, limit: 10, cursor: nil, authorization: owner
            )
            XCTAssertEqual(page.members.map(\.did), [Self.alice])
        }
    }

    func testUserIsCheckedBeforeAppAndManagedSpaceDefersToTheApp() async throws {
        try await withDatabase { database in
            let allowList = SpacePolicy.member(try MemberSpacePolicy(allowedApps: ["https://app.example/client.json"]))
            _ = try await database.createSimpleSpace(
                space: space, owner: Self.alice,
                configuration: SimpleSpaceConfiguration(policy: allowList), authorization: owner
            )
            _ = try await database.putSimpleSpaceMember(
                space: space, member: Self.bob, read: true, write: false, authorization: owner
            )
            let carolAuth = AuthorizationContext.accountOAuthForTesting(subject: Self.carol, scopes: ["atproto"])
            let bobAuth = AuthorizationContext.accountOAuthForTesting(subject: Self.bob, scopes: ["atproto"])
            // An outsider with the wrong app is SpaceNotFound, not an app error.
            do {
                _ = try await database.authorizeSimpleSpaceRead(
                    space: space, user: Self.carol, clientID: "https://other.example/client.json",
                    authorization: carolAuth
                )
                XCTFail("an outsider must be refused")
            } catch AuthorizedSimpleSpaceLifecycleError.notFound {
            }
            // A member with the wrong app is refused on the app.
            do {
                _ = try await database.authorizeSimpleSpaceRead(
                    space: space, user: Self.bob, clientID: "https://other.example/client.json",
                    authorization: bobAuth
                )
                XCTFail("a member with an unlisted app must be refused")
            } catch AuthorizedSimpleSpaceLifecycleError.notFound {
                XCTFail("a member must not be told SpaceNotFound for an unlisted app")
            } catch {
            }
            let allowed = try await database.authorizeSimpleSpaceRead(
                space: space, user: Self.bob, clientID: "https://app.example/client.json",
                authorization: bobAuth
            )
            XCTAssertEqual(allowed, .authorized)
            // allowedApps does not apply to writes; bob has no write flag.
            do {
                _ = try await database.authorizeSimpleSpaceWrite(space: space, user: Self.bob)
                XCTFail("a read-only member must not be authorized to write")
            } catch {}

            let app = "did:web:manager.example#space"
            _ = try await database.updateSimpleSpace(
                space: space,
                configuration: SimpleSpaceConfiguration(policy: .managed(try ManagedSpacePolicy(managingApp: app))),
                authorization: owner
            )
            let pending = try await database.authorizeSimpleSpaceRead(
                space: space, user: Self.carol, clientID: nil, authorization: carolAuth
            )
            XCTAssertEqual(pending, .requiresManagingApp(app))
            let approved = try await database.authorizeSimpleSpaceRead(
                space: space, user: Self.carol, clientID: nil, authorization: carolAuth,
                managedApproval: app
            )
            XCTAssertEqual(approved, .authorized)
            // An approval obtained for another app is not this app's answer.
            do {
                let stale = try await database.authorizeSimpleSpaceRead(
                    space: space, user: Self.carol, clientID: nil, authorization: carolAuth,
                    managedApproval: "did:web:other.example"
                )
                XCTAssertNotEqual(stale, .authorized)
            } catch AuthorizedSimpleSpaceLifecycleError.notFound {
            }
            let ownerRead = try await database.authorizeSimpleSpaceRead(
                space: space, user: Self.alice, clientID: nil, authorization: owner
            )
            XCTAssertEqual(ownerRead, .authorized)
            let writePending = try await database.authorizeSimpleSpaceWrite(space: space, user: Self.carol)
            XCTAssertEqual(writePending, .requiresManagingApp(app))
        }
    }

    func testMigrationV29ConvertsLegacyRowsAndRecordsLossyOnes() async throws {
        let oneSided = try SpaceURI(authority: Self.alice, spaceType: "app.bsky.bookmarks", skey: "one-sided")
        let notADID = try SpaceURI(authority: Self.alice, spaceType: "app.bsky.bookmarks", skey: "not-a-did")
        let allowList = try SpaceURI(authority: Self.alice, spaceType: "app.bsky.bookmarks", skey: "allow-list")
        try await withDatabase { database in
            for target in [oneSided, notADID, allowList] {
                _ = try await database.createSimpleSpace(
                    space: target, owner: Self.alice,
                    configuration: SimpleSpaceConfiguration(policy: .member(try MemberSpacePolicy())),
                    authorization: owner
                )
                _ = try await database.putSimpleSpaceMember(
                    space: target, member: Self.bob, read: true, write: true, authorization: owner
                )
            }
            // Rewrite the rows into October 22 shapes and forget v29.
            let connection = await database.connection
            _ = try await connection.query(
                """
                UPDATE permissioned_simple_space_authorities
                SET read_policy = 'managing-app', read_managing_app = 'did:web:manager.example',
                    write_policy = 'member-list', write_managing_app = NULL
                WHERE space_uri = ?
                """,
                [.text(oneSided.rawValue)]
            )
            _ = try await connection.query(
                """
                UPDATE permissioned_simple_space_authorities
                SET read_policy = 'managing-app', read_managing_app = 'https://manager.example',
                    write_policy = 'managing-app', write_managing_app = 'https://manager.example'
                WHERE space_uri = ?
                """,
                [.text(notADID.rawValue)]
            )
            _ = try await connection.query(
                """
                UPDATE permissioned_simple_space_authorities
                SET read_policy = 'public', app_access = 'allow-list'
                WHERE space_uri = ?
                """,
                [.text(allowList.rawValue)]
            )
            _ = try await connection.query(
                "DELETE FROM permissioned_repository_migrations WHERE version = 29"
            )
            _ = try await connection.query("DROP TABLE IF EXISTS permissioned_space_policy_migration_v29")
        }

        let databasePath = SQLiteLayout.accountDatabase(in: root, did: Self.alice).path
        let predicted = try await SpacePolicyMigrationReport.scan(databasePath: databasePath)
        XCTAssertTrue(predicted.allSatisfy { !$0.recorded })
        XCTAssertEqual(Set(predicted.map(\.spaceURI)), [oneSided.rawValue, notADID.rawValue])

        try await withDatabase { database in
            let one = try await database.simpleSpace(oneSided, authorization: owner)
            XCTAssertEqual(
                one?.space.configuration.policy,
                .managed(try ManagedSpacePolicy(managingApp: "did:web:manager.example"))
            )
            XCTAssertEqual(one.map { Set($0.space.members.keys) }, [Self.alice])
            let personal = try await database.simpleSpace(notADID, authorization: owner)
            XCTAssertEqual(personal?.space.configuration.policy, .personal)
            let member = try await database.simpleSpace(allowList, authorization: owner)
            XCTAssertEqual(
                member?.space.configuration.policy,
                .member(try MemberSpacePolicy(publicRead: true, allowedApps: []))
            )
        }

        let recorded = try await SpacePolicyMigrationReport.scan(databasePath: databasePath)
        XCTAssertTrue(recorded.allSatisfy(\.recorded))
        let byURI = Dictionary(uniqueKeysWithValues: recorded.map { ($0.spaceURI, $0) })
        let oneEntry = try XCTUnwrap(byURI[oneSided.rawValue])
        XCTAssertEqual(oneEntry.newPolicyType, "managedspace")
        XCTAssertEqual(oneEntry.newManagingApp, "did:web:manager.example")
        XCTAssertEqual(oneEntry.droppedMemberCount, 1)
        XCTAssertTrue(oneEntry.reasons.contains("one-sided-managing-app"))
        XCTAssertTrue(oneEntry.reasons.contains("members-dropped"))
        let notEntry = try XCTUnwrap(byURI[notADID.rawValue])
        XCTAssertEqual(notEntry.newPolicyType, "personalspace")
        XCTAssertTrue(notEntry.reasons.contains("managing-app-not-a-did"))
        XCTAssertEqual(predicted.count, recorded.count)
    }
}
