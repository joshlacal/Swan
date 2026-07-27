import Foundation
import SQLiteNIO
import SwanCore
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class PreMigratedAccountDirectoryTests: XCTestCase {
    private let alice = "did:plc:abcdefghijklmnopqrstuvwx"
    private let bob = "did:plc:bcdefghijklmnopqrstuvwxy"
    private let carol = "did:plc:cdefghijklmnopqrstuvwxyz"

    func testActiveAccountInventoryIsStatusOnlyCanonicalAndOrdered() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await control.createAccount(registration(did: bob, handle: "bob.example.com"))
        _ = try await control.createAccount(registration(did: alice, handle: "alice.example.com"))
        _ = try await control.createAccount(registration(did: carol, handle: "carol.example.com"))

        _ = try await control.transitionStatus(
            did: bob,
            to: .deactivated,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_001)
        )
        let activeDIDs = try await control.activeAccountDIDs()
        XCTAssertEqual(activeDIDs, [alice, carol])
        try await control.close()
    }

    func testBootstrapPreopensActiveAccountAndProjectsOnlySafeDescription() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let space = try makeSpace(authority: alice)
        try await installAccountDatabase(root: root, did: alice, space: space)
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await control.createAccount(registration(did: alice, handle: "alice.example.com"))

        let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: root,
            controlStore: control
        )
        let loaded = try await directory.space(
            space,
            authorization: .accountOAuth(subject: alice, scopes: ["atproto"])
        )
        let description = try XCTUnwrap(loaded)
        XCTAssertEqual(description.space, space)
        XCTAssertEqual(description.configuration.policy, .memberList)

        // The public result type cannot accidentally grow a durable authority
        // snapshot: none of owner, members, revision, deletion state, or app
        // decisions are structurally present.
        let labels = Set(Mirror(reflecting: description).children.compactMap(\.label))
        XCTAssertEqual(labels, ["space", "configuration"])
        XCTAssertFalse(labels.contains("owner"))
        XCTAssertFalse(labels.contains("members"))
        XCTAssertFalse(labels.contains("revision"))
        XCTAssertFalse(labels.contains("isDeleted"))

        try await directory.close()
        try await control.close()
    }

    func testMissingDatabaseAndSymlinkedDatabaseFailBootstrapWithoutCreation() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await control.createAccount(registration(did: alice, handle: "alice.example.com"))
        let accountURL = SQLiteLayout.accountDatabase(in: root, did: alice)

        await XCTAssertSwanUnavailableAsync(
            try await SQLitePreMigratedAccountDirectory.bootstrap(
                dataDirectory: root,
                controlStore: control
            )
        )
        assertNoAccountDatabase(root: root, did: alice)

        try FileManager.default.createDirectory(
            at: accountURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let target = root.appending(path: "outside-account.sqlite")
        try Data("not a database".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(
            atPath: accountURL.path,
            withDestinationPath: target.path
        )
        await XCTAssertSwanUnavailableAsync(
            try await SQLitePreMigratedAccountDirectory.bootstrap(
                dataDirectory: root,
                controlStore: control
            )
        )
        XCTAssertTrue(FileManager.default.fileExists(atPath: accountURL.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path + "-wal"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path + "-shm"))
        try await control.close()
    }

    func testUnknownForeignAndReactivatedAuthoritiesNeverOpenDatabasesAfterBootstrap() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let aliceSpace = try makeSpace(authority: alice)
        let bobSpace = try makeSpace(authority: bob)
        let unknown = "did:plc:defghijklmnopqrstuvwxyza"
        let unknownSpace = try makeSpace(authority: unknown)
        try await installAccountDatabase(root: root, did: alice, space: aliceSpace)

        let control = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await control.createAccount(registration(did: alice, handle: "alice.example.com"))
        _ = try await control.createAccount(registration(did: bob, handle: "bob.example.com"))
        _ = try await control.transitionStatus(
            did: bob,
            to: .deactivated,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_001)
        )
        let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: root,
            controlStore: control
        )

        let unknownResult = try await directory.space(
            unknownSpace,
            authorization: .accountOAuth(subject: unknown, scopes: ["atproto"])
        )
        XCTAssertNil(unknownResult)
        let inactiveForeignResult = try await directory.space(
            bobSpace,
            authorization: .accountOAuth(subject: bob, scopes: ["atproto"])
        )
        XCTAssertNil(inactiveForeignResult)
        assertNoAccountDatabase(root: root, did: bob)
        assertNoAccountDatabase(root: root, did: unknown)

        _ = try await control.transitionStatus(
            did: bob,
            to: .active,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_002)
        )
        await XCTAssertSwanUnavailableAsync(
            try await directory.space(
                bobSpace,
                authorization: .accountOAuth(subject: bob, scopes: ["atproto"])
            )
        )
        assertNoAccountDatabase(root: root, did: bob)

        try await directory.close()
        try await control.close()
    }

    func testLifecycleAndCloseRechecksHidePreopenedAuthorityState() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let space = try makeSpace(authority: alice)
        try await installAccountDatabase(root: root, did: alice, space: space)
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await control.createAccount(registration(did: alice, handle: "alice.example.com"))
        let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: root,
            controlStore: control
        )
        let authorization: AuthorizationContext = .accountOAuth(
            subject: alice,
            scopes: ["atproto"]
        )
        let initiallyVisible = try await directory.space(space, authorization: authorization)
        XCTAssertNotNil(initiallyVisible)

        _ = try await control.transitionStatus(
            did: alice,
            to: .deactivated,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_001)
        )
        let deactivatedResult = try await directory.space(space, authorization: authorization)
        XCTAssertNil(deactivatedResult)

        _ = try await control.transitionStatus(
            did: alice,
            to: .active,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_002)
        )
        let reactivatedResult = try await directory.space(space, authorization: authorization)
        XCTAssertNotNil(reactivatedResult)

        _ = try await control.transitionStatus(
            did: alice,
            to: .deleted,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_003)
        )
        let deletedResult = try await directory.space(space, authorization: authorization)
        XCTAssertNil(deletedResult)

        try await directory.close()
        await XCTAssertSwanUnavailableAsync(
            try await directory.space(space, authorization: authorization)
        )
        try await control.close()
    }

    func testVanishedPreopenedDatabaseFailsUnavailableWithoutRecreation() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let space = try makeSpace(authority: alice)
        try await installAccountDatabase(root: root, did: alice, space: space)
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await control.createAccount(registration(did: alice, handle: "alice.example.com"))
        let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: root,
            controlStore: control
        )
        let databaseURL = SQLiteLayout.accountDatabase(in: root, did: alice)
        try FileManager.default.removeItem(at: databaseURL)

        await XCTAssertSwanUnavailableAsync(
            try await directory.space(
                space,
                authorization: .accountOAuth(subject: alice, scopes: ["atproto"])
            )
        )
        // The existing preopened connection may retain its original WAL/SHM
        // sidecars until shutdown, but the primary path must stay absent: the
        // request was denied instead of recreating the account database.
        XCTAssertFalse(FileManager.default.fileExists(atPath: databaseURL.path))
        try await directory.close()
        try await control.close()
    }

    func testWrongCallerScopeAndCorruptConfigurationFailClosed() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let space = try makeSpace(authority: alice)
        try await installAccountDatabase(root: root, did: alice, space: space)
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await control.createAccount(registration(did: alice, handle: "alice.example.com"))
        let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: root,
            controlStore: control
        )

        await XCTAssertSwanUnauthorizedAsync(
            try await directory.space(
                space,
                authorization: .accountOAuth(subject: bob, scopes: ["atproto"])
            )
        )
        await XCTAssertSwanUnauthorizedAsync(
            try await directory.space(
                space,
                authorization: .accountOAuth(
                    subject: alice,
                    scopes: ["space:app.bsky.bookmarks?authority=\(alice)&skey=directory&action=read"]
                )
            )
        )
        try await directory.close()

        let raw = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(in: root, did: alice).path)
        )
        _ = try await raw.query(
            "INSERT INTO permissioned_simple_space_clients(space_uri, client_id) VALUES (?, ?)",
            [.text(space.rawValue), .text("app.example.client")]
        )
        try await raw.close()

        let reopened = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: root,
            controlStore: control
        )
        await XCTAssertSwanUnavailableAsync(
            try await reopened.space(
                space,
                authorization: .accountOAuth(subject: alice, scopes: ["atproto"])
            )
        )
        try await reopened.close()
        try await control.close()
    }
}

private extension PreMigratedAccountDirectoryTests {
    func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPreMigratedAccountDirectoryTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        return root
    }

    func makeSpace(authority: String) throws -> SpaceURI {
        try SpaceURI(
            authority: authority,
            spaceType: "app.bsky.bookmarks",
            skey: "directory"
        )
    }

    func registration(did: String, handle: String) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
            rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
    }

    func installAccountDatabase(root: URL, did: String, space: SpaceURI) async throws {
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let authority = try DurableSimpleSpaceAuthority(
            database: database,
            credentialSecret: Data(repeating: 0xA5, count: 32)
        )
        _ = try await authority.create(
            space: space,
            owner: did,
            configuration: try SimpleSpaceConfiguration(policy: .memberList, appAccess: .open),
            authorization: .accountOAuth(subject: did, scopes: ["atproto"]),
            now: Date(timeIntervalSince1970: 1_750_000_000)
        )
        try await database.close()
    }

    func assertNoAccountDatabase(root: URL, did: String, file: StaticString = #filePath, line: UInt = #line) {
        let path = SQLiteLayout.accountDatabase(in: root, did: did).path
        XCTAssertFalse(FileManager.default.fileExists(atPath: path), file: file, line: line)
        XCTAssertFalse(FileManager.default.fileExists(atPath: path + "-wal"), file: file, line: line)
        XCTAssertFalse(FileManager.default.fileExists(atPath: path + "-shm"), file: file, line: line)
    }
}

private func XCTAssertSwanUnavailableAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected unavailable", file: file, line: line)
    } catch let error as SwanError {
        guard case .unavailable = error else {
            return XCTFail("expected unavailable, got \(error)", file: file, line: line)
        }
    } catch {
        XCTFail("expected SwanError.unavailable, got \(error)", file: file, line: line)
    }
}

private func XCTAssertSwanUnauthorizedAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected unauthorized", file: file, line: line)
    } catch let error as SwanError {
        guard case .unauthorized = error else {
            return XCTFail("expected unauthorized, got \(error)", file: file, line: line)
        }
    } catch {
        XCTFail("expected SwanError.unauthorized, got \(error)", file: file, line: line)
    }
}
