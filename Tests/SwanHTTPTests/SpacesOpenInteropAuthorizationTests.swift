import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import SwanAccounts
import XCTest
@testable import SwanCore
@testable import SwanHTTP
import SwanOAuth
import SwanSQLite
import SwanSpaces
import SwanStorage

/// `--enable-spaces-open-interop` decision B(d) at the authorization boundary:
/// legacy sessions reach space routes as upstream admits them (account
/// password: getDelegationToken and own-repo; app password: own-repo and
/// listing only), and nothing changes without the flag.
final class SpacesOpenInteropAuthorizationTests: XCTestCase {
    private static let did = "did:plc:legacyspaceuserabcdefghi"

    private struct Fixture {
        let root: URL
        let control: SQLiteControlDatabase
        let legacySessions: DurableLegacySessionService
        let runtime: SwanOAuthRuntime
        let accountToken: String
        let appPasswordToken: String

        func authorizer(interop: Bool) throws -> SwanOAuthResourceAuthorizer {
            try SwanOAuthResourceAuthorizer(
                publicURL: URL(string: "https://swan.test")!,
                runtime: runtime,
                accountControlStore: control,
                legacySessions: legacySessions,
                spacesOpenInterop: interop
            )
        }

        func close() async {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
        }
    }

    private func makeFixture() async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SpacesOpenInteropAuthorization-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            return try await populate(root: root, control: control)
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    private func populate(root: URL, control: SQLiteControlDatabase) async throws -> Fixture {
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: Self.did,
                canonicalHandle: "legacy-space.example.com",
                passwordVerifier:
                    "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: .init(purpose: .signing, generation: 1),
                rotationKey: .init(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )
        _ = try await control.createAppPassword(
            did: Self.did,
            name: "mobile",
            scopes: "transition:generic",
            digest: Data(repeating: 0x9E, count: 32),
            now: Date()
        )
        let records = try await control.listAppPasswords(did: Self.did)
        let record = try XCTUnwrap(records.first)
        let legacySessions = try DurableLegacySessionService(
            store: control,
            appPasswords: control,
            accountControlStore: control,
            credentials: try AppPasswordCredentials(),
            serviceDID: "did:web:swan.test",
            serverKey: Data(repeating: 0x48, count: 32)
        )
        let accountTokens = try await legacySessions.issue(did: Self.did, appPassword: nil)
        let appTokens = try await legacySessions.issue(did: Self.did, appPassword: record)
        return Fixture(
            root: root,
            control: control,
            legacySessions: legacySessions,
            runtime: try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0x49, count: 32)
            ),
            accountToken: accountTokens.accessJWT,
            appPasswordToken: appTokens.accessJWT
        )
    }

    private func withFixture(_ body: (Fixture) async throws -> Void) async throws {
        let fixture = try await makeFixture()
        do {
            try await body(fixture)
        } catch {
            await fixture.close()
            throw error
        }
        await fixture.close()
    }

    /// Runs `authorizeSpaceRoute` through a real Hummingbird request and
    /// reports the resulting context kind, or "denied".
    private func outcome(
        _ authorizer: SwanOAuthResourceAuthorizer,
        token: String,
        admission: SwanOAuthResourceAuthorizer.SpaceRouteLegacyAdmission
    ) async throws -> (kind: String, permissions: SwanScopePermissions?) {
        let router = Router()
        let box = OutcomeBox()
        router.get("/probe") { request, _ -> String in
            do {
                let context = try await authorizer.authorizeSpaceRoute(
                    request: request,
                    method: "GET",
                    fixedPath: "/probe",
                    legacyAdmission: admission
                )
                switch context {
                case let .accountOAuth(_, permissions):
                    await box.set("oauth", permissions)
                case .accountLegacySession:
                    await box.set("legacy", nil)
                default:
                    await box.set("other", nil)
                }
            } catch {
                await box.set("denied", nil)
            }
            return "ok"
        }
        try await Application(router: router).test(.router) { client in
            try await client.execute(
                uri: "/probe",
                method: .get,
                headers: [.authorization: "Bearer \(token)"]
            ) { _ in }
        }
        return await box.value()
    }

    func testWithoutTheFlagLegacySessionsStayLegacyContexts() async throws {
        try await withFixture { fixture in
            let authorizer = try fixture.authorizer(interop: false)
            let account = try await outcome(authorizer, token: fixture.accountToken, admission: .fullAccessOnly)
            XCTAssertEqual(account.kind, "legacy")
            let app = try await outcome(authorizer, token: fixture.appPasswordToken, admission: .standard)
            XCTAssertEqual(app.kind, "legacy")
        }
    }

    func testFlagAdmitsAccountPasswordToDelegationAndRefusesAppPasswordThere() async throws {
        try await withFixture { fixture in
            let authorizer = try fixture.authorizer(interop: true)
            let account = try await outcome(authorizer, token: fixture.accountToken, admission: .fullAccessOnly)
            XCTAssertEqual(account.kind, "oauth")
            let space = try SpaceURI(
                authority: "did:plc:someauthorityabcdefghijk",
                spaceType: "com.example.forum",
                skey: "general"
            )
            XCTAssertEqual(account.permissions?.allowsSpace(.delegationExchange(space)), true)

            let app = try await outcome(authorizer, token: fixture.appPasswordToken, admission: .fullAccessOnly)
            XCTAssertEqual(app.kind, "denied")
        }
    }

    /// Both legacy kinds reach own-repo reads/writes and listing; the domain
    /// policy still confines them to the subject's own repository.
    func testFlagAdmitsBothLegacyKindsToOwnRepositoryOnly() async throws {
        try await withFixture { fixture in
            let authorizer = try fixture.authorizer(interop: true)
            let app = try await outcome(authorizer, token: fixture.appPasswordToken, admission: .standard)
            XCTAssertEqual(app.kind, "oauth")
            let permissions = try XCTUnwrap(app.permissions)
            let space = try SpaceURI(
                authority: "did:plc:someauthorityabcdefghijk",
                spaceType: "com.example.forum",
                skey: "general"
            )
            let ownRecord = try SpaceRecordURI(
                space: space, author: Self.did, collection: "com.example.post", rkey: "a"
            )
            XCTAssertNoThrow(try SpaceAuthorizationPolicy.require(
                space: space,
                author: Self.did,
                uri: ownRecord,
                authorization: .accountOAuth(subject: Self.did, permissions: permissions),
                permission: .create
            ))
            let otherRecord = try SpaceRecordURI(
                space: space, author: "did:plc:someoneelseabcdefghijklm", collection: "com.example.post", rkey: "a"
            )
            XCTAssertThrowsError(try SpaceAuthorizationPolicy.require(
                space: space,
                author: "did:plc:someoneelseabcdefghijklm",
                uri: otherRecord,
                authorization: .accountOAuth(subject: Self.did, permissions: permissions),
                permission: .create
            ))
            XCTAssertTrue(permissions.allowsSpaceListing(type: nil, authority: nil))
        }
    }
}

private actor OutcomeBox {
    private var kind = "unset"
    private var permissions: SwanScopePermissions?

    func set(_ kind: String, _ permissions: SwanScopePermissions?) {
        self.kind = kind
        self.permissions = permissions
    }

    func value() -> (kind: String, permissions: SwanScopePermissions?) {
        (kind, permissions)
    }
}
