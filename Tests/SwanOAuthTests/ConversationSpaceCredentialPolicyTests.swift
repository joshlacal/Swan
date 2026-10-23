import Foundation
import Crypto
import SwanSQLite
@testable import SwanCore
import SwanSpaces
import SwanStorage
@testable import SwanOAuth
import XCTest

final class ConversationSpaceCredentialPolicyTests: XCTestCase, @unchecked Sendable {
    private let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    private let user = "did:plc:bcdefghijklmnopqrstuvwxy"

    func testConversationRequiresVerifiedDelegationAndRechecksMembershipEveryIssuance() async throws {
        let store = PolicyStore()
        let checker = Membership()
        let directory = ConversationSpaceCredentialDirectory(local: store, accounts: store,
            authority: authority, membership: checker, lifecycle: store)
        let space = try SpaceURI(authority: authority, spaceType: "blue.catbird.labyrinth.conversation", skey: UUID().uuidString.lowercased())
        do {
            try await directory.authorizeSimpleSpaceCredentialRead(space: space, user: nil, clientID: nil, authorization: .public)
            XCTFail("anonymous conversation credentials must fail")
        } catch {}
        do {
            try await directory.authorizeSimpleSpaceCredentialRead(space: space, user: user, clientID: nil,
                authorization: .spaceDelegation(subject: authority, space: space))
            XCTFail("delegation must bind the selected user")
        } catch {}
        try await directory.authorizeSimpleSpaceCredentialRead(space: space, user: user, clientID: nil,
            authorization: .spaceDelegation(subject: user, space: space))
        await checker.setDenied()
        do {
            try await directory.authorizeSimpleSpaceCredentialRead(space: space, user: user, clientID: nil,
                authorization: .spaceDelegation(subject: user, space: space))
            XCTFail("removed membership must not reuse a previous positive lookup")
        } catch {}
        let calls = await checker.calls
        let localCalls = await store.localCalls
        XCTAssertEqual(calls, 2)
        XCTAssertEqual(localCalls, 0)
    }

    func testDeletionDuringSigningKeyReadCannotMintAnotherCredential() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("SwanConversationSigningFence-" + UUID().uuidString)
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: authority)
        let space = try SpaceURI(authority: authority, spaceType: "blue.catbird.labyrinth.conversation", skey: UUID().uuidString.lowercased())
        let accounts = PolicyStore()
        let checker = Membership()
        let policy = ConversationSpaceCredentialDirectory(local: accounts, accounts: accounts,
            authority: authority, membership: checker, lifecycle: database)
        let issuer = DurableSpaceCredentialAuthority(policyDirectory: policy,
            signingKeys: ClosingSpaceSigningResolver(database: database, space: space))
        do {
            do {
                _ = try await issuer.issueSpaceCredential(space: space, user: user,
                    authorization: .spaceDelegation(subject: user, space: space),
                    confirmationKeyID: SpaceHTTPSignature.keyID(for: P256.Signing.PrivateKey()))
                XCTFail("key-read suspension allowed a credential after deletion began")
            } catch let error as AuthorizedSimpleSpaceLifecycleError {
                XCTAssertEqual(error, .deleted)
            }
            let pending = try await database.pendingConversationSpaceDeletions(authority: authority)
            XCTAssertEqual(pending.count, 1)
            let checks = await checker.calls
            XCTAssertEqual(checks, 2, "issuance must recheck membership and lifecycle after key custody suspends")
            try await database.close()
        } catch { try? await database.close(); throw error }
    }

    func testOtherSpaceTypesKeepTheirLocalPolicy() async throws {
        let store = PolicyStore()
        let checker = Membership()
        let directory = ConversationSpaceCredentialDirectory(local: store, accounts: store,
            authority: authority, membership: checker, lifecycle: store)
        let space = try SpaceURI(authority: authority, spaceType: "app.bsky.bookmarks", skey: "saved")
        try await directory.authorizeSimpleSpaceCredentialRead(space: space, user: nil, clientID: nil, authorization: .public)
        let calls = await store.localCalls
        XCTAssertEqual(calls, 1)
    }
}

private actor PolicyStore: AuthorizedSimpleSpaceCredentialDirectory, AuthorizedPreopenedAccountDirectory, ConversationSpaceAuthorityLifecycle {
    func registerKnownConversationSpace(space: SpaceURI, now: Date) async throws {}
    func requireConversationSpaceActive(space: SpaceURI) async throws {}
    func beginConversationSpaceDeletion(space: SpaceURI, authorization: AuthorizationContext, now: Date) async throws -> ConversationSpaceDeletion { throw SwanError.unavailable("not exercised") }
    func pendingConversationSpaceDeletions(authority: String) async throws -> [ConversationSpaceDeletion] { [] }
    func finishConversationSpaceDeletion(_ deletion: ConversationSpaceDeletion, now: Date) async throws {}
    func receiveMembershipVerifiedConversationSpaceWriteNotification(_ notification: AuthorizedSpaceWriteNotification, now: Date) async throws {}
    func deferConversationSpaceDeletion(_ deletion: ConversationSpaceDeletion, now: Date) async throws {}
    var localCalls = 0
    func requireActivePreopenedAccount(_ did: String) async throws {}
    func authorizeSimpleSpaceCredentialRead(space: SpaceURI, user: String?, clientID: String?, authorization: AuthorizationContext) async throws { localCalls += 1 }
}
private actor Membership: ConversationSpaceMembershipChecking {
    var calls = 0
    var denied = false
    func setDenied() { denied = true }
    func requireMembership(space: SpaceURI, user: String, now: Date) async throws {
        calls += 1
        if denied { throw SwanError.unauthorized("membership removed") }
    }
}

private struct ClosingSpaceSigningResolver: SpaceCredentialSigningKeyResolver {
    let database: SQLiteAccountDatabase
    let space: SpaceURI
    func signingKey(for authority: String) async throws -> SpaceCredentialAuthoritySigningKey? {
        _ = try await database.beginConversationSpaceDeletion(space: space,
            authorization: .accountOAuthForTesting(subject: authority, scopes: ["atproto", "space:\(space.spaceType)?authority=\(authority)&skey=\(space.skey)&manage=delete"]), now: Date())
        return SpaceCredentialAuthoritySigningKey(authority: authority, privateKey: P256.Signing.PrivateKey())
    }
}
