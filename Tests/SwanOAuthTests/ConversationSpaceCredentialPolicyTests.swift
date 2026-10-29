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
            XCTAssertEqual(checks, 1, "the recheck after key custody suspends answers SpaceDeleted before membership")
            try await database.close()
        } catch { try? await database.close(); throw error }
    }

    /// SWAN-AUTH-3 (Oct 22 §1, §6): the local deletion record answers
    /// SpaceDeleted before the delegation guard and the delivery-service
    /// membership call, with or without a delegation token.
    func testDeletedConversationSpaceAnswersSpaceDeletedBeforePolicyChecks() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("SwanConversationTombstoneFirst-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: authority)
        do {
            let space = try SpaceURI(authority: authority, spaceType: "blue.catbird.labyrinth.conversation", skey: UUID().uuidString.lowercased())
            let accounts = PolicyStore()
            let checker = Membership()
            let directory = ConversationSpaceCredentialDirectory(local: accounts, accounts: accounts,
                authority: authority, membership: checker, lifecycle: database)
            try await database.registerKnownConversationSpace(space: space, now: Date())
            _ = try await database.beginConversationSpaceDeletion(space: space,
                authorization: .accountOAuthForTesting(subject: authority, scopes: ["atproto", "space:\(space.spaceType)?authority=\(authority)&skey=\(space.skey)&manage=delete"]), now: Date())
            await checker.setUnavailable()
            do {
                try await directory.authorizeSimpleSpaceCredentialRead(space: space, user: nil, clientID: nil, authorization: .public)
                XCTFail("a token-less request for a deleted conversation space was not SpaceDeleted")
            } catch let error as AuthorizedSimpleSpaceLifecycleError {
                XCTAssertEqual(error, .deleted)
            }
            do {
                try await directory.authorizeSimpleSpaceCredentialRead(space: space, user: user, clientID: nil,
                    authorization: .spaceDelegation(subject: user, space: space))
                XCTFail("an unreachable delivery service hid the local deletion record")
            } catch let error as AuthorizedSimpleSpaceLifecycleError {
                XCTAssertEqual(error, .deleted)
            }
            let calls = await checker.calls
            XCTAssertEqual(calls, 0, "a deleted space must not reach the membership policy")
            try await database.close()
        } catch { try? await database.close(); throw error }
    }

    /// SWAN-AUTH-3 (Oct 22 §1): a conversation space is never public, so a
    /// request without a delegation token is SpaceNotFound, whether or not
    /// the generation is registered locally.
    func testTokenlessConversationSpaceIsNotFound() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("SwanConversationTokenless-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: authority)
        do {
            let registered = try SpaceURI(authority: authority, spaceType: "blue.catbird.labyrinth.conversation", skey: UUID().uuidString.lowercased())
            let unknown = try SpaceURI(authority: authority, spaceType: "blue.catbird.labyrinth.conversation", skey: UUID().uuidString.lowercased())
            let accounts = PolicyStore()
            let checker = Membership()
            let directory = ConversationSpaceCredentialDirectory(local: accounts, accounts: accounts,
                authority: authority, membership: checker, lifecycle: database)
            try await database.registerKnownConversationSpace(space: registered, now: Date())
            for space in [registered, unknown] {
                do {
                    try await directory.authorizeSimpleSpaceCredentialRead(space: space, user: nil, clientID: nil, authorization: .public)
                    XCTFail("a token-less conversation credential was authorized")
                } catch let error as AuthorizedSimpleSpaceLifecycleError {
                    XCTAssertEqual(error, .notFound)
                }
            }
            let calls = await checker.calls
            XCTAssertEqual(calls, 0)
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
    var unavailable = false
    func setDenied() { denied = true }
    func setUnavailable() { unavailable = true }
    func requireMembership(space: SpaceURI, user: String, now: Date) async throws {
        calls += 1
        if unavailable { throw SwanError.unavailable("delivery service unreachable") }
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
