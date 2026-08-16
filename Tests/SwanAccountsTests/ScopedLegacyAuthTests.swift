import XCTest
@testable import SwanAccounts
import SwanStorage

final class ScopedLegacyAuthTests: XCTestCase {
    func testScopeGrammarRejectsEmptyMalformedAndWildcardAudience() throws {
        for value in ["", " ", "rpc:*?aud=*", "rpc:com.atproto.server.getSession?aud=", "repo:"] {
            XCTAssertThrowsError(try SwanScope.parse(value), "should reject \(value.debugDescription)")
        }
    }

    func testScopeGrammarCanonicalizesAudienceFragmentsAndDotBoundaries() throws {
        let scope = try SwanScope.parse("rpc:com.atproto.repo?aud=https://pds.example.test/service#section")
        XCTAssertEqual(scope.canonicalValue, "rpc:com.atproto.repo?aud=https://pds.example.test/service")
        XCTAssertTrue(scope.allows(method: "com.atproto.repo.createRecord", audience: "https://pds.example.test/service/v1#x"))
        XCTAssertFalse(scope.allows(method: "com.atproto.repository.createRecord", audience: "https://pds.example.test/service/v1"))
        XCTAssertFalse(scope.allows(method: "com.atproto.repo.createRecord", audience: "https://pds.example.test/service-evil"))
    }

    func testDeclaredMethodPolicyDeniesUndeclaredMethodsAndRequiresScopes() throws {
        let policy = DeclaredMethodScopePolicy(declarations: [
            "com.atproto.repo.createRecord": ["repo:write"],
        ])
        XCTAssertTrue(policy.allows(credential: .scopes(["repo:write"]), method: "com.atproto.repo.createRecord"))
        XCTAssertFalse(policy.allows(credential: .scopes(["repo:read"]), method: "com.atproto.repo.createRecord"))
        XCTAssertFalse(policy.allows(credential: .scopes(["repo:write"]), method: "com.atproto.repo.deleteRecord"))
        XCTAssertFalse(policy.allows(credential: .fullAccessV1, method: "com.atproto.repo.createRecord"))
        XCTAssertTrue(DeclaredMethodScopePolicy.fullAccessV1.allows(credential: .fullAccessV1, method: "com.atproto.repo.createRecord"))
    }

    func testAppPasswordSecretPresentedOnceAndSessionRefreshReDerivesScope() async throws {
        let store = InMemoryLegacyAuthStore()
        let service = try LegacyAuthService(store: store, accountResolver: .fixture)
        let created = try await service.createAppPassword(accountDID: "did:plc:alice", name: "writer", scopes: ["repo:write"], now: Date(timeIntervalSince1970: 10))
        XCTAssertFalse(created.secret.isEmpty)
        let listed = try await service.listAppPasswords(accountDID: "did:plc:alice")
        XCTAssertEqual(listed.count, 1)
        let session = try await service.createSession(identifier: "did:plc:alice", password: created.secret, now: Date(timeIntervalSince1970: 11))
        XCTAssertEqual(session.scopes, ["repo:write"])
        try await service.updateAppPasswordScopes(accountDID: "did:plc:alice", name: "writer", scopes: ["repo:read"], now: Date(timeIntervalSince1970: 12))
        let refreshed = try await service.refreshSession(session.refreshToken, now: Date(timeIntervalSince1970: 13))
        XCTAssertEqual(refreshed.scopes, ["repo:read"])
        XCTAssertFalse(String(describing: listed).contains(created.secret))
    }

    func testRefreshReuseAtomicallyRevokesFamilyAndAppPasswordRevokesDerivedSessions() async throws {
        let store = InMemoryLegacyAuthStore()
        let service = try LegacyAuthService(store: store, accountResolver: .fixture)
        let created = try await service.createAppPassword(accountDID: "did:plc:alice", name: "writer", scopes: ["repo:write"], now: Date(timeIntervalSince1970: 10))
        let session = try await service.createSession(identifier: "did:plc:alice", password: created.secret, now: Date(timeIntervalSince1970: 11))
        _ = try await service.refreshSession(session.refreshToken, now: Date(timeIntervalSince1970: 12))
        do { _ = try await service.refreshSession(session.refreshToken, now: Date(timeIntervalSince1970: 13)); XCTFail("refresh replay must revoke the family") } catch { }
        do { _ = try await service.getSession(session.accessToken, now: Date(timeIntervalSince1970: 14)); XCTFail("revoked family must reject access") } catch { }

        let second = try await service.createSession(identifier: "did:plc:alice", password: created.secret, now: Date(timeIntervalSince1970: 15))
        try await service.revokeAppPassword(accountDID: "did:plc:alice", name: "writer", now: Date(timeIntervalSince1970: 16))
        do { _ = try await service.getSession(second.accessToken, now: Date(timeIntervalSince1970: 17)); XCTFail("revoked app password must revoke derived sessions") } catch { }
    }

    func testMFAEnabledPasswordLoginRequiresInjectedFactorButScopedPasswordRemainsAlternative() async throws {
        let store = InMemoryLegacyAuthStore()
        let resolver = LegacyAccountResolver(
            resolve: { identifier in
                identifier == "did:plc:mfa" ? LegacyAccountRecord(did: "did:plc:mfa", handle: "mfa.test", passwordVerifier: "password", mfaEnabled: true) : nil
            },
            verifyPassword: { account, password, factor in
                account.passwordVerifier == password && factor == "valid-factor"
            }
        )
        let service = try LegacyAuthService(store: store, accountResolver: resolver)
        do { _ = try await service.createSession(identifier: "did:plc:mfa", password: "password") ; XCTFail("MFA password login must require a factor") } catch { }
        let app = try await service.createAppPassword(accountDID: "did:plc:mfa", name: "scoped", scopes: ["repo:read"])
        let scoped = try await service.createSession(identifier: "did:plc:mfa", password: app.secret)
        XCTAssertEqual(scoped.scopes, ["repo:read"])
        let password = try await service.createSession(identifier: "did:plc:mfa", password: "password", authFactorToken: "valid-factor")
        XCTAssertEqual(password.scopes, ["atproto"])
    }
}
