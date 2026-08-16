import XCTest
@testable import SwanAccounts
import SwanStorage

final class ScopedLegacyAuthTests: XCTestCase {
    func testScopeGrammarRejectsEmptyMalformedAndWildcardAudience() throws {
        for value in ["", " ", "rpc:*?aud=*", "rpc:com.atproto.server.getSession?aud=", "repo:"] {
            XCTAssertThrowsError(try SwanScope.parse(value), "should reject \(value.debugDescription)")
        }
        XCTAssertThrowsError(try SwanScope.parse("include:bluesky"))
    }

    func testScopeGrammarCanonicalizesAudienceFragmentsAndDotBoundaries() throws {
        let scope = try SwanScope.parse("rpc:com.atproto.repo?aud=https://pds.example.test/service#section")
        XCTAssertEqual(scope.canonicalValue, "rpc:com.atproto.repo?aud=https://pds.example.test/service")
        XCTAssertTrue(scope.allows(method: "com.atproto.repo.createRecord", audience: "https://pds.example.test/service/v1#x"))
        XCTAssertFalse(scope.allows(method: "com.atproto.repository.createRecord", audience: "https://pds.example.test/service/v1"))
        XCTAssertFalse(scope.allows(method: "com.atproto.repo.createRecord", audience: "https://pds.example.test/service-evil"))
        XCTAssertFalse(SwanScope.audienceMatches("https://api.bsky.app", "https://api.bsky.app.evil/"))
        XCTAssertTrue(SwanScope.audienceMatches("https://api.bsky.app", "https://api.bsky.app:443/"))
    }

    func testBlueskyPresetsRoundTripTwoLabelNamespacesAndRejectEvilBoundaries() throws {
        for preset in [SwanScopePreset.bluesky, .readOnly, .postOnly] {
            for value in preset.scopes {
                let parsed = try SwanScope.parse(value)
                XCTAssertEqual(try SwanScope.parse(parsed.canonicalValue).canonicalValue, parsed.canonicalValue)
            }
        }
        let app = try SwanScope.parse("rpc:app.bsky?aud=did:web:api.bsky.app")
        let chat = try SwanScope.parse("rpc:chat.bsky?aud=did:web:api.bsky.chat")
        XCTAssertTrue(app.allows(method: "app.bsky.feed.getTimeline", audience: "did:web:api.bsky.app"))
        XCTAssertTrue(chat.allows(method: "chat.bsky.convo.listConvos", audience: "did:web:api.bsky.chat"))
        XCTAssertFalse(app.allows(method: "app.bsky.feed.getFeed", audience: "https://api.bsky.app"))
        XCTAssertFalse(app.allows(method: "app.bsky.evil.feed.getTimeline", audience: "https://api.bsky.app.evil"))
        let feed = try SwanScope.parse("rpc:app.bsky.feed?aud=https://api.bsky.app")
        XCTAssertFalse(feed.allows(method: "app.bsky.feed-evil.getTimeline", audience: "https://api.bsky.app"))
        XCTAssertFalse(feed.allows(method: "app.bsky.feed.getTimeline.evil", audience: "https://api.bsky.app"))
        for value in ["rpc:app?aud=https://api.bsky.app", "rpc:app.*?aud=https://api.bsky.app", "rpc:app..bsky?aud=https://api.bsky.app"] {
            XCTAssertThrowsError(try SwanScope.parse(value))
        }
    }

    func testDeclaredMethodPolicyDeniesUndeclaredMethodsAndRequiresScopes() throws {
        let policy = DeclaredMethodScopePolicy(declarations: [
            "com.atproto.repo.createRecord": ["repo:write"],
        ])
        XCTAssertTrue(policy.allows(credential: .scopes(["repo:write"]), method: "com.atproto.repo.createRecord"))
        XCTAssertFalse(policy.allows(credential: .scopes(["repo:read"]), method: "com.atproto.repo.createRecord"))
        XCTAssertFalse(policy.allows(credential: .scopes(["repo:write"]), method: "com.atproto.repo.deleteRecord"))
        XCTAssertFalse(policy.allows(credential: .fullAccessV1, method: "com.atproto.repo.createRecord"))
        XCTAssertFalse(DeclaredMethodScopePolicy.fullAccessV1.allows(credential: .fullAccessV1, method: "com.atproto.repo.createRecord"))
        XCTAssertThrowsError(try SwanScopeEvaluator().evaluate(credential: .fullAccessV1, canonicalMethod: "com.atproto.repo.deleteRecord", declaredMethodPolicy: policy))
    }

    func testReferenceLegacyMethodMatrixUsesPresetCompatibleRequiredScopes() throws {
        let matrix: [(String, Set<String>)] = [
            ("com.atproto.repo.getRecord", ["repo:read"]),
            ("com.atproto.repo.createRecord", ["repo:write"]),
            ("com.atproto.sync.getBlob", ["blob:read"]),
            ("com.atproto.identity.resolveHandle", ["identity:read"]),
            ("app.bsky.feed.getTimeline", ["rpc:app.bsky?aud=https://api.bsky.app"]),
            ("chat.bsky.convo.listConvos", ["rpc:chat.bsky?aud=https://api.bsky.app"])
        ]
        for (method, scopes) in matrix {
            XCTAssertEqual(DeclaredMethodScopePolicy.referenceLegacy.requiredScopes(for: method), scopes.contains(where: { $0.hasPrefix("rpc:") }) ? [scopes.first!.split(separator: "?").first.map(String.init)!] : scopes)
            let audience = scopes.first?.contains("?aud=") == true ? "https://api.bsky.app" : nil
            XCTAssertNoThrow(try SwanScopeEvaluator().evaluate(credential: .scopes(scopes), canonicalMethod: method, declaredMethodPolicy: .referenceLegacy, audience: audience))
            XCTAssertTrue(DeclaredMethodScopePolicy.fullAccessV1.declares(method))
        }
        XCTAssertFalse(DeclaredMethodScopePolicy.referenceLegacy.declares("app.bsky.feed.unknown"))
    }

    func testAppPasswordSecretPresentedOnceAndScopeEditRevokesDerivedSession() async throws {
        let store = InMemoryLegacyAuthStore()
        let service = try LegacyAuthService(store: store, accountResolver: .fixture, secretKey: Data(repeating: 7, count: 32), tokenIssuer: HMACLegacyTokenIssuer(key: Data(repeating: 8, count: 32), issuer: "swan.test"), managementAuthorizer: LegacyManagementAuthorizer { _, session, stepUp in session == "management" && (stepUp.isEmpty || stepUp == "step-up") }, loginAdmission: LegacyLoginAdmission { _ in }, methodPolicy: DeclaredMethodScopePolicy.fullAccessV1)
        let created = try await service.createAppPassword(accountDID: "did:plc:alice", name: "writer", scopes: ["repo:write"], managementSessionToken: "management", stepUpToken: "step-up", now: Date(timeIntervalSince1970: 10))
        XCTAssertFalse(created.secret.isEmpty)
        let listed = try await service.listAppPasswords(accountDID: "did:plc:alice", managementSessionToken: "management")
        XCTAssertEqual(listed.count, 1)
        let session = try await service.createSession(identifier: "did:plc:alice", password: created.secret, now: Date(timeIntervalSince1970: 11))
        XCTAssertEqual(session.scopes, ["repo:write"])
        let used = try await service.listAppPasswords(accountDID: "did:plc:alice", managementSessionToken: "management")
        XCTAssertEqual(used.first?.lastUsedAt, Date(timeIntervalSince1970: 11))
        try await service.updateAppPasswordScopes(accountDID: "did:plc:alice", name: "writer", scopes: ["repo:read"], managementSessionToken: "management", stepUpToken: "step-up", now: Date(timeIntervalSince1970: 12))
        do { _ = try await service.refreshSession(session.refreshToken, now: Date(timeIntervalSince1970: 13)); XCTFail("scope edit must revoke the old family") } catch { }
        let replacement = try await service.createSession(identifier: "did:plc:alice", password: created.secret, now: Date(timeIntervalSince1970: 14))
        XCTAssertEqual(replacement.scopes, ["repo:read"])
        XCTAssertFalse(String(describing: listed).contains(created.secret))
    }

    func testRefreshReuseAtomicallyRevokesFamilyAndAppPasswordRevokesDerivedSessions() async throws {
        let store = InMemoryLegacyAuthStore()
        let service = try LegacyAuthService(store: store, accountResolver: .fixture, secretKey: Data(repeating: 7, count: 32), tokenIssuer: HMACLegacyTokenIssuer(key: Data(repeating: 8, count: 32), issuer: "swan.test"), managementAuthorizer: LegacyManagementAuthorizer { _, _, _ in true }, loginAdmission: LegacyLoginAdmission { _ in }, methodPolicy: DeclaredMethodScopePolicy.fullAccessV1)
        let created = try await service.createAppPassword(accountDID: "did:plc:alice", name: "writer", scopes: ["repo:write"], managementSessionToken: "m", stepUpToken: "s", now: Date(timeIntervalSince1970: 10))
        let session = try await service.createSession(identifier: "did:plc:alice", password: created.secret, now: Date(timeIntervalSince1970: 11))
        _ = try await service.refreshSession(session.refreshToken, now: Date(timeIntervalSince1970: 12))
        do { _ = try await service.refreshSession(session.refreshToken, now: Date(timeIntervalSince1970: 13)); XCTFail("refresh replay must revoke the family") } catch { }
        do { _ = try await service.getSession(session.accessToken, now: Date(timeIntervalSince1970: 14)); XCTFail("revoked family must reject access") } catch { }

        let second = try await service.createSession(identifier: "did:plc:alice", password: created.secret, now: Date(timeIntervalSince1970: 15))
        try await service.revokeAppPassword(accountDID: "did:plc:alice", name: "writer", managementSessionToken: "m", stepUpToken: "s", now: Date(timeIntervalSince1970: 16))
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
        let service = try LegacyAuthService(store: store, accountResolver: resolver, secretKey: Data(repeating: 7, count: 32), tokenIssuer: HMACLegacyTokenIssuer(key: Data(repeating: 8, count: 32), issuer: "swan.test"), managementAuthorizer: LegacyManagementAuthorizer { _, _, _ in true }, loginAdmission: LegacyLoginAdmission { _ in }, methodPolicy: DeclaredMethodScopePolicy.fullAccessV1)
        do { _ = try await service.createSession(identifier: "did:plc:mfa", password: "password") ; XCTFail("MFA password login must require a factor") } catch { }
        let app = try await service.createAppPassword(accountDID: "did:plc:mfa", name: "scoped", scopes: ["repo:read"], managementSessionToken: "m", stepUpToken: "s")
        let scoped = try await service.createSession(identifier: "did:plc:mfa", password: app.secret)
        XCTAssertEqual(scoped.scopes, ["repo:read"])
        let password = try await service.createSession(identifier: "did:plc:mfa", password: "password", authFactorToken: "valid-factor")
        XCTAssertTrue(password.fullAccess)
        _ = try await service.getServiceAuth(accessToken: password.accessToken, lxm: "com.atproto.repo.getRecord", aud: "https://pds.example.test")
        let refreshed = try await service.refreshSession(password.refreshToken)
        XCTAssertTrue(refreshed.fullAccess)
        let fetched = try await service.getSession(refreshed.accessToken)
        XCTAssertTrue(fetched.fullAccess)
        _ = try await service.getServiceAuth(accessToken: fetched.accessToken, lxm: "com.atproto.repo.getRecord", aud: "https://pds.example.test")
        let exactExpiry = Date(timeIntervalSince1970: 50)
        let serviceToken = try await service.getServiceAuth(accessToken: fetched.accessToken, lxm: "com.atproto.repo.getRecord", aud: "https://pds.example.test", requestedExpiry: exactExpiry, now: Date(timeIntervalSince1970: 15))
        XCTAssertEqual(serviceToken.expiresAt, exactExpiry)
        do { _ = try await service.getServiceAuth(accessToken: fetched.accessToken, lxm: "com.atproto.repo.getRecord", aud: "https://pds.example.test", requestedExpiry: Date(timeIntervalSince1970: 76), now: Date(timeIntervalSince1970: 15)); XCTFail("expiry over 60 seconds must deny") } catch { }
        do { _ = try await service.getServiceAuth(accessToken: password.accessToken, lxm: "com.atproto.repo.undeclared", aud: "https://pds.example.test"); XCTFail("undeclared full-access method must deny") } catch { }
    }

    func testManagementMutationWithoutVerifiedSessionOrStepUpIsDenied() async throws {
        let store = InMemoryLegacyAuthStore()
        let service = try LegacyAuthService(store: store, accountResolver: .fixture, secretKey: Data(repeating: 7, count: 32), tokenIssuer: HMACLegacyTokenIssuer(key: Data(repeating: 8, count: 32), issuer: "swan.test"), managementAuthorizer: LegacyManagementAuthorizer { _, _, _ in XCTFail("authorizer must not run without both proofs"); return true }, loginAdmission: LegacyLoginAdmission { _ in }, methodPolicy: DeclaredMethodScopePolicy.fullAccessV1)
        do { _ = try await service.createAppPassword(accountDID: "did:plc:alice", name: "bad", scopes: ["repo:read"]); XCTFail("missing management proof must deny") } catch { }
    }
}
