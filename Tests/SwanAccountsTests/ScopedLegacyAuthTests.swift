import XCTest
@testable import SwanAccounts
@testable import SwanSQLite
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
        XCTAssertTrue(DeclaredMethodScopePolicy.fullAccessV1.allows(credential: .fullAccessV1, method: "com.atproto.repo.createRecord"))
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

    func testReferenceRegistryCoversPinnedProxyParityManifest() {
        let proxyManifest: Set<String> = [
            "app.bsky.actor.getPreferences", "app.bsky.actor.getPreferencesExtended",
            "app.bsky.actor.getProfile", "app.bsky.actor.putPreferences", "app.bsky.actor.searchActors",
            "app.bsky.feed.getAuthorFeed", "app.bsky.feed.getFeed", "app.bsky.feed.getFeedSkeleton",
            "app.bsky.feed.getTimeline", "app.bsky.notification.updateSeen", "chat.bsky.convo.listConvos"
        ]
        XCTAssertTrue(proxyManifest.isSubset(of: DeclaredMethodScopePolicy.referenceLegacy.declaredMethods))
        XCTAssertFalse(DeclaredMethodScopePolicy.referenceLegacy.declaredMethods.contains("app.bsky.unknown.getFeed"))
        XCTAssertTrue(DeclaredMethodScopePolicy.referenceLegacy.allows(credential: .fullAccessV1, method: "com.atproto.repo.getRecord"))
        XCTAssertTrue(DeclaredMethodScopePolicy.referenceLegacy.allows(credential: .fullAccessV1, method: "tools.ozone.moderation.emitEvent"))
        XCTAssertTrue(DeclaredMethodScopePolicy.referenceLegacy.declares("tools.ozone.moderation.getRepo"))
    }

    func testGeneratedRegistryIsTheExactAuthorizationSet() {
        XCTAssertEqual(
            DeclaredMethodScopePolicy.referenceLegacy.declaredMethods,
            Set(GeneratedLegacyMethodRegistry.declarations.keys)
        )
        XCTAssertTrue(GeneratedLegacyMethodRegistry.declarations.keys.contains("com.atproto.server.createSession"))
        XCTAssertTrue(GeneratedLegacyMethodRegistry.routing["com.atproto.server.createSession"] == .local)
        XCTAssertFalse(GeneratedLegacyMethodRegistry.declarations.keys.contains("app.bsky.actor.defs"))
        XCTAssertEqual(GeneratedLegacyMethodRegistry.declarations.count, 259)
        XCTAssertEqual(GeneratedLegacyMethodRegistry.sourceDigest, "12749bd4e4f1f33da823c24705b30a9f59a2c1300fbf87c763ee5f7ce152ec19")
        XCTAssertEqual(GeneratedLegacyMethodRegistry.sourceRevision, "d6296a1cfdb40a773319cb59061300e4e8e52f26")
        XCTAssertTrue(GeneratedLegacyMethodRegistry.declarations.keys.contains("chat.bsky.convo.getUnreadCounts"))
        XCTAssertTrue(GeneratedLegacyMethodRegistry.declarations.keys.contains("app.bsky.video.getUploadStatus"))
        for (method, scopes) in GeneratedLegacyMethodRegistry.declarations {
            XCTAssertTrue(DeclaredMethodScopePolicy.isCanonicalMethod(method))
            for scope in scopes {
                let concrete = scope.hasPrefix("rpc:") && !scope.contains("?aud=") ? scope + "?aud=did:web:api.bsky.app" : scope
                XCTAssertNoThrow(try SwanScope.parse(concrete))
            }
        }
        XCTAssertTrue(GeneratedLegacyMethodRegistry.routing["com.atproto.repo.getRecord"] == .local)
        XCTAssertTrue(GeneratedLegacyMethodRegistry.routing["app.bsky.feed.getFeed"] == .proxyDefault)
        XCTAssertTrue(GeneratedLegacyMethodRegistry.routing["com.atproto.moderation.createReport"] == .proxyExplicit)
        XCTAssertTrue(GeneratedLegacyMethodRegistry.routing["chat.bsky.convo.getUnreadCounts"] == .proxyDefault)
        XCTAssertTrue(GeneratedLegacyMethodRegistry.routing["app.bsky.video.getUploadStatus"] == .proxyDefault)
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
        let password = try await service.createSession(identifier: "did:plc:mfa", password: "password", authFactorToken: "valid-factor", now: Date(timeIntervalSince1970: 15))
        XCTAssertTrue(password.fullAccess)
        _ = try await service.getServiceAuth(accessToken: password.accessToken, lxm: "com.atproto.repo.getRecord", aud: "https://pds.example.test", now: Date(timeIntervalSince1970: 15))
        let refreshed = try await service.refreshSession(password.refreshToken, now: Date(timeIntervalSince1970: 15))
        XCTAssertTrue(refreshed.fullAccess)
        let fetched = try await service.getSession(refreshed.accessToken, now: Date(timeIntervalSince1970: 15))
        XCTAssertTrue(fetched.fullAccess)
        _ = try await service.getServiceAuth(accessToken: fetched.accessToken, lxm: "com.atproto.repo.getRecord", aud: "https://pds.example.test", now: Date(timeIntervalSince1970: 15))
        let exactExpiry = Date(timeIntervalSince1970: 50)
        let serviceToken = try await service.getServiceAuth(accessToken: fetched.accessToken, lxm: "com.atproto.repo.getRecord", aud: "https://pds.example.test", requestedExpiry: exactExpiry, now: Date(timeIntervalSince1970: 15))
        XCTAssertEqual(serviceToken.expiresAt, exactExpiry)
        let fractional = try await service.getServiceAuth(accessToken: fetched.accessToken, lxm: "com.atproto.repo.getRecord", aud: "https://pds.example.test", requestedExpiry: Date(timeIntervalSince1970: 75.9), now: Date(timeIntervalSince1970: 15.9))
        XCTAssertEqual(fractional.expiresAt, Date(timeIntervalSince1970: 75))
        do { _ = try await service.getServiceAuth(accessToken: fetched.accessToken, lxm: "com.atproto.repo.getRecord", aud: "https://pds.example.test", requestedExpiry: Date(timeIntervalSince1970: 76), now: Date(timeIntervalSince1970: 15)); XCTFail("expiry over 60 seconds must deny") } catch { }
        do { _ = try await service.getServiceAuth(accessToken: password.accessToken, lxm: "com.atproto.repo.undeclared", aud: "https://pds.example.test"); XCTFail("undeclared full-access method must deny") } catch { }
    }

    func testManagementMutationWithoutVerifiedSessionOrStepUpIsDenied() async throws {
        let store = InMemoryLegacyAuthStore()
        let service = try LegacyAuthService(store: store, accountResolver: .fixture, secretKey: Data(repeating: 7, count: 32), tokenIssuer: HMACLegacyTokenIssuer(key: Data(repeating: 8, count: 32), issuer: "swan.test"), managementAuthorizer: LegacyManagementAuthorizer { _, _, _ in XCTFail("authorizer must not run without both proofs"); return true }, loginAdmission: LegacyLoginAdmission { _ in }, methodPolicy: DeclaredMethodScopePolicy.fullAccessV1)
        do { _ = try await service.createAppPassword(accountDID: "did:plc:alice", name: "bad", scopes: ["repo:read"]); XCTFail("missing management proof must deny") } catch { }
    }

    func testSQLiteBackedSessionFamilySurvivesRestartAndAppPasswordRevocationHolds() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "ScopedLegacyAuthTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let accountDID = "did:plc:abcdefghijklmnopqrstuvwx"
        let secretKey = Data(repeating: 7, count: 32)
        let issuerKey = Data(repeating: 8, count: 32)
        let managementAuthorizer = LegacyManagementAuthorizer { _, _, _ in true }
        let loginAdmission = LegacyLoginAdmission { _ in }
        let resolver = LegacyAccountResolver(
            resolve: { identifier in
                guard identifier == accountDID || identifier == "alice.test" else { return nil }
                return LegacyAccountRecord(did: accountDID, handle: "alice.test", passwordVerifier: "password")
            },
            verifyPassword: { account, password, factor in
                account.passwordVerifier == password && (!account.mfaEnabled || factor == "valid-factor")
            }
        )

        func makeService(_ store: any AccountLegacyAuthStore) throws -> LegacyAuthService {
            try LegacyAuthService(
                store: store,
                accountResolver: resolver,
                secretKey: secretKey,
                tokenIssuer: HMACLegacyTokenIssuer(key: issuerKey, issuer: "swan.test"),
                managementAuthorizer: managementAuthorizer,
                loginAdmission: loginAdmission,
                methodPolicy: DeclaredMethodScopePolicy.fullAccessV1
            )
        }

        // First process: create the account, an app password, and a derived
        // session family, then rotate once so the family has a live refresh
        // token that must survive the restart.
        let first = try await SQLiteControlDatabase(dataDirectory: root)
        addTeardownBlock { try? await first.close() }
        _ = try await first.createAccount(try AccountControlRegistration(
            did: accountDID,
            canonicalHandle: "alice.test",
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$initialsalt$initial-precomputed-verifier",
            signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
            rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
            createdAt: Date(timeIntervalSince1970: 10)
        ))
        let firstService = try makeService(first)
        let created = try await firstService.createAppPassword(accountDID: accountDID, name: "writer", scopes: ["repo:write"], managementSessionToken: "m", stepUpToken: "s", now: Date(timeIntervalSince1970: 11))
        let session = try await firstService.createSession(identifier: accountDID, password: created.secret, now: Date(timeIntervalSince1970: 12))
        let rotated = try await firstService.refreshSession(session.refreshToken, now: Date(timeIntervalSince1970: 13))
        XCTAssertEqual(rotated.scopes, ["repo:write"])
        try await first.close()

        // Restart: reopen the same data directory and rebuild the service.
        // The rotated refresh token must still be live, and the app-password
        // revocation performed after restart must still revoke the derived
        // session family.
        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        addTeardownBlock { try? await reopened.close() }
        let restartedService = try makeService(reopened)
        let afterRestart = try await restartedService.refreshSession(rotated.refreshToken, now: Date(timeIntervalSince1970: 14))
        XCTAssertEqual(afterRestart.scopes, ["repo:write"])
        try await restartedService.revokeAppPassword(accountDID: accountDID, name: "writer", managementSessionToken: "m", stepUpToken: "s", now: Date(timeIntervalSince1970: 15))
        do {
            _ = try await restartedService.getSession(afterRestart.accessToken, now: Date(timeIntervalSince1970: 16))
            XCTFail("app-password revocation after restart must reject derived access")
        } catch { }
        do {
            _ = try await restartedService.refreshSession(afterRestart.refreshToken, now: Date(timeIntervalSince1970: 17))
            XCTFail("app-password revocation after restart must reject derived refresh")
        } catch { }
        try await reopened.close()
    }
}
