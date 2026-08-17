import Crypto
import Foundation
import Hummingbird
import HTTPTypes
import Logging
import NIOCore
@testable import SwanAccounts
@testable import SwanHTTP
@testable import SwanSQLite
import SwanCore
import SwanStorage
import XCTest

/// Task 4 regressions: durable portal projections, account-bound immediate
/// revocation, durable identity admission, atomic factor-mutation authority,
/// and revision-bound portal/legacy grant consumption at issuance.
final class Task4PortalProjectionIdentityTests: XCTestCase, @unchecked Sendable {
    private func makeDatabase(_ name: String) async throws -> (SQLiteControlDatabase, URL) {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "Task4-\(name)-\(UUID().uuidString)")
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        return (database, root)
    }

    private func createAccount(
        _ database: SQLiteControlDatabase,
        did: String,
        handle: String,
        now: Date
    ) async throws {
        let registration = try AccountControlRegistration(
                did: did,
                canonicalHandle: handle,
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: try .init(purpose: .signing, generation: 1),
                rotationKey: try .init(purpose: .rotation, generation: 1),
                createdAt: now.addingTimeInterval(-100)
            )
        _ = try await database.createAccount(registration)
        let stored = try await database.account(did: did)
        precondition(stored != nil, "fixture account must persist")
    }

    // MARK: Projections

    func testPortalProjectionListsManagementLegacyAndOAuthSessionsWithoutPlaceholders() async throws {
        let (database, root) = try await makeDatabase("projection")
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let did = "did:plc:projtestqwertyuiopasdfgh"
        let handle = "projection.example"
        let now = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        try await createAccount(database, did: did, handle: handle, now: now)

        let sessions = SwanManagementSessionRuntime(
            store: database,
            preAuthStore: database,
            csrfStore: database,
            preAuthSessionCoordinator: database
        )
        let first = try await sessions.issue(accountDID: did, strength: .password, now: now)
        let second = try await sessions.issue(accountDID: did, strength: .stepUpPassword(verifiedAt: now), now: now)

        // A legacy session family for the same account.
        try await database.createLegacySessionFamily(
            familyID: "legacy-family-1",
            did: did,
            appPasswordID: nil,
            accessDigest: Data(repeating: 0xA1, count: 32),
            accessExpiresAt: now.addingTimeInterval(3_600),
            refreshDigest: Data(repeating: 0xA2, count: 32),
            refreshExpiresAt: now.addingTimeInterval(90 * 86_400),
            now: now
        )

        // An OAuth token family (connected app).
        let familyID = UUID()
        let binding = try OAuthClientBinding(
            issuer: "https://issuer.example",
            clientID: "https://client.example/app",
            redirectURI: "https://client.example/callback",
            scopes: ["atproto"],
            dpopJKT: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
            confidentialClientKey: nil,
            refreshTokenAllowed: true
        )
        try await database.issueTokenPair(
            family: OAuthTokenFamily(
                familyID: familyID, subject: did, binding: binding,
                expiresAt: now.addingTimeInterval(14 * 86_400), createdAt: now
            ),
            tokens: OAuthIssuedTokenDigests(
                familyID: familyID,
                accessTokenDigest: Data(repeating: 0xB1, count: 32),
                refreshTokenDigest: Data(repeating: 0xB2, count: 32),
                accessExpiresAt: now.addingTimeInterval(300),
                refreshExpiresAt: now.addingTimeInterval(14 * 86_400)
            ),
            now: now
        )

        let storedAccount = try await database.account(did: did)
        let account = try XCTUnwrap(storedAccount)
        let service = SwanAccountPortalService(
            accountDirectory: FixedAccountDirectory(account: account),
            oauth: SwanAccountPortalOAuthProjectionProduction(store: database),
            sessions: sessions,
            legacySessions: database
        )
        let snapshot = try await service.portal(
            accountDID: did, currentSessionID: first.metadata.sessionID.rawValue, now: now
        )
        // No empty-session placeholder.
        XCTAssertEqual(snapshot.sessions.count, 3)
        let managementRows = snapshot.sessions.filter { $0.kind == "management" }
        let legacyRows = snapshot.sessions.filter { $0.kind == "legacy" }
        XCTAssertEqual(managementRows.count, 2)
        XCTAssertEqual(legacyRows.count, 1)
        XCTAssertEqual(legacyRows.first?.id, "legacy-family-1")
        // Exactly the presenting session is marked current.
        XCTAssertEqual(managementRows.filter(\.current).count, 1)
        XCTAssertEqual(
            managementRows.first(where: \.current)?.id,
            first.metadata.sessionID.rawValue
        )
        // No nil-OAuth placeholder: the family is listed with its scopes.
        XCTAssertEqual(snapshot.apps.count, 1)
        XCTAssertEqual(snapshot.apps.first?.id, familyID.uuidString)
        XCTAssertEqual(snapshot.apps.first?.scopes, ["atproto"])
    }

    // MARK: Revocation

    func testSessionRevocationIsAccountBoundIdempotentAndStepUpProtected() async throws {
        let (database, root) = try await makeDatabase("revoke")
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let did = "did:plc:revoketestqwertyuiopasda"
        let handle = "revoke.example"
        let now = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        try await createAccount(database, did: did, handle: handle, now: now)

        let sessions = SwanManagementSessionRuntime(
            store: database,
            preAuthStore: database,
            csrfStore: database,
            preAuthSessionCoordinator: database
        )
        let plain = try await sessions.issue(accountDID: did, strength: .password, now: now)
        let steppedUp = try await sessions.issue(
            accountDID: did, strength: .stepUpPassword(verifiedAt: now), now: now
        )
        let otherDID = "did:plc:otheraccountqwertyuiopaa"
        try await createAccount(database, did: otherDID, handle: "other.example", now: now)
        let otherAccount = try await sessions.issue(accountDID: otherDID, strength: .password, now: now)

        let storedAccount = try await database.account(did: did)
        let account = try XCTUnwrap(storedAccount)
        let service = SwanAccountPortalService(
            accountDirectory: FixedAccountDirectory(account: account),
            sessions: sessions,
            legacySessions: database
        )

        // Step-up protection: revoking others from a password-strength session
        // is refused.
        do {
            _ = try await service.mutate(
                path: "sessions/revoke-others",
                context: .init(
                    sessionID: plain.sessionValue, accountDID: did, strength: .password
                ),
                payload: nil,
                now: now
            )
            XCTFail("session revocation without step-up must be refused")
        } catch let error as SwanAccountPortalServiceError {
            XCTAssertEqual(error, .forbidden)
        }

        // Account-bound per-session revocation: another account's session ID
        // must not revoke this account's sessions.
        try await service.mutate(
            path: "sessions/\(plain.metadata.sessionID.rawValue)",
            context: .init(
                sessionID: steppedUp.sessionValue,
                accountDID: did,
                strength: .stepUpPassword(verifiedAt: now)
            ),
            payload: nil,
            now: now
        )
        let remaining = try await sessions.managementSessions(accountDID: did, now: now)
        XCTAssertEqual(remaining.count, 1)
        XCTAssertEqual(remaining.first?.sessionID.rawValue, steppedUp.metadata.sessionID.rawValue)

        // Idempotent: revoking the same session again is not an error.
        _ = try await service.mutate(
            path: "sessions/\(plain.metadata.sessionID.rawValue)",
            context: .init(
                sessionID: steppedUp.sessionValue,
                accountDID: did,
                strength: .stepUpPassword(verifiedAt: now)
            ),
            payload: nil,
            now: now
        )

        // Immediately effective: the revoked session no longer authenticates.
        do {
            _ = try await sessions.authenticate(sessionValue: plain.sessionValue, now: now)
            XCTFail("revoked session must not authenticate")
        } catch {}
    }

    func testConnectedAppRevocationIsAccountBoundIdempotentAndImmediatelyEffective() async throws {
        let (database, root) = try await makeDatabase("oauth-revoke")
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let did = "did:plc:oauthrevoketestasdfghjka"
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        try await createAccount(database, did: did, handle: "oauth-revoke.example", now: now)
        let familyID = UUID()
        let binding = try OAuthClientBinding(
            issuer: "https://issuer.example",
            clientID: "https://client.example/app",
            redirectURI: "https://client.example/callback",
            scopes: ["atproto"],
            dpopJKT: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
            confidentialClientKey: nil,
            refreshTokenAllowed: true
        )
        let tokens = OAuthIssuedTokenDigests(
            familyID: familyID,
            accessTokenDigest: Data(repeating: 0xC1, count: 32),
            refreshTokenDigest: Data(repeating: 0xC2, count: 32),
            accessExpiresAt: now.addingTimeInterval(300),
            refreshExpiresAt: now.addingTimeInterval(14 * 86_400)
        )
        try await database.issueTokenPair(
            family: OAuthTokenFamily(
                familyID: familyID, subject: did, binding: binding,
                expiresAt: now.addingTimeInterval(14 * 86_400), createdAt: now
            ),
            tokens: tokens,
            now: now
        )
        // Account-bound: revoking under another subject is a no-op.
        try await database.revokeTokenFamily(
            familyID: familyID, subject: "did:plc:somebodyabcdefghijklmnop-else", now: now
        )
        let liveFamilies = try await database.tokenFamilies(subject: did, now: now)
        XCTAssertEqual(liveFamilies.count, 1)
        // The access token is still valid before revocation.
        _ = try await database.validatedAccessToken(
            accessTokenDigest: tokens.accessTokenDigest,
            requireActiveSubject: false,
            now: now.addingTimeInterval(1)
        )
        // Real revocation.
        try await database.revokeTokenFamily(familyID: familyID, subject: did, now: now)
        let revokedFamilies = try await database.tokenFamilies(subject: did, now: now)
        XCTAssertTrue(revokedFamilies.isEmpty)
        // Idempotent.
        try await database.revokeTokenFamily(familyID: familyID, subject: did, now: now)
        // Immediately effective.
        do {
            _ = try await database.validatedAccessToken(
                accessTokenDigest: tokens.accessTokenDigest,
                requireActiveSubject: false,
                now: now.addingTimeInterval(2)
            )
            XCTFail("revoked family access token must be rejected")
        } catch {}
    }

    // MARK: Durable identity admission

    func testDurableIdentityAdmissionPreservesPLCAndActiveDeniesSuspendedAndFailsClosed() async throws {
        let now = Date(timeIntervalSince1970: 1_000)
        // PLC-only: no binding → full admission.
        let plcOnly = IdentityBindingFixture(binding: nil, failure: false)
        let plcDecision = try await SwanDurableIdentityAdmission(
            bindings: plcOnly, gracePeriod: 86_400
        ).identityAdmission(accountDID: "did:plc:plainabcdefghijklmnopqrs", now: now)
        XCTAssertTrue(plcDecision.allowsWrite)
        XCTAssertTrue(plcDecision.allowsTokenIssuance)
        XCTAssertTrue(plcDecision.allowsRead)

        // Active did:web → full admission.
        let active = try IdentityBinding(
            accountDID: "did:plc:webbyabcdefghijklmnopqrs",
            identityDID: "did:web:example.com",
            method: .didWeb,
            handle: "webby.example",
            documentDigest: Data(repeating: 1, count: 32),
            claimReceiptDigest: Data(repeating: 2, count: 32),
            reservedKeyID: "#atproto",
            lastValidatedAt: now,
            graceExpiresAt: now.addingTimeInterval(86_400),
            state: .active
        )
        let activeDecision = try await SwanDurableIdentityAdmission(
            bindings: IdentityBindingFixture(binding: active, failure: false),
            gracePeriod: 86_400
        ).identityAdmission(accountDID: "did:plc:webbyabcdefghijklmnopqrs", now: now)
        XCTAssertTrue(activeDecision.allowsWrite)
        XCTAssertTrue(activeDecision.allowsTokenIssuance)

        // Suspended did:web → reads preserved, writes and tokens denied.
        let suspended = try IdentityBinding(
            accountDID: "did:plc:webbyabcdefghijklmnopqrs",
            identityDID: "did:web:example.com",
            method: .didWeb,
            handle: "webby.example",
            documentDigest: Data(repeating: 1, count: 32),
            claimReceiptDigest: Data(repeating: 2, count: 32),
            reservedKeyID: "#atproto",
            lastValidatedAt: now.addingTimeInterval(-2 * 86_400),
            graceExpiresAt: now.addingTimeInterval(-1 * 86_400),
            state: .active
        )
        let suspendedDecision = try await SwanDurableIdentityAdmission(
            bindings: IdentityBindingFixture(binding: suspended, failure: false),
            gracePeriod: 86_400
        ).identityAdmission(accountDID: "did:plc:webbyabcdefghijklmnopqrs", now: now)
        XCTAssertEqual(suspendedDecision.continuity, .suspended)
        XCTAssertTrue(suspendedDecision.allowsRead)
        XCTAssertFalse(suspendedDecision.allowsWrite)
        XCTAssertFalse(suspendedDecision.allowsTokenIssuance)

        // Failed grace (stale within the active state) is also denied.
        let failedGrace = try IdentityBinding(
            accountDID: "did:plc:webbyabcdefghijklmnopqrs",
            identityDID: "did:web:example.com",
            method: .didWeb,
            handle: "webby.example",
            documentDigest: Data(repeating: 1, count: 32),
            claimReceiptDigest: Data(repeating: 2, count: 32),
            reservedKeyID: "#atproto",
            lastValidatedAt: now.addingTimeInterval(-86_401),
            graceExpiresAt: now.addingTimeInterval(-1),
            state: .active
        )
        let graceDecision = try await SwanDurableIdentityAdmission(
            bindings: IdentityBindingFixture(binding: failedGrace, failure: false),
            gracePeriod: 86_400
        ).identityAdmission(accountDID: "did:plc:webbyabcdefghijklmnopqrs", now: now)
        XCTAssertFalse(graceDecision.allowsWrite)
        XCTAssertFalse(graceDecision.allowsTokenIssuance)

        // Store failure fails closed: the evaluator throws, never allows.
        do {
            _ = try await SwanDurableIdentityAdmission(
                bindings: IdentityBindingFixture(binding: nil, failure: true),
                gracePeriod: 86_400
            ).identityAdmission(accountDID: "did:plc:webbyabcdefghijklmnopqrs", now: now)
            XCTFail("store failure must surface as an error")
        } catch {}
    }

    // MARK: Atomic factor-mutation authority (Task 3 Finding 1)

    func testFactorMutationCASRejectsStaleAuthorizationAndReturnsCommittedRevision() async throws {
        let (database, root) = try await makeDatabase("factor-cas")
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let did = "did:plc:factorcastqwertyuiopasda"
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        try await createAccount(database, did: did, handle: "factor-cas.example", now: now)

        let authorizedAt = try await database.factorRevision(accountDID: did, now: now)
        XCTAssertEqual(authorizedAt, 0)

        let first = try AuthenticationFactorMetadata(
            id: "totp-1", accountDID: did, kind: .totp, label: "First",
            lookupDigest: Data(repeating: 5, count: 32), createdAt: now, disabledAt: now
        )
        let committed = try await database.saveFactor(
            first, expectedRevision: authorizedAt, now: now
        )
        XCTAssertEqual(committed, 1)

        // A stale authorization (against revision 0) must fail the predicate.
        let second = try AuthenticationFactorMetadata(
            id: "totp-2", accountDID: did, kind: .totp, label: "Second",
            lookupDigest: Data(repeating: 6, count: 32), createdAt: now, disabledAt: now
        )
        do {
            _ = try await database.saveFactor(
                second, expectedRevision: authorizedAt, now: now
            )
            XCTFail("stale factor authorization must not commit")
        } catch let error as AccountControlStoreError {
            XCTAssertEqual(error, .invalidTransition)
        }

        // The concurrent winner's revision commits and bumps.
        let third = try AuthenticationFactorMetadata(
            id: "totp-3", accountDID: did, kind: .totp, label: "Third",
            lookupDigest: Data(repeating: 7, count: 32), createdAt: now
        )
        let committedTwo = try await database.saveFactor(
            third, expectedRevision: committed, now: now
        )
        XCTAssertEqual(committedTwo, 2)
        // Disable CAS also returns the committed revision.
        let disabled = try await database.disableFactor(
            id: "totp-3", accountDID: did, expectedRevision: committedTwo, now: now
        )
        XCTAssertEqual(disabled, 3)
        do {
            _ = try await database.disableFactor(
                id: "totp-1", accountDID: did, expectedRevision: committedTwo, now: now
            )
            XCTFail("stale disable authorization must not commit")
        } catch let error as AccountControlStoreError {
            XCTAssertEqual(error, .invalidTransition)
        }
    }

    // MARK: Revision-bound grant consumption at issuance (Task 3 Finding 2)

    func testPortalLoginGrantIsConsumedAtSessionIssuanceAndCannotReplay() async throws {
        let (database, root) = try await makeDatabase("portal-grant")
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let did = "did:plc:portalgrantqwertyuiopaab"
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        try await createAccount(database, did: did, handle: "portal-grant.example", now: now)

        let sessions = SwanManagementSessionRuntime(
            store: database,
            preAuthStore: database,
            csrfStore: database,
            preAuthSessionCoordinator: database
        )
        let context = try AccountAuthorizationContext(
            channel: .portal, sessionID: "pre-auth-session", purpose: "managementLogin"
        )
        let grant = try await database.createPasswordAuthorizationGrant(
            grantDigest: Data(repeating: 0xD1, count: 32),
            accountDID: did,
            context: context,
            now: now
        )
        let preAuth = await sessions.issuePreAuth(now: now)
        let issued = try await sessions.issueAfterPreAuth(
            preAuth,
            accountDID: did,
            strength: grant.strength,
            authorizationGrantDigest: grant.grantDigest,
            authorizationContext: context,
            now: now
        )
        XCTAssertFalse(issued.sessionValue.isEmpty)
        _ = try await sessions.authenticate(sessionValue: issued.sessionValue, now: now)

        // The grant is one-time: a second protected issuance must fail closed.
        let secondPreAuth = await sessions.issuePreAuth(now: now)
        do {
            _ = try await sessions.issueAfterPreAuth(
                secondPreAuth,
                accountDID: did,
                strength: grant.strength,
                authorizationGrantDigest: grant.grantDigest,
                authorizationContext: context,
                now: now
            )
            XCTFail("replayed portal grant must not issue a second session")
        } catch {}
    }

    func testLegacyFamilyCreationConsumesGrantAtomicallyAndCannotReplay() async throws {
        let (database, root) = try await makeDatabase("legacy-grant")
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let did = "did:plc:legacygrantqwertyuiopaab"
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        try await createAccount(database, did: did, handle: "legacy-grant.example", now: now)

        let context = try AccountAuthorizationContext(
            channel: .legacy, sessionID: "legacy-request-1", purpose: "managementLogin"
        )
        let grant = try await database.createPasswordAuthorizationGrant(
            grantDigest: Data(repeating: 0xE1, count: 32),
            accountDID: did,
            context: context,
            now: now
        )
        try await database.createLegacySessionFamilyConsumingGrant(
            familyID: "legacy-family-grant",
            did: did,
            appPasswordID: nil,
            accessDigest: Data(repeating: 0xE2, count: 32),
            accessExpiresAt: now.addingTimeInterval(3_600),
            refreshDigest: Data(repeating: 0xE3, count: 32),
            refreshExpiresAt: now.addingTimeInterval(90 * 86_400),
            authorizationGrantDigest: grant.grantDigest,
            authorizationContext: context,
            now: now
        )
        let families = try await database.legacySessionFamilies(did: did, now: now)
        XCTAssertEqual(families.count, 1)
        XCTAssertEqual(families.first?.familyID, "legacy-family-grant")

        do {
            try await database.createLegacySessionFamilyConsumingGrant(
                familyID: "legacy-family-replay",
                did: did,
                appPasswordID: nil,
                accessDigest: Data(repeating: 0xE4, count: 32),
                accessExpiresAt: now.addingTimeInterval(3_600),
                refreshDigest: Data(repeating: 0xE5, count: 32),
                refreshExpiresAt: now.addingTimeInterval(90 * 86_400),
                authorizationGrantDigest: grant.grantDigest,
                authorizationContext: context,
                now: now
            )
            XCTFail("replayed legacy grant must not create a family")
        } catch {}
        let familiesAfterReplay = try await database.legacySessionFamilies(did: did, now: now)
        XCTAssertEqual(familiesAfterReplay.count, 1)
    }

    // MARK: HTTP policy regressions

    func testHostileOriginDuplicateCookieAndRouteFallbackPolicy() async throws {
        let (database, root) = try await makeDatabase("http-policy")
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let did = "did:plc:httppolicyqwertyuiopasab"
        let now = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        try await createAccount(database, did: did, handle: "http-policy.example", now: now)

        let sessions = SwanManagementSessionRuntime(
            store: database,
            preAuthStore: database,
            csrfStore: database,
            preAuthSessionCoordinator: database
        )
        let issued = try await sessions.issue(accountDID: did, strength: .password, now: now)
        let storedAccount = try await database.account(did: did)
        let account = try XCTUnwrap(storedAccount)
        let service = SwanAccountPortalService(
            accountDirectory: FixedAccountDirectory(account: account),
            sessions: sessions
        )
        let configuration = try SwanAccountPortalConfiguration(
            publicOrigin: URL(string: "https://accounts.example")!,
            staticDirectory: root.appending(path: "web/build")
        )
        let router = Router(context: SwanHTTPRequestContext.self)
        SwanAccountPortalHTTP(
            configuration: configuration, sessions: sessions, service: service
        ).register(on: router)
        let application = Application(
            router: router,
            configuration: .init(address: .hostname("127.0.0.1", port: 0), serverName: "task4-policy"),
            logger: Logger(label: "task4-policy")
        )
        let baseHeaders: HTTPFields = [
            .contentType: "application/json",
            HTTPField.Name("Origin")!: "https://accounts.example",
            HTTPField.Name("Sec-Fetch-Site")!: "same-origin",
            HTTPField.Name("X-Swan-CSRF")!: issued.csrfValue,
        ]

        // Hostile origin: the mutation is refused before any session work.
        var hostile = baseHeaders
        hostile[HTTPField.Name("Origin")!] = "https://evil.example"
        hostile[.cookie] = "__Secure-swan_management=\(issued.sessionValue); swan_csrf=\(issued.csrfValue)"
        let hostileHeaders = hostile
        try await application.test(.router) { client in
            try await client.execute(
                uri: "/account/api/logout", method: .post, headers: hostileHeaders
            ) { response in
                XCTAssertEqual(response.status, HTTPResponse.Status.forbidden)
            }
        }

        // Duplicate cookies: an attacker-controlled first CSRF value cannot
        // authenticate; only the exact cookie/header pair does.
        var dupFirstAttacker = baseHeaders
        dupFirstAttacker[.cookie] = "__Secure-swan_management=\(issued.sessionValue); swan_csrf=ATTACKER; swan_csrf=\(issued.csrfValue)"
        let dupFirstAttackerHeaders = dupFirstAttacker
        try await application.test(.router) { client in
            try await client.execute(
                uri: "/account/api/logout", method: .post, headers: dupFirstAttackerHeaders
            ) { response in
                XCTAssertEqual(response.status, HTTPResponse.Status.forbidden)
            }
        }
        var dupValidFirst = baseHeaders
        dupValidFirst[.cookie] = "__Secure-swan_management=\(issued.sessionValue); swan_csrf=\(issued.csrfValue); swan_csrf=ATTACKER"
        let dupValidFirstHeaders = dupValidFirst
        try await application.test(.router) { client in
            try await client.execute(
                uri: "/account/api/logout", method: .post, headers: dupValidFirstHeaders
            ) { response in
                XCTAssertEqual(response.status, HTTPResponse.Status.ok)
            }
        }

        // Route fallback: unknown account API paths 404 instead of reaching
        // the SPA or a proxy handler.
        var unknown = baseHeaders
        unknown[.cookie] = "__Secure-swan_management=\(issued.sessionValue); swan_csrf=\(issued.csrfValue)"
        let unknownHeaders = unknown
        try await application.test(.router) { client in
            try await client.execute(
                uri: "/account/api/does-not-exist", method: .post, headers: unknownHeaders
            ) { response in
                XCTAssertEqual(response.status, HTTPResponse.Status.notFound)
            }
        }
    }

    // MARK: Restart persistence

    func testProjectionAndRevocationStatePersistAcrossReopen() async throws {
        let (database, root) = try await makeDatabase("restart")
        let did = "did:plc:restarttestqwertyuiopaab"
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        try await createAccount(database, did: did, handle: "restart.example", now: now)

        let sessions = SwanManagementSessionRuntime(
            store: database,
            preAuthStore: database,
            csrfStore: database,
            preAuthSessionCoordinator: database
        )
        _ = try await sessions.issue(accountDID: did, strength: .password, now: now)
        try await database.createLegacySessionFamily(
            familyID: "legacy-family-restart",
            did: did,
            appPasswordID: nil,
            accessDigest: Data(repeating: 0xF1, count: 32),
            accessExpiresAt: now.addingTimeInterval(3_600),
            refreshDigest: Data(repeating: 0xF2, count: 32),
            refreshExpiresAt: now.addingTimeInterval(90 * 86_400),
            now: now
        )
        try await database.close()

        // Reopen the same data directory: durable projection state survives.
        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        defer {
            Task {
                try? await reopened.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let management = try await reopened.managementSessions(accountDID: did, now: now)
        XCTAssertEqual(management.count, 1)
        let families = try await reopened.legacySessionFamilies(did: did, now: now)
        XCTAssertEqual(families.count, 1)
        XCTAssertEqual(families.first?.familyID, "legacy-family-restart")
        // Account-bound revocation works after reopen.
        try await reopened.revokeLegacySessionFamily(
            familyID: "legacy-family-restart", did: did, now: now
        )
        let familiesAfterRevoke = try await reopened.legacySessionFamilies(did: did, now: now)
        XCTAssertTrue(familiesAfterRevoke.isEmpty)
    }
}

// MARK: - Fixtures

private struct FixedAccountDirectory: SwanAccountPortalAccountDirectory {
    let account: AccountControlAccount
    func account(did: String) async throws -> AccountControlAccount? {
        did == account.did ? account : nil
    }
    func resolve(handle: String) async throws -> AccountControlAccount? {
        handle == account.canonicalHandle ? account : nil
    }
    func authenticateForLogin(handle: String, password: String, now: Date) async throws -> AccountLoginAuthenticationOutcome {
        .rejected
    }
}

private struct IdentityBindingFixture: IdentityBindingStore {
    let binding: IdentityBinding?
    let failure: Bool

    func identityBinding(accountDID: String) async throws -> IdentityBinding? {
        if failure { throw SwanError.unavailable("identity store failure") }
        return binding
    }
    func reserveDidWebClaim(_ transaction: DidWebClaimTransaction, now: Date) async throws {
        throw SwanError.unavailable("fixture")
    }
    func transitionDidWebClaim(_ transaction: DidWebClaimTransaction, from expected: DidWebClaimTransactionState, now: Date) async throws {
        throw SwanError.unavailable("fixture")
    }
    func commitDidWebClaim(_ request: DidWebClaimCommitRequest, history: IdentityBindingHistoryEntry?, now: Date) async throws {
        throw SwanError.unavailable("fixture")
    }
    func purgeExpiredIdentityClaims(now: Date) async throws {
        throw SwanError.unavailable("fixture")
    }
}
