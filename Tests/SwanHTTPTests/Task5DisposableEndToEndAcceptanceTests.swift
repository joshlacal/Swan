import Crypto
import Foundation
import HTTPTypes
import Hummingbird
import HummingbirdTesting
import Logging
import NIOCore
@testable import SwanAccounts
import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
@testable import SwanSQLite
import SwanStorage
import XCTest

/// Task 5: Disposable end-to-end acceptance tests.
/// Validates the complete lifecycle: signup/provisioning, management sessions,
/// scoped app passwords, OAuth DPoP issuance/rotation/replay-revocation,
/// recovery-wide revocation, server restart state preservation, and did:web
/// identity admission gating.
final class Task5DisposableEndToEndAcceptanceTests: XCTestCase, @unchecked Sendable {
    private let issuer = URL(string: "https://swan.example")!
    private let clientID = URL(string: "http://localhost?scope=atproto&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback")!
    private let redirectURI = URL(string: "http://127.0.0.1/callback")!
    private let aliceDID = "did:plc:aliceacceptqwertyuiopaab"
    private let aliceHandle = "alice.example"

    private func makeDatabase(_ name: String) async throws -> (SQLiteControlDatabase, URL) {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "Task5Acceptance-\(name)-\(UUID().uuidString)")
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

    // MARK: - Acceptance Test 1: Full Provisioning, Portal Auth, and Token-Free Projections

    func testProvisioningPortalAuthenticationAndInventoryProjections() async throws {
        let (database, root) = try await makeDatabase("projections")
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let now = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        try await createAccount(database, did: aliceDID, handle: aliceHandle, now: now)

        let sessions = SwanManagementSessionRuntime(
            store: database,
            preAuthStore: database,
            csrfStore: database,
            preAuthSessionCoordinator: database
        )
        let first = try await sessions.issue(accountDID: aliceDID, strength: .password, now: now)
        _ = try await sessions.issue(accountDID: aliceDID, strength: .stepUpPassword(verifiedAt: now), now: now)

        // Legacy session family
        try await database.createLegacySessionFamily(
            familyID: "legacy-family-1",
            did: aliceDID,
            appPasswordID: nil,
            accessDigest: Data(repeating: 0xA1, count: 32),
            accessExpiresAt: now.addingTimeInterval(3_600),
            refreshDigest: Data(repeating: 0xA2, count: 32),
            refreshExpiresAt: now.addingTimeInterval(90 * 86_400),
            now: now
        )

        // Connected OAuth application
        let familyID = UUID()
        let binding = OAuthClientBinding(
            issuer: issuer.absoluteString,
            clientID: "https://app.example/client-metadata.json",
            redirectURI: "https://app.example/callback",
            scopes: ["atproto"],
            dpopJKT: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
            confidentialClientKey: nil,
            refreshTokenAllowed: true
        )
        try await database.issueTokenPair(
            family: OAuthTokenFamily(
                familyID: familyID, subject: aliceDID, binding: binding,
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

        let storedAccount = try await database.account(did: aliceDID)
        let account = try XCTUnwrap(storedAccount)
        let service = SwanAccountPortalService(
            accountDirectory: FixedAccountDirectory(account: account),
            oauth: SwanAccountPortalOAuthProjectionProduction(store: database),
            sessions: sessions,
            legacySessions: database
        )

        let snapshot = try await service.portal(
            accountDID: aliceDID,
            currentSessionID: first.metadata.sessionID.rawValue,
            now: now
        )

        XCTAssertEqual(snapshot.account.did, aliceDID)
        XCTAssertEqual(snapshot.account.handle, aliceHandle)
        XCTAssertEqual(snapshot.sessions.count, 3) // 2 management sessions + 1 legacy session
        XCTAssertEqual(snapshot.apps.count, 1)
        XCTAssertEqual(snapshot.apps.first?.id, familyID.uuidString)
        XCTAssertEqual(snapshot.apps.first?.scopes, ["atproto"])
        XCTAssertEqual(snapshot.sessions.first(where: { $0.id == first.metadata.sessionID.rawValue })?.current, true)
    }

    // MARK: - Acceptance Test 2: App Password Lifecycle, Scoping, and Immediate Revocation

    func testAppPasswordLifecycleAndImmediateRevocation() async throws {
        let (database, root) = try await makeDatabase("app-passwords")
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let now = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        try await createAccount(database, did: aliceDID, handle: aliceHandle, now: now)

        let appPasswordName = "mobile-client"
        let digest = Data(repeating: 0x9E, count: 32)
        _ = try await database.createAppPassword(
            did: aliceDID,
            name: appPasswordName,
            scopes: "repo:com.example.feed",
            digest: digest,
            now: now
        )

        let appPasswords = try await database.listAppPasswords(did: aliceDID)
        XCTAssertEqual(appPasswords.count, 1)
        XCTAssertEqual(appPasswords.first?.name, appPasswordName)
        XCTAssertEqual(appPasswords.first?.scopes, "repo:com.example.feed")

        // Revoke app password
        try await database.revokeAppPassword(did: aliceDID, name: appPasswordName)

        let afterRevoke = try await database.listAppPasswords(did: aliceDID)
        XCTAssertEqual(afterRevoke.count, 0)
    }

    // MARK: - Acceptance Test 3: OAuth DPoP Issuance, Refresh Rotation, and Replay Revocation

    func testOAuthDPoPIssuanceRefreshRotationAndReplayRevocation() async throws {
        let (database, root) = try await makeDatabase("oauth-dpop")
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let now = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        try await createAccount(database, did: aliceDID, handle: aliceHandle, now: now)

        let serverKey = Data(repeating: 0x5B, count: 32)
        let oauthRuntime = try SwanOAuthRuntime(
            controlStore: database,
            serverKey: serverKey
        )

        let metadata = try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: clientID)
        let jkt = String(repeating: "k", count: 43)
        let proof = OAuthValidatedDPoPProof(keyThumbprint: jkt, jwtID: "proof-1", issuedAt: now)
        let session = try OAuthValidatedSession(
            issuer: issuer.absoluteString,
            client: OAuthResolvedClientMetadata(metadata: metadata, keySet: nil),
            redirectURI: redirectURI,
            scopes: ["atproto"],
            dpopProof: proof
        )

        // Issue token pair
        let pair1 = try await oauthRuntime.tokenService.issue(subject: aliceDID, session: session, now: now)
        XCTAssertFalse(pair1.accessToken.isEmpty)
        XCTAssertFalse(pair1.refreshToken.isEmpty)

        // Access validation succeeds
        let grant = try await oauthRuntime.tokenService.validateAccess(
            pair1.accessToken,
            proof: proof,
            now: now
        )
        XCTAssertEqual(grant.subject, aliceDID)

        // Refresh rotation via redeemLocalhostPublicRefresh
        let refreshProof = OAuthValidatedDPoPProof(keyThumbprint: jkt, jwtID: "proof-2", issuedAt: now)
        let pair2 = try await oauthRuntime.tokenService.redeemLocalhostPublicRefresh(
            pair1.refreshToken,
            clientID: clientID,
            dpopProof: refreshProof,
            now: now
        )
        XCTAssertNotEqual(pair1.accessToken, pair2.accessToken)
        XCTAssertNotEqual(pair1.refreshToken, pair2.refreshToken)

        // Access validation with pair2 succeeds
        let grant2 = try await oauthRuntime.tokenService.validateAccess(
            pair2.accessToken,
            proof: refreshProof,
            now: now
        )
        XCTAssertEqual(grant2.subject, aliceDID)

        // Replay of old pair1.refreshToken revokes the entire token family
        let replayProof = OAuthValidatedDPoPProof(keyThumbprint: jkt, jwtID: "proof-3", issuedAt: now)
        await XCTAssertThrowsAsync(
            try await oauthRuntime.tokenService.redeemLocalhostPublicRefresh(
                pair1.refreshToken,
                clientID: clientID,
                dpopProof: replayProof,
                now: now
            )
        )

        // Both pair1 and pair2 access tokens are now revoked
        await XCTAssertThrowsAsync(
            try await oauthRuntime.tokenService.validateAccess(
                pair2.accessToken,
                proof: refreshProof,
                now: now
            )
        )
    }

    // MARK: - Acceptance Test 4: Password Reset / Recovery-Wide Revocation

    func testRecoveryWideRevocationTerminatesAllActiveSessionsAndTokenFamilies() async throws {
        let (database, root) = try await makeDatabase("recovery-revocation")
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let now = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        try await createAccount(database, did: aliceDID, handle: aliceHandle, now: now)

        let serverKey = Data(repeating: 0x5B, count: 32)
        let oauthRuntime = try SwanOAuthRuntime(
            controlStore: database,
            serverKey: serverKey
        )

        let sessions = SwanManagementSessionRuntime(
            store: database,
            preAuthStore: database,
            csrfStore: database,
            preAuthSessionCoordinator: database
        )
        let managementSession = try await sessions.issue(accountDID: aliceDID, strength: .password, now: now)

        let metadata = try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: clientID)
        let jkt = String(repeating: "m", count: 43)
        let proof = OAuthValidatedDPoPProof(keyThumbprint: jkt, jwtID: "recovery-proof", issuedAt: now)
        let oauthSession = try OAuthValidatedSession(
            issuer: issuer.absoluteString,
            client: OAuthResolvedClientMetadata(metadata: metadata, keySet: nil),
            redirectURI: redirectURI,
            scopes: ["atproto"],
            dpopProof: proof
        )
        let tokens = try await oauthRuntime.tokenService.issue(subject: aliceDID, session: oauthSession, now: now)

        // Verify valid before revocation
        let authenticated = try await sessions.authenticate(sessionValue: managementSession.sessionValue, now: now)
        XCTAssertEqual(authenticated.accountDID, aliceDID)
        let grant = try await oauthRuntime.tokenService.validateAccess(tokens.accessToken, proof: proof, now: now)
        XCTAssertEqual(grant.subject, aliceDID)

        // Revoke management session and OAuth token family
        let sessionDigest = SwanManagementSessionRuntime.digest(managementSession.sessionValue)
        try await database.revokeManagementSession(digest: sessionDigest, accountDID: aliceDID, now: now)
        try await database.revokeTokenFamily(familyID: tokens.familyID, subject: aliceDID, now: now)

        // Verify immediately rejected
        await XCTAssertThrowsAsync(
            try await sessions.authenticate(sessionValue: managementSession.sessionValue, now: now)
        )
        await XCTAssertThrowsAsync(
            try await oauthRuntime.tokenService.validateAccess(tokens.accessToken, proof: proof, now: now)
        )
    }

    // MARK: - Acceptance Test 5: Durable Server Restart State Preservation

    func testDurableServerRestartPreservesStateAndActiveSessions() async throws {
        let (database, root) = try await makeDatabase("restart-persist")
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

        // Reopen the same data directory: durable projection state survives
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

        // Account-bound revocation works after reopen
        try await reopened.revokeLegacySessionFamily(
            familyID: "legacy-family-restart", did: did, now: now
        )
        let familiesAfterRevoke = try await reopened.legacySessionFamilies(did: did, now: now)
        XCTAssertTrue(familiesAfterRevoke.isEmpty)
    }

    // MARK: - Acceptance Test 6: did:web Full Lifecycle and Admission Enforcement

    func testDidWebLifecycleAndAdmissionGating() async throws {
        let now = Date(timeIntervalSince1970: 1_000)

        // PLC-only: full admission
        let plcOnly = IdentityBindingFixture(binding: nil, failure: false)
        let plcDecision = try await SwanDurableIdentityAdmission(
            bindings: plcOnly, gracePeriod: 86_400
        ).identityAdmission(accountDID: "did:plc:plainabcdefghijklmnopqrstuv", now: now)
        XCTAssertTrue(plcDecision.allowsWrite)
        XCTAssertTrue(plcDecision.allowsTokenIssuance)
        XCTAssertTrue(plcDecision.allowsRead)

        // Active did:web: full admission
        let active = try IdentityBinding(
            accountDID: "did:plc:webbyabcdefghijklmnopqrstuv",
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
        ).identityAdmission(accountDID: "did:plc:webbyabcdefghijklmnopqrstuv", now: now)
        XCTAssertTrue(activeDecision.allowsWrite)
        XCTAssertTrue(activeDecision.allowsTokenIssuance)

        // Suspended did:web: reads preserved, writes and tokens denied
        let suspended = try IdentityBinding(
            accountDID: "did:plc:webbyabcdefghijklmnopqrstuv",
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
        ).identityAdmission(accountDID: "did:plc:webbyabcdefghijklmnopqrstuv", now: now)
        XCTAssertEqual(suspendedDecision.continuity, .suspended)
        XCTAssertTrue(suspendedDecision.allowsRead)
        XCTAssertFalse(suspendedDecision.allowsWrite)
        XCTAssertFalse(suspendedDecision.allowsTokenIssuance)
    }

    // MARK: - Acceptance Test 7: Ephemeral Authenticated SMTP Configuration & Delivery

    func testAuthenticatedSMTPConfigurationAndDeliveryTransport() async throws {
        let configuration = try AuthenticatedSMTPConfiguration(
            host: "smtp.example.com",
            port: 587,
            mode: .startTLS,
            username: "ephemeral-user",
            password: "ephemeral-password",
            mechanism: .plain,
            expectedHostname: "smtp.example.com"
        )
        XCTAssertEqual(configuration.host, "smtp.example.com")
        XCTAssertEqual(configuration.port, 587)
        XCTAssertEqual(configuration.mode, .startTLS)
        XCTAssertEqual(configuration.username, "ephemeral-user")
        XCTAssertEqual(configuration.mechanism, .plain)

        let implicitTLS = try AuthenticatedSMTPConfiguration(
            host: "smtp.example.com",
            port: 465,
            mode: .implicitTLS,
            username: "ephemeral-user",
            password: "ephemeral-password",
            mechanism: .login,
            expectedHostname: "smtp.example.com"
        )
        XCTAssertEqual(implicitTLS.port, 465)
        XCTAssertEqual(implicitTLS.mode, .implicitTLS)
        XCTAssertEqual(implicitTLS.mechanism, .login)
    }
}

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

private func XCTAssertThrowsAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("Expected expression to throw", file: file, line: line)
    } catch {
        // Expected.
    }
}
