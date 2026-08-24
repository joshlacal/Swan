import Crypto
import Foundation
import PetrelCrypto
import SwanAccounts
import SwanCore
@testable import SwanSQLite
import SwanStorage
import XCTest

final class Task7MFATests: XCTestCase {
    func testSQLiteFactorStoreRoundTripsAndConsumesAtomically() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("swan-task7-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }
        try await database.connection.query("INSERT INTO accounts(did, handle, status, created_at) VALUES ('did:plc:alice', 'alice.example', 'active', 1)")
        let factor = try AuthenticationFactorMetadata(id: "factor", accountDID: "did:plc:alice", kind: .totp, label: "Authenticator", lookupDigest: Data(repeating: 1, count: 32), createdAt: Date(timeIntervalSince1970: 1))
        try await database.saveFactor(factor, now: Date(timeIntervalSince1970: 1))
        let factors = try await database.listFactors(accountDID: "did:plc:alice", now: Date(timeIntervalSince1970: 1))
        XCTAssertEqual(factors, [factor])
        let recoveryFactor = try AuthenticationFactorMetadata(id: "recovery", accountDID: "did:plc:alice", kind: .recoveryCode, label: "Recovery", lookupDigest: Data(repeating: 4, count: 32), createdAt: Date(timeIntervalSince1970: 1))
        try await database.saveFactor(recoveryFactor, now: Date(timeIntervalSince1970: 1))
        let code = try RecoveryCodeDigest(accountDID: "did:plc:alice", digest: Data(repeating: 2, count: 32), issuedAt: Date(timeIntervalSince1970: 1))
        try await database.replaceRecoveryCodeDigests(accountDID: "did:plc:alice", digests: [code], now: Date(timeIntervalSince1970: 1))
        _ = try await database.consumeRecoveryCode(digest: code.digest, accountDID: "did:plc:alice", now: Date(timeIntervalSince1970: 2))
        do { _ = try await database.consumeRecoveryCode(digest: code.digest, accountDID: "did:plc:alice", now: Date(timeIntervalSince1970: 3)); XCTFail("recovery code replay") } catch {}
        let firstReplayCAS = try await database.compareAndSwapTOTPReplay(factorID: "factor", accountDID: "did:plc:alice", expected: nil, proposed: 4, now: Date(timeIntervalSince1970: 4))
        let replayCAS = try await database.compareAndSwapTOTPReplay(factorID: "factor", accountDID: "did:plc:alice", expected: nil, proposed: 4, now: Date(timeIntervalSince1970: 4))
        XCTAssertTrue(firstReplayCAS); XCTAssertFalse(replayCAS)
        let token = try DurableFactorTokenRecord(digest: Data(repeating: 3, count: 32), accountDID: "did:plc:alice", sessionID: "session", purpose: "stepUp", factor: .totp, factorID: "factor", strength: .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: Date(timeIntervalSince1970: 4)), issuedAt: Date(timeIntervalSince1970: 4), expiresAt: Date(timeIntervalSince1970: 30))
        try await database.saveFactorToken(token, now: Date(timeIntervalSince1970: 4))
        do {
            _ = try await database.consumeFactorToken(digest: token.digest, accountDID: token.accountDID, sessionID: token.sessionID, purpose: token.purpose, factor: token.factor, factorID: token.factorID, strength: .stepUpMFA(base: .passwordPlusPasskey, verifiedAt: Date(timeIntervalSince1970: 4)), now: Date(timeIntervalSince1970: 5))
            XCTFail("mismatched authentication strength must not consume the token")
        } catch { }
        let consumedToken = try await database.consumeFactorToken(digest: token.digest, accountDID: token.accountDID, sessionID: token.sessionID, purpose: token.purpose, factor: token.factor, factorID: token.factorID, strength: token.strength, now: Date(timeIntervalSince1970: 5))
        XCTAssertEqual(consumedToken, token)
        do { _ = try await database.consumeFactorToken(digest: token.digest, accountDID: token.accountDID, sessionID: token.sessionID, purpose: token.purpose, factor: token.factor, factorID: token.factorID, strength: token.strength, now: Date(timeIntervalSince1970: 5)); XCTFail("factor token replay") } catch {}

        // Login validation consumes only the opaque digest and account DID;
        // caller-supplied factor/session/purpose metadata cannot launder a
        // step-up token into a login token. A correctly issued management
        // login token is accepted once, then rejected on replay.
        let loginService = FactorTokenService(store: database)
        let loginToken = try await loginService.issue(
            accountDID: "did:plc:alice",
            sessionID: "portal-session",
            purpose: .managementLogin,
            factor: .totp,
            factorID: "factor",
            strength: .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: Date(timeIntervalSince1970: 5)),
            now: Date(timeIntervalSince1970: 5)
        )
        let loginStrength = try await loginService.verifyLoginFactorToken(
            token: loginToken.token,
            accountDID: "did:plc:alice",
            now: Date(timeIntervalSince1970: 6)
        )
        XCTAssertEqual(loginStrength, .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: Date(timeIntervalSince1970: 5)))
        do {
            _ = try await loginService.verifyLoginFactorToken(
                token: loginToken.token,
                accountDID: "did:plc:alice",
                now: Date(timeIntervalSince1970: 6)
            )
            XCTFail("login factor token replay")
        } catch {}

        let sessionBoundToken = try await loginService.issue(
            accountDID: "did:plc:alice",
            sessionID: "portal-session-a",
            purpose: .managementLogin,
            factor: .totp,
            factorID: "factor",
            strength: .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: Date(timeIntervalSince1970: 6)),
            now: Date(timeIntervalSince1970: 6)
        )
        do {
            _ = try await loginService.verifyLoginFactorToken(
                token: sessionBoundToken.token,
                accountDID: "did:plc:alice",
                sessionID: "portal-session-b",
                now: Date(timeIntervalSince1970: 7)
            )
            XCTFail("management login token must be bound to its pre-auth session")
        } catch {}
        let sessionBoundStrength = try await loginService.verifyLoginFactorToken(
            token: sessionBoundToken.token,
            accountDID: "did:plc:alice",
            sessionID: "portal-session-a",
            now: Date(timeIntervalSince1970: 7)
        )
        XCTAssertEqual(sessionBoundStrength, .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: Date(timeIntervalSince1970: 6)))

        // Recovery is a login factor only for a recovery-only account. The
        // authorization decision is committed with receipt consumption, so a
        // mixed TOTP/recovery account cannot downgrade to email recovery.
        let mixedRecovery = try await loginService.issue(
            accountDID: "did:plc:alice", sessionID: "recovery-session", purpose: .loginRecovery,
            factor: .recoveryCode, factorID: "recovery", strength: .emailRecovery,
            now: Date(timeIntervalSince1970: 8))
        do {
            _ = try await loginService.verifyLoginFactorToken(
                token: mixedRecovery.token, accountDID: "did:plc:alice", sessionID: "recovery-session",
                now: Date(timeIntervalSince1970: 9))
            XCTFail("mixed-factor account must not accept recovery login")
        } catch {}
        try await database.disableFactor(id: "factor", accountDID: "did:plc:alice", now: Date(timeIntervalSince1970: 10))
        let recoveryOnly = try await loginService.issue(
            accountDID: "did:plc:alice", sessionID: "recovery-session-2", purpose: .loginRecovery,
            factor: .recoveryCode, factorID: "recovery", strength: .emailRecovery,
            now: Date(timeIntervalSince1970: 11))
        let recoveryStrength = try await loginService.verifyLoginFactorToken(
            token: recoveryOnly.token, accountDID: "did:plc:alice", sessionID: "recovery-session-2",
            now: Date(timeIntervalSince1970: 12))
        XCTAssertEqual(recoveryStrength, .emailRecovery)
        do {
            _ = try await loginService.verifyLoginFactorToken(
                token: recoveryOnly.token, accountDID: "did:plc:alice", sessionID: "recovery-session-2",
                now: Date(timeIntervalSince1970: 12))
            XCTFail("recovery login receipt must be single use")
        } catch {}
        try await database.appendMFAAuditEvent(try MFAAuditEventRecord(event: "totpAccepted", accountDID: "did:plc:alice", factorID: "factor", success: true, occurredAt: Date(timeIntervalSince1970: 5)), now: Date(timeIntervalSince1970: 5))
    }

    func testRFC6238SHA1Vectors() throws {
        let secret = Data("12345678901234567890".utf8)
        XCTAssertEqual(try TOTPAuthenticator.code(secret: secret, counter: 1), "287082")
        XCTAssertEqual(try TOTPAuthenticator.code(secret: secret, counter: 20), "328281")
        XCTAssertEqual(try TOTPAuthenticator.code(secret: secret, counter: 59 / 30), "287082")
    }

    func testOAuthRecoveryGrantIsChannelAndRequestBound() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("swan-oauth-recovery-(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }
        try await database.connection.query("INSERT INTO accounts(did, handle, status, created_at) VALUES ('did:plc:recovery', 'recovery.example', 'active', 1)")
        let factor = try AuthenticationFactorMetadata(
            id: "recovery-factor", accountDID: "did:plc:recovery", kind: .recoveryCode,
            label: "Recovery", lookupDigest: Data(repeating: 7, count: 32),
            createdAt: Date(timeIntervalSince1970: 1)
        )
        try await database.saveFactor(factor, now: Date(timeIntervalSince1970: 1))
        let service = FactorTokenService(store: database)
        let csrf = Data(repeating: 8, count: 32)
        let request = Data(repeating: 9, count: 32)
        let context = try AccountAuthorizationContext(
            channel: .oauth, sessionID: "oauth-browser", csrfDigest: csrf,
            clientID: "client.example", requestDigest: request, purpose: "oauthToken"
        )
        let token = try await service.issue(
            accountDID: "did:plc:recovery", sessionID: context.sessionID,
            purpose: .oauthToken, factor: .recoveryCode, factorID: factor.id,
            strength: .emailRecovery, now: Date(timeIntervalSince1970: 2),
            channel: .oauth, bindingDigest: csrf, clientID: context.clientID,
            requestDigest: request
        )
        let wrongContext = try AccountAuthorizationContext(
            channel: .oauth, sessionID: context.sessionID, csrfDigest: Data(repeating: 1, count: 32),
            clientID: context.clientID, requestDigest: request, purpose: "oauthToken"
        )
        do {
            _ = try await service.authorizeLoginWithFactorToken(
                token: token.token, accountDID: "did:plc:recovery", context: wrongContext,
                now: Date(timeIntervalSince1970: 3)
            )
            XCTFail("OAuth recovery receipt must not cross CSRF binding")
        } catch {}
        let wrongClient = try AccountAuthorizationContext(
            channel: .oauth, sessionID: context.sessionID, csrfDigest: context.csrfDigest!,
            clientID: "other-client.example", requestDigest: request, purpose: "oauthToken"
        )
        do {
            _ = try await service.authorizeLoginWithFactorToken(
                token: token.token, accountDID: "did:plc:recovery", context: wrongClient,
                now: Date(timeIntervalSince1970: 3)
            )
            XCTFail("OAuth recovery receipt must not cross client binding")
        } catch {}
        let wrongRequest = try AccountAuthorizationContext(
            channel: .oauth, sessionID: context.sessionID, csrfDigest: context.csrfDigest!,
            clientID: context.clientID, requestDigest: Data(repeating: 2, count: 32), purpose: "oauthToken"
        )
        do {
            _ = try await service.authorizeLoginWithFactorToken(
                token: token.token, accountDID: "did:plc:recovery", context: wrongRequest,
                now: Date(timeIntervalSince1970: 3)
            )
            XCTFail("OAuth recovery receipt must not cross request binding")
        } catch {}
        let wrongChannel = try AccountAuthorizationContext(
            channel: .portal, sessionID: context.sessionID, csrfDigest: context.csrfDigest,
            clientID: nil, requestDigest: nil, purpose: "managementLogin"
        )
        do {
            _ = try await service.authorizeLoginWithFactorToken(
                token: token.token, accountDID: "did:plc:recovery", context: wrongChannel,
                now: Date(timeIntervalSince1970: 3)
            )
            XCTFail("OAuth recovery receipt must not cross authorization channel")
        } catch {}
        let grant = try await service.authorizeLoginWithFactorToken(
            token: token.token, accountDID: "did:plc:recovery", context: context,
            now: Date(timeIntervalSince1970: 3)
        )
        XCTAssertEqual(grant.context, context)
        XCTAssertEqual(grant.strength, .emailRecovery)
        do {
            _ = try await service.authorizeLoginWithFactorToken(
                token: token.token, accountDID: "did:plc:recovery", context: context,
                now: Date(timeIntervalSince1970: 3)
            )
            XCTFail("OAuth recovery receipt must be one-time")
        } catch {}
        // The same opaque receipt is never consumable through a no-session
        // account/legacy path, even when its account and factor match.
        do {
            _ = try await database.consumeFactorTokenForLogin(
                digest: Data(SHA256.hash(data: Data(token.token.utf8))),
                accountDID: "did:plc:recovery", now: Date(timeIntervalSince1970: 3)
            )
            XCTFail("OAuth receipt must not enter the account-only SQL path")
        } catch {}
    }

    func testAuthorizationGrantRevisionAndRecoveryPersistAcrossReopen() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("swan-grant-revision-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        try await database.connection.query("INSERT INTO accounts(did, handle, status, created_at) VALUES ('did:plc:grant', 'grant.example', 'active', 1)")
        let factor = try AuthenticationFactorMetadata(
            id: "totp-factor", accountDID: "did:plc:grant", kind: .totp,
            label: "Authenticator", lookupDigest: Data(repeating: 3, count: 32),
            createdAt: Date(timeIntervalSince1970: 1)
        )
        try await database.saveFactor(factor, now: Date(timeIntervalSince1970: 1))
        let context = try AccountAuthorizationContext(
            channel: .oauth, sessionID: "grant-session", csrfDigest: Data(repeating: 4, count: 32),
            clientID: "client.example", requestDigest: Data(repeating: 5, count: 32), purpose: "oauthToken"
        )
        let service = FactorTokenService(store: database)
        let token = try await service.issue(
            accountDID: "did:plc:grant", sessionID: context.sessionID, purpose: .oauthToken,
            factor: .totp, factorID: factor.id,
            strength: .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: Date(timeIntervalSince1970: 2)),
            now: Date(timeIntervalSince1970: 2), channel: .oauth,
            bindingDigest: context.csrfDigest, clientID: context.clientID, requestDigest: context.requestDigest
        )
        let grant = try await service.authorizeLoginWithFactorToken(
            token: token.token, accountDID: "did:plc:grant", context: context,
            now: Date(timeIntervalSince1970: 3)
        )
        XCTAssertEqual(grant.factorRevision, 1)
        try await database.disableFactor(id: factor.id, accountDID: "did:plc:grant", now: Date(timeIntervalSince1970: 4))
        do {
            _ = try await database.consumeAuthorizationGrant(
                grantDigest: grant.grantDigest, accountDID: grant.accountDID,
                context: context, now: Date(timeIntervalSince1970: 5)
            )
            XCTFail("factor revision change must invalidate an unconsumed grant")
        } catch {}

        // Recovery consumption is durable and remains one-time after a
        // close/reopen boundary, rather than living in an in-memory receipt.
        let recoveryFactor = try AuthenticationFactorMetadata(
            id: "recovery-factor", accountDID: "did:plc:grant", kind: .recoveryCode,
            label: "Recovery", lookupDigest: Data(repeating: 6, count: 32),
            createdAt: Date(timeIntervalSince1970: 6)
        )
        try await database.saveFactor(recoveryFactor, now: Date(timeIntervalSince1970: 6))
        let recovery = "RECOVERY-REOPEN-ONLY"
        try await database.replaceRecoveryCodeDigests(
            accountDID: "did:plc:grant",
            digests: [try RecoveryCodeDigest(
                accountDID: "did:plc:grant", digest: RecoveryCodeService.digest(recovery),
                issuedAt: Date(timeIntervalSince1970: 6))],
            now: Date(timeIntervalSince1970: 6)
        )
        try await database.close()
        do {
            let reopened = try await SQLiteControlDatabase(dataDirectory: root)
            let recoveryService = RecoveryCodeService(store: reopened, factorStore: reopened)
            let firstRecovery = try await recoveryService.consume(
                recovery, accountDID: "did:plc:grant", now: Date(timeIntervalSince1970: 7))
            XCTAssertTrue(firstRecovery)
            try await reopened.close()
        }
        do {
            let reopened = try await SQLiteControlDatabase(dataDirectory: root)
            let recoveryService = RecoveryCodeService(store: reopened, factorStore: reopened)
            let replayedRecovery = try await recoveryService.consume(
                recovery, accountDID: "did:plc:grant", now: Date(timeIntervalSince1970: 8))
            XCTAssertFalse(replayedRecovery)
            try await reopened.close()
        }
    }

    func testAuthorizationGrantRaceWithFactorRevisionHasOneSafeOutcome() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("swan-grant-race-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        try await database.connection.query("INSERT INTO accounts(did, handle, status, created_at) VALUES ('did:plc:grant-race', 'grant-race.example', 'active', 1)")
        let factor = try AuthenticationFactorMetadata(
            id: "grant-race-factor", accountDID: "did:plc:grant-race", kind: .totp,
            label: "Authenticator", lookupDigest: Data(repeating: 0x31, count: 32),
            createdAt: Date(timeIntervalSince1970: 1)
        )
        try await database.saveFactor(factor, now: Date(timeIntervalSince1970: 1))
        let context = try AccountAuthorizationContext(
            channel: .oauth, sessionID: "grant-race-session", csrfDigest: Data(repeating: 0x32, count: 32),
            clientID: "grant-race-client", requestDigest: Data(repeating: 0x33, count: 32), purpose: "oauthToken"
        )
        let service = FactorTokenService(store: database)
        let token = try await service.issue(
            accountDID: factor.accountDID, sessionID: context.sessionID, purpose: .oauthToken,
            factor: .totp, factorID: factor.id,
            strength: .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: Date(timeIntervalSince1970: 2)),
            now: Date(timeIntervalSince1970: 2), channel: .oauth,
            bindingDigest: context.csrfDigest, clientID: context.clientID, requestDigest: context.requestDigest
        )

        // No timing sleeps are needed: both operations are durable actor/SQL
        // operations. Whichever operation linearizes first, the factor
        // revision change must prevent a grant from being consumed afterward.
        let racedGrantDigest = await withTaskGroup(of: Data?.self, returning: Data?.self) { group in
            group.addTask {
                guard let grant = try? await service.authorizeLoginWithFactorToken(
                    token: token.token, accountDID: factor.accountDID, context: context,
                    now: Date(timeIntervalSince1970: 3)
                ) else { return nil }
                return grant.grantDigest
            }
            group.addTask {
                try? await database.disableFactor(
                    id: factor.id, accountDID: factor.accountDID,
                    now: Date(timeIntervalSince1970: 4)
                )
                return nil
            }
            var digest: Data?
            for await result in group where result != nil {
                digest = result
            }
            return digest
        }
        if let racedGrantDigest {
            do {
                _ = try await database.consumeAuthorizationGrant(
                    grantDigest: racedGrantDigest, accountDID: factor.accountDID,
                    context: context, now: Date(timeIntervalSince1970: 5)
                )
                XCTFail("factor revision change must invalidate a raced grant")
            } catch {}
        }
        try await database.close()
    }

    func testTOTPUsesOneStepDriftAndRejectsReplay() async throws {
        let replay = TOTPReplayGuard(store: InMemoryTOTPReplayStore())
        let secret = Data("12345678901234567890".utf8)
        let now = Date(timeIntervalSince1970: 60)
        let adjacent = try TOTPAuthenticator.code(secret: secret, counter: 1)
        let first = try await replay.accept(factorID: "factor", accountDID: "did:plc:alice", code: adjacent, secret: secret, at: now)
        let second = try await replay.accept(factorID: "factor", accountDID: "did:plc:alice", code: adjacent, secret: secret, at: now)
        let other = try await replay.accept(factorID: "other", accountDID: "did:plc:alice", code: adjacent, secret: secret, at: Date(timeIntervalSince1970: 120))
        XCTAssertTrue(first); XCTAssertFalse(second); XCTAssertFalse(other)
    }

    func testTOTPEnvelopeAndConcurrentReplayAreBounded() async throws {
        let key = Data(repeating: 7, count: 32)
        let envelope = try TOTPEnvelopeCrypto.seal(secret: Data("12345678901234567890".utf8), factorID: "factor", keyReference: "kms:1", key: key)
        let factor = try AuthenticationFactorMetadata(id: "factor", accountDID: "did:plc:alice", kind: .totp, label: "TOTP", lookupDigest: Data(repeating: 1, count: 32), createdAt: Date(timeIntervalSince1970: 1))
        let service = TOTPFactorService(keyStore: InMemoryTOTPKeyStore(reference: "kms:1", key: key), replayGuard: TOTPReplayGuard(store: InMemoryTOTPReplayStore()), factorStore: InMemoryFactorStore(factors: [factor]))
        let code = try TOTPAuthenticator.code(secret: Data("12345678901234567890".utf8), counter: 1)
        let results = await withTaskGroup(of: Bool.self, returning: [Bool].self) { group in
            for _ in 0 ..< 8 { group.addTask { (try? await service.verify(envelope: envelope, accountDID: "did:plc:alice", factorID: "factor", code: code, at: Date(timeIntervalSince1970: 30))) == true } }
            var values: [Bool] = []
            for await value in group { values.append(value) }
            return values
        }
        XCTAssertEqual(results.filter { $0 }.count, 1)
    }

    func testRecoveryCodesAreHighEntropyAndSingleUse() async throws {
        let store = InMemoryRecoveryCodeStore()
        let factor = try AuthenticationFactorMetadata(id: "recovery", accountDID: "did:plc:alice", kind: .recoveryCode, label: "Recovery", lookupDigest: Data(repeating: 9, count: 32), createdAt: Date(timeIntervalSince1970: 1))
        let service = RecoveryCodeService(store: store, factorStore: InMemoryFactorStore(factors: [factor]))
        let codes = try await service.replace(accountDID: "did:plc:alice", now: Date(timeIntervalSince1970: 1))
        XCTAssertEqual(codes.count, RecoveryCodeService.defaultCount)
        XCTAssertTrue(codes.allSatisfy { $0.count >= 20 })
        let consumed = try await service.consume(codes[0], accountDID: "did:plc:alice", now: Date(timeIntervalSince1970: 2))
        let replayed = try await service.consume(codes[0], accountDID: "did:plc:alice", now: Date(timeIntervalSince1970: 3))
        XCTAssertTrue(consumed); XCTAssertFalse(replayed)
    }

    func testRecoveryCodeConcurrentConsumeHasOneWinner() async throws {
        let store = InMemoryRecoveryCodeStore()
        let factor = try AuthenticationFactorMetadata(id: "recovery", accountDID: "did:plc:alice", kind: .recoveryCode, label: "Recovery", lookupDigest: Data(repeating: 9, count: 32), createdAt: Date(timeIntervalSince1970: 1))
        let service = RecoveryCodeService(store: store, factorStore: InMemoryFactorStore(factors: [factor]))
        let code = try await service.replace(accountDID: "did:plc:alice", count: 1, now: Date(timeIntervalSince1970: 1))[0]
        let results = await withTaskGroup(of: Bool.self, returning: [Bool].self) { group in
            for _ in 0 ..< 8 { group.addTask { (try? await service.consume(code, accountDID: "did:plc:alice", now: Date(timeIntervalSince1970: 2))) == true } }
            var values: [Bool] = []
            for await value in group { values.append(value) }
            return values
        }
        XCTAssertEqual(results.filter { $0 }.count, 1)
    }

    func testFactorTokensAreShortLivedSinglePurposeAndBoundToAccount() async throws {
        let service = FactorTokenService(store: InMemoryFactorTokenStore())
        let issued = try await service.issue(accountDID: "did:plc:alice", sessionID: "session-a", purpose: .stepUp, factor: .totp, factorID: "factor", strength: .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: Date(timeIntervalSince1970: 10)), now: Date(timeIntervalSince1970: 10))
        let strength: AuthenticationStrength = .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: Date(timeIntervalSince1970: 10))
        let consumed = try? await service.consume(issued.token, accountDID: "did:plc:alice", sessionID: "session-a", purpose: .stepUp, factor: .totp, factorID: "factor", strength: strength, now: Date(timeIntervalSince1970: 11))
        let replayed = try? await service.consume(issued.token, accountDID: "did:plc:alice", sessionID: "session-a", purpose: .stepUp, factor: .totp, factorID: "factor", strength: strength, now: Date(timeIntervalSince1970: 11))
        XCTAssertNotNil(consumed); XCTAssertNil(replayed)
        let other = try await service.issue(accountDID: "did:plc:alice", sessionID: "session-a", purpose: .stepUp, factor: .passkey, factorID: "passkey", strength: .stepUpMFA(base: .passwordPlusPasskey, verifiedAt: Date(timeIntervalSince1970: 10)), now: Date(timeIntervalSince1970: 10))
        let wrongAccount = try? await service.consume(other.token, accountDID: "did:plc:bob", sessionID: "session-a", purpose: .stepUp, factor: .passkey, factorID: "passkey", strength: .stepUpMFA(base: .passwordPlusPasskey, verifiedAt: Date(timeIntervalSince1970: 10)), now: Date(timeIntervalSince1970: 11))
        XCTAssertNil(wrongAccount)
    }

    func testStepUpTokenConsumptionIsSessionBoundAndSingleUse() async throws {
        let service = FactorTokenService(store: InMemoryFactorTokenStore())
        let verifiedAt = Date(timeIntervalSince1970: 10)
        let issued = try await service.issue(
            accountDID: "did:plc:alice",
            sessionID: "session-a",
            purpose: .stepUp,
            factor: .totp,
            factorID: "factor",
            strength: .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: verifiedAt),
            now: verifiedAt
        )
        let consumed = try await service.consumeStepUpToken(
            token: issued.token,
            accountDID: "did:plc:alice",
            sessionID: "session-a",
            now: verifiedAt.addingTimeInterval(1)
        )
        XCTAssertEqual(consumed.strength, .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: verifiedAt))
        do {
            _ = try await service.consumeStepUpToken(
                token: issued.token,
                accountDID: "did:plc:alice",
                sessionID: "session-a",
                now: verifiedAt.addingTimeInterval(1)
            )
            XCTFail("step-up token replay must fail")
        } catch {}
    }

    func testManagementSessionStepUpDurablyUpgradesStrengthOnce() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("swan-task7-step-up-(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }
        let did = "did:plc:alice"
        try await database.connection.query(
            "INSERT INTO accounts(did, handle, status, created_at) VALUES (?, ?, 'active', 1)",
            [.text(did), .text("alice.example")]
        )
        let factor = try AuthenticationFactorMetadata(
            id: "factor",
            accountDID: did,
            kind: .totp,
            label: "Authenticator",
            lookupDigest: Data(repeating: 1, count: 32),
            createdAt: Date(timeIntervalSince1970: 1)
        )
        try await database.saveFactor(factor, now: Date(timeIntervalSince1970: 1))
        let sessions = SwanManagementSessionRuntime(
            store: database,
            preAuthStore: SwanInMemoryManagementPreAuthStore(),
            csrfStore: SwanInMemoryManagementCSRFStore()
        )
        let issuedSession = try await sessions.issue(accountDID: did, now: Date(timeIntervalSince1970: 10))
        let factors = FactorTokenService(store: database)
        let verifiedAt = Date(timeIntervalSince1970: 11)
        let token = try await factors.issue(
            accountDID: did,
            sessionID: issuedSession.metadata.sessionID.rawValue,
            purpose: .stepUp,
            factor: .totp,
            factorID: factor.id,
            strength: .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: verifiedAt),
            now: verifiedAt
        )
        let upgraded = try await sessions.upgradeFromStepUp(
            sessionValue: issuedSession.sessionValue,
            token: token.token,
            factorTokens: factors,
            now: Date(timeIntervalSince1970: 12)
        )
        XCTAssertEqual(upgraded.strength, .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: verifiedAt))
        XCTAssertEqual(upgraded.lastStepUpAt, verifiedAt)
        do {
            _ = try await sessions.upgradeFromStepUp(
                sessionValue: issuedSession.sessionValue,
                token: token.token,
                factorTokens: factors,
                now: Date(timeIntervalSince1970: 12)
            )
            XCTFail("step-up receipt replay must fail")
        } catch {}
    }

    func testStepUpPolicyRequiresPasswordAndConfiguredMFAForSensitiveOperations() throws {
        let policy = StepUpPolicy()
        XCTAssertThrowsError(try policy.authorize(.deleteAccount, strength: .stepUpPassword(verifiedAt: Date(timeIntervalSince1970: 10)), mfaEnabled: true, now: Date(timeIntervalSince1970: 11)))
        XCTAssertNoThrow(try policy.authorize(.deleteAccount, strength: .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: Date(timeIntervalSince1970: 10)), mfaEnabled: true, now: Date(timeIntervalSince1970: 11)))
        XCTAssertThrowsError(try policy.authorize(.deleteAccount, strength: .emailRecovery, mfaEnabled: false, now: Date(timeIntervalSince1970: 11)))
        XCTAssertThrowsError(try policy.authorize(.deleteAccount, strength: .stepUpPassword(verifiedAt: Date(timeIntervalSince1970: 0)), mfaEnabled: false, now: Date(timeIntervalSince1970: 601)))
    }

    func testWebAuthnRejectsWrongOriginRPChallengeTypeUVSignatureAndAccount() async throws {
        let key = P256.Signing.PrivateKey()
        let credentialID = Data("credential".utf8)
        let challenge = Data("challenge".utf8)
        let clientData = try JSONSerialization.data(withJSONObject: [
            "type": "webauthn.get",
            "challenge": testBase64URL(challenge),
            "origin": "https://example.com"
        ])
        let authData = Data(SHA256.hash(data: Data("example.com".utf8))) + Data([0x05, 0, 0, 0, 1])
        let signature = try P256WireSignature.sign(authData + Data(SHA256.hash(data: clientData)), using: key)
        let assertion = WebAuthnAssertion(credentialID: credentialID, clientDataJSON: clientData, authenticatorData: authData, signature: signature)
        let challengeRecord = try WebAuthnChallenge(challengeDigest: Data(SHA256.hash(data: challenge)), accountDID: "did:plc:alice", credentialIDDigest: Data(SHA256.hash(data: credentialID)), relyingPartyID: "example.com", origin: "https://example.com", issuedAt: Date(timeIntervalSince1970: 1), expiresAt: Date(timeIntervalSince1970: 30))
        let credential = try WebAuthnCredentialMetadata(credentialIDDigest: Data(SHA256.hash(data: credentialID)), accountDID: "did:plc:alice", factorID: "factor", publicKeyReference: "key", signCount: 0, createdAt: Date(timeIntervalSince1970: 1))
        let keys = InMemoryWebAuthnKeyStore(reference: "key", key: key.publicKey)
        let store = InMemoryWebAuthnStore(credential: credential, challenge: challengeRecord)
        let factors = InMemoryFactorStore(factors: [try AuthenticationFactorMetadata(id: "factor", accountDID: "did:plc:alice", kind: .passkey, label: "Passkey", lookupDigest: Data(repeating: 2, count: 32), createdAt: Date(timeIntervalSince1970: 1))])
        let verifier = WebAuthnVerifier(keyStore: keys, credentialStore: store, challengeStore: store, factorStore: factors, relyingPartyID: "example.com", origin: "https://example.com")
        let badClientData = try JSONSerialization.data(withJSONObject: ["type": "webauthn.get", "challenge": testBase64URL(challenge), "origin": "https://evil.example"])
        let badAssertion = WebAuthnAssertion(credentialID: credentialID, clientDataJSON: badClientData, authenticatorData: authData, signature: try P256WireSignature.sign(authData + Data(SHA256.hash(data: badClientData)), using: key))
        do { _ = try await verifier.verify(assertion: badAssertion, accountDID: "did:plc:alice", challenge: challenge, now: Date(timeIntervalSince1970: 2)); XCTFail("wrong origin") } catch {}
        let result = try await verifier.verify(assertion: assertion, accountDID: "did:plc:alice", challenge: challenge, now: Date(timeIntervalSince1970: 2))
        XCTAssertEqual(result.accountDID, "did:plc:alice")
        do {
            _ = try await verifier.verify(assertion: assertion, accountDID: "did:plc:alice", challenge: challenge, now: Date(timeIntervalSince1970: 2))
            XCTFail("challenge replay should be rejected")
        } catch {}
    }

    func testWebAuthnRegistrationAcceptsOnlyP256UPAndUV() throws {
        let key = P256.Signing.PrivateKey()
        let challenge = Data("register-challenge".utf8)
        let clientData = try JSONSerialization.data(withJSONObject: ["type": "webauthn.create", "challenge": testBase64URL(challenge), "origin": "https://example.com", "crossOrigin": false])
        let credentialID = Data("credential".utf8)
        let x963 = key.publicKey.x963Representation
        let cose = Data([0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]) + x963.dropFirst().prefix(32) + Data([0x22, 0x58, 0x20]) + x963.suffix(32)
        let authData = Data(SHA256.hash(data: Data("example.com".utf8))) + Data([0x45, 0, 0, 0, 0]) + Data(repeating: 0, count: 16) + Data([0, UInt8(credentialID.count)]) + credentialID + cose
        let record = try WebAuthnChallenge(challengeDigest: Data(SHA256.hash(data: challenge)), accountDID: "did:plc:alice", purpose: .enrollment, relyingPartyID: "example.com", origin: "https://example.com", issuedAt: Date(timeIntervalSince1970: 1), expiresAt: Date(timeIntervalSince1970: 30))
        let result = try WebAuthnRegistrationVerifier.verify(clientDataJSON: clientData, authenticatorData: authData, challenge: challenge, accountDID: "did:plc:alice", challengeRecord: record, expectedOrigin: "https://example.com", relyingPartyID: "example.com", now: Date(timeIntervalSince1970: 2))
        XCTAssertEqual(result.signCount, 0)
        XCTAssertEqual(result.publicKey.x963Representation, x963)
        XCTAssertThrowsError(try WebAuthnRegistrationVerifier.verify(clientDataJSON: clientData, authenticatorData: authData, challenge: challenge, accountDID: "did:plc:bob", challengeRecord: record, expectedOrigin: "https://example.com", relyingPartyID: "example.com", now: Date(timeIntervalSince1970: 2)))
    }

    func testLegacyChannelAuthenticationRequiresFactorWhenEnrolled() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("swan-legacy-channel-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }

        let hasher = try LibsodiumArgon2idHasher()
        let verifier = try hasher.hash("hunter2-correct-password")
        // Registered through the store's own API rather than raw INSERTs: the
        // credential row, its state machine and the handle uniqueness
        // constraint are the store's invariants, and hand-written SQL here
        // depended on a schema shape that is not this store's.
        _ = try await database.createAccount(
            try AccountControlRegistration(
                did: "did:plc:mfauser2345677abcdefghij",
                canonicalHandle: "mfauser.example",
                passwordVerifier: verifier,
                signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
                rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1)
            )
        )

        let factorTokens = FactorTokenService(store: database)
        let directory = DurableAccountDirectory(
            store: database,
            passwordHasher: hasher,
            verificationExecutor: try Argon2idVerificationExecutor(hasher: hasher),
            loginFactorTokenVerifier: factorTokens,
            authenticationFactors: database
        )
        let now = Date(timeIntervalSince1970: 100)
        let legacyContext = try AccountAuthorizationContext(
            channel: .legacy,
            sessionID: "legacy-session-1",
            purpose: "managementLogin"
        )

        // 1. Correct password, no factors enrolled → authenticated with requiresFactor: false
        let noFactorOutcome = try await directory.authenticateForLogin(
            handle: "mfauser.example",
            password: "hunter2-correct-password",
            authFactorToken: nil,
            authorizationContext: legacyContext,
            now: now
        )
        guard case let .authenticated(noFactorSuccess) = noFactorOutcome else {
            XCTFail("expected .authenticated for account without MFA factors")
            return
        }
        XCTAssertFalse(noFactorSuccess.requiresFactor)
        XCTAssertNotNil(noFactorSuccess.authorizationGrantDigest)

        // 2. Enroll a TOTP factor
        let factor = try AuthenticationFactorMetadata(
            id: "mfa-totp",
            accountDID: "did:plc:mfauser2345677abcdefghij",
            kind: .totp,
            label: "Authenticator",
            lookupDigest: Data(repeating: 0x55, count: 32),
            createdAt: now
        )
        try await database.saveFactor(factor, now: now)

        // 3. Correct password, factor enrolled, no token → authenticated with requiresFactor: true
        let factorRequiredOutcome = try await directory.authenticateForLogin(
            handle: "mfauser.example",
            password: "hunter2-correct-password",
            authFactorToken: nil,
            authorizationContext: legacyContext,
            now: now
        )
        guard case let .authenticated(factorRequiredSuccess) = factorRequiredOutcome else {
            XCTFail("expected .authenticated(requiresFactor: true) when active factor is enrolled")
            return
        }
        XCTAssertTrue(factorRequiredSuccess.requiresFactor)

        // 4. Wrong password, factor enrolled → rejected (enumeration prevention)
        let wrongPasswordOutcome = try await directory.authenticateForLogin(
            handle: "mfauser.example",
            password: "wrong-password",
            authFactorToken: nil,
            authorizationContext: legacyContext,
            now: now
        )
        XCTAssertEqual(wrongPasswordOutcome, .rejected)
    }
}

private actor InMemoryRecoveryCodeStore: RecoveryCodeStore {
    private var digests: [Data: RecoveryCodeDigest] = [:]
    private var plaintexts: Set<String> = []
    func replaceRecoveryCodeDigests(accountDID: String, digests: [RecoveryCodeDigest], now: Date) async throws {
        self.digests = Dictionary(uniqueKeysWithValues: digests.map { ($0.digest, $0) })
    }
    func consumeRecoveryCode(digest: Data, accountDID: String, now: Date) async throws -> RecoveryCodeDigest {
        guard let value = digests[digest], value.accountDID == accountDID, value.consumedAt == nil else { throw AccountControlStoreError.notFound }
        let consumed = try RecoveryCodeDigest(accountDID: value.accountDID, digest: value.digest, issuedAt: value.issuedAt, consumedAt: now)
        digests[digest] = consumed
        return consumed
    }
    func containsPlaintext(_ value: String) -> Bool { plaintexts.contains(value) }
}

private actor InMemoryFactorStore: AuthenticationFactorStore {
    private var factors: [AuthenticationFactorMetadata]
    init(factors: [AuthenticationFactorMetadata]) { self.factors = factors }
    func listFactors(accountDID: String, now: Date) async throws -> [AuthenticationFactorMetadata] { factors.filter { $0.accountDID == accountDID && $0.disabledAt == nil } }
    func saveFactor(_ factor: AuthenticationFactorMetadata, now: Date) async throws { factors.append(factor) }
    func disableFactor(id: String, accountDID: String, now: Date) async throws { factors = try factors.map { value in guard value.id == id && value.accountDID == accountDID else { return value }; return try AuthenticationFactorMetadata(id: value.id, accountDID: value.accountDID, kind: value.kind, label: value.label, lookupDigest: value.lookupDigest, createdAt: value.createdAt, lastUsedAt: value.lastUsedAt, disabledAt: now) } }
    func reserveChallenge(_ challenge: FactorChallenge, now: Date) async throws {}
    func consumeChallenge(digest: Data, now: Date) async throws -> FactorChallenge { throw AccountControlStoreError.notFound }
    func purgeExpiredFactorState(now: Date) async throws {}
}

private actor InMemoryTOTPReplayStore: TOTPReplayStore {
    private var counters: [String: UInt64] = [:]
    func compareAndSwapTOTPReplay(factorID: String, accountDID: String, expected: UInt64?, proposed: UInt64, now: Date) async throws -> Bool {
        let key = accountDID + "\u{0}" + factorID
        guard proposed > (counters[key] ?? UInt64.min) else { return false }
        if let expected, counters[key] != expected { return false }
        counters[key] = proposed; return true
    }
}

private actor InMemoryFactorTokenStore: DurableFactorTokenStore {
    private var records: [Data: DurableFactorTokenRecord] = [:]
    private var consumed: Set<Data> = []
    func saveFactorToken(_ record: DurableFactorTokenRecord, now: Date) async throws { records[record.digest] = record }
    func consumeFactorToken(digest: Data, accountDID: String, sessionID: String, purpose: String, factor: AuthenticationFactorKind, factorID: String, strength: AuthenticationStrength, now: Date) async throws -> DurableFactorTokenRecord {
        guard !consumed.contains(digest), let record = records[digest], record.accountDID == accountDID, record.sessionID == sessionID, record.purpose == purpose, record.factor == factor, record.factorID == factorID, record.strength == strength, now < record.expiresAt else { throw AccountControlStoreError.notFound }
        consumed.insert(digest); return record
    }
    func consumeFactorTokenForStepUp(digest: Data, accountDID: String, sessionID: String, now: Date) async throws -> DurableFactorTokenRecord {
        guard !consumed.contains(digest), let record = records[digest], record.accountDID == accountDID, record.sessionID == sessionID, record.purpose == FactorTokenPurpose.stepUp.rawValue, record.strength.isStepUp, now < record.expiresAt else { throw AccountControlStoreError.notFound }
        consumed.insert(digest); return record
    }
    func revokeFactorTokens(accountDID: String, sessionID: String?, now: Date) async throws {}
}

private actor InMemoryWebAuthnStore: WebAuthnCredentialStore, WebAuthnAtomicVerificationStore, WebAuthnChallengeLookupStore {
    var credential: WebAuthnCredentialMetadata
    var challenge: WebAuthnChallenge
    init(credential: WebAuthnCredentialMetadata, challenge: WebAuthnChallenge) { self.credential = credential; self.challenge = challenge }
    func saveWebAuthnCredential(_ value: WebAuthnCredentialMetadata, now: Date) async throws { credential = value }
    func webAuthnCredential(credentialIDDigest: Data, accountDID: String, now: Date) async throws -> WebAuthnCredentialMetadata? { credential.credentialIDDigest == credentialIDDigest && credential.accountDID == accountDID ? credential : nil }
    func compareAndSwapWebAuthnSignCount(_ update: WebAuthnSignCountUpdate) async throws -> WebAuthnSignCountUpdateOutcome {
        guard credential.signCount == update.expectedCurrent else { return .rollbackDetected(storedCount: credential.signCount) }
        credential = try WebAuthnCredentialMetadata(credentialIDDigest: credential.credentialIDDigest, accountDID: credential.accountDID, factorID: credential.factorID, publicKeyReference: credential.publicKeyReference, signCount: update.proposed, transports: credential.transports, createdAt: credential.createdAt, lastUsedAt: update.now, disabledAt: credential.disabledAt)
        return .updated(newCount: update.proposed)
    }
    func disableWebAuthnCredential(credentialIDDigest: Data, accountDID: String, now: Date) async throws {}
    func reserveWebAuthnChallenge(_ value: WebAuthnChallenge, now: Date) async throws { challenge = value }
    func webAuthnChallenge(digest: Data, accountDID: String, now: Date) async throws -> WebAuthnChallenge? { challenge.challengeDigest == digest && challenge.accountDID == accountDID && challenge.consumedAt == nil && now < challenge.expiresAt ? challenge : nil }
    func consumeWebAuthnChallenge(digest: Data, accountDID: String, now: Date) async throws -> WebAuthnChallenge {
        guard challenge.challengeDigest == digest, challenge.accountDID == accountDID, challenge.consumedAt == nil else { throw SwanError.invalidIdentifier("challenge") }
        let value = try WebAuthnChallenge(challengeDigest: challenge.challengeDigest, accountDID: challenge.accountDID, credentialIDDigest: challenge.credentialIDDigest, sessionID: challenge.sessionID, factorID: challenge.factorID, purpose: challenge.purpose, relyingPartyID: challenge.relyingPartyID, origin: challenge.origin, issuedAt: challenge.issuedAt, expiresAt: challenge.expiresAt, consumedAt: now)
        challenge = value
        return value
    }
    func compareAndSwapWebAuthnSignCountAndConsumeChallenge(_ update: WebAuthnSignCountUpdate, challengeDigest: Data, now: Date) async throws -> WebAuthnSignCountUpdateOutcome {
        guard credential.signCount == update.expectedCurrent else { return .rollbackDetected(storedCount: credential.signCount) }
        guard challenge.challengeDigest == challengeDigest, challenge.accountDID == update.accountDID, challenge.consumedAt == nil else { throw AccountControlStoreError.malformedRecord }
        credential = try WebAuthnCredentialMetadata(credentialIDDigest: credential.credentialIDDigest, accountDID: credential.accountDID, factorID: credential.factorID, publicKeyReference: credential.publicKeyReference, signCount: update.proposed, transports: credential.transports, createdAt: credential.createdAt, lastUsedAt: now, disabledAt: credential.disabledAt)
        challenge = try WebAuthnChallenge(challengeDigest: challenge.challengeDigest, accountDID: challenge.accountDID, credentialIDDigest: challenge.credentialIDDigest, sessionID: challenge.sessionID, factorID: challenge.factorID, purpose: challenge.purpose, relyingPartyID: challenge.relyingPartyID, origin: challenge.origin, issuedAt: challenge.issuedAt, expiresAt: challenge.expiresAt, consumedAt: now)
        return .updated(newCount: update.proposed)
    }
}

private struct InMemoryWebAuthnKeyStore: WebAuthnPublicKeyStore {
    let reference: String
    let key: P256.Signing.PublicKey
    func publicKey(reference: String) async throws -> P256.Signing.PublicKey? { reference == self.reference ? key : nil }
}

private struct InMemoryTOTPKeyStore: TOTPEnvelopeKeyStore {
    let reference: String
    let key: Data
    func key(reference: String) async throws -> Data? { reference == self.reference ? key : nil }
}

private func testBase64URL(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}
