import Foundation
import Crypto
@testable import SwanAccounts
@testable import SwanHTTP
@testable import SwanSQLite
import SwanStorage
import XCTest

final class SwanAccountPortalMFARuntimeTests: XCTestCase {
    func testTOTPEnrollmentStepUpAndReplayUseDurableFactorServices() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanAccountPortalMFARuntimeTests-\(UUID().uuidString)")
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let suffix = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let did = "did:plc:\(String(suffix.prefix(24)))"
        let handle = "alice-\(String(suffix.prefix(12))).example"
        try await database.connection.query(
            "INSERT INTO accounts(did, handle, status, created_at) VALUES (?, ?, 'active', 1)",
            [.text(did), .text(handle)]
        )
        let factorTokens = FactorTokenService(store: database)
        let runtime = try SwanAccountPortalMFARuntime(
            factors: database,
            totpSecrets: database,
            replayStore: database,
            recoveryStore: database,
            webAuthnCredentials: database,
            webAuthnChallenges: database,
            webAuthnEnrollmentStore: database,
            factorTokens: factorTokens,
            accountKEK: Data(repeating: 0x4B, count: 32),
            accountKEKID: "primary",
            relyingPartyID: "swan.example",
            origin: "https://swan.example"
        )
        let enrollment = try JSONSerialization.data(withJSONObject: [
            "kind": "totp",
            "factorID": "totp-factor",
            "label": "Authenticator",
            "secret": "GEZDGNBVGY3TQOJQ"
        ])
        _ = try await runtime.mutate(
            path: "factors/totp",
            accountDID: did,
            sessionID: "portal-session",
            strength: .password,
            payload: enrollment,
            now: Date(timeIntervalSince1970: 60)
        )
        let pendingFactors = try await database.listFactors(accountDID: did, now: Date(timeIntervalSince1970: 60))
        XCTAssertTrue(pendingFactors.isEmpty)
        let secret = try TOTPAuthenticator.decodeBase32("GEZDGNBVGY3TQOJQ")
        let code = try TOTPAuthenticator.code(secret: secret, counter: 2)
        let verifiedEnrollment = try await runtime.mutate(
            path: "factors/totp/verify",
            accountDID: did,
            sessionID: "portal-session",
            strength: .stepUpPassword(verifiedAt: Date(timeIntervalSince1970: 60)),
            payload: try JSONSerialization.data(withJSONObject: [
                "factorID": "totp-factor",
                "code": code,
            ]),
            now: Date(timeIntervalSince1970: 60)
        )
        XCTAssertTrue(verifiedEnrollment.accepted)
        let activeFactors = try await database.listFactors(accountDID: did, now: Date(timeIntervalSince1970: 60))
        XCTAssertEqual(activeFactors.count, 1)
        let stepUp = try JSONSerialization.data(withJSONObject: [
            "kind": "totp",
            "factorID": "totp-factor",
            "code": code
        ])
        let issued = try await runtime.mutate(
            path: "factors/step-up",
            accountDID: did,
            sessionID: "portal-session",
            strength: .password,
            payload: stepUp,
            now: Date(timeIntervalSince1970: 60)
        )
        XCTAssertNotNil(issued.factorToken)
        do {
            _ = try await runtime.mutate(
                path: "factors/step-up",
                accountDID: did,
                sessionID: "portal-session",
                strength: .password,
                payload: stepUp,
                now: Date(timeIntervalSince1970: 60)
            )
            XCTFail("TOTP code replay must be rejected")
        } catch let error as MFAError {
            XCTAssertTrue(error == .invalidCode || error == .replay)
        }

        // Login-purpose tokens are separately typed and consumed once by the
        // same durable FactorTokenService used by the account directory.
        let login = try await factorTokens.issue(
            accountDID: did,
            sessionID: "portal-session",
            purpose: .managementLogin,
            factor: .totp,
            factorID: "totp-factor",
            strength: .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: Date(timeIntervalSince1970: 60)),
            now: Date(timeIntervalSince1970: 60)
        )
        let verifiedLoginStrength = try await factorTokens.verifyLoginFactorToken(
            token: login.token,
            accountDID: did,
            now: Date(timeIntervalSince1970: 61)
        )
        XCTAssertEqual(
            verifiedLoginStrength,
            .stepUpMFA(base: .passwordPlusTOTP, verifiedAt: Date(timeIntervalSince1970: 60))
        )
    }

    func testWebAuthnChallengesAreServerGeneratedAndSessionBound() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanAccountPortalMFARuntimeTests-\(UUID().uuidString)")
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let suffix = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let did = "did:plc:\(String(suffix.prefix(24)))"
        let handle = "alice-\(String(suffix.prefix(12))).example"
        try await database.connection.query(
            "INSERT INTO accounts(did, handle, status, created_at) VALUES (?, ?, 'active', 1)",
            [.text(did), .text(handle)]
        )
        let runtime = try SwanAccountPortalMFARuntime(
            factors: database,
            totpSecrets: database,
            replayStore: database,
            recoveryStore: database,
            webAuthnCredentials: database,
            webAuthnChallenges: database,
            webAuthnEnrollmentStore: database,
            factorTokens: FactorTokenService(store: database),
            accountKEK: Data(repeating: 0x4B, count: 32),
            accountKEKID: "primary",
            relyingPartyID: "swan.example",
            origin: "https://swan.example"
        )
        let first = try await runtime.mutate(
            path: "factors/passkeys/challenge",
            accountDID: did,
            sessionID: "session-a",
            strength: .password,
            payload: Data(#"{"label":"Laptop"}"#.utf8),
            now: Date(timeIntervalSince1970: 60)
        )
        let firstChallenge = try XCTUnwrap(first.challenge)
        let firstBytes = try decodeBase64URL(firstChallenge)
        XCTAssertEqual(firstBytes.count, 32)
        let storedFirstRecord = try await database.webAuthnChallenge(
            digest: Data(SHA256.hash(data: firstBytes)),
            accountDID: did,
            now: Date(timeIntervalSince1970: 61)
        )
        let firstRecord = try XCTUnwrap(storedFirstRecord)
        XCTAssertEqual(firstRecord.sessionID, "session-a")
        XCTAssertEqual(firstRecord.factorID, first.factorID)
        XCTAssertEqual(firstRecord.purpose, .enrollment)

        let second = try await runtime.mutate(
            path: "factors/passkeys/challenge",
            accountDID: did,
            sessionID: "session-a",
            strength: .password,
            payload: Data(#"{"label":"Laptop" ,"challenge":"caller-chosen"}"#.utf8),
            now: Date(timeIntervalSince1970: 60)
        )
        XCTAssertNotEqual(first.challenge, second.challenge)
    }

    func testConcurrentFactorIdentifierInsertionHasOneWinnerWithoutDisablingIt() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanAccountPortalMFARuntimeTests-factor-race-\(UUID().uuidString)")
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let now = Date(timeIntervalSince1970: 60)
        try await database.connection.query(
            "INSERT INTO accounts(did, handle, status, created_at) VALUES (?, ?, 'active', ?)",
            [.text(did), .text("factor-race.example"), .integer(1_000_000)]
        )
        let factor = try AuthenticationFactorMetadata(
            id: "concurrent-passkey",
            accountDID: did,
            kind: .passkey,
            label: "Laptop",
            lookupDigest: Data(repeating: 0xA1, count: 32),
            createdAt: now
        )
        let results = await withTaskGroup(of: Bool.self, returning: [Bool].self) { group in
            for _ in 0 ..< 4 {
                group.addTask {
                    (try? await database.saveFactorIfAbsent(factor, now: now)) ?? false
                }
            }
            var values: [Bool] = []
            for await value in group { values.append(value) }
            return values
        }
        XCTAssertEqual(results.filter { $0 }.count, 1)
        XCTAssertEqual(results.filter { !$0 }.count, 3)
        let storedFactors = try await database.listFactors(accountDID: did, now: now)
        XCTAssertEqual(storedFactors.map(\.id), [factor.id])
    }

    func testFactorMutationRejectsAStaleStepUpAtCommit() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanAccountPortalMFARuntimeTests-stale-\(UUID().uuidString)")
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let now = Date(timeIntervalSince1970: 1_000)
        _ = try await database.createAccount(
            try AccountControlRegistration(
                did: did,
                canonicalHandle: "stale.example",
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$initialsalt$initial-precomputed-verifier",
                signingKey: try .init(purpose: .signing, generation: 1),
                rotationKey: try .init(purpose: .rotation, generation: 1),
                createdAt: now.addingTimeInterval(-100)
            )
        )
        let accountRecord = try await database.account(did: did)
        let account = try XCTUnwrap(accountRecord)
        let sessions = SwanManagementSessionRuntime(
            store: StaleStepUpSessionStore(),
            preAuthStore: SwanInMemoryManagementPreAuthStore(),
            csrfStore: SwanInMemoryManagementCSRFStore()
        )
        let issued = try await sessions.issue(
            accountDID: did,
            strength: .stepUpPassword(verifiedAt: now.addingTimeInterval(-601)),
            now: now.addingTimeInterval(-601)
        )
        let runtime = try SwanAccountPortalMFARuntime(
            factors: database,
            totpSecrets: database,
            replayStore: database,
            recoveryStore: database,
            webAuthnCredentials: database,
            webAuthnChallenges: database,
            webAuthnEnrollmentStore: database,
            factorTokens: FactorTokenService(store: database),
            accountKEK: Data(repeating: 0x4B, count: 32),
            accountKEKID: "primary",
            relyingPartyID: "swan.example",
            origin: "https://swan.example"
        )
        let service = SwanAccountPortalService(
            accountDirectory: StaleStepUpPortalDirectory(account: account),
            factors: database,
            mfa: runtime,
            sessions: sessions
        )
        do {
            _ = try await service.mutate(
                path: "factors/totp",
                context: .init(sessionID: issued.sessionValue, accountDID: did, strength: issued.metadata.strength),
                payload: Data(#"{"factorID":"stale","label":"Authenticator","secret":"GEZDGNBVGY3TQOJQ"}"#.utf8),
                now: now
            )
            XCTFail("a step-up older than ten minutes must not authorize factor enrollment")
        } catch let error as SwanAccountPortalServiceError {
            XCTAssertEqual(error, .forbidden)
        }
    }

    private func decodeBase64URL(_ value: String) throws -> Data {
        var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        return try XCTUnwrap(Data(base64Encoded: base64))
    }
}

private struct StaleStepUpPortalDirectory: SwanAccountPortalAccountDirectory {
    let account: AccountControlAccount
    func account(did: String) async throws -> AccountControlAccount? { did == account.did ? account : nil }
    func resolve(handle: String) async throws -> AccountControlAccount? { handle == account.canonicalHandle ? account : nil }
    func authenticateForLogin(handle: String, password: String, now: Date) async throws -> AccountLoginAuthenticationOutcome { .rejected }
}

private actor StaleStepUpSessionStore: ManagementSessionStore {
    private var values: [Data: ManagementSessionMetadata] = [:]

    func createManagementSession(
        _ session: ManagementSessionMetadata,
        sessionDigest: Data,
        csrfDigest _: Data,
        now _: Date
    ) async throws {
        values[sessionDigest] = session
    }

    func managementSession(digest: Data, now _: Date) async throws -> ManagementSessionMetadata? {
        values[digest]
    }

    func revokeManagementSession(digest: Data, now _: Date) async throws {
        values.removeValue(forKey: digest)
    }

    func revokeManagementSession(digest: Data, accountDID: String, now _: Date) async throws {
        guard let session = values[digest], session.accountDID == accountDID else { return }
        values.removeValue(forKey: digest)
    }

    func revokeManagementSessions(accountDID: String, now _: Date) async throws {
        values = values.filter { $0.value.accountDID != accountDID }
    }

    func managementSessions(accountDID: String, now _: Date) async throws -> [ManagementSessionMetadata] {
        values.values.filter { $0.accountDID == accountDID }
    }

    func revokeOtherManagementSessions(
        accountDID: String,
        except sessionID: ManagementSessionID,
        now _: Date
    ) async throws {
        values = values.filter {
            $0.value.accountDID != accountDID || $0.value.sessionID == sessionID
        }
    }

    func purgeExpiredManagementSessions(now _: Date) async throws {}
}
