import Foundation
import SQLiteNIO
@_spi(PortableRestore) @testable import SwanSQLite
import SwanStorage
import XCTest

final class PasswordRecoveryCompletionSQLiteTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let otherDID = "did:plc:bcdefghijklmnopqrstuvwxy"
    private let email = try! AccountEmailAddress("person@example.com")
    private let initialVerifier =
        "$argon2id$v=19$m=65536,t=2,p=1$initialsalt$initial-precomputed-verifier"
    private let replacementVerifier =
        "$argon2id$v=19$m=65536,t=2,p=1$replacesalt$replacement-precomputed-verifier"

    func testExactEmailConfirmationDoesNotBurnMismatchAndHasOneWinner() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let first = try await SQLiteControlDatabase(dataDirectory: root)
        let second = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let now = Date(timeIntervalSince1970: 1_750_000_000)
            _ = try await first.createAccount(try registration())
            try await first.associateEmail(did: did, email: email, now: now)
            let proofDigest = Data(repeating: 0x21, count: 32)
            try await first.issueEmailToken(
                did: did,
                email: email,
                purpose: .verifyEmail,
                digest: proofDigest,
                expiresAt: now.addingTimeInterval(600),
                now: now
            )

            let wrongDID = try await first.confirmEmail(
                try AccountEmailConfirmationRequest(
                    did: otherDID,
                    email: email,
                    proofDigest: proofDigest
                ),
                now: now.addingTimeInterval(1)
            )
            XCTAssertFalse(wrongDID)
            let wrongEmail = try await first.confirmEmail(
                try AccountEmailConfirmationRequest(
                    did: did,
                    email: AccountEmailAddress("attacker@example.com"),
                    proofDigest: proofDigest
                ),
                now: now.addingTimeInterval(1)
            )
            XCTAssertFalse(wrongEmail)

            let exact = try AccountEmailConfirmationRequest(
                did: did,
                email: email,
                proofDigest: proofDigest
            )
            async let firstConfirmation = first.confirmEmail(
                exact,
                now: now.addingTimeInterval(2)
            )
            async let secondConfirmation = second.confirmEmail(
                exact,
                now: now.addingTimeInterval(2)
            )
            let outcome = try await (
                firstConfirmation,
                secondConfirmation
            )
            XCTAssertEqual([outcome.0, outcome.1].filter { $0 }.count, 1)
            let verified = try await first.verifiedEmail(did: did)
            XCTAssertEqual(verified, email)
            let replay = try await first.confirmEmail(
                exact,
                now: now.addingTimeInterval(3)
            )
            XCTAssertFalse(replay)

            try await second.close()
            try await first.close()
        } catch {
            try? await second.close()
            try? await first.close()
            throw error
        }
    }

    func testCompletionRequiresExactVerifiedEmailAndRevokesEveryFamily() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let now = Date(timeIntervalSince1970: 1_750_000_000)
            _ = try await database.createAccount(try registration())
            try await database.associateEmail(did: did, email: email, now: now)

            let verificationDigest = Data(repeating: 0x31, count: 32)
            let recoveryDigest = Data(repeating: 0x32, count: 32)
            try await database.issueEmailToken(
                did: did,
                email: email,
                purpose: .verifyEmail,
                digest: verificationDigest,
                expiresAt: now.addingTimeInterval(600),
                now: now
            )
            try await database.issueEmailToken(
                did: did,
                email: email,
                purpose: .passwordRecovery,
                digest: recoveryDigest,
                expiresAt: now.addingTimeInterval(600),
                now: now
            )

            let unverifiedConfirmation =
                try await database.passwordRecoveryConfirmation(
                    proofDigest: recoveryDigest,
                    now: now.addingTimeInterval(1)
                )
            XCTAssertNil(unverifiedConfirmation)
            let unverifiedRequest = try recoveryRequest(
                digest: recoveryDigest,
                replacementVerifier: replacementVerifier
            )
            let unverified = try await database.completePasswordRecovery(
                unverifiedRequest,
                now: now.addingTimeInterval(1)
            )
            XCTAssertEqual(unverified, .unchanged)

            let verifiedDID = try await database.consumeEmailToken(
                digest: verificationDigest,
                purpose: .verifyEmail,
                now: now.addingTimeInterval(2)
            )
            XCTAssertEqual(verifiedDID, did)
            let legacySplitPhase = try await database.consumeEmailToken(
                digest: recoveryDigest,
                purpose: .passwordRecovery,
                now: now.addingTimeInterval(2)
            )
            XCTAssertNil(legacySplitPhase)
            let loadedConfirmation =
                try await database.passwordRecoveryConfirmation(
                    proofDigest: recoveryDigest,
                    now: now.addingTimeInterval(2)
                )
            let confirmation = try XCTUnwrap(loadedConfirmation)
            XCTAssertEqual(confirmation.did, did)
            XCTAssertEqual(confirmation.email, email)
            let request = try AccountPasswordRecoveryRequest(
                confirmation: confirmation,
                expectedVerifier: initialVerifier,
                replacementVerifier: replacementVerifier
            )

            let wrongEmail = try AccountEmailAddress("attacker@example.com")
            let wrongEmailResult = try await database.completePasswordRecovery(
                try recoveryRequest(
                    email: wrongEmail,
                    digest: recoveryDigest,
                    replacementVerifier: replacementVerifier
                ),
                now: now.addingTimeInterval(3)
            )
            XCTAssertEqual(wrongEmailResult, .unchanged)
            let wrongDIDResult = try await database.completePasswordRecovery(
                try recoveryRequest(
                    did: otherDID,
                    digest: recoveryDigest,
                    replacementVerifier: replacementVerifier
                ),
                now: now.addingTimeInterval(3)
            )
            XCTAssertEqual(wrongDIDResult, .unchanged)
            let staleVerifierResult = try await database.completePasswordRecovery(
                try AccountPasswordRecoveryRequest(
                    confirmation: confirmation,
                    expectedVerifier:
                        "$argon2id$v=19$m=65536,t=2,p=1$stalesalt$stale-precomputed-verifier",
                    replacementVerifier: replacementVerifier
                ),
                now: now.addingTimeInterval(3)
            )
            XCTAssertEqual(staleVerifierResult, .unchanged)

            // Leave a second, differently scoped proof behind so completion
            // proves that it deletes every email proof, not just the winner.
            try await database.issueEmailToken(
                did: did,
                email: email,
                purpose: .verifyEmail,
                digest: Data(repeating: 0x33, count: 32),
                expiresAt: now.addingTimeInterval(600),
                now: now.addingTimeInterval(4)
            )

            let firstFamily = try await issueOAuthFamily(
                in: database,
                subject: did,
                marker: 0x41,
                now: now
            )
            let secondFamily = try await issueOAuthFamily(
                in: database,
                subject: did,
                marker: 0x51,
                now: now
            )
            let otherFamily = try await issueOAuthFamily(
                in: database,
                subject: otherDID,
                marker: 0x61,
                now: now
            )

            let completed = try await database.completePasswordRecovery(
                request,
                now: now.addingTimeInterval(5)
            )
            XCTAssertEqual(completed, .completed)
            let credential = try await database.credential(did: did)
            XCTAssertEqual(credential?.verifier, replacementVerifier)

            let proofRows = try await database.connection.query(
                "SELECT digest FROM account_email_tokens WHERE did = ?",
                [.text(did)]
            )
            XCTAssertTrue(proofRows.isEmpty)
            let consumedConfirmation =
                try await database.passwordRecoveryConfirmation(
                    proofDigest: recoveryDigest,
                    now: now.addingTimeInterval(6)
                )
            XCTAssertNil(consumedConfirmation)
            let familyRows = try await database.connection.query(
                """
                SELECT revoked_at
                FROM oauth_control_token_families
                WHERE subject = ?
                ORDER BY family_id
                """,
                [.text(did)]
            )
            XCTAssertEqual(familyRows.count, 2)
            XCTAssertTrue(familyRows.allSatisfy {
                $0.column("revoked_at")?.isNull == false
            })

            await assertOAuthTokenExpired(
                database,
                digest: firstFamily.accessDigest,
                now: now.addingTimeInterval(6)
            )
            await assertOAuthTokenExpired(
                database,
                digest: secondFamily.accessDigest,
                now: now.addingTimeInterval(6)
            )
            let unrelatedFamily = try await database.validatedAccessToken(
                accessTokenDigest: otherFamily.accessDigest,
                requireActiveSubject: false,
                now: now.addingTimeInterval(6)
            )
            XCTAssertEqual(unrelatedFamily.subject, otherDID)
            for revoked in [firstFamily, secondFamily] {
                await assertOAuthRefreshFamilyExpired(
                    database,
                    digest: revoked.refreshDigest,
                    now: now.addingTimeInterval(6)
                )
                let hiddenFamily = try await database.tokenFamily(
                    tokenDigest: revoked.refreshDigest,
                    kind: .refreshToken,
                    now: now.addingTimeInterval(6)
                )
                XCTAssertNil(
                    hiddenFamily,
                    "password recovery left a revoked target family discoverable"
                )
                await assertOAuthRefreshRedemptionExpired(
                    database,
                    issued: revoked,
                    now: now.addingTimeInterval(6)
                )
            }

            let unrelatedRefreshFamily = try await database.refreshTokenFamily(
                refreshTokenDigest: otherFamily.refreshDigest,
                now: now.addingTimeInterval(6)
            )
            XCTAssertEqual(unrelatedRefreshFamily.subject, otherDID)
            let unrelatedLookup = try await database.tokenFamily(
                tokenDigest: otherFamily.refreshDigest,
                kind: .refreshToken,
                now: now.addingTimeInterval(6)
            )
            XCTAssertEqual(unrelatedLookup?.subject, otherDID)
            let rotatedOtherAccess = Data(repeating: 0x71, count: 32)
            try await database.redeemRefreshToken(
                refreshTokenDigest: otherFamily.refreshDigest,
                replacement: OAuthIssuedTokenDigests(
                    familyID: otherFamily.familyID,
                    accessTokenDigest: rotatedOtherAccess,
                    refreshTokenDigest: Data(repeating: 0x72, count: 32),
                    accessExpiresAt: now.addingTimeInterval(300),
                    refreshExpiresAt: now.addingTimeInterval(600)
                ),
                requireActiveSubject: false,
                now: now.addingTimeInterval(6)
            )
            let rotatedOtherFamily = try await database.validatedAccessToken(
                accessTokenDigest: rotatedOtherAccess,
                requireActiveSubject: false,
                now: now.addingTimeInterval(7)
            )
            XCTAssertEqual(rotatedOtherFamily.subject, otherDID)

            let replay = try await database.completePasswordRecovery(
                request,
                now: now.addingTimeInterval(7)
            )
            XCTAssertEqual(replay, .unchanged)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testConcurrentCompletionsAcrossConnectionsHaveOneWinner() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let first = try await SQLiteControlDatabase(dataDirectory: root)
        let second = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let now = Date(timeIntervalSince1970: 1_750_000_000)
            _ = try await first.createAccount(try registration())
            let recoveryDigest = try await installVerifiedRecoveryProof(
                in: first,
                now: now
            )
            let firstReplacement =
                "$argon2id$v=19$m=65536,t=2,p=1$firstsalt$first-race-replacement"
            let secondReplacement =
                "$argon2id$v=19$m=65536,t=2,p=1$secondsalt$second-race-replacement"
            let loadedConfirmation =
                try await first.passwordRecoveryConfirmation(
                    proofDigest: recoveryDigest,
                    now: now
                )
            let confirmation = try XCTUnwrap(loadedConfirmation)
            let firstRequest = try AccountPasswordRecoveryRequest(
                confirmation: confirmation,
                expectedVerifier: initialVerifier,
                replacementVerifier: firstReplacement
            )
            let secondRequest = try AccountPasswordRecoveryRequest(
                confirmation: confirmation,
                expectedVerifier: initialVerifier,
                replacementVerifier: secondReplacement
            )

            async let firstResult = first.completePasswordRecovery(
                firstRequest,
                now: now.addingTimeInterval(1)
            )
            async let secondResult = second.completePasswordRecovery(
                secondRequest,
                now: now.addingTimeInterval(1)
            )
            let outcome = try await (firstResult, secondResult)
            let results = [outcome.0, outcome.1]
            XCTAssertEqual(results.filter { $0 == .completed }.count, 1)
            XCTAssertEqual(results.filter { $0 == .unchanged }.count, 1)

            let credential = try await first.credential(did: did)
            XCTAssertTrue(
                credential?.verifier == firstReplacement ||
                    credential?.verifier == secondReplacement
            )
            let proofs = try await first.connection.query(
                "SELECT 1 FROM account_email_tokens WHERE did = ?",
                [.text(did)]
            )
            XCTAssertTrue(proofs.isEmpty)

            try await second.close()
            try await first.close()
        } catch {
            try? await second.close()
            try? await first.close()
            throw error
        }
    }

    func testCompletionRejectsExpiredProofAndInactiveAccount() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let now = Date(timeIntervalSince1970: 1_750_000_000)
            _ = try await database.createAccount(try registration())
            let expiredDigest = try await installVerifiedRecoveryProof(
                in: database,
                now: now
            )
            let expired = try await database.completePasswordRecovery(
                try recoveryRequest(
                    digest: expiredDigest,
                    replacementVerifier: replacementVerifier
                ),
                now: now.addingTimeInterval(601)
            )
            XCTAssertEqual(expired, .unchanged)

            let lifecycleDigest = Data(repeating: 0x73, count: 32)
            try await database.issueEmailToken(
                did: did,
                email: email,
                purpose: .passwordRecovery,
                digest: lifecycleDigest,
                expiresAt: now.addingTimeInterval(1_200),
                now: now.addingTimeInterval(602)
            )
            _ = try await database.transitionStatus(
                did: did,
                to: .deactivated,
                declaration: AccountLifecycleDeclaration(),
                now: now.addingTimeInterval(603)
            )
            let inactive = try await database.completePasswordRecovery(
                try recoveryRequest(
                    digest: lifecycleDigest,
                    replacementVerifier: replacementVerifier
                ),
                now: now.addingTimeInterval(604)
            )
            XCTAssertEqual(inactive, .unchanged)
            let credential = try await database.credential(did: did)
            // The credential projection is deliberately active-only.  The
            // lifecycle transition must block authentication and recovery
            // without destroying the verifier needed for an explicit
            // reactivation.
            XCTAssertNil(credential)
            _ = try await database.transitionStatus(
                did: did,
                to: .active,
                declaration: AccountLifecycleDeclaration(),
                now: now.addingTimeInterval(605)
            )
            let reactivatedCredential = try await database.credential(did: did)
            XCTAssertEqual(reactivatedCredential?.verifier, initialVerifier)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testOperatorRestoreRejectsFabricatedEmailRecoveryTrustState() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            _ = try await database.createAccount(try registration())
            try await database.associateEmail(
                did: did,
                email: email,
                now: Date(timeIntervalSince1970: 1_750_000_000)
            )

            do {
                try await database.validateOperatorRestoreOnlyAccount(did: did)
                XCTFail("operator restore accepted fabricated email trust state")
            } catch {
                XCTAssertEqual(
                    error as? AccountControlStoreError,
                    .malformedRecord
                )
            }
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    private func installVerifiedRecoveryProof(
        in database: SQLiteControlDatabase,
        now: Date
    ) async throws -> Data {
        try await database.associateEmail(did: did, email: email, now: now)
        let verificationDigest = Data(repeating: 0x71, count: 32)
        try await database.issueEmailToken(
            did: did,
            email: email,
            purpose: .verifyEmail,
            digest: verificationDigest,
            expiresAt: now.addingTimeInterval(600),
            now: now
        )
        let verified = try await database.consumeEmailToken(
            digest: verificationDigest,
            purpose: .verifyEmail,
            now: now
        )
        guard verified == did else {
            throw AccountControlStoreError.malformedRecord
        }
        let recoveryDigest = Data(repeating: 0x72, count: 32)
        try await database.issueEmailToken(
            did: did,
            email: email,
            purpose: .passwordRecovery,
            digest: recoveryDigest,
            expiresAt: now.addingTimeInterval(600),
            now: now
        )
        return recoveryDigest
    }

    private func issueOAuthFamily(
        in database: SQLiteControlDatabase,
        subject: String,
        marker: UInt8,
        now: Date
    ) async throws -> IssuedOAuthFamily {
        let familyID = UUID()
        let accessDigest = Data(repeating: marker, count: 32)
        let refreshDigest = Data(repeating: marker &+ 1, count: 32)
        let family = OAuthTokenFamily(
            familyID: familyID,
            subject: subject,
            binding: OAuthClientBinding(
                issuer: "https://swan.example",
                clientID: "https://client.example/metadata.json",
                redirectURI: "https://client.example/callback",
                scopes: ["atproto"],
                dpopJKT: String(repeating: "D", count: 43)
            ),
            expiresAt: now.addingTimeInterval(600)
        )
        try await database.issueTokenPair(
            family: family,
            tokens: OAuthIssuedTokenDigests(
                familyID: familyID,
                accessTokenDigest: accessDigest,
                refreshTokenDigest: refreshDigest,
                accessExpiresAt: now.addingTimeInterval(300),
                refreshExpiresAt: now.addingTimeInterval(600)
            ),
            now: now
        )
        return IssuedOAuthFamily(
            familyID: familyID,
            accessDigest: accessDigest,
            refreshDigest: refreshDigest
        )
    }

    private func recoveryRequest(
        did: String? = nil,
        email: AccountEmailAddress? = nil,
        digest: Data,
        replacementVerifier: String
    ) throws -> AccountPasswordRecoveryRequest {
        try AccountPasswordRecoveryRequest(
            did: did ?? self.did,
            email: email ?? self.email,
            proofDigest: digest,
            expectedVerifier: initialVerifier,
            replacementVerifier: replacementVerifier
        )
    }

    private func registration() throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: "recovery-completion.example.com",
            passwordVerifier: initialVerifier,
            signingKey: try .init(purpose: .signing, generation: 1),
            rotationKey: try .init(purpose: .rotation, generation: 1),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "PasswordRecoveryCompletionSQLiteTests-\(UUID().uuidString)"
        )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }
}

private struct IssuedOAuthFamily {
    let familyID: UUID
    let accessDigest: Data
    let refreshDigest: Data
}

private func assertOAuthTokenExpired(
    _ database: SQLiteControlDatabase,
    digest: Data,
    now: Date,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await database.validatedAccessToken(
            accessTokenDigest: digest,
            requireActiveSubject: false,
            now: now
        )
        XCTFail("password recovery left an OAuth family active", file: file, line: line)
    } catch {
        XCTAssertEqual(
            error as? OAuthControlStoreError,
            .expired,
            file: file,
            line: line
        )
    }
}

private func assertOAuthRefreshFamilyExpired(
    _ database: SQLiteControlDatabase,
    digest: Data,
    now: Date,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await database.refreshTokenFamily(
            refreshTokenDigest: digest,
            now: now
        )
        XCTFail(
            "password recovery left a target refresh family active",
            file: file,
            line: line
        )
    } catch {
        XCTAssertEqual(
            error as? OAuthControlStoreError,
            .expired,
            file: file,
            line: line
        )
    }
}

private func assertOAuthRefreshRedemptionExpired(
    _ database: SQLiteControlDatabase,
    issued: IssuedOAuthFamily,
    now: Date,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        try await database.redeemRefreshToken(
            refreshTokenDigest: issued.refreshDigest,
            replacement: OAuthIssuedTokenDigests(
                familyID: issued.familyID,
                accessTokenDigest: Data(repeating: 0x91, count: 32),
                refreshTokenDigest: Data(repeating: 0x92, count: 32),
                accessExpiresAt: now.addingTimeInterval(120),
                refreshExpiresAt: now.addingTimeInterval(240)
            ),
            requireActiveSubject: false,
            now: now
        )
        XCTFail(
            "password recovery allowed target refresh-token redemption",
            file: file,
            line: line
        )
    } catch {
        XCTAssertEqual(
            error as? OAuthControlStoreError,
            .expired,
            file: file,
            line: line
        )
    }
}
