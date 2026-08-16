import Crypto
import Foundation
@testable import SwanAccounts
@testable import SwanCore
@testable import SwanSQLite
@testable import SwanStorage
import XCTest

/// Task 3: the connection-scoped foundation writer must roll back account,
/// identity binding, management session, invite/proof consumption, and the
/// finalization result together when any single write fails. Each stage is
/// injected with a failure in isolation; after the failure the durable state
/// must be exactly as it was before the transaction.
final class SignupTransactionRollbackTests: XCTestCase {
    func testInjectedFailureAtEachWriteStageRollsBackEverything() async throws {
        for stage in ["account", "identity", "session"] {
            let root = try rollbackTestRoot()
            defer { try? FileManager.default.removeItem(at: root) }
            let database = try await SQLiteControlDatabase(dataDirectory: root)
            defer { Task { try? await database.close() } }

            let now = Date().addingTimeInterval(-60)
            let did = "did:plc:abcdefghijklmnopqrstuvwx"
            let handle = "alice.example.com"
            let email = try AccountEmailAddress("alice@example.com")
            let secret = try SignupSecret(Data(repeating: 0x24, count: 32))
            let proofService = SignupEmailProofService(secret: secret)
            let inviteService = SignupInviteService(secret: secret)

            // Seed the durable signup state: an invite, an email proof, and a
            // pending authorization that the finalization transaction consumes.
            let invite = try inviteService.issue(code: "invite-code-1234567890", expiresAt: now.addingTimeInterval(600))
            try await database.persistInvite(try SignupInvite(digest: invite.digest, issuedAt: now, expiresAt: now.addingTimeInterval(600)))
            let proofCode = "proof-code-123456789012"
            let proofDigest = try proofService.digest(code: proofCode, email: email, handle: handle)
            try await database.insertSignupEmailProof(digest: proofDigest, email: email, handle: handle, issuedAt: now, expiresAt: now.addingTimeInterval(600))

            let requestID = "request-\(stage)"
            let authorizationID = try SignupAuthorizationID(rawValue: requestID)
            let peer = try SocketAddressSignupPeerExtractor(serverSecret: Data(repeating: 9, count: 32))
                .bucket(forCanonicalPeerIP: "192.0.2.1")
            let authorization = try SignupAuthorization(
                id: authorizationID,
                requestID: requestID,
                policy: .inviteRequired,
                handle: handle,
                email: email.value,
                identityDID: did,
                emailProofDigest: proofDigest,
                inviteDigest: invite.digest,
                clientIPBucketDigest: peer.digest,
                issuedAt: now,
                expiresAt: now.addingTimeInterval(600),
                leaseExpiresAt: now.addingTimeInterval(120)
            )
            try await database.reserve(authorization, now: now)

            // Build the finalization request exactly as the production
            // provisioning conformer does.
            let sessionID = try ManagementSessionID(rawValue: String(repeating: "a", count: 43))
            let sessionDigest = Data(repeating: 0x02, count: 32)
            let csrfDigest = Data(repeating: 0x03, count: 32)
            let metadata = try ManagementSessionMetadata(
                sessionID: sessionID,
                accountDID: did,
                issuedAt: now,
                idleExpiresAt: now.addingTimeInterval(60),
                absoluteExpiresAt: now.addingTimeInterval(600),
                strength: .password
            )
            let request = try SignupFinalizationRequest(
                authorizationID: authorizationID,
                accountDID: did,
                handle: handle,
                identityDID: did,
                reservedKeyID: "account-signing:1",
                managementSession: metadata,
                sessionDigest: sessionDigest,
                csrfDigest: csrfDigest,
                emailProofDigest: proofDigest,
                inviteDigest: invite.digest,
                preAuthCSRFDigest: csrfDigest,
                idempotencyKey: requestID
            )

            // The writer fails at exactly the named stage.
            let writer = SQLiteSignupFoundationWriter(
                verifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingReference: "account-signing:1",
                rotationReference: "account-rotation:1",
                injecting: { name in
                    if name == stage {
                        throw AccountControlStoreError.unavailable
                    }
                }
            )
            let coordinator = AssembledSQLiteSignupCoordinator(database: database, writer: writer)
            do {
                _ = try await coordinator.finalizeSignup(request, now: now)
                XCTFail("stage \(stage) must fail")
            } catch {}

            // Nothing may have been committed: no account, no identity
            // binding, no management session, no consumed proof/invite, no
            // persisted result, and the authorization still pending.
            let accountAfter = try await database.account(did: did)
            XCTAssertNil(accountAfter, "stage \(stage) leaked an account")
            let bindingAfter = try await database.identityBinding(accountDID: did)
            XCTAssertNil(bindingAfter, "stage \(stage) leaked an identity binding")
            let sessionAfter = try await database.managementSession(digest: sessionDigest, now: now)
            XCTAssertNil(sessionAfter, "stage \(stage) leaked a management session")
            let storedInvite = try await database.listInvites(limit: 10).first { $0.digest == invite.digest }
            XCTAssertNil(storedInvite?.redeemedAt, "stage \(stage) consumed the invite")
            let storedProof = try await database.verifySubmittedCode(
                proofCode, email: email, handle: handle,
                authorizationID: authorizationID, proof: proofService, now: now
            )
            XCTAssertEqual(storedProof, proofDigest, "stage \(stage) consumed the email proof")
            let storedAuthorization = try await database.authorization(id: authorizationID, now: now)
            XCTAssertEqual(storedAuthorization?.state, .issued, "stage \(stage) mutated the authorization state")
        }
    }

    func testSuccessfulFinalizationCommitsAllRowsAtomically() async throws {
        let root = try rollbackTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }

        let now = Date().addingTimeInterval(-60)
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let handle = "bob.example.com"
        let email = try AccountEmailAddress("bob@example.com")
        let secret = try SignupSecret(Data(repeating: 0x25, count: 32))
        let proofService = SignupEmailProofService(secret: secret)
        let inviteService = SignupInviteService(secret: secret)

        let invite = try inviteService.issue(code: "invite-code-0987654321", expiresAt: now.addingTimeInterval(600))
        try await database.persistInvite(try SignupInvite(digest: invite.digest, issuedAt: now, expiresAt: now.addingTimeInterval(600)))
        let proofCode = "proof-code-987654321098"
        let proofDigest = try proofService.digest(code: proofCode, email: email, handle: handle)
        try await database.insertSignupEmailProof(digest: proofDigest, email: email, handle: handle, issuedAt: now, expiresAt: now.addingTimeInterval(600))

        let requestID = "request-commit"
        let authorizationID = try SignupAuthorizationID(rawValue: requestID)
        let peer = try SocketAddressSignupPeerExtractor(serverSecret: Data(repeating: 9, count: 32))
            .bucket(forCanonicalPeerIP: "192.0.2.1")
        let authorization = try SignupAuthorization(
            id: authorizationID,
            requestID: requestID,
            policy: .inviteRequired,
            handle: handle,
            email: email.value,
            identityDID: did,
            emailProofDigest: proofDigest,
            inviteDigest: invite.digest,
            clientIPBucketDigest: peer.digest,
            issuedAt: now,
            expiresAt: now.addingTimeInterval(600),
            leaseExpiresAt: now.addingTimeInterval(120)
        )
        try await database.reserve(authorization, now: now)

        let sessionID = try ManagementSessionID(rawValue: String(repeating: "b", count: 43))
        let sessionDigest = Data(repeating: 0x04, count: 32)
        let csrfDigest = Data(repeating: 0x05, count: 32)
        let metadata = try ManagementSessionMetadata(
            sessionID: sessionID,
            accountDID: did,
            issuedAt: now,
            idleExpiresAt: now.addingTimeInterval(60),
            absoluteExpiresAt: now.addingTimeInterval(600),
            strength: .password
        )
        let request = try SignupFinalizationRequest(
            authorizationID: authorizationID,
            accountDID: did,
            handle: handle,
            identityDID: did,
            reservedKeyID: "account-signing:1",
            managementSession: metadata,
            sessionDigest: sessionDigest,
            csrfDigest: csrfDigest,
            emailProofDigest: proofDigest,
            inviteDigest: invite.digest,
            preAuthCSRFDigest: csrfDigest,
            idempotencyKey: requestID
        )
        let writer = SQLiteSignupFoundationWriter(
            verifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingReference: "account-signing:1",
            rotationReference: "account-rotation:1",
            injecting: nil
        )
        let coordinator = AssembledSQLiteSignupCoordinator(database: database, writer: writer)
        let result = try await coordinator.finalizeSignup(request, now: now)
        XCTAssertEqual(result.accountDID, did)
        XCTAssertEqual(result.managementSessionID, sessionID)

        let accountAfter = try await database.account(did: did)
        XCTAssertNotNil(accountAfter)
        let bindingAfter = try await database.identityBinding(accountDID: did)
        XCTAssertNotNil(bindingAfter)
        let sessionAfter = try await database.managementSession(digest: sessionDigest, now: now)
        XCTAssertNotNil(sessionAfter)
        let storedInvite = try await database.listInvites(limit: 10).first { $0.digest == invite.digest }
        XCTAssertNotNil(storedInvite?.redeemedAt)
        XCTAssertEqual(storedInvite?.redemptionAccountDID, did)
        do {
            _ = try await database.verifySubmittedCode(
                proofCode, email: email, handle: handle,
                authorizationID: authorizationID, proof: proofService, now: now
            )
            XCTFail("consumed proof must not verify")
        } catch {}
        let storedAuthorization = try await database.authorization(id: authorizationID, now: now)
        XCTAssertEqual(storedAuthorization?.state, .committed)

        // A retry with the same request returns the persisted result without
        // minting a second identity.
        let retry = try await coordinator.finalizeSignup(request, now: now)
        XCTAssertEqual(retry.accountDID, did)
        XCTAssertEqual(retry.managementSessionID, sessionID)
    }

    private func rollbackTestRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("swan-signup-rollback-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        return root
    }
}
