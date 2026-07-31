import Foundation
import SQLiteNIO
@testable import SwanSQLite
import SwanCore
import SwanStorage
import XCTest

final class AccountEmailOutboxSQLiteTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let otherDID = "did:plc:bcdefghijklmnopqrstuvwxy"
    private let email = try! AccountEmailAddress("person@example.com")
    private let verifier =
        "$argon2id$v=19$m=65536,t=2,p=1$initialsalt$initial-precomputed-verifier"

    func testAssociationRequiresActiveAccountAdvancesRevisionAndInvalidatesDelivery() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let now = fixture.now
        let initial = try await fixture.database.createAccount(try registration())

        try await fixture.database.associateEmail(did: did, email: email, now: now)
        let associatedResult = try await fixture.database.account(did: did)
        let associated = try XCTUnwrap(associatedResult)
        XCTAssertGreaterThan(associated.updatedAt, initial.updatedAt)

        let request = try deliveryRequest(
            purpose: .verifyEmail,
            deliveryByte: 0x11,
            proofByte: 0x21,
            now: now.addingTimeInterval(1)
        )
        let enqueueResult = try await fixture.database.enqueueEmailProofDelivery(request)
        XCTAssertEqual(enqueueResult, .enqueued)

        _ = try await fixture.database.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: AccountLifecycleDeclaration(),
            now: now.addingTimeInterval(2)
        )
        let inactiveLease = try await fixture.database.claimNextEmailDelivery(
            workerID: "worker-a",
            now: now.addingTimeInterval(3),
            leaseDuration: 30
        )
        XCTAssertNil(inactiveLease)
        await XCTAssertThrowsAccountControlError(
            try await fixture.database.associateEmail(
                did: did,
                email: try AccountEmailAddress("new@example.com"),
                now: now.addingTimeInterval(4)
            ),
            expected: .invalidTransition
        )
    }

    func testPasswordRecoveryEnqueueIsExistenceOpaqueAndRequiresVerifiedActiveEmail() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let now = fixture.now
        _ = try await fixture.database.createAccount(try registration())
        try await fixture.database.associateEmail(did: did, email: email, now: now)

        let unknown = try passwordRecoveryRequest(
            email: AccountEmailAddress("unknown@example.com"),
            deliveryByte: 0x12,
            proofByte: 0x22,
            now: now
        )
        try await fixture.database.enqueuePasswordRecoveryDelivery(unknown)
        let blindWork = try await fixture.database.connection.query(
            "SELECT lookup_digest, expires_at, created_at FROM account_password_recovery_work"
        )
        XCTAssertEqual(blindWork.count, 1)
        let blindRow = try XCTUnwrap(blindWork.first)
        guard case let .blob(blindDigest) = blindRow.column("lookup_digest") else {
            return XCTFail("blind recovery marker was not stored as a blob")
        }
        XCTAssertEqual(blindDigest.readableBytes, 32)
        let blindColumns = try await fixture.database.connection.query(
            "PRAGMA table_info(account_password_recovery_work)"
        )
        let blindColumnNames = blindColumns.compactMap { row -> String? in
            guard case let .text(name) = row.column("name") else { return nil }
            return name
        }
        XCTAssertEqual(
            blindColumnNames,
            ["lookup_digest", "expires_at", "created_at"]
        )
        let unknownLease = try await fixture.database.claimNextEmailDelivery(
            workerID: "worker-a",
            now: now,
            leaseDuration: 30
        )
        XCTAssertNil(unknownLease)

        let verification = try deliveryRequest(
            purpose: .verifyEmail,
            deliveryByte: 0x13,
            proofByte: 0x23,
            now: now
        )
        _ = try await fixture.database.enqueueEmailProofDelivery(verification)
        let confirmed = try await fixture.database.confirmEmailProof(
            try AccountEmailConfirmationRequest(
                did: did,
                email: email,
                proofDigest: verification.proofDigest
            ),
            now: now.addingTimeInterval(1)
        )
        XCTAssertEqual(confirmed, .confirmed)

        let recovery = try passwordRecoveryRequest(
            email: email,
            deliveryByte: 0x14,
            proofByte: 0x24,
            now: now.addingTimeInterval(2)
        )
        try await fixture.database.enqueuePasswordRecoveryDelivery(recovery)
        let knownAndUnknownWork = try await fixture.database.connection.query(
            "SELECT lookup_digest FROM account_password_recovery_work"
        )
        XCTAssertEqual(knownAndUnknownWork.count, 2)
        let leaseResult = try await fixture.database.claimNextEmailDelivery(
            workerID: "worker-a",
            now: now.addingTimeInterval(2),
            leaseDuration: 30
        )
        let lease = try XCTUnwrap(leaseResult)
        XCTAssertEqual(lease.deliveryID, recovery.deliveryID)
        XCTAssertEqual(lease.did, did)
        XCTAssertEqual(lease.email, email)
        XCTAssertEqual(lease.purpose, .passwordRecovery)
    }

    func testPasswordRecoveryMarkersRespectGlobalCapacity() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock {
            try? await fixture.database.close()
            fixture.cleanup()
        }
        let now = fixture.now
        let capacity = SQLiteControlDatabase.maximumPasswordRecoveryWorkMarkers

        let seedValues = (0 ..< capacity).map { value in
            let digestHex = String(repeating: "00", count: 28)
                + String(format: "%08x", value)
            return "(X'"
                + digestHex
                + "', 1750000601000000, "
                + String(1750000001000000 + value)
                + ")"
        }.joined(separator: ",")
        _ = try await fixture.database.connection.query(
            "INSERT INTO account_password_recovery_work(lookup_digest, expires_at, created_at) VALUES "
                + seedValues
        )
        let seeded = try await fixture.database.connection.query(
            "SELECT COUNT(*) AS row_count FROM account_password_recovery_work"
        )
        XCTAssertEqual(seeded.first?.column("row_count")?.integer, capacity)

        let overflowRequest = try passwordRecoveryRequest(
            email: AccountEmailAddress("overflow@example.com"),
            deliveryByte: 0x41,
            proofByte: 0x51,
            lookupDigest: Data(repeating: 0xff, count: 32),
            now: now.addingTimeInterval(1)
        )
        do {
            try await fixture.database.enqueuePasswordRecoveryDelivery(
                overflowRequest
            )
            XCTFail("expected global recovery marker capacity to reject a new digest")
        } catch let error as SwanError {
            guard case .unavailable = error else {
                return XCTFail("unexpected Swan error: \(error)")
            }
        }

        let afterReject = try await fixture.database.connection.query(
            "SELECT COUNT(*) AS row_count FROM account_password_recovery_work"
        )
        XCTAssertEqual(
            afterReject.first?.column("row_count")?.integer,
            capacity
        )

        let existingDigest = Data(repeating: 0, count: 32)
        let existingRequest = try passwordRecoveryRequest(
            email: AccountEmailAddress("existing-marker@example.com"),
            deliveryByte: 0x42,
            proofByte: 0x52,
            lookupDigest: existingDigest,
            now: now.addingTimeInterval(2)
        )
        try await fixture.database.enqueuePasswordRecoveryDelivery(
            existingRequest
        )
        let afterRefresh = try await fixture.database.connection.query(
            "SELECT COUNT(*) AS row_count FROM account_password_recovery_work"
        )
        XCTAssertEqual(
            afterRefresh.first?.column("row_count")?.integer,
            capacity
        )
    }

    func testAccountRevisionRemainsMonotonicWhenWallClockMovesBackward() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock {
            try? await fixture.database.close()
            fixture.cleanup()
        }
        let associationTime = fixture.now
        _ = try await fixture.database.createAccount(try registration())
        try await fixture.database.associateEmail(
            did: did,
            email: email,
            now: associationTime
        )
        let associatedResult = try await fixture.database.account(did: did)
        let associated = try XCTUnwrap(associatedResult)

        let verification = try deliveryRequest(
            purpose: .verifyEmail,
            deliveryByte: 0x18,
            proofByte: 0x28,
            now: associationTime
        )
        _ = try await fixture.database.enqueueEmailProofDelivery(verification)
        let confirmed = try await fixture.database.confirmEmailProof(
            try AccountEmailConfirmationRequest(
                did: did,
                email: email,
                proofDigest: verification.proofDigest
            ),
            now: associationTime.addingTimeInterval(-10)
        )
        XCTAssertEqual(confirmed, .confirmed)
        let confirmedResult = try await fixture.database.account(did: did)
        let confirmedAccount = try XCTUnwrap(confirmedResult)
        XCTAssertGreaterThan(confirmedAccount.updatedAt, associated.updatedAt)

        let deactivated = try await fixture.database.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: AccountLifecycleDeclaration(),
            now: associationTime.addingTimeInterval(-20)
        )
        XCTAssertGreaterThan(
            deactivated.updatedAt,
            confirmedAccount.updatedAt
        )
    }

    func testLeaseSurvivesRestartAndRetryNeverPassesProofExpiry() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let now = fixture.now
        _ = try await fixture.database.createAccount(try registration())
        try await fixture.database.associateEmail(did: did, email: email, now: now)
        let request = try deliveryRequest(
            purpose: .verifyEmail,
            deliveryByte: 0x15,
            proofByte: 0x25,
            now: now,
            lifetime: 10
        )
        _ = try await fixture.database.enqueueEmailProofDelivery(request)

        let firstResult = try await fixture.database.claimNextEmailDelivery(
            workerID: "crashed-worker",
            now: now,
            leaseDuration: 2
        )
        let first = try XCTUnwrap(firstResult)
        XCTAssertEqual(first.attempts, 1)
        try await fixture.database.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: fixture.root)
        fixture.database = reopened
        let heldLease = try await reopened.claimNextEmailDelivery(
            workerID: "replacement",
            now: now.addingTimeInterval(1),
            leaseDuration: 2
        )
        XCTAssertNil(heldLease)
        let reclaimedResult = try await reopened.claimNextEmailDelivery(
            workerID: "replacement",
            now: now.addingTimeInterval(3),
            leaseDuration: 2
        )
        let reclaimed = try XCTUnwrap(reclaimedResult)
        XCTAssertEqual(reclaimed.deliveryID, request.deliveryID)
        XCTAssertEqual(reclaimed.attempts, 2)

        let disposition = try await reopened.retryEmailDelivery(
            deliveryID: reclaimed.deliveryID,
            workerID: "replacement",
            now: now.addingTimeInterval(4),
            policy: try AccountEmailRetryPolicy(
                maximumAttempts: 8,
                initialDelay: 8,
                maximumDelay: 30
            )
        )
        XCTAssertEqual(disposition, .expired)
        let expiredLease = try await reopened.claimNextEmailDelivery(
            workerID: "replacement",
            now: now.addingTimeInterval(5),
            leaseDuration: 2
        )
        XCTAssertNil(expiredLease)
    }

    func testDeletionCannotScrubAfterEmailWorkerCrossesNetworkFence() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let now = fixture.now
        _ = try await fixture.database.createAccount(try registration())
        try await fixture.database.associateEmail(did: did, email: email, now: now)
        let request = try deliveryRequest(
            purpose: .verifyEmail,
            deliveryByte: 0x19,
            proofByte: 0x29,
            now: now
        )
        _ = try await fixture.database.enqueueEmailProofDelivery(request)
        let leaseResult = try await fixture.database.claimNextEmailDelivery(
            workerID: "email-worker",
            now: now,
            leaseDuration: 30
        )
        let lease = try XCTUnwrap(leaseResult)

        let fenced = try await fixture.database.beginEmailDeliveryAttempt(
            deliveryID: lease.deliveryID,
            workerID: "email-worker",
            now: now.addingTimeInterval(1)
        )
        XCTAssertTrue(fenced)
        do {
            _ = try await fixture.database.beginDeletion(
                did: did,
                declaration: .init(),
                now: now.addingTimeInterval(2)
            )
            XCTFail("deletion scrubbed an email send already admitted to SMTP")
        } catch let error as AccountDeletionStoreError {
            XCTAssertEqual(error, .conflict)
        }

        let acknowledged = try await fixture.database.acknowledgeEmailDelivery(
            deliveryID: lease.deliveryID,
            workerID: "email-worker",
            now: now.addingTimeInterval(3)
        )
        XCTAssertTrue(acknowledged)
        _ = try await fixture.database.beginDeletion(
            did: did,
            declaration: .init(),
            now: now.addingTimeInterval(4)
        )
    }

    func testNetworkFenceExtendsShortClaimLeaseUntilBoundedAttemptWindow() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let now = fixture.now
        _ = try await fixture.database.createAccount(try registration())
        try await fixture.database.associateEmail(did: did, email: email, now: now)
        let request = try deliveryRequest(
            purpose: .verifyEmail,
            deliveryByte: 0x1c,
            proofByte: 0x2c,
            now: now
        )
        _ = try await fixture.database.enqueueEmailProofDelivery(request)
        let claimed = try await fixture.database.claimNextEmailDelivery(
            workerID: "email-worker",
            now: now,
            leaseDuration: 1
        )
        let lease = try XCTUnwrap(claimed)

        let fenced = try await fixture.database.beginEmailDeliveryAttempt(
            deliveryID: lease.deliveryID,
            workerID: "email-worker",
            now: now.addingTimeInterval(0.5)
        )
        XCTAssertTrue(fenced)
        do {
            _ = try await fixture.database.beginDeletion(
                did: did,
                declaration: .init(),
                now: now.addingTimeInterval(2)
            )
            XCTFail("deletion crossed a live SMTP fence after the claim lease expired")
        } catch let error as AccountDeletionStoreError {
            XCTAssertEqual(error, .conflict)
        }
        let replacement = try await fixture.database.claimNextEmailDelivery(
            workerID: "replacement-worker",
            now: now.addingTimeInterval(2),
            leaseDuration: 1
        )
        XCTAssertNil(replacement)
        let acknowledged = try await fixture.database.acknowledgeEmailDelivery(
            deliveryID: lease.deliveryID,
            workerID: "email-worker",
            now: now.addingTimeInterval(3)
        )
        XCTAssertTrue(acknowledged)
    }

    func testDeletionWinsBeforeEmailWorkerFenceAndWorkerCannotSend() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let now = fixture.now
        _ = try await fixture.database.createAccount(try registration())
        try await fixture.database.associateEmail(did: did, email: email, now: now)
        let request = try deliveryRequest(
            purpose: .verifyEmail,
            deliveryByte: 0x1a,
            proofByte: 0x2a,
            now: now
        )
        _ = try await fixture.database.enqueueEmailProofDelivery(request)
        let leaseResult = try await fixture.database.claimNextEmailDelivery(
            workerID: "email-worker",
            now: now,
            leaseDuration: 30
        )
        let lease = try XCTUnwrap(leaseResult)
        _ = try await fixture.database.beginDeletion(
            did: did,
            declaration: .init(),
            now: now.addingTimeInterval(1)
        )
        let fenced = try await fixture.database.beginEmailDeliveryAttempt(
            deliveryID: lease.deliveryID,
            workerID: "email-worker",
            now: now.addingTimeInterval(2)
        )
        XCTAssertFalse(fenced)
    }

    func testExpiredEmailLeaseCannotCrossNetworkFence() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let now = fixture.now
        _ = try await fixture.database.createAccount(try registration())
        try await fixture.database.associateEmail(did: did, email: email, now: now)
        let request = try deliveryRequest(
            purpose: .verifyEmail,
            deliveryByte: 0x1b,
            proofByte: 0x2b,
            now: now
        )
        _ = try await fixture.database.enqueueEmailProofDelivery(request)
        let leaseResult = try await fixture.database.claimNextEmailDelivery(
            workerID: "email-worker",
            now: now,
            leaseDuration: 1
        )
        let lease = try XCTUnwrap(leaseResult)

        let fenced = try await fixture.database.beginEmailDeliveryAttempt(
            deliveryID: lease.deliveryID,
            workerID: "email-worker",
            now: now.addingTimeInterval(2)
        )
        XCTAssertFalse(fenced)
    }

    func testTypedConfirmationDistinguishesBoundErrorsWithoutBurningProof() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let now = fixture.now
        _ = try await fixture.database.createAccount(try registration())
        try await fixture.database.associateEmail(did: did, email: email, now: now)
        let request = try deliveryRequest(
            purpose: .verifyEmail,
            deliveryByte: 0x16,
            proofByte: 0x26,
            now: now,
            lifetime: 5
        )
        _ = try await fixture.database.enqueueEmailProofDelivery(request)

        let wrongAccount = try await fixture.database.confirmEmailProof(
            try AccountEmailConfirmationRequest(
                did: otherDID,
                email: email,
                proofDigest: request.proofDigest
            ),
            now: now.addingTimeInterval(1)
        )
        XCTAssertEqual(wrongAccount, .accountNotFound)
        let wrongEmail = try await fixture.database.confirmEmailProof(
            try AccountEmailConfirmationRequest(
                did: did,
                email: AccountEmailAddress("attacker@example.com"),
                proofDigest: request.proofDigest
            ),
            now: now.addingTimeInterval(1)
        )
        XCTAssertEqual(wrongEmail, .invalidEmail)
        let wrongToken = try await fixture.database.confirmEmailProof(
            try AccountEmailConfirmationRequest(
                did: did,
                email: email,
                proofDigest: Data(repeating: 0xee, count: 32)
            ),
            now: now.addingTimeInterval(1)
        )
        XCTAssertEqual(wrongToken, .invalidToken)
        let expiredToken = try await fixture.database.confirmEmailProof(
            try AccountEmailConfirmationRequest(
                did: did,
                email: email,
                proofDigest: request.proofDigest
            ),
            now: now.addingTimeInterval(6)
        )
        XCTAssertEqual(expiredToken, .expiredToken)
    }

    func testRateLimitStateIsDurableAndScopedByHMACDigest() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let now = fixture.now
        let emailKey = try AccountEmailRateLimitKey(
            scope: .email,
            digest: Data(repeating: 0x31, count: 32)
        )
        let peerKey = try AccountEmailRateLimitKey(
            scope: .directPeer,
            digest: Data(repeating: 0x31, count: 32)
        )
        let policy = try AccountEmailRateLimitPolicy(
            maximumAttempts: 2,
            window: 60
        )

        let firstAttempt = try await fixture.database.consumeEmailRateLimit(
            key: emailKey,
            policy: policy,
            now: now
        )
        XCTAssertEqual(firstAttempt, .allowed(remaining: 1))
        let secondAttempt = try await fixture.database.consumeEmailRateLimit(
            key: emailKey,
            policy: policy,
            now: now.addingTimeInterval(1)
        )
        XCTAssertEqual(secondAttempt, .allowed(remaining: 0))
        let limited = try await fixture.database.consumeEmailRateLimit(
            key: emailKey,
            policy: policy,
            now: now.addingTimeInterval(2)
        )
        XCTAssertEqual(limited, .limited(until: now.addingTimeInterval(60)))
        let separateScope = try await fixture.database.consumeEmailRateLimit(
            key: peerKey,
            policy: policy,
            now: now.addingTimeInterval(2)
        )
        XCTAssertEqual(separateScope, .allowed(remaining: 1))

        try await fixture.database.close()
        let reopened = try await SQLiteControlDatabase(dataDirectory: fixture.root)
        fixture.database = reopened
        let durableLimit = try await reopened.consumeEmailRateLimit(
            key: emailKey,
            policy: policy,
            now: now.addingTimeInterval(3)
        )
        XCTAssertEqual(durableLimit, .limited(until: now.addingTimeInterval(60)))
    }

    private func deliveryRequest(
        email: AccountEmailAddress? = nil,
        purpose: AccountEmailTokenPurpose,
        deliveryByte: UInt8,
        proofByte: UInt8,
        now: Date,
        lifetime: TimeInterval = 600
    ) throws -> AccountEmailProofDeliveryRequest {
        try AccountEmailProofDeliveryRequest(
            deliveryID: AccountEmailDeliveryID(
                rawValue: Self.base64URL(Data(repeating: deliveryByte, count: 32))
            ),
            did: did,
            email: email ?? self.email,
            purpose: purpose,
            proofDigest: Data(repeating: proofByte, count: 32),
            expiresAt: now.addingTimeInterval(lifetime),
            now: now
        )
    }

    private func passwordRecoveryRequest(
        email: AccountEmailAddress,
        deliveryByte: UInt8,
        proofByte: UInt8,
        lookupDigest: Data? = nil,
        now: Date,
        lifetime: TimeInterval = 600
    ) throws -> AccountPasswordRecoveryDeliveryRequest {
        try AccountPasswordRecoveryDeliveryRequest(
            deliveryID: AccountEmailDeliveryID(
                rawValue: Self.base64URL(Data(repeating: deliveryByte, count: 32))
            ),
            email: email,
            proofDigest: Data(repeating: proofByte, count: 32),
            lookupDigest: lookupDigest,
            expiresAt: now.addingTimeInterval(lifetime),
            now: now
        )
    }

    private func registration() throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: "account-email-outbox.example.com",
            passwordVerifier: verifier,
            signingKey: try .init(purpose: .signing, generation: 1),
            rotationKey: try .init(purpose: .rotation, generation: 1),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private final class Fixture: @unchecked Sendable {
    let root: URL
    var database: SQLiteControlDatabase
    let now = Date(timeIntervalSince1970: 1_750_000_001)

    init(testCase _: XCTestCase) async throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanAccountEmailOutbox-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        database = try await SQLiteControlDatabase(dataDirectory: root)
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }
}

private func XCTAssertThrowsAccountControlError<T: Sendable>(
    _ expression: @autoclosure () async throws -> T,
    expected: AccountControlStoreError,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected \(expected)", file: file, line: line)
    } catch {
        XCTAssertEqual(error as? AccountControlStoreError, expected, file: file, line: line)
    }
}
