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
            [
                "lookup_digest", "expires_at", "created_at",
                "account_candidate",
                "delivery_id", "proof_digest", "email_envelope",
                "lease_owner", "lease_expires_at", "attempts",
            ]
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
        let discardedWorkResult =
            try await fixture.database.claimNextPasswordRecoveryWork(
                workerID: "worker-a",
                now: now.addingTimeInterval(2),
                leaseDuration: 30
            )
        let discardedWork = try XCTUnwrap(
            discardedWorkResult
        )
        let discardedOutcome =
            try await fixture.database.materializePasswordRecoveryWork(
                discardedWork,
                email: try AccountEmailAddress("unknown@example.com"),
                workerID: "worker-a",
                now: now.addingTimeInterval(2)
            )
        XCTAssertEqual(discardedOutcome,
            .discarded
        )
        let knownWorkResult =
            try await fixture.database.claimNextPasswordRecoveryWork(
                workerID: "worker-a",
                now: now.addingTimeInterval(2),
                leaseDuration: 30
            )
        let knownWork = try XCTUnwrap(
            knownWorkResult
        )
        let knownOutcome =
            try await fixture.database.materializePasswordRecoveryWork(
                knownWork,
                email: email,
                workerID: "worker-a",
                now: now.addingTimeInterval(2)
            )
        XCTAssertEqual(knownOutcome,
            .enqueued
        )
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

    func testVerifiedAccountUsesReservedRecoveryCapacityAfterAnonymousPartitionFills() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock {
            try? await fixture.database.close()
            fixture.cleanup()
        }
        let now = fixture.now
        _ = try await fixture.database.createAccount(try registration())
        try await fixture.database.associateEmail(did: did, email: email, now: now)
        let verification = try deliveryRequest(
            purpose: .verifyEmail,
            deliveryByte: 0x61,
            proofByte: 0x71,
            now: now
        )
        _ = try await fixture.database.enqueueEmailProofDelivery(verification)
        let confirmation = try await fixture.database.confirmEmailProof(
            try AccountEmailConfirmationRequest(
                did: did,
                email: email,
                proofDigest: verification.proofDigest
            ),
            now: now
        )
        XCTAssertEqual(confirmation, .confirmed)

        let anonymousCapacity =
            SQLiteControlDatabase.maximumPasswordRecoveryWorkMarkers
            - SQLiteControlDatabase.passwordRecoveryKnownAccountReserve
        let seedValues = (0 ..< anonymousCapacity).map { value in
            let digestHex = String(repeating: "00", count: 28)
                + String(format: "%08x", value)
            return "(X'" + digestHex
                + "', 1750000601000000, "
                + String(1750000001000000 + value) + ")"
        }.joined(separator: ",")
        _ = try await fixture.database.connection.query(
            "INSERT INTO account_password_recovery_work(lookup_digest, expires_at, created_at) VALUES "
                + seedValues
        )

        do {
            try await fixture.database.enqueuePasswordRecoveryDelivery(
                try passwordRecoveryRequest(
                    email: AccountEmailAddress("still-unknown@example.com"),
                    deliveryByte: 0x62,
                    proofByte: 0x72,
                    lookupDigest: Data(repeating: 0xfe, count: 32),
                    now: now.addingTimeInterval(1)
                )
            )
            XCTFail("anonymous recovery work consumed the reserved partition")
        } catch let error as SwanError {
            guard case .unavailable = error else {
                return XCTFail("unexpected Swan error: \(error)")
            }
        }

        try await fixture.database.enqueuePasswordRecoveryDelivery(
            try passwordRecoveryRequest(
                email: email,
                deliveryByte: 0x63,
                proofByte: 0x73,
                lookupDigest: Data(repeating: 0xfd, count: 32),
                now: now.addingTimeInterval(2)
            )
        )
        let rows = try await fixture.database.connection.query(
            "SELECT account_candidate FROM account_password_recovery_work WHERE lookup_digest = ?",
            [.blob(ByteBuffer(data: Data(repeating: 0xfd, count: 32)))]
        )
        XCTAssertEqual(rows.first?.column("account_candidate")?.integer, 1)
    }

    func testPasswordRecoveryRequestPurgesOnlyOneBoundedBatchOfExpiredMarkers() async throws {
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
                + "', 1749999900000000, "
                + String(1749999800000000 + value)
                + ")"
        }.joined(separator: ",")
        _ = try await fixture.database.connection.query(
            "INSERT INTO account_password_recovery_work(lookup_digest, expires_at, created_at) VALUES "
                + seedValues
        )

        let request = try passwordRecoveryRequest(
            email: AccountEmailAddress("bounded-cleanup@example.com"),
            deliveryByte: 0x43,
            proofByte: 0x53,
            lookupDigest: Data(repeating: 0xff, count: 32),
            now: now
        )
        try await fixture.database.enqueuePasswordRecoveryDelivery(request)

        let remaining = try await fixture.database.connection.query(
            "SELECT COUNT(*) AS row_count FROM account_password_recovery_work"
        )
        // One bounded purge plus the new marker.  If this request regresses
        // to a predicate-only DELETE, the count would be one instead.
        let expectedRemaining = 3_840 // 4,096 - 257 + 1
        XCTAssertEqual(
            remaining.first?.column("row_count")?.integer,
            expectedRemaining
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

    func testPasswordRecoveryWorkLeaseRequeuesAfterRestartBeforeMaterialization()
        async throws
    {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock {
            try? await fixture.database.close()
            fixture.cleanup()
        }
        let now = fixture.now
        _ = try await fixture.database.createAccount(try registration())
        try await fixture.database.associateEmail(did: did, email: email, now: now)

        let verification = try deliveryRequest(
            purpose: .verifyEmail,
            deliveryByte: 0x31,
            proofByte: 0x41,
            now: now
        )
        _ = try await fixture.database.enqueueEmailProofDelivery(verification)
        let confirmation = try await fixture.database.confirmEmailProof(
            try AccountEmailConfirmationRequest(
                did: did,
                email: email,
                proofDigest: verification.proofDigest
            ),
            now: now.addingTimeInterval(1)
        )
        XCTAssertEqual(confirmation,
            .confirmed
        )

        let request = try passwordRecoveryRequest(
            email: email,
            deliveryByte: 0x32,
            proofByte: 0x42,
            now: now.addingTimeInterval(2)
        )
        try await fixture.database.enqueuePasswordRecoveryDelivery(request)
        let firstResult =
            try await fixture.database.claimNextPasswordRecoveryWork(
                workerID: "crashed-worker",
                now: now.addingTimeInterval(2),
                leaseDuration: 2
            )
        let first = try XCTUnwrap(
            firstResult
        )
        try await fixture.database.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: fixture.root)
        fixture.database = reopened
        let heldWork = try await reopened.claimNextPasswordRecoveryWork(
            workerID: "replacement",
            now: now.addingTimeInterval(3),
            leaseDuration: 2
        )
        XCTAssertNil(heldWork)
        let reclaimedResult =
            try await reopened.claimNextPasswordRecoveryWork(
                workerID: "replacement",
                now: now.addingTimeInterval(5),
                leaseDuration: 2
            )
        let reclaimed = try XCTUnwrap(
            reclaimedResult
        )
        XCTAssertEqual(reclaimed.deliveryID, first.deliveryID)
        let materialization =
            try await reopened.materializePasswordRecoveryWork(
                reclaimed,
                email: email,
                workerID: "replacement",
                now: now.addingTimeInterval(5)
            )
        XCTAssertEqual(materialization,
            .enqueued
        )
        let deliveryLease = try await reopened.claimNextEmailDelivery(
            workerID: "replacement",
            now: now.addingTimeInterval(5),
            leaseDuration: 30
        )
        XCTAssertNotNil(deliveryLease)
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

    func testExpiryPurgePreservesAnInFlightSendFence() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let now = fixture.now
        _ = try await fixture.database.createAccount(try registration())
        try await fixture.database.associateEmail(did: did, email: email, now: now)
        let request = try deliveryRequest(
            purpose: .verifyEmail,
            deliveryByte: 0x1d,
            proofByte: 0x2d,
            now: now,
            lifetime: 1
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
            now: now.addingTimeInterval(0.5)
        )
        XCTAssertTrue(fenced)

        // The proof has expired, but the bounded SMTP fence is still live.
        // Purging it would make permanent deletion forget that network I/O
        // was admitted and permit a late send after account deletion.
        try await fixture.database.purgeExpiredEmailRecoveryState(
            now: now.addingTimeInterval(2)
        )
        let retained = try await fixture.database.connection.query(
            "SELECT delivery_id FROM account_email_delivery_outbox WHERE delivery_id = ?",
            [.text(lease.deliveryID.rawValue)]
        )
        XCTAssertEqual(retained.count, 1)
        do {
            _ = try await fixture.database.beginDeletion(
                did: did,
                declaration: .init(),
                now: now.addingTimeInterval(2)
            )
            XCTFail("deletion crossed the retained in-flight send fence")
        } catch let error as AccountDeletionStoreError {
            XCTAssertEqual(error, .conflict)
        }
    }

    func testEmailDeliveryClaimPurgesExpiredProofsInBoundedPagesUntilConverged() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let now = fixture.now
        _ = try await fixture.database.createAccount(try registration())
        try await fixture.database.associateEmail(did: did, email: email, now: now)
        let backlog = 263
        try await seedEmailRecoveryRows(
            in: fixture.database,
            count: backlog,
            expiresAt: now.addingTimeInterval(-1)
        )

        let firstClaim = try await fixture.database.claimNextEmailDelivery(
            workerID: "bounded-purge-worker",
            now: now,
            leaseDuration: 30
        )
        XCTAssertNil(firstClaim)
        let afterOneClaim = try await emailRecoveryRowCounts(in: fixture.database)
        XCTAssertEqual(afterOneClaim.tokens, 7)
        XCTAssertEqual(afterOneClaim.outbox, 7)

        let secondClaim = try await fixture.database.claimNextEmailDelivery(
            workerID: "bounded-purge-worker",
            now: now,
            leaseDuration: 30
        )
        XCTAssertNil(secondClaim)
        let converged = try await emailRecoveryRowCounts(in: fixture.database)
        XCTAssertEqual(converged.tokens, 0)
        XCTAssertEqual(converged.outbox, 0)
    }

    func testEmailDeliveryClaimResetsExpiredLeasesInBoundedPagesUntilConverged() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let now = fixture.now
        _ = try await fixture.database.createAccount(try registration())
        try await fixture.database.associateEmail(did: did, email: email, now: now)
        try await seedExpiredLeasedOutboxRows(
            in: fixture.database,
            count: 263,
            now: now
        )

        let firstClaim = try await fixture.database.claimNextEmailDelivery(
            workerID: "bounded-lease-reset-worker",
            now: now,
            leaseDuration: 30
        )
        XCTAssertNil(firstClaim)
        let afterOneClaim = try await emailDeliveryStateCounts(
            in: fixture.database
        )
        XCTAssertEqual(afterOneClaim.pending, 256)
        XCTAssertEqual(afterOneClaim.leased, 7)

        let secondClaim = try await fixture.database.claimNextEmailDelivery(
            workerID: "bounded-lease-reset-worker",
            now: now,
            leaseDuration: 30
        )
        XCTAssertNil(secondClaim)
        let converged = try await emailDeliveryStateCounts(in: fixture.database)
        XCTAssertEqual(converged.pending, 263)
        XCTAssertEqual(converged.leased, 0)
    }

    func testDeactivationPurgesProofsInBoundedPagesAndRetainsSendFence() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let now = fixture.now
        _ = try await fixture.database.createAccount(try registration())
        try await fixture.database.associateEmail(did: did, email: email, now: now)
        let fencedRequest = try deliveryRequest(
            purpose: .verifyEmail,
            deliveryByte: 0x1e,
            proofByte: 0x2e,
            now: now
        )
        _ = try await fixture.database.enqueueEmailProofDelivery(fencedRequest)
        let leaseResult = try await fixture.database.claimNextEmailDelivery(
            workerID: "lifecycle-fence-worker",
            now: now,
            leaseDuration: 1
        )
        let lease = try XCTUnwrap(leaseResult)
        let fenced = try await fixture.database.beginEmailDeliveryAttempt(
            deliveryID: lease.deliveryID,
            workerID: "lifecycle-fence-worker",
            now: now.addingTimeInterval(0.5)
        )
        XCTAssertTrue(fenced)
        try await seedEmailRecoveryRows(
            in: fixture.database,
            count: 263,
            expiresAt: now.addingTimeInterval(600)
        )

        _ = try await fixture.database.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: .init(),
            now: now.addingTimeInterval(2)
        )
        let afterOneTransition = try await emailRecoveryRowCounts(
            in: fixture.database
        )
        XCTAssertEqual(afterOneTransition.tokens, 8)
        XCTAssertEqual(afterOneTransition.outbox, 8)
        await XCTAssertThrowsAccountControlError(
            try await fixture.database.transitionStatus(
                did: did,
                to: .active,
                declaration: .init(),
                now: now.addingTimeInterval(3)
            ),
            expected: .invalidTransition
        )

        _ = try await fixture.database.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: .init(),
            now: now.addingTimeInterval(3)
        )
        let fencedResidue = try await emailRecoveryRowCounts(in: fixture.database)
        XCTAssertEqual(fencedResidue.tokens, 0)
        XCTAssertEqual(fencedResidue.outbox, 1)
        let retainedFence = try await fixture.database.connection.query(
            "SELECT delivery_id FROM account_email_delivery_outbox WHERE delivery_id = ?",
            [.text(lease.deliveryID.rawValue)]
        )
        XCTAssertEqual(retainedFence.count, 1)
        await XCTAssertThrowsAccountControlError(
            try await fixture.database.transitionStatus(
                did: did,
                to: .active,
                declaration: .init(),
                now: now.addingTimeInterval(4)
            ),
            expected: .invalidTransition
        )

        _ = try await fixture.database.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: .init(),
            now: now.addingTimeInterval(302)
        )
        let converged = try await emailRecoveryRowCounts(in: fixture.database)
        XCTAssertEqual(converged.tokens, 0)
        XCTAssertEqual(converged.outbox, 0)
        let reactivated = try await fixture.database.transitionStatus(
            did: did,
            to: .active,
            declaration: .init(),
            now: now.addingTimeInterval(303)
        )
        XCTAssertEqual(reactivated.status, .active)
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

    func testRateLimitGlobalCapacityDoesNotAllocateUnboundedEmailKeys() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let now = fixture.now
        let policy = try AccountEmailRateLimitPolicy(maximumAttempts: 2, window: 60)
        let capacity = SQLiteControlDatabase.maximumEmailRateLimitEntries

        // Fill every globally admitted digest through the same durable API.
        // A hostile caller can choose a fresh email digest on every request;
        // the table must stop allocating before the process runs out of disk.
        for index in 0 ..< capacity {
            var digest = Data(repeating: 0, count: 32)
            withUnsafeBytes(of: UInt32(index).bigEndian) { bytes in
                digest.replaceSubrange(28 ..< 32, with: bytes)
            }
            let result = try await fixture.database.consumeEmailRateLimit(
                key: try AccountEmailRateLimitKey(scope: .email, digest: digest),
                policy: policy,
                now: now
            )
            XCTAssertEqual(result, .allowed(remaining: 1))
        }

        let before = try await fixture.database.connection.query(
            "SELECT COUNT(*) AS row_count FROM account_email_rate_limits"
        )
        XCTAssertEqual(before.first?.column("row_count")?.integer, capacity)

        let overflow = try await fixture.database.consumeEmailRateLimit(
            key: try AccountEmailRateLimitKey(
                scope: .email,
                digest: Data(repeating: 0xff, count: 32)
            ),
            policy: policy,
            now: now
        )
        guard case .limited = overflow else {
            return XCTFail("a fresh digest must be denied once the global table capacity is full")
        }

        let after = try await fixture.database.connection.query(
            "SELECT COUNT(*) AS row_count FROM account_email_rate_limits"
        )
        XCTAssertEqual(after.first?.column("row_count")?.integer, capacity)
    }

    func testLegacyRateLimitSchemaMigratesToExpiringBoundedTable() async throws {
        let fixture = try await Fixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let now = fixture.now
        try await fixture.database.close()

        let legacy = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.controlDatabase(in: fixture.root).path)
        )
        _ = try await legacy.query("DROP TABLE account_email_rate_limits")
        _ = try await legacy.query(
            """
            CREATE TABLE account_email_rate_limits (
                scope TEXT NOT NULL,
                key_digest BLOB NOT NULL,
                window_started_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL,
                PRIMARY KEY(scope, key_digest)
            ) WITHOUT ROWID
            """
        )
        let digest = Data(repeating: 0x44, count: 32)
        _ = try await legacy.query(
            """
            INSERT INTO account_email_rate_limits(
                scope, key_digest, window_started_at, attempts
            ) VALUES ('email', ?, ?, 2)
            """,
            [
                digest.sqliteData!,
                .integer(Int(now.timeIntervalSince1970 * 1_000_000)),
            ]
        )
        try await legacy.close()

        let migrated = try await SQLiteControlDatabase(dataDirectory: fixture.root)
        fixture.database = migrated
        let columns = try await migrated.connection.query(
            "PRAGMA table_info(account_email_rate_limits)"
        )
        XCTAssertTrue(columns.contains { $0.column("name")?.string == "expires_at" })
        let capacityRows = try await migrated.connection.query(
            "SELECT entry_count FROM account_email_rate_limit_capacity WHERE singleton = 1"
        )
        XCTAssertEqual(capacityRows.first?.column("entry_count")?.integer, 1)
        let decision = try await migrated.consumeEmailRateLimit(
            key: try AccountEmailRateLimitKey(scope: .email, digest: digest),
            policy: try AccountEmailRateLimitPolicy(maximumAttempts: 2, window: 60),
            now: now.addingTimeInterval(1)
        )
        guard case .limited = decision else {
            return XCTFail("legacy attempts must remain active during migration")
        }
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
            proofDigest: Data(repeating: proofByte, count: 32),
            email: email,
            lookupDigest: lookupDigest ?? Data(repeating: proofByte, count: 32),
            emailEnvelope: Data(repeating: 0x5a, count: 32),
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

    private func seedEmailRecoveryRows(
        in database: SQLiteControlDatabase,
        count: Int,
        expiresAt: Date
    ) async throws {
        let emailRows = try await database.connection.query(
            "SELECT updated_at FROM account_emails WHERE did = ?",
            [.text(did)]
        )
        let generation = try XCTUnwrap(
            emailRows.first?.column("updated_at")?.integer
        )
        let expiry = Int(expiresAt.timeIntervalSince1970 * 1_000_000)
        var tokenValues: [String] = []
        var outboxValues: [String] = []
        tokenValues.reserveCapacity(count)
        outboxValues.reserveCapacity(count)
        for value in 0 ..< count {
            var bytes = Data(repeating: 0, count: 32)
            let suffix = withUnsafeBytes(of: UInt32(value).bigEndian) {
                Array($0)
            }
            bytes.replaceSubrange(
                28 ..< 32,
                with: suffix
            )
            let digestHex = bytes.map { String(format: "%02x", $0) }.joined()
            let deliveryID = Self.base64URL(bytes)
            tokenValues.append(
                "(X'\(digestHex)', '\(did)', '\(email.value)', "
                    + "'verify-email', \(expiry), NULL, '\(deliveryID)')"
            )
            outboxValues.append(
                "('\(deliveryID)', '\(did)', '\(email.value)', \(generation), "
                    + "'verify-email', \(expiry), 'pending', NULL, NULL, 0, "
                    + "\(expiry), \(expiry), NULL, NULL)"
            )
        }
        _ = try await database.connection.query(
            """
            INSERT INTO account_email_tokens(
                digest, did, email, purpose, expires_at, consumed_at, delivery_id
            ) VALUES
            """ + tokenValues.joined(separator: ",")
        )
        _ = try await database.connection.query(
            """
            INSERT INTO account_email_delivery_outbox(
                delivery_id, did, email, email_generation, purpose, expires_at,
                state, lease_owner, lease_expires_at, attempts, next_attempt_at,
                created_at, send_started_at, sent_at
            ) VALUES
            """ + outboxValues.joined(separator: ",")
        )
    }

    private func emailRecoveryRowCounts(
        in database: SQLiteControlDatabase
    ) async throws -> (tokens: Int, outbox: Int) {
        let tokens = try await database.connection.query(
            "SELECT COUNT(*) AS row_count FROM account_email_tokens"
        )
        let outbox = try await database.connection.query(
            "SELECT COUNT(*) AS row_count FROM account_email_delivery_outbox"
        )
        return (
            try XCTUnwrap(tokens.first?.column("row_count")?.integer),
            try XCTUnwrap(outbox.first?.column("row_count")?.integer)
        )
    }

    private func seedExpiredLeasedOutboxRows(
        in database: SQLiteControlDatabase,
        count: Int,
        now: Date
    ) async throws {
        let emailRows = try await database.connection.query(
            "SELECT updated_at FROM account_emails WHERE did = ?",
            [.text(did)]
        )
        let generation = try XCTUnwrap(
            emailRows.first?.column("updated_at")?.integer
        )
        let timestamp = Int(now.timeIntervalSince1970 * 1_000_000)
        var values: [String] = []
        values.reserveCapacity(count)
        for value in 0 ..< count {
            var bytes = Data(repeating: 0xff, count: 32)
            let suffix = withUnsafeBytes(of: UInt32(value).bigEndian) {
                Array($0)
            }
            bytes.replaceSubrange(28 ..< 32, with: suffix)
            let deliveryID = Self.base64URL(bytes)
            values.append(
                "('\(deliveryID)', '\(did)', '\(email.value)', \(generation), "
                    + "'verify-email', \(timestamp + 600_000_000), 'leased', "
                    + "'expired-worker', \(timestamp - 1), 1, \(timestamp), "
                    + "\(timestamp - count + value), NULL, NULL)"
            )
        }
        _ = try await database.connection.query(
            """
            INSERT INTO account_email_delivery_outbox(
                delivery_id, did, email, email_generation, purpose, expires_at,
                state, lease_owner, lease_expires_at, attempts, next_attempt_at,
                created_at, send_started_at, sent_at
            ) VALUES
            """ + values.joined(separator: ",")
        )
    }

    private func emailDeliveryStateCounts(
        in database: SQLiteControlDatabase
    ) async throws -> (pending: Int, leased: Int) {
        let rows = try await database.connection.query(
            """
            SELECT state, COUNT(*) AS row_count
            FROM account_email_delivery_outbox
            GROUP BY state
            """
        )
        var counts = (pending: 0, leased: 0)
        for row in rows {
            switch row.column("state")?.string {
            case "pending":
                counts.pending = try XCTUnwrap(row.column("row_count")?.integer)
            case "leased":
                counts.leased = try XCTUnwrap(row.column("row_count")?.integer)
            default:
                XCTFail("unexpected email delivery state")
            }
        }
        return counts
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
