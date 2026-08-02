import Dispatch
import Foundation
@testable import SwanAccounts
import SwanSQLite
import SwanStorage
import XCTest

final class AccountEmailOutboxRuntimeTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let email = try! AccountEmailAddress("person@example.com")
    private let verifier =
        "$argon2id$v=19$m=65536,t=2,p=1$initialsalt$initial-precomputed-verifier"

    func testCanonicalMailboxValidatorIsStrictAndNormalizesOneRepresentation() throws {
        XCTAssertEqual(
            try AccountEmailAddress("Person+tag@Example.COM").value,
            "person+tag@example.com"
        )
        for invalid in [
            "\"quoted\"@example.com",
            ".leading@example.com",
            "trailing.@example.com",
            "double..dot@example.com",
            "person@-example.com",
            "person@example-.com",
            "person@example..com",
            "person@exa_mple.com",
            "person@éxample.com",
            "person@example.com\r\nRCPT TO:<victim@example.com>",
        ] {
            XCTAssertThrowsError(try AccountEmailAddress(invalid), invalid)
        }
    }

    func testProofCodecUsesDomainSeparatedHMACAndNeverTreatsDeliveryIDAsProof() throws {
        let codec = AccountEmailProofCodec(
            key: try AccountEmailProofKey(Data(repeating: 0x41, count: 32))
        )
        let deliveryID = try AccountEmailDeliveryID(
            rawValue: Self.base64URL(Data(repeating: 0x22, count: 32))
        )
        let firstProof = codec.proof(for: deliveryID)
        let secondProof = codec.proof(for: deliveryID)
        XCTAssertEqual(firstProof, secondProof)
        XCTAssertNotEqual(firstProof, deliveryID.rawValue)
        let firstDigest = try codec.digest(proof: firstProof)
        XCTAssertEqual(firstDigest.count, 32)
        let lookupDigest = codec.lookupDigest(
            email: try AccountEmailAddress("Person@Example.COM")
        )
        XCTAssertEqual(lookupDigest.count, 32)
        XCTAssertEqual(
            lookupDigest,
            codec.lookupDigest(email: try AccountEmailAddress("person@example.com"))
        )
        XCTAssertNotEqual(lookupDigest, firstDigest)

        let emailKey = try codec.rateLimitKey(scope: .email, value: "person@example.com")
        let peerKey = try codec.rateLimitKey(scope: .directPeer, value: "person@example.com")
        XCTAssertNotEqual(emailKey.digest, peerKey.digest)
        XCTAssertThrowsError(
            try AccountEmailProofKey(Data(repeating: 0x41, count: 31))
        )
        XCTAssertThrowsError(try codec.digest(proof: "not base64url!"))

        let mailbox = try AccountEmailAddress("Person@Example.COM")
        let envelope = try codec.recoveryEmailEnvelope(for: mailbox)
        XCTAssertEqual(
            try codec.email(
                fromRecoveryEnvelope: envelope,
                expectedLookupDigest: codec.lookupDigest(email: mailbox)
            ),
            mailbox
        )
        var tampered = envelope
        tampered[tampered.startIndex] ^= 0x01
        XCTAssertThrowsError(
            try codec.email(
                fromRecoveryEnvelope: tampered,
                expectedLookupDigest: codec.lookupDigest(email: mailbox)
            )
        )
        XCTAssertThrowsError(
            try codec.email(
                fromRecoveryEnvelope: envelope,
                expectedLookupDigest: Data(repeating: 0, count: 32)
            )
        )
    }

    func testHashExecutorBoundsBlockingArgon2idWorkAndRejectsOverflow() async throws {
        let release = DispatchSemaphore(value: 0)
        let executor = try Argon2idHashExecutor(
            maximumConcurrentHashes: 1,
            maximumQueuedHashes: 1
        ) { password in
            release.wait()
            return "$argon2id$v=19$m=65536,t=2,p=1$testsalt$\(password)-replacement-verifier"
        }

        let active = Task { try await executor.hash("active") }
        try await waitUntil {
            let metrics = await executor.metrics()
            return metrics.active == 1
        }
        let queued = Task { try await executor.hash("queued") }
        try await waitUntil {
            let metrics = await executor.metrics()
            return metrics.queued == 1
        }
        do {
            _ = try await executor.hash("overflow")
            XCTFail("overflow hash was admitted")
        } catch {
            XCTAssertEqual(
                error as? AccountEmailRecoveryError,
                .capacityExhausted
            )
        }

        release.signal()
        release.signal()
        let values = try await (active.value, queued.value)
        XCTAssertTrue(values.0.contains("active"))
        XCTAssertTrue(values.1.contains("queued"))
        let metrics = await executor.metrics()
        XCTAssertEqual(metrics.peakActive, 1)
        XCTAssertEqual(metrics.totalRejected, 1)
    }

    func testDurableWorkerResendsSameProofAfterCrashLikeSMTPFailure() async throws {
        let fixture = try await RuntimeFixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let codec = AccountEmailProofCodec(
            key: try AccountEmailProofKey(Data(repeating: 0x51, count: 32))
        )
        let delivery = RecordingDelivery(failFirst: true)
        let replacementVerifier = self.replacementVerifier
        let service = try AccountEmailRecoveryService(
            store: fixture.database,
            delivery: delivery,
            proofCodec: codec,
            hashExecutor: try Argon2idHashExecutor(
                maximumConcurrentHashes: 1
            ) { _ in replacementVerifier },
            tokenLifetime: 600,
            retryPolicy: AccountEmailRetryPolicy(
                maximumAttempts: 4,
                initialDelay: 1,
                maximumDelay: 4
            )
        )
        try await service.requestEmailConfirmation(
            did: did,
            email: email,
            now: fixture.now
        )

        let failed = try await service.deliverNext(
            workerID: "worker-a",
            now: fixture.now
        )
        guard case .retryScheduled(_, let retryAt) = failed else {
            return XCTFail("expected retry, got \(failed)")
        }
        let delivered = try await service.deliverNext(
            workerID: "worker-b",
            now: retryAt
        )
        guard case .delivered = delivered else {
            return XCTFail("expected delivery, got \(delivered)")
        }
        let messages = await delivery.messages()
        XCTAssertEqual(messages.count, 2)
        XCTAssertEqual(messages[0].body, messages[1].body)

        let proof = try XCTUnwrap(Self.proof(from: messages[1].body))
        let confirmed = try await service.confirmEmail(
            did: did,
            email: email,
            proof: proof,
            now: retryAt.addingTimeInterval(1)
        )
        XCTAssertEqual(confirmed, .confirmed)
        let replay = try await service.confirmEmail(
            did: did,
            email: email,
            proof: proof,
            now: retryAt.addingTimeInterval(2)
        )
        XCTAssertEqual(replay, .invalidToken)
    }

    func testDeliveryTimeoutCancelsBeforeDurableFenceExpires() async throws {
        let fixture = try await RuntimeFixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let codec = AccountEmailProofCodec(
            key: try AccountEmailProofKey(Data(repeating: 0x57, count: 32))
        )
        let replacementVerifier = self.replacementVerifier
        let service = try AccountEmailRecoveryService(
            store: fixture.database,
            delivery: SlowCancellableDelivery(),
            proofCodec: codec,
            hashExecutor: try Argon2idHashExecutor(
                maximumConcurrentHashes: 1
            ) { _ in replacementVerifier },
            tokenLifetime: 600,
            retryPolicy: AccountEmailRetryPolicy(
                maximumAttempts: 2,
                initialDelay: 1,
                maximumDelay: 1
            ),
            deliveryAttemptTimeout: 0.02
        )

        try await service.requestEmailConfirmation(
            did: did,
            email: email,
            now: fixture.now
        )
        let result = try await service.deliverNext(
            workerID: "timeout-worker",
            now: fixture.now
        )
        guard case .retryScheduled = result else {
            return XCTFail("expected a bounded delivery timeout, got \(result)")
        }
    }

    func testRecoveryRejectsUnverifiedDeliveryCancellationContract() async throws {
        let fixture = try await RuntimeFixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let codec = AccountEmailProofCodec(
            key: try AccountEmailProofKey(Data(repeating: 0x58, count: 32))
        )
        let replacementVerifier = self.replacementVerifier
        XCTAssertThrowsError(
            try AccountEmailRecoveryService(
                store: fixture.database,
                delivery: UnverifiedDelivery(),
                proofCodec: codec,
                hashExecutor: try Argon2idHashExecutor(
                    maximumConcurrentHashes: 1
                ) { _ in replacementVerifier },
                tokenLifetime: 600
            )
        ) { error in
            XCTAssertEqual(error as? AccountControlStoreError, .invalidInput)
        }
    }

    func testPasswordResetRequestIsOpaqueAndCompletionUsesBoundedHasher() async throws {
        let fixture = try await RuntimeFixture(testCase: self)
        addTeardownBlock { try? await fixture.database.close(); fixture.cleanup() }
        let codec = AccountEmailProofCodec(
            key: try AccountEmailProofKey(Data(repeating: 0x61, count: 32))
        )
        let delivery = RecordingDelivery()
        let replacementVerifier = self.replacementVerifier
        let service = try AccountEmailRecoveryService(
            store: fixture.database,
            delivery: delivery,
            proofCodec: codec,
            hashExecutor: try Argon2idHashExecutor(
                maximumConcurrentHashes: 1
            ) { _ in replacementVerifier },
            tokenLifetime: 600
        )

        try await service.requestPasswordRecovery(
            email: try AccountEmailAddress("unknown@example.com"),
            now: fixture.now
        )
        let unknownDelivery = try await service.deliverNext(
            workerID: "worker",
            now: fixture.now
        )
        XCTAssertEqual(unknownDelivery, .idle)

        try await service.requestEmailConfirmation(
            did: did,
            email: email,
            now: fixture.now
        )
        _ = try await service.deliverNext(workerID: "worker", now: fixture.now)
        let verificationMessageResult = await delivery.lastMessage()
        let verificationMessage = try XCTUnwrap(verificationMessageResult)
        let verificationProof = try XCTUnwrap(Self.proof(from: verificationMessage.body))
        let verificationResult = try await service.confirmEmail(
            did: did,
            email: email,
            proof: verificationProof,
            now: fixture.now.addingTimeInterval(1)
        )
        XCTAssertEqual(verificationResult, .confirmed)

        try await service.requestPasswordRecovery(
            email: email,
            now: fixture.now.addingTimeInterval(2)
        )
        _ = try await service.deliverNext(
            workerID: "worker",
            now: fixture.now.addingTimeInterval(2)
        )
        let recoveryMessageResult = await delivery.lastMessage()
        let recoveryMessage = try XCTUnwrap(recoveryMessageResult)
        let recoveryProof = try XCTUnwrap(Self.proof(from: recoveryMessage.body))
        let resetResult = try await service.resetPassword(
            proof: recoveryProof,
            password: "new correct horse battery staple",
            now: fixture.now.addingTimeInterval(3)
        )
        XCTAssertEqual(resetResult, .completed)
        let credential = try await fixture.database.credential(did: did)
        XCTAssertEqual(credential?.verifier, replacementVerifier)
        let resetReplay = try await service.resetPassword(
            proof: recoveryProof,
            password: "another password",
            now: fixture.now.addingTimeInterval(4)
        )
        XCTAssertEqual(resetReplay, .invalidToken)
    }

    private var replacementVerifier: String {
        "$argon2id$v=19$m=65536,t=2,p=1$replacesalt$replacement-precomputed-verifier"
    }

    private static func proof(from body: String) -> String? {
        body.split(separator: " ").last.map(String.init)
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func waitUntil(
        timeout: TimeInterval = 2,
        _ predicate: @escaping @Sendable () async -> Bool
    ) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if await predicate() { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTFail("condition was not met before timeout")
    }
}

private actor RecordingDelivery: AccountEmailDelivery {
    nonisolated var cancellationContract:
        AccountEmailDeliveryCancellationContract { .bounded }

    struct Message: Sendable {
        let to: AccountEmailAddress
        let subject: String
        let body: String
    }

    private var recorded: [Message] = []
    private var failuresRemaining: Int

    init(failFirst: Bool = false) {
        failuresRemaining = failFirst ? 1 : 0
    }

    func deliver(to: AccountEmailAddress, subject: String, body: String) async throws {
        recorded.append(Message(to: to, subject: subject, body: body))
        if failuresRemaining > 0 {
            failuresRemaining -= 1
            throw AccountEmailRecoveryError.deliveryUnavailable
        }
    }

    func messages() -> [Message] { recorded }
    func lastMessage() -> Message? { recorded.last }
}

private actor SlowCancellableDelivery: AccountEmailDelivery {
    nonisolated var cancellationContract:
        AccountEmailDeliveryCancellationContract { .bounded }

    func deliver(
        to _: AccountEmailAddress,
        subject _: String,
        body _: String
    ) async throws {
        try await Task.sleep(for: .seconds(1))
    }
}

private actor UnverifiedDelivery: AccountEmailDelivery {
    nonisolated var cancellationContract:
        AccountEmailDeliveryCancellationContract { .unverified }

    func deliver(
        to _: AccountEmailAddress,
        subject _: String,
        body _: String
    ) async throws {
        // This deliberately ignores cancellation. The recovery service must
        // reject it at construction rather than allowing a task-group timeout
        // to leave SMTP work running beyond the durable send fence.
        while true {
            try? await Task.sleep(for: .seconds(1))
        }
    }
}

private final class RuntimeFixture: @unchecked Sendable {
    let root: URL
    let database: SQLiteControlDatabase
    let now = Date(timeIntervalSince1970: 1_750_000_001)

    init(testCase _: XCTestCase) async throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanAccountEmailRuntime-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        database = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await database.createAccount(
            AccountControlRegistration(
                did: "did:plc:abcdefghijklmnopqrstuvwx",
                canonicalHandle: "account-email-runtime.example.com",
                passwordVerifier:
                    "$argon2id$v=19$m=65536,t=2,p=1$initialsalt$initial-precomputed-verifier",
                signingKey: .init(purpose: .signing, generation: 1),
                rotationKey: .init(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )
        try await database.associateEmail(
            did: "did:plc:abcdefghijklmnopqrstuvwx",
            email: AccountEmailAddress("person@example.com"),
            now: now
        )
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }
}
