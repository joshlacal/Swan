import Foundation
import SwanPublicFirehose
import SwanStorage
import XCTest

@_spi(Testing) @testable import SwanSQLite

final class AccountAuthorizationLeaseTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let time = "2026-08-04T12:00:00.000Z"

    private func identityItem(did: String) -> LifecycleEventItem {
        let material = PublicFirehoseIdentityMaterial(
            did: did,
            handle: "authorization-lease.example.com",
            time: time
        )
        return LifecycleEventItem(
            sourceKey: PublicFirehoseSourceKey.identity(
                did: did,
                plcOperationCID: "bafyid1"
            ),
            kind: .identity,
            payload: try! JSONEncoder().encode(material),
            carBytes: nil
        )
    }

    func testAuthorizationLeaseSerializesFinalMutationWithActiveLifecycle() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "SwanAccountAuthorizationLease-\(UUID().uuidString)"
            )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await control.close() } }
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: did,
                canonicalHandle: "authorization-lease.example.com",
                passwordVerifier:
                    "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: .init(purpose: .signing, generation: 1),
                rotationKey: .init(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )

        let result = try await control.withActiveAccountAuthorization(
            did: did
        ) {
            let hasLease = await control.hasActiveWriteTransactionForTesting()
            XCTAssertTrue(
                hasLease,
                "the publication callback must run under the control write lease"
            )
            return "published"
        }
        XCTAssertEqual(result, "published")

        _ = try await control.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_001)
        )
        do {
            _ = try await control.withActiveAccountAuthorization(did: did) {
                XCTFail("deactivated accounts must not reach publication")
                return "unreachable"
            }
            XCTFail("expected deactivated authorization to fail")
        } catch let error as AccountControlStoreError {
            XCTAssertEqual(error, .invalidTransition)
        }
    }

    func testFirehoseAuthorizationFencePassesLiveGenerationAndRejectsInactive() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "SwanAccountAuthorizationLease-\(UUID().uuidString)"
            )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await control.close() } }
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: did,
                canonicalHandle: "authorization-lease.example.com",
                passwordVerifier:
                    "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: .init(purpose: .signing, generation: 1),
                rotationKey: .init(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )
        _ = try await control.enqueueLifecycleEventBatch(
            did: did,
            operationID: "op-1",
            items: [identityItem(did: did)],
            now: Date(timeIntervalSince1970: 1_750_000_000)
        )
        let seen = try await control.withActiveAccountFirehoseAuthorization(
            did: did
        ) { generation in
            generation
        }
        XCTAssertEqual(seen, 1)

        _ = try await control.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_001)
        )
        do {
            _ = try await control.withActiveAccountFirehoseAuthorization(did: did) { _ in
                XCTFail("deactivated accounts must not reach the firehose generation")
                return true
            }
            XCTFail("expected deactivated firehose authorization to fail")
        } catch let error as AccountControlStoreError {
            guard case .invalidTransition = error else { throw error }
        }
    }

    func testRotationIdentityAndKeyPromotionHoldOneAuthorizationFence() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "SwanAccountAuthorizationLease-\(UUID().uuidString)"
            )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await control.close() } }
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: did,
                canonicalHandle: "authorization-lease.example.com",
                passwordVerifier:
                    "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: .init(purpose: .signing, generation: 1),
                rotationKey: .init(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )
        _ = try await control.enqueueLifecycleEventBatch(
            did: did,
            operationID: "activation",
            items: [identityItem(did: did)],
            now: Date(timeIntervalSince1970: 1_750_000_000)
        )

        let rotationBarrier = RotationCommitBarrier()
        let accountDID = did
        await control.setBeforeRotationCommitForTesting {
            await rotationBarrier.park()
        }
        let rotation = Task {
            try await control.rotateAccountKeys(
                did: accountDID,
                request: .init(
                    expectedGeneration: 1,
                    signingKey: .init(purpose: .signing, generation: 2),
                    rotationKey: .init(purpose: .rotation, generation: 2)
                ),
                emitting: .init(
                    plcOperationCID: "bafyrotation2",
                    handle: nil,
                    materialTime: Date(timeIntervalSince1970: 1_750_000_001)
                ),
                now: Date(timeIntervalSince1970: 1_750_000_001)
            )
        }
        await rotationBarrier.waitUntilParked()

        let fenceProbe = RotationFenceProbe()
        await control.setConnectionGateWaiterEnqueuedForTesting {
            Task { await fenceProbe.record(.queuedAtControlGate) }
        }
        let fence = Task {
            return try await control.withActiveAccountFirehoseAuthorization(
                did: accountDID,
                signingGeneration: 2
            ) { lifecycleGeneration in
                await fenceProbe.record(.enteredAuthorization)
                return lifecycleGeneration
            }
        }
        let firstFenceOutcome = await fenceProbe.waitForFirstOutcome()
        XCTAssertEqual(firstFenceOutcome, .queuedAtControlGate)
        let enteredBeforeRelease = await fenceProbe.hasEntered
        XCTAssertFalse(
            enteredBeforeRelease,
            "the publication fence must remain behind the uncommitted rotation"
        )

        await rotationBarrier.release()
        let rotated = try await rotation.value
        let lifecycleGeneration = try await fence.value
        XCTAssertEqual(rotated.signingKey?.generation, 2)
        XCTAssertEqual(rotated.rotationKey?.generation, 2)
        XCTAssertEqual(lifecycleGeneration, 2)
        let enteredAfterRelease = await fenceProbe.hasEntered
        XCTAssertTrue(enteredAfterRelease)

        let finalLifecycleGeneration = try await control.currentLifecycleGeneration(did: did)
        XCTAssertEqual(finalLifecycleGeneration, 2)
    }

    func testStaleSignerGenerationNeverFallsBackToNonEmittingMutation() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "SwanAccountAuthorizationLease-\(UUID().uuidString)"
            )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await control.close() } }
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: did,
                canonicalHandle: "authorization-lease.example.com",
                passwordVerifier:
                    "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: .init(purpose: .signing, generation: 2),
                rotationKey: .init(purpose: .rotation, generation: 2),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )
        let callback = RotationFenceProbe()
        let fence = PublicFirehoseCommitFence(control: control)
        do {
            _ = try await fence.apply(did: did, signingGeneration: 1) { _ in
                await callback.record(.enteredAuthorization)
                throw TestPublicationError.unexpectedMutation
            }
            XCTFail("a stale signer must be rejected")
        } catch let error as PublicRepositoryMutationPublicationError {
            XCTAssertEqual(error, .staleSigningGeneration)
        }
        let entered = await callback.hasEntered
        XCTAssertFalse(entered, "stale signer rejection must not retry with nil firehose context")
    }
}

private enum TestPublicationError: Error {
    case unexpectedMutation
}

private actor RotationCommitBarrier {
    private var parked = false
    private var parkedWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiter: CheckedContinuation<Void, Never>?

    func park() async {
        parked = true
        let waiters = parkedWaiters
        parkedWaiters.removeAll()
        waiters.forEach { $0.resume() }
        await withCheckedContinuation { releaseWaiter = $0 }
    }

    func waitUntilParked() async {
        if parked { return }
        await withCheckedContinuation { parkedWaiters.append($0) }
    }

    func release() {
        releaseWaiter?.resume()
        releaseWaiter = nil
    }
}

private actor RotationFenceProbe {
    enum Outcome: Sendable, Equatable {
        case queuedAtControlGate
        case enteredAuthorization
    }

    private var firstOutcome: Outcome?
    private var outcomeWaiters: [CheckedContinuation<Outcome, Never>] = []
    private(set) var hasEntered = false

    func record(_ outcome: Outcome) {
        if outcome == .enteredAuthorization {
            hasEntered = true
        }
        guard firstOutcome == nil else { return }
        firstOutcome = outcome
        let waiters = outcomeWaiters
        outcomeWaiters.removeAll()
        waiters.forEach { $0.resume(returning: outcome) }
    }

    func waitForFirstOutcome() async -> Outcome {
        if let firstOutcome { return firstOutcome }
        return await withCheckedContinuation { outcomeWaiters.append($0) }
    }
}
