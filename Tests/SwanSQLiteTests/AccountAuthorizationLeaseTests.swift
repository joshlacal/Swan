import Foundation
import Petrel
import SwanCore
import PetrelFirehose
import SwanSpaces
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
        try await control.close()
    }

    func testDeactivationQueuedBeforeLegacyIssuanceRejectsBothFamilyCreationPaths() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "SwanLegacyIssuanceLifecycle-\(UUID().uuidString)"
            )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        addTeardownBlock { [control, root] in
            await control.setConnectionGateWaiterEnqueuedForTesting(nil)
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
        }
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: did,
                canonicalHandle: "legacy-issuance.example.com",
                passwordVerifier:
                    "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: .init(purpose: .signing, generation: 1),
                rotationKey: .init(purpose: .rotation, generation: 1),
                createdAt: now
            )
        )
        let context = try AccountAuthorizationContext(
            channel: .legacy,
            sessionID: "queued-legacy-issuance",
            purpose: "managementLogin"
        )
        let grant = try await control.createPasswordAuthorizationGrant(
            grantDigest: Data(repeating: 0x61, count: 32),
            accountDID: did,
            context: context,
            now: now
        )

        // Hold the FIFO connection gate, then enqueue deactivation ahead of
        // both family-creation transactions. This chooses the ordering without
        // wall-clock sleeps: once released, deactivation must win first.
        let blocker = RotationCommitBarrier()
        let accountDID = did
        let heldAuthorization = Task {
            try await control.withActiveAccountAuthorization(did: accountDID) {
                await blocker.park()
            }
        }
        await blocker.waitUntilParked()

        let queue = ConnectionGateWaiterProbe()
        await control.setConnectionGateWaiterEnqueuedForTesting {
            Task { await queue.recordWaiter() }
        }
        let deactivation = Task {
            try await control.transitionStatus(
                did: accountDID,
                to: .deactivated,
                declaration: .init(),
                now: now.addingTimeInterval(1)
            )
        }
        await queue.waitUntilCount(1)

        let directIssuance = Task {
            try await control.createLegacySessionFamily(
                familyID: "queued-direct-family",
                did: accountDID,
                appPasswordID: nil,
                accessDigest: Data(repeating: 0x62, count: 32),
                accessExpiresAt: now.addingTimeInterval(3_600),
                refreshDigest: Data(repeating: 0x63, count: 32),
                refreshExpiresAt: now.addingTimeInterval(90 * 86_400),
                now: now.addingTimeInterval(2)
            )
        }
        let grantIssuance = Task {
            try await control.createLegacySessionFamilyConsumingGrant(
                familyID: "queued-grant-family",
                did: accountDID,
                appPasswordID: nil,
                accessDigest: Data(repeating: 0x64, count: 32),
                accessExpiresAt: now.addingTimeInterval(3_600),
                refreshDigest: Data(repeating: 0x65, count: 32),
                refreshExpiresAt: now.addingTimeInterval(90 * 86_400),
                authorizationGrantDigest: grant.grantDigest,
                authorizationContext: context,
                now: now.addingTimeInterval(2)
            )
        }
        await queue.waitUntilCount(3)
        await blocker.release()

        _ = try await heldAuthorization.value
        _ = try await deactivation.value
        let directResult = await directIssuance.result
        let grantResult = await grantIssuance.result
        assertInvalidTransition(
            directResult,
            "deactivation-first must reject ordinary legacy family creation"
        )
        assertInvalidTransition(
            grantResult,
            "deactivation-first must reject grant-consuming legacy family creation"
        )

        if case .failure = grantResult {
            // Deactivation updates accounts.updated_at, which durably invalidates
            // pre-existing grants. Reactivation must not allow the stale grant to be consumed.
            _ = try await control.transitionStatus(
                did: did,
                to: .active,
                declaration: .init(),
                now: now.addingTimeInterval(3)
            )
            do {
                try await control.createLegacySessionFamilyConsumingGrant(
                    familyID: "grant-after-reactivation",
                    did: did,
                    appPasswordID: nil,
                    accessDigest: Data(repeating: 0x66, count: 32),
                    accessExpiresAt: now.addingTimeInterval(3_600),
                    refreshDigest: Data(repeating: 0x67, count: 32),
                    refreshExpiresAt: now.addingTimeInterval(90 * 86_400),
                    authorizationGrantDigest: grant.grantDigest,
                    authorizationContext: context,
                    now: now.addingTimeInterval(4)
                )
                XCTFail("stale grant must not be usable after reactivation")
            } catch {}
        }
        await control.setConnectionGateWaiterEnqueuedForTesting(nil)
        try await control.close()
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
        try await control.close()
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
        try await control.close()
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
        try await control.close()
    }

    /// F18. The publication fence used to answer a non-authorizing account by
    /// re-running the mutation with no firehose context: the write committed
    /// and no event was published, leaving the repository permanently ahead of
    /// every relay's view of it with nothing to reconcile from. The pinned
    /// reference PDS has no such concept — its write routes refuse a
    /// deactivated account outright — so the fence refuses too, and the
    /// mutation must never run.
    func testDeactivatedAccountIsRefusedRatherThanCommittedWithoutAnEvent() async throws {
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
        _ = try await control.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_001)
        )

        let callback = RotationFenceProbe()
        let fence = PublicFirehoseCommitFence(control: control)
        do {
            _ = try await fence.apply(did: did, signingGeneration: 1) { _ in
                await callback.record(.enteredAuthorization)
                throw TestPublicationError.unexpectedMutation
            }
            XCTFail("a deactivated account must not publish a public commit")
        } catch let error as AccountControlStoreError {
            XCTAssertEqual(
                error,
                .invalidTransition,
                """
                the refusal must stay the control store's own answer, which \
                SwanPublicRepositoryMutationCoordinator maps to \
                `.inactiveAccount` and the route answers 403 AccountInactive
                """
            )
        }
        let entered = await callback.hasEntered
        XCTAssertFalse(
            entered,
            "a refused account must not reach the mutation at all"
        )
        try await control.close()
    }

    /// F46. `apply` used to commit the permissioned batch first and only then
    /// ask whether the account still authorized it, so a deactivation that
    /// landed in between produced a durable write *and* an `unauthorized`
    /// response. Nothing downstream can undo that commit: the post-commit
    /// check rejects a write it has already made permanent.
    ///
    /// The interleaving is forced, not slept on. The batch parks inside the
    /// account database's write transaction (`beforeApplyCommit`, immediately
    /// before COMMIT) and the deactivation is only released from there, so the
    /// two orderings — deactivation committed first, or deactivation queued
    /// behind the write's control lease — are both observed deterministically.
    func testPermissionedWriteRacingDeactivationNeverCommitsARejectedBatch() async throws {
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

        let space = try SpaceURI(
            authority: did,
            spaceType: "app.bsky.bookmarks",
            skey: "linearization"
        )
        let record = try SpaceRecordURI(
            space: space,
            author: did,
            collection: "app.bsky.bookmarks.bookmark",
            rkey: "raced"
        )
        print("P1: before installSpaceAccountDatabase")
        try await installSpaceAccountDatabase(root: root, did: did, space: space)
        print("P2: after installSpaceAccountDatabase")

        let control = try await SQLiteControlDatabase(dataDirectory: root)
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
        let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: root,
            controlStore: control,
            publicIdentityVerifier: nil
        )

        let commitBarrier = RotationCommitBarrier()
        try await directory.installAccountTestingHooks(
            SQLiteTestingHooks(beforeApplyCommit: { await commitBarrier.park() }),
            did: did
        )

        let value = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "$type", value: "app.bsky.bookmarks.bookmark"),
            (key: "subject", value: "raced permissioned write"),
        ]))
        let accountDID = did
        let scope = "space:app.bsky.bookmarks?authority=\(did)"
            + "&skey=linearization&action=create"
            + "&collection=app.bsky.bookmarks.bookmark"
        let write = Task {
            try await directory.apply(
                space: space,
                author: accountDID,
                writes: [.create(uri: record, value: value)],
                requestID: UUID(),
                wireRevision: "3333333333333",
                authorization: .accountOAuthForTesting(subject: accountDID, scopes: [scope])
            )
        }
        await commitBarrier.waitUntilParked()
        // Either the deactivation commits while the batch is parked (the
        // defect), or it queues behind the batch's control lease (the fix).
        // Recording both makes the observed ordering an assertion input rather
        // than a timing assumption.
        let probe = LifecycleRaceProbe()
        await control.setConnectionGateWaiterEnqueuedForTesting {
            Task { await probe.record(.deactivationQueuedAtControlGate) }
        }
        let deactivation = Task {
            _ = try await control.transitionStatus(
                did: accountDID,
                to: .deactivated,
                declaration: .init(),
                now: Date(timeIntervalSince1970: 1_750_000_001)
            )
            await probe.record(.deactivationCommitted)
        }
        let observed = await probe.waitForFirstOutcome()
        await commitBarrier.release()

        let writeOutcome = await write.result
        try await deactivation.value
        await control.setConnectionGateWaiterEnqueuedForTesting(nil)
        try await directory.close()
        try await control.close()

        let reopened = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let durable = try await reopened.spaceRecord(record)
        try await reopened.close()
        // the deactivation task existed, so under the fence it necessarily
        // holds the control lease first and the deactivation necessarily
        // queues behind it. There is no admissible ordering in which this
        // batch is refused.
        switch writeOutcome {
        case .success:
            XCTAssertEqual(
                observed,
                .deactivationQueuedAtControlGate,
                "an accepted batch must have held the control authorization lease"
            )
            XCTAssertNotNil(
                durable,
                "an accepted permissioned batch must be durable"
            )
        case let .failure(error):
            XCTAssertNil(
                durable,
                """
                a permissioned batch rejected for a racing deactivation must \
                not be durable; the post-commit check cannot roll back the \
                write it rejects (\(error))
                """
            )
            XCTFail(
                """
                the batch entered the account write transaction before the \
                deactivation was requested, so the authorization fence must \
                admit it (\(error))
                """
            )
        }
    }
    /// F46's residual. Closing the write-then-check race put the whole batch
    /// under the process-wide control-plane write gate, so the reads, the
    /// authorization checks, and CID computation over as much as 1 MiB across
    /// as many as 4,096 operations all head-of-line blocked OAuth and account
    /// lifecycle traffic — at request rate, with no timeout. Only the durable
    /// transaction needs the lease; staging is durably inert.
    ///
    /// The batch parks in staging, immediately after its first durable read.
    /// The lease must not be held there, and an unrelated control-plane write
    /// must be able to commit while it stays parked.
    func testPermissionedWriteStagesWithoutHoldingTheControlLease() async throws {
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

        let space = try SpaceURI(
            authority: did,
            spaceType: "app.bsky.bookmarks",
            skey: "staging"
        )
        let record = try SpaceRecordURI(
            space: space,
            author: did,
            collection: "app.bsky.bookmarks.bookmark",
            rkey: "staged"
        )
        try await installSpaceAccountDatabase(root: root, did: did, space: space)

        let control = try await SQLiteControlDatabase(dataDirectory: root)
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
        let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: root,
            controlStore: control,
            publicIdentityVerifier: nil
        )

        let stagingBarrier = RotationCommitBarrier()
        try await directory.installAccountTestingHooks(
            SQLiteTestingHooks(
                afterRepositoryStateRead: { await stagingBarrier.park() }
            ),
            did: did
        )

        let value = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
            (key: "$type", value: "app.bsky.bookmarks.bookmark"),
            (key: "subject", value: "staged permissioned write"),
        ]))
        let accountDID = did
        let scope = "space:app.bsky.bookmarks?authority=\(did)"
            + "&skey=staging&action=create"
            + "&collection=app.bsky.bookmarks.bookmark"
        let write = Task {
            try await directory.apply(
                space: space,
                author: accountDID,
                writes: [.create(uri: record, value: value)],
                requestID: UUID(),
                wireRevision: "3333333333333",
                authorization: .accountOAuthForTesting(subject: accountDID, scopes: [scope])
            )
        }
        await stagingBarrier.waitUntilParked()

        let staging = await control.connectionGate.admissionSnapshotForTesting()
        XCTAssertFalse(
            staging.isHeld,
            "staging a permissioned batch must not hold the control lease"
        )

        // The behavioural half: a control-plane write must commit while the
        // batch is still parked. Raced against a deadline rather than simply
        // awaited, so a regression that reinstates the coupling fails here
        // instead of hanging the suite.
        let unrelated = "did:plc:zyxwvutsrqponmlkjihgfedc"
        let admitted = await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                _ = try? await control.createAccount(
                    AccountControlRegistration(
                        did: unrelated,
                        canonicalHandle: "unrelated.example.com",
                        passwordVerifier:
                            "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                        signingKey: .init(purpose: .signing, generation: 1),
                        rotationKey: .init(purpose: .rotation, generation: 1),
                        createdAt: Date(timeIntervalSince1970: 1_750_000_002)
                    )
                )
                return true
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: 10_000_000_000)
                return false
            }
            let first = await group.next() ?? false
            group.cancelAll()
            return first
        }
        XCTAssertTrue(
            admitted,
            """
            an unrelated control-plane write must not queue behind a \
            permissioned batch that is only staging
            """
        )

        await stagingBarrier.release()
        _ = try await write.value

        try await directory.close()
        try await control.close()

        let reopened = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let durable = try await reopened.spaceRecord(record)
        try await reopened.close()
        XCTAssertNotNil(
            durable,
            "the batch must still commit once it leaves staging"
        )
    }

    func testStalePasswordGrantRejectedAfterCredentialUpdate() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("SwanGrantStale-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        addTeardownBlock { [control, root] in
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
        }
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: did,
                canonicalHandle: "grant-stale.example.com",
                passwordVerifier:
                    "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: .init(purpose: .signing, generation: 1),
                rotationKey: .init(purpose: .rotation, generation: 1),
                createdAt: now
            )
        )
        let context = try AccountAuthorizationContext(
            channel: .legacy,
            sessionID: "grant-stale-session",
            purpose: "managementLogin"
        )
        let grantDigest = Data(repeating: 0x77, count: 32)
        _ = try await control.createPasswordAuthorizationGrant(
            grantDigest: grantDigest,
            accountDID: did,
            context: context,
            now: now
        )
        // Status change updates accounts.updated_at
        _ = try await control.transitionStatus(did: did, to: .deactivated, declaration: .init(), emitting: nil, now: now.addingTimeInterval(5))
        _ = try await control.transitionStatus(did: did, to: .active, declaration: .init(), emitting: nil, now: now.addingTimeInterval(10))

        do {
            _ = try await control.consumeAuthorizationGrant(
                grantDigest: grantDigest,
                accountDID: did,
                context: context,
                now: now.addingTimeInterval(15)
            )
            XCTFail("grant consumption must fail after credential revision change")
        } catch {}
    }
}

private extension AccountAuthorizationLeaseTests {
    /// Creates the account database with one open space so the permissioned
    /// write path has a repository to commit into, exactly as the directory
    /// bootstrap expects to find it.
    func installSpaceAccountDatabase(
        root: URL,
        did: String,
        space: SpaceURI
    ) async throws {
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let authority = try DurableSimpleSpaceAuthority(
            database: database,
            credentialSecret: Data(repeating: 0xA5, count: 32)
        )
        _ = try await authority.create(
            space: space,
            owner: did,
            configuration: try SimpleSpaceConfiguration(
                policy: .memberList,
                appAccess: .open
            ),
            authorization: .accountOAuthForTesting(subject: did, scopes: ["atproto"]),
            now: Date(timeIntervalSince1970: 1_750_000_000)
        )
        try await database.close()
    }
}

private func assertInvalidTransition(
    _ result: Result<Void, any Error>,
    _ message: String,
    file: StaticString = #filePath,
    line: UInt = #line
) {
    switch result {
    case .success:
        XCTFail(message, file: file, line: line)
    case let .failure(error):
        XCTAssertEqual(
            error as? AccountControlStoreError,
            .invalidTransition,
            message,
            file: file,
            line: line
        )
    }
}

private actor LifecycleRaceProbe {
    enum Outcome: Sendable, Equatable {
        case deactivationQueuedAtControlGate
        case deactivationCommitted
    }

    private var firstOutcome: Outcome?
    private var outcomeWaiters: [CheckedContinuation<Outcome, Never>] = []

    func record(_ outcome: Outcome) {
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

private actor ConnectionGateWaiterProbe {
    private var count = 0
    private var waiters: [(target: Int, continuation: CheckedContinuation<Void, Never>)] = []

    func recordWaiter() {
        count += 1
        let ready = waiters.filter { $0.target <= count }
        waiters.removeAll { $0.target <= count }
        ready.forEach { $0.continuation.resume() }
    }

    func waitUntilCount(_ target: Int) async {
        if count >= target { return }
        await withCheckedContinuation { continuation in
            waiters.append((target, continuation))
        }
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
