import Foundation
@testable import SwanAccounts
import SwanCore
import SwanSQLite
import SwanStorage
import XCTest

final class AccountPermanentDeletionCoordinatorTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"

    func testCoordinatorKeepsRotationKeyThroughPLCThenErasesAllData() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(
            dataDirectory: root.appending(path: "data")
        )
        let keyStore = try FileAccountKeyStore(
            root: root.appending(path: "keys"),
            configuration: try AccountKeyEncryptionConfiguration(
                activeKeyID: "deletion-coordinator",
                activeKey: Data(repeating: 0x99, count: 32)
            )
        )
        let signing = try AccountKeyReference(
            accountDID: did,
            purpose: .signing,
            generation: 1
        )
        let rotation = try AccountKeyReference(
            accountDID: did,
            purpose: .rotation,
            generation: 1
        )
        try await keyStore.createBatch([
            try AccountKeyMaterial(
                reference: signing,
                key: Data(repeating: 0x11, count: 32)
            ),
            try AccountKeyMaterial(
                reference: rotation,
                key: Data(repeating: 0x22, count: 32)
            ),
        ])
        _ = try await control.createAccount(
            try registration(handle: "coordinator.example.com")
        )

        let recorder = DeletionOrderRecorder()
        let plc = KeyAssertingPLCTombstoner(
            keyStore: keyStore,
            rotationReference: rotation,
            recorder: recorder
        )
        let data = KeyErasureAssertingDataDestroyer(
            keyStore: keyStore,
            signingReference: signing,
            recorder: recorder
        )
        let quiescer = RecordingDeletionQuiescer(recorder: recorder)
        let coordinator = AccountPermanentDeletionCoordinator(
            controlStore: control,
            keyStore: keyStore,
            quiescer: quiescer,
            plcTombstoner: plc,
            dataDestroyer: data
        )
        let tombstone = try await coordinator.beginAndResume(
            did: did,
            declaration: AccountLifecycleDeclaration(
                tombstone: try AccountTombstoneMetadata(
                    reason: "user-request"
                )
            ),
            now: Date(timeIntervalSince1970: 1_750_000_500)
        )
        XCTAssertEqual(tombstone.did, did)
        let events = await recorder.events()
        let receivedRotationKey = await plc.receivedRotationKey()
        let finalizedAccount = try await control.account(did: did)
        XCTAssertEqual(events, ["quiesce", "plc", "data"])
        XCTAssertEqual(receivedRotationKey, rotation)
        XCTAssertNil(finalizedAccount)
        await XCTAssertThrowsErrorAsync(
            try await keyStore.key(for: signing)
        )
        await XCTAssertThrowsErrorAsync(
            try await keyStore.key(for: rotation)
        )
        try await control.close()
    }

    func testCoordinatorResumesAfterExternalDataCompletionBeforeStageAdvance() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(
            dataDirectory: root.appending(path: "data")
        )
        let keyStore = try FileAccountKeyStore(
            root: root.appending(path: "keys"),
            configuration: try AccountKeyEncryptionConfiguration(
                activeKeyID: "deletion-restart",
                activeKey: Data(repeating: 0x88, count: 32)
            )
        )
        _ = try await control.createAccount(
            try registration(handle: "restart.example.com")
        )
        let data = FailAfterFirstDataDestruction()
        _ = try await control.beginDeletion(
            did: did,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_600)
        )
        let beforeRestart = try await control.deletionJob(did: did)
        XCTAssertEqual(beforeRestart?.rotationKey?.generation, 1)
        try await control.close()
        let reopened = try await SQLiteControlDatabase(
            dataDirectory: root.appending(path: "data")
        )
        let afterRestart = try await reopened.deletionJob(did: did)
        XCTAssertEqual(afterRestart?.rotationKey?.generation, 1)
        let plc = RecordingPLCTombstoner()
        let quiescer = RecordingDeletionQuiescer()
        let coordinator = AccountPermanentDeletionCoordinator(
            controlStore: reopened,
            keyStore: keyStore,
            quiescer: quiescer,
            plcTombstoner: plc,
            dataDestroyer: data
        )
        await XCTAssertThrowsErrorAsync(
            try await coordinator.resume(
                did: did,
                now: Date(timeIntervalSince1970: 1_750_000_601)
            )
        )
        let interruptedJob = try await reopened.deletionJob(did: did)
        let interrupted = try XCTUnwrap(interruptedJob)
        XCTAssertEqual(interrupted.stage, .keyMaterialDestroyed)
        let restartedRotationKey = await plc.receivedRotationKey()
        XCTAssertEqual(
            restartedRotationKey,
            try AccountKeyReference(
                accountDID: did,
                purpose: .rotation,
                generation: 1
            )
        )

        let tombstone = try await coordinator.resume(
            did: did,
            now: Date(timeIntervalSince1970: 1_750_000_602)
        )
        XCTAssertEqual(tombstone.did, did)
        let dataCallCount = await data.callCount()
        let finalizedJob = try await reopened.deletionJob(did: did)
        XCTAssertEqual(dataCallCount, 2)
        XCTAssertNil(finalizedJob)
        try await reopened.close()
    }

    func testConcurrentBeginForOneDIDSharesOneExternalDeletionFlight() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(
            dataDirectory: root.appending(path: "data")
        )
        let keyStore = try FileAccountKeyStore(
            root: root.appending(path: "keys"),
            configuration: try AccountKeyEncryptionConfiguration(
                activeKeyID: "deletion-singleflight",
                activeKey: Data(repeating: 0x77, count: 32)
            )
        )
        let signing = try AccountKeyReference(
            accountDID: did,
            purpose: .signing,
            generation: 1
        )
        let rotation = try AccountKeyReference(
            accountDID: did,
            purpose: .rotation,
            generation: 1
        )
        try await keyStore.createBatch([
            try AccountKeyMaterial(
                reference: signing,
                key: Data(repeating: 0x31, count: 32)
            ),
            try AccountKeyMaterial(
                reference: rotation,
                key: Data(repeating: 0x32, count: 32)
            ),
        ])
        _ = try await control.createAccount(
            try registration(handle: "singleflight.example.com")
        )
        let plc = CountingPLCTombstoner()
        let data = CountingDataDestroyer()
        let quiescer = CountingDeletionQuiescer()
        let coordinator = AccountPermanentDeletionCoordinator(
            controlStore: control,
            keyStore: keyStore,
            quiescer: quiescer,
            plcTombstoner: plc,
            dataDestroyer: data
        )
        let now = Date(timeIntervalSince1970: 1_750_000_700)
        let declaration = AccountLifecycleDeclaration(
            tombstone: try AccountTombstoneMetadata(
                declaredAt: now,
                reason: "concurrent-operator-request"
            )
        )
        let accountDID = did

        let tombstones = try await withThrowingTaskGroup(
            of: AccountDeletionTombstone.self,
            returning: [AccountDeletionTombstone].self
        ) { group in
            for _ in 0 ..< 16 {
                group.addTask {
                    try await coordinator.beginAndResume(
                        did: accountDID,
                        declaration: declaration,
                        now: now
                    )
                }
            }
            var values: [AccountDeletionTombstone] = []
            for try await value in group {
                values.append(value)
            }
            return values
        }

        XCTAssertEqual(tombstones.count, 16)
        let firstTombstone = try XCTUnwrap(tombstones.first)
        XCTAssertTrue(tombstones.allSatisfy { $0 == firstTombstone })
        let plcCallCount = await plc.callCount()
        let dataCallCount = await data.callCount()
        let quiesceCallCount = await quiescer.callCount()
        XCTAssertEqual(plcCallCount, 1)
        XCTAssertEqual(dataCallCount, 1)
        XCTAssertEqual(quiesceCallCount, 1)
        try await control.close()
    }

    func testCoordinatorFailsBeforePLCWhenDIDScopedQuiescenceCannotBeProven() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(
            dataDirectory: root.appending(path: "data")
        )
        let keyStore = try FileAccountKeyStore(
            root: root.appending(path: "keys"),
            configuration: try AccountKeyEncryptionConfiguration(
                activeKeyID: "deletion-quiescence",
                activeKey: Data(repeating: 0x76, count: 32)
            )
        )
        let signing = try AccountKeyReference(
            accountDID: did,
            purpose: .signing,
            generation: 1
        )
        let rotation = try AccountKeyReference(
            accountDID: did,
            purpose: .rotation,
            generation: 1
        )
        try await keyStore.createBatch([
            try AccountKeyMaterial(
                reference: signing,
                key: Data(repeating: 0x41, count: 32)
            ),
            try AccountKeyMaterial(
                reference: rotation,
                key: Data(repeating: 0x42, count: 32)
            ),
        ])
        _ = try await control.createAccount(
            try registration(handle: "quiescence.example.com")
        )
        let quiescer = RejectingDeletionQuiescer()
        let plc = CountingPLCTombstoner()
        let data = CountingDataDestroyer()
        let coordinator = AccountPermanentDeletionCoordinator(
            controlStore: control,
            keyStore: keyStore,
            quiescer: quiescer,
            plcTombstoner: plc,
            dataDestroyer: data
        )

        await XCTAssertThrowsErrorAsync(
            try await coordinator.beginAndResume(
                did: did,
                declaration: .init(),
                now: Date(timeIntervalSince1970: 1_750_000_800)
            )
        )

        let loadedJob = try await control.deletionJob(did: did)
        let job = try XCTUnwrap(loadedJob)
        let quiescerCallCount = await quiescer.callCount()
        let plcCallCount = await plc.callCount()
        let dataCallCount = await data.callCount()
        let signingByteCount = try await keyStore.key(for: signing).count
        let rotationByteCount = try await keyStore.key(for: rotation).count
        XCTAssertEqual(job.stage, .controlScrubbed)
        XCTAssertEqual(job.rotationKey?.generation, 1)
        XCTAssertEqual(quiescerCallCount, 1)
        XCTAssertEqual(plcCallCount, 0)
        XCTAssertEqual(dataCallCount, 0)
        XCTAssertEqual(signingByteCount, 32)
        XCTAssertEqual(rotationByteCount, 32)
        try await control.close()
    }

    private func registration(
        handle: String
    ) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier:
                "$argon2id$v=19$m=65536,t=2,p=1$initialsalt$initial-precomputed-verifier",
            signingKey: AccountControlKeyReference(
                purpose: .signing,
                generation: 1
            ),
            rotationKey: AccountControlKeyReference(
                purpose: .rotation,
                generation: 1
            ),
            publicGenesisCommitCID:
                "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            createdAt: Date(timeIntervalSince1970: 1_750_000_500)
        )
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "swan-deletion-coordinator-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }
}

private actor DeletionOrderRecorder {
    private var recorded: [String] = []

    func append(_ event: String) {
        recorded.append(event)
    }

    func events() -> [String] { recorded }
}

private actor RecordingDeletionQuiescer:
    AccountPermanentDeletionQuiescing
{
    let recorder: DeletionOrderRecorder?
    private var calls = 0

    init(recorder: DeletionOrderRecorder? = nil) {
        self.recorder = recorder
    }

    func quiesceAccount(did _: String) async throws {
        calls += 1
        await recorder?.append("quiesce")
    }

    func callCount() -> Int { calls }
}

private actor RejectingDeletionQuiescer:
    AccountPermanentDeletionQuiescing
{
    private var calls = 0

    func quiesceAccount(did _: String) throws {
        calls += 1
        throw SwanError.unavailable(
            "injected account quiescence failure"
        )
    }

    func callCount() -> Int { calls }
}

private actor CountingDeletionQuiescer:
    AccountPermanentDeletionQuiescing
{
    private var calls = 0

    func quiesceAccount(did _: String) async throws {
        calls += 1
        await Task.yield()
    }

    func callCount() -> Int { calls }
}

private actor KeyAssertingPLCTombstoner:
    AccountPermanentDeletionPLCTombstoner
{
    let keyStore: FileAccountKeyStore
    let rotationReference: AccountKeyReference
    let recorder: DeletionOrderRecorder
    private var received: AccountKeyReference?

    init(
        keyStore: FileAccountKeyStore,
        rotationReference: AccountKeyReference,
        recorder: DeletionOrderRecorder
    ) {
        self.keyStore = keyStore
        self.rotationReference = rotationReference
        self.recorder = recorder
    }

    func tombstonePLCIdentity(
        did _: String,
        rotationKey: AccountKeyReference
    ) async throws {
        guard rotationKey == rotationReference else {
            throw SwanError.unavailable(
                "deletion coordinator passed the wrong rotation generation"
            )
        }
        guard try await keyStore.key(for: rotationReference).count == 32 else {
            throw SwanError.unavailable(
                "rotation key disappeared before PLC tombstone"
            )
        }
        received = rotationKey
        await recorder.append("plc")
    }

    func receivedRotationKey() -> AccountKeyReference? { received }
}

private struct KeyErasureAssertingDataDestroyer:
    AccountPermanentDeletionDataDestroyer
{
    let keyStore: FileAccountKeyStore
    let signingReference: AccountKeyReference
    let recorder: DeletionOrderRecorder

    func destroyAccountData(did _: String) async throws {
        do {
            _ = try await keyStore.key(for: signingReference)
            throw SwanError.unavailable(
                "account data destruction ran before key erasure"
            )
        } catch let error as SwanError {
            guard error != .unavailable(
                "account data destruction ran before key erasure"
            ) else {
                throw error
            }
        }
        await recorder.append("data")
    }
}

private actor RecordingPLCTombstoner:
    AccountPermanentDeletionPLCTombstoner
{
    private var received: AccountKeyReference?

    func tombstonePLCIdentity(
        did _: String,
        rotationKey: AccountKeyReference
    ) async throws {
        received = rotationKey
    }

    func receivedRotationKey() -> AccountKeyReference? { received }
}

private actor FailAfterFirstDataDestruction:
    AccountPermanentDeletionDataDestroyer
{
    private var calls = 0

    func destroyAccountData(did _: String) throws {
        calls += 1
        if calls == 1 {
            throw SwanError.unavailable(
                "injected post-destruction interruption"
            )
        }
    }

    func callCount() -> Int { calls }
}

private actor CountingPLCTombstoner:
    AccountPermanentDeletionPLCTombstoner
{
    private var calls = 0

    func tombstonePLCIdentity(
        did _: String,
        rotationKey _: AccountKeyReference
    ) async throws {
        calls += 1
        await Task.yield()
    }

    func callCount() -> Int { calls }
}

private actor CountingDataDestroyer:
    AccountPermanentDeletionDataDestroyer
{
    private var calls = 0

    func destroyAccountData(did _: String) async throws {
        calls += 1
        await Task.yield()
    }

    func callCount() -> Int { calls }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ errorHandler: (any Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("expected expression to throw")
    } catch {
        errorHandler(error)
    }
}
