import Crypto
import Foundation
import Petrel
import SwanCore
import SwanPublicFirehose
import SwanPublicRepository
import XCTest
@testable import SwanSQLite

private struct FixedLifecycleAccountSource: PublicFirehoseAccountDatabaseSource {
  let accounts: [PublicFirehoseAccountDatabase]

  func publicFirehoseAccountDatabases() async throws -> [PublicFirehoseAccountDatabase] {
    accounts
  }
}

final class PublicLifecycleEmitterTests: XCTestCase {
  private let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
  private let epoch = Date(timeIntervalSince1970: 1_785_844_800)

  private var root: URL!
  private var control: SQLiteControlDatabase!
  private var account: SQLiteAccountDatabase!
  private var emitter: SQLitePublicLifecycleEmitter!

  override func setUp() async throws {
    let root = FileManager.default.temporaryDirectory
      .appending(path: "swan-lifecycle-emitter-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
      at: root,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    self.root = root
    control = try await SQLiteControlDatabase(dataDirectory: root)
    account = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
    let key = P256.Signing.PrivateKey()
    let genesis = try PublicRepositoryGenesisCodec.create(
      did: did,
      revision: "3lqby3xuo4k2a",
      signingKey: key
    )
    _ = try await account.installPublicRepositoryGenesis(
      genesis,
      signingPublicKey: key.publicKey,
      installedAt: epoch
    )
    emitter = SQLitePublicLifecycleEmitter(
      control: control,
      accounts: FixedLifecycleAccountSource(
        accounts: [PublicFirehoseAccountDatabase(did: did, database: account)]
      )
    )
  }

  override func tearDown() async throws {
    try? await control?.close()
    try? await account?.close()
    if let root {
      try? FileManager.default.removeItem(at: root)
    }
  }

  func testEmitActivationEnqueuesBatchAndBarrieredHeadSync() async throws {
    try await emitter.emitActivation(
      did: did, operationID: "req-1", plcOperationCID: "bafyplc1",
      handle: "alice.example", materialTime: epoch, now: epoch
    )
    let pendingBatch = try await control.nextPendingLifecycleBatch(did: did)
    let batch = try XCTUnwrap(pendingBatch)
    XCTAssertEqual(batch.generation, 1)
    XCTAssertEqual(batch.items.count, 2)
    XCTAssertEqual(batch.items[0].kind, .identity)
    XCTAssertEqual(batch.items[1].kind, .account)
    let identity = try JSONDecoder().decode(
      PublicFirehoseIdentityMaterial.self, from: batch.items[0].payload
    )
    XCTAssertEqual(identity.handle, "alice.example")
    XCTAssertEqual(
      String(decoding: batch.items[0].payload, as: UTF8.self),
      #"{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","handle":"alice.example","time":"2026-08-04T12:00:00.000Z"}"#
    )
    let oldest = try await account.oldestPendingPublicFirehoseOutbox()
    let head = try XCTUnwrap(oldest)
    XCTAssertEqual(head.kind, .sync)
    XCTAssertEqual(head.lifecycleGeneration, batch.generation)
    XCTAssertEqual(
      head.sourceKey,
      PublicFirehoseSourceKey.syncActivation(did: did, operationID: "req-1")
    )
    XCTAssertFalse(head.carBytes.isEmpty)
  }

  func testEmitActivationIsIdempotentOnExactRetry() async throws {
    try await emitter.emitActivation(
      did: did, operationID: "req-1", plcOperationCID: "bafyplc1",
      handle: "alice.example", materialTime: epoch, now: epoch
    )
    try await emitter.emitActivation(
      did: did, operationID: "req-1", plcOperationCID: "bafyplc1",
      handle: "alice.example", materialTime: epoch, now: epoch
    )
    let generation = try await control.currentLifecycleGeneration(did: did)
    XCTAssertEqual(generation, 1)
    let pending = try await account.pendingPublicFirehoseOutbox()
    XCTAssertEqual(pending.count, 1, "the exact retry must not insert a second sync row")
    XCTAssertEqual(pending[0].sourceKey, PublicFirehoseSourceKey.syncActivation(did: did, operationID: "req-1"))
  }

  func testEmitActivationReusesByteIdenticalMaterialWithLaterInvocationClock() async throws {
    try await emitter.emitActivation(
      did: did, operationID: "req-later", plcOperationCID: "bafyplc-later",
      handle: "alice.example", materialTime: epoch, now: epoch
    )
    let firstPendingBatch = try await control.nextPendingLifecycleBatch(did: did)
    let firstBatch = try XCTUnwrap(firstPendingBatch)
    let firstPendingSync = try await account.oldestPendingPublicFirehoseOutbox()
    let firstSync = try XCTUnwrap(firstPendingSync)

    try await emitter.emitActivation(
      did: did, operationID: "req-later", plcOperationCID: "bafyplc-later",
      handle: "alice.example", materialTime: epoch,
      now: epoch.addingTimeInterval(60)
    )

    let replayedPendingBatch = try await control.nextPendingLifecycleBatch(did: did)
    let replayedBatch = try XCTUnwrap(replayedPendingBatch)
    let replayedPendingSync = try await account.oldestPendingPublicFirehoseOutbox()
    let replayedSync = try XCTUnwrap(replayedPendingSync)
    XCTAssertEqual(replayedBatch.items.map(\.payload), firstBatch.items.map(\.payload))
    XCTAssertEqual(replayedSync.payload, firstSync.payload)
  }

  func testEmitActivationStillRejectsChangedSemanticMaterialOnRetry() async throws {
    try await emitter.emitActivation(
      did: did, operationID: "req-conflict", plcOperationCID: "bafyplc-conflict",
      handle: "alice.example", materialTime: epoch, now: epoch
    )

    do {
      try await emitter.emitActivation(
        did: did, operationID: "req-conflict", plcOperationCID: "bafyplc-conflict",
        handle: "mallory.example", materialTime: epoch,
        now: epoch.addingTimeInterval(60)
      )
      XCTFail("changed lifecycle material must remain a hard conflict")
    } catch let error as LifecycleEventOutboxError {
      guard case .conflictingBatch = error else {
        return XCTFail("expected conflictingBatch, got \(error)")
      }
    }
  }

  func testEmitManualSyncUsesCurrentGenerationAndManualSourceKey() async throws {
    try await emitter.emitActivation(
      did: did, operationID: "req-1", plcOperationCID: "bafyplc1",
      handle: nil, materialTime: epoch, now: epoch
    )
    try await emitter.emitManualSync(did: did, requestUUID: "d0c0ffee", now: epoch)
    let activationPending = try await account.oldestPendingPublicFirehoseOutbox()
    let activation = try XCTUnwrap(activationPending)
    XCTAssertEqual(
      activation.sourceKey,
      PublicFirehoseSourceKey.syncActivation(did: did, operationID: "req-1")
    )
    let leased = try await account.leaseNextPublicFirehoseOutbox(
      now: epoch,
      leaseDuration: 30
    )
    let lease = try XCTUnwrap(leased)
    _ = try await account.completePublicFirehoseOutboxLease(
      id: lease.row.id,
      token: lease.token
    )
    let manualPending = try await account.oldestPendingPublicFirehoseOutbox()
    let manual = try XCTUnwrap(manualPending)
    XCTAssertEqual(
      manual.sourceKey,
      PublicFirehoseSourceKey.syncManual(did: did, requestUUID: "d0c0ffee")
    )
    XCTAssertEqual(manual.lifecycleGeneration, 1)
  }

  func testEmitRotationIdentityBumpsGenerationAndEmitsIdentityItemOnly() async throws {
    try await emitter.emitRotationIdentity(
      did: did, plcOperationCID: "bafyrotate1", handle: "alice.example",
      materialTime: epoch, now: epoch
    )
    let pendingBatch = try await control.nextPendingLifecycleBatch(did: did)
    let batch = try XCTUnwrap(pendingBatch)
    XCTAssertEqual(batch.generation, 1)
    XCTAssertEqual(batch.items.count, 1)
    XCTAssertEqual(batch.items[0].kind, .identity)
    XCTAssertEqual(
      batch.items[0].sourceKey,
      PublicFirehoseSourceKey.identity(did: did, plcOperationCID: "bafyrotate1")
    )
    let identity = try JSONDecoder().decode(
      PublicFirehoseIdentityMaterial.self, from: batch.items[0].payload
    )
    XCTAssertEqual(identity.handle, "alice.example")
    let pending = try await account.pendingPublicFirehoseOutbox()
    XCTAssertTrue(pending.isEmpty, "rotation identity emission must not touch the account outbox")
  }

  func testEmitRotationIdentityReusesByteIdenticalMaterialWithLaterInvocationClock() async throws {
    try await emitter.emitRotationIdentity(
      did: did, plcOperationCID: "bafyrotate-later", handle: "alice.example",
      materialTime: epoch, now: epoch
    )
    let firstPendingBatch = try await control.nextPendingLifecycleBatch(did: did)
    let firstBatch = try XCTUnwrap(firstPendingBatch)

    try await emitter.emitRotationIdentity(
      did: did, plcOperationCID: "bafyrotate-later", handle: "alice.example",
      materialTime: epoch, now: epoch.addingTimeInterval(60)
    )

    let replayedPendingBatch = try await control.nextPendingLifecycleBatch(did: did)
    let replayedBatch = try XCTUnwrap(replayedPendingBatch)
    XCTAssertEqual(replayedBatch.items.map(\.payload), firstBatch.items.map(\.payload))
  }

  func testEmitReactivationSyncUsesCurrentGenerationAndReactivationSourceKey() async throws {
    try await emitter.emitActivation(
      did: did, operationID: "req-1", plcOperationCID: "bafyplc1",
      handle: nil, materialTime: epoch, now: epoch
    )
    try await emitter.emitReactivationSync(did: did, operationID: "react-1", now: epoch)
    let activationLease = try await account.leaseNextPublicFirehoseOutbox(
      now: epoch,
      leaseDuration: 30
    )
    let drainedActivation = try XCTUnwrap(activationLease)
    XCTAssertEqual(
      drainedActivation.row.sourceKey,
      PublicFirehoseSourceKey.syncActivation(did: did, operationID: "req-1")
    )
    _ = try await account.completePublicFirehoseOutboxLease(
      id: drainedActivation.row.id,
      token: drainedActivation.token
    )
    let pendingHead = try await account.oldestPendingPublicFirehoseOutbox()
    let head = try XCTUnwrap(pendingHead)
    XCTAssertEqual(
      head.sourceKey,
      PublicFirehoseSourceKey.syncReactivation(did: did, operationID: "react-1")
    )
    XCTAssertEqual(head.lifecycleGeneration, 1)
    XCTAssertFalse(head.carBytes.isEmpty)
  }

  func testEmitterThrowsWhenAccountDatabaseIsUnknown() async throws {
    do {
      try await emitter.emitManualSync(did: "did:web:missing.example", requestUUID: "x", now: epoch)
      XCTFail("expected accountUnavailable")
    } catch let error as PublicLifecycleEmitterError {
      XCTAssertEqual(error, .accountUnavailable("did:web:missing.example"))
    }
  }
}
