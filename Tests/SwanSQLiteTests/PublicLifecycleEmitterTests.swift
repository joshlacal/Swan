import Crypto
import Foundation
import Petrel
import SwanCore
import PetrelFirehose
import PetrelRepo
import SwanStorage
import XCTest
@testable import SwanSQLite

private struct FixedLifecycleAccountSource: PublicFirehoseAccountDatabaseSource {
  let accounts: [PublicFirehoseAccountDatabase]

  func publicFirehoseAccountDatabases() async throws -> [PublicFirehoseAccountDatabase] {
    accounts
  }
}

private actor LifecycleAuthorizationBarrier {
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

final class PublicLifecycleEmitterTests: XCTestCase {
  private let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
  private let epoch = Date(timeIntervalSince1970: 1_785_844_800)

  private var root: URL!
  private var control: SQLiteControlDatabase!
  private var firehose: SQLiteFirehoseDatabase!
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
    _ = try await control.createAccount(
      AccountControlRegistration(
        did: did,
        canonicalHandle: "lifecycle-emitter.example.com",
        passwordVerifier:
          "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        signingKey: .init(purpose: .signing, generation: 1),
        rotationKey: .init(purpose: .rotation, generation: 1),
        createdAt: epoch
      )
    )
    firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
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
    try? await firehose?.close()
    try? await control?.close()
    try? await account?.close()
    if let root {
      try? FileManager.default.removeItem(at: root)
    }
  }

  private func makeSequencer() throws -> PublicFirehoseSequencer {
    PublicFirehoseSequencer(
      accountSource: FixedLifecycleAccountSource(
        accounts: [PublicFirehoseAccountDatabase(did: did, database: account)]
      ),
      control: control,
      firehose: firehose,
      configuration: try PublicFirehoseSequencerConfiguration(
        leaseDuration: 30,
        idlePollInterval: 0.25,
        initialFailureBackoff: 1,
        maximumFailureBackoff: 60
      )
    )
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

  func testEmitActivationExactRetryAcceptsCanonicalMillisecondTimestamp()
    async throws
  {
    // ISO8601DateFormatter parses this canonical .166 timestamp to a Date
    // whose floating-point calendar projection can report .165999889. Stored
    // validation must validate the canonical wire syntax, not require an
    // unstable Date round trip.
    let millisecondBoundary = Date(
      timeIntervalSince1970: 1_786_245_951.1661
    )
    XCTAssertEqual(
      PublicFirehoseTime.encode(millisecondBoundary),
      "2026-08-09T03:25:51.166Z"
    )
    try await emitter.emitActivation(
      did: did, operationID: "req-millisecond", plcOperationCID: "bafyplc-ms",
      handle: "alice.example", materialTime: millisecondBoundary,
      now: millisecondBoundary
    )
    try await emitter.emitActivation(
      did: did, operationID: "req-millisecond", plcOperationCID: "bafyplc-ms",
      handle: "alice.example", materialTime: millisecondBoundary,
      now: millisecondBoundary.addingTimeInterval(1)
    )

    let generation = try await control.currentLifecycleGeneration(did: did)
    let pending = try await account.pendingPublicFirehoseOutbox()
    XCTAssertEqual(generation, 1)
    XCTAssertEqual(pending.count, 1)
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

  func testActivationRetryAfterFullSequencingKeepsGenerationAndGlobalEventCount() async throws {
    let sequencer = try makeSequencer()
    try await emitter.emitActivation(
      did: did, operationID: "req-sequenced", plcOperationCID: "bafyplc-sequenced",
      handle: "alice.example", materialTime: epoch, now: epoch
    )
    let initialSteps = try await sequencer.drainAll(now: epoch)
    XCTAssertEqual(initialSteps, 2)
    let before = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(before.count, 3)

    try await emitter.emitActivation(
      did: did, operationID: "req-sequenced", plcOperationCID: "bafyplc-sequenced",
      handle: "alice.example", materialTime: epoch,
      now: epoch.addingTimeInterval(300)
    )

    let generation = try await control.currentLifecycleGeneration(did: did)
    XCTAssertEqual(generation, 1)
    let replaySteps = try await sequencer.drainAll(now: epoch.addingTimeInterval(300))
    XCTAssertEqual(replaySteps, 0)
    let after = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(after.map(\.sourceKey), before.map(\.sourceKey))
    XCTAssertEqual(after.map(\.seq), before.map(\.seq))
  }

  func testActivationRetryAfterLifecycleCompletionBeforeSyncDrainConverges() async throws {
    let sequencer = try makeSequencer()
    try await emitter.emitActivation(
      did: did, operationID: "req-crash-gap", plcOperationCID: "bafyplc-crash-gap",
      handle: "alice.example", materialTime: epoch, now: epoch
    )
    guard case .sequencedLifecycleBatch = try await sequencer.sequenceNext(now: epoch) else {
      return XCTFail("the lifecycle batch must sequence before its generation-matched sync")
    }
    let pendingLifecycleAfterFirstStep = try await control.nextPendingLifecycleBatch(did: did)
    XCTAssertNil(pendingLifecycleAfterFirstStep)
    let pendingSyncAfterFirstStep = try await account.pendingPublicFirehoseOutbox()
    XCTAssertEqual(pendingSyncAfterFirstStep.count, 1)

    try await emitter.emitActivation(
      did: did, operationID: "req-crash-gap", plcOperationCID: "bafyplc-crash-gap",
      handle: "alice.example", materialTime: epoch,
      now: epoch.addingTimeInterval(300)
    )

    let replayedGeneration = try await control.currentLifecycleGeneration(did: did)
    XCTAssertEqual(replayedGeneration, 1)
    let replayedPendingLifecycle = try await control.nextPendingLifecycleBatch(did: did)
    XCTAssertNil(replayedPendingLifecycle)
    let replayedPendingSync = try await account.pendingPublicFirehoseOutbox()
    XCTAssertEqual(replayedPendingSync.count, 1)
    let remainingSteps = try await sequencer.drainAll(now: epoch.addingTimeInterval(300))
    XCTAssertEqual(remainingSteps, 1)
    let events = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(events.count, 3)
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

  func testEmitManualSyncExactRetryKeepsOneDurableSourceRow() async throws {
    let requestID = "123e4567-e89b-42d3-a456-426614174000"
    try await emitter.emitManualSync(did: did, requestUUID: requestID, now: epoch)
    try await emitter.emitManualSync(
      did: did, requestUUID: requestID, now: epoch.addingTimeInterval(1)
    )
    let pending = try await account.pendingPublicFirehoseOutbox()
    XCTAssertEqual(pending.count, 1)
    XCTAssertEqual(
      pending.first?.sourceKey,
      PublicFirehoseSourceKey.syncManual(did: did, requestUUID: requestID)
    )
    let leasedValue = try await account.leaseNextPublicFirehoseOutbox(
      now: epoch, leaseDuration: 30
    )
    let leased = try XCTUnwrap(leasedValue)
    let completed = try await account.completePublicFirehoseOutboxLease(
      id: leased.row.id, token: leased.token
    )
    XCTAssertTrue(completed)
    try await account.close()
    account = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
    emitter = SQLitePublicLifecycleEmitter(
      control: control,
      accounts: FixedLifecycleAccountSource(
        accounts: [PublicFirehoseAccountDatabase(did: did, database: account)]
      )
    )
    try await emitter.emitManualSync(
      did: did, requestUUID: requestID, now: epoch.addingTimeInterval(2)
    )
    let pendingAfterRestart = try await account.pendingPublicFirehoseOutbox()
    XCTAssertEqual(pendingAfterRestart.count, 0)

    let secondRequestID = "123e4567-e89b-42d3-a456-426614174001"
    try await emitter.emitManualSync(
      did: did, requestUUID: secondRequestID, now: epoch.addingTimeInterval(3)
    )
    let secondPending = try await account.pendingPublicFirehoseOutbox()
    XCTAssertEqual(secondPending.count, 1)
    XCTAssertEqual(
      secondPending.first?.sourceKey,
      PublicFirehoseSourceKey.syncManual(did: did, requestUUID: secondRequestID)
    )
  }

  func testManualSyncLosesDeterministicRaceToDeactivation() async throws {
    let barrier = LifecycleAuthorizationBarrier()
    let racingEmitter = SQLitePublicLifecycleEmitter(
      control: control,
      accounts: FixedLifecycleAccountSource(
        accounts: [PublicFirehoseAccountDatabase(did: did, database: account)]
      ),
      hooks: .init(beforeManualAuthorization: { await barrier.park() })
    )
    let accountDID = did
    let eventTime = epoch
    let emission = Task {
      try await racingEmitter.emitManualSync(
        did: accountDID,
        requestUUID: "123e4567-e89b-42d3-a456-426614174002",
        now: eventTime
      )
    }
    await barrier.waitUntilParked()
    _ = try await control.transitionStatus(
      did: did,
      to: .deactivated,
      declaration: .init(),
      now: epoch.addingTimeInterval(1)
    )
    await barrier.release()
    do {
      try await emission.value
      XCTFail("deactivated account emitted a manual sync")
    } catch let error as AccountControlStoreError {
      XCTAssertEqual(error, .invalidTransition)
    }
    let pending = try await account.pendingPublicFirehoseOutbox()
    XCTAssertTrue(pending.isEmpty)
  }

  /// F37. The property is stated the way the relay observes it: once
  /// `#account(active:false)` has been sequenced onto the public firehose, no
  /// `#sync` announcing a superseded repository generation may follow it.
  /// `emitActivation` publishes its head sync after its own lifecycle batch
  /// has already committed, so a deactivation that linearizes in between can
  /// drain the whole lifecycle queue before the sync row is ever inserted —
  /// at which point the sequencer has no pending batch to order it against.
  func testActivationSyncLosesDeterministicRaceToDeactivation() async throws {
    let barrier = LifecycleAuthorizationBarrier()
    let racingEmitter = SQLitePublicLifecycleEmitter(
      control: control,
      accounts: FixedLifecycleAccountSource(
        accounts: [PublicFirehoseAccountDatabase(did: did, database: account)]
      ),
      hooks: .init(beforeActivationAuthorization: { await barrier.park() })
    )
    let accountDID = did
    let eventTime = epoch
    let emission = Task {
      try await racingEmitter.emitActivation(
        did: accountDID, operationID: "req-raced", plcOperationCID: "bafyplc-raced",
        handle: "alice.example", materialTime: eventTime, now: eventTime
      )
    }
    await barrier.waitUntilParked()
    _ = try await control.transitionStatus(
      did: did,
      to: .deactivated,
      declaration: .init(),
      emitting: .init(operationID: "deact-during-activation"),
      now: epoch.addingTimeInterval(1)
    )
    // Drain everything durable at this instant: the activation batch
    // (generation 1) and the deactivation batch (generation 2). The account
    // outbox is still empty, so #account(active:false) is the firehose tail
    // and there is no pending batch left for the sequencer to order a late
    // sync row against.
    let sequencer = try makeSequencer()
    let drainedBeforeRelease = try await sequencer.drainAll(
      now: epoch.addingTimeInterval(1)
    )
    XCTAssertEqual(drainedBeforeRelease, 2)
    await barrier.release()

    do {
      try await emission.value
      XCTFail("a deactivated account published an activation sync")
    } catch let error as AccountControlStoreError {
      XCTAssertEqual(error, .invalidTransition)
    }
    let pending = try await account.pendingPublicFirehoseOutbox()
    XCTAssertTrue(pending.isEmpty, "the raced activation sync must not become durable")
    let drainedAfterRelease = try await sequencer.drainAll(
      now: epoch.addingTimeInterval(2)
    )
    XCTAssertEqual(drainedAfterRelease, 0)
    let events = try await firehose.events(after: 0, limit: 20, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(
      events.map(\.kind),
      [.identity, .account, .account],
      "no #sync may be sequenced after the #account(active:false) that supersedes it"
    )
    XCTAssertEqual(
      events.last?.sourceKey,
      PublicFirehoseSourceKey.account(
        did: did, operationID: "deact-during-activation"
      )
    )
  }

  /// F37, reactivation half. `emitReactivationSync` reads the generation and
  /// then performs unfenced account-database I/O before inserting the sync
  /// row, so the same interleaving republishes an already-superseded head.
  func testReactivationSyncLosesDeterministicRaceToDeactivation() async throws {
    let sequencer = try makeSequencer()
    try await emitter.emitActivation(
      did: did, operationID: "req-1", plcOperationCID: "bafyplc1",
      handle: "alice.example", materialTime: epoch, now: epoch
    )
    let drainedActivation = try await sequencer.drainAll(now: epoch)
    XCTAssertEqual(drainedActivation, 2)

    let barrier = LifecycleAuthorizationBarrier()
    let racingEmitter = SQLitePublicLifecycleEmitter(
      control: control,
      accounts: FixedLifecycleAccountSource(
        accounts: [PublicFirehoseAccountDatabase(did: did, database: account)]
      ),
      hooks: .init(beforeReactivationAuthorization: { await barrier.park() })
    )
    let accountDID = did
    let eventTime = epoch
    let emission = Task {
      try await racingEmitter.emitReactivationSync(
        did: accountDID, operationID: "react-raced", now: eventTime
      )
    }
    await barrier.waitUntilParked()
    _ = try await control.transitionStatus(
      did: did,
      to: .deactivated,
      declaration: .init(),
      emitting: .init(operationID: "deact-during-reactivation"),
      now: epoch.addingTimeInterval(1)
    )
    let drainedDeactivation = try await sequencer.drainAll(
      now: epoch.addingTimeInterval(1)
    )
    XCTAssertEqual(drainedDeactivation, 1)
    await barrier.release()

    do {
      try await emission.value
      XCTFail("a deactivated account published a reactivation sync")
    } catch let error as AccountControlStoreError {
      XCTAssertEqual(error, .invalidTransition)
    }
    let pending = try await account.pendingPublicFirehoseOutbox()
    XCTAssertTrue(pending.isEmpty, "the raced reactivation sync must not become durable")
    let drainedAfterRelease = try await sequencer.drainAll(
      now: epoch.addingTimeInterval(2)
    )
    XCTAssertEqual(drainedAfterRelease, 0)
    let events = try await firehose.events(after: 0, limit: 20, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(
      events.map(\.kind),
      [.identity, .account, .sync, .account],
      "no #sync may be sequenced after the #account(active:false) that supersedes it"
    )
    XCTAssertEqual(
      events.last?.sourceKey,
      PublicFirehoseSourceKey.account(
        did: did, operationID: "deact-during-reactivation"
      )
    )
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

  func testCompletedManualSyncReplayIdempotency() async throws {
    let requestUUID = UUID().uuidString.lowercased()
    try await emitter.emitManualSync(did: did, requestUUID: requestUUID, now: epoch)

    let leased = try await account.leaseNextPublicFirehoseOutbox(
      now: epoch,
      leaseDuration: 30
    )
    let lease = try XCTUnwrap(leased)
    XCTAssertEqual(
      lease.row.sourceKey,
      PublicFirehoseSourceKey.syncManual(did: did, requestUUID: requestUUID)
    )
    let completed = try await account.completePublicFirehoseOutboxLease(
      id: lease.row.id,
      token: lease.token
    )
    XCTAssertTrue(completed)

    // Replay emitManualSync with the same requestUUID
    try await emitter.emitManualSync(did: did, requestUUID: requestUUID, now: epoch.addingTimeInterval(5))

    // Assert that no new pending item is enqueued
    let pending = try await account.oldestPendingPublicFirehoseOutbox()
    XCTAssertNil(pending)
  }
}
