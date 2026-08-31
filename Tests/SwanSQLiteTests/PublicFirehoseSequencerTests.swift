import Foundation
import Petrel
import SwanCore
import PetrelFirehose
import SwanStorage
import XCTest
@testable import SwanSQLite

private enum SequencerInjectedFailure: Error {
  case expected
}

private struct FixedAccountSource: PublicFirehoseAccountDatabaseSource {
  let accounts: [PublicFirehoseAccountDatabase]

  func publicFirehoseAccountDatabases() async throws -> [PublicFirehoseAccountDatabase] {
    accounts
  }
}

private actor RecordingWakeupSink: PublicFirehoseWakeupSink {
  private var maxSeqs: [Int64] = []

  func firehoseDidAppend(maxSeq: Int64) async {
    maxSeqs.append(maxSeq)
  }

  func received() -> [Int64] {
    maxSeqs
  }
}

private actor FirstCallThrower {
  private var count = 0

  func shouldThrow() -> Bool {
    count += 1
    return count == 1
  }
}

final class PublicFirehoseSequencerTests: XCTestCase {
  private let didA = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
  private let didB = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"
  private let epoch = Date(timeIntervalSince1970: 1_785_844_800)
  private let time = "2026-08-04T12:00:00.000Z"
  private let verifier =
    "$argon2id$v=19$m=65536,t=2,p=1$initialsalt$initial-precomputed-verifier"
  private let genesisCID =
    "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

  private static let payloadEncoder: JSONEncoder = {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return encoder
  }()

  private var root: URL!
  private var control: SQLiteControlDatabase!
  private var firehose: SQLiteFirehoseDatabase!
  private var accountA: SQLiteAccountDatabase!
  private var accountB: SQLiteAccountDatabase!

  override func setUp() async throws {
    let root = FileManager.default.temporaryDirectory
      .appending(path: "swan-sequencer-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
      at: root,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    self.root = root
    control = try await SQLiteControlDatabase(dataDirectory: root)
    firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    accountA = try await SQLiteAccountDatabase(dataDirectory: root, did: didA)
    accountB = try await SQLiteAccountDatabase(dataDirectory: root, did: didB)
  }

  override func tearDown() async throws {
    try? await firehose?.close()
    try? await control?.close()
    try? await accountA?.close()
    try? await accountB?.close()
    if let root {
      try? FileManager.default.removeItem(at: root)
    }
  }

  private func makeSequencer(
    accounts: [PublicFirehoseAccountDatabase]? = nil,
    wakeup: (any PublicFirehoseWakeupSink)? = nil
  ) throws -> PublicFirehoseSequencer {
    let source = FixedAccountSource(
      accounts: accounts ?? [
        PublicFirehoseAccountDatabase(did: didA, database: accountA),
        PublicFirehoseAccountDatabase(did: didB, database: accountB),
      ]
    )
    return PublicFirehoseSequencer(
      accountSource: source,
      control: control,
      firehose: firehose,
      wakeup: wakeup,
      configuration: try PublicFirehoseSequencerConfiguration(
        leaseDuration: 30,
        idlePollInterval: 0.25,
        initialFailureBackoff: 1,
        maximumFailureBackoff: 60
      )
    )
  }

  private func registration(
    did: String,
    handle: String,
    createdAt: Date
  ) throws -> AccountControlRegistration {
    try AccountControlRegistration(
      did: did,
      canonicalHandle: handle,
      passwordVerifier: verifier,
      signingKey: AccountControlKeyReference(
        purpose: .signing,
        generation: 3
      ),
      rotationKey: AccountControlKeyReference(
        purpose: .rotation,
        generation: 3
      ),
      publicGenesisCommitCID: genesisCID,
      createdAt: createdAt
    )
  }

  private func commitMaterial(did: String, commitCID: CID) -> PublicFirehoseCommitMaterial {
    PublicFirehoseCommitMaterial(
      did: did,
      rev: "3kabc",
      since: "3jzzz",
      commitCID: commitCID.string,
      prevDataCID: CID.fromDAGCBOR(Data([0x01, 0x02, 0x09])).string,
      ops: [],
      time: time
    )
  }

  private func commitPair(_ seed: UInt8) -> (cid: CID, bytes: Data) {
    let bytes = Data([0x01, 0x02, seed])
    return (CID.fromDAGCBOR(bytes), bytes)
  }

  private func commitCAR(_ cid: CID, bytes: Data) async throws -> Data {
    try await PublicFirehoseDiffCAR.commitOnly(commitCID: cid, commitBytes: bytes)
  }

  private func enqueueCommit(
    database: SQLiteAccountDatabase,
    did: String,
    generation: Int64,
    seed: UInt8,
    kind: PublicFirehoseEventKind = .commit
  ) async throws -> String {
    let pair = commitPair(seed)
    let car = try await commitCAR(pair.cid, bytes: pair.bytes)
    let sourceKey: String
    let payload: Data
    switch kind {
    case .commit:
      sourceKey = PublicFirehoseSourceKey.commit(did: did, commitCID: pair.cid.string)
      payload = try Self.payloadEncoder.encode(commitMaterial(did: did, commitCID: pair.cid))
    case .sync:
      sourceKey = PublicFirehoseSourceKey.syncOversize(did: did, commitCID: pair.cid.string)
      let material = PublicFirehoseSyncMaterial(did: did, rev: "3kabc", commitCID: pair.cid.string, time: time)
      payload = try Self.payloadEncoder.encode(material)
    case .identity, .account:
      fatalError("account outbox kinds are commit or sync")
    }
    _ = try await database.enqueuePublicFirehoseEvent(
      sourceKey: sourceKey,
      kind: kind,
      lifecycleGeneration: generation,
      payload: payload,
      carBytes: car,
      now: epoch
    )
    return sourceKey
  }

  private func identityItem(did: String, operationID: String) -> LifecycleEventItem {
    LifecycleEventItem(
      sourceKey: PublicFirehoseSourceKey.identity(did: did, plcOperationCID: "bafyid\(operationID)"),
      kind: .identity,
      payload: try! Self.payloadEncoder.encode(
        PublicFirehoseIdentityMaterial(did: did, handle: "\(did)-alice.test", time: time)
      ),
      carBytes: nil
    )
  }

  private func accountItem(did: String, operationID: String) -> LifecycleEventItem {
    LifecycleEventItem(
      sourceKey: PublicFirehoseSourceKey.account(did: did, operationID: operationID),
      kind: .account,
      payload: try! Self.payloadEncoder.encode(
        PublicFirehoseAccountMaterial(did: did, active: true, status: nil, time: time)
      ),
      carBytes: nil
    )
  }

  private func deletedAccountItem(did: String, operationID: String) -> LifecycleEventItem {
    LifecycleEventItem(
      sourceKey: PublicFirehoseSourceKey.account(did: did, operationID: operationID),
      kind: .account,
      payload: try! Self.payloadEncoder.encode(
        PublicFirehoseAccountMaterial(
          did: did,
          active: false,
          status: .deleted,
          time: time
        )
      ),
      carBytes: nil
    )
  }

  func testOrdinaryGenerationZeroCommitFlowsToGlobalSequenceOne() async throws {
    let sequencer = try makeSequencer()
    let sourceKey = try await enqueueCommit(
      database: accountA,
      did: didA,
      generation: 0,
      seed: 0x01
    )
    let result = try await sequencer.sequenceNext(now: epoch)
    XCTAssertEqual(
      result,
      .sequencedAccountEvent(sourceKey: sourceKey, seq: 1)
    )
    let pending = try await accountA.pendingPublicFirehoseOutbox()
    XCTAssertTrue(pending.isEmpty)
    let events = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(events.count, 1)
    XCTAssertEqual(events[0].seq, 1)
    XCTAssertEqual(events[0].kind, .commit)
    XCTAssertEqual(events[0].did, didA)
  }

  func testWakeupReceivesNewMaxSequenceAfterSourceCompletion() async throws {
    let wakeup = RecordingWakeupSink()
    let sequencer = try makeSequencer(wakeup: wakeup)
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 0, seed: 0x01)
    _ = try await enqueueCommit(database: accountB, did: didB, generation: 0, seed: 0x02)
    _ = try await sequencer.sequenceNext(now: epoch)
    _ = try await sequencer.sequenceNext(now: epoch)
    let received = await wakeup.received()
    XCTAssertEqual(received, [1, 2])
  }

  func testAccountCrashReplayReusesOriginalSequence() async throws {
    let sequencer = try makeSequencer()
    let sourceKey = try await enqueueCommit(
      database: accountA,
      did: didA,
      generation: 0,
      seed: 0x03
    )
    let thrower = FirstCallThrower()
    await sequencer.setTestCrashHook { _ in
      if await thrower.shouldThrow() {
        throw SequencerInjectedFailure.expected
      }
    }
    do {
      _ = try await sequencer.sequenceNext(now: epoch)
      XCTFail("expected injected failure")
    } catch SequencerInjectedFailure.expected {}
    let afterCrash = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(afterCrash.count, 1)
    XCTAssertEqual(afterCrash[0].seq, 1)
    XCTAssertEqual(afterCrash[0].sourceKey, sourceKey)

    let retried = try await sequencer.sequenceNext(now: epoch.addingTimeInterval(31))
    XCTAssertEqual(retried, .sequencedAccountEvent(sourceKey: sourceKey, seq: 1))
    let afterRetry = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(afterRetry.count, 1)
    let pending = try await accountA.pendingPublicFirehoseOutbox()
    XCTAssertTrue(pending.isEmpty)
  }

  func testLifecycleCrashReplayReusesConsecutiveRange() async throws {
    let sequencer = try makeSequencer()
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-1",
      items: [identityItem(did: didA, operationID: "op-1"), accountItem(did: didA, operationID: "op-1")],
      now: epoch
    )
    let thrower = FirstCallThrower()
    await sequencer.setTestCrashHook { _ in
      if await thrower.shouldThrow() {
        throw SequencerInjectedFailure.expected
      }
    }
    do {
      _ = try await sequencer.sequenceNext(now: epoch)
      XCTFail("expected injected failure")
    } catch SequencerInjectedFailure.expected {}
    let afterCrash = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(afterCrash.map(\.seq), [1, 2])

    let retried = try await sequencer.sequenceNext(now: epoch.addingTimeInterval(1))
    guard case let .sequencedLifecycleBatch(batchID, seqs) = retried else {
      return XCTFail("expected lifecycle batch result, got \(retried)")
    }
    XCTAssertEqual(seqs, [1, 2])
    XCTAssertEqual(batchID, PublicFirehoseSourceKey.lifecycleBatch(did: didA, operationID: "op-1"))
    let afterRetry = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(afterRetry.map(\.seq), [1, 2])
    let pendingBatch = try await control.nextPendingLifecycleBatch(did: didA)
    XCTAssertNil(pendingBatch)
  }

  func testSameGenerationOrderingIdentityThenAccountThenAccountEvent() async throws {
    let sequencer = try makeSequencer()
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-1",
      items: [identityItem(did: didA, operationID: "op-1"), accountItem(did: didA, operationID: "op-1")],
      now: epoch
    )
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 1, seed: 0x04)
    _ = try await sequencer.sequenceNext(now: epoch)
    _ = try await sequencer.sequenceNext(now: epoch)
    let events = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(events.map(\.kind), [.identity, .account, .commit])
    XCTAssertEqual(events.map(\.seq), [1, 2, 3])
  }

  func testTwoSidedBoundaryOrderingAcrossGenerations() async throws {
    let sequencer = try makeSequencer()
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 0, seed: 0x10)
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-1",
      items: [identityItem(did: didA, operationID: "op-1"), accountItem(did: didA, operationID: "op-1")],
      now: epoch
    )
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 1, seed: 0x11)
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-2",
      items: [identityItem(did: didA, operationID: "op-2"), accountItem(did: didA, operationID: "op-2")],
      now: epoch
    )
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 2, seed: 0x12)
    let steps = try await sequencer.drainAll(now: epoch)
    XCTAssertEqual(steps, 5)
    let events = try await firehose.events(after: 0, limit: 20, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(
      events.map(\.kind),
      [.commit, .identity, .account, .commit, .identity, .account, .commit]
    )
    XCTAssertEqual(events.map(\.seq), [1, 2, 3, 4, 5, 6, 7])
  }

  func testMultiplePendingLifecycleGenerationsMergeWithAccountHeads() async throws {
    let sequencer = try makeSequencer()
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-1",
      items: [identityItem(did: didA, operationID: "op-1")],
      now: epoch
    )
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 1, seed: 0x20)
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-2",
      items: [accountItem(did: didA, operationID: "op-2")],
      now: epoch
    )
    _ = try await sequencer.drainAll(now: epoch)
    let events = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(events.map(\.kind), [.identity, .commit, .account])
  }

  func testBlockedHeadBlocksItsDIDOnly() async throws {
    let sequencer = try makeSequencer()
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 0, seed: 0x30, kind: .commit)
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 0, seed: 0x31, kind: .commit)
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-1",
      items: [identityItem(did: didA, operationID: "op-1")],
      now: epoch
    )
    let lease = try await accountA.leaseNextPublicFirehoseOutbox(
      now: epoch,
      leaseDuration: 30
    )
    let unwrappedLease = try XCTUnwrap(lease)
    _ = try await accountA.failPublicFirehoseOutboxLease(
      id: unwrappedLease.row.id,
      token: unwrappedLease.token,
      retryAt: epoch.addingTimeInterval(300)
    )
    let keyB = try await enqueueCommit(database: accountB, did: didB, generation: 0, seed: 0x32)
    let result = try await sequencer.sequenceNext(now: epoch)
    XCTAssertEqual(result, .sequencedAccountEvent(sourceKey: keyB, seq: 1))
    let second = try await sequencer.sequenceNext(now: epoch)
    XCTAssertEqual(second, .idle)
  }

  func testRoundRobinPreventsStarvation() async throws {
    let sequencer = try makeSequencer()
    let keyA1 = try await enqueueCommit(database: accountA, did: didA, generation: 0, seed: 0x40)
    let keyA2 = try await enqueueCommit(database: accountA, did: didA, generation: 0, seed: 0x41)
    let keyB1 = try await enqueueCommit(database: accountB, did: didB, generation: 0, seed: 0x42)
    let first = try await sequencer.sequenceNext(now: epoch)
    let second = try await sequencer.sequenceNext(now: epoch)
    let third = try await sequencer.sequenceNext(now: epoch)
    let firstKey: String
    switch first {
    case let .sequencedAccountEvent(sourceKey, _): firstKey = sourceKey
    default: return XCTFail("unexpected first result \(first)")
    }
    let secondKey: String
    switch second {
    case let .sequencedAccountEvent(sourceKey, _): secondKey = sourceKey
    default: return XCTFail("unexpected second result \(second)")
    }
    XCTAssertTrue(
      (firstKey == keyA1 && secondKey == keyB1) || (firstKey == keyB1 && secondKey == keyA1),
      "first two steps must alternate DIDs, got \(firstKey), \(secondKey)"
    )
    let thirdKey: String
    switch third {
    case let .sequencedAccountEvent(sourceKey, _): thirdKey = sourceKey
    default: return XCTFail("unexpected third result \(third)")
    }
    XCTAssertEqual(thirdKey, keyA2)
    XCTAssertEqual(Set([firstKey, secondKey, thirdKey]), Set([keyA1, keyA2, keyB1]))
  }

  func testStoredFinalKindIsHonoredWithoutReinterpretation() async throws {
    let sequencer = try makeSequencer()
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 0, seed: 0x50, kind: .commit)
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 0, seed: 0x51, kind: .sync)
    _ = try await sequencer.drainAll(now: epoch)
    let events = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(events.map(\.kind), [.commit, .sync])
  }

  func testLifecycleSyncUsesStoredCARBytes() async throws {
    let sequencer = try makeSequencer()
    let pair = commitPair(0x60)
    let car = try await commitCAR(pair.cid, bytes: pair.bytes)
    let material = PublicFirehoseSyncMaterial(did: didA, rev: "3kabc", commitCID: pair.cid.string, time: time)
    let item = LifecycleEventItem(
      sourceKey: PublicFirehoseSourceKey.syncActivation(did: didA, operationID: "op-1"),
      kind: .sync,
      payload: try Self.payloadEncoder.encode(material),
      carBytes: car
    )
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "op-1",
      items: [item],
      now: epoch
    )
    _ = try await sequencer.sequenceNext(now: epoch)
    let events = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(events.count, 1)
    XCTAssertEqual(events[0].kind, .sync)
    let expected = try FirehoseFrameEncoder.syncFrame(seq: 1, material: material, commitCAR: car)
    XCTAssertEqual(events[0].frameBytes, expected)
  }

  func testSourceConflictFailsClosedWithoutDeletingSource() async throws {
    let sequencer = try makeSequencer()
    let sourceKey = try await enqueueCommit(
      database: accountA,
      did: didA,
      generation: 0,
      seed: 0x70
    )
    let conflictDID = didA
    let conflictTime = time
    _ = try await firehose.appendBatch(
      [
        FirehoseAppendItem(
          sourceKey: sourceKey,
          batchID: nil,
          did: didA,
          kind: .identity
        ) { seq in
          try FirehoseFrameEncoder.identityFrame(
            seq: seq,
            material: PublicFirehoseIdentityMaterial(
              did: conflictDID,
              handle: nil,
              time: conflictTime
            )
          )
        },
      ],
      now: epoch
    )
    do {
      _ = try await sequencer.sequenceNext(now: epoch)
      XCTFail("expected conflicting source key")
    } catch let error as SQLiteFirehoseDatabaseError {
      guard case .conflictingSourceKey = error else {
        return XCTFail("expected conflictingSourceKey, got \(error)")
      }
    }
    let pending = try await accountA.pendingPublicFirehoseOutbox()
    XCTAssertEqual(pending.count, 1)
    XCTAssertEqual(pending.first?.sourceKey, sourceKey)
    let events = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(events.count, 1)
    XCTAssertEqual(events[0].kind, .identity)
  }

  func testStaleLeaseCompletionProducesLeaseLostWhileAppendRemainsDurable() async throws {
    let sequencer = try makeSequencer()
    let sourceKey = try await enqueueCommit(
      database: accountA,
      did: didA,
      generation: 0,
      seed: 0x80
    )
    let database = try XCTUnwrap(accountA)
    await sequencer.setTestCrashHook { context in
      guard let lease = context.accountLease else {
        throw SequencerInjectedFailure.expected
      }
      _ = try await database.completePublicFirehoseOutboxLease(
        id: lease.id,
        token: lease.token
      )
    }
    let result = try await sequencer.sequenceNext(now: epoch)
    XCTAssertEqual(result, .leaseLost(sourceKey: sourceKey, seq: 1))
    let events = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(events.count, 1)
    XCTAssertEqual(events[0].seq, 1)
    XCTAssertEqual(events[0].sourceKey, sourceKey)
  }

  func testDrainAllCountsSuccessfulSourceSteps() async throws {
    let sequencer = try makeSequencer()
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 0, seed: 0x90)
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 0, seed: 0x91)
    _ = try await control.enqueueLifecycleEventBatch(
      did: didB,
      operationID: "op-1",
      items: [identityItem(did: didB, operationID: "op-1"), accountItem(did: didB, operationID: "op-1")],
      now: epoch
    )
    let steps = try await sequencer.drainAll(now: epoch)
    XCTAssertEqual(steps, 3)
    let events = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(events.count, 4)
  }

  func testDeletedAccountEventAndPriorDIDPruningShareOneGlobalAppend() async throws {
    let sequencer = try makeSequencer()
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 0, seed: 0x01)
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 0, seed: 0x02)
    _ = try await enqueueCommit(database: accountB, did: didB, generation: 0, seed: 0x03)
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "delete-1",
      items: [deletedAccountItem(did: didA, operationID: "delete-1")],
      now: epoch
    )

    let steps = try await sequencer.drainAll(now: epoch)
    XCTAssertEqual(steps, 4)
    let events = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(events.map(\.seq), [2, 4])
    XCTAssertEqual(events.map(\.did), [didB, didA])
    XCTAssertEqual(events.last?.kind, .account)
    let maxSeq = try await firehose.maxSequencedSeq()
    XCTAssertEqual(maxSeq, 4)
    let pendingBatch = try await control.nextPendingLifecycleBatch(did: didA)
    XCTAssertNil(pendingBatch)
    let pendingAccountRows = try await accountA.pendingPublicFirehoseOutbox()
    XCTAssertEqual(
      pendingAccountRows,
      [],
      "the account-local source is completed after the global transaction"
    )
  }

  func testDeletedAccountCrashReplayKeepsDeletionAtomic() async throws {
    let sequencer = try makeSequencer()
    let oldMaterial = PublicFirehoseIdentityMaterial(
      did: didA,
      handle: "alice.test",
      time: time
    )
    _ = try await firehose.appendBatch(
      [
        FirehoseAppendItem(
          sourceKey: "pre-delete-1",
          batchID: "pre-delete-history",
          did: didA,
          kind: .identity
        ) { seq in
          try FirehoseFrameEncoder.identityFrame(seq: seq, material: oldMaterial)
        },
        FirehoseAppendItem(
          sourceKey: "pre-delete-2",
          batchID: "pre-delete-history",
          did: didA,
          kind: .identity
        ) { seq in
          try FirehoseFrameEncoder.identityFrame(seq: seq, material: oldMaterial)
        },
      ],
      now: epoch
    )
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "delete-crash",
      items: [deletedAccountItem(did: didA, operationID: "delete-crash")],
      now: epoch
    )

    let thrower = FirstCallThrower()
    await sequencer.setTestCrashHook { context in
      guard context.batchID != nil, await thrower.shouldThrow() else { return }
      throw SequencerInjectedFailure.expected
    }
    do {
      _ = try await sequencer.sequenceNext(now: epoch)
      XCTFail("expected injected failure after the deletion transaction")
    } catch SequencerInjectedFailure.expected {}

    let afterCrash = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(afterCrash.map(\.seq), [3])
    XCTAssertEqual(afterCrash.first?.kind, .account)
    let pendingAfterCrash = try await control.nextPendingLifecycleBatch(did: didA)
    XCTAssertNotNil(pendingAfterCrash)

    let retry = try await sequencer.sequenceNext(now: epoch.addingTimeInterval(1))
    guard case let .sequencedLifecycleBatch(_, seqs) = retry else {
      return XCTFail("expected the exact deletion batch replay")
    }
    XCTAssertEqual(seqs, [3])
    let afterRetry = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(afterRetry.map(\.seq), [3])
    let pendingAfterRetry = try await control.nextPendingLifecycleBatch(did: didA)
    XCTAssertNil(pendingAfterRetry)
  }

  /// Regression: a real lifecycle batch pairing a same-DID `#identity` item
  /// with the deleted `#account` marker item — the identity item is
  /// allocated a lower sequence than the account item inside this very
  /// batch. The delete boundary must exclude both items of this call, not
  /// just the marker's own row: only the DID's pre-batch history is pruned.
  func testDeletedAccountSurvivesSameBatchIdentitySibling() async throws {
    let sequencer = try makeSequencer()
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 0, seed: 0x06)
    _ = try await control.enqueueLifecycleEventBatch(
      did: didA,
      operationID: "delete-3",
      items: [
        identityItem(did: didA, operationID: "delete-3"),
        deletedAccountItem(did: didA, operationID: "delete-3"),
      ],
      now: epoch
    )

    let steps = try await sequencer.drainAll(now: epoch)
    XCTAssertEqual(steps, 2)
    let events = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(
      events.map(\.kind),
      [.identity, .account],
      "the pre-batch commit is pruned; the same-batch identity sibling survives alongside the deletion event"
    )
    XCTAssertEqual(events.map(\.did), [didA, didA])
    let maxSeq = try await firehose.maxSequencedSeq()
    XCTAssertEqual(maxSeq, 3)
  }

  func testRealBeginDeletionEmitsDeletedAccountAndPrunesPriorHistory() async throws {
    let sequencer = try makeSequencer()
    _ = try await control.createAccount(
      try registration(
        did: didA,
        handle: "delete-me.example.com",
        createdAt: epoch
      )
    )
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 0, seed: 0x01)
    _ = try await enqueueCommit(database: accountA, did: didA, generation: 0, seed: 0x02)
    _ = try await enqueueCommit(database: accountB, did: didB, generation: 0, seed: 0x03)
    let firstDrain = try await sequencer.drainAll(now: epoch)
    XCTAssertEqual(firstDrain, 3)

    _ = try await control.beginDeletion(did: didA, declaration: .init(), now: epoch)
    let secondDrain = try await sequencer.drainAll(now: epoch)
    XCTAssertEqual(secondDrain, 1)

    let events = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
    XCTAssertEqual(events.map(\.seq), [2, 4])
    XCTAssertEqual(events.map(\.did), [didB, didA])
    XCTAssertEqual(events.last?.kind, .account)
    XCTAssertFalse(
      events.contains { $0.did == didA && $0.kind == .commit },
      "didA's earlier commits must be pruned by the real deletion"
    )
    let maxSeq = try await firehose.maxSequencedSeq()
    XCTAssertEqual(maxSeq, 4)
    let pendingBatch = try await control.nextPendingLifecycleBatch(did: didA)
    XCTAssertNil(pendingBatch)
  }
}
