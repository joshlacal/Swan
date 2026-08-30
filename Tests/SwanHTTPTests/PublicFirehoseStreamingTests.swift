import Foundation
import Logging
import Petrel
import SwanCore
import PetrelFirehose
import XCTest
@testable import SwanHTTP
@testable import SwanSQLite

final class PublicFirehoseStreamingTests: XCTestCase {
  private let did = "did:plc:abcdefghijklmnopqrstuvwx"
  private let time = "2026-08-04T12:00:00.000Z"
  private let epoch = Date(timeIntervalSince1970: 1_785_844_800)
  private let logger = Logger(label: "swan.public-firehose-streaming-tests")

  private func makeRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory
      .appending(path: "swan-firehose-streaming-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
      at: root,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    return root
  }

  private func identityItem(sourceKey: String, did: String? = nil) -> FirehoseAppendItem {
    let identityDID = did ?? self.did
    let material = PublicFirehoseIdentityMaterial(
      did: identityDID,
      handle: "alice.test",
      time: time
    )
    return FirehoseAppendItem(
      sourceKey: sourceKey,
      batchID: nil,
      did: identityDID,
      kind: .identity
    ) { seq in
      try FirehoseFrameEncoder.identityFrame(seq: seq, material: material)
    }
  }

  private func deletedAccountItem(sourceKey: String, did: String? = nil) -> FirehoseAppendItem {
    let accountDID = did ?? self.did
    let material = PublicFirehoseAccountMaterial(
      did: accountDID,
      active: false,
      status: .deleted,
      time: time
    )
    return FirehoseAppendItem(
      sourceKey: sourceKey,
      batchID: nil,
      did: accountDID,
      kind: .account
    ) { seq in
      try FirehoseFrameEncoder.accountFrame(seq: seq, material: material)
    }
  }

  private actor FrameRecorder {
    private var frames: [Data] = []

    func record(_ frame: Data) {
      frames.append(frame)
    }

    func snapshot() -> [Data] {
      frames
    }
  }

  private func waitUntil(
    timeoutNanoseconds: UInt64 = 5_000_000_000,
    _ condition: @escaping @Sendable () async -> Bool
  ) async throws {
    let deadline = ContinuousClock.now + .seconds(
      Double(timeoutNanoseconds) / 1_000_000_000
    )
    while ContinuousClock.now < deadline {
      if await condition() { return }
      try await Task.sleep(nanoseconds: 10_000_000)
    }
    XCTFail("condition not met before deadline")
  }

  // MARK: - Cursor policy

  func testCursorPolicyMatrix() {
    XCTAssertEqual(
      PublicFirehoseCursorPolicy.resolve(
        cursor: nil,
        maxSequencedSeq: 10,
        retainedFromSeq: nil
      ),
      .live
    )
    XCTAssertEqual(
      PublicFirehoseCursorPolicy.resolve(
        cursor: 0,
        maxSequencedSeq: 10,
        retainedFromSeq: 1
      ),
      .fullWindow
    )
    XCTAssertEqual(
      PublicFirehoseCursorPolicy.resolve(
        cursor: 3,
        maxSequencedSeq: 10,
        retainedFromSeq: nil
      ),
      .backfill(from: 3)
    )
    XCTAssertEqual(
      PublicFirehoseCursorPolicy.resolve(
        cursor: 10,
        maxSequencedSeq: 10,
        retainedFromSeq: nil
      ),
      .backfill(from: 10)
    )
    XCTAssertEqual(
      PublicFirehoseCursorPolicy.resolve(
        cursor: 11,
        maxSequencedSeq: 10,
        retainedFromSeq: nil
      ),
      .futureCursor
    )
    XCTAssertEqual(
      PublicFirehoseCursorPolicy.resolve(
        cursor: 2,
        maxSequencedSeq: 10,
        retainedFromSeq: 5
      ),
      .outdatedCursor
    )
    XCTAssertEqual(
      PublicFirehoseCursorPolicy.resolve(
        cursor: 5,
        maxSequencedSeq: 10,
        retainedFromSeq: 5
      ),
      .backfill(from: 5)
    )
    XCTAssertEqual(
      PublicFirehoseCursorPolicy.resolve(
        cursor: 5,
        maxSequencedSeq: 10,
        retainedFromSeq: nil
      ),
      .backfill(from: 5)
    )
  }

  // MARK: - Tailer

  func testTailerBackfillThenLiveHasNoGapOrDuplicateAtBoundary() async throws {
    let root = try makeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await firehose.close() } }
    for index in 1 ... 5 {
      _ = try await firehose.appendBatch(
        [identityItem(sourceKey: "boundary-\(index)")],
        now: epoch
      )
    }
    let stored = try await firehose.events(after: 0, limit: 10)
    XCTAssertEqual(stored.map(\.seq), [1, 2, 3, 4, 5])

    let recorder = FrameRecorder()
    let wakeup = AsyncStream<Int64>.makeStream(bufferingPolicy: .bufferingNewest(1))
    let limits = try PublicFirehoseStreamingLimits()
    let tailer = PublicFirehoseTailer(database: firehose, limits: limits, logger: logger)
    let task = Task {
      try await tailer.run(
        lastSent: 3,
        outbound: { await recorder.record($0) },
        waitForWakeup: {
          for await seq in wakeup.stream {
            return seq
          }
          return nil
        }
      )
    }

    try await waitUntil { await recorder.snapshot().count == 2 }
    _ = try await firehose.appendBatch(
      [identityItem(sourceKey: "boundary-6")],
      now: epoch
    )
    wakeup.continuation.yield(6)

    try await waitUntil { await recorder.snapshot().count == 3 }
    let delivered = await recorder.snapshot()
    XCTAssertEqual(delivered.count, 3)
    let storedAfter = try await firehose.events(after: 0, limit: 10)
    XCTAssertEqual(storedAfter.map(\.seq), [1, 2, 3, 4, 5, 6])
    XCTAssertEqual(
      delivered,
      storedAfter.filter { $0.seq >= 4 }.map(\.frameBytes),
      "backfill must deliver 4, 5 then live 6 with no gap or duplicate"
    )

    task.cancel()
    wakeup.continuation.yield(Int64.max)
    _ = await task.result
  }

  func testTailerShipsStoredFrameBytesVerbatim() async throws {
    let root = try makeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await firehose.close() } }
    for index in 1 ... 2 {
      _ = try await firehose.appendBatch(
        [identityItem(sourceKey: "verbatim-\(index)")],
        now: epoch
      )
    }
    let stored = try await firehose.events(after: 0, limit: 10)

    let recorder = FrameRecorder()
    let limits = try PublicFirehoseStreamingLimits()
    let tailer = PublicFirehoseTailer(database: firehose, limits: limits, logger: logger)
    let task = Task {
      try await tailer.run(
        lastSent: 0,
        outbound: { await recorder.record($0) },
        waitForWakeup: { nil }
      )
    }
    defer { task.cancel() }

    try await waitUntil { await recorder.snapshot().count == 2 }
    let delivered = await recorder.snapshot()
    XCTAssertEqual(delivered, stored.map(\.frameBytes))
    task.cancel()
    _ = await task.result
  }

  func testTailerDroppedWakeupRecoversByPoll() async throws {
    let root = try makeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await firehose.close() } }

    let recorder = FrameRecorder()
    let limits = try PublicFirehoseStreamingLimits(idlePollInterval: 0.01)
    let tailer = PublicFirehoseTailer(database: firehose, limits: limits, logger: logger)
    let task = Task {
      try await tailer.run(
        lastSent: 0,
        outbound: { await recorder.record($0) },
        waitForWakeup: { nil }
      )
    }
    defer { task.cancel() }

    try await Task.sleep(nanoseconds: 50_000_000)
    _ = try await firehose.appendBatch(
      [identityItem(sourceKey: "poll-recovery")],
      now: epoch
    )
    try await waitUntil { await recorder.snapshot().count == 1 }
    let delivered = await recorder.snapshot()
    XCTAssertEqual(delivered.count, 1)
    task.cancel()
    _ = await task.result
  }

  func testTailerConsumerTooSlowPolicy() throws {
    let limits = try PublicFirehoseStreamingLimits(
      maximumSequenceLag: 1,
      maximumBackfillCatchUp: .milliseconds(10),
      maximumWriteDuration: .milliseconds(10)
    )
    XCTAssertTrue(
      PublicFirehoseSlowConsumerPolicy.shouldDrop(
        seqLag: 2,
        backfillElapsed: .zero,
        writeDuration: nil,
        limits: limits
      )
    )
    XCTAssertFalse(
      PublicFirehoseSlowConsumerPolicy.shouldDrop(
        seqLag: 1,
        backfillElapsed: .zero,
        writeDuration: nil,
        limits: limits
      )
    )
    XCTAssertFalse(
      PublicFirehoseSlowConsumerPolicy.shouldDrop(
        seqLag: 0,
        backfillElapsed: .zero,
        writeDuration: nil,
        limits: limits
      )
    )
    XCTAssertTrue(
      PublicFirehoseSlowConsumerPolicy.shouldDrop(
        seqLag: 0,
        backfillElapsed: .milliseconds(11),
        writeDuration: nil,
        limits: limits
      )
    )
    XCTAssertFalse(
      PublicFirehoseSlowConsumerPolicy.shouldDrop(
        seqLag: 0,
        backfillElapsed: .milliseconds(10),
        writeDuration: nil,
        limits: limits
      )
    )
    XCTAssertTrue(
      PublicFirehoseSlowConsumerPolicy.shouldDrop(
        seqLag: 0,
        backfillElapsed: .zero,
        writeDuration: .milliseconds(11),
        limits: limits
      )
    )
    XCTAssertFalse(
      PublicFirehoseSlowConsumerPolicy.shouldDrop(
        seqLag: 0,
        backfillElapsed: .zero,
        writeDuration: nil,
        limits: limits
      )
    )
  }

  func testTailerThrowsConsumerTooSlowBeyondInjectedLagCeiling() async throws {
    let root = try makeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await firehose.close() } }
    for index in 1 ... 2 {
      _ = try await firehose.appendBatch(
        [identityItem(sourceKey: "lag-\(index)")],
        now: epoch
      )
    }

    let limits = try PublicFirehoseStreamingLimits(maximumSequenceLag: 1)
    let tailer = PublicFirehoseTailer(database: firehose, limits: limits, logger: logger)
    do {
      try await tailer.run(
        lastSent: 0,
        outbound: { _ in XCTFail("no frame may be written to a dropped consumer") },
        waitForWakeup: { nil }
      )
      XCTFail("expected consumerTooSlow")
    } catch let error as PublicFirehoseTailerError {
      guard case let .consumerTooSlow(seqLag, backfillElapsed) = error else {
        return XCTFail("unexpected tailer error \(error)")
      }
      XCTAssertEqual(seqLag, 2)
      XCTAssertEqual(backfillElapsed, .zero)
    }
  }

  /// Phase 4 entry gate: a per-DID deletion gap wider than the lag limit
  /// must not drop a consumer that has almost nothing left to read.
  func testTailerSurvivesDeletionGapWiderThanSequenceLagLimit() async throws {
    let root = try makeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await firehose.close() } }

    // Seq 1 (survivor), 2...4 (doomed did), 5 = the deleted #account event.
    _ = try await firehose.appendBatch([identityItem(sourceKey: "keep-1")], now: epoch)
    for index in 2 ... 4 {
      _ = try await firehose.appendBatch(
        [identityItem(sourceKey: "gap-\(index)", did: "did:web:doomed.example")],
        now: epoch
      )
    }
    _ = try await firehose.appendBatch(
      [deletedAccountItem(sourceKey: "gap-account", did: "did:web:doomed.example")],
      now: epoch,
      deletingPriorEvents: [
        FirehoseDeletionMarker(did: "did:web:doomed.example", sourceKey: "gap-account"),
      ]
    )
    // Consumer at cursor 1: raw lag = 4 > limit 2, but only seq 5 is stored.
    let limits = try PublicFirehoseStreamingLimits(maximumSequenceLag: 2)
    let tailer = PublicFirehoseTailer(database: firehose, limits: limits, logger: logger)
    let recorder = FrameRecorder()
    let task = Task {
      try await tailer.run(
        lastSent: 1,
        outbound: { data in await recorder.record(data) },
        waitForWakeup: { nil }
      )
    }
    defer { task.cancel() }

    try await waitUntil { await recorder.snapshot().count == 1 }
    let frames = await recorder.snapshot()
    XCTAssertEqual(frames.count, 1)
    task.cancel()
    _ = await task.result
  }

  /// A consumer with more deliverable rows than the limit is still dropped.
  func testTailerStillDropsConsumerWithRealDeliverableBacklog() async throws {
    let root = try makeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await firehose.close() } }
    for index in 1 ... 4 {
      _ = try await firehose.appendBatch(
        [identityItem(sourceKey: "real-\(index)")],
        now: epoch
      )
    }
    let limits = try PublicFirehoseStreamingLimits(maximumSequenceLag: 2)
    let tailer = PublicFirehoseTailer(database: firehose, limits: limits, logger: logger)
    do {
      try await tailer.run(
        lastSent: 0,
        outbound: { _ in XCTFail("dropped consumer must receive nothing") },
        waitForWakeup: { nil }
      )
      XCTFail("expected consumerTooSlow")
    } catch let error as PublicFirehoseTailerError {
      guard case let .consumerTooSlow(seqLag, _) = error else {
        return XCTFail("unexpected tailer error \(error)")
      }
      // The two-step check clamps the reported lag at maximumSequenceLag + 1
      // (plan Task 1 Step 7): the bounded count stops at the bound, so a
      // backlog deeper than it reports the clamped value.
      XCTAssertEqual(seqLag, 3)
    }
  }

  func testTailerReportsAnOutdatedCursorAfterRetentionAdvances() async throws {
    let root = try makeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await firehose.close() } }
    _ = try await firehose.appendBatch([identityItem(sourceKey: "old-1")], now: epoch)
    _ = try await firehose.appendBatch([identityItem(sourceKey: "old-2")], now: epoch)

    let result = try await firehose.prune(
      now: epoch.addingTimeInterval(20),
      policy: try PublicFirehoseRetentionPolicy(
        maximumAge: .seconds(1),
        maximumRows: 100,
        maximumBytes: 1_073_741_824
      )
    )
    XCTAssertEqual(
      result.retainedFromSeq,
      3,
      "the boundary is one past the last deleted sequence (2), not the "
        + "deleted sequence itself, since seq 2 no longer exists"
    )

    let tailer = PublicFirehoseTailer(
      database: firehose,
      limits: .standard,
      logger: logger
    )
    do {
      try await tailer.run(
        lastSent: 0,
        outbound: { _ in XCTFail("outdated cursor must be reported before a write") },
        waitForWakeup: { nil }
      )
      XCTFail("expected outdatedCursor")
    } catch let error as PublicFirehoseTailerError {
      XCTAssertEqual(error, .outdatedCursor(retainedFromSeq: 3))
    }
  }

  /// Regression for the whole-log-prune boundary off-by-one: before the fix,
  /// an emptied log's boundary was set to the last deleted sequence (`M`)
  /// rather than one past it. A session already delivered up to `M - 1`
  /// would then pass the tailer's `cursor < retainedFromSeq - 1` check
  /// (`M - 1 < M - 1` is false) and silently resume with nothing to
  /// deliver, even though seq `M` itself was pruned out from under it. This
  /// proves that scenario now correctly reports `OutdatedCursor`.
  func testTailerReportsOutdatedCursorForLastSentOneBelowWhollyPrunedBoundary() async throws {
    let root = try makeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await firehose.close() } }
    for index in 1 ... 3 {
      _ = try await firehose.appendBatch(
        [identityItem(sourceKey: "wipe-\(index)")],
        now: epoch
      )
    }

    let result = try await firehose.prune(
      now: epoch.addingTimeInterval(20),
      policy: try PublicFirehoseRetentionPolicy(
        maximumAge: .seconds(1),
        maximumRows: 100,
        maximumBytes: 1_073_741_824
      )
    )
    XCTAssertEqual(result.deletedRows, 3)
    XCTAssertEqual(result.retainedFromSeq, 4)

    let tailer = PublicFirehoseTailer(
      database: firehose,
      limits: .standard,
      logger: logger
    )
    do {
      // lastSent == 2 is one below the last deleted sequence (3), the exact
      // boundary value the pre-fix code would have written.
      try await tailer.run(
        lastSent: 2,
        outbound: { _ in XCTFail("outdated cursor must be reported before a write") },
        waitForWakeup: { nil }
      )
      XCTFail("expected outdatedCursor")
    } catch let error as PublicFirehoseTailerError {
      XCTAssertEqual(error, .outdatedCursor(retainedFromSeq: 4))
    }
  }

  func testTailerCancellationExitsPromptly() async throws {
    let root = try makeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await firehose.close() } }

    let recorder = FrameRecorder()
    let limits = try PublicFirehoseStreamingLimits()
    let tailer = PublicFirehoseTailer(database: firehose, limits: limits, logger: logger)
    let task = Task {
      try await tailer.run(
        lastSent: 0,
        outbound: { await recorder.record($0) },
        waitForWakeup: {
          try? await Task.sleep(nanoseconds: 10_000_000)
          return nil
        }
      )
    }

    try await Task.sleep(nanoseconds: 50_000_000)
    task.cancel()
    _ = await task.result
    let delivered = await recorder.snapshot()
    XCTAssertTrue(delivered.isEmpty, "cancellation mid-idle must deliver nothing")
  }
  func testTailerDropsSlowWriteAtDeadline() async throws {
    let root = try makeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await firehose.close() } }
    _ = try await firehose.appendBatch([identityItem(sourceKey: "slow-write-test")], now: epoch)

    let limits = try PublicFirehoseStreamingLimits(
      maximumWriteDuration: .milliseconds(200),
      idlePollInterval: 0.01
    )
    let tailer = PublicFirehoseTailer(database: firehose, limits: limits, logger: logger)

    let (writeStartedStream, writeStartedContinuation) = AsyncStream<Void>.makeStream(
      bufferingPolicy: .bufferingNewest(1)
    )

    let clock = ContinuousClock()
    let tailerTask = Task {
      try await tailer.run(
        lastSent: 0,
        outbound: { _ in
          writeStartedContinuation.yield()
          try await Task.sleep(for: .seconds(10))
        },
        waitForWakeup: { nil }
      )
    }

    // Await explicit confirmation that outbound has actually started and is suspended in its sleep
    var iterator = writeStartedStream.makeAsyncIterator()
    _ = await iterator.next()
    let writeStarted = clock.now

    // Await tailerTask with a bounded timeout (2 seconds) so failures fail fast without hanging
    let outcome: Result<Void, any Error> = await withThrowingTaskGroup(of: Void.self) { group in
      group.addTask {
        try await tailerTask.value
      }
      group.addTask {
        try await Task.sleep(for: .seconds(2))
        tailerTask.cancel()
        throw SwanError.malformed("tailer did not drop slow write within bounded interval")
      }
      do {
        try await group.next()
        group.cancelAll()
        return .success(())
      } catch {
        group.cancelAll()
        return .failure(error)
      }
    }
    switch outcome {
    case .success:
      XCTFail("expected tailer.run to throw writeTooSlow, but it returned normally")
    case .failure(let error as PublicFirehoseTailerError):
      guard case .writeTooSlow(let duration) = error else {
        return XCTFail("expected writeTooSlow, got \(error)")
      }
      XCTAssertEqual(duration, .milliseconds(200))
    case .failure(let error):
      XCTFail("expected writeTooSlow, got \(error)")
    }

    let elapsed = clock.now - writeStarted
    XCTAssertLessThan(
      elapsed,
      .seconds(1),
      "the drop must happen at the deadline (~200ms), not after the 10s write completes"
    )
    XCTAssertGreaterThanOrEqual(
      elapsed,
      .milliseconds(150),
      "the drop must not happen prematurely before the write was actually attempted"
    )
  }

  // MARK: - Wakeup hub

  func testWakeupHubCoalescingAndFanOut() async throws {
    let hub = PublicFirehoseWakeupHub()
    let sink: any PublicFirehoseWakeupSink = hub

    let first = await hub.subscribe()
    let second = await hub.subscribe()
    let third = await hub.subscribe()

    await sink.firehoseDidAppend(maxSeq: 1)
    await sink.firehoseDidAppend(maxSeq: 2)
    await sink.firehoseDidAppend(maxSeq: 3)

    var firstIterator = first.makeAsyncIterator()
    var secondIterator = second.makeAsyncIterator()
    var thirdIterator = third.makeAsyncIterator()
    let observedFirst = await firstIterator.next()
    let observedSecond = await secondIterator.next()
    let observedThird = await thirdIterator.next()
    XCTAssertEqual(observedFirst, 3)
    XCTAssertEqual(observedSecond, 3)
    XCTAssertEqual(observedThird, 3)

    await sink.firehoseDidAppend(maxSeq: 3)
    await sink.firehoseDidAppend(maxSeq: 4)
    let next = await firstIterator.next()
    XCTAssertEqual(next, 4)
  }

  func testWakeupHubRetentionSignalIsNotSuppressedByAppendCoalescing() async throws {
    let hub = PublicFirehoseWakeupHub()
    let stream = await hub.subscribe()
    var iterator = stream.makeAsyncIterator()

    await hub.firehoseDidAppend(maxSeq: 4)
    let first = await iterator.next()
    XCTAssertEqual(first, 4)

    await hub.firehoseRetentionDidAdvance(maxSeq: 4)
    let retention = await iterator.next()
    XCTAssertEqual(
      retention,
      4,
      "retention changes must wake a tailer even when no new sequence exists"
    )
  }

  func testPageAdmissionLimitsConcurrentPagesToFour() {
    let admission = PublicFirehosePageAdmission(maximumConcurrentPages: 4)
    let lease1 = admission.reserve()
    XCTAssertNotNil(lease1)
    let lease2 = admission.reserve()
    XCTAssertNotNil(lease2)
    let lease3 = admission.reserve()
    XCTAssertNotNil(lease3)
    let lease4 = admission.reserve()
    XCTAssertNotNil(lease4)
    XCTAssertEqual(admission.currentActiveLeases, 4)

    let lease5 = admission.reserve()
    XCTAssertNil(lease5, "5th concurrent page reservation must be rejected")

    lease2?.release()
    XCTAssertEqual(admission.currentActiveLeases, 3)

    let lease6 = admission.reserve()
    XCTAssertNotNil(lease6, "reservation succeeds after lease released")
    XCTAssertEqual(admission.currentActiveLeases, 4)

    lease1?.release()
    lease3?.release()
    lease4?.release()
    lease6?.release()
    XCTAssertEqual(admission.currentActiveLeases, 0)
  }

  func testTailerReleasesPageReservationOnOutboundErrorOrCancellation() async throws {
    let root = try makeRoot()
    defer { try? FileManager.default.removeItem(at: root) }
    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await firehose.close() } }
    _ = try await firehose.appendBatch([identityItem(sourceKey: "k1")], now: epoch)

    let admission = PublicFirehosePageAdmission(maximumConcurrentPages: 1)
    let limits = try PublicFirehoseStreamingLimits(idlePollInterval: 0.01)
    let tailer = PublicFirehoseTailer(
      database: firehose,
      limits: limits,
      logger: logger,
      pageAdmission: admission
    )

    enum InjectedOutboundError: Error { case boom }

    do {
      try await tailer.run(
        lastSent: 0,
        outbound: { _ in
          throw InjectedOutboundError.boom
        },
        waitForWakeup: { nil as Int64? }
      )
      XCTFail("expected outbound error")
    } catch is InjectedOutboundError {
      XCTAssertEqual(admission.currentActiveLeases, 0, "page reservation must be released after outbound error")
    }
  }
}
