import Foundation
import Logging
import Petrel
import SwanCore
import SwanPublicFirehose
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

  private func identityItem(sourceKey: String) -> FirehoseAppendItem {
    let material = PublicFirehoseIdentityMaterial(
      did: did,
      handle: "alice.test",
      time: time
    )
    return FirehoseAppendItem(
      sourceKey: sourceKey,
      batchID: nil,
      did: did,
      kind: .identity
    ) { seq in
      try FirehoseFrameEncoder.identityFrame(seq: seq, material: material)
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
}
