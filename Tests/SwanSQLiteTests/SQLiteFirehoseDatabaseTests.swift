import Foundation
import Petrel
import SQLiteNIO
import SwanCore
import SwanPublicFirehose
import XCTest
@testable import SwanSQLite

final class SQLiteFirehoseDatabaseTests: XCTestCase {
  private let did = "did:plc:abcdefghijklmnopqrstuvwx"
  private let time = "2026-08-04T12:00:00.000Z"
  private let epoch = Date(timeIntervalSince1970: 1_785_844_800)

  private var root: URL!
  private var firehose: SQLiteFirehoseDatabase!

  override func setUp() async throws {
    let root = FileManager.default.temporaryDirectory
      .appending(path: "swan-firehose-log-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
      at: root,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    self.root = root
    firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
  }

  override func tearDown() async throws {
    try? await firehose?.close()
    if let root {
      try? FileManager.default.removeItem(at: root)
    }
  }

  private func identityItem(
    sourceKey: String = "did:plc:abc|identity|bafy1",
    did: String? = nil,
    batchID: String? = nil
  ) -> FirehoseAppendItem {
    let identityDID = did ?? self.did
    let material = PublicFirehoseIdentityMaterial(
      did: identityDID,
      handle: "alice.test",
      time: time
    )
    return FirehoseAppendItem(
      sourceKey: sourceKey,
      batchID: batchID,
      did: identityDID,
      kind: .identity
    ) { seq in
      try FirehoseFrameEncoder.identityFrame(seq: seq, material: material)
    }
  }

  private func expectThrows<T>(
    _ expression: @autoclosure () async throws -> T,
    _ check: (SQLiteFirehoseDatabaseError) -> Bool,
    file: StaticString = #filePath,
    line: UInt = #line
  ) async {
    do {
      _ = try await expression()
      XCTFail("expected firehose error", file: file, line: line)
    } catch let error as SQLiteFirehoseDatabaseError {
      XCTAssertTrue(check(error), "unexpected error \(error)", file: file, line: line)
    } catch {
      XCTFail("unexpected error \(error)", file: file, line: line)
    }
  }

  func testThreeItemBatchAllocatesConsecutiveSequences() async throws {
    let seqs = try await firehose.appendBatch(
      [
        identityItem(sourceKey: "k1", batchID: "batch-1"),
        identityItem(sourceKey: "k2", batchID: "batch-1"),
        identityItem(sourceKey: "k3", batchID: "batch-1"),
      ],
      now: epoch
    )
    XCTAssertEqual(seqs, [1, 2, 3])
    let maxSeq = try await firehose.maxSequencedSeq()
    XCTAssertEqual(maxSeq, 3)
    let stored = try await firehose.events(after: 0, limit: 10)
    XCTAssertEqual(stored.map(\.seq), [1, 2, 3])
    XCTAssertEqual(stored.map(\.batchOrdinal), [0, 1, 2])
    for event in stored {
      XCTAssertEqual(
        event.frameBytes,
        try FirehoseFrameEncoder.identityFrame(
          seq: event.seq,
          material: PublicFirehoseIdentityMaterial(
            did: did,
            handle: "alice.test",
            time: time
          )
        )
      )
    }
  }

  func testReopeningContinuesAtFour() async throws {
    _ = try await firehose.appendBatch(
      [
        identityItem(sourceKey: "k1", batchID: "batch-1"),
        identityItem(sourceKey: "k2", batchID: "batch-1"),
        identityItem(sourceKey: "k3", batchID: "batch-1"),
      ],
      now: epoch
    )
    try await firehose.close()
    let reopened = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await reopened.close() } }
    let seqs = try await reopened.appendBatch(
      [identityItem(sourceKey: "k4", batchID: "batch-2")],
      now: epoch
    )
    XCTAssertEqual(seqs, [4])
  }

  func testExactSourceReplayReturnsOriginalSequencesWithoutNewRows() async throws {
    let item = identityItem(sourceKey: "k1", batchID: "batch-1")
    let first = try await firehose.appendBatch([item], now: epoch)
    let replayed = try await firehose.appendBatch([item], now: epoch)
    XCTAssertEqual(replayed, first)
    let maxSeq = try await firehose.maxSequencedSeq()
    XCTAssertEqual(maxSeq, 1)
    let stored = try await firehose.events(after: 0, limit: 10)
    XCTAssertEqual(stored.count, 1)
  }

  func testChangedContentUnderSameSourceKeyThrowsConflict() async throws {
    let original = identityItem(sourceKey: "k1", batchID: "batch-1")
    _ = try await firehose.appendBatch([original], now: epoch)
    await expectThrows(
      try await firehose.appendBatch(
        [identityItem(sourceKey: "k1", did: "did:plc:different", batchID: "batch-1")],
        now: epoch
      ),
      { if case .conflictingSourceKey = $0 { return true }; return false }
    )
    await expectThrows(
      try await firehose.appendBatch(
        [identityItem(sourceKey: "k1", did: did, batchID: "batch-2")],
        now: epoch
      ),
      { if case .conflictingSourceKey = $0 { return true }; return false }
    )
    let otherDID = did
    let otherTime = time
    let differentMaterial = FirehoseAppendItem(
      sourceKey: "k1",
      batchID: "batch-1",
      did: did,
      kind: .identity
    ) { seq in
      try FirehoseFrameEncoder.identityFrame(
        seq: seq,
        material: PublicFirehoseIdentityMaterial(
          did: otherDID,
          handle: "bob.test",
          time: otherTime
        )
      )
    }
    await expectThrows(
      try await firehose.appendBatch([differentMaterial], now: epoch),
      { if case .conflictingSourceKey = $0 { return true }; return false }
    )
    let eventCount = try await firehose.events(after: 0, limit: 10).count
    XCTAssertEqual(eventCount, 1)
  }

  func testMixedExistingAndNewBatchFailsClosed() async throws {
    _ = try await firehose.appendBatch(
      [identityItem(sourceKey: "k1", batchID: "batch-1")],
      now: epoch
    )
    await expectThrows(
      try await firehose.appendBatch(
        [
          identityItem(sourceKey: "k1", batchID: "batch-1"),
          identityItem(sourceKey: "k2", batchID: "batch-1"),
        ],
        now: epoch
      ),
      { if case .mixedBatchReplay = $0 { return true }; return false }
    )
    await expectThrows(
      try await firehose.appendBatch(
        [
          identityItem(sourceKey: "k2", batchID: "batch-1"),
          identityItem(sourceKey: "k3", batchID: "batch-1"),
          identityItem(sourceKey: "k1", batchID: "batch-1"),
        ],
        now: epoch
      ),
      { if case .mixedBatchReplay = $0 { return true }; return false }
    )
  }

  func testAllExistingBatchPreservesOrderAndConsecutiveRange() async throws {
    _ = try await firehose.appendBatch(
      [
        identityItem(sourceKey: "k1", batchID: "batch-1"),
        identityItem(sourceKey: "k2", batchID: "batch-1"),
      ],
      now: epoch
    )
    let replayed = try await firehose.appendBatch(
      [
        identityItem(sourceKey: "k1", batchID: "batch-1"),
        identityItem(sourceKey: "k2", batchID: "batch-1"),
      ],
      now: epoch
    )
    XCTAssertEqual(replayed, [1, 2])
    await expectThrows(
      try await firehose.appendBatch(
        [
          identityItem(sourceKey: "k2", batchID: "batch-1"),
          identityItem(sourceKey: "k1", batchID: "batch-1"),
        ],
        now: epoch
      ),
      { if case .mixedBatchReplay = $0 { return true }; return false }
    )
  }

  func testMismatchedBatchIDsInOneRequestRejected() async throws {
    await expectThrows(
      try await firehose.appendBatch(
        [
          identityItem(sourceKey: "k1", batchID: "batch-1"),
          identityItem(sourceKey: "k2", batchID: "batch-2"),
        ],
        now: epoch
      ),
      { if case .invalidRequest = $0 { return true }; return false }
    )
  }

  func testNilBatchIDAllowedOnlyForOneItem() async throws {
    await expectThrows(
      try await firehose.appendBatch(
        [
          identityItem(sourceKey: "k1"),
          identityItem(sourceKey: "k2"),
        ],
        now: epoch
      ),
      { if case .invalidRequest = $0 { return true }; return false }
    )
    _ = try await firehose.appendBatch(
      [identityItem(sourceKey: "k1")],
      now: epoch
    )
  }

  func testDuplicateSourceKeysInOneRequestRejected() async throws {
    await expectThrows(
      try await firehose.appendBatch(
        [
          identityItem(sourceKey: "k1", batchID: "batch-1"),
          identityItem(sourceKey: "k1", batchID: "batch-1"),
        ],
        now: epoch
      ),
      { if case .invalidRequest = $0 { return true }; return false }
    )
  }

  func testAllocationAcrossMaximumSequenceFailsAndInsertsNothing() async throws {
    try await firehose.reseedSequence(toAtLeast: FirehoseFrameLimits.maximumSequence)
    await expectThrows(
      try await firehose.appendBatch(
        [
          identityItem(sourceKey: "k1", batchID: "batch-1"),
          identityItem(sourceKey: "k2", batchID: "batch-1"),
        ],
        now: epoch
      ),
      { $0 == .sequenceExhausted }
    )
    let eventCount = try await firehose.events(after: 0, limit: 10).count
    XCTAssertEqual(eventCount, 0)
  }

  func testExhaustedSentinelIsStable() async throws {
    try await firehose.reseedSequence(
      toAtLeast: FirehoseFrameLimits.maximumSequence + 1
    )
    await expectThrows(
      try await firehose.appendBatch(
        [identityItem(sourceKey: "k1", batchID: "batch-1")],
        now: epoch
      ),
      { $0 == .sequenceExhausted }
    )
    await expectThrows(
      try await firehose.appendBatch(
        [identityItem(sourceKey: "k2", batchID: "batch-1")],
        now: epoch
      ),
      { $0 == .sequenceExhausted }
    )
    let eventCount = try await firehose.events(after: 0, limit: 10).count
    XCTAssertEqual(eventCount, 0)
  }

  func testEncodingFailureRollsBackMetadataAndRows() async throws {
    let failing = FirehoseAppendItem(
      sourceKey: "k1",
      batchID: "batch-1",
      did: did,
      kind: .identity
    ) { _ in
      throw FirehoseFrameEncoderError.invalidCID("bad")
    }
    await expectThrows(
      try await firehose.appendBatch([failing], now: epoch),
      { if case .corruptDatabase = $0 { return true }; return false }
    )
    let eventCount = try await firehose.events(after: 0, limit: 10).count
    XCTAssertEqual(eventCount, 0)
    let seqs = try await firehose.appendBatch(
      [identityItem(sourceKey: "k2", batchID: "batch-1")],
      now: epoch
    )
    XCTAssertEqual(seqs, [1])
  }

  func testFrameLargerThanFiveMillionFailsAndRollsBack() async throws {
    let oversized = FirehoseAppendItem(
      sourceKey: "k1",
      batchID: "batch-1",
      did: did,
      kind: .identity
    ) { _ in
      Data(repeating: 0, count: 5_000_001)
    }
    await expectThrows(
      try await firehose.appendBatch([oversized], now: epoch),
      { if case .invalidRequest = $0 { return true }; return false }
    )
    let eventCount = try await firehose.events(after: 0, limit: 10).count
    XCTAssertEqual(eventCount, 0)
  }

  func testEventsAreAscendingAndStrictlyGreaterThanCursor() async throws {
    _ = try await firehose.appendBatch(
      [
        identityItem(sourceKey: "k1", batchID: "batch-1"),
        identityItem(sourceKey: "k2", batchID: "batch-1"),
        identityItem(sourceKey: "k3", batchID: "batch-1"),
      ],
      now: epoch
    )
    let afterOne = try await firehose.events(after: 1, limit: 10)
    XCTAssertEqual(afterOne.map(\.seq), [2, 3])
    let afterTwo = try await firehose.events(after: 2, limit: 1)
    XCTAssertEqual(afterTwo.map(\.seq), [3])
    let fromZero = try await firehose.events(after: 0, limit: 10)
    XCTAssertEqual(fromZero.map(\.seq), [1, 2, 3])
  }

  func testInvalidCursorsAndLimitsRejected() async throws {
    for cursor in [-1, FirehoseFrameLimits.maximumSequence + 1] {
      await expectThrows(
        try await firehose.events(after: cursor, limit: 10),
        { if case .invalidRequest = $0 { return true }; return false }
      )
    }
    for limit in [0, -1, 1_001] {
      await expectThrows(
        try await firehose.events(after: 0, limit: limit),
        { if case .invalidRequest = $0 { return true }; return false }
      )
    }
  }

  func testReseedRaisesOnlyAndAcceptsExhaustedSentinel() async throws {
    _ = try await firehose.appendBatch(
      [identityItem(sourceKey: "k1", batchID: "batch-1")],
      now: epoch
    )
    try await firehose.reseedSequence(toAtLeast: 5)
    _ = try await firehose.appendBatch(
      [identityItem(sourceKey: "k2", batchID: "batch-2")],
      now: epoch
    )
    let afterReseed = try await firehose.maxSequencedSeq()
    XCTAssertEqual(afterReseed, 5)
    try await firehose.reseedSequence(toAtLeast: 3)
    _ = try await firehose.appendBatch(
      [identityItem(sourceKey: "k3", batchID: "batch-3")],
      now: epoch
    )
    let afterLowerReseed = try await firehose.maxSequencedSeq()
    XCTAssertEqual(afterLowerReseed, 6)
    try await firehose.reseedSequence(
      toAtLeast: FirehoseFrameLimits.maximumSequence + 1
    )
    await expectThrows(
      try await firehose.appendBatch(
        [identityItem(sourceKey: "k4", batchID: "batch-4")],
        now: epoch
      ),
      { $0 == .sequenceExhausted }
    )
  }

  func testReopenAfterCloseAndDescriptorCleanup() async throws {
    _ = try await firehose.appendBatch(
      [identityItem(sourceKey: "k1", batchID: "batch-1")],
      now: epoch
    )
    try await firehose.close()
    let reopened = try await SQLiteFirehoseDatabase(dataDirectory: root)
    let reopenedMax = try await reopened.maxSequencedSeq()
    XCTAssertEqual(reopenedMax, 1)
    try await reopened.close()
  }

  func testFirehoseRetainedFromSeqAccessor() async throws {
    let retained = try await firehose.retainedFromSeq()
    XCTAssertNil(retained, "retention is never advanced in Phase 2")

    let path = SQLiteLayout.firehoseDatabase(in: root).path
    let raw = try await SQLiteConnection.open(storage: .file(path: path))
    _ = try await raw.query("PRAGMA busy_timeout=5000")
    _ = try await raw.query(
      "UPDATE firehose_meta SET retained_from_seq = ? WHERE singleton = 1",
      [.integer(5)]
    )
    try await raw.close()

    let advanced = try await firehose.retainedFromSeq()
    XCTAssertEqual(advanced, 5)
  }

  func testRetentionPolicyRejectsNonPositiveAgeAndBudgets() {
    XCTAssertThrowsError(
      try PublicFirehoseRetentionPolicy(maximumAge: .zero)
    )
    XCTAssertThrowsError(
      try PublicFirehoseRetentionPolicy(maximumRows: 0)
    )
    XCTAssertThrowsError(
      try PublicFirehoseRetentionPolicy(maximumBytes: 4_999_999)
    )
  }

  func testAgePruningDeletesExpiredRowsAndAdvancesRetainedCursor() async throws {
    _ = try await firehose.appendBatch(
      [identityItem(sourceKey: "old")],
      now: epoch
    )
    _ = try await firehose.appendBatch(
      [identityItem(sourceKey: "new")],
      now: epoch.addingTimeInterval(20)
    )

    let result = try await firehose.prune(
      now: epoch.addingTimeInterval(20),
      policy: try PublicFirehoseRetentionPolicy(
        maximumAge: .seconds(10),
        maximumRows: 100,
        maximumBytes: 1_073_741_824
      )
    )

    XCTAssertEqual(result.deletedRows, 1)
    XCTAssertEqual(result.retainedFromSeq, 2)
    XCTAssertTrue(result.didAdvanceRetention)
    let retained = try await firehose.retainedFromSeq()
    let stored = try await firehose.events(after: 0, limit: 10)
    let maxSeq = try await firehose.maxSequencedSeq()
    XCTAssertEqual(retained, 2)
    XCTAssertEqual(stored.map(\.seq), [2])
    XCTAssertEqual(maxSeq, 2)
  }

  func testRowBudgetDeletesOldestRowsWithoutAnAgeFloor() async throws {
    for index in 1 ... 3 {
      _ = try await firehose.appendBatch(
        [identityItem(sourceKey: "row-\(index)")],
        now: epoch
      )
    }

    let result = try await firehose.prune(
      now: epoch,
      policy: try PublicFirehoseRetentionPolicy(
        maximumAge: .seconds(72 * 60 * 60),
        maximumRows: 2,
        maximumBytes: 1_073_741_824
      )
    )

    XCTAssertEqual(result.deletedRows, 1)
    XCTAssertEqual(result.retainedFromSeq, 2)
    let stored = try await firehose.events(after: 0, limit: 10)
    XCTAssertEqual(stored.map(\.seq), [2, 3])
  }

  func testByteBudgetDeletesOldestRowsByStoredFrameBytes() async throws {
    func rawItem(sourceKey: String, seed: UInt8) -> FirehoseAppendItem {
      FirehoseAppendItem(
        sourceKey: sourceKey,
        batchID: nil,
        did: did,
        kind: .identity
      ) { _ in Data(repeating: seed, count: 3_000_000) }
    }

    _ = try await firehose.appendBatch(
      [rawItem(sourceKey: "bytes-1", seed: 0x01)],
      now: epoch
    )
    _ = try await firehose.appendBatch(
      [rawItem(sourceKey: "bytes-2", seed: 0x02)],
      now: epoch
    )

    let result = try await firehose.prune(
      now: epoch,
      policy: try PublicFirehoseRetentionPolicy(
        maximumAge: .seconds(72 * 60 * 60),
        maximumRows: 100,
        maximumBytes: 5_000_000
      )
    )

    XCTAssertEqual(result.deletedRows, 1)
    XCTAssertEqual(result.deletedBytes, 3_000_000)
    let stored = try await firehose.events(after: 0, limit: 10)
    XCTAssertEqual(stored.map(\.seq), [2])
  }

  func testAgeCeilingCanPruneTheEntireLogAndHighWaterMarkDoesNotRegress() async throws {
    for index in 1 ... 2 {
      _ = try await firehose.appendBatch(
        [identityItem(sourceKey: "all-old-\(index)")],
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

    XCTAssertEqual(result.deletedRows, 2)
    XCTAssertEqual(result.retainedFromSeq, 2)
    let stored = try await firehose.events(after: 0, limit: 10)
    XCTAssertTrue(stored.isEmpty)
    let maxSeq = try await firehose.maxSequencedSeq()
    XCTAssertEqual(
      maxSeq,
      2,
      "deleting every row must not make an already-issued cursor future"
    )
  }

  func testAgePruningPagesAcrossMultipleThousandRowBatches() async throws {
    // Exceeds the age pass's 1000-row-per-statement page size, so a single
    // prune must loop across at least two bounded DELETE...RETURNING pages
    // instead of buffering every expired row in one unbounded statement.
    let rowCount = 1200
    let items = (1 ... rowCount).map { index in
      identityItem(sourceKey: "bulk-old-\(index)", batchID: "bulk-old")
    }
    _ = try await firehose.appendBatch(items, now: epoch)

    let result = try await firehose.prune(
      now: epoch.addingTimeInterval(20),
      policy: try PublicFirehoseRetentionPolicy(
        maximumAge: .seconds(10),
        maximumRows: 1_000_000,
        maximumBytes: 1_073_741_824
      )
    )

    XCTAssertEqual(result.deletedRows, Int64(rowCount))
    XCTAssertEqual(result.retainedFromSeq, Int64(rowCount))
    XCTAssertTrue(result.didAdvanceRetention)
    let stored = try await firehose.events(after: 0, limit: 10)
    XCTAssertTrue(stored.isEmpty)
    let maxSeq = try await firehose.maxSequencedSeq()
    XCTAssertEqual(
      maxSeq,
      Int64(rowCount),
      "deleting every row across multiple age-pass pages must not make the cursor future"
    )
  }

  func testNoOpPruneDoesNotInitializeRetention() async throws {
    _ = try await firehose.appendBatch(
      [identityItem(sourceKey: "fresh")],
      now: epoch
    )

    let result = try await firehose.prune(
      now: epoch,
      policy: try PublicFirehoseRetentionPolicy(
        maximumAge: .seconds(72 * 60 * 60),
        maximumRows: 100,
        maximumBytes: 1_073_741_824
      )
    )

    XCTAssertEqual(result.deletedRows, 0)
    XCTAssertFalse(result.didAdvanceRetention)
    let retained = try await firehose.retainedFromSeq()
    XCTAssertNil(retained, "a no-op prune must not arm the retained window")
  }
}
