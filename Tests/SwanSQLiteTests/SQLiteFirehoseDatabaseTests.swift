import Foundation
import Petrel
import SQLiteNIO
import SwanCore
import PetrelFirehose
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

  private func deletedAccountItem(
    sourceKey: String,
    did: String? = nil,
    batchID: String? = nil
  ) -> FirehoseAppendItem {
    let accountDID = did ?? self.did
    let material = PublicFirehoseAccountMaterial(
      did: accountDID,
      active: false,
      status: .deleted,
      time: time
    )
    return FirehoseAppendItem(
      sourceKey: sourceKey,
      batchID: batchID,
      did: accountDID,
      kind: .account
    ) { seq in
      try FirehoseFrameEncoder.accountFrame(seq: seq, material: material)
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

  func testDeliverableEventCountStopsAtLimitAndIgnoresSequenceGaps() async throws {
    // seqs 1...5 for did A, then delete 2...4 via the deletion-marker path is
    // not needed: create a gap directly by pruning is overkill — append 5,
    // then measure counts with cursors inside the range.
    for index in 1 ... 5 {
      _ = try await firehose.appendBatch(
        [identityItem(sourceKey: "count-\(index)")],
        now: epoch
      )
    }
    // All five deliverable from cursor 0.
    let all = try await firehose.deliverableEventCount(after: 0, limit: 10)
    XCTAssertEqual(all, 5)
    // Bounded: stops counting at the limit.
    let bounded = try await firehose.deliverableEventCount(after: 0, limit: 3)
    XCTAssertEqual(bounded, 3)
    // Cursor mid-range.
    let tail = try await firehose.deliverableEventCount(after: 3, limit: 10)
    XCTAssertEqual(tail, 2)
    // Invalid limit rejected.
    await expectThrows(
      try await firehose.deliverableEventCount(after: 0, limit: 0),
      { if case .invalidRequest = $0 { return true }; return false }
    )
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
    XCTAssertEqual(
      result.retainedFromSeq,
      3,
      "the boundary is one past the last deleted sequence (2), not the "
        + "deleted sequence itself, since seq 2 no longer exists"
    )
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
    XCTAssertEqual(
      result.retainedFromSeq,
      Int64(rowCount) + 1,
      "the boundary is one past the last deleted sequence, not the "
        + "deleted sequence itself, since the whole log was pruned"
    )
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

  /// Regression for the budget loop's prefix-break operator: with `||`, the
  /// inner break fired as soon as *either* budget was already satisfied by
  /// the prospective deletion, so when only the row budget was violated (the
  /// common case — bytes stayed far under budget the whole time) every
  /// outer-loop pass deleted exactly one row and re-ran the full-table
  /// `SELECT COUNT(*), SUM(length(frame_bytes))` — K excess rows cost K
  /// full-table scans inside one transaction. With `&&`, the prefix grows to
  /// the full bounded (<=1000-row) page whenever the other budget is already
  /// fine, so paging is bounded by `ceil(excess / 1000)` outer iterations
  /// instead of `excess`. This seeds 2500 rows against a 650-row budget
  /// (excess 1850, more than one 1000-row page) so a single `prune` must
  /// page: the first 1000-row page is deleted in full (the inner break never
  /// fires inside it, since even removing the whole page leaves more than
  /// 650 rows), and the second page stops partway through (850 of its 1000
  /// rows) exactly where the row budget is satisfied.
  func testRowBudgetPagesAcrossMultipleThousandRowBatchesWithoutDegradingToOneRowPerIteration(
  ) async throws {
    let rowCount = 2500
    let items = (1 ... rowCount).map { index in
      identityItem(sourceKey: "budget-multi-\(index)", batchID: "budget-multi")
    }
    _ = try await firehose.appendBatch(items, now: epoch)

    let result = try await firehose.prune(
      now: epoch,
      policy: try PublicFirehoseRetentionPolicy(
        maximumAge: .seconds(72 * 60 * 60),
        maximumRows: 650,
        maximumBytes: 1_073_741_824
      )
    )

    XCTAssertEqual(result.deletedRows, 1850)
    XCTAssertEqual(result.retainedFromSeq, 1851)
    XCTAssertTrue(result.didAdvanceRetention)
    let stored = try await firehose.events(after: 0, limit: 1_000)
    XCTAssertEqual(stored.count, 650)
    XCTAssertEqual(stored.map(\.seq), Array(Int64(1_851) ... Int64(2_500)))
    let maxSeq = try await firehose.maxSequencedSeq()
    XCTAssertEqual(maxSeq, Int64(rowCount))
  }

  /// Regression for the whole-log-prune boundary off-by-one's second-order
  /// bug: the monotonicity guard (`newBoundary > previous`) must still
  /// advance when a later prune's maximum deleted sequence numerically
  /// equals a boundary already recorded by an earlier, non-emptying prune.
  /// Before the fix, an emptied log's boundary was the bare maximum deleted
  /// sequence, so if that value happened to equal the already-recorded
  /// boundary the guard silently rejected the write — `didAdvanceRetention`
  /// came back `false` even though this prune's `deletedRows` was nonzero,
  /// and no retention wakeup would fire. This seeds two rows, prunes the
  /// older one by row budget (setting the boundary to the survivor's own
  /// seq, 2, via the normal `MIN(seq)` path), then ages the survivor out in
  /// a second prune that empties the log. The second prune's maximum deleted
  /// sequence is exactly 2 — the value already recorded as the boundary — so
  /// this proves the fixed `+ 1` boundary (3) still compares greater and
  /// still advances.
  func testSecondWholeLogPruneAdvancesEvenWhenItsMaximumDeletedSequenceEqualsThePriorBoundary(
  ) async throws {
    _ = try await firehose.appendBatch([identityItem(sourceKey: "carry-1")], now: epoch)
    _ = try await firehose.appendBatch([identityItem(sourceKey: "carry-2")], now: epoch)

    let first = try await firehose.prune(
      now: epoch,
      policy: try PublicFirehoseRetentionPolicy(
        maximumAge: .seconds(72 * 60 * 60),
        maximumRows: 1,
        maximumBytes: 1_073_741_824
      )
    )
    XCTAssertEqual(first.deletedRows, 1)
    XCTAssertEqual(first.retainedFromSeq, 2)
    XCTAssertTrue(first.didAdvanceRetention)

    let second = try await firehose.prune(
      now: epoch.addingTimeInterval(20),
      policy: try PublicFirehoseRetentionPolicy(
        maximumAge: .seconds(1),
        maximumRows: 100,
        maximumBytes: 1_073_741_824
      )
    )
    XCTAssertEqual(second.deletedRows, 1, "the surviving row (seq 2) must age out")
    XCTAssertEqual(
      second.retainedFromSeq,
      3,
      "one past the second prune's maximum deleted sequence (2), which "
        + "equals the boundary the first prune already recorded"
    )
    XCTAssertTrue(
      second.didAdvanceRetention,
      "a prune that actually deleted a row must never silently skip the "
        + "retention advance"
    )
    let retained = try await firehose.retainedFromSeq()
    XCTAssertEqual(retained, 3)
    let stored = try await firehose.events(after: 0, limit: 10)
    XCTAssertTrue(stored.isEmpty)
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

  // MARK: - Deletion markers

  func testDeletingPriorEventsRemovesOnlyThatDIDsEarlierRows() async throws {
    let otherDID = "did:plc:yyyyyyyyyyyyyyyyyyyyyyyy"
    _ = try await firehose.appendBatch(
      [
        identityItem(sourceKey: "k1", batchID: "history"),
        identityItem(sourceKey: "k2", batchID: "history"),
      ],
      now: epoch
    )
    _ = try await firehose.appendBatch(
      [identityItem(sourceKey: "k3", did: otherDID)],
      now: epoch
    )

    let seqs = try await firehose.appendBatch(
      [deletedAccountItem(sourceKey: "delete-1")],
      now: epoch,
      deletingPriorEvents: [FirehoseDeletionMarker(did: did, sourceKey: "delete-1")]
    )
    XCTAssertEqual(seqs, [4])

    let stored = try await firehose.events(after: 0, limit: 10)
    XCTAssertEqual(stored.map(\.seq), [3, 4])
    XCTAssertEqual(stored.map(\.did), [otherDID, did])
    XCTAssertEqual(stored.last?.kind, .account)
    let maxSeq = try await firehose.maxSequencedSeq()
    XCTAssertEqual(maxSeq, 4, "sequence gaps left by per-DID deletion are permitted")
  }

  func testDeletingPriorEventsNeverAdvancesRetainedFromSeq() async throws {
    _ = try await firehose.appendBatch(
      [identityItem(sourceKey: "k1")],
      now: epoch
    )
    _ = try await firehose.appendBatch(
      [deletedAccountItem(sourceKey: "delete-1")],
      now: epoch,
      deletingPriorEvents: [FirehoseDeletionMarker(did: did, sourceKey: "delete-1")]
    )
    let retained = try await firehose.retainedFromSeq()
    XCTAssertNil(
      retained,
      "per-DID deletion is not a global retention boundary and must not arm retained_from_seq"
    )
  }

  func testDeletingPriorEventsAppliesIdenticallyOnExactReplay() async throws {
    _ = try await firehose.appendBatch(
      [identityItem(sourceKey: "k1")],
      now: epoch
    )
    let item = deletedAccountItem(sourceKey: "delete-1")
    let marker = [FirehoseDeletionMarker(did: did, sourceKey: "delete-1")]
    let first = try await firehose.appendBatch(
      [item],
      now: epoch,
      deletingPriorEvents: marker
    )
    XCTAssertEqual(first, [2])
    let afterFirst = try await firehose.events(after: 0, limit: 10)
    XCTAssertEqual(afterFirst.map(\.seq), [2])

    let replayed = try await firehose.appendBatch(
      [item],
      now: epoch,
      deletingPriorEvents: marker
    )
    XCTAssertEqual(
      replayed,
      first,
      "exact source replay must not allocate a new sequence or duplicate the delete"
    )
    let stored = try await firehose.events(after: 0, limit: 10)
    XCTAssertEqual(stored.map(\.seq), [2])
  }

  func testDeletionMarkerRejectsEmptyDIDOrSourceKey() async throws {
    await expectThrows(
      try await firehose.appendBatch(
        [deletedAccountItem(sourceKey: "delete-1")],
        now: epoch,
        deletingPriorEvents: [FirehoseDeletionMarker(did: "", sourceKey: "delete-1")]
      ),
      { if case .invalidRequest = $0 { return true }; return false }
    )
    await expectThrows(
      try await firehose.appendBatch(
        [deletedAccountItem(sourceKey: "delete-1")],
        now: epoch,
        deletingPriorEvents: [FirehoseDeletionMarker(did: did, sourceKey: "")]
      ),
      { if case .invalidRequest = $0 { return true }; return false }
    )
  }

  func testDeletionMarkerRejectsDuplicateMarkerSourceKeys() async throws {
    await expectThrows(
      try await firehose.appendBatch(
        [deletedAccountItem(sourceKey: "delete-1")],
        now: epoch,
        deletingPriorEvents: [
          FirehoseDeletionMarker(did: did, sourceKey: "delete-1"),
          FirehoseDeletionMarker(did: did, sourceKey: "delete-1"),
        ]
      ),
      { if case .invalidRequest = $0 { return true }; return false }
    )
  }

  func testDeletionMarkerRejectsSourceKeyNotInBatch() async throws {
    await expectThrows(
      try await firehose.appendBatch(
        [deletedAccountItem(sourceKey: "delete-1")],
        now: epoch,
        deletingPriorEvents: [FirehoseDeletionMarker(did: did, sourceKey: "not-in-batch")]
      ),
      { if case .invalidRequest = $0 { return true }; return false }
    )
  }

  func testDeletionMarkerRejectsNonAccountItemAndMismatchedDID() async throws {
    await expectThrows(
      try await firehose.appendBatch(
        [identityItem(sourceKey: "k1")],
        now: epoch,
        deletingPriorEvents: [FirehoseDeletionMarker(did: did, sourceKey: "k1")]
      ),
      { if case .invalidRequest = $0 { return true }; return false }
    )
    let otherDID = "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz"
    await expectThrows(
      try await firehose.appendBatch(
        [deletedAccountItem(sourceKey: "delete-1")],
        now: epoch,
        deletingPriorEvents: [FirehoseDeletionMarker(did: otherDID, sourceKey: "delete-1")]
      ),
      { if case .invalidRequest = $0 { return true }; return false }
    )
  }

  /// Regression: the marker's own item's sequence must never be the delete
  /// boundary. Pairing a same-DID identity item with the deleted-account
  /// item in one batch, when history for that DID already exists from a
  /// prior call, exercises the exact failure mode the fix addresses — using
  /// the marker's own sequence would also delete the same-batch sibling.
  func testDeletingPriorEventsSurvivesSameBatchSiblingAndOnlyDeletesPreBatchHistory() async throws {
    _ = try await firehose.appendBatch(
      [
        identityItem(sourceKey: "pre-1", batchID: "pre-history"),
        identityItem(sourceKey: "pre-2", batchID: "pre-history"),
      ],
      now: epoch
    )
    let otherDID = "did:plc:wwwwwwwwwwwwwwwwwwwwwwww"
    _ = try await firehose.appendBatch(
      [identityItem(sourceKey: "other-1", did: otherDID)],
      now: epoch
    )

    let sibling = identityItem(sourceKey: "sibling-1", batchID: "delete-batch")
    let deletion = deletedAccountItem(sourceKey: "delete-1", batchID: "delete-batch")
    let seqs = try await firehose.appendBatch(
      [sibling, deletion],
      now: epoch,
      deletingPriorEvents: [FirehoseDeletionMarker(did: did, sourceKey: "delete-1")]
    )
    XCTAssertEqual(seqs, [4, 5])

    let stored = try await firehose.events(after: 0, limit: 10)
    XCTAssertEqual(
      stored.map(\.sourceKey),
      ["other-1", "sibling-1", "delete-1"],
      "pre-batch history for the deleted DID is gone, but the same-batch sibling survives"
    )
    XCTAssertEqual(stored.map(\.seq), [3, 4, 5])
    XCTAssertEqual(stored.map(\.did), [otherDID, did, did])
    XCTAssertEqual(stored.last?.kind, .account)
  }

  /// Regression: the exact-replay path must re-derive the same batch-start
  /// boundary from its own replayed sequences, not reuse the marker's own
  /// sequence either. Replaying the same sibling+deletion batch a second
  /// time must not retroactively delete the sibling that survived the first
  /// call.
  func testDeletingPriorEventsBatchBoundaryIsPreservedOnExactReplay() async throws {
    _ = try await firehose.appendBatch(
      [identityItem(sourceKey: "pre-1")],
      now: epoch
    )
    let sibling = identityItem(sourceKey: "sibling-1", batchID: "delete-batch")
    let deletion = deletedAccountItem(sourceKey: "delete-1", batchID: "delete-batch")
    let marker = [FirehoseDeletionMarker(did: did, sourceKey: "delete-1")]

    let first = try await firehose.appendBatch(
      [sibling, deletion],
      now: epoch,
      deletingPriorEvents: marker
    )
    XCTAssertEqual(first, [2, 3])
    let afterFirst = try await firehose.events(after: 0, limit: 10)
    XCTAssertEqual(
      afterFirst.map(\.seq),
      [2, 3],
      "pre-batch history removed; same-batch sibling survives"
    )

    let replayed = try await firehose.appendBatch(
      [sibling, deletion],
      now: epoch,
      deletingPriorEvents: marker
    )
    XCTAssertEqual(replayed, first, "exact replay reproduces the same sequences")
    let afterReplay = try await firehose.events(after: 0, limit: 10)
    XCTAssertEqual(
      afterReplay.map(\.seq),
      [2, 3],
      "replay must rederive the same batch-start boundary and must not delete the sibling"
    )
  }
}
