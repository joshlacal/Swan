# Swan Firehose Phase 3: Liveness, Retention, and Account Deletion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add production liveness, bounded durable-log retention, active `OutdatedCursor` recovery, and atomic public account deletion to Swan's Phase 2 `subscribeRepos` firehose.

**Architecture:** `firehose.sqlite` remains the queue and its `firehose_meta.next_seq` remains the sequence high-water mark even after event rows are deleted. A transaction-owned SQLite pruner removes age- and budget-expired rows, advances `retained_from_seq`, and reports a retention wakeup to the existing in-process hub; each tailer checks the retained boundary before reading and resets to the retained window after an `OutdatedCursor` info frame. The Phase 2 WebSocket handler keeps Hummingbird's built-in `withGracefulShutdownHandler`, while the server enables its 30-second automatic ping and gains live ServiceGroup tests for both ping timeout and graceful close.

**Tech Stack:** Swift 6 strict concurrency, actors, XCTest, SQLiteNIO, Hummingbird 2.25.1, hummingbird-websocket 2.7.0, swift-service-lifecycle, `jj`.

## Global Constraints

- **WebSocket ping heartbeat:** send a WebSocket ping every 30 s.
- **Graceful shutdown:** graceful shutdown sends close frames via the service-lifecycle hook.
- **Retention:** use a hard maximum age, default 72 h on `sequenced_at`, plus a separate maximum row/byte budget.
- **Retention floor:** no minimum-row floor overrides the age ceiling.
- **Retention cursor:** pruning advances `retained_from_seq`; either bound expiring history yields `OutdatedCursor` for older cursors.
- **Account deletion:** append the `deleted` `#account` event and delete earlier retained events for that DID in the same global transaction.
- **Sequence gaps:** sequence gaps are permitted after per-DID deletion pruning.
- **Concurrency:** Swift 6 strict concurrency, actors for shared mutable state, 2-space indentation, XCTest rather than Swift Testing.
- **SQLite:** every database operation uses `connection.query(sql, bindings)` inside `withConnectionGate` and, for writes, `transaction`; no network or WebSocket I/O occurs inside a SQLite transaction.
- **Wire bytes:** `firehose_events.frame_bytes` is shipped verbatim; deletion and retention never re-encode an event.
- **WebSocket dependency:** keep `hummingbird` exact `2.25.1` and `hummingbird-websocket` exact `2.7.0`.
- **Profiles:** the existing `public-data-testing-2026-08-05` profile and all legacy profile artifacts remain byte-immutable; the activated retention behavior gets a new successor profile.
- **Generator:** do not change or repin `Petrel-swan-generator`; no generated Swift source is hand-edited.
- **Feature flag:** `--enable-public-firehose` remains default-off during Phase 3; changing the default is a separate activation decision.
- **Workspace:** work only from `/Users/joshlacalamito/Developer/Catbird+Petrel/.worktrees/swan-public-federation`.
- **VCS:** use `jj`, not Git, and commit only the files belonging to the current task.
- **Verification:** use `xcrun swift test --filter <filter>` from the worktree root; use `xcrun swift test` for the final exit gate.

The design specifies the 72-hour age default but does not name numeric row and byte defaults. This plan makes those values explicit so the implementation is executable: `maximumRows = 1_000_000`, `maximumBytes = 1_073_741_824` frame bytes (1 GiB), and a 60-second pruning interval. All three are command-line options when the firehose flag is enabled.

---

## File Structure

The following boundaries are intentional. The database owns retention decisions and atomic deletes; the HTTP module owns scheduling, wakeups, and WebSocket presentation; the command owns operator configuration; the profile verifier owns immutable compatibility pins.

- Create `Sources/SwanSQLite/PublicFirehoseRetention.swift` for the validated retention policy and prune result value types.
- Modify `Sources/SwanSQLite/SQLiteFirehoseDatabase.swift` for age/row/byte pruning, the `sequenced_at` index, high-water-mark reads, and deletion-marker transaction support.
- Modify `Sources/SwanSQLite/PublicFirehoseSequencer.swift` to identify a decoded `status: "deleted"` account item and pass its deletion marker to the global append transaction.
- Create `Sources/SwanHTTP/SwanPublicFirehoseRetentionService.swift` for the ServiceLifecycle-managed periodic pruner.
- Modify `Sources/SwanHTTP/PublicFirehoseWakeupHub.swift` for retention wakeups that are not suppressed by append-sequence coalescing.
- Modify `Sources/SwanHTTP/PublicFirehoseStreaming.swift` for retained-boundary checks and an `outdatedCursor` tailer error.
- Modify `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift` for retained-window `cursor=0` behavior and active-session `OutdatedCursor` recovery.
- Modify `Sources/SwanHTTP/SwanHTTP.swift` for 30-second auto-ping and a testable server-running callback/auto-ping interval override.
- Modify `Sources/swan/SwanCommand.swift` for retention CLI options and ServiceGroup membership.
- Extend `Tests/SwanSQLiteTests/SQLiteFirehoseDatabaseTests.swift` for retention algorithms and sequence high-water behavior.
- Extend `Tests/SwanSQLiteTests/PublicFirehoseSequencerTests.swift` for atomic deleted-account events and sparse sequences.
- Extend `Tests/SwanHTTPTests/PublicFirehoseStreamingTests.swift` for retained-boundary tailer behavior and hub retention signals.
- Extend `Tests/SwanHTTPTests/PublicFirehoseStreamingHTTPTests.swift` for post-prune connect behavior and full-window semantics.
- Extend `Tests/SwanHTTPTests/PublicFirehoseStreamingHTTPTests.swift` for live auto-ping and ServiceGroup graceful-shutdown behavior; keeping the tests in this class reuses its existing fixture, WebSocket client, polling, and deadline helpers.
- Extend `Tests/SwanHTTPTests/PublicFirehoseServiceWiringTests.swift` for the production retention service wiring.
- Create successor profile artifacts `Profiles/public-data-testing-2026-08-06.json`, `.lexicons.sha256`, and `.generated-wire.sha256`.
- Modify `Scripts/public-wire-generation-common.sh` for the new selected profile and frozen 2026-08-05 predecessor.
- Modify `Sources/SwanPublicWire/SwanPublicWire.swift` for the successor profile descriptor alias.
- Modify `Sources/SwanInterop/SwanInterop.swift` and `Tests/SwanInteropTests/PublicProtocolProfileVerifierTests.swift` for the new profile pins and divergence count.
- Extend `Tests/SwanPublicWireTests/SwanPublicWireTests.swift` for the successor profile selection.
- Create `docs/superpowers/plans/2026-08-05-swan-firehose-phase3-completion-record.md` after implementation and verification.

---

### Task 0: Freeze the Phase 3 Contract

**Files:**
- Create: `docs/superpowers/plans/2026-08-05-swan-firehose-phase3-liveness-retention.md`
- Verify: `docs/superpowers/specs/2026-08-04-swan-public-firehose-design.md:283-312`
- Verify: `docs/superpowers/plans/2026-08-04-swan-firehose-phase2-completion-record.md:200-212`

**Interfaces:**
- Consumes: the design requirements for liveness, retention, cursor reset, and deletion.
- Produces: this plan, which later tasks implement without changing the Phase 1/2 wire or sequence contracts.

- [ ] **Step 1: Confirm the scope before editing code**

Read the design's cursor and liveness sections and verify that the Phase 2 completion record still lists only these Phase 3 items as unimplemented: 30-second auto-ping, graceful shutdown close verification, retention pruning and `retained_from_seq`, active `OutdatedCursor`, and deleted-account pruning. Do not add Phase 4 lifecycle integration, `requestCrawl`, or Phase 5 relay acceptance to this plan.

```bash
rg -n "Cursor semantics|Liveness and retention|Account deletion|requestCrawl|OutdatedCursor" \
  docs/superpowers/specs/2026-08-04-swan-public-firehose-design.md
rg -n "Explicitly unimplemented|heartbeat|retention|Account-deletion" \
  docs/superpowers/plans/2026-08-04-swan-firehose-phase2-completion-record.md
```

- [ ] **Step 2: Commit the plan before implementation**

```bash
jj commit docs/superpowers/plans/2026-08-05-swan-firehose-phase3-liveness-retention.md \
  -m "firehose: phase 3 liveness and retention plan"
```

**Acceptance:** the plan is committed, the worktree is clean, and every later task has a named file, interface, test, and commit boundary.

---

### Task 1: Add the Durable Retention Primitives

**Files:**
- Create: `Sources/SwanSQLite/PublicFirehoseRetention.swift`
- Modify: `Sources/SwanSQLite/SQLiteFirehoseDatabase.swift:331-410, 541-591`
- Test: `Tests/SwanSQLiteTests/SQLiteFirehoseDatabaseTests.swift`

**Interfaces:**
- Consumes: `FirehoseFrameLimits.maximumFrameBytes`, `PublicFirehoseTime.microseconds(_:)`, `firehose_meta`, and `firehose_events`.
- Produces: `PublicFirehoseRetentionPolicy`, `PublicFirehosePruneResult`, `SQLiteFirehoseDatabase.prune(now:policy:)`, and a high-water-mark implementation of `maxSequencedSeq()`.

The exact public policy is:

```swift
public struct PublicFirehoseRetentionPolicy: Sendable, Equatable {
  public let maximumAge: Duration
  public let maximumRows: Int64
  public let maximumBytes: Int64

  public static let standard = try! PublicFirehoseRetentionPolicy()

  public init(
    maximumAge: Duration = .seconds(259_200),
    maximumRows: Int64 = 1_000_000,
    maximumBytes: Int64 = 1_073_741_824
  ) throws
}

public struct PublicFirehosePruneResult: Sendable, Equatable {
  public let deletedRows: Int64
  public let deletedBytes: Int64
  public let retainedFromSeq: Int64?
  public let didAdvanceRetention: Bool
}

extension SQLiteFirehoseDatabase {
  public func prune(
    now: Date,
    policy: PublicFirehoseRetentionPolicy
  ) async throws -> PublicFirehosePruneResult
}
```

- [ ] **Step 1: Write failing policy and pruning tests**

Add these tests to `SQLiteFirehoseDatabaseTests`. The existing `identityItem(sourceKey:did:batchID:)`, `epoch`, and `firehose` fixture are sufficient; `appendBatch(now:)` already writes deterministic microsecond `sequenced_at` values.

```swift
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
```

- [ ] **Step 2: Run the focused tests and verify they fail for missing symbols**

Run:

```bash
xcrun swift test --filter SQLiteFirehoseDatabaseTests
```

Expected: compilation fails because `PublicFirehoseRetentionPolicy`, `PublicFirehosePruneResult`, and `prune(now:policy:)` do not exist yet; no existing Phase 2 test is allowed to regress once the implementation is added.

- [ ] **Step 3: Implement policy validation and duration conversion**

Use the existing `Duration.components` conversion pattern from `SwanJSONWriteBodyDrainHandler.swift:17-24`. Convert the positive duration to checked microseconds and store that value as an internal policy property. Reject `maximumAge <= .zero`, `maximumRows < 1`, and `maximumBytes < FirehoseFrameLimits.maximumFrameBytes`; the last rule guarantees that one valid maximum-sized frame can fit under the byte budget.

```swift
let components = maximumAge.components
let seconds = components.seconds.multipliedReportingOverflow(by: 1_000_000)
let fraction = components.attoseconds / 1_000_000_000_000
let micros = seconds.partialValue.addingReportingOverflow(fraction)
guard !seconds.overflow, !micros.overflow, micros.partialValue > 0 else {
  throw SwanError.malformed("firehose retention age must be positive")
}
```

Store the checked microsecond value privately in the policy and use the exact error strings above for invalid age, plus `firehose retention row budget must be positive` and `firehose retention byte budget must be at least 5000000` for the other two failures.

- [ ] **Step 4: Implement transactional age and budget pruning**

Add `CREATE INDEX IF NOT EXISTS firehose_events_sequenced_at_seq ON firehose_events(sequenced_at, seq)` to `schemaStatements`. The existing schema migration runs these idempotent statements on every open, so no separate migration version is needed.

Implement `prune(now:policy:)` under `checkOpen()`, `withConnectionGate`, and `transaction`. Compute the cutoff with `PublicFirehoseTime.microseconds(now)` minus the policy's checked microseconds. Delete all age-expired rows first and collect `seq` plus `length(frame_bytes)` through `RETURNING`:

```sql
DELETE FROM firehose_events
WHERE sequenced_at < ?
RETURNING seq, length(frame_bytes) AS bytes
```

Then repeatedly read the current totals and delete the oldest bounded page while either budget is exceeded:

```sql
SELECT COUNT(*) AS row_count,
       COALESCE(SUM(length(frame_bytes)), 0) AS byte_count
FROM firehose_events
```

```sql
SELECT seq
FROM firehose_events
ORDER BY seq
LIMIT 1000
```

Build the `IN` placeholders from the selected sequence values and delete that page with `RETURNING seq, length(frame_bytes) AS bytes`. Do not add a minimum-row condition. The loop stops only when both `row_count <= maximumRows` and `byte_count <= maximumBytes`.

After all deletes in the same transaction, compute the new boundary as `MIN(seq)` from remaining rows, or the greatest deleted sequence when the log is empty. Read the previous `retained_from_seq`, and write it only when at least one row was deleted in this prune and the new boundary is greater than the previous value (treat the never-set state as unbounded, never as `0`). A no-op prune — zero rows deleted by any bound — must not write `retained_from_seq` at all and must return `didAdvanceRetention == false`; this keeps the dormant Phase 2 behavior intact until the first real prune. Return the retained boundary and advance flag accordingly.

Change `maxSequencedSeq()` to read `firehose_meta.next_seq - 1` rather than `MAX(seq)`. Validate the result is between `0` and `FirehoseFrameLimits.maximumSequence`. This preserves the current sequence high-water mark after retention deletes all rows or after per-DID deletion creates gaps.

- [ ] **Step 5: Run the focused tests and the database regression filter**

```bash
xcrun swift test --filter SQLiteFirehoseDatabaseTests
xcrun swift test --filter 'SQLiteFirehoseDatabaseTests|PublicFirehoseSequencerTests'
```

Expected: all retention tests pass, all existing Phase 1 database/sequencer tests pass, and the all-rows-pruned test reports `maxSequencedSeq() == 2` with an empty event page.

- [ ] **Step 6: Commit the database deliverable**

```bash
jj commit Sources/SwanSQLite/SQLiteFirehoseDatabase.swift \
  Sources/SwanSQLite/PublicFirehoseRetention.swift \
  Tests/SwanSQLiteTests/SQLiteFirehoseDatabaseTests.swift \
  -m "firehose: add bounded retention pruning"
```

**Acceptance:** age, row, and byte bounds are enforced in one SQLite transaction; `retained_from_seq` only advances; no minimum-row floor exists; the sequence high-water mark survives an empty event table.

---

### Task 2: Schedule Retention and Wire Operator Configuration

**Files:**
- Create: `Sources/SwanHTTP/SwanPublicFirehoseRetentionService.swift`
- Modify: `Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:15-73`
- Modify: `Sources/swan/SwanCommand.swift:1525-1529, 2174-2205, 2352-2367`
- Test: `Tests/SwanHTTPTests/PublicFirehoseStreamingTests.swift`
- Test: `Tests/SwanHTTPTests/PublicFirehoseServiceWiringTests.swift`

**Interfaces:**
- Consumes: `SQLiteFirehoseDatabase.prune(now:policy:)`, `PublicFirehoseRetentionPolicy`, and `PublicFirehoseWakeupHub`.
- Produces: `SwanPublicFirehoseRetentionService`, the hub method `firehoseRetentionDidAdvance(maxSeq:)`, and four `serve` options.

The service interface is:

```swift
public struct SwanPublicFirehoseRetentionService: Service {
  public init(
    database: SQLiteFirehoseDatabase,
    hub: PublicFirehoseWakeupHub,
    policy: PublicFirehoseRetentionPolicy,
    interval: Duration = .seconds(60),
    logger: Logger
  ) throws

  public func run() async throws
}
```

- [ ] **Step 1: Write the failing retention-wakeup test**

Extend `testWakeupHubCoalescingAndFanOut` with a separate retention signal test. The signal must be delivered even when its `maxSeq` equals the last append signal; append coalescing must remain unchanged.

```swift
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
```

Add the service test to `PublicFirehoseServiceWiringTests` after opening a temporary `SQLiteFirehoseDatabase`:

```swift
func testRetentionServicePrunesImmediatelyAndSignalsSubscribers() async throws {
  let root = FileManager.default.temporaryDirectory
    .appending(path: "swan-firehose-retention-service-\(UUID().uuidString)")
  try FileManager.default.createDirectory(
    at: root,
    withIntermediateDirectories: true,
    attributes: [.posixPermissions: 0o700]
  )
  defer { try? FileManager.default.removeItem(at: root) }

  let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
  defer { Task { try? await firehose.close() } }
  let hub = PublicFirehoseWakeupHub()
  let stream = await hub.subscribe()
  var iterator = stream.makeAsyncIterator()
  _ = try await firehose.appendBatch(
    [FirehoseAppendItem(
      sourceKey: "retention-service",
      batchID: nil,
      did: "did:plc:retentionservice000000000",
      kind: .identity
    ) { _ in Data([0x01]) }],
    now: Date(timeIntervalSince1970: 1_700_000_000)
  )

  let service = try SwanPublicFirehoseRetentionService(
    database: firehose,
    hub: hub,
    policy: try PublicFirehoseRetentionPolicy(
      maximumAge: .seconds(1),
      maximumRows: 100,
      maximumBytes: 5_000_000
    ),
    interval: .seconds(60),
    logger: Logger(label: "retention-service-test")
  )
  let task = Task { try await service.run() }
  defer { task.cancel() }

  let wakeup = await iterator.next()
  XCTAssertEqual(wakeup, 1)
  let retained = try await firehose.retainedFromSeq()
  XCTAssertEqual(retained, 1)
}
```

- [ ] **Step 2: Run the new tests and verify the APIs are missing**

```bash
xcrun swift test --filter 'PublicFirehoseStreamingTests|PublicFirehoseServiceWiringTests'
```

Expected: compilation fails for `firehoseRetentionDidAdvance` and `SwanPublicFirehoseRetentionService`.

- [ ] **Step 3: Add a retention signal to the hub**

Keep `AsyncStream<Int64>` and `.bufferingNewest(1)`. Add this actor method without changing `PublicFirehoseWakeupSink`:

```swift
public func firehoseRetentionDidAdvance(maxSeq: Int64) {
  guard maxSeq >= 0 else { return }
  for continuation in subscribers.values {
    continuation.yield(maxSeq)
  }
}
```

Unlike `firehoseDidAppend(maxSeq:)`, this method must not compare against or update `latestMaxSeq`; a prune can change the database while the sequence high-water mark remains unchanged.

- [ ] **Step 4: Implement the ServiceLifecycle retention worker**

The worker runs one prune immediately, then sleeps for the configured interval. A transient database error is logged and retried after the same interval; cancellation returns normally. When `didAdvanceRetention` is true, read the high-water mark and call `await hub.firehoseRetentionDidAdvance(maxSeq:)`.

```swift
public func run() async throws {
  while !Task.isCancelled {
    do {
      let result = try await database.prune(now: Date(), policy: policy)
      if result.didAdvanceRetention {
        let maxSeq = try await database.maxSequencedSeq()
        await hub.firehoseRetentionDidAdvance(maxSeq: maxSeq)
      }
    } catch is CancellationError {
      return
    } catch {
      logger.error("public firehose retention pass failed", metadata: [
        "error": "\(error)"
      ])
    }

    do {
      try await Task.sleep(for: interval)
    } catch is CancellationError {
      return
    }
  }
}
```

Validate `interval > .zero` in the initializer and use `SwanError.malformed("firehose retention interval must be positive")` for invalid input.

- [ ] **Step 5: Add CLI options and service-group ownership**

Add these `Serve` properties immediately after `enablePublicFirehose`:

```swift
@Option(
  name: .customLong("public-firehose-retention-age-hours"),
  help: "Maximum retained firehose age in hours (default: 72)"
)
var publicFirehoseRetentionAgeHours: Int64 = 72

@Option(
  name: .customLong("public-firehose-retention-max-rows"),
  help: "Maximum retained firehose rows (default: 1000000)"
)
var publicFirehoseRetentionMaxRows: Int64 = 1_000_000

@Option(
  name: .customLong("public-firehose-retention-max-bytes"),
  help: "Maximum retained firehose frame bytes (default: 1073741824)"
)
var publicFirehoseRetentionMaxBytes: Int64 = 1_073_741_824

@Option(
  name: .customLong("public-firehose-retention-interval-seconds"),
  help: "Retention pruning interval in seconds (default: 60)"
)
var publicFirehoseRetentionIntervalSeconds: Int64 = 60
```

When `enablePublicFirehose` is true, validate checked multiplication for `ageHours * 3_600` and `intervalSeconds`, construct the policy, and convert policy/service construction errors to `ValidationError` with the option name. When the flag is false, reject non-default retention values with `ValidationError("public firehose retention options require --enable-public-firehose")` so an operator cannot silently believe an unused setting is active.

Construct and retain a `SwanPublicFirehoseRetentionService?` next to `publicFirehoseService`:

```swift
let publicFirehoseRetentionService: SwanPublicFirehoseRetentionService?
if enablePublicFirehose {
  let retentionService = try SwanPublicFirehoseRetentionService(
    database: firehoseDatabase,
    hub: wakeupHub,
    policy: retentionPolicy,
    interval: .seconds(publicFirehoseRetentionIntervalSeconds),
    logger: logger
  )
  publicFirehoseRetentionService = retentionService
} else {
  publicFirehoseRetentionService = nil
}
```

Append it to `services` after `publicFirehoseService` and before the management application. The existing shutdown order then cancels the worker before `preopenedFirehoseDatabase?.close()` runs.

- [ ] **Step 6: Run the service and command compilation tests**

```bash
xcrun swift test --filter 'PublicFirehoseStreamingTests|PublicFirehoseServiceWiringTests|SwanHTTPTests'
xcrun swift build
```

Expected: the retention service prunes at startup, emits a non-coalesced retention wakeup, invalid intervals fail construction, and the executable still builds with the flag defaulting to false.

- [ ] **Step 7: Commit the scheduling and wiring deliverable**

```bash
jj commit Sources/SwanHTTP/SwanPublicFirehoseRetentionService.swift \
  Sources/SwanHTTP/PublicFirehoseWakeupHub.swift \
  Sources/swan/SwanCommand.swift \
  Tests/SwanHTTPTests/PublicFirehoseStreamingTests.swift \
  Tests/SwanHTTPTests/PublicFirehoseServiceWiringTests.swift \
  -m "firehose: schedule bounded retention"
```

**Acceptance:** enabling the feature starts the pruner and only the pruner; a retention advance wakes subscribers even without a new append; disabled mode does not open or prune `firehose.sqlite`.

---

### Task 3: Enable Liveness and Prove Graceful Shutdown

**Files:**
- Modify: `Sources/SwanHTTP/SwanHTTP.swift:1015-1057`
- Modify: `Tests/SwanHTTPTests/PublicFirehoseStreamingHTTPTests.swift:38-78`

**Interfaces:**
- Consumes: Hummingbird 2.7.0 `AutoPingSetup.enabled(timePeriod:)`, `WebSocketOutboundWriter.close`, `ApplicationProtocol`, and `SwanHTTPServiceLifecycle.makeServiceGroup`.
- Produces: the production 30-second auto-ping configuration, a test-only auto-ping interval override, and a testable `onServerRunning` callback on `buildApplication`.

Hummingbird's `WebSocketHandler.handle` already wraps every upgraded handler in `withGracefulShutdownHandler`; its graceful callback sends `.normalClosure`. Do not add a separate connection registry or duplicate close task.

- [ ] **Step 1: Write the failing liveness tests**

Add the tests to `PublicFirehoseStreamingHTTPTests` so they can use its existing `Fixture`, `makeFixture`, `waitUntil`, `awaitWithDeadline`, and WebSocket helpers. First change `makeFixture` to accept `port: Int = 3_000` and pass that value into `SwanHTTPConfiguration`; `port: 0` is used only by the explicit ServiceGroup test. Add this actor to the test class for the `onServerRunning` callback:

Change the existing fixture signature to:

```swift
private func makeFixture(
  limits: PublicFirehoseStreamingLimits? = nil,
  includeRuntime: Bool = true,
  port: Int = 3_000
) async throws -> Fixture
```

Change its server construction line to:

```swift
configuration: .init(host: "127.0.0.1", port: port),
```

```swift
private actor PortBox {
  enum Error: Swift.Error { case timeout }

  private var value: Int?

  func set(_ value: Int?) {
    self.value = value
  }

  func wait() async throws -> Int {
    let deadline = ContinuousClock.now + .seconds(5)
    while ContinuousClock.now < deadline {
      if let value { return value }
      try await Task.sleep(for: .milliseconds(10))
    }
    throw Error.timeout
  }
}
```

The first test uses a short override only to avoid a 30-second test; the production default remains exactly 30 seconds. A client handler that does not iterate inbound cannot answer the server's ping, so Hummingbird should close with `.goingAway` and reason `Ping timeout`.

```swift
func testPublicFirehoseAutoPingClosesAClientThatDoesNotPong() async throws {
  let fixture = try await makeFixture()
  defer { Task { try? await fixture.firehose.close(); try? await fixture.control.close() } }
  let app = fixture.server.buildApplication(
    logger: logger,
    webSocketAutoPingInterval: .milliseconds(50)
  )

  try await app.test(.live) { client in
    let closeFrame = try await self.awaitWithDeadline(timeout: .seconds(2)) {
      try await client.ws(
        self.subscribePath,
        configuration: .init(maxFrameSize: 5_000_000),
        logger: self.logger
      ) { _, _, _ in
        try await Task.sleep(for: .milliseconds(250))
      }
    }
    XCTAssertEqual(closeFrame?.closeCode, .goingAway)
    XCTAssertEqual(closeFrame?.reason, "Ping timeout")
  }
}
```

The second test runs the real application as a member of an explicit `ServiceGroup`, captures its ephemeral port through `onServerRunning`, holds a passive WebSocket open, triggers `serviceGroup.triggerGracefulShutdown()`, and asserts the close frame arrives before the ServiceGroup exits:

```swift
func testPublicFirehoseGracefulShutdownSendsNormalCloseFrame() async throws {
  let fixture = try await makeFixture(port: 0)
  defer { Task { try? await fixture.firehose.close(); try? await fixture.control.close() } }
  let portBox = PortBox()
  let application = fixture.server.buildApplication(
    logger: logger,
    onServerRunning: { channel in
      await portBox.set(channel.localAddress?.port)
    }
  )
  let serviceGroup = SwanHTTPServiceLifecycle.makeServiceGroup(
    services: [application],
    logger: logger
  )
  let serviceTask = Task { try await serviceGroup.run() }
  let port = try await portBox.wait()
  let client = TestClient(
    host: "127.0.0.1",
    port: port,
    configuration: .init(timeout: .seconds(5))
  )
  client.connect()
  defer { Task { try? await client.shutdown() } }

  let wsTask = Task {
    try await client.ws(self.subscribePath) { inbound, _, _ in
      for try await _ in inbound {}
    }
  }
  try await waitUntil { await fixture.hub.subscriberCount() == 1 }
  await serviceGroup.triggerGracefulShutdown()

  let closeFrame = try await awaitWithDeadline { try await wsTask.value }
  XCTAssertEqual(closeFrame?.closeCode, .normalClosure)
  _ = try await serviceTask.value
}
```

`PortBox` is a small actor with `set(_:)` and a polling `wait()` that throws after five seconds. Reuse the existing `waitUntil` and deadline helper shapes; do not use a process signal in the test.

- [ ] **Step 2: Run the tests and verify the new builder arguments are missing**

```bash
xcrun swift test --filter PublicFirehoseStreamingHTTPTests
```

Expected: compilation fails because `buildApplication` does not yet accept `webSocketAutoPingInterval` or `onServerRunning`.

- [ ] **Step 3: Enable the production ping and add test-only builder injection**

Change the WebSocket configuration from:

```swift
autoPing: .disabled,
```

to:

```swift
autoPing: .enabled(timePeriod: autoPingInterval),
```

Change `buildApplication` to this signature, retaining the existing default behavior for all callers:

```swift
public func buildApplication(
  logger: Logger,
  onServerRunning: @escaping @Sendable (any Channel) async -> Void = { _ in },
  webSocketAutoPingInterval: Duration = .seconds(30)
) -> some ApplicationProtocol
```

Pass `onServerRunning` to `Application(..., onServerRunning: onServerRunning, ...)` and pass `webSocketAutoPingInterval` to `publicFirehoseWebSocketConfiguration(autoPingInterval:)`. Keep `maxFrameSize: 5_000_000`, `closeTimeout: .seconds(15)`, and `validateUTF8: true` unchanged.

- [ ] **Step 4: Run liveness and existing WebSocket tests**

```bash
xcrun swift test --filter PublicFirehoseStreamingHTTPTests
xcrun swift test --filter 'PublicFirehoseStreamingHTTPTests|PublicFirehoseServiceWiringTests'
```

Expected: the short-interval client receives `.goingAway` / `Ping timeout`; ServiceGroup shutdown receives `.normalClosure`; all Phase 2 WebSocket tests remain green.

- [ ] **Step 5: Commit the liveness deliverable**

```bash
jj commit Sources/SwanHTTP/SwanHTTP.swift \
  Tests/SwanHTTPTests/PublicFirehoseStreamingHTTPTests.swift \
  -m "firehose: enable websocket liveness and graceful close"
```

**Acceptance:** production WebSocket configuration sends pings every 30 seconds, a peer that fails to pong is closed by Hummingbird, and a ServiceGroup graceful shutdown produces a WebSocket close frame rather than only tearing down the channel.

---

### Task 4: Activate Retained-Cursor Streaming Behavior

**Files:**
- Modify: `Sources/SwanHTTP/PublicFirehoseStreaming.swift:112-216`
- Modify: `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift:153-283`
- Modify: `Sources/SwanHTTP/PublicFirehoseWakeupHub.swift:21-31`
- Test: `Tests/SwanHTTPTests/PublicFirehoseStreamingTests.swift`
- Test: `Tests/SwanHTTPTests/PublicFirehoseStreamingHTTPTests.swift`

**Interfaces:**
- Consumes: `SQLiteFirehoseDatabase.retainedFromSeq()`, `PublicFirehoseWakeupHub.firehoseRetentionDidAdvance(maxSeq:)`, and the existing `PublicFirehoseCursorPolicy`.
- Produces: `PublicFirehoseTailerError.outdatedCursor(retainedFromSeq:)`, retained-window full-sync behavior, and active-session info-frame recovery.

- [ ] **Step 1: Write failing unit and live-server tests**

Change the existing `appendCommit` helper signature to accept `now: Date = epoch` and pass that value to `firehose.appendBatch(now:)`:

```swift
private func appendCommit(
  to firehose: SQLiteFirehoseDatabase,
  hub: PublicFirehoseWakeupHub,
  sourceKey: String,
  seed: UInt8,
  now: Date = epoch
) async throws -> FirehoseStoredEvent
```

Add this frame assertion beside `assertErrorFrame`:

```swift
private func assertInfoFrame(
  _ frame: WebSocketDataFrame,
  name: String,
  file: StaticString = #filePath,
  line: UInt = #line
) throws {
  XCTAssertEqual(frame.opcode, .binary, file: file, line: line)
  var reader = FirehoseStreamingTestCBORReader(Data(buffer: frame.data))
  let (header, body) = try reader.readFrame()
  XCTAssertEqual(reader.headerOp(header), 1, file: file, line: line)
  XCTAssertEqual(reader.headerType(header), "#info", file: file, line: line)
  guard case .some(.text(let value)) = reader.bodyValue(body, key: "name") else {
    return XCTFail("info frame must carry a name", file: file, line: line)
  }
  XCTAssertEqual(value, name, file: file, line: line)
}
```

Add the tailer error case to the unit test matrix:

```swift
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
  XCTAssertEqual(result.retainedFromSeq, 2)

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
    XCTAssertEqual(error, .outdatedCursor(retainedFromSeq: 2))
  }
}
```

Replace the Phase 2 dormant HTTP test with a deterministic post-prune test. Seed sequences 1 and 2 at `epoch`, sequence 3 at `epoch + 20`, prune with a one-second age at `epoch + 20`, connect with `cursor=1`, and assert exactly an `#info` `OutdatedCursor` frame followed by the stored sequence-3 frame. Also add a `cursor=0` test against the same pruned log and assert it receives sequence 3 without an info frame.

```swift
func testSubscribeReposPrunedCursorReportsOutdatedThenStreamsRetainedRows() async throws {
  let fixture = try await makeFixture()
  defer { try? FileManager.default.removeItem(at: fixture.root) }
  try await appendCommit(to: fixture.firehose, hub: fixture.hub, sourceKey: "pruned-1", seed: 0x01, now: epoch)
  try await appendCommit(to: fixture.firehose, hub: fixture.hub, sourceKey: "pruned-2", seed: 0x02, now: epoch)
  let retained = try await appendCommit(to: fixture.firehose, hub: fixture.hub, sourceKey: "retained-3", seed: 0x03, now: epoch.addingTimeInterval(20))
  _ = try await fixture.firehose.prune(
    now: epoch.addingTimeInterval(20),
    policy: try PublicFirehoseRetentionPolicy(
      maximumAge: .seconds(1),
      maximumRows: 100,
      maximumBytes: 1_073_741_824
    )
  )

  let app = fixture.server.buildApplication(logger: logger)
  try await app.test(.live) { client in
    let recorder = WSFrameRecorder()
    let wsTask = Task {
      try await runWSClient(
        client,
        path: "\(subscribePath)?cursor=1",
        recorder: recorder,
        closeAfterFrames: 2
      )
    }
    try await waitUntil { await recorder.snapshot().count == 2 }
    _ = try await awaitWithDeadline { try await wsTask.value }
    let frames = await recorder.snapshot()
    try assertInfoFrame(frames[0], name: "OutdatedCursor")
    XCTAssertEqual(Data(buffer: frames[1].data), retained.frameBytes)
  }
}
```

Add the retained-window full-sync test using the same fixture setup. It must close after one frame and assert that the first frame is a `#commit`, not `#info`:

```swift
func testSubscribeReposCursorZeroUsesRetainedWindowWithoutOutdatedInfo() async throws {
  let fixture = try await makeFixture()
  defer { try? FileManager.default.removeItem(at: fixture.root) }
  try await appendCommit(to: fixture.firehose, hub: fixture.hub, sourceKey: "full-old-1", seed: 0x11, now: epoch)
  try await appendCommit(to: fixture.firehose, hub: fixture.hub, sourceKey: "full-old-2", seed: 0x12, now: epoch)
  let retained = try await appendCommit(to: fixture.firehose, hub: fixture.hub, sourceKey: "full-retained-3", seed: 0x13, now: epoch.addingTimeInterval(20))
  _ = try await fixture.firehose.prune(
    now: epoch.addingTimeInterval(20),
    policy: try PublicFirehoseRetentionPolicy(
      maximumAge: .seconds(1),
      maximumRows: 100,
      maximumBytes: 1_073_741_824
    )
  )

  let app = fixture.server.buildApplication(logger: logger)
  try await app.test(.live) { client in
    let recorder = WSFrameRecorder()
    let wsTask = Task {
      try await runWSClient(
        client,
        path: "\(subscribePath)?cursor=0",
        recorder: recorder,
        closeAfterFrames: 1
      )
    }
    try await waitUntil { await recorder.snapshot().count == 1 }
    _ = try await awaitWithDeadline { try await wsTask.value }
    let frames = await recorder.snapshot()
    let frame = try XCTUnwrap(frames.first)
    let header = try decodeFrameHeader(frame)
    XCTAssertEqual(header.type, "#commit")
    XCTAssertEqual(Data(buffer: frame.data), retained.frameBytes)
  }
}
```

- [ ] **Step 2: Run the new tests and verify the tailer error is missing**

```bash
xcrun swift test --filter 'PublicFirehoseStreamingTests|PublicFirehoseStreamingHTTPTests'
```

Expected: compilation fails for the new error case and the live test cannot yet reset from an active retained boundary.

- [ ] **Step 3: Make the tailer retention-aware**

Add:

```swift
case outdatedCursor(retainedFromSeq: Int64)
```

At the top of each `while !Task.isCancelled` iteration, before `events(after:limit:)`, read `retainedFromSeq()`. The tailer stores the last sent sequence, so `lastSent == retainedFromSeq - 1` is valid and must not be rejected. Throw only when:

```swift
if let retainedFromSeq = try await database.retainedFromSeq(),
   cursor < retainedFromSeq - 1 {
  throw PublicFirehoseTailerError.outdatedCursor(
    retainedFromSeq: retainedFromSeq
  )
}
```

`retainedFromSeq` is constrained to be at least 1 by the database schema, so the subtraction is safe. Change the wakeup branch so any non-`nil` signal immediately continues the loop; append signals that are not ahead of the cursor and retention signals with an unchanged high-water mark must both cause a fresh retention check.

- [ ] **Step 4: Correct the full-window starting cursor and recover active sessions**

In `publicFirehoseOnUpgrade`, set `.fullWindow` to the first unread sequence before the retained window:

```swift
case .fullWindow:
  lastSent = max(0, (retainedFromSeq ?? 1) - 1)
```

This preserves the design rule that `cursor=0` streams the retained window without an `OutdatedCursor` info frame. Keep `.outdatedCursor` as an info frame followed by `lastSent = retainedFromSeq - 1`.

Change the call site to pass `initialLastSent: lastSent`, then replace `publicFirehoseRunTailer` with a version that keeps a mutable cursor and defines the existing route's outbound/mailbox closures once:

```swift
private func publicFirehoseRunTailer(
  tailer: PublicFirehoseTailer,
  initialLastSent: Int64,
  outbound: WebSocketOutboundWriter,
  wakeupMailbox: NIOLockedValueBox<Int64?>,
  logger: Logger
) async {
  let outboundWrite: (Data) async throws -> Void = { frameBytes in
    try await outbound.write(.binary(ByteBuffer(data: frameBytes)))
  }
  let wakeupRead: () async -> Int64? = {
    wakeupMailbox.withLockedValue { value in
      let pending = value
      value = nil
      return pending
    }
  }

  var lastSent = initialLastSent
  while !Task.isCancelled {
    do {
      try await tailer.run(
        lastSent: lastSent,
        outbound: outboundWrite,
        waitForWakeup: wakeupRead
      )
      return
    } catch let error as PublicFirehoseTailerError {
      switch error {
      case let .outdatedCursor(retainedFromSeq):
        try? await outbound.write(
          .binary(ByteBuffer(data: try FirehoseFrameEncoder.infoFrame(
            name: "OutdatedCursor",
            message: nil
          )))
        )
        lastSent = max(0, retainedFromSeq - 1)
      case .consumerTooSlow, .writeTooSlow:
        try? await outbound.write(
          .binary(ByteBuffer(data: try FirehoseFrameEncoder.errorFrame(
            error: "ConsumerTooSlow",
            message: nil
          )))
        )
        try? await outbound.close(.normalClosure, reason: "ConsumerTooSlow")
        return
      }
    } catch {
      logger.debug("public firehose tailer ended with error", metadata: [
        "error": "\(error)"
      ])
      return
    }
  }
}
```

Retain the Phase 2 sibling-task cancellation and `finishWakeup()` behavior. The `wakeupRead` closure is nonblocking, so the tailer still reaches its bounded poll and retained-boundary check after a lost signal.

- [ ] **Step 5: Run the streaming matrix**

```bash
xcrun swift test --filter PublicFirehoseStreamingTests
xcrun swift test --filter PublicFirehoseStreamingHTTPTests
```

Expected: pruned cursors receive `#info` then the retained bytes, `cursor=0` starts at the oldest retained row without `#info`, active tailers recover after a retention signal, and all Phase 2 cursor/slow-consumer tests remain green.

- [ ] **Step 6: Commit the retained-cursor deliverable**

```bash
jj commit Sources/SwanHTTP/PublicFirehoseStreaming.swift \
  Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift \
  Sources/SwanHTTP/PublicFirehoseWakeupHub.swift \
  Tests/SwanHTTPTests/PublicFirehoseStreamingTests.swift \
  Tests/SwanHTTPTests/PublicFirehoseStreamingHTTPTests.swift \
  -m "firehose: activate retained cursor recovery"
```

**Acceptance:** the dormant policy branch is reachable, `cursor=0` never emits `OutdatedCursor`, a cursor older than the retained boundary gets an info frame and resumes from the oldest retained sequence, and pruning signals do not require a new event row.

---

### Task 5: Make Account Deletion Atomic With Its Public Event

**Files:**
- Modify: `Sources/SwanSQLite/SQLiteFirehoseDatabase.swift:6-269`
- Modify: `Sources/SwanSQLite/PublicFirehoseSequencer.swift:214-241, 331-367`
- Test: `Tests/SwanSQLiteTests/PublicFirehoseSequencerTests.swift`
- Test: `Tests/SwanSQLiteTests/SQLiteFirehoseDatabaseTests.swift`

**Interfaces:**
- Consumes: lifecycle `PublicFirehoseAccountMaterial`, whose `.deleted` status is already supported by `FirehoseFrameEncoder.accountFrame`.
- Produces: `FirehoseDeletionMarker` and `SQLiteFirehoseDatabase.appendBatch(_:now:deletingPriorEvents:)`.

The exact marker and append signature are:

```swift
public struct FirehoseDeletionMarker: Sendable, Equatable {
  public let did: String
  public let sourceKey: String

  public init(did: String, sourceKey: String) {
    self.did = did
    self.sourceKey = sourceKey
  }
}

public func appendBatch(
  _ items: [FirehoseAppendItem],
  now: Date,
  deletingPriorEvents: [FirehoseDeletionMarker] = []
) async throws -> [Int64]
```

- [ ] **Step 1: Write the failing deletion tests**

Add a `deletedAccountItem(did:operationID:)` helper beside the existing `accountItem` helper:

```swift
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
```

Add this sequence-gap test to `PublicFirehoseSequencerTests`:

```swift
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
  let events = try await firehose.events(after: 0, limit: 10)
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
```

Add an injected-crash test proving the deletion remains atomic with the event insertion: after the sequencer crash hook throws, the old DID rows are already absent, the deleted event is durable, the lifecycle batch remains pending, and a retry returns the same sequence without deleting another DID's row.

Use direct identity rows as the pre-deletion history so the lifecycle batch is the first sequencer operation in this test:

```swift
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

  let afterCrash = try await firehose.events(after: 0, limit: 10)
  XCTAssertEqual(afterCrash.map(\.seq), [3])
  XCTAssertEqual(afterCrash.first?.kind, .account)
  let pendingAfterCrash = try await control.nextPendingLifecycleBatch(did: didA)
  XCTAssertNotNil(pendingAfterCrash)

  let retry = try await sequencer.sequenceNext(now: epoch.addingTimeInterval(1))
  guard case let .sequencedLifecycleBatch(_, seqs) = retry else {
    return XCTFail("expected the exact deletion batch replay")
  }
  XCTAssertEqual(seqs, [3])
  let afterRetry = try await firehose.events(after: 0, limit: 10)
  XCTAssertEqual(afterRetry.map(\.seq), [3])
  let pendingAfterRetry = try await control.nextPendingLifecycleBatch(did: didA)
  XCTAssertNil(pendingAfterRetry)
}
```

- [ ] **Step 2: Run the sequencer tests and verify deletion markers are missing**

```bash
xcrun swift test --filter PublicFirehoseSequencerTests
```

Expected: compilation fails because the deletion marker type and append argument do not exist.

- [ ] **Step 3: Add marker-aware append behavior inside the existing transaction**

Validate every marker has a nonempty DID/source key, has a unique source key, and matches exactly one `.account` item in `items`. Locate the marker's allocated sequence by source key after either the new insert path or exact replay path. Within the same `BEGIN IMMEDIATE` transaction, execute:

```sql
DELETE FROM firehose_events
WHERE did = ? AND seq < ?
```

Do not update `retained_from_seq` for this per-DID deletion; it is a global retention boundary, and deleting one account's history creates permitted sequence gaps rather than expiring the whole log. Apply the same delete operation on exact source replay so a crash/retry cannot leave prior rows behind if the first transaction committed the append and deletion but not lifecycle completion.

- [ ] **Step 4: Mark only decoded deleted account lifecycle items**

In the lifecycle branch of `PublicFirehoseSequencer.sequenceNext`, decode each `.account` payload before appending. Build markers only when `material.active == false` and `material.status == .deleted`:

```swift
let deletionMarkers = try batch.items.compactMap { item -> FirehoseDeletionMarker? in
  guard item.kind == .account else { return nil }
  let material = try JSONDecoder().decode(
    PublicFirehoseAccountMaterial.self,
    from: item.payload
  )
  guard !material.active, material.status == .deleted else { return nil }
  return FirehoseDeletionMarker(did: batch.did, sourceKey: item.sourceKey)
}

let seqs = try await firehose.appendBatch(
  items,
  now: now,
  deletingPriorEvents: deletionMarkers
)
```

Keep the existing append-then-complete ordering and crash hook. Do not wire real `transitionStatus` or `installPublicPLCOperation` callers in this task; those remain Phase 4 lifecycle integration.

- [ ] **Step 5: Run the deletion and full Phase 1 firehose tests**

```bash
xcrun swift test --filter 'PublicFirehoseSequencerTests|SQLiteFirehoseDatabaseTests|PublicFirehoseEventTests'
```

Expected: the deleted account frame remains in the log, all earlier rows for that DID are absent, another DID's row survives, sequence 4 remains the high-water mark, and crash replay is exact.

- [ ] **Step 6: Commit the account-deletion deliverable**

```bash
jj commit Sources/SwanSQLite/SQLiteFirehoseDatabase.swift \
  Sources/SwanSQLite/PublicFirehoseSequencer.swift \
  Tests/SwanSQLiteTests/PublicFirehoseSequencerTests.swift \
  Tests/SwanSQLiteTests/SQLiteFirehoseDatabaseTests.swift \
  -m "firehose: prune account history on deletion"
```

**Acceptance:** a decoded deleted-account lifecycle event and all earlier retained rows for that DID commit or roll back together in `firehose.sqlite`; unrelated DIDs remain intact and sequence gaps are observable but valid.

---

### Task 6: Advance the Immutable Public Profile Pin

**Files:**
- Create: `Profiles/public-data-testing-2026-08-06.json`
- Create: `Profiles/public-data-testing-2026-08-06.lexicons.sha256`
- Create: `Profiles/public-data-testing-2026-08-06.generated-wire.sha256`
- Modify: `Scripts/public-wire-generation-common.sh`
- Modify: `Sources/SwanPublicWire/SwanPublicWire.swift`
- Modify: `Sources/SwanInterop/SwanInterop.swift`
- Modify: `Tests/SwanInteropTests/PublicProtocolProfileVerifierTests.swift`
- Modify: `Tests/SwanPublicWireTests/SwanPublicWireTests.swift`

**Interfaces:**
- Consumes: the Phase 2 profile's exact lexicon/generated-wire manifests and the now-active `OutdatedCursor` behavior.
- Produces: selected profile `public-data-testing-2026-08-06` with the same 21 lexicons/19 endpoints and only the two remaining intentional divergences: `getRepo` nonempty-since and strict malformed-cursor rejection.

- [ ] **Step 1: Write the profile pin test first**

Change the selected-profile test to load `Profiles/public-data-testing-2026-08-06.json`, expect `OfflineProtocolProfileVerifier.publicProfileID`, and assert the verifier reports valid. Add a frozen predecessor test for all three Phase 2 artifacts:

```swift
func testFrozen20260805ProfileRemainsByteExactButIsNoLongerSelected() throws {
  let root = packageRoot()
  let artifacts = [
    ("public-data-testing-2026-08-05.json", "98bb8609b6dc2dfde2db34fb4f6ee1f56d18dab584fa7987b3d259f151f96121"),
    ("public-data-testing-2026-08-05.lexicons.sha256", "2f14fbc29b2c3414baca5e659fb8dbe85f6b5a5252e13ff677b5b19d4309374d"),
    ("public-data-testing-2026-08-05.generated-wire.sha256", "80a03ee8bcaed70008b74556add80108f5cf64d96932b21df60e2d18e247dcc7"),
  ]
  for (name, checksum) in artifacts {
    let data = try Data(contentsOf: root.appending(path: "Profiles/\(name)"))
    XCTAssertEqual(SHA256.hash(data: data).hex, checksum)
  }

  let report = OfflineProtocolProfileVerifier.verify(
    profileURL: root.appending(path: "Profiles/public-data-testing-2026-08-05.json"),
    sourceRoot: root
  )
  XCTAssertEqual(report.profileID, "public-data-testing-2026-08-05")
  XCTAssertEqual(
    report.diagnostics,
    [.init(.unsupportedProfileID, artifact: "profile")]
  )
}
```

- [ ] **Step 2: Create the successor artifacts without regeneration**

The wire files did not change, so copy the two manifests byte-for-byte and copy the JSON before removing only the stale dormant-divergence object:

```bash
cp Profiles/public-data-testing-2026-08-05.lexicons.sha256 \
  Profiles/public-data-testing-2026-08-06.lexicons.sha256
cp Profiles/public-data-testing-2026-08-05.generated-wire.sha256 \
  Profiles/public-data-testing-2026-08-06.generated-wire.sha256
cp Profiles/public-data-testing-2026-08-05.json \
  Profiles/public-data-testing-2026-08-06.json
```

In the copied JSON, change only the profile `id` to `public-data-testing-2026-08-06` and remove the divergence object whose `referenceBehavior` is `Delivers an OutdatedCursor info frame when the requested cursor predates the retained window.` Keep the `getRepo` and malformed-cursor objects byte-for-byte unchanged. Compute the new profile hash and record the real value:

```bash
shasum -a 256 Profiles/public-data-testing-2026-08-06.json \
  Profiles/public-data-testing-2026-08-06.lexicons.sha256 \
  Profiles/public-data-testing-2026-08-06.generated-wire.sha256
```

The new profile JSON hash is `b96ac7c7fa3df3a0bb5b396c25f776734493d7b0a09a71e1e082e24813b64124`. Verify your edited file: it is the 2026-08-05 JSON byte-for-byte with only the `id` value changed and the third `intentionalDivergences` object (the `OutdatedCursor` one) removed; `shasum -a 256` on the result must print `b96ac7c7fa3df3a0bb5b396c25f776734493d7b0a09a71e1e082e24813b64124`. If your editor re-serialized or re-formatted the JSON and the hash differs, redo the edit so the hash matches exactly — the profile pin is byte-immutable once committed. The lexicon and generated-wire manifest hashes must equal their 2026-08-05 counterparts because no lexicon or generated source changed.

- [ ] **Step 3: Update the selected-profile verifier and hand-maintained descriptor list**

In `SwanPublicWire.swift`, add the successor descriptor without duplicating the 19-entry array:

```swift
public enum PublicDataTesting20260806 {
  public static let profileID = "public-data-testing-2026-08-06"
  public static let methods = PublicDataTesting20260805.methods
}
```

In `SwanInterop.swift`, change the selected profile ID to `public-data-testing-2026-08-06` and set `expectedPublicProfileSHA256` to `b96ac7c7fa3df3a0bb5b396c25f776734493d7b0a09a71e1e082e24813b64124`; leave the 21 expected lexicons, 19 endpoint count, lexicon manifest hash, and generated-wire manifest hash unchanged. Change the expected divergence count from 3 to 2 and remove the index-2 `OutdatedCursor` assertions. Keep the exact checks for the `getRepo` and malformed-cursor divergences.

Update `PublicProtocolProfileVerifierTests.PublicProfileFixture.profileURL`, the selected profile test, and the frozen predecessor hash test. Update `SwanPublicWireTests` to assert `PublicDataTesting20260806.profileID`, 19 methods, and the same `subscribeRepos` `.subscription` descriptor.

- [ ] **Step 4: Update the generation gate while freezing 2026-08-05**

In `Scripts/public-wire-generation-common.sh`, select the 2026-08-06 JSON/manifest paths and profile ID, set `public_wire_expected_profile_sha256` to `b96ac7c7fa3df3a0bb5b396c25f776734493d7b0a09a71e1e082e24813b64124`, keep the two manifest hashes unchanged, and add the three 2026-08-05 files to `public_wire_verify_legacy_profile_immutable` with their exact Phase 2 hashes above. Do not change the ordered lexicon or endpoint lists, counts, generated source paths, generator commit, or reference archive pin.

No call to `Scripts/regenerate-public-wire.sh` is expected in this task because the lexicon and generated files are unchanged. The deterministic verification scripts still must be run; they will verify the copied manifests and the new selected profile pin.

- [ ] **Step 5: Run profile and generation tests**

```bash
xcrun swift test --filter 'SwanInteropTests|SwanPublicWireTests'
PETREL_GENERATOR_ROOT=/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel-swan-generator \
  ./Scripts/verify-public-wire-generation.sh
PETREL_GENERATOR_ROOT=/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel-swan-generator \
  ./Scripts/test-public-wire-generation.sh
```

Expected: 2026-08-06 is the only selected profile, 2026-08-05 remains byte-exact but reports `.unsupportedProfileID` when verified as a selected profile, and both scripts pass without mutating generated sources.

- [ ] **Step 6: Commit the profile-pin deliverable**

```bash
jj commit Profiles Scripts/public-wire-generation-common.sh \
  Sources/SwanPublicWire/SwanPublicWire.swift \
  Sources/SwanInterop/SwanInterop.swift \
  Tests/SwanInteropTests/PublicProtocolProfileVerifierTests.swift \
  Tests/SwanPublicWireTests/SwanPublicWireTests.swift \
  -m "firehose: pin active retained-cursor profile"
```

**Acceptance:** the profile verifier describes the actual activated behavior, every prior profile remains immutable, and the wire generator remains pinned and unchanged.

---

### Task 7: Integrate, Record, and Pass the Exit Gate

**Files:**
- Modify: `Tests/SwanHTTPTests/PublicFirehoseServiceWiringTests.swift`
- Create: `docs/superpowers/plans/2026-08-05-swan-firehose-phase3-completion-record.md`

**Interfaces:**
- Consumes: all Phase 3 interfaces from Tasks 1–6 and the existing Phase 2 service wiring test.
- Produces: one end-to-end retention-service proof, a completion record, and a green full-suite verification record.

- [ ] **Step 1: Add the end-to-end production composition test**

Extend the existing live wiring fixture so it constructs the same objects as `SwanCommand.Serve`: one `SQLiteFirehoseDatabase`, one `PublicFirehoseWakeupHub`, one `SwanPublicFirehoseSequencerService`, one `SwanPublicFirehoseRetentionService`, and one `SwanPublicFirehoseStreamingRuntime`. Start the retention service in a task, seed an old event and a newer event, wait for `retainedFromSeq()`, then connect with an old cursor and assert `#info` plus the newer stored frame. Cancel both services before closing the database.

The test must assert the identity of the shared hub:

```swift
let subscriberCount = await hub.subscriberCount()
XCTAssertEqual(subscriberCount, 1)
let maxSeq = try await firehose.maxSequencedSeq()
await hub.firehoseRetentionDidAdvance(maxSeq: maxSeq)
```

It must also assert the retained database bytes directly, as the Phase 2 tests do:

```swift
let stored = try await firehose.events(after: 0, limit: 10)
XCTAssertEqual(Data(buffer: receivedFrame.data), stored.last?.frameBytes)
```

- [ ] **Step 2: Run the complete focused Phase 3 suite**

```bash
xcrun swift test --filter 'SQLiteFirehoseDatabaseTests|PublicFirehoseSequencerTests|PublicFirehoseStreamingTests|PublicFirehoseStreamingHTTPTests|PublicFirehoseServiceWiringTests|SwanHTTPTests|SwanInteropTests|SwanPublicWireTests'
```

Expected: every focused suite passes with zero `error: -` diagnostics. If a test waits on a WebSocket, bound it with the existing deadline helper so a failed shutdown cannot hang the test process.

- [ ] **Step 3: Run the full exit gate**

Run each command from the worktree root and preserve the output in a temporary log:

```bash
xcrun swift build
PETREL_GENERATOR_ROOT=/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel-swan-generator \
  ./Scripts/verify-public-wire-generation.sh
PETREL_GENERATOR_ROOT=/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel-swan-generator \
  ./Scripts/test-public-wire-generation.sh
xcrun swift test
```

The full suite must exit 0 and report zero failures. A stale or environmental test process is not evidence of a passing gate; rerun the isolated failing filter and then the full suite until the recorded run itself exits 0.

- [ ] **Step 4: Write the Phase 3 completion record**

Create `docs/superpowers/plans/2026-08-05-swan-firehose-phase3-completion-record.md` with these exact sections:

```markdown
# Swan Firehose Phase 3 Completion Record

## Delivered

- 30-second WebSocket auto-ping and ServiceGroup graceful close verification.
- Transactional age, row, and byte pruning with a monotonic retained cursor.
- Retention worker and operator-configurable budgets, default-off with the public firehose flag.
- Active OutdatedCursor info-frame recovery and retained-window cursor=0 behavior.
- Atomic deleted-account event plus same-DID historical-row pruning with sequence gaps permitted.
- Successor public profile pin with the dormant-divergence entry removed.

## Verification

Record the exact command lines and the observed `swift build`, focused-filter, generation-script, and full-suite results.

## Explicitly Unimplemented

- Real lifecycle operation integration in `transitionStatus` and `installPublicPLCOperation` remains Phase 4.
- `requestCrawl` announcer remains Phase 4.
- Reference-relay Docker/interop acceptance remains Phase 5.
- The `--enable-public-firehose` default remains off pending the separate activation gate.
```

After the exit-gate commands finish, fill `Verification` with the actual process exit codes, XCTest counts, and generation-script result lines; do not claim a command passed unless its recorded process exited successfully.

- [ ] **Step 5: Inspect status, diff, and history before the final commit**

```bash
jj status
jj diff --stat
jj diff
jj log --limit 10 --no-graph
```

Confirm `.interop-cache/` is absent from the diff and only intended Phase 3 files are changed.

- [ ] **Step 6: Commit the completion record and integration test**

```bash
jj commit Tests/SwanHTTPTests/PublicFirehoseServiceWiringTests.swift \
  docs/superpowers/plans/2026-08-05-swan-firehose-phase3-completion-record.md \
  -m "firehose: record phase 3 completion"
```

**Acceptance:** the production composition has one shared database/hub/sequencer/retention runtime, all focused and full verification commands pass, the completion record is factual, and no Phase 4/5 behavior was silently pulled into Phase 3.

---

## Self-Review

### Spec Coverage

- Design lines 302–305: Task 3 enables 30-second auto-ping and proves the existing ServiceLifecycle close hook.
- Design lines 306–309: Tasks 1, 2, and 4 implement hard age plus row/byte budgets, monotonic `retained_from_seq`, retention wakeups, and active `OutdatedCursor` handling.
- Design lines 310–312: Task 5 appends the deleted account event and deletes earlier same-DID rows inside the same global transaction, preserving gaps.
- Design lines 283–300: Task 4 preserves no-cursor/live, cursor-zero/full-window, strictly-after, future-cursor, and outdated-cursor semantics.
- Profile regime: Task 6 makes the behavior pin truthful without mutating the 2026-08-05 artifact.
- Phase 4 and Phase 5 exclusions: Task 7 records lifecycle integration, `requestCrawl`, and relay acceptance as remaining work.

### Placeholder and Type Checks

- Every task names concrete files, signatures, SQL statements, tests, commands, and commit paths.
- Later tasks use the exact earlier interfaces `PublicFirehoseRetentionPolicy`, `PublicFirehosePruneResult`, `SQLiteFirehoseDatabase.prune(now:policy:)`, `SwanPublicFirehoseRetentionService`, `firehoseRetentionDidAdvance(maxSeq:)`, `outdatedCursor(retainedFromSeq:)`, and `FirehoseDeletionMarker`.
- No generated wire source is modified by hand, no historical profile is overwritten, and no task relies on an unspecified clock abstraction; database tests inject `Date` through existing `appendBatch(now:)` and `prune(now:)` arguments.
