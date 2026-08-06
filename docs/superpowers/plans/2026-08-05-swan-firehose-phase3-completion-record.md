# Swan Firehose Phase 3 Completion Record

## Delivered

- 30-second WebSocket auto-ping and `ServiceGroup` graceful-close
  verification (Task 3), proved with a `RawTestClient` test helper — a
  reviewed deviation from the plan's literal `TestClient` snippet, which does
  not compile against the pinned Hummingbird version.
- Transactional age, row, and byte pruning with a monotonic retained cursor
  (`SQLiteFirehoseDatabase.prune(now:policy:)`, Task 1). The age pass and the
  row/byte budget loop each page through at most 1000 rows per `DELETE`
  inside the single prune transaction — a human-approved deviation from the
  plan's single-statement age delete, so a large first-ever prune (up to
  ~1M rows) never buffers the whole expired set in one statement.
- `SwanPublicFirehoseRetentionService` retention worker and four
  operator-configurable retention CLI options (age hours, max rows, max
  bytes, interval seconds), all validated and default-off with
  `--enable-public-firehose` (Task 2). `firehoseRetentionDidAdvance(maxSeq:)`
  wakes idle tailers on a prune that advances the retained boundary even when
  no new sequence was appended.
- Active `OutdatedCursor` info-frame recovery (both at connect time via
  `PublicFirehoseCursorPolicy.resolve` and mid-stream via
  `PublicFirehoseTailer`'s per-iteration `retainedFromSeq()` check) and
  retained-window `cursor=0` (`.fullWindow`) behavior (Task 4), including a
  restored slow-consumer drop warning log — a human-approved addition over
  the plan's snippet.
- Atomic deleted-account event plus same-DID historical-row pruning inside
  the same global append transaction (`FirehoseDeletionMarker`, Task 5),
  bounded to pre-batch history (`seq < batchStartSeq`) rather than the
  marker's own seq — a human-approved deviation — with sequence gaps
  permitted in the retained log.
- Successor public profile `public-data-testing-2026-08-06` pinned at SHA-256
  `b96ac7c7fa3df3a0bb5b396c25f776734493d7b0a09a71e1e082e24813b64124`, with
  manifests byte-identical to `public-data-testing-2026-08-05`, and the
  dormant-divergence entry removed (Task 6). By human ruling the plan's
  `PublicDataTesting20260806` enum case was **not** added — adding it would
  regenerate `SwanPublicWire.swift` and break the pinned hashes above;
  `testPublicDataTesting20260806IncludesSubscribeReposSubscription` stands in
  as the substitute coverage that the successor profile still carries the
  subscription method.
- (Task 7) An end-to-end production-composition test
  (`PublicFirehoseServiceWiringTests.testProductionCompositionRunsSequencerRetentionAndStreamingOverSharedHubAndDatabase`)
  constructing the same five objects `SwanCommand.Serve` builds — one
  `SQLiteFirehoseDatabase`, one `PublicFirehoseWakeupHub`, one
  `SwanPublicFirehoseSequencerService`, one
  `SwanPublicFirehoseRetentionService`, and one
  `SwanPublicFirehoseStreamingRuntime` — running the sequencer and retention
  services concurrently against one live `subscribeRepos` route, proving
  shared-hub identity, a real retention-service-driven prune advancing
  `retainedFromSeq()`, the `OutdatedCursor` info frame, and byte-exact
  delivery of the retained stored frame.

## Verification

All commands were run from the worktree root
(`.worktrees/swan-public-federation`) in the foreground, unfiltered where
specified, and the recorded exit codes and counts below are from those
literal runs (not a prior or cached process).

```text
$ xcrun swift build
Build complete! (3.63 sec)
exit code: 0
```

```text
$ PETREL_GENERATOR_ROOT=/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel-swan-generator \
    ./Scripts/verify-public-wire-generation.sh
...
pinned Swan public wire generation verified without worktree mutation
exit code: 0
```

```text
$ PETREL_GENERATOR_ROOT=/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel-swan-generator \
    ./Scripts/test-public-wire-generation.sh
...
public wire generation rejection and deterministic verification passed
exit code: 0
```

Focused Phase 3 filter (Step 2 of this task's brief), run before the full
suite:

```text
$ xcrun swift test --filter 'SQLiteFirehoseDatabaseTests|PublicFirehoseSequencerTests|PublicFirehoseStreamingTests|PublicFirehoseStreamingHTTPTests|PublicFirehoseServiceWiringTests|SwanHTTPTests|SwanInteropTests|SwanPublicWireTests'
```
Every named suite passed with zero `error: -` diagnostics:
`PublicFirehoseSequencerTests`, `SQLiteFirehoseDatabaseTests`,
`SwanInteropTests`, `PublicFirehoseServiceWiringTests` (4 tests, including
the new Task 7 composition test), `PublicFirehoseStreamingHTTPTests`,
`PublicFirehoseStreamingTests`, `SwanHTTPTests.xctest` (231 tests total as of
the final-review fix wave below, 0 failures), `SwanPublicWireTests`
(swift-testing, 6 tests, 0 failures).

Full exit gate:

```text
$ xcrun swift test
exit code: 0
```

Exact XCTest per-bundle totals parsed from the recorded run (`Executed N
tests, with S skipped and F failures`):

| Bundle                          | Tests | Skipped | Failures |
|----------------------------------|------:|--------:|---------:|
| SwanSpacesTests.xctest           |    39 |       1 |        0 |
| SwanSQLiteTests.xctest           |   338 |       6 |        0 |
| SwanPublicRepositoryTests.xctest |   111 |       0 |        0 |
| SwanPublicFirehoseTests.xctest   |    38 |       0 |        0 |
| SwanOAuthTests.xctest            |   109 |       0 |        0 |
| SwanInteropTests.xctest          |   116 |       0 |        0 |
| SwanHTTPTests.xctest             |   231 |       0 |        0 |
| SwanCoreTests.xctest             |     5 |       0 |        0 |
| SwanCLITests.xctest              |    67 |       1 |        0 |
| SwanAccountsTests.xctest         |   118 |       0 |        0 |
| SwanAccountExportTests.xctest    |    56 |       1 |        0 |
| **XCTest subtotal**              | **1228** | **9** | **0** |

Plus one Swift Testing suite (`Swan public wire profile`,
`Tests/SwanPublicWireTests`): 6 tests, 0 failures.

**Grand total: 1234 tests executed, 9 skipped, 0 failures, 0 unexpected
failures, process exit code 0.** The 9 skips are all pre-existing opt-in
gates unrelated to Phase 3 (e.g. `SWAN_RUN_256MIB_PORTABLE_RESTORE`-style
manual/resource-gated tests), not new skips introduced by this phase.

**Updated by the final-review fix wave** (see
`.superpowers/sdd/2026-08-05-swan-firehose-phase3-liveness-retention/task-7-report.md`
for the itemized findings and fixes): the totals above supersede the
original Task 7 run (1231 tests / 9 skipped / 0 failures). The delta is
exactly the 3 regression tests the fix wave added — 2 in
`SQLiteFirehoseDatabaseTests` (`SwanSQLiteTests.xctest` 336 → 338) and 1 in
`PublicFirehoseStreamingTests` (`SwanHTTPTests.xctest` 230 → 231) — proving
the budget-loop paging fix and the whole-log-prune boundary fix; no test was
removed or newly skipped, and failures remained 0 throughout. Reproduced
identically across two independent full unfiltered runs (both exit code 0,
byte-identical per-bundle totals).

## Explicitly Unimplemented

- Real lifecycle operation integration in `transitionStatus` and
  `installPublicPLCOperation` remains Phase 4.
- `requestCrawl` announcer remains Phase 4.
- Reference-relay Docker/interop acceptance remains Phase 5.
- The `--enable-public-firehose` default remains off pending the separate
  activation gate.

## Phase 4 Entry Gates

Conditions the final whole-branch review ruled must be satisfied *before*
Phase 4 work proceeds, even though nothing in Phase 3 needs to change to
satisfy them today.

- **Deletion-gap-aware lag computation, required before `transitionStatus`
  wires deletion markers.** `PublicFirehoseTailer.run`'s slow-consumer check
  computes `seqLag = maxSeq - cursor` against `maxSequencedSeq()`
  (`Sources/SwanHTTP/PublicFirehoseStreaming.swift:201-202`), i.e. the
  highest sequence ever issued. Per-DID deletion (`FirehoseDeletionMarker`,
  Task 5) can remove an account's entire historical run of sequences while
  leaving the high-water mark untouched, so a deleted account with more than
  `maximumSequenceLag` (default 50,000) events between its earliest and
  latest sequence would make `seqLag` cross the slow-consumer threshold for
  every connected reader, dropping them all with `ConsumerTooSlow` — a false
  positive caused entirely by a sequence-space hole, not by any consumer
  actually falling behind. This is unreachable in Phase 3: nothing calls
  `deletingPriorEvents` outside test fixtures, since `transitionStatus` and
  `installPublicPLCOperation` (the only real triggers for account deletion)
  are themselves Phase 4 work. **Phase 4 must not wire deletion markers into
  a live lifecycle path until `seqLag` is made deletion-gap-aware** — e.g. by
  computing lag from the count of actually-deliverable rows between `cursor`
  and `maxSeq` (a bounded `COUNT(*)` or similar) rather than the raw
  sequence-number difference, or by clamping the lag calculation to the
  first stored sequence strictly above `cursor` so a deletion gap is never
  counted against the consumer. No code changed for this in the fix wave;
  this is a documented pre-condition on the next phase's design, per human
  ruling during the final branch review.
