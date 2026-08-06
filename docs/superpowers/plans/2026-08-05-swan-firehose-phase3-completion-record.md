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
`PublicFirehoseStreamingTests`, `SwanHTTPTests.xctest` (230 tests total, 0
failures), `SwanPublicWireTests` (swift-testing, 6 tests, 0 failures).

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
| SwanSQLiteTests.xctest           |   336 |       6 |        0 |
| SwanPublicRepositoryTests.xctest |   111 |       0 |        0 |
| SwanPublicFirehoseTests.xctest   |    38 |       0 |        0 |
| SwanOAuthTests.xctest            |   109 |       0 |        0 |
| SwanInteropTests.xctest          |   116 |       0 |        0 |
| SwanHTTPTests.xctest             |   230 |       0 |        0 |
| SwanCoreTests.xctest             |     5 |       0 |        0 |
| SwanCLITests.xctest              |    67 |       1 |        0 |
| SwanAccountsTests.xctest         |   118 |       0 |        0 |
| SwanAccountExportTests.xctest    |    56 |       1 |        0 |
| **XCTest subtotal**              | **1225** | **9** | **0** |

Plus one Swift Testing suite (`Swan public wire profile`,
`Tests/SwanPublicWireTests`): 6 tests, 0 failures.

**Grand total: 1231 tests executed, 9 skipped, 0 failures, 0 unexpected
failures, process exit code 0.** The 9 skips are all pre-existing opt-in
gates unrelated to Phase 3 (e.g. `SWAN_RUN_256MIB_PORTABLE_RESTORE`-style
manual/resource-gated tests), not new skips introduced by this phase.

## Explicitly Unimplemented

- Real lifecycle operation integration in `transitionStatus` and
  `installPublicPLCOperation` remains Phase 4.
- `requestCrawl` announcer remains Phase 4.
- Reference-relay Docker/interop acceptance remains Phase 5.
- The `--enable-public-firehose` default remains off pending the separate
  activation gate.
