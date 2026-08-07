# Swan Firehose Phase 4 Completion Record

## Delivered

- **Entry gate fix (Task 1):** deletion-gap-aware slow-consumer lag.
  `SQLiteFirehoseDatabase.deliverableEventCount(after:limit:)` added, and
  `PublicFirehoseTailer.run`'s `seqLag` computation (`PublicFirehoseStreaming.swift`)
  became a two-step check: the raw `maxSeq - cursor` difference is treated as an
  upper bound on deliverable rows, and only when it exceeds
  `maximumSequenceLag` does the tailer run the bounded deliverable-count query
  (`limit: maximumSequenceLag + 1`). A per-DID deletion gap wider than the lag
  limit no longer drops a consumer with almost nothing left to read, while a
  real backlog deeper than the limit is still clamped to
  `maximumSequenceLag + 1` and still drops.
- **Commit generation snapshot and pre-activation gating (Task 2):** commit
  outbox rows are no longer hardcoded to `lifecycleGeneration: 0`; production
  serve-path mutations run under `PublicFirehoseCommitFence`, which holds the
  control-plane authorization transaction and snapshots the DID's live
  lifecycle generation (`withActiveAccountFirehoseAuthorization`), stamping the
  enqueued row with it. Pre-activation and post-deactivation commits emit
  nothing (fence throws `invalidTransition` → falls back to a non-emitting
  mutation); `nil` contexts skip the firehose material build and enqueue
  entirely. No `lifecycleGeneration: 0` literal remains in
  `PublicRepositoryStore.swift`.
- **Lifecycle emitter and activation emission (Task 3):** the cross-module
  `PublicLifecycleEventEmitting` protocol (SwanStorage) and its
  `SQLitePublicLifecycleEmitter` implementation (SwanSQLite). `activate` emits
  the `[#identity, #account(active)]` batch followed by the barriered `#sync`
  (commit-only CAR of the public head, stamped with the batch generation),
  with exact-retry idempotence via source-key dedupe. The emitter is built
  unconditionally in `Serve.run()` ("unconditional enqueue, gated drain").
- **Rotation emission (Task 4):** `PLCAccountRotationService.promote` emits
  `#identity` keyed on the confirmed operation CID before the signing
  generation promotion, so a crash between emit and promotion re-emits
  idempotently on recovery rather than losing the promoted generation's event.
- **Status-change emission (Task 5):** operator `deactivate`/`reactivate` emit
  `#account` batches (one item per status change, mapped to public material)
  atomically inside the same control transaction as the status write, via the
  new `transitionStatus(…emitting:…)` requirement; reactivation additionally
  enqueues the barriered `#sync`. Bare `transitionStatus` calls emit nothing.
- **Permanent-deletion emission (Task 6):** `beginDeletion` enqueues the
  `deleted` `#account` batch inside the same control transaction as the scrub,
  using Task 5's in-transaction enqueue; the sequencer's existing marker
  derivation and the firehose DB's atomic append+prune complete the path.
  Legacy-migrated `deleted` rows announce the same way.
- **requestCrawl announcer (Task 7):** `SwanPublicFirehoseCrawlAnnouncerService`
  with per-crawler persistent backoff in `control.sqlite`
  (`public_crawl_announcer_state`), `SWAN_PUBLIC_CRAWLERS` wiring, startup
  announces, 15-minute update-throttled announces, 24-hour periodic refresh,
  and exponential backoff (`min(3600, 30 × 2^min(attempts,7))` s, ±20 % jitter)
  that survives service restarts. A review-fix round (commit `afea124e`)
  restructured the eligibility rule to the brief's exact three-rule listing
  (the original gated every state behind `now >= nextAttemptAt`, making the
  throttled-update branch unreachable within 24 h of a success), wrapped the
  poll sleep so `CancellationError` exits cleanly instead of surfacing
  `.serviceThrew`, and moved the outcome upsert inside
  `withConnectionGate { transaction { … } }`.
- **Operator force-`#sync` CLI (Task 8):** `swan firehose force-sync
  --data-directory <dir> --did <did>` enqueues a manual `#sync` offline for an
  active DID (via `SingleAccountFirehoseSource` + `emitManualSync`), refusing
  non-active accounts and collapsing all failures to one
  `ValidationError("firehose force-sync failed")`.

## Verification

All commands were run from the worktree root
(`.worktrees/swan-public-federation`) in the foreground, one at a time, and
the recorded exit codes and counts below are from those literal runs.

```text
$ xcrun swift test
exit code: 0
```

Exact XCTest per-bundle totals parsed from the recorded run (`Executed N
tests, with S skipped and F failures`), full unfiltered suite:

| Bundle                          | Tests | Skipped | Failures |
|----------------------------------|------:|--------:|---------:|
| SwanSpacesTests.xctest           |    39 |       1 |        0 |
| SwanSQLiteTests.xctest           |   358 |       6 |        0 |
| SwanPublicRepositoryTests.xctest |   111 |       0 |        0 |
| SwanPublicFirehoseTests.xctest   |    38 |       0 |        0 |
| SwanOAuthTests.xctest            |   109 |       0 |        0 |
| SwanInteropTests.xctest          |   129 |       0 |        0 |
| SwanHTTPTests.xctest             |   238 |       0 |        0 |
| SwanCoreTests.xctest             |     5 |       0 |        0 |
| SwanCLITests.xctest              |    77 |       1 |        0 |
| SwanAccountsTests.xctest         |   120 |       0 |        0 |
| SwanAccountExportTests.xctest    |    56 |       1 |        0 |
| **XCTest subtotal**              | **1280** | **9** | **0** |

Plus one Swift Testing suite (`Swan public wire profile`,
`Tests/SwanPublicWireTests`): 6 tests, 0 failures.

**Grand total: 1286 tests executed, 9 skipped, 0 failures, 0 unexpected
failures, process exit code 0.** The 9 skips are all pre-existing opt-in
gates unrelated to Phase 4 (manual/resource-gated tests). The phase grew the
XCTest total by 52 over Phase 3's final 1228 (e.g. `SwanHTTPTests` 231 → 238,
`SwanSQLiteTests` 338 → 358, `SwanAccountsTests` 118 → 120, `SwanCLITests`
67 → 77, `SwanInteropTests` 116 → 129); the only log noise is the
pre-existing `'petrel': failed to retrieve search paths with pkg-config`
warning plus expected test-side warning logs (e.g. the announcer failure
backoff test logs its `requestCrawl announce failed` warning by design).

### Profile immutability (Step 2)

```text
$ shasum -a 256 Profiles/public-data-testing-2026-08-06.json
b96ac7c7fa3df3a0bb5b396c25f776734493d7b0a09a71e1e082e24813b64124  Profiles/public-data-testing-2026-08-06.json
```

Byte-identical to the hash pinned by the Phase 3 completion record (and to the
successor profile's manifest hash recorded at its creation). The companion
`.generated-wire.sha256` records every generated wire source file; all 24
entries verify:

```text
$ shasum -a 256 -c Profiles/public-data-testing-2026-08-06.generated-wire.sha256
… Sources/SwanPublicWire/SwanPublicWire.swift: OK
exit code: 0
```

And the whole-branch diff over the three protected paths is empty:

```text
$ jj diff --from a9bbd311 --to @ --stat -- 'Profiles/' 'Scripts/' 'Sources/SwanPublicWire/'
0 files changed, 0 insertions(+), 0 deletions(-)
```

No profile, generation script, or generated wire source changed anywhere on
the Phase 4 branch (Task 0 plan commit `a9bbd311` → head `@`). The
`.lexicons.sha256` companion also exists; like every other profile pair it
uses paths relative to the generator repo (`Petrel-swan-generator/atproto/…`)
and is not verifiable from the worktree — consistent with prior phases.

## Deviations with Rulings

- **Task 1 — gap-survival test idiom.** The plan's test sketch was rewritten
  into the file's own `Task` + `waitUntil` + `cancel` idiom because
  `PublicFirehoseTailer.run` only exits on cancellation or a thrown error; the
  test asserts the lone surviving frame arrives via the `FrameRecorder` actor
  instead of expecting `run` to return. Ruling: accepted — the brief's
  placeholder shapes don't match the real tailer's exit contract.
- **Task 1 — still-drops expectation clamped.** `testTailerStillDropsConsumerWithRealDeliverableBacklog`
  asserts `seqLag == 3` for a limit of 2, per the plan's own Step 7 note: the
  bounded count stops at `maximumSequenceLag + 1`, so a backlog deeper than
  the bound reports the clamped count. Ruling: accepted — prescribed by the
  plan (the Step 7 note explicitly says a backlog deeper than the bound
  "reports the clamped count").
- **Task 2 — protocol-witness overload.** The plan's `applyPublicRepositoryMutation`
  gains `firehose: PublicFirehoseCommitContext? = nil`, but a defaulted-argument
  method does not witness the 2-argument `PublicRepositoryMutationStore`
  protocol requirement (verified with scratch `swiftc` compiles), so the
  concrete type keeps a 2-argument overload that delegates with `firehose: nil`.
  Ruling: accepted — the overload preserves protocol conformance and
  unambiguously forwards the no-context case.
- **Task 2 — `--filter` substitution.** The plan's Step 4 filter
  (`--filter PublicRepositoryStore`) matches no test class name in this
  package (verified against all suite names); the two suites actually covering
  `applyPublicRepositoryMutation` (`PublicFirehoseCommitEnqueueTests`,
  `PublicRepositoryMutationStoreTests`) were run instead, plus the fence suite
  (`AccountAuthorizationLeaseTests`). Ruling: accepted — the plan's command
  name was stale; same coverage intent.
- **Task 5 — full call-site audit outcome.** Every production
  `transitionStatus` caller is emission-aware or a definition; none was left on
  the nil-emitting overload. The five mappable public statuses emit correct
  material; `unknown` and policy-unreachable `deleting`/`deleted` emit nothing.
  CLI composition roots (`swan account deactivate`/`reactivate`/`declare-export`,
  export/delete) deliberately construct `AccountOperatorService` without an
  emitter — they have no `PublicFirehoseAccountDatabaseSource`, so CLI status
  changes do not announce. Ruling: accepted — matches the plan's emission-
  ownership constraint and the Task 3 precedent.
- **Task 7 — review-fix round.** The initial announcer commit was followed by
  a fix commit (`afea124e`) for three review findings: (1) eligibility
  restructured — the original guard made the throttled-update branch
  unreachable for 24 h after a success; the new rule matches the brief's
  exact three-rule listing; (2) the poll `Task.sleep` is now wrapped so a
  `CancellationError` returns cleanly (the retention service's pattern)
  instead of surfacing `.serviceThrew` on SIGTERM; (3) the outcome upsert runs
  inside `withConnectionGate { transaction { … } }` per the "for writes,
  transaction" constraint. Ruling: accepted — all three findings were correct;
  tests were strengthened/pinned for each.
- **Task 8 — control open inside the error boundary.** The plan's literal
  snippet opened `SQLiteControlDatabase` *outside* the outer `do`/`catch`,
  which would let the `/nonexistent` smoke-test failure escape as a raw
  Foundation error instead of the collapsed `ValidationError` message that the
  plan's own Step 2 smoke test expects. The control open was moved inside the
  error boundary (the `Backup` shape the plan says to model on), so every
  failure collapses to `firehose force-sync failed`. Ruling: accepted — makes
  the plan's own acceptance smoke test pass.

## Explicitly Unimplemented

- Reference-relay Docker/interop acceptance remains Phase 5.
- Live deployment prerequisites remain open: `--enable-public-firehose` stays
  default-off pending the separate activation gate; sequencing, WebSocket
  serving, and the announcer remain gated by the flag (lifecycle batches and
  outbox rows accumulate durably regardless, per the "unconditional enqueue,
  gated drain" constraint).

## Phase 4 Entry Gate: SATISFIED by Task 1

The Phase 3 completion record's entry gate required that **Phase 4 must not
wire deletion markers into a live lifecycle path until `seqLag` is made
deletion-gap-aware** — i.e. no `transitionStatus`/`beginDeletion`-driven
deletion may coexist with a raw `maxSeq - cursor` slow-consumer lag that
counts sequence-space holes against the consumer.

Task 1 (commit `6ff79183`) satisfied this before any live deletion emission
was wired (the gate's ordering constraint — Task 1 before Task 6 — was
honored). `PublicFirehoseStreaming.swift` now implements the two-step
gap-aware check:

```swift
let maxSeq = try await database.maxSequencedSeq()
// Raw difference is an upper bound on deliverable rows (deletion
// gaps only shrink the real count), so the bounded count runs only
// when a drop is already plausible.
var seqLag = maxSeq - cursor
if seqLag > limits.maximumSequenceLag {
  seqLag = try await database.deliverableEventCount(
    after: cursor,
    limit: limits.maximumSequenceLag + 1
  )
}
```

The raw `maxSeq - cursor` difference is only an upper bound; when it crosses
`maximumSequenceLag`, the tailer asks the database for the bounded count of
actually-deliverable rows above the cursor (`deliverableEventCount(after:limit:)`,
a `COUNT(*)` over `firehose_events WHERE seq > ? LIMIT ?`). A per-DID deletion
gap wider than the lag limit therefore no longer drops a consumer with almost
nothing left to read, while a real deliverable backlog deeper than the bound
is clamped to `maximumSequenceLag + 1` and still drops — pinned by
`testTailerSurvivesDeletionGapWiderThanSequenceLagLimit` and
`testTailerStillDropsConsumerWithRealDeliverableBacklog`.

**Ruling: entry gate SATISFIED** — deletion emission (Tasks 5-6) was allowed
to proceed only after this commit existed, and the gap-survival test proves
the end-to-end behavior the gate demanded.
