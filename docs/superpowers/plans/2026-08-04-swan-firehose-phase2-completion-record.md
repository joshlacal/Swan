# Swan Firehose Phase 2 — completion record

Date: 2026-08-05
Workspace: `.worktrees/swan-public-federation`

Phase 2 of the reviewed implementation plan
(`docs/superpowers/plans/2026-08-04-swan-firehose-phase2-streaming.md`) is
implemented and committed. This record captures the durable facts a later
phase needs.

## Resolved dependency versions

- `hummingbird-websocket` **2.7.0** (exact pin, Package.swift; imports
  `HummingbirdWebSocket` from SwanHTTP/SwanHTTPTests and
  `HummingbirdWSTesting` from SwanHTTPTests).
- `hummingbird` 2.25.1 (unchanged exact pin; satisfies the 2.24.0 minimum).
- Transitives newly pulled by resolution, recorded in `Package.resolved`
  (no additional exact pins — repo convention keeps direct pins only for
  directly imported products):
  - `swift-websocket` **1.6.1**
  - `swift-nio-extras` **1.34.3**
  - `swift-nio-ssl` 2.37.2 (unchanged exact pin).

## Final `PublicFirehoseStreamingLimits` values

Defaults from `PublicFirehoseStreamingLimits.init` (validated, throwing;
`PublicFirehoseStreamingLimits.standard` is the non-throwing production
default; all values must be positive, `pageSize ≤ 1_000`):

```text
pageSize              1_000            (== SQLiteFirehoseDatabase.maximumCursorLimit)
maximumSequenceLag    50_000
maximumBackfillCatchUp .seconds(120)
maximumWriteDuration   .seconds(30)
idlePollInterval       0.25 s
```

Enforcement lives in `PublicFirehoseTailer` (SwanHTTP), with the pure
`PublicFirehoseSlowConsumerPolicy.shouldDrop` gate; a dropped consumer
receives `FirehoseFrameEncoder.errorFrame("ConsumerTooSlow")` followed by
`outbound.close(.normalClosure, reason: "ConsumerTooSlow")`.

## Cursor semantics as implemented

`PublicFirehoseCursorPolicy.resolve(cursor:maxSequencedSeq:retainedFromSeq:)`
is the single decision point (pure, unit-tested); the ws route resolves it
once per connection after one `maxSequencedSeq()` and one `retainedFromSeq()`
read:

- No cursor → `.live`: tail starts at the current max sequence; pre-connect
  history never leaks.
- `cursor=0` → `.fullWindow`: starts at sequence 0, **no** `OutdatedCursor`
  frame, then live.
- Cursor within retention → `.backfill(from:)`: delivery is **strictly
  after** the cursor (`seq > cursor`, the P0 compatibility decision recorded
  in the design doc); backfill and live are the same code path, so the
  boundary has no gap and no duplicate.
- `cursor > maxSequencedSeq` → `.futureCursor`: `{"op":-1,"error":"FutureCursor"}`
  error frame, then close `.normalClosure`; detected after upgrade (it needs
  the async max-seq read and a live websocket to carry the error frame).
- Cursor below retention → `.outdatedCursor`: `#info` frame then stream from
  the oldest retained event. **Dormant in Phase 2**: `retainedFromSeq()` is
  always `nil` while Phase 3 pruning never runs, so the branch cannot trigger
  (exercised at the policy-unit level only).
- Malformed cursor (non-decimal, negative, `> 2^53 - 1`, fragments, query
  over 8 KiB, repeated keys) → `shouldUpgrade` returns `.dontUpgrade` and the
  upgrade is rejected (400 over an attempted upgrade; 405 for a plain GET).
  Strictness is a recorded deviation: the reference PDS parses cursors
  tolerantly.
- `retainedFromSeq()` accessor (SwanSQLite) reads
  `firehose_meta.retained_from_seq`; `nil` on a fresh database, never advanced
  in Phase 2.

## ConsumerTooSlow behavior

- Seq lag ceiling 50_000, backfill catch-up budget 120 s (accumulated
  wall-clock while backfilling), per-write duration bound 30 s (any single
  `outbound.write`).
- Drop = `{"op":-1,"error":"ConsumerTooSlow"}` error frame (no message) then
  close `.normalClosure` with reason `ConsumerTooSlow`. Close-code choice is
  not specified by the event-stream spec; the pinned-relay acceptance scenario
  (Phase 5) confirms the reference's preference.

## Generated `subscribeRepos` surface

- `PublicXRPCMethodKind` gained `.subscription`; `PublicDataTesting20260805`
  ships 19 methods, `subscribeRepos` with kind `.subscription`,
  `inputEncoding`/`outputEncoding` nil, declared errors
  `["FutureCursor", "ConsumerTooSlow"]`.
- The generated `ComAtprotoSyncSubscribeRepos.swift` descriptor is
  `kind: "subscription"` with the `Message` union (`commit`/`sync`/`identity`/
  `account`/`info`), `Parameters { cursor: Int? }`, the `Error` enum, and the
  client `subscribeRepos(cursor:)` extension.
- The generated **single-shot** `protocol ServerHandler { func handle(...) async
  throws -> Message }` for subscriptions is **unused dead code** (D3): it
  returns one `Message` and is structurally unusable for a firehose; the
  server implementation (tailer + verbatim `frame_bytes` shipping) never
  references it, and the tests' strict reader never touches it. No generator
  change and no generator pin repin (`c2a1cdbee8c621c7682416114700f032cc7e2b37`).

## Wakeup wiring

- `PublicFirehoseWakeupHub` (actor, `PublicFirehoseWakeupSink` conformance) is
  the only fan-out primitive in `Sources/`; `firehoseDidAppend(maxSeq:)` is
  coalesced (equal/lower bumps dropped) and fanned out to per-subscriber
  `AsyncStream` with `.bufferingNewest(1)`.
- `Sources/swan/SwanCommand.swift` (Task 5): `--enable-public-firehose` now
  constructs one hub, passes it as the sequencer's `wakeup:` (was `nil`),
  builds `SwanPublicFirehoseStreamingRuntime(database:firehoseDatabase,
  hub:wakeupHub, limits:.standard, logger:)`, and hands it to
  `SwanHTTPServer.init` via `makeServer(publicFirehoseStreaming:)`. With the
  flag off the runtime is `nil` and the endpoint keeps the legacy wildcard-404
  behavior (default-off preserved).
- Exit paths need no hub handling: the hub holds no resources, and its
  per-connection subscribers remove themselves when their streams finish; the
  existing `preopenedFirehoseDatabase.close()` paths are unchanged.

## Shutdown behavior

- Cancellation-driven teardown only: the `onUpgrade` handler's two child
  tasks (inbound drain + tailer loop) observe `Task.isCancelled` and exit
  promptly; `finishWakeup()` resumes a suspended `AsyncStream.next()` so the
  subscriber removes itself. No heartbeat/ping, no graceful-close frames in
  Phase 2 (Phase 3 liveness); a restart appears as an abnormal closure.

## Wire profile state

- **Successor:** `public-data-testing-2026-08-05` — 21 lexicons, 19 endpoints,
  24 generated files (21 lexicon files + 2 client files + the hand-maintained
  `SwanPublicWire.swift`, per `public-data-testing-2026-08-05.generated-wire.sha256`).
- **Frozen legacy:** the 2026-07-30 trio (byte-immutable), alongside the
  original 2026-07-27 trio; `public-wire-generation-common.sh` carries the
  frozen hashes.
- `intentionalDivergences` recorded in the profile JSON for
  `com.atproto.sync.subscribeRepos`: (1) strict malformed-cursor rejection vs
  the reference's tolerant parsing; (2) dormant `OutdatedCursor` delivery
  until Phase 3 pruning advances `retained_from_seq`.

## Phase 2 implementation notes (deviations and decisions)

- `SwanCommand.swift` edits follow the file's existing 4-space indentation
  (the Phase 2 global 2-space rule applied to the new SwanHTTP/SwanSQLite
  sources; a mixed indent inside the legacy serve method would have been
  inconsistent).
- The Task 5 wiring test lives in `SwanHTTPTests`
  (`PublicFirehoseServiceWiringTests`) rather than `SwanCLITests`: CLI tests
  drive the built binary as a subprocess, which cannot assert an in-process
  hub/websocket state; the wiring test builds a live server the way `serve`
  does (`makeServer` shape: profile + oauthRuntime + streaming runtime) and
  proves the full chain commit → account outbox → sequencer → hub wakeup →
  websocket, with the stored `frame_bytes` delivered verbatim.
- The plan's Task 5 non-goal list and D10/D7/D8 decision text were re-verified
  against the implemented code; the design doc
  (`2026-08-04-swan-public-firehose-design.md`) needed **no edits** — no
  implemented decision contradicts it.
- `Package.resolved` additions (`swift-websocket`, `swift-nio-extras`) are
  unpinned transitives; recorded here per D1 so a later repin can restore
  these exact versions.

## Test results (exit gate, run from the worktree root)

```text
swift build                                   : pass
swift test --filter PublicFirehoseStreamingTests    : pass (unit: cursor matrix, tailer, hub)
swift test --filter PublicFirehoseStreamingHTTPTests : pass (18 tests, wire matrix, .live)
swift test --filter PublicFirehose            : pass (Phase 1 suite still green)
swift test --filter SwanSQLiteTests           : pass
swift test --filter SwanHTTPTests             : pass (incl. the Task 5 wiring test
                                                  testSequencerWakeupHubStreamsRealCommitOverLiveSubscribeRepos)
swift test --filter SwanPublicWireTests       : pass (5 tests)
swift test                                    : pass (complete suite)
PETREL_GENERATOR_ROOT=... verify-public-wire-generation.sh : pass
PETREL_GENERATOR_ROOT=... test-public-wire-generation.sh   : pass
```

**Full-suite regression found and fixed during the exit gate (Task 1 follow-up).**
`testCheckedInPublicProfileIsValid` verified the frozen `2026-07-30` profile
against the live tree; `OfflineProtocolProfileVerifier.publicProfileID`
(Sources/SwanInterop/SwanInterop.swift:68) was never advanced past
`public-data-testing-2026-07-30` when Task 1 landed the 2026-08-05 successor,
so the verifier reported `generatedWireSourceChecksumMismatch` /
`generatedWireSourceSetMismatch` against the 2026-08-05 generated file set.
Reproduced byte-identically on the pre-Task-5 parent commit (Task 4) in a
throwaway workspace — the last known-green full-suite run before this phase
predates Task 1's profile commit, and the Task 1–4 gates only ran focused
filters. Fixed in this phase's final commit: `publicProfileID` advanced to
`public-data-testing-2026-08-05`, the four pin constants (profile / lexicon
manifest / generated-wire manifest hashes) and inventory counts (21/19)
updated, the `intentionalDivergences` pin extended to the three recorded
entries, the test pointed at the 2026-08-05 profile, and a new
`testFrozen20260730ProfileRemainsByteExactButIsNoLongerSelected` pins the
frozen 2026-07-30 trio (same pattern as the 2026-07-27 legacy test).

## Feature flag status

`--enable-public-firehose` in `serve` (Sources/swan/SwanCommand.swift)
remains **default-off**. Help text now documents that it also serves
`com.atproto.sync.subscribeRepos` WebSocket streaming on the public listener.

## Explicitly unimplemented (Phase 3+)

- WebSocket heartbeat / 30 s auto-ping (Phase 3 liveness).
- Graceful-shutdown close frames via the service-lifecycle hook (Phase 3);
  Phase 2 relies on cancellation + channel teardown.
- Retention pruning, `retained_from_seq` advance, per-DID deletion pruning —
  and therefore delivered `OutdatedCursor` behavior (decision path
  implemented and unit-tested; cannot trigger while retention is unbounded).
- Account-deletion handling (`deleted` `#account` event + same-transaction
  pruning) (Phase 3).
- `requestCrawl` announcer (Phase 4) and reference-relay acceptance proof
  (Phase 5) — the pinned relay will also re-verify the malformed-cursor
  strictness and the `.normalClosure` close-code choice.
