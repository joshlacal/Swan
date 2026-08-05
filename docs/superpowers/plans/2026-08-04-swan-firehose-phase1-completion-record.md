# Swan Firehose Phase 1 — completion record

Date: 2026-08-05
Workspace: `.worktrees/swan-public-federation`

Phase 1 of the reviewed implementation plan
(`docs/superpowers/plans/2026-08-04-swan-firehose-phase1-event-core.md`) is
implemented and committed. This record captures the durable facts a later
phase needs.

## Final migration versions

- Account DB (`SQLiteAccountDatabase`): public event outbox migration
  version **13** (`publicFirehoseOutboxMigrationVersion`), installed in the
  account migration transaction after version 12. Creates
  `public_event_outbox`.
- Control DB (`SQLiteControlDatabase`): lifecycle tables are appended to
  `SQLiteLayout.controlMigrations` (idempotent DDL, no ledger version):
  `account_lifecycle_generation`, `lifecycle_event_batches`,
  `lifecycle_event_items`, index `lifecycle_event_batches_pending`.
- Global log (`firehose.sqlite`): hardened schema owned by
  `SQLiteFirehoseDatabase` (`firehose_meta`, `firehose_events`).

## Final source-key formats

```text
<did>|commit|<cid>
<did>|sync|oversize|<cid>
<did>|sync|manual|<lowercase UUID>
<did>|sync|activation|<operation ID>
<did>|sync|reactivation|<operation ID>
<did>|account|<operation ID>
<did>|identity|<PLC operation CID>
<did>|lifecycle|<operation ID>
```

## Per-DID generation ordering rule

```text
lifecycle batch g  <  account events stamped g  <  lifecycle batch g + 1
```

The sequencer peeks the smallest account outbox head (generation `a`) and the
smallest pending lifecycle batch (generation `l`) per DID and chooses:
account when only the account head exists or `a < l`; lifecycle when only a
batch exists or `l <= a`. A blocked or leased account head stalls that DID's
later events and next lifecycle generation, but never another DID; the actor
rotates a round-robin cursor over the sorted DID union.

## Global sequence allocator semantics

- `firehose_meta.next_seq` is the next unused number, seeded at 1.
- One `BEGIN IMMEDIATE` transaction per append: existing-source lookup,
  checked Swift arithmetic (`last = start + count - 1`, `last <= 2^53 - 1`),
  frame encoding, `UPDATE ... WHERE next_seq = ?` (compare-and-set), row
  insertion — all commit or roll back together.
- `9_007_199_254_740_992` is valid only as the exhausted sentinel in
  `next_seq`; no event may receive it.
- Exact source-key replay re-encodes every item at its stored sequence and
  requires byte-exact equality of source key, batch ID, ordinal, DID, kind,
  and frame; mixed existing/new batches fail closed.
- `reseedSequence(toAtLeast:)` raises only and accepts the sentinel; the
  operator restore workflow must supply a safe high-water mark in a later
  phase.

## Source semantics

- Account outbox is strict FIFO by smallest `id`; the lease query never
  orders by `available_at`.
- Final commit-versus-sync kind is decided inside the repository transaction
  (`PublicFirehoseSourceDecisionMaker`, preflight at
  `FirehoseFrameLimits.maximumSequence`); the sequencer never reinterprets a
  persisted row. Oversize shapes degrade to `.sync` with a `syncOversize`
  key and commit-only CAR. Note: with the pinned engine limits
  (`maximumWrites = 200`, `maximumRelevantBlockBytes = 2_000_000`) the
  fallback is defensive-only in Phase 1; it is exercised by unit tests of the
  decision maker.
- Payload JSON uses sorted keys for byte-stable replay (plain `JSONEncoder`
  key order is not stable across calls).
- Crash safety is append-then-complete; the test crash hook fires after the
  global append commits and before source completion.

## Phase 1 implementation notes (deviations and decisions)

- `SQLiteFirehoseDatabase` uses its own connection gate (copy of the
  control-database pattern) rather than a shared one.
- The engine's pinned write/block budgets make oversize commit frames
  unreachable through `PublicRepositoryEngine`; the sync fallback is
  implemented and unit-tested but not integration-tested end-to-end.
- The serve-level "startup failure after firehose open does not leak
  descriptors" hostile path was not added; descriptor cleanup is covered by
  the close/reopen tests and the service wiring test's clean-exit assertion.
- A source-level dependency tripwire was not added: the repository has no
  existing architecture/dependency test pattern. The behavioral isolation
  test (`PublicFirehoseIsolationTests`) is the hard gate.
- The Petrel sibling checkout is reachable from the worktree via a symlink at
  `/Users/joshlacalamito/Developer/Catbird+Petrel/.worktrees/Petrel`
  (untracked, outside the jj repo).

## Test results

```text
swift build                                   : pass
swift test --filter PublicFirehose            : pass (all firehose tests)
swift test --filter SwanSQLiteTests           : pass
swift test --filter SwanHTTPTests             : pass
swift test                                    : pass (complete suite)
```

## Feature flag status

`--enable-public-firehose` in `serve` (Sources/swan/SwanCommand.swift)
remains **default-off**. The account-local outbox insertion is not
feature-gated: with the worker disabled, rows accumulate durably and drain
once the flag is enabled.

## Explicitly unimplemented (later phases)

WebSocket streaming and the `subscribeRepos` endpoint (Phase 2/3),
cursor/retention semantics and per-DID deletion pruning (Phase 3), real
lifecycle integrations — activation, rotation, status changes, deletion
(Phase 4), `requestCrawl` announcement, and indigo relay acceptance proof
(Phase 5). Phase 1 stamps ordinary public commits with lifecycle
generation 0.
