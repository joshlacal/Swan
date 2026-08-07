# Swan public firehose Phase 4 — design addendum

Date: 2026-08-07
Status: approved by Josh (section-by-section) in brainstorming session
Parent design: `docs/superpowers/specs/2026-08-04-swan-public-firehose-design.md`
(authoritative for everything not restated here)
Baseline: integrated Phase 3 head `20bae590`
Workspace: `.worktrees/swan-public-federation` (jj workspace `swan-public-federation`)

## Scope ruling

Phase 4 is exactly the parent design's Phase 4: real lifecycle integrations
(activation, rotation, status changes, permanent deletion), the `requestCrawl`
announcer, and the operator CLI force-`#sync` — plus the Phase 4 entry gate
recorded in the Phase 3 completion record
(`docs/superpowers/plans/2026-08-05-swan-firehose-phase3-completion-record.md`,
"Phase 4 Entry Gates").

Done bar (ruled): proven entirely at the Swift test level — no Docker. The
first end-to-end proof against a real relay is Phase 5. The
`--enable-public-firehose` flag stays default-off through Phase 4.

Task structure (ruled): gate-first, one saga per task. Ordering:

1. Deletion-gap-aware lag fix (entry gate) + regression tests
2. Activation emission saga
3. Rotation emission saga
4. Status-change emission saga
5. Permanent-deletion emission saga + wiring `deletingPriorEvents`
6. `requestCrawl` announcer
7. Operator CLI force-`#sync`

Task 5 is gated on Task 1 by construction: deletion markers must never reach a
live lifecycle path while the lag computation is gap-blind.

## 1. Deletion-gap-aware lag (entry gate)

`PublicFirehoseTailer.run` currently computes `seqLag = maxSeq - cursor`
against `maximumSequenceLag` (default 50,000). A per-DID deletion gap wider
than the limit would drop every connected reader with a false
`ConsumerTooSlow`. Replace with a two-step check:

1. **Cheap upper bound:** if `maxSeq - cursor <= maximumSequenceLag`, skip —
   the raw difference is an upper bound on deliverable rows (gaps only shrink
   the real count), so the hot loop is unchanged for healthy consumers.
2. **Bounded deliverable count, only when the raw number exceeds the limit:**
   `SELECT COUNT(*) FROM (SELECT 1 FROM firehose_events WHERE seq > :cursor
   LIMIT :maxLag + 1)`. Drop the consumer only if the count of actually stored
   rows exceeds the limit. `seq` is the INTEGER PRIMARY KEY, so this is an
   index range count capped at `maxLag + 1` rows, and it runs only when a drop
   is already plausible.

Byte-lag and maximum-catch-up-time bounds are unchanged. `OutdatedCursor` /
`retained_from_seq` semantics are untouched.

Regression tests: (a) a synthetic deletion gap wider than
`maximumSequenceLag` between a live consumer's cursor and `maxSeq` must NOT
drop the consumer; (b) a consumer with more than the limit in real deliverable
rows must still be dropped; (c) mixed case — gap plus genuine backlog under
the limit — survives.

## 2. Lifecycle emission sagas

The batch model, per-DID generation counter, sequencer barriers, and frame
encoders all exist from Phase 1. Each task wires one confirmed operation to
`enqueueLifecycleEventBatch`, per the parent design's emission table. Source
keys and idempotence exactly as specified there (idempotent on the durable
lifecycle operation ID; saga pattern with recovery re-enqueue on crash between
operation completion and enqueue, or same-transaction enqueue where the
operation is a single control transaction).

- **Activation** (registration flow / `DurableAccountDirectory`): after DID
  resolution is confirmed, the account is durably active, and repo genesis
  exists → enqueue `[#identity, #account(active)]` and the barriered
  activation `#sync` (account outbox,
  `did|sync|activation|<lifecycleOperationID>`).
- **Rotation** (`PLCAccountRotationService`): after PLC submission is
  verified, coupled to signing-generation promotion → `[#identity]`
  (`did|identity|<plcOpCID>`). `installPublicPLCOperation` (history
  reinstall) continues to emit nothing.
- **Status changes** (`transitionStatus` callers, `AccountOperatorService`):
  `[#account(active, status?)]` (`did|account|<operationID>`) enqueued
  transactionally with the public status change; reactivation also enqueues a
  `#sync` (account outbox, `did|sync|reactivation|<lifecycleOperationID>`).
- **Permanent deletion** (`AccountPermanentDeletionCoordinator` /
  `beginDeletion`, at the point the account becomes publicly unavailable):
  `[#account(active: false, status: "deleted")]` (`did|account|<operationID>`)
  carrying `FirehoseDeletionMarker`, so the sequencer appends the event and prunes the
  DID's prior retained history in one global transaction (the Phase 3
  primitive, bounded to pre-batch history).

**Phase 1 assumptions the plan must verify in source, not assume** (both were
built in Phase 1 but have never run with a nonzero generation):

- Ordinary commit outbox rows snapshot the live per-DID lifecycle generation
  via the `withActiveAccountAuthorization` fence — not a hardcoded `0`. If
  hardcoded, wiring the snapshot is in-scope for the first saga task that
  needs it (activation).
- The pre-activation guard is active: commits for a not-yet-publicly-active
  account (genesis, restore, import) produce no outbox rows; the activation
  `#sync` announces the resulting head.

## 3. `requestCrawl` announcer

New ServiceLifecycle service in `SwanHTTP`, attached via
`makeServiceGroup` alongside the retention pruner.

- Config: `SWAN_PUBLIC_CRAWLERS` (comma-separated crawler origins; empty or
  unset = announcer disabled) plus Swan's existing canonical public hostname
  for the request body. Malformed origins are rejected at startup.
- Triggers: startup; update-triggered on sequenced events with a throttle
  (the plan fixes one default in the parent design's 10–20 minute range);
  periodic refresh (default 24 h).
- Persistent per-crawler retry state in `control.sqlite` (attempts,
  next-attempt time, last success); exponential backoff with jitter. State is
  one row per crawler — nothing accumulates per event.
- Plain HTTP `POST /xrpc/com.atproto.sync.requestCrawl`, never inside a
  database transaction. Announcer failure never affects sequencing or
  delivery.

Tests against a stub HTTP crawler: startup announce; update-trigger
throttling; backoff state surviving restart; malformed-origin startup
rejection; disabled when unconfigured.

## 4. Operator CLI force-`#sync`

One new `swan` subcommand following the existing subcommand pattern
(`Backup`/`Restore`): enqueue a forced `#sync` for a single DID via the
account outbox with source key `did|sync|manual|<requestUUID>`. Single-DID
only; no bulk mode until something needs it (YAGNI).

## 5. Error handling and testing

- Lifecycle enqueue is atomic with its owning operation, or crash-safe via
  idempotent re-enqueue on recovery — no window where an operation is
  confirmed but its event is silently lost.
- Deletion rides the existing atomic append+prune; sequence gaps are permitted
  and, after §1, harmless to connected readers.
- Test matrix: emission fixtures per confirmed operation (the Phase 1 barrier
  matrix now driven end-to-end by real operations); negative fixtures —
  `installPublicPLCOperation`, restore/reinstall, pre-activation commits, and
  permissioned writes emit nothing (adversarial isolation suite stays green);
  lag regression (§1); announcer suite (§3); CLI test (§4).
- Exit: full Swift suite green; flag default-off; existing wire-profile pins
  byte-identical.

## Out of scope (Phase 4)

- Reference-relay interop lab and acceptance proof (Phase 5).
- Live-network deployment. Recorded for roadmap clarity — after Phase 5,
  reaching live-network testing still requires: a public Linux x86_64
  deployment with real hostname + TLS; real `plc.directory` instead of the
  lab PLC; flipping the `--enable-public-firehose` activation gate on that
  deployment; and `SWAN_PUBLIC_CRAWLERS` pointed at `bsky.network`.
- `updateHandle`, repo import/migration, `listRepos`/`getBlocks`/
  `sync.getRecord`/`listBlobs` (unchanged from parent design's P0 exclusions).
