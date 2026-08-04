# Swan public firehose federation (P0) — design

Date: 2026-08-04 (revised same day after external design review)
Status: revised; pending user re-review
Workspace: `.worktrees/swan-public-federation` (jj workspace `swan-public-federation`, based on `bc3bec32`)

## Goal

Make Swan's existing public repository plane visible to the AT Protocol network:
a durable public event log with a global sequence, a spec-conformant
`com.atproto.sync.subscribeRepos` WebSocket endpoint, `#identity`/`#account`
lifecycle events, a `requestCrawl` announcer, and acceptance proof against a
locally self-hosted reference relay (indigo `cmd/relay`) inside the existing
docker-compose interop lab.

Success criterion: a record created on Swan arrives as a verified `#commit` on
the reference relay's outbound firehose, with cursor recovery and full-sync
recovery proven.

## What already exists (verified in source)

- `applyPublicRepositoryMutation` (`Sources/SwanSQLite/PublicRepositoryStore.swift`)
  is the single public-commit chokepoint: blocks, record projection, repository
  head, and the committed mutation request all change in one account-local
  transaction. Per-commit op lists, base/next rev, and base commit CID are
  already durably computed there.
- Transactional outbox + leased at-least-once delivery worker pattern:
  `permissioned_space_outbox` + `PermissionedSpaceOutboxDeliveryWorker`
  (`Sources/SwanSQLite/PermissionedOutboxDelivery.swift:117`). Transport I/O
  strictly between lease commit and completion commit; token-checked
  completion; exponential backoff.
- DAG-CBOR: Petrel `DAGCBOR` + `OrderedCBORMap`, tag-42 links, Swan's strict
  canonical parser (`CommitCBORParser`), `canonicalUnsignedVarint`.
- `PublicRepositoryCAR.write(rootCID:blocks:to:)` is a generic CAR writer with
  no completeness requirement — reusable for diff CARs. Note:
  `PublicRepositoryBlockMap.cids` is a `Set<CID>` (unordered), so diff-CAR
  block ordering must be fixed explicitly at build time.
- Lifecycle: `AccountControlStore.transitionStatus` covers ordinary status
  edges only — the policy forbids generic transitions to `deleting`/`deleted`;
  permanent deletion is the separate resumable `beginDeletion`/
  `finalizeDeletion` workflow (`AccountPermanentDeletionStore.swift`). Initial
  registration can create an already-active account without passing through
  `transitionStatus`.
- PLC: `installPublicPLCOperation` is implemented on `SQLiteAccountDatabase`
  (account-local `plc_identity_operations`), and rotation deliberately persists
  the pending PLC operation *before* network submission
  (`PLCAccountRotationService.swift`) — so history installation must NOT emit
  identity events.
- Commit-vs-lifecycle linearization fence: `withActiveAccountAuthorization`
  holds the control-plane transaction around a staged, network-free repo
  mutation — this gives account-outbox writes a consistent read of
  control-plane lifecycle state.
- Interop lab: docker-compose with `swan`, `reference-pds`, `reference-plc`,
  `caddy` (private CA TLS), `mailpit`, `toxiproxy`, `scenario-runner`.
  `interop/fetch-reference.sh` pins only `bluesky-social/atproto`; indigo needs
  its own pinned fetch.

Gaps: no global sequence; no WebSocket transport (`hummingbird-websocket` not
a dependency); `subscribeRepos` not in the frozen public wire profile; no
handle-change path.

## Architecture

```text
ACCOUNT DATABASE (per account)
  repository transaction (applyPublicRepositoryMutation)
    └─ public_event_outbox row: exact event material
       (source_key, kind, lifecycle_generation snapshot, ops,
        prev rev/data CID, commit CID, exact diff-CAR bytes, time)

CONTROL DATABASE (control.sqlite)
  confirmed lifecycle operation (saga)
    └─ lifecycle_event_outbox batch: ordered #identity/#account items
       (batch_id, batch_ordinal, did, source_key, generation)

GLOBAL SEQUENCER (single durable leader, actor)
  ├─ drains per-DID in source order, respecting lifecycle barriers
  ├─ allocates seq range from firehose_meta
  ├─ encodes complete frames (header + body, seq embedded)
  └─ appends whole batch in one firehose.sqlite transaction

FIREHOSE DATABASE (firehose.sqlite)
  firehose_meta, firehose_events (complete frame_bytes)

SUBSCRIBER (per WebSocket connection)
  ├─ tails firehose.sqlite from lastSent (seq > lastSent)
  ├─ in-process broadcasts are wakeups only, never the data path
  ├─ short periodic poll as recovery
  └─ closes with ConsumerTooSlow on bounded lag
```

New module `SwanPublicFirehose`: event model, frame encoding, sequencer logic.
Stores in `SwanSQLite`; WebSocket/XRPC adapter in `SwanHTTP`; workers attached
via `SwanHTTPServiceLifecycle.makeServiceGroup`. Domain modules never see HTTP
types.

### Account-local outbox: exact event material

Written inside the `applyPublicRepositoryMutation` transaction. Each row
stores everything needed to reproduce the exact event with no later lookups:

- `source_key TEXT UNIQUE` — purpose-specific (see below)
- `kind` (`commit` | `sync`)
- `lifecycle_generation` — snapshot of the account's control-plane lifecycle
  generation, read consistently via the `withActiveAccountAuthorization` fence
- prev commit CID, prev data root CID, base/next rev, op list, commit time
- **exact diff-CAR bytes** (commit block first root + new MST blocks + new
  record blocks, deterministic order fixed at build time; bounded ~2 MB)
- lease columns cloned from `permissioned_space_outbox`

Rows are deleted once their `source_key` is durably present in the global log.
Storing exact bytes (rather than a CID list resolved later) gives exact crash
replay, no dependency on future block-GC behavior, no nondeterministic block
ordering, and a simpler sequencer. `#commit.blobs` is deprecated per the sync
spec — producers send `[]`; no blob CIDs are collected or stored.

### Control-plane outbox: confirmed lifecycle batches

Lifecycle events are emitted by the **higher-level operation that knows the
externally visible transition has completed** — never by persistence helpers:

| Operation | Emission point | Batch contents |
| --- | --- | --- |
| Initial activation | after DID resolution confirmed, account durably active, repo genesis exists | `#identity`, `#account(active)`; saga also enqueues a barriered `#sync` (account outbox) announcing the current head |
| PLC/key rotation | after PLC submission verified, coupled to signing-generation promotion | `#identity` |
| Deactivation / reactivation / suspension etc. | in the control transaction changing public status (`transitionStatus` callers) | `#account`; reactivation also enqueues a `#sync` row (account outbox) |
| Permanent deletion | in `beginDeletion`, when the account becomes publicly unavailable | `#account(active:false, status:"deleted")` |
| Restore/import | only when the restored account is intentionally activated as current host | activation batch; never during identity-history reinstall |

Schema adds per batch: `batch_id`, `batch_ordinal`, `did`, `source_key`,
`generation`. Enqueue is idempotent on the durable lifecycle operation ID
(saga pattern: complete the operation → idempotently enqueue → recovery
re-enqueues on crash between the two). `installPublicPLCOperation` and
`transitionStatus` themselves emit nothing.

The optional `#identity` `handle` field is captured from the confirmed
lifecycle operation at enqueue time, or omitted — never read from the mutable
account record at sequencing time.

### Per-DID ordering barrier

`control.sqlite` keeps a per-DID `lifecycle_generation` counter, incremented by
every lifecycle batch enqueue. Account-outbox rows snapshot it at enqueue
(consistent via the existing fence). The sequencer never sequences an
account-outbox row until every lifecycle batch for that DID with
`generation <= snapshot` is in the global log. This makes the intended orders
structural: activation `#identity → #account → #sync(current head)`; rotation
`#identity(gen N) → first gen-N #commit`; reactivation `#account(active) →
#sync`.

Commit events are only enqueued while the account is publicly active (a
consistent read via the same fence). Pre-activation commits — genesis,
restore, import — emit nothing; the activation `#sync` announces the head that
resulted from them. This closes the gap where a genesis commit row would
snapshot a pre-activation generation and bypass the activation barrier.

### Global log

```sql
CREATE TABLE firehose_meta (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  next_seq INTEGER NOT NULL,
  retained_from_seq INTEGER
);

CREATE TABLE firehose_events (
  seq          INTEGER PRIMARY KEY,     -- allocated from firehose_meta, NOT AUTOINCREMENT
  source_key   TEXT NOT NULL UNIQUE,    -- idempotent crash replay
  batch_id     TEXT,
  did          TEXT NOT NULL,
  kind         TEXT NOT NULL,
  sequenced_at INTEGER NOT NULL,        -- local storage metadata; retention uses this, never payload time
  frame_bytes  BLOB NOT NULL            -- complete frame: header + body, seq embedded
);
```

Sequencer append, one transaction per batch:

1. `UPDATE firehose_meta SET next_seq = next_seq + n` returning the range.
2. Encode complete frame bytes with those seqs.
3. Insert all rows; commit. Consecutive seqs within a batch.

Invariant: `1 <= seq < 2^53` (hard guard). After catastrophic restore of an
old `firehose.sqlite`, reseed `next_seq` to a safe margin above any previously
published seq (documented recovery procedure; the event-stream spec forbids
sequence reuse after state loss).

Source keys are purpose-specific so the same repository head can legitimately
produce more than one event over time:

```text
did|commit|<commitCID>
did|sync|oversize|<commitCID>
did|sync|manual|<requestUUID>
did|sync|activation|<lifecycleOperationID>
did|sync|reactivation|<lifecycleOperationID>
did|account|<operationID>
did|identity|<plcOpCID>
```

### Live delivery: the log is the queue

In-process broadcasts from the sequencer are **wakeups only** — coalesced
notifications carrying no event data. Each WebSocket connection runs:

```text
loop:
  rows = SELECT ... WHERE seq > lastSent ORDER BY seq LIMIT page
  if rows: send in order; advance lastSent
  else: await (wakeup | short periodic poll | cancellation)
```

A lost wakeup or process restart cannot lose an event; backfill and live
transmission are the same code path; no per-subscriber event buffers. Slow
consumers are detected by bounds — WebSocket write duration, max seq/byte lag,
max total catch-up time — then error frame `ConsumerTooSlow` + close.

## `subscribeRepos` endpoint

- Dependency: `hummingbird-websocket` 2.x, pinned exact.
- `GET /xrpc/com.atproto.sync.subscribeRepos`, unauthenticated WebSocket
  upgrade in `SwanHTTP`. NSID added to the frozen public wire profile via
  `Scripts/regenerate-public-wire.sh` (never hand-edited); replaces the
  `public_streaming_pending` placeholder.
- Framing: two concatenated DAG-CBOR objects — header
  `{"op": 1, "t": "#commit" | "#sync" | "#identity" | "#account" | "#info"}` +
  body; errors `{"op": -1}` + `{error, message}`. Strict decoder ships for
  tests.

### Event bodies

- `#commit`: `seq, rebase: false, tooBig: false, repo, commit, rev, since,
  blocks (diff CAR), ops, blobs: [], prevData, time`.
- `#sync`: `seq, did, blocks (commit-block CAR), rev, time`.
- `#identity`: `seq, did, time, handle?` (handle from confirmed operation or
  omitted).
- `#account`: `seq, did, time, active, status?` — status from
  `AccountControlStatus` (`deactivated`, `suspended`, `takendown`,
  `desynchronized`, `deleted`).

### Limits

- ≤200 ops and ≤2,000,000 bytes in `blocks`; individual record blocks
  ≤1,000,000 bytes; **entire encoded frame ≤5,000,000 bytes, enforced after
  final encoding**.
- Swan already rejects ordinary writes over the ops/blocks limits, so the
  fallback rule is: if a valid persisted repository change cannot be
  represented as a conforming complete `#commit` frame, emit `#sync`. That
  chiefly covers import, rebase, recovery, and exceptional framing overhead.
  The decision is made durably at outbox-write time.

### Cursor semantics on connect

- No cursor → live tail from current position.
- `cursor=0` → entire retained window from oldest event, **no**
  `OutdatedCursor`, then live.
- Cursor within retention → backfill, then live (tailer handles the boundary
  with no gap or duplicate).
- Cursor > current max seq → error frame `FutureCursor`, close.
- Cursor older than retention → info frame `{"name": "OutdatedCursor"}`, then
  stream from oldest retained event.

**P0 compatibility decision:** the cursor represents the last successfully
processed event; Swan resumes strictly after it (`seq > cursor`). The
published event-stream prose says greater-or-equal, but the reference PDS
queries `seq > cursor` and indigo reconnects with its last processed seq. A
fixture proves the pinned relay receives no duplicate at the cutover boundary.
Recorded as a compatibility choice, not claimed as unambiguously
spec-conformant.

### Liveness and retention

- WebSocket ping heartbeat every 30 s; graceful shutdown sends close frames
  via the service-lifecycle hook.
- Retention: **hard maximum age** (default 72 h on `sequenced_at`) plus a
  separate maximum row/byte budget. No minimum-row floor that overrides the
  age ceiling. Pruning advances `retained_from_seq`; either bound expiring
  history yields `OutdatedCursor` for older cursors.
- Account deletion: append the `deleted` `#account` event and delete earlier
  retained events for that DID **in the same global transaction** (matching
  reference PDS behavior). Sequence gaps are permitted.

## `requestCrawl` announcer

- Config `SWAN_PUBLIC_CRAWLERS` (comma-separated crawler origins, no default);
  request body carries Swan's canonical public hostname.
- Triggers: startup; update-triggered on sequenced events with a 10–20 minute
  throttle; periodic refresh (default 24 h).
- Persistent retry state (attempts, next attempt, last success) in
  `control.sqlite`; exponential backoff with jitter; plain HTTP client calls,
  never inside a transaction.

## Acceptance: reference relay in the interop lab

New compose service `reference-relay` (indigo `cmd/relay`):

- New checksum-pinned `interop/fetch-reference-indigo.sh` (the existing
  `fetch-reference.sh` pins only `bluesky-social/atproto`), plus
  `interop/Dockerfile.reference-relay` following the reference-pds pattern —
  Caddy private-CA trust, PLC resolution pointed at `reference-plc`.

Scenario (ordered to eliminate the onboarding race — a relay with no prior
state subscribes at the **current** position, so pre-announcement events would
never be replayed):

1. Announce Swan via `requestCrawl`; wait until relay `listHosts` shows Swan.
2. Wait until Swan observes the relay's actual `subscribeRepos` connection.
3. Then create/activate a **fresh test account**, producing the ordered
   lifecycle sequence (`#identity` → `#account` → activation `#sync`).
4. Create the test record.
5. Verify the `#commit` on the relay's outbound firehose.
6. Cursor recovery: interrupt relay↔swan via toxiproxy, create N commits,
   reconnect — relay receives exactly the missed events; relay `getRepo`
   matches Swan's.
7. Forced `#sync` (operator CLI) causes a clean relay resync.

Independent verification of the relayed `#commit` (the inductive-sync core):
binary two-object CBOR framing; frame/field size limits; DID resolves to Swan;
signed commit CID + signature; `repo`/`rev`/`commit` match the signed commit;
every CAR block matches its CID; CAR root is the commit CID; op paths and
old/new CIDs correct; reversing ops reconstructs `prevData`; `since`/`prevData`
match previously accepted state; relay `getRepo` resolves to the same commit
and MST state.

`getRepo?since`: observe first whether the pinned relay sends `since`. If it
does, either implement revision-aware block selection or explicitly prove the
pinned relay correctly accepts a full-snapshot response. A full snapshot is
never silently labeled a diff.

## Swift-level tests (no Docker)

- Frame codec round-trip + strict-decode fixtures; 5 MB post-encode limit.
- Sequencer crash/replay idempotency (kill between append and lease-complete →
  no duplicate seq, no lost event); batch atomicity (consecutive seqs, all-or-
  nothing).
- Barrier matrix: activation ordering, rotation generation barrier (gen-N
  commit cannot pass pending gen-N `#identity`), reactivation `#account` before
  `#sync`.
- Cursor matrix: live, backfill, boundary handoff (no gap/duplicate),
  `cursor=0`, `FutureCursor`, `OutdatedCursor`, `ConsumerTooSlow` lag bounds.
- Tailer recovery: dropped wakeup and process restart lose nothing.
- Retention: age + budget pruning, `retained_from_seq` advance, deletion
  prunes per-DID history in-transaction.
- Lifecycle emission per confirmed operation; `installPublicPLCOperation` and
  restore/reinstall paths emit nothing.
- Isolation: permissioned writes never produce outbox rows or firehose events
  (extends the adversarial suite; hard gate).

## Out of scope (P0)

OAuth permission corrections (bare-`atproto` fix), `updateHandle`,
repo import/migration endpoints, `listRepos`/`getBlocks`/`sync.getRecord`/
`listBlobs`, live `bsky.network` proof (requires public deployment).

## Phasing

1. Event material + ordinary account outbox + lifecycle batch model +
   per-DID barriers + sequence allocator + global persistence (crash/
   idempotency/barrier tests).
2. Global-log tailer + crash/cutover tests.
3. WebSocket framing, cursor matrix, retention, slow-consumer behavior.
4. Lifecycle integrations (activation, rotation, status changes, deletion) +
   `requestCrawl` announcer + operator CLI force-`#sync`.
5. Pinned indigo relay in the interop lab + independent acceptance proof.
