# Swan public firehose federation (P0) — design

Date: 2026-08-04
Status: approved pending user review
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

- `public_repository_mutation_requests` (`Sources/SwanSQLite/SwanSQLite.swift:402`)
  durably stores per commit: `base_commit_cid`, `base_revision`,
  `next_revision`, `committed_commit_cid`, `committed_data_cid`, and the full
  op list `[{action, collection, rkey, recordCID, previousCID}]`
  (`PublicRepositoryStore.swift:948`). It lacks ordering and timestamps.
- `public_repository_blocks` is content-addressed and never pruned — every
  historical commit/MST/record block remains readable by CID.
- `PublicRepositoryCAR.write(rootCID:blocks:to:)`
  (`Sources/SwanPublicRepository/PublicRepositoryCAR.swift:117`) is a generic
  CAR writer with no completeness requirement — reusable for diff CARs.
- Transactional outbox + leased at-least-once delivery worker pattern:
  `permissioned_space_outbox` + `PermissionedSpaceOutboxDeliveryWorker`
  (`Sources/SwanSQLite/PermissionedOutboxDelivery.swift:117`). Transport I/O
  strictly between lease commit and completion commit; token-checked
  completion; exponential backoff.
- DAG-CBOR: Petrel `DAGCBOR` (`Petrel/Sources/Petrel/Core/Types/CID.swift:410`),
  `OrderedCBORMap`, tag-42 links, plus Swan's strict canonical parser
  (`CommitCBORParser`) and `canonicalUnsignedVarint`.
- Lifecycle chokepoint: `AccountControlStore.transitionStatus`
  (`Sources/SwanSQLite/AccountControlStore.swift:2237`).
- PLC operation log: `installPublicPLCOperation`
  (`Sources/SwanSQLite/PLCIdentityHistoryStore.swift:7`) — ordered, sequenced.
- Interop lab: docker-compose with `swan`, `reference-pds`, `reference-plc`,
  `caddy` (private CA TLS), `mailpit`, `toxiproxy`, `scenario-runner`; pinned
  upstream checkouts via `interop/fetch-reference.sh`.

Gaps: no global sequence anywhere; no WebSocket transport
(`hummingbird-websocket` not a dependency); `subscribeRepos` not in the frozen
public wire profile; no handle-change path (so `#identity` covers PLC ops
only).

## Architecture

New module `SwanPublicFirehose`: event model, frame encoding, sequencer logic.
Depends on `SwanPublicRepository` and Petrel. Stores live in `SwanSQLite`;
WebSocket/XRPC adapter in `SwanHTTP`; announcer worker attached via
`SwanHTTPServiceLifecycle.makeServiceGroup`. Domain modules never see HTTP
types (per `docs/architecture.md`).

### Event sources: two outboxes

1. **Account-local `public_event_outbox`** (each account DB). Written in the
   same transaction as the public repository commit. Columns:
   - `source_key TEXT UNIQUE` — deterministic: `did|commit|<commitCID>` for
     commit events, `did|sync|<commitCID>` for sync events
   - `kind` (`commit` | `sync`)
   - payload: prev commit CID, prev data root CID, base/next rev, op list,
     newly referenced blob CID list (for the `#commit` `blobs` field),
     diff-CAR block **CID list** (bytes resolved later), commit timestamp
   - lease columns (`attempts`, `available_at`, `lease_token`,
     `lease_expires_at`) cloned from `permissioned_space_outbox`
2. **Control-plane `account_event_outbox`** (`control.sqlite`). Written inside
   `transitionStatus` (`#account`, source key `did|account|<status>|<updated_at>`)
   and `installPublicPLCOperation` (`#identity`, source key
   `did|identity|<plcOpCID>`).

Permissioned repositories and spaces never write to either outbox; the
adversarial isolation suite gains a test asserting this.

### Global log: `firehose.sqlite`

New database, append-only:

```sql
CREATE TABLE firehose_events(
  seq        INTEGER PRIMARY KEY AUTOINCREMENT, -- global monotonic; never reused after pruning
  source_key TEXT NOT NULL UNIQUE,              -- idempotent crash replay
  did        TEXT NOT NULL,
  kind       TEXT NOT NULL,                     -- commit | sync | identity | account
  time       TEXT NOT NULL,
  frame_body BLOB NOT NULL                      -- final encoded DAG-CBOR body, seq embedded, diff CAR inlined
);
```

### Sequencer worker

Actor modeled on `PermissionedSpaceOutboxDeliveryWorker`:

1. Lease next outbox row (per-account outboxes drained in row order, so
   per-account `rev` order is preserved globally).
2. Resolve diff-CAR block bytes from that account's `public_repository_blocks`.
3. Append to `firehose_events` — `seq` assigned by insert, frame body encoded
   with `seq` embedded. UNIQUE `source_key` makes retry after crash a no-op.
4. Complete the lease (token-checked).
5. Broadcast the event in-process to live subscribers.

No network I/O; DB reads/writes never span an open transaction on another
database. Rationale for storing final bytes in the global log: the serve path
reads exactly one database (no per-account opens during backfill, no lock
contention with writers), and replays are byte-exact. Storage bounded by
retention.

## `subscribeRepos` endpoint

- Dependency: `hummingbird-websocket` 2.x, pinned exact.
- `GET /xrpc/com.atproto.sync.subscribeRepos`, unauthenticated WebSocket
  upgrade, registered in `SwanHTTP`.
- NSID added to the frozen public wire profile via
  `Scripts/regenerate-public-wire.sh` (never hand-edited); replaces the
  `public_streaming_pending` placeholder.

### Framing

Each message = two concatenated DAG-CBOR objects: header
`{"op": 1, "t": "#commit" | "#sync" | "#identity" | "#account" | "#info"}` +
body; error frames `{"op": -1}` + `{error, message}`. Encoded with
`DAGCBOR`/`OrderedCBORMap`; a strict decoder (modeled on `CommitCBORParser`)
ships for tests.

### Event bodies

- `#commit`: `seq, rebase: false, tooBig: false, repo, commit, rev, since,
  blocks (diff CAR), ops, blobs, prevData, time`. Diff CAR's first root is the
  commit CID; contains commit block + new MST blocks + new record blocks.
- `#sync`: `seq, did, blocks (commit-block CAR), rev, time`.
- `#identity`: `seq, did, time, handle?`.
- `#account`: `seq, did, time, active, status?` where status maps from
  `AccountControlStatus` (`deactivated`, `suspended`, `takendown`,
  `desynchronized`, `deleted`).

### Cursor semantics

- No cursor → live tail from next event.
- Cursor ≤ max seq → backfill `WHERE seq > cursor` in order, then hand off to
  live broadcast at the boundary seq (no gap, no duplicate).
- Cursor > max seq → error frame `FutureCursor`, close.
- Cursor older than retained history → info frame `{"name": "OutdatedCursor"}`,
  then stream from oldest retained event.

### Limits, slow consumers, liveness, retention

- At outbox-write time (inside the commit transaction): >200 ops or >2 MB of
  diff blocks → write a `#sync` row instead of `#commit`.
- Per-consumer bounded queue, default 500 events; overflow → error frame
  `ConsumerTooSlow`, close.
- WebSocket ping heartbeat every 30 s; graceful shutdown sends close frames via
  the service-lifecycle hook.
- Retention: default 72 h AND minimum 10,000 events (whichever retains more);
  periodic head pruning; `AUTOINCREMENT` prevents seq regression.

## Lifecycle events and `requestCrawl`

- `#account`: every legal `transitionStatus` edge emits an event;
  `active → X` sets `active: false` + status; `X → active` sets `active: true`.
- `#identity`: PLC operation installs only. Handle field read from the account
  record at sequencing time. Building `updateHandle` is out of scope.
- `#sync` triggers in P0: oversized commits, plus an operator CLI subcommand to
  force-emit `#sync` for an account (needed for acceptance and future
  import/migration).
- Announcer: `SWAN_PUBLIC_CRAWLERS` (comma-separated origins, no default).
  Worker POSTs `com.atproto.sync.requestCrawl {hostname}` to each crawler at
  startup, after the first sequenced event, and on periodic refresh (default
  24 h). Persistent retry state (attempts, next attempt, last success) in
  `control.sqlite`; exponential backoff with jitter; plain HTTP client calls,
  never inside a transaction.

## Acceptance: reference relay in the interop lab

New compose service `reference-relay` (indigo `cmd/relay`):

- `interop/Dockerfile.reference-relay` following the reference-pds pattern —
  pinned upstream checkout via `fetch-reference.sh`, Caddy private-CA trust,
  PLC resolution pointed at `reference-plc`.
- Scenario-runner acceptance script proves, in order:
  1. Swan announces via `requestCrawl`; relay `listHosts` shows the Swan host.
  2. A record created on Swan arrives as a `#commit` on the **relay's**
     outbound firehose (inductive verification passed, not mere receipt).
  3. Cursor recovery: interrupt relay↔swan via toxiproxy, create N commits,
     reconnect — relay receives exactly the missed events and relay `getRepo`
     of the account matches Swan's.
  4. Forced `#sync` (CLI) causes a clean relay resync.

Known integration risks (resolve during implementation): indigo relay flags/env
for custom PLC host and private CA trust; relay may call `getRepo` with
`since` (Swan currently rejects it — fallback: accept the param and serve the
full snapshot).

## Swift-level tests (no Docker)

- Frame codec round-trip + strict-decode fixtures.
- Sequencer crash/replay idempotency (kill between append and lease-complete →
  no duplicate seq, no lost event).
- Cursor matrix: live, backfill, backfill→live boundary, `FutureCursor`,
  `OutdatedCursor`, `ConsumerTooSlow`.
- Oversize commit → `#sync` fallback decision durability.
- Lifecycle emission per legal status edge.
- Isolation: permissioned writes never produce outbox rows or firehose events
  (extends the adversarial suite).

## Out of scope (P0)

OAuth permission corrections (bare-`atproto` fix), `updateHandle`,
repo import/migration endpoints, `listRepos`/`getBlocks`/`sync.getRecord`/
`listBlobs`, live `bsky.network` proof (requires public deployment).

## Phasing

1. Outboxes + sequencer + `firehose.sqlite` persistence, with crash/idempotency
   tests.
2. `subscribeRepos` WebSocket: framing, backfill, live tail, cursor semantics,
   slow-consumer handling, retention.
3. `#account`/`#identity`/`#sync` emission + `requestCrawl` announcer + CLI
   force-sync.
4. `reference-relay` in the interop lab + acceptance scenario.
