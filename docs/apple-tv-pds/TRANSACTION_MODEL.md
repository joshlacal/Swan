# Transaction and consistency model

## What Swan needs to be atomic

Evidence from the code:

* Every write in each plane is one SQLite `BEGIN IMMEDIATE … COMMIT`
  (`SQLiteAccountDatabase.transaction`, `SwanSQLite.swift:10786`;
  `SQLiteControlDatabase.transaction`, `OAuthControlStore.swift:1720`;
  `SQLiteFirehoseDatabase.transaction`, `SQLiteFirehoseDatabase.swift:807`).
* A public repository mutation is `reserve → (prepare + sign outside storage)
  → apply` on the account database (`PublicRepositoryMutationStore`,
  `Sources/SwanStorage/PublicRepositoryStore.swift:109-124`). `apply` writes
  the new blocks, the record projection, the commit/head, and the account-local
  outbox row in that one account-database transaction
  (`SwanSQLite.swift:2177-2179`: "`BEGIN IMMEDIATE` makes the oplog/outbox
  write atomic").
* Firehose sequencing is a *separate* transaction on `firehose.sqlite` that
  drains the account outbox ("checked sequence allocation, frame encoding, and
  row insertion commit or roll back together", `SQLiteFirehoseDatabase.swift:62-64`).
  Cross-database atomicity therefore already does not exist in Swan; the
  outbox makes it crash-safe: a crash between `apply` and sequencing leaves an
  undrained outbox row that is re-emitted on restart (`PublicLifecycleEventEmitting`
  doc comment, `Sources/SwanStorage/PublicLifecycleEventEmitting.swift:5`).
* Swan's own durability stance today: `synchronous=NORMAL`, "can lose the tail
  of the most recent transaction on host power loss" (`SwanSQLite.swift:54-57`).
  SwanTV strengthens this: a transaction is acknowledged to the client only
  after the vault has fsynced its frames.

So the unit the vault must make durable is exactly **one SQLite transaction on
one database file**, and the ordering the vault must preserve is **commit
order within a database**. Cross-database ordering is handled by the same
outbox mechanism that already handles crashes.

## The three forbidden states, and why they cannot occur

| Forbidden | Why it cannot happen |
|---|---|
| Repo block written, commit pointer not written | Same SQLite transaction → same WAL commit frame. The vault only accepts segments that end on a commit frame; a partial segment is rejected whole (422) and never referenced by the manifest. |
| Commit pointer written, block missing | Same as above; additionally a client-visible ack requires the segment containing both to be fsynced. |
| Sequence emitted, repo transaction not durable | The firehose transaction can only be reached after the account transaction's barrier returned; the barrier returns only after the vault fsynced the account segment. A WebSocket subscriber therefore never sees a seq whose repo write is not durable. |

Additional guarantee: **no accepted write is reported to a client before it is
durable off-device.** The barrier sits between `COMMIT` and the return to the
XRPC handler.

## Exact write sequence (SwanTV)

```
client ── POST /xrpc/com.atproto.repo.createRecord ──▶ Swan (Apple TV)
   1. reservePublicRepositoryRevision        (account.sqlite tx #1 + barrier)
   2. prepare blocks, sign commit            (memory)
   3. applyPublicRepositoryMutation          (account.sqlite tx #2: blocks, record, head, outbox)
   4. COMMIT ─▶ barrier:
        a. read new frames from account.sqlite-wal (salt + checksum chain)
        b. POST /v1/db/<did>/wal?gen=G  seq=n
        c. vault: validate → fsync seg → fsync manifest → 200
        d. return to Swan
   5. respond 200 {uri, cid, commit}   ◀── only now
   6. firehose drain (async): firehose.sqlite tx + its own barrier, then emit frame
```

Blob uploads: `PUT /v1/objects/<sha256>` completes (201/200) **before** the
local file write and before the metadata transaction that references it. A
crash after the object upload but before the row leaves an unreferenced object
(garbage, harmless); the reverse is impossible.

Key envelopes: same object rule; the envelope is uploaded before the identity
binding transaction that depends on it.

## Barrier failure handling

* Vault returns 5xx / times out: the local commit stands. The barrier throws
  after its deadline; the handler maps this to HTTP 503 with `Retry-After`; the
  store's write fence stays closed until the backlog ships. The client never
  received success, so a retry is legitimate; Swan's `swapCommit`/`InvalidSwap`
  semantics make a duplicate `createRecord` detectable by the client.
* Vault returns 409 (generation): this Apple TV has been fenced. Writes stop
  permanently until an operator re-leases. Reads continue.
* Vault returns 422 (chain/checksum): shipper stops and raises an alert; the
  local WAL is authoritative for forensics and must not be checkpointed.

## Checkpoint discipline

`PRAGMA wal_autocheckpoint=0` on every SwanTV connection. The shipper issues
`PRAGMA wal_checkpoint(TRUNCATE)` only when `next_frame` locally equals the
vault's acknowledged `next_frame` and the WAL exceeds a size threshold (e.g.
16 MiB). `SQLITE_BUSY` (open reader) is simply retried later; correctness does
not depend on when checkpoints happen, only on never checkpointing unshipped
frames.

## Restore

`snapshot.db` + `segments[]` in order → for each frame write page `p` at
`(p-1)*page_size`, truncate to the last commit frame's `db_pages`. This is the
same algorithm `swan-vault compact` runs, so a restore is verified every time a
compaction is (`wal_ship_selftest.py` compares the compacted image to the live
database row-for-row and runs `integrity_check`).

## Classification

* WAL frame validation, chain, reset, compaction, restore equality: PROVEN (macOS, SQLite via python3 and via SQLiteNIO).
* Barrier placement in the three `transaction` helpers and fence-on-409: PROVEN on macOS through `SQLiteControlDatabase` (`SwanDurableStoreTests`); the account and firehose actors carry the identical helper and hook.
* Cross-database outbox recovery after mid-sequence crash on tvOS: INFERRED from Swan's existing design; must be exercised in `FAILURE_TESTS.md`.
