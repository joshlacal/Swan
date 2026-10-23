# Storage model

## 1. Swan state inventory and classification

Source of truth: `Swan/AGENTS.md` (planes), `CREATE TABLE` statements in
`Sources/SwanSQLite/*.swift`, `SwanCommand.swift` (`keys/` default at
`SwanCommand.swift:2782`).

Plane files: `control.sqlite`, `actors/<sha256(did)[0..2]>/<sha256(did)>.sqlite`,
`firehose.sqlite`, `blobs/` (content digest), `keys/` (encrypted envelopes).

| State | Where today | Class | SwanTV placement |
|---|---|---|---|
| Accounts, handles, status (`accounts`, `identity_bindings`, `identity_binding_history`, `did_web_claim_transactions`) | control.sqlite | AUTHORITATIVE DURABLE | vault (WAL-shipped) |
| Signup/invite/email tables, `account_emails`, `account_email_*` | control.sqlite | AUTHORITATIVE DURABLE | vault |
| Legacy sessions (`legacy_session_families`, `legacy_session_tokens`), app passwords, management sessions | control.sqlite | AUTHORITATIVE DURABLE (revocable) | vault |
| MFA: `authentication_factors`, `totp_*`, `webauthn_*`, `recovery_code_digests`, `mfa_*`, `account_authorization_grants` | control.sqlite | AUTHORITATIVE DURABLE + SECRET-bearing (TOTP envelopes encrypted) | vault |
| OAuth: `oauth_tokens`, `oauth_client_metadata` (+ grants/replay tables) | control.sqlite | tokens AUTHORITATIVE DURABLE; client metadata CACHE | vault (same file; cache rows are cheap) |
| Actor preferences (`actor_preferences`) | control.sqlite | AUTHORITATIVE DURABLE | vault |
| Rate-limit windows, `public_crawl_announcer_state`, `account_deletion_*` | control.sqlite | EPHEMERAL / DURABLE BUT RECONSTRUCTIBLE | vault (rides along) |
| Repo records, MST blocks, signed commits, head/rev, permissioned space records, oplog/outbox | `<did>.sqlite` | AUTHORITATIVE DURABLE | vault |
| Firehose seq (`firehose_meta.next_seq`), `firehose_events` frame log, diff CARs | firehose.sqlite | AUTHORITATIVE DURABLE (seq must never regress) | vault |
| Blob bytes | `blobs/<digest>` | AUTHORITATIVE DURABLE, immutable | vault objects (`/v1/objects/<sha256>`), local cache |
| Blob metadata / quota | `<did>.sqlite` | AUTHORITATIVE DURABLE | vault |
| Account signing keys, PLC rotation keys, did:web keys (`keys/`, encrypted with account KEK) | `keys/` files | SECRET, AUTHORITATIVE | vault objects (ciphertext only) |
| Account KEK (`--*-account-kek-file`), OAuth server key (`--oauth-server-key-file`), operator secret, email proof key | operator-mounted 0600 files | SECRET, bootstrap | Apple TV keychain/App Group + operator backup; **never** in vault plaintext |
| PLC key cache (60 s), lexicon cache, OAuth metadata freshness | control.sqlite / memory | CACHE | anywhere |
| Space CAR recovery index (`SQLiteSpaceCARRecoveryIndex`, unlinked scratch dir) | temp | EPHEMERAL | local only |
| NIO buffers, admission counters | memory | EPHEMERAL | – |

Consequence: three SQLite files + the object namespace carry everything
authoritative. There is no authoritative state outside them except the
operator-held bootstrap secrets.

## 2. The vault protocol (`swan-vault`)

Binary: `AppleTV/swan-vault` (Rust, 505 KB release on arm64 macOS, no async
runtime, thread-per-connection, one global mutex).

Disk layout under `--root`:

```
vault.json                  vault_id, generation, lease holder
db/<name>/manifest.json     page_size, current WAL salt, checksum chain, next_seq, segments[]
db/<name>/snapshot.db       base image
db/<name>/wal/<seq>.seg     raw SQLite WAL frames, one file per accepted segment
objects/<aa>/<sha256>       immutable objects (blobs, key envelopes, exported CARs)
tmp/                        in-flight writes, wiped on start
```

HTTP API (bearer PSK on everything except `/v1/health`; `?gen=N` on every
mutation):

| Method/path | Purpose | Durability step |
|---|---|---|
| `GET /v1/health` | liveness, generation, disk free, db list | – |
| `POST /v1/lease {holder}` | bump generation, fence previous writer | write `vault.json` (tmp+fsync+rename+dirsync) |
| `PUT /v1/db/{name}/snapshot?gen` | install base image (validated SQLite header), reset WAL | atomic write, manifest reset |
| `POST /v1/db/{name}/wal?gen` + `X-Wal-*` headers | append one segment: contiguous frames ending on a commit frame | validate salt + SQLite checksum chain → write seg (fsync) → write manifest (fsync) |
| `POST /v1/db/{name}/compact?gen` | fold segments into snapshot | new image fsynced, renamed, manifest swapped, then segments removed |
| `GET /v1/db/{name}/manifest`, `/snapshot`, `/wal/{seq}` | restore path | – |
| `PUT /v1/objects/{sha256}?gen` | immutable object; digest verified; idempotent | atomic write |
| `GET/HEAD /v1/objects/{sha256}` | fetch | – |

Rejection semantics: wrong seq → 409; salt mismatch without `X-Wal-Reset` →
409; checksum/commit-frame failure → 422 and nothing written; stale
generation → 409; digest mismatch → 422. Replaying the last accepted segment
byte-identically → 200 (idempotent), replaying with different bytes → 409.

### Proof (PROVEN, macOS, SQLite 3.x via python3 stdlib)

`python3 AppleTV/swan-vault/tests/wal_ship_selftest.py` output:

```
PASS: 40 commits shipped as 40 segments incl. one WAL reset; restored image matches live DB; fencing, digest, replay checks ok
```

What it exercises: WAL header checksum equality with SQLite's own header
(asserts our checksum algorithm is SQLite's), per-commit shipping straight from
the `-wal` file, `PRAGMA wal_checkpoint(TRUNCATE)` mid-run (salt change →
reset segment), remote compaction, `PRAGMA integrity_check == ok` on the
restored image, row-for-row equality, generation fencing, object digest
verification, idempotent replay, corrupted replay refused, daemon restart with
state intact.

Not yet exercised: power loss on the router (needs hardware), disk full,
multi-GB objects (streamed reads are in place; ingest buffers up to 256 MB and
must become streaming before blob upload qualification), TLS (see D-004).

## 3. Apple TV side: `SwanDurableStore` (built; PROVEN on macOS)

New SPM target `Sources/SwanDurableStore` (depends only on SQLiteNIO + Crypto):

* `VaultClient` (actor) — URLSession, bearer PSK, lease generation on every
  mutation, 15 s request timeout, ≤2 connections. Errors are typed:
  `.fenced` (409 stale generation → stop writing), `.rejected` (4xx: chain,
  seq, digest), `.unavailable` (transport/5xx: retry), `.notLeased`.
* `WALShipper` (actor, one per database file) — `bootstrap()` (checkpoint
  TRUNCATE via its own connection, upload the image as the snapshot),
  `attach()` (adopt the vault manifest), `ship()` (walk the `-wal` from
  `nextFrame` to the last commit frame with the current salt, POST one
  segment; salt change ⇒ reset segment with the header checksum; a salt change
  with unshipped frames ⇒ `unshippedFramesLost`, i.e. an autocheckpoint ran
  without a barrier), `checkpointIfShipped()` (TRUNCATE only when every frame
  is acknowledged; `SQLITE_BUSY` ⇒ `checkpointBlocked`, retry later),
  `restore(client:database:to:)` (snapshot + segments → file, same page loop
  as the daemon's `compact`).
* Swan hook: `SQLiteLayout.CommitBarrier = @Sendable () async throws -> Void`;
  `installCommitBarrier(_:)` on `SQLiteAccountDatabase`,
  `SQLiteControlDatabase`, `SQLiteFirehoseDatabase`. Installing sets
  `PRAGMA wal_autocheckpoint=0` on that actor's write connection; the three
  `transaction {}` helpers call the barrier after `COMMIT`, inside the actor
  and (for account/control) inside the connection gate, so the next write on
  that database cannot start until the previous one is durable remotely.
  `nil` (the default, and what `swan serve` uses) restores autocheckpoint and
  changes nothing else.

Proof: `swift test --filter SwanDurableStoreTests` (skips itself unless
`AppleTV/swan-vault/target/release/swan-vault` exists or `SWAN_VAULT_BINARY`
is set). 2026-09-04: both tests pass.

* `testControlDatabaseWritesSurviveColdRestoreFromVault`: real
  `SQLiteControlDatabase`, barrier installed, two `createAccount`
  transactions ⇒ ≥2 segments at the vault before the calls return; explicit
  checkpoint (WAL reset) then a third account; cold `restore` into an empty
  directory reopened by `SQLiteControlDatabase` returns all three accounts;
  vault `compact` then restore again ⇒ same content.
* `testFencedWriterFailsTheTransactionNotTheProcess`: a second lease holder
  appears; the next `createAccount` throws `VaultClient.Failure.fenced`, the
  vault holds zero segments for it.

Not yet built: blob/key-envelope object wrapper (`VaultObjectStore`), the
SwanTV bootstrap sequence that wires these into the extension, cold-start
503 gating, and the shipper's retry/backoff policy (today one failed POST
fails the write and the next write retries the whole backlog, which is
correct but not tuned).

### Failure semantics (design for the untested paths; see `FAILURE_TESTS.md`)

| Event | Behaviour |
|---|---|
| Vault unreachable during a write | local COMMIT already happened; barrier throws `.unavailable` → XRPC 503; the actor's next write re-ships the backlog first. Autocheckpoint is off, so frames stay in the WAL. |
| Vault unreachable at startup | 503; retry loop. Serve reads from the cache only if the vault manifest, once reachable, is not ahead of local. |
| Apple TV cache purged | `WALShipper.restore` per database, then normal open. Anything never shipped was never acknowledged to a client. |
| Two Apple TVs on one vault | PROVEN: the fenced writer's transaction fails with `.fenced`; nothing lands remotely. |
| Segment rejected `.rejected` | shipper halts and alerts; local WAL is kept for forensics. |

## 4. Backup model (OpenWrt side)

* Snapshot + segments + objects are append-only between compactions, so
  `rsync -a --link-dest` or `tar` of `--root` is a consistent backup **if**
  taken while `swan-vault` is paused *or* by copying `manifest.json` last and
  ignoring segments newer than it (segments are never rewritten).
* Restore test = point a fresh vault root at the copy, run
  `swan-vault`, cold-start SwanTV against it. Until that has produced a working
  PDS, backups are not "complete" (mission rule).
* Bootstrap secrets (KEK, OAuth server key) are not in the vault; the backup
  runbook must pair the vault copy with the operator's secret store.

## 5. Open items

* Streaming ingest for objects/segments in the daemon (currently buffered, capped).
* Disk-full behaviour: atomic_write fails → 500 → barrier fails → fence closes. Needs a low-water-mark 507 before that point.
* Router architecture unknown (aarch64 vs mipsel vs armv7) → cross target TBD (`DECISION_LOG.md` Q-2).
