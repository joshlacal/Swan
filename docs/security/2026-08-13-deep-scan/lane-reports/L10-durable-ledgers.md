# Lane report — L10 sqlite-durable-ledgers

Program: `docs/security/2026-08-13-deep-scan/REMEDIATION-PROGRAM.md` §3 L10, §4 item 10.
Clusters: `C11-quotas-and-ledgers.md` (F27), `C4-service-jwt.md` (F31).
Workspace: `Swan-L10-durable-ledgers`, based on `77bab90c5e79` (the seven-lane merge).
Logs: `/private/tmp/swan-lane-L10-durable-ledgers/` (nothing else writes there).

Closes **F27** and **F31 step 1**. Step 2 (a space claim in the service JWT) is
out of scope and stays with the maintainer; §7 below records what it would take.

Every line number in the program predates this base. All citations below were
re-derived against the current tree.

---

## 1. F31 step 1 — participation precondition

**Verdict: PARTIALLY CONFIRMED, and step 1 is an interop *fix*, not a
behaviour reversal.** See §2 for the evidence behind that judgement.

The mechanism is real and I reproduced it before changing anything. The
deletion service JWT carries `iss`, `aud`, `lxm`, `jti` and time claims only —
no space — and `SpaceServiceAuthentication.swift:40` states in terms that the
verifier keeps **no replay cache**: "notification idempotence is a durable
receiver property". The route can therefore only check that the body space's
authority equals the issuer (`SwanSpaceNotificationXRPC.swift:209`), and
`receiveSpaceDeletionNotification` (`SwanSQLite.swift:7190`, pre-fix) accepted
any syntactically valid SpaceURI under that authority.

**One extra consequence the scan filed under F31 but never named: this is also
an unbounded durable ledger, which is F27's own shape.** Receipt identity is
`(issuer, event_id, space_uri)` (`SwanSQLite.swift:342-348`), so replaying a
*single* valid token against N distinct space URIs is N non-duplicates: N
permanent `permissioned_space_notification_receipts` rows **and** N permanent
`permissioned_space_recipient_tombstones` rows. The receipt table's own
anti-growth control — the terminal-tombstone early return whose comment says
"must not create an unbounded replay-receipt stream"
(`SwanSQLite.swift:7243-7245`) — is per space, so it does not bound growth
across spaces.

**Fix** (`SwanSQLite.swift:7205-7234`): a participation precondition as the
first statement inside the transaction. Participation is the same pair of facts
Swan's own hosted-space projection reports (`hostedSpaceURIs`,
`SwanSQLite.swift:5531-5566`) — an authority row this account owns, or a local
repository row it authored:

- `permissioned_repository_state WHERE space_uri = ? AND author_did = <account>`
- `permissioned_simple_space_authorities WHERE space_uri = ? AND owner_did = <account>`

Absent both, the call returns without writing. That is Swan's structural
equivalent of the reference's `actorTxn.space.getSpace(space)` /
`if (!existing) return`
(`.interop-cache/atproto-3f6c96d5…/packages/pds/src/api/com/atproto/space/notifySpaceDeleted.ts:33-34`).
The authority arm is included deliberately: a locally-owned space keeps its
authority row after deletion (`is_deleted = 1`), so the self-notification case
the original implementation called out ("If this account is itself the
(already-deleted) authority") still records normally.

**Residual after step 1.** An attacker holding one valid authority-issued
deletion token can still tombstone any *participated* space under that
authority. That is bounded, and the authority could legitimately delete those
spaces anyway. What step 1 removes is the unbounded arm: spaces this account
has never joined, including spaces that do not exist yet.

---

## 2. Was omitting the precondition deliberate?

**No. It is an artefact of how the tombstone was retrofitted, not a designed
pre-emptive closure.** Four pieces of evidence, in order of weight:

1. **The original implementation had no tombstone at all.** At
   `2c52c235cb6b` ("feat: add durable space writer notifications"),
   `receiveSpaceDeletionNotification` wrote a receipt row and nothing else, with
   the comment: "If this account is itself the (already-deleted) authority, no
   additional state is needed. A local writer repository has no authority table
   to mutate in this alpha." There was no closure to gate, so no precondition
   could have been omitted.
2. **The tombstone arrived later, scoped to an existing repository.**
   `6fce917d1084` ("fix: harden space notification delivery") added
   `permissioned_space_recipient_tombstones`, `requireLocalRepositorySpaceOpen`,
   and eleven call sites, with the rationale: "A recipient **may retain** a
   local repository for its own writes in this remote space. Persist a closure
   rather than creating a synthetic remote authority row." The stated object is
   a repository the recipient already has. Nothing in that commit, or anywhere
   in `docs/`, claims a tombstone for a never-joined space is meaningful.
3. **Nothing consumes an early tombstone.** Every consumer requires the
   repository row to exist in the same query, so a tombstone that predates
   repository state changes no answer they give (detail in §3).
4. **No test asserts the pre-emptive property as a property.** One test
   incidentally depended on it —
   `testNotificationReceiptsCompactToCurrentStateAndTombstonesStopGrowth`
   delivered 100 deletions to a recipient database with no repository state —
   but it is a receipt-growth bound test, not a pre-emptive-closure test. I gave
   it the participation it always implied
   (`SpaceNotificationSQLiteTests.swift:185-189`); its assertion is unchanged
   and still passes.

**The one property genuinely lost**, and it should be recorded rather than
waved away: pre-fix, a tombstone for a never-joined space would refuse a
*later first write* into that space (`apply` → `requireLocalRepositorySpaceOpen`,
`SwanSQLite.swift:3662`). Post-fix it does not, because no tombstone is
written. My pre-fix run observed exactly that behaviour as a failure —
`"unauthorized: permissioned space is closed"` — which is what the sequencing
looks like from the inside. Losing it restores parity with the pinned reference,
which has the same gap by construction.

---

## 3. Does portable restore depend on a tombstone predating repository state?

**No. Shipping the precondition cannot break restore.** All three closures in
that neighbourhood require the repository row in the *same* query, so a
tombstone is only ever load-bearing for a repository that already exists:

- `requirePortableBlobRestoreRepository` (`SwanSQLite.swift:9717-9746`) —
  `SELECT 1 FROM permissioned_repository_state … AND NOT EXISTS (tombstone)`.
  With no repository row it fails on the row, tombstone or not.
- `requireReadablePermissionedBlobRepository` (`:9751-9786`) — same shape.
- `requireLocalRepositorySpaceOpen` (`:9694-9710`) — tombstone-only, but every
  one of its eleven call sites operates on an existing repository.

`restorePortableRepositories` itself never reads the tombstone table: it
requires `permissioned_repository_state`, `permissioned_space_records`,
`permissioned_space_oplog`, `permissioned_space_requests`,
`permissioned_space_outbox` and `permissioned_restored_repository_closures` to
be **empty** (`SwanSQLite.swift:4130-4146`). A restore target is a fresh
database.

---

## 4. F27 — the unbounded receipt ledger

**Verdict: CONFIRMED as a growth defect; the scan's severity framing is
generous, and its threat model is wrong in a way worth stating.**

The ledger is real: one permanent ~150-byte row per successful permissioned
write, inserted in the same transaction that prunes
`permissioned_space_oplog` by retention depth, with no expiry, compaction or
quota anywhere (`SwanSQLite.swift:3835-3848` insert, `:3869-3897` oplog prune).

**But the request ID is not attacker-chosen over HTTP.** Every
`com.atproto.space.*` write mints a fresh server-side UUID —
`let requestID = UUID()` at `SwanSpaceXRPC.swift:928` — so the scan's "unique
request IDs" precondition is not a capability an attacker exercises; the ledger
simply grows one row per write. Two consequences: the growth is exactly
proportional to legitimate write volume, and `duplicateRequest` is
**unreachable from HTTP** (a fresh UUID cannot collide, and the one retry that
reuses a request ID, `SwanSpaceXRPC.swift:945-950`, retries a failure thrown
before any INSERT). The reachable callers of the replay reservation are the
in-process interop harness (`LocalSemanticInterop.swift:175-235`) and tests.

**Fix**, three parts, all inside the existing apply transaction:

1. `created_at INTEGER NOT NULL DEFAULT 0 CHECK(created_at >= 0)` on
   `permissioned_space_requests` (`SwanSQLite.swift:991-1002`).
2. Stamped at the INSERT from the `Date()` the outbox row already computes,
   hoisted three lines up so one clock value covers both
   (`SwanSQLite.swift:3834-3848`).
3. A depth prune immediately after the oplog prune
   (`SwanSQLite.swift:3899-3941`), scoped to `(space_uri, author_did)` and
   ordered `created_at DESC, final_revision DESC` — the same
   `LIMIT 1 OFFSET retention - 1` cutoff shape as the oplog prune beside it.

**One knob, not two.** The prune reuses `oplogRetention` (default 10,000,
`SwanCommand.swift:1876`, `--space-oplog-retention`) rather than introducing a
second constant. Depth, not age, for the same reason. Note the two windows are
not equal in revisions and the inequality runs the safe way: the oplog counts
*operations* (an `applyWrites` of 200 writes is 200 oplog rows) while receipts
count *requests* (one row), so a receipt always outlives the oplog entries of
its own request. The interop pin `oplogRetention == 10_000`
(`SwanInterop.swift:668`) is unchanged.

### Duplicate-versus-conflict, confirmed

The scan's proposed reading is correct: **the receipt is not what protects
state; the revision CAS is.** The order inside the transaction is dup-check
(`:3664`) → CAS (`:3673-3678`) → wire-revision monotonicity (`:3679-3683`). A
replay whose receipt has been pruned falls through to the CAS with a stale
`expectedRevision`, and the CAS cannot be satisfied — revisions only increase,
and a receipt is only pruned after `oplogRetention` further commits, so the
repository has provably moved on. **No replay can become an accepted write.**

Client-visible answers on the permissioned write routes:

| case | error thrown | HTTP |
|---|---|---|
| receipt retained | `SQLiteRepositoryError.duplicateRequest` — not a `SwanError`, so it falls to the default arm at `SwanSpaceXRPC.swift:956` | **503 `temporarily_unavailable`** |
| receipt pruned | `SwanError.conflict` → `AuthenticatedSpaceWriteFailure.conflict` (`:953`) | **409 `ConcurrentWrite`** |

So pruning changes 503 → 409 for the affected replay, and **only for callers
that can supply their own request ID** — which, per the paragraph above, is not
the HTTP surface at all. A 409 `ConcurrentWrite` is not a harder failure than a
503; it is the more accurate and more retriable of the two. Nothing here turns a
duplicate into something a client treats as a hard failure. Both are pinned by
`testRequestReceiptsPruneToRetentionDepthAndStaleReplayBecomesAConflict`.

### Effect on the live database

This is a schema change on `swan.place` with one real account's data.

- The migration is **additive only**: version 16,
  `migratePermissionedRequestReceiptRetentionIfNeeded`
  (`SwanSQLite.swift:2568-2596`), one `ALTER TABLE … ADD COLUMN` behind
  `addAccountColumnIfMissing` (`:3325-3337`), inside the same startup
  transaction as every other account migration, recorded in
  `permissioned_repository_migrations`. It follows
  `migratePublicFirehoseCompletionAnchorsIfNeeded` (version 14,
  `public_event_outbox.completed`) statement for statement, including the
  `NOT NULL DEFAULT … CHECK(…)` column definition.
- **No existing row is rewritten, moved or deleted by the migration.** Every
  pre-upgrade receipt keeps its `request_id`, `space_uri`, `author_did`,
  `base_revision`, `final_revision` and `event_id`, and takes `created_at = 0`.
  I deliberately did **not** back-fill a synthetic timestamp: the real enqueue
  time was never recorded, and inventing one could let a pre-upgrade row outrank
  a genuinely newer stamped row in the retention window.
- **`created_at = 0` sorts oldest, so pre-upgrade rows are evicted first.**
  That is the correct order — they are the oldest — and it is asserted by
  `testRequestReceiptMigrationStampsExistingRowsAsOldest`, which drops the
  column from a real database file, reopens it, and checks both the surviving
  row and the eviction order.
- **Nothing prunes on the live box in the foreseeable future.** Retention is
  per `(space_uri, author_did)` at the default 10,000; the first eviction for a
  repository needs its 10,001st write. Deleting a receipt has no effect on
  repository state, records, the oplog, the outbox, account export, or
  portable restore (which requires the table empty).
- Rollback is safe in the direction that matters: an older binary ignores the
  extra column, since every read of this table is by explicit column name.

---

## 5. Exact pre-fix failures

Built with `xcrun --toolchain XcodeDefault swift build --build-tests`, run with
`--skip-build`. Log: `prefix-sqlite.log`.

```
SpaceNotificationSQLiteTests.swift:484: error: -[… testDeletionNotificationForAnUnjoinedSpaceIsANoOp] : XCTAssertEqual failed: ("Optional(1)") is not equal to ("Optional(0)")
SpaceNotificationSQLiteTests.swift:493: error: -[… testDeletionNotificationForAnUnjoinedSpaceIsANoOp] : XCTAssertEqual failed: ("Optional(1)") is not equal to ("Optional(0)")
SwanSQLite.swift:8986: error: -[… testDeletionNotificationForAnUnjoinedSpaceIsANoOp] : failed: caught error: "unauthorized: permissioned space is closed"
SpaceNotificationSQLiteTests.swift:692: error: -[… testRequestReceiptMigrationStampsExistingRowsAsOldest] : failed: caught error: "error: no such column: \"created_at\""
AsyncAwaitSupport.swift:86: error: -[… testRequestReceiptsPruneToRetentionDepthAndStaleReplayBecomesAConflict] : failed: caught error: "error: no such column: created_at"
```

Line 484 is the tombstone count for the unjoined space, 493 the receipt count —
both `1` where the reference answers `0`. The third line is the pre-emptive
closure refusing the account's own later first write into that space.

An earlier pre-fix run (`prefix-targeted.log`) **truncated**: the migration
test's raw `SQLiteConnection` was left open on the throwing path and tripped
`SQLiteNIO/SQLiteConnection.swift:339: Assertion failed: SQLiteConnection was
not closed before deinitializing`, killing the target with signal 5 and hiding
the two F27 failures. The test now closes the connection on both paths
(`SpaceNotificationSQLiteTests.swift:672-696`). Recording it because the log
still reads as a smaller failure set than the truth.

---

## 6. Suite result

macOS, `xcrun --toolchain XcodeDefault swift test --skip-build`, log
`postfix-full.log`:

- **1547 passed, 0 failed**, exit 0, `Some test targets reported failures` count
  0, **11/11 targets** green.
- Baseline (merged tree) was 1543 / 0 / 11. **Delta +4 passed, ±0 failed** — the
  four tests this lane adds. No pre-existing test changed verdict.

Counted with `grep -cE "^Test Case .* passed"` / `"^Test Case .* failed"`.

**Linux: PASS, aarch64** (`aarch64-unknown-linux-gnu`, `swift:6.1-jammy`,
`--build-tests`, `Build complete! (303.78s)`; log `linux-build.log`). Not
amd64 — QEMU is unusable on this host. The container rewrote `Package.resolved`
from 35 to 34 identities as expected; restored with `jj restore Package.resolved`
and re-verified at 35.

Tests added (all four are new; none replaced):

| test | file | pins |
|---|---|---|
| `testDeletionNotificationForAnUnjoinedSpaceIsANoOp` | `SpaceNotificationSQLiteTests.swift:457` | F31 step 1: no tombstone, no receipt, no pre-emptive closure; and the joined case still tombstones |
| `testRequestReceiptsPruneToRetentionDepthAndStaleReplayBecomesAConflict` | `:526` | F27: depth bound, stamps, retained→duplicate, pruned→conflict with the exact expected/actual revisions |
| `testRequestReceiptMigrationStampsExistingRowsAsOldest` | `:637` | F27: real drop-column/reopen migration; legacy row preserved at `created_at = 0` and evicted first |
| `testDeletionTokenIsNotBoundToTheBodySpace` | `SpaceNotificationHTTPTests.swift:209` | F31 **residual**: the route accepts a token paired with a different space under the same authority, and refuses a different authority |

That last one is deliberately a *documentation* test — it passes before and
after this lane. It exists so that nobody reads step 1 as having closed F31 at
the wire.

`Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift` was **not** edited; no fix
here needed it.

---

## 7. For the maintainer

1. **F31 step 2 stays open and I did not attempt it** (§4 item 10 of the
   program). The recommendation there — do not add a space claim unilaterally —
   holds after this lane, and step 1 does not depend on it. If it ever ships,
   the durable precondition should stay: it is the only bound that survives an
   issuer that does not emit the claim.
2. **Accept the lost pre-emptive closure** described at the end of §2, or say
   so and I will restore it as an explicit, separately named predicate rather
   than a side effect of a space-keyed table. My recommendation is to accept:
   it is what the pinned reference does, and the alternative hands one leaked
   authority token an unbounded permanent-row primitive.
3. **`permissioned_space_notification_receipts` and
   `permissioned_space_recipient_tombstones` still have no depth retention of
   their own.** Step 1 bounds them by participation, which on a one-account
   PDS is a very small number, so I did not add retention there — but they are
   the same ledger shape as F27 and the scan did not file them. Worth a
   follow-up alongside F21's outbox half.
