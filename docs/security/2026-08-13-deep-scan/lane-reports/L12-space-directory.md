# Lane L12 — permissioned space directory (F23, F46)

**Status:** DONE — build clean, full macOS suite green (exit 0, **1577 passed**,
zero `Some test targets reported failures`). Both findings are fixed, and both
fixes are proven by tests that fail against the unfixed source.

**Carries one accepted, undocumented wire-behaviour change** — see
[Client-visible change](#client-visible-change) below. The coordinator reviewed
and accepted it; it is to be surfaced to Josh.

**Base commit:** `c1a71eb38adf`
**Inherited (unverified) parent:** `e5199e63` — "WIP L12 (unverified)"
**Scratch / logs:** `/private/tmp/swan-lane-L12-space-directory/`

---

## What I actually ran

| Command | Log | Result |
|---|---|---|
| `swift build --build-tests` (inherited state) | `build-01-inherited.log` | exit 1 — 8 distinct errors, all in `SpaceBlobHTTPTests.swift` |
| `swift build --build-tests` (final) | `build-11-final.log` | **exit 0**, `grep -c "error:"` = 0 |
| `swift test --skip-build` (full macOS suite, final) | `suite-full-02.log` | **exit 0 — 1577 passed, 0 failed**, `grep -c "Some test targets reported failures"` = **0** |
| `swift test --skip-build` (full suite, before the test rewrite) | `suite-full.log` | exit 1 — 1576 passed, 1 failed (the 409 assertion) |
| `... --filter SpaceBlobHTTPTests` (final) | `test-blob-03.log` | exit 0, **5 passed**, Executed 5 tests, 0 failures |
| `... --filter AccountAuthorizationLeaseTests` (final) | `test-f46-01.log` | exit 0, **5 passed**, Executed 5 tests, 0 failures |
| `... --filter SpaceBlobHTTPTests` against the **base** `SwanSpaceBlobXRPC.swift` | `test-blob-PREFIX.log` | exit 1 — 4 of 5 fail (F23 regression proof) |
| `... --filter AccountAuthorizationLeaseTests` with the **fence reverted** | `test-f46-PREFIX.log` | exit 1 — the F46 test fails (F46 regression proof) |
| `... --filter ".../testConcurrentHTTPWritesExposeCASConflictsWithoutLosingCommittedFacts"` ×3 (old test) | `test-cas-run{1,2,3}.log` | fails 3/3 — deterministic, not flaky |
| `... --filter ".../testConcurrentHTTPWritesAllCommitInATotalOrderUnderTheAuthorizationFence"` (rewritten) | `test-cas-rewritten-02.log` | exit 0, 1 passed |
| same rewritten test with the **fence reverted** | `test-cas-rewritten-PREFIX.log` | exit 1, 4 assertions fail — proof it can still fail |

All commands were run as `xcrun --toolchain XcodeDefault swift ...`, in the
foreground, redirected to a file and grepped. Pass counts use exactly
`grep -cE "^Test Case .* passed"`.

**Arithmetic.** The brief's baseline is 1571. I added 6 tests (5 blob, 1 F46)
and *renamed* one existing test rather than adding or deleting one, so
1571 + 6 = **1577** expected and 1577 observed. Nothing else regressed and
nothing was quietly dropped.

I ran no Docker/Linux containers. `grep -c '"identity"' Package.resolved` is
still **35**. I ran no `swiftformat` and no `swiftlint`.

---

<a id="client-visible-change"></a>
## Client-visible change: concurrent same-account permissioned writes no longer return 409

**This is the one wire-observable consequence of this lane and it should not be
merged silently.**

F46 wraps `applyAuthorizedWrites` in
`SQLiteControlDatabase.withActiveAccountAuthorization`, which holds the
control-plane *write* transaction across the account-database batch. The
control database is one per process (`SwanSQLite.swift:9080`, a single
process-wide `withConnectionGate`), so permissioned record writes now serialize.
Every request reads a fresh repository revision and the CAS on
`expectedRevision` has nothing left to conflict with **in-process**.

Measured, not inferred. 16 concurrent `createRecord` requests to one repository:

| | statuses |
|---|---|
| before F46 | `[200, 409 × 15]` — 1 commit, 15 rejections the client must retry |
| after F46 | `[200 × 16]` — 16 commits, 16 distinct revisions, nothing lost |

No status code, error name, or wire field changed shape. What changed is how
often `409` occurs: within a single Swan process, never. Cross-process CAS via
`BEGIN IMMEDIATE` on the account database is unaffected, so `409` remains
reachable in a multi-process deployment.

**Accepted by the coordinator**, on the grounds that no AT Protocol client can
depend on receiving a 409, a 409 is a retry so removing it is strictly better
for callers, and the permissioned path now matches the public mutation path
rather than diverging from it — `PublicFirehoseCommitFence`
(`SQLitePreMigratedAccountDirectory.swift:2707-2720`) has always imposed the
same serialization on public posting, which is why public writes have never
surfaced a 409 here either.

### CAS-conflict coverage after this change: retained

The coordinator asked whether CAS-conflict rejection still has coverage
anywhere. **It does**, at the store level, and one of the two tests covers
precisely the case the fence leaves reachable:

- `Tests/SwanSQLiteTests/SwanSQLiteTests.swift:1521`
  `testSeparateConnectionsRaceThroughSQLiteCAS` — two **separate connections**
  race one `apply`; asserts exactly 1 success and exactly 1
  `SwanError.conflict(expected: 0, actual: 1)`, then checks the durable
  revision. This is the cross-connection/cross-process path, which the fence
  does not serialize.
- `Tests/SwanSQLiteTests/SwanSQLiteTests.swift:1426`
  `testCASFailureAndInvalidBatchRollBackEveryFact` — asserts
  `SwanError.conflict(expected: 0, actual: 1)` from
  `SQLiteAccountDatabase.apply` and that every fact rolls back on rejection.

What is lost is only the *HTTP-level* framing of that path — the ability to
observe a 409 emerging from concurrent requests through the router. The
rejection logic itself (`SwanSQLite.swift:11040-11041`) is still directly
exercised. This is a narrowing of coverage, not a removal of it.

### Batch size now bounds control-plane availability

Worth stating plainly, because it is new: **this lane is the first
request-path caller of `withActiveAccountAuthorization`.** The other five
callers are all in `Sources/swan/SwanCommand.swift` (`:4393`, `:4474`, `:4864`,
`:6748`, `:6926`) — operator CLI paths. The API's own doc comment
(`AccountControlStore.swift:2434-2439`) describes it as "a short final
publication fence, not a general-purpose transaction wrapper."

The fence stays inside that stated contract — `applyAuthorizedWrites` is
staged and network-free (proved below) — but it has moved from operator rate to
request rate. A large permissioned batch now holds the process-wide control
write transaction for the duration of its account-database commit, so **batch
size bounds control-plane availability process-wide**, for every account, not
just the writer's.

Mitigating fact: the public mutation path already behaves exactly this way via
`PublicFirehoseCommitFence`, so this is not a new class of coupling — it is the
permissioned path adopting an existing one. `SpaceWriteLimits.validate`
(operation count and aggregate value bytes) still caps how large a single batch
can be, and it runs before the fence is entered.

---

## What I kept, what I rewrote, and what was wrong with the inherited work

### Kept

- **The F46 source change in `SQLitePreMigratedAccountDirectory.swift`**, in
  full — the fence, `requireAuthorizationFence()`, the
  `AccountControlStoreError` → `SwanError` mapping, and the
  `installAccountTestingHooks` refactor. It compiles, it is correct, and its
  reasoning holds up (verified independently below). Zero edits.
- **The F46 test** `testPermissionedWriteRacingDeactivationNeverCommitsARejectedBatch`
  and its `LifecycleRaceProbe` / `installSpaceAccountDatabase` helpers, in full.
  Zero edits. It is a good test: the interleaving is forced through
  `beforeApplyCommit`, not slept on.
- The *shape* of the F23 change — reserve the ceiling as an admission gate,
  open, then exchange for a right-sized transfer lease; plus the response
  writer's declared-length bound.

### Rewrote

- **`Tests/SwanHTTPTests/SpaceBlobHTTPTests.swift` — substantially.** It never
  compiled and, more importantly, could not have passed against the source it
  shipped with.
- **`Sources/SwanHTTP/SwanSpaceBlobXRPC.swift` — the lease bookkeeping and the
  comments.**
- **`Tests/SwanHTTPTests/PermissionedRecordReadHTTPTests.swift`** — one test,
  under explicit coordinator clearance (see below). Not originally in this
  lane's owned-file list.

### What I found wrong with the inherited work

1. **The test file did not compile — 8 errors.** `fixture.router()` returns
   `Router<SwanHTTP.BasicRequestContext>`, which has no `buildApplication`
   (that is a `SwanHTTPServer` method). `Router<SwanHTTP.BasicRequestContext>()`
   also does not compile: the default `context:` argument is
   `Hummingbird.BasicRequestContext.self`. The five
   `type 'Equatable' has no member '.ok'/.serviceUnavailable` errors were
   **cascade** from the `buildApplication` failure, not an independent
   inference problem — the brief listed them as a separate item (#2). Fixing
   `buildApplication` fixed all five.

   The brief prescribes rewriting the fixture to vend a `SwanHTTPServer`. I did
   not. `SwanHTTPServer` builds its blob capability with a real
   `DurableSpaceCredentialVerifier`, so the fixture would have to mint signed
   `PermissionedDataJWT` credentials and stand up an
   `AuthorizedSimpleSpaceDirectory` — machinery unrelated to an admission
   finding, and it would lose the stub directory's `openCount` and the stub
   body's independent declared length, which are exactly what two of these
   tests assert on. Instead I used `Application(router:logger:)` directly — the
   same constructor `SwanHTTPServer.buildApplication` itself calls
   (`SwanHTTP.swift:1159`) — plus `Router(context: SwanHTTPRequestContext.self)`
   as `buildRouter` does (`SwanHTTP.swift:771`). Same harness, none of the
   unrelated failure modes.

2. **The inherited tests could not have passed against the inherited source,
   and the author never found out.** The fixture set both the global and the
   per-account transfer budget to **8 MiB**. The route's first act is
   `reserve(maximumBytes: 256 MiB)`. `PublicRepositorySpoolAdmission.reserve`
   (`PublicRepositoryReadDirectory.swift:906-932`) refuses outright when
   `maximumBytes > maximumGlobalBytes - global`, so with an 8 MiB budget every
   request would have 503'd and the "right-sized" test would have failed on
   status, not on bytes. The 8 MiB number belongs to the *brief's* design
   (reserve the true size up front, never the ceiling); the source shipped a
   different design. The two halves of that commit were written against
   different mental models.

   I re-sized the fixture to 512 MiB global / **384 MiB per account** and made
   that the load-bearing property: 384 MiB admits exactly one ceiling-sized
   reservation and not two, so "what is held across the stream" becomes a
   pass/fail rather than a number nobody checks.

3. **The observation point was wrong for what the finding is about.** The
   original hook fired *after* the first chunk was consumed. The finding is
   about what a **stalled** reader pins, so the hook now runs *before* the first
   `consume`, inside `streamBody`, while the transfer lease is held — exactly
   where a stalled reader sits.

4. **Lease bookkeeping could leak on an intermediate throw.** The inherited code
   used one `var streamLease` reassigned in place with
   `defer { if !handedOff { streamLease.release() } }`. Between
   `streamLease = rightSizedLease` and `admittedLease.release()` the ceiling
   lease was reachable from nothing the `defer` would release. Nothing throws
   there *today*, so this was latent, not live. I now track `admissionLease` and
   `transferLease` separately and release both in the `defer`;
   `PublicRepositorySpoolLease.release()` is idempotent, so double-release is
   safe.

5. **An off-by-shape in the writer guard.**
   `writtenBytes <= declaredLength - chunk.count` is correct but reads as if it
   could underflow. Rewritten as `chunk.count <= declaredLength - writtenBytes`,
   the same predicate with the subtraction bounded by the invariant
   `writtenBytes <= declaredLength`.

6. **The scratch file was *deleted*, not moved to `_trash/`.** The brief states
   it "was moved to `_trash/`". There is no `_trash/` directory in this
   workspace and `find . -name L12DiagTests.swift` (excluding `.build`) returns
   nothing. I kept the deletion as instructed but recovered the content to
   `/private/tmp/swan-lane-L12-space-directory/L12DiagTests.swift.recovered`
   rather than creating a new tracked `_trash/` directory that would land in the
   merge. It is a throwaway diagnostic superseded by
   `AccountAuthorizationLeaseTests`.

7. **The brief's file inventory was wrong in one place.**
   `Tests/SwanSQLiteTests/AccountAuthorizationLeaseTests.swift` is described as
   "+199, new". It is **not** new — it exists at `c1a71eb38adf` with 322 lines
   and the inherited commit adds 199 to it (522 total).

---

## F23 — right-sizing the permissioned blob transfer reservation

### Disagreement: the brief's prescribed fix is not implementable in this lane

The brief says to add a metadata-only lookup to `AuthorizedSpaceBlobDirectory`
mirroring `publicBlobMetadata`, call it before the reservation, and reserve the
real size. **That cannot be done inside this lane's owned-file list.**

`AuthorizedSpaceBlobDirectory` (owned, `AuthorizedSimpleSpaceDirectory.swift`)
and its conformance on `SQLitePreMigratedAccountDirectory` (owned) are only the
top two layers. The actual metadata read has to happen on
`SQLiteAccountDatabase`, in `Sources/SwanSQLite/SwanSQLite.swift`, which this
lane does not own. Everything it needs there is `private`, i.e. file-scoped and
unreachable from another file even within the same module:

| symbol | `SwanSQLite.swift` | access |
|---|---|---|
| `publicBlobMetadataIfReachable` | `:8365` | `private` |
| `requireReadablePermissionedBlobRepository` | `:9751` | `private` |
| `canonicalRawBlobCID` | `:10263` | `private` |
| `blobDigestHex` | `:10436` | `private` |
| `legacyBlobDigest` | `:10449` | `private` |
| `safeBlobMIMEType` | `:10487` | `private` |
| `requiredText` | `:10647` | `private` |

Reaching the size without them would mean re-implementing CAS-digest, CID, and
MIME validation a second time in a second file — duplicating security-critical
validation to dodge a scope boundary. CONSTRAINTS §0 says to stop and report
instead. **The metadata-only accessor
(`SQLiteAccountDatabase.permissionedBlobMetadata` + a `DurableSpaceRepository`
passthrough + the protocol requirement) is a clean follow-up for whoever owns
`SwanSQLite.swift`.**

### What shipped instead

The ceiling is reserved only across `directory.spaceBlob(...)` — the
open-and-verify step, which is bounded work no client can stall — and is then
**exchanged** for a lease covering exactly `blob.body.contentLength`. The
exchange acquires before it releases, so an already-admitted request can never
be turned into a refusal by the resize; the worst case is that it keeps the
ceiling it already had.

This fixes the failure mode the finding actually describes ("holds it for as
long as the reader takes"): the window a reader controls is right-sized. What it
does **not** fix is admission throughput — concurrent *opens* are still gated at
the ceiling, so 2 per account / 4 globally. That is a throughput bound on
storage work, not a stall-based denial, and closing it needs the metadata
accessor above. **F23 is therefore partially closed.**

### The brief's critical-correctness point, satisfied by a different mechanism

The brief asks for `contentLength == metadata.size` with a release on mismatch,
because "a right-sized reservation that can under-cover the actual transfer is
strictly worse than reserving the ceiling."

There is no second number to compare against here, so the guarantee is enforced
at the only place it can be violated — the wire. `contentLength` is the single
declared length: it sizes the reservation, it is emitted as `Content-Length`,
and the response writer now refuses to pass a byte beyond it and refuses to
`finish` a body that delivered fewer. The reservation therefore *cannot*
under-cover the transfer it admits. That is a stronger property than comparing
two database-derived numbers and then trusting the body to honour one of them.

`testBodyStreamingMoreThanItDeclaredDoesNotEmitTheSurplus` is the brief's
"a size smaller than the real payload cannot get through" test: the body
declares 128 KiB and delivers 129 KiB in three chunks, so the refusal happens
*mid-stream after real bytes were already written*, and the stub counts only
bytes the route's writer accepted — 131072, exactly the declared length, never
the surplus kibibyte.

### Regression proof

Against the base `SwanSpaceBlobXRPC.swift` (`test-blob-PREFIX.log`), 4 of the
5 new tests fail and only the control passes:

```
testBodyStreamingLessThanItDeclaredNeverCompletesTheResponse   failed
testBodyStreamingMoreThanItDeclaredDoesNotEmitTheSurplus       failed
testExhaustedTransferBudgetStillRefusesTheReadBeforeOpeningIt  passed   (control)
testSmallBlobReservesItsOwnLengthRatherThanTheTransferCeiling  failed
testStalledSmallReadDoesNotDenyAFurtherReadOfTheSameAuthor     failed
```

The control passing matters: it shows the budget is still enforced, and still
enforced *before* storage is touched (`openCount == 0` on refusal), so nothing
here bought the route an unbounded transfer surface.

---

## F46 — fencing `applyAuthorizedWrites`

### How I confirmed nothing under the closure re-enters the control store

Structurally, not by enumerating call sites. The closure calls
`DurableSpaceRepository.applyAuthorizedWrites`, and both
`DurableSpaceRepository` (`SwanSQLite.swift:10950`) and `SQLiteAccountDatabase`
(`:1673`) live entirely in `SwanSQLite.swift`. That whole file contains **zero**
occurrences of `AccountControlStore`, `SQLiteControlDatabase`, `controlStore`,
`PublicFirehoseCommitFence`, `URLSession`, `NIOHTTP`, or `HTTPClient`:

```
$ grep -c "AccountControlStore\|SQLiteControlDatabase\|controlStore\|URLSession\|PublicFirehoseCommitFence\|NIOHTTP\|HTTPClient" Sources/SwanSQLite/SwanSQLite.swift
0
```

Positive controls, because an absence claim is worthless without one:

```
$ grep -c "AccountControlStore\|SQLiteControlDatabase\|controlStore" Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift
37                       # the pattern is findable
$ grep -c "SQLiteAccountDatabase" Sources/SwanSQLite/SwanSQLite.swift
9                        # grep does read this file
```

`SQLiteAccountDatabase`'s stored properties (`:1747-1763`) are a connection, a
connection gate, a data directory, a DID, retention/quota/mode flags, three file
descriptors, an external-body lease gate, testing hooks and two counters — no
control-store handle and no network client. Its imports are `Crypto`,
`Foundation`, `Petrel`, `SQLiteNIO`, `SwanCore`, `SwanPublicRepository`,
`SwanSpaces`, `SwanStorage`, `Darwin`/`Glibc`. There is no path from inside the
fence back to the control store, and no network I/O — the precondition
`withActiveAccountAuthorization` documents at `AccountControlStore.swift:2434-2439`.

**Lock order.** The fence takes control gate → account-database gate. That order
already exists: `PublicFirehoseCommitFence.apply`
(`SQLitePreMigratedAccountDirectory.swift:2707-2720`) holds
`withActiveAccountFirehoseAuthorization` and calls `mutate`, which performs an
account-database mutation. No new inversion.

### Regression proof

Reverting only the fence (keeping `installAccountTestingHooks` so the file still
compiles) and re-running `AccountAuthorizationLeaseTests` (`test-f46-PREFIX.log`)
reproduces the defect exactly as described:

```
XCTAssertNil failed: "PersistedSpaceRecord(uri: at://.../raced, ..., revision: 1)"
  - a permissioned batch rejected for a racing deactivation must not be durable;
    the post-commit check cannot roll back the write it rejects
    (unauthorized: account repository is unavailable)
```

The write is durable **and** the caller is told `unauthorized`. With the fence,
the deactivation queues behind the batch's control lease and the batch is
admitted and durable — one consistent outcome instead of two contradictory ones.

### One residual trade

`requireAuthorizationFence()` downcasts `controlStore` to `SQLiteControlDatabase`
and fails **closed** (`SwanError.unavailable`) when the downcast fails, because
`withActiveAccountAuthorization` is a concrete `SQLiteControlDatabase`
capability, not an `AccountControlStore` requirement. Any deployment or test
that injects a non-`SQLiteControlDatabase` control store into
`SQLitePreMigratedAccountDirectory` therefore loses `apply` entirely rather than
silently reverting to the post-commit recheck. Nothing in the tree does this —
the full suite is green on that path — but it is a hard dependency worth
recording. Lifting it means adding `withActiveAccountAuthorization` to the
`AccountControlStore` protocol, which is outside this lane.

---

## The one test I edited outside my original list

`Tests/SwanHTTPTests/PermissionedRecordReadHTTPTests.swift` was not in this
lane's owned-file list. I did **not** touch it when its
`XCTAssertGreaterThan(statuses.filter { $0 == 409 }.count, 0)` began failing; I
stopped and asked the coordinator, who confirmed no other lane owns the file and
cleared me to take it — with the explicit instruction not to weaken it into a
test that cannot fail.

`testConcurrentHTTPWritesExposeCASConflictsWithoutLosingCommittedFacts` →
`testConcurrentHTTPWritesAllCommitInATotalOrderUnderTheAuthorizationFence`.
The CAS-conflict framing in the old name is no longer true, so the name went
with the behaviour. It now asserts what the fence must never break:

- no request fails in transport,
- **all 16** return `200` (a 409 here means the fence stopped serializing — the
  failure message says so, with the observed status vector),
- exactly 16 oplog entries, matching the count of accepted writes,
- rkeys `race-0 … race-15` each land **exactly once** — the "no acknowledged
  fact is lost" guarantee, stated concretely rather than as a count,
- 16 distinct wire revisions, and 16 distinct, non-decreasing durable revisions
  — a total order with no revision reuse.

A doc comment on the test names the fence, cites `PublicFirehoseCommitFence` as
the precedent, states that the 409 branch is unreachable **in-process by
design**, and points at the two `SwanSQLiteTests` cases that still cover CAS
rejection directly — so the next reader does not "fix" the 409 assertion back in.

**It is not a test that cannot fail.** With the fence reverted
(`test-cas-rewritten-PREFIX.log`) it fails on four assertions at once:

```
statuses: [200, 409, 409, 409, 409, 409, 409, 409, 409, 409, 409, 409, 409, 409, 409, 409]
("1") is not equal to ("16")                      # accepted writes
("1") is not equal to ("16")                      # durable oplog entries
(["race-3"]) is not equal to ([... all 16 ...])   # facts lost
```

That is also the clearest statement of what the old behaviour cost callers:
15 of 16 concurrent writes rejected and requiring a retry.

---

## Open items for the coordinator

1. **F23 is partially closed.** The metadata-only accessor on
   `SQLiteAccountDatabase` is still needed to stop reserving the ceiling across
   the open, and requires a lane that owns `Sources/SwanSQLite/SwanSQLite.swift`.
2. **The 409 change needs to reach Josh** as an accepted-but-undocumented wire
   change, together with the note that its only remaining coverage is at the
   store level, not through HTTP.
3. **`withActiveAccountAuthorization` is now on a request path** for the first
   time. If control-plane contention shows up under load, this is the change to
   look at first, and the fix is a narrower per-DID authorization lease rather
   than backing out the fence.
