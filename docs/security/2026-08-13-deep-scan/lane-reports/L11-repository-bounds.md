# L11 — public-repository-bounds

Lane closes: the unfiled record-index ceiling (lead item), **F28**, **F30**
(hardening + the coverage that was actually missing). Based on `77bab90c5e79`.

Every citation below was re-resolved against the merged tree; the program's
line numbers predate seven landed lanes and several had drifted (noted inline).

---

## 1. The unfiled item — repository writes past the public read ceiling

**Verdict: CONFIRMED, and it is the sharpest item in the lane.** Not in the
scan's finding list at all.

### What is actually there

- `PublicRepositoryReadLimits.maximumGenerationIndexEntries = 100_000` —
  `Sources/SwanStorage/PublicRepositoryReadDirectory.swift:528`.
- Enforced on **every public read**: `admitPublicRepositoryGeneration`
  (`Sources/SwanSQLite/PublicRepositoryReadStore.swift:241`) →
  `namedProjectionVerificationWithoutGate`
  (`Sources/SwanSQLite/PublicRepositoryStore.swift:962`) →
  `preflightPublicReadProjectionWithoutGate`
  (`PublicRepositoryReadStore.swift:481`), which throws
  `PublicRepositoryReadError.resourceLimitExceeded` at
  `PublicRepositoryReadStore.swift:529-534`. Program cited `:529-534` — correct.
- Enforced again on projection verification at `PublicRepositoryStore.swift:990-992`
  (program cited `:945-948`; it was `:986-989` at the merged tree, drifted ~41
  lines, and this lane's own edits moved it again).
- **Not enforced anywhere on the write path.** `applyPublicRepositoryMutation`
  (`PublicRepositoryStore.swift:440-697` pre-change) writes the record index at
  `:574-605` with an upsert per create/update and a delete per delete, and
  counts nothing.

So ~100,001 `createRecord` calls — inside the Cloudflare 600 req/10 s budget,
roughly 28 minutes — permanently break `getRecord`, `listRecords`,
`getLatestCommit` and `getRepo` for that account while writes keep returning
200. Self-inflicted, no attacker, and the account cannot read its way out.

### Fix

`refuseGrowthPastPublicReadCeilingWithoutGate`
(`Sources/SwanSQLite/PublicRepositoryStore.swift:1217`), called from inside the
commit transaction immediately before the record-index writes and immediately
after `validatedProjection` (now `:1267`).

### Counter design — measured, and `COUNT(*)` won

The brief preferred a maintained counter column. I chose `COUNT(*)` on evidence
plus one hard constraint:

- **Measured.** `SELECT COUNT(*) FROM public_repository_record_index` over a
  full 100,000-row index, on the exact schema with the account database's
  production pragmas (`journal_mode=WAL`, `busy_timeout=5000`,
  `foreign_keys=ON`): **p50 0.66 ms, p95 0.81 ms, max 0.90 ms warm; 0.78 ms
  p50 on a fresh connection.** `EXPLAIN QUERY PLAN` confirms
  `SCAN … USING COVERING INDEX sqlite_autoindex_public_repository_record_index_1`
  — SQLite's optimized count path over the smallest index, not a table scan.
  Method: SQLite C library against a replica of the schema, 100 iterations;
  this isolates the b-tree cost, which is the whole term that scales. The
  surrounding commit has already rebuilt an MST path, signed a commit, written
  every new block and built two CARs.
  - For contrast, a `SELECT COUNT(*) FROM (SELECT 1 … LIMIT n)` "bounded" form
    is **5× slower** (p50 3.3 ms) because it defeats that optimization. Do not
    reach for it.
- **The query does not run on the common path at all.** It is guarded by
  `growth > 0`; update-only and delete-only commits never issue it.
- **Hard constraint.** A counter column needs a schema change, and
  `public_repository_record_index` is declared in
  `Sources/SwanSQLite/SwanSQLite.swift:440-446`, which this lane does not own
  (L10's file). It would also add a drift surface between the counter and the
  index that `namedProjectionVerificationWithoutGate` would then have to verify
  as well — a third thing that can disagree with the MST.

**Migration required: none.** No schema change, no new column, no new table.
Effect on the live database with one real account's data: **zero** — the guard
is a read-only `COUNT(*)` inside the existing commit transaction. The one real
account is nowhere near 100,000 records, so the guard never fires and no
existing behaviour changes.

### Only growth is refused

`growth = creates − deletes`, and the guard returns early unless `growth > 0`.
This is exact, not approximate: `validatedProjection`
(`PublicRepositoryStore.swift:1267`) has already proved every
`.create` path is **absent** from the index and every `.delete` path is
**present**, and rejects duplicate paths within a batch. A repository that
somehow ends up over the ceiling — import, older build, operator repair — can
therefore always shrink. A check that refused deletes on a full repository
would be a trap with no exit.

### Error choice — a maintainer decision

The guard throws `PublicRepositoryReadError.resourceLimitExceeded`, the same
error the read path raises for the same bound. `PublicRepositoryMutationStoreError`
is declared in `Sources/SwanStorage/PublicRepositoryStore.swift:5-17`, which
this lane does not own, so no dedicated `recordCeilingExceeded` case was added.
`SwanPublicRepositoryMutationCoordinator.map` (`SwanPublicRepositoryMutationXRPC`
chain, `SwanPublicRepositoryMutationCoordinator.swift:265-281`) maps anything
unrecognised to `.unavailable`, which is the correct client-visible answer for
a repository at capacity and **widens no error body**. If a distinct wire code
is wanted, that needs a case on the `SwanStorage` enum.

---

## 2. F28 — repository-wide leaf ceiling

**Verdict: CONFIRMED as a gap, but the scan overstates it, and it missed an
existing control.**

- The per-node caps are real and cited correctly in spirit:
  `guard node.entries.count <= …MSTEntriesPerNode` — post-change
  `RepositoryMSTValidation.swift:420` in `validateProjection` and `:198` in
  `validate` (the program cited `:387`). Neither bounds the aggregate leaf set.
- **The scan missed `reachableBytes`.** Post-change
  `RepositoryMSTValidation.swift:399` declares it in `validateProjection`,
  `:418` and `:533` accumulate every reachable MST and record block into it
  (`:177`, `:195`, `:322` for `validate`), and `adding(_:to:maximum:)` throws
  `reachableRepositoryByteLimitExceeded` past `limits.maximumCARBytes` =
  **512 MiB**. So this was never an unbounded server-side allocation. It is a
  bounded blow-up on an **operator-only CLI path** (`swan import-public`), and
  it should not be described as anything more.

What the cap actually buys is consistency: without it an import can publish a
repository whose record count the read path then refuses — a repository nobody
can read, which is item 1 arriving by a different door.

**Fix.** New `PublicRepositoryLimits.maximumRepositoryRecords`, defaulted to
`standardMaximumRepositoryRecords = 100_000`, checked before each
`leaves.append` in **both** validators — `RepositoryMSTValidation.swift:262`
(`validate`) and `:475` (`validateProjection`) — throwing a new
`RepositoryMSTValidationError.recordLimitExceeded`.

The init parameter is **defaulted** rather than required, deliberately: durable
import-session rows persist the six work budgets they were opened with
(`SwanSQLite.swift:481-496`) and are reconstructed at
`Sources/SwanSQLite/PublicRepositoryImportStaging.swift:1197, :1469` and
`Sources/SwanStorage/PublicRepositoryImportStagingStore.swift:44` — files this
lane does not own. Defaulting keeps those reconstructions compiling and gives
them the standard ceiling.

**Comparator hoist.** `leaves.sort { Data($0.path.mstKey.utf8)
.lexicographicallyPrecedes(Data($1.path.mstKey.utf8)) }` built two `Data`
values on *every comparison* — on the order of `2·n·log n` allocations for a
repository-sized sort. Both validators already compute
`let key = Data(leaf.path.mstKey.utf8)` at the append site for the subtree
range check and threw it away; they now keep it in a parallel `leafKeys` array
and sort through `sortedByMSTKey(_:keys:)` (`RepositoryMSTValidation.swift:590`).
One `Data` per leaf. As the brief said, a bigger constant-factor win than the
cap.

**Read-path classification.** `validateProjection` also runs on every read
admission, and `namedProjectionVerificationWithoutGate`'s generic `catch` maps
unknown errors to `.unavailable(reason: .storageFailure)`. A new
`recordLimitExceeded` escaping there would be misdiagnosed as a storage fault,
so it is now caught explicitly and re-raised as
`PublicRepositoryReadError.resourceLimitExceeded`
(`PublicRepositoryStore.swift`, beside the existing
`PublicRepositoryMutationStoreError` branch). It is only reachable when the MST
and the index disagree — for a consistent repository the preflight raises the
same bound first.

---

## 3. F30 — REFUTED as filed; the tests were the point

**Verdict: the refutation is correct, and there is a second control the program
did not name.**

The conversion phase genuinely did not advance depth through objects
(`PublicRepositoryRecordCodec.swift:107, 130, 141, 183, 193` pre-change: the
`convertCBOR` map branches had **no depth guard at all**). But:

1. Every HTTP feeder is depth-capped upstream by
   `StrictPermissionedWriteJSON.validate` at 64 for **both** containers —
   verified: parser at `Sources/SwanHTTP/SwanSpaceXRPC.swift:1167-1263`, gate at
   `:1187`, advancing at `:1191-1192`.
2. Stored blocks are capped by `RepositoryRecordBlockValidator`
   (`RepositoryMSTValidation.swift:576+`), which enters at `readMap(depth: 1)`
   and guards `depth < maximumDepth` before each nested container — **64 object
   levels, exactly**.
3. **The control the program did not name:** `prepare`'s own encoder already
   refused what conversion accepted. `encodeObject` guards `depth <= maximumDepth`
   and `encode`'s `.object` case recurses at `depth + 1`
   (`PublicRepositoryRecordCodec.swift:354, 399`). Since nothing reaches storage
   without `prepare`, there was no durable bypass even at the package-public API.

So: not a control bypass, and the residual was strictly a maintainability
inconsistency. **Do not re-file it as a vulnerability.**

### What was real: zero test coverage of the load-bearing gate

`grep -rln StrictPermissionedWriteJSON Tests` returned nothing at the merged
tree. It is the depth / duplicate-key / trailing-garbage gate for five write
surfaces — `SwanSpaceXRPC.swift:1083`,
`SwanPublicRepositoryMutationXRPC.swift:678`,
`SwanSpaceCredentialXRPC.swift:236`, `SwanSimpleSpaceXRPC.swift:558`,
`SwanSpaceNotificationXRPC.swift:504`.

`Tests/SwanHTTPTests/StrictWriteJSONTests.swift` (new) adds six tests:

- 64-vs-65 **object-only** nesting (the case with no coverage anywhere);
- 64-vs-65 array-only nesting;
- alternating object/array levels sharing one budget — pins that the counter is
  neither reset nor double-advanced by a container switch;
- duplicate keys refused at the top level and three levels down, while the same
  key at sibling levels is accepted;
- empty body, trailing garbage, and trailing whitespace accepted;
- **route-level**: a 65-level `createRecord` body on the live public write
  surface answers **400 `InvalidRequest`** and leaves `loadPublicRepositoryState`
  byte-identical, paired with an otherwise identical shallow request that
  answers 200 and does advance the state — so the 400 is attributable to the
  gate and not to auth or plumbing.

Note for whoever reads this next: the route test needs a fully authorized DPoP
request because **L4 has landed** — `withPublicMutationInput` now authorizes on
headers before body admission (`SwanPublicRepositoryMutationXRPC.swift:643-651`),
so an unauthenticated over-deep body 401s before ever reaching the gate.

**`StrictPermissionedWriteJSON` was NOT moved out of `SwanSpaceXRPC.swift`** —
that file belongs to L12. §4 item 15 of the program recommends the move; it is
deferred, and the tests reach the gate via `@testable import SwanHTTP` where it
lives.

### Optional hardening: taken

Conversion now mirrors the encoder exactly. `depth` names the level a
*container* occupies, the record object is level 1, and both containers advance
it: `convert`'s `.object` and `.unknownType` cases recurse at `depth + 1`, both
`convertCBOR` map branches gained the guard they never had and recurse at
`depth + 1`, and the `.knownType` entry point passes `depth: 0` so the
top-level map still lands on level 1. Array accounting is unchanged.

This is a read-path strictness change over durable data, so: **nothing already
stored can be refused by it.** Every durable record passed either `prepare`'s
encoder or `RepositoryRecordBlockValidator`, and both cap object nesting at the
same 64. Ran `SwanPublicRepositoryTests` and `SwanSQLiteTests` rather than
assuming — both green, including the two read-path call sites that convert
stored blocks (`PublicRepositoryReadStore.swift:130, :225`).

---

## 4. Exact pre-fix failures

Each guard was disabled in turn against the finished tests, and the failure
observed rather than predicted.

**Record ceiling** (guard short-circuited):

```
PublicRepositoryRecordCeilingTests.swift:82: error: -[…testCreateThatWouldCrossTheReadCeilingIsRefused] :
  XCTAssertEqual failed: ("nil") is not equal to
  ("Optional(SwanStorage.PublicRepositoryReadError.resourceLimitExceeded)")
  - a create that would push the record index past the read ceiling must be refused
PublicRepositoryRecordCeilingTests.swift:89: error: […] :
  XCTAssertEqual failed: ("100001") is not equal to ("100000")
  - the refused create must leave no durable index row
```

The 100,001st create commits. In the same run
`testRecordIndexOverTheCeilingRefusesEveryPublicRead` **passed** — that is the
whole demonstration in one run: at 100,001 rows reads are already dead and
writes still succeed.

**F28 leaf ceiling** (limit replaced with `Int.max`):

```
PublicRepositoryDomainTests.swift:524: error: -[…testValidationRefusesMoreLeavesThanTheRepositoryRecordCeiling] : failed - expected recordLimitExceeded
PublicRepositoryDomainTests.swift:529: error: […] : failed - expected recordLimitExceeded
```

Both validators, `validate` and `validateProjection`.

**F30 codec mirror** (object recursion reverted to `depth`):

```
PublicRepositoryDomainTests.swift:578: error: -[…testRecordConversionAndEncodingAgreeOnObjectNestingDepth] :
  XCTAssertThrowsError failed: did not throw an error
```

65 object levels convert cleanly while `prepare` refuses them.

The six `StrictWriteJSONTests` cases are **characterization, not regression**.
`SwanSpaceXRPC.swift` is byte-identical to the merged tree — this lane did not
touch it — so they describe behaviour that already held. That is the point: the
gate works, and now something proves it.

---

## 5. Suite

| | passed | failed | targets |
|---|---|---|---|
| Baseline (merged tree, stated) | 1543 | 0 | 11/11 |
| This lane | **1556** | **0** | **11/11** |

Delta **+13 passed, ±0 failed**, all thirteen new: 4 record-ceiling, 6 strict
JSON, 3 domain. `swift test` exit code 0; `grep -c "Some test targets reported
failures"` = 0. Counted with `grep -cE "^Test Case .* passed"` /
`"^Test Case .* failed"`; targets with
`grep -cE "^Test Suite '.*\.xctest' passed"`. Full log:
`/private/tmp/swan-lane-L11-repository-bounds/07-full-suite.log`.

`grep -c '"identity"' Package.resolved` = **35**. The `swift:6.1-jammy`
container did rewrite it to 34 by dropping `swift-configuration`, exactly as
documented; it was restored from `77bab90c5e79` before the commit.

## 6. Linux

`swift build --build-tests` in `swift:6.1-jammy` per the recipe, scratch inside
the mount. Result: see the "Linux" line in the handoff summary — the container
is **aarch64**, not x86_64, so it proves the source compiles on Linux/Glibc and
does **not** prove the deployable x86_64 artifact. `--platform linux/amd64` was
not attempted (QEMU signal 4 on this host).

---

## 7. Files touched

Owned by this lane:

- `Sources/SwanSQLite/PublicRepositoryStore.swift` — write ceiling; MST
  record-limit error classified on the read path.
- `Sources/SwanPublicRepository/RepositoryMSTValidation.swift` — leaf ceiling in
  both validators; `recordLimitExceeded`; comparator hoist.
- `Sources/SwanPublicRepository/PublicRepositoryLimits.swift` —
  `maximumRepositoryRecords`, its permitted range, its error case.
- `Sources/SwanPublicRepository/PublicRepositoryRecordCodec.swift` — conversion
  depth mirrors the encoder.
- `Tests/SwanPublicRepositoryTests/PublicRepositoryDomainTests.swift` — F28 and
  codec-depth tests.
- `Tests/SwanHTTPTests/StrictWriteJSONTests.swift` (new).

`Sources/SwanSQLite/PublicRepositoryReadStore.swift` was read and cited but
needed no change — the read-side bound was already correct; the write side was
the gap.

**Two files outside the stated list**, both flagged for review:

1. `Sources/SwanInterop/PublicRepositoryCARReplication.swift:212` — **one line**.
   `repositoryCode(_:)` at `:190` is an exhaustive `switch` over
   `RepositoryMSTValidationError`; adding a case to a public enum makes it
   non-exhaustive and the build fails. Added
   `case .recordLimitExceeded: return "RecordLimitExceeded"`, matching the
   surrounding naming. No lane in the program owns this file.
2. `Tests/SwanSQLiteTests/PublicRepositoryRecordCeilingTests.swift` — **new
   file**. The brief's test list has no `SwanSQLiteTests` entry, but the test
   that matters demonstrates the *read breakage*, and both the ceiling and the
   preflight live in SQLite; it is not expressible in
   `SwanPublicRepositoryTests`. A new, distinctly named file cannot collide
   with L5's `PublicLifecycleEmitterTests.swift` or L10's
   `SpaceNotificationSQLiteTests.swift`.

`Sources/SwanHTTP/SwanSpaceXRPC.swift` was **not** touched (L12).

The tests pad `public_repository_record_index` with one recursive
`INSERT … SELECT` rather than committing 100,000 real records. That is sound
here and the file says so: the bound is a property of the index's cardinality,
the read preflight reads only that table, and the mutation path's own
consistency checks are per-path lookups that padding rows elsewhere cannot
affect.

---

## 8. Open for the maintainer

1. **Wire code for a repository at capacity.** The write ceiling currently
   surfaces as `.unavailable`. A distinct client-visible code needs a case on
   `PublicRepositoryMutationStoreError` in `Sources/SwanStorage/`.
2. **`StrictPermissionedWriteJSON` relocation** (§4 item 15) is deferred to
   whoever owns `SwanSpaceXRPC.swift` after L12. The tests do not depend on
   where it lives.
3. **100,000 is now enforced in three places** — the read preflight, the
   projection check, and the import validator — plus the new write guard.
   `PublicRepositoryRecordCeilingTests.testWriteCeilingMatchesTheImportLeafCeiling`
   pins the two module-level constants together. If that number is ever
   revisited, revisit it as one number.
4. **One dimension of the same shape is still uncounted.** The blob-promotion
   walk carries two static per-account bounds
   (`Sources/SwanStorage/PublicRepositoryReadDirectory.swift:538-539`).
   `maximumBlobPromotionIndexEntries` is also 100,000 and is now covered for
   free by the write ceiling. `maximumBlobPromotionUniqueCIDs` is **not**: it
   counts distinct blob CIDs, and one record can reference many, so a
   repository well under 100,000 records can still cross it
   (`PublicRepositoryReadStore.swift:137-141`) and lose
   `publicRepositoryBlobCIDs` — which is what permissioned blob promotion
   consults. Same shape as this lane's lead item, different axis; not filed by
   the scan, not fixed here.
