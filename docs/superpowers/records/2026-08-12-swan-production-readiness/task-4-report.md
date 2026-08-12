# Task 4 — Demote `data_version` to change detection

**Commits:**
- `6961078b7c43` "SwanSQLite: treat data_version movement as change detection" (original)
- `04c68d89fb0a` "SwanSQLite: name and bound reason-less public read admission failures" (fix round)

**Baseline:** `af6c92c82874` (Task 3)
**Suite (after fix round):** exit 0, **1434** `Test Case '-[...]' passed`, 0 failed, no
`Some test targets reported failures`, all 11 xctest bundles reported `passed`.

---

## Fix round — 2026-08-12

Both review findings were reproduced against the source before anything was changed, and both are
addressed below. Neither is disputed; one is upheld with an added correction to its premise.

### Finding 2 (fixed) — reason-less admission failures were neither journalled nor bounded

**Confirmed exactly as written.** `PublicRepositoryReadError.resourceLimitExceeded` carries no
`unavailableReason`, and both `logPublicReadAdmissionFailure` and
`recordPublicReadReadmissionFailure` early-returned on `nil`. I traced the reachability chain
rather than accepting it: `admitPublicRepositoryGeneration` (`PublicRepositoryReadStore.swift:259`)
→ `namedProjectionVerificationWithoutGate` (`PublicRepositoryStore.swift:917`) → its **first**
statement, `preflightPublicReadProjectionWithoutGate` (`:924`), which paginates
`public_repository_record_index` 256 rows at a time and throws `.resourceLimitExceeded` at
`PublicRepositoryReadStore.swift:533` / `:556`. Two further admission-reachable producers exist that
the finding did not name: `PublicRepositoryStore.swift:947` (post-projection record count) and
`PublicRepositoryReadDescription.init` (`PublicRepositoryReadDirectory.swift:349`, `:362` — the
`describeRepo` collection count/byte caps), which admission calls at
`PublicRepositoryReadStore.swift:432`. So the hole is wider than one call site.

`refreshPublicReadGeneration`'s `catch let error as PublicRepositoryReadError` rethrows it
untouched, `admitPublicReadGenerationForRequest` hands it to the recorder, and
`withPublicReadGeneration` does not retry it — so it reached the caller as a bare
`.resourceLimitExceeded` with **zero** journal lines and **zero** negative-cache entries. Measured,
not argued: under the falsification break below the whole test emitted `0` lines matching
`public read admission refused`, and one refusal cost **6** full admissions instead of 1.

**Fix.**

- `Sources/SwanStorage/PublicRepositoryReadDirectory.swift` — new reason
  `projectionBoundExceeded`. I did **not** reuse `.admissionBudgetExhausted` as the finding
  suggested. That case means a shared, load-dependent lease refusal that clears when traffic drops;
  this one is a property of the account's own data and repeats identically until an operator
  changes the data or the limit. Collapsing them would send the next incident at load shedding when
  the cause is one oversized account — the precise misdirection this enum exists to prevent, per its
  own header comment. The golden list in `PublicRepositoryReadDiagnosticsTests` was updated in the
  same commit, as its contract requires, and the exhaustive `isChangeDetection` switch forced the
  new case to be classified (`false`) at compile time.
- Same file — new `PublicRepositoryReadError.admissionFailureReason`. Exhaustive over the error, no
  `default`. `.unavailable` answers its own reason; `.resourceLimitExceeded` answers
  `.projectionBoundExceeded`; `.invalidSelector` / `.invalidLimit` / `.invalidCursor` answer `nil`
  **deliberately** — they are decided from the request, no admission path can raise one, and
  recording one *would* be a regression: the negative cache replays as
  `.unavailable(reason:)`, so a cached request-shape error would convert that DID's `400` into a
  `503` for every other caller for the whole window. This is the one place I narrowed the finding's
  proposed fix ("record a synthetic reason for reason-less read errors") rather than applying it
  literally.
- `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:1828, :1985` — both consumers now
  classify through `admissionFailureReason`.

**Client-visible behaviour is unchanged**, and this was checked rather than assumed.
`.resourceLimitExceeded` already had no `catch` clause of its own in `SwanPublicRepositoryReadXRPC`
(only `.invalidSelector` / `.invalidLimit` / `.invalidCursor` are caught into `400`), so it fell to
the generic `catch` → `publicReadUnavailable` → `503 {"error":"temporarily_unavailable"}`. The
suppressed replay is `.unavailable(reason: .projectionBoundExceeded)`, which lands in the same
generic `catch` and the same body. The only difference at the HTTP edge is that
`publicReadDiagnosticToken` now prints `projectionBoundExceeded` instead of `unclassified` for the
replayed refusal. `PublicRepositoryCARReplication.swift:518`, which catches
`.resourceLimitExceeded` by name, is unaffected: it calls `database.publicRepositoryBlobCIDs()`
directly and never goes through directory admission.

**Test.** `testReasonlessAdmissionFailureIsNamedAndBounded` in
`Tests/SwanSQLiteTests/PublicRepositoryReadStaleGenerationTests.swift`. It asserts the caller still
receives `.resourceLimitExceeded` **unchanged** and that it genuinely carries no reason (so the test
cannot silently drift onto the already-covered named path), that the failure is now recorded, that
all five read shapes then refuse from the recorded entry with `.projectionBoundExceeded` adding
**zero** further admissions, and that the bound is still a window rather than a wall — past 250 ms
the account admits again. `CountingPLCVerifier` grew `rejectEverything(throwing:)` so an admission
can refuse with a whole `PublicRepositoryReadError` rather than only a reason; `captureRefusal` is
now a thin wrapper over a new `captureRefusalError`, since the old helper could not distinguish "no
reason" from "did not refuse". Plus `testReasonlessReadErrorsAreClassifiedForTheJournal` in the
diagnostics tests, which pins the mapping totally, including that `.unavailable` still answers its
own reason for every `allCases` value.

**Falsification.** Both consumers reverted to `error.unavailableReason` (source only, tests
untouched), rebuilt, re-run. The new test failed at exactly the predicted points and nowhere else:
line 333 (`XCTAssertTrue` — nothing recorded), lines 343 ×5 (`nil` where
`.projectionBoundExceeded` was expected, once per read shape), line 350 (`("6") is not equal to
("1")` — six full admissions inside a window that must cost one). `grep -c "public read admission
refused"` over that run returned **0**. Restored; `grep -rn FALSIFICATION Sources/ Tests/` → none.

### Finding 1 (upheld, with a correction) — out-of-list files: ratification requested

The finding is factually right about the diff and I am not disputing it. The brief named one source
file; the original commit changed three, and the behavioural change lived in two of them. That
should have been flagged in the report as a scope expansion, and it was not. **Flagged here, and
carried into this round's structured concerns for the controller to ratify or reject.** The full
out-of-list set across both commits:

| File | Change | Why |
|---|---|---|
| `Sources/SwanStorage/PublicRepositoryReadDirectory.swift` | `isChangeDetection`; `projectionBoundExceeded`; `admissionFailureReason` | Design spec D3 is "`data_version` becomes change detection"; the enum it is a property of lives here. Finding 2's fix is not expressible anywhere else. |
| `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift` | negative-cache and journal classification | The two consumers of both properties. |
| `Tests/SwanSQLiteTests/PublicRepositoryReadDiagnosticsTests.swift` | golden list + classifier test | Contractually required by the golden list when a reason is added. |

The reviewer's verification of the *reachability* claim is correct and I confirmed it independently:
the `.generationPinStale` re-pin at `PublicRepositoryReadStore.swift:457-460` and the recheck at
`:924-929` are both inside the single `readTransaction` opened at `:246`, so `PRAGMA data_version`
is snapshot-frozen for the whole admission and neither can fire today.

**One premise of the finding no longer holds, however.** It says the commit "guards a path that is
provably unreachable today". That was true of the `!reason.isChangeDetection` clause in isolation.
After this round, the line the finding anchors to
(`SQLitePreMigratedAccountDirectory.swift:1828`) is *load-bearing today*: the same `guard`
statement now also carries the `admissionFailureReason` classification that fixes a live,
reachable, unbounded-cost bug. The file was going to be edited on this line regardless of how
Finding 1 is adjudicated. Concretely:

- If the controller **ratifies**: nothing to do; the diff stands as written.
- If the controller **rejects** the `data_version` half specifically: the revert is exactly two
  tokens — drop `, !reason.isChangeDetection` from `:1828-1829` and revert the `where` clause at
  `withPublicReadGeneration:1666` to the literal `== .generationPinStale`. That would fail
  `testStalePinIsNeverRecordedAsAnAdmissionFailure` and nothing else, and `isChangeDetection` would
  become unused. The Finding-2 fix is independent of that revert and does not need to move.

**Not done, deliberately:** `publicReadDiagnosticToken` in `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift`
still answers `"unclassified"` for a `.resourceLimitExceeded` that reaches the HTTP edge without
passing through admission. Switching it to `admissionFailureReason` is a one-line improvement, but
it is a fourth out-of-list file in a round whose other finding is about unflagged scope, and the
edge is not blind there — it already logs one line per refusal. Raised as a follow-up rather than
taken.

---

## What the brief asked, and what was actually left to do

Brief Step 3: *"`data_version` movement maps to `.generationPinStale` (re-admit) rather than a
hard failure. `fileIdentity` and `state` keep their meaning."*
Brief file/line: `Sources/SwanSQLite/PublicRepositoryReadStore.swift:796-797`.

Those original lines were the `data_version` clause of the compound guard in
`requirePublicRepositoryGenerationWithoutGate`. **Task 1's F1 fix already split that guard and
already mapped the clause to `.generationPinStale`, and Task 2 already re-admits on that reason.**
So the literal target of Step 3 was landed before this task began. The brief anticipates this
("with Tasks 2-3 in place this is belt and braces") and the design spec's D3 says the same:
"With D1 in place it is harmless. Without D1 it is a liveness landmine armed by any future
component that opens a second connection."

I therefore treated Task 4 as: **find where `data_version` movement can still produce a hard
failure, close it, and make the demotion structural rather than incidental.** I found one, and it
is real.

## The gap found: the negative cache could be poisoned with `.generationPinStale`

`.generationPinStale` has exactly one defined meaning in this codebase — *re-admit* — and
`withPublicReadGeneration` is built around it. But `recordPublicReadReadmissionFailure` recorded
**any** `PublicReadUnavailableReason` into `publicReadReadmissionFailures`, and that entry means
the opposite: *refuse for 250 ms without admitting*.

The two meanings collide on the recovery path itself:

1. read finds a drifted pin → `withPublicReadGeneration` catches `.generationPinStale`
2. → `readmitPublicReadGeneration` → `admitPublicReadGenerationForRequest`
3. that function **consults the negative cache first** (`SQLitePreMigratedAccountDirectory:1731`)
4. if the entry holds `.generationPinStale`, the re-admission is suppressed and the request 503s
5. and every read for that DID stays dark for the rest of the window

That is the 2026-08-12 outage again — a stale pin making an admittable account unreadable —
reached through the path built to end it, merely time-boxed to 250 ms. A stale pin would suppress
its own recovery.

### Reachability today

Currently **unreachable**, and only by accident of SQLite semantics. The only producer of
`.generationPinStale` inside an *admission* is the end-of-admission re-pin at
`PublicRepositoryReadStore.swift:438-443`, and that guard cannot fire, because the whole admission
runs inside one `readTransaction`. I verified this empirically rather than assuming it:

```
first_read=1
dv_in_txn_1=2
foreign insert done          <- a second connection commits here
dv_in_txn_2=2                <- frozen inside the open read transaction
rows_in_txn=1
dv_after_commit=3            <- advances only once the snapshot is released
```

So the poison is one refactor away (split admission across transactions; add any
admission-internal pin check) rather than impossible. That is precisely D3's landmine, and closing
it is the substantive content of this task.

## Changes

### `Sources/SwanStorage/PublicRepositoryReadDirectory.swift` (+63)

New `PublicReadUnavailableReason.isChangeDetection`. One named property saying "this reason
reports that something committed, not that the account is invalid". True for `.generationPinStale`
and nothing else; `.fileIdentityMismatch`, `.repositoryStateMismatch` and `.repositoryStateMissing`
are explicitly listed among the falses, which is the brief's "`fileIdentity` and `state` keep their
meaning" made mechanical.

The switch is **exhaustive with no `default`**, so a reason added later cannot silently inherit an
answer — the same compile-enforcement discipline as Task 1's F2 fix. No enum case was added, so
`testJournalTokensMatchTheGoldenList` is untouched and still passes.

### `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift` (+30/-14)

- `withPublicReadGeneration:1666` — `where error.unavailableReason == .generationPinStale` becomes
  `where error.unavailableReason?.isChangeDetection == true`. Same behaviour, but the retry set is
  now read from the same definition the recording site uses instead of a duplicated literal.
- `recordPublicReadReadmissionFailure:1817-1818` — **the behavioural change.** The guard now also
  requires `!reason.isChangeDetection`, so a stale pin is never written into the negative cache.
  Cost of the exclusion: at most one redone admission per read, in a race that resolves itself.
  It sits beside the existing `CancellationError` exclusion, which is the same idea (a caller
  hanging up is not evidence about the account).
- Doc comments on both functions now state the invariant explicitly: the reason
  `withPublicReadGeneration` retries is, by construction, the reason that is never cached as a
  refusal.

### `Sources/SwanSQLite/PublicRepositoryReadStore.swift` (+18, comment only)

Documented the asymmetry at the end-of-admission re-pin (438-443): `data_version` cannot move
there (transaction-frozen, measured above), the guard is kept because it stops being dead the
moment admission is split across transactions, and it is now demoted — a `.generationPinStale`
from inside an admission costs one 503 and the next read admits again, rather than opening a
backoff window. The neighbouring `fileIdentity` re-check **is** live, because `lstat` is not
transaction-scoped, and that distinction was previously invisible.

I did **not** delete the dead guard. Removing a guard is a larger claim than this task authorises,
and it becomes live again under a plausible refactor.

### `Tests/SwanSQLiteTests/PublicRepositoryReadStaleGenerationTests.swift` (+204)

Two tests, both written fully (no stubs), plus a verifier seam.

**`testDataVersionDriftAloneTriggersReAdmissionNotRejection`** — the brief's named test. Not a
tautology and not a duplicate of `testForeignConnectionCommitDoesNotBreakPublicReads`: it measures
both of its own preconditions from an independent third connection — that `PRAGMA data_version`
moved, *and* that `public_repository_state` is unchanged across the foreign commit, so drift is
provably the only thing that changed — then asserts the read is served, costs **exactly one**
admission (zero would mean the pin is no longer checked at all), **replaces** the cached generation
ID (a surviving ID would mean the drifted pin was served rather than re-admitted), writes **no**
negative-cache entry, and leaves steady state costing zero further admissions.

**`testStalePinIsNeverRecordedAsAnAdmissionFailure`** — the test for the gap above. It drives a
`.generationPinStale` *admission* failure through the injected verifier, then asserts (a) nothing
was recorded, and (b) the very next read, issued immediately and well inside the 250 ms window,
runs its own admission and serves. It closes with a narrowness control: a subsequent
`.identityFactsMalformed` failure **must** still be recorded, so the demotion cannot be a quiet
disabling of the bound that Tasks 2-3 rely on.

`CountingPLCVerifier.rejectEverything(with:)` added so an admission can refuse with a chosen
reason; the no-argument `rejectEverything()` keeps its old meaning (`.identityFactsMalformed`), so
every existing test is unaffected.

## Ambiguity resolved

1. **Stale line numbers.** The brief's `:796-797` predates Tasks 1-3. I located the original text
   with `jj file show -r 77153b50af97` and confirmed it was the clause Task 1's F1 fix already
   split. Recorded rather than silently retargeted.
2. **"rather than a hard failure" when the mapping already exists.** Resolved by reading D3 in the
   design spec, which frames the task as disarming a landmine rather than fixing live behaviour,
   and by auditing every path where `data_version` movement still ends in a refusal. The negative
   cache was the one that survived the audit.
3. **Allow-list at trust boundaries.** The change reads as a deny-list (`!isChangeDetection`) at
   one site, so I put the decision in a single exhaustive switch that forces a per-case answer.
   The failure direction is also safe: an unclassified new reason gets `false`, i.e. it is recorded
   and not retried — the conservative behaviour, identical to today.
4. **I did not add a third read attempt.** A second `.generationPinStale` from attempt #2 is still
   a hard 503. That bound is deliberate, documented in Task 2's comment ("`attempt` appears exactly
   twice on a straight line"), and pinned by `testReAdmissionHappensOnceNotInALoop`.

## Falsification

Three separate breaks, each rebuilt and re-run, each restored. All markers removed afterwards
(`grep -rn FALSIFICATION Sources/ Tests/` → none).

**F-B — `isChangeDetection` returns `false` for `.generationPinStale`** (demotion removed).
8 of 12 tests in the file failed. Critically the brief's named test failed with
`caught error: "unavailable(reason: ...generationPinStale)"` at the read call — it 503s instead of
re-admitting. This proves the test detects loss of re-admission and is not asserting something it
constructed.

**F-C — `isChangeDetection` also returns `true` for `.identityFactsMalformed`** (exclusion widened).
My narrowness control failed at line 283, "a real admission failure must still be recorded", and
the two pre-existing bound tests failed with `("6") is not equal to ("1") - reads inside the
backoff window must add no admissions`. This proves the exclusion is exactly one reason wide.

**F-A — property restored, only the `!reason.isChangeDetection` clause removed** from
`recordPublicReadReadmissionFailure`. Exactly one test failed —
`testStalePinIsNeverRecordedAsAnAdmissionFailure` — at both predicted points: the entry is written
(line 248), and the recovering read is refused by the suppression throw at
`SQLitePreMigratedAccountDirectory.swift:1746` despite the verifier now accepting. This proves the
new guard, and only the new guard, carries the new behaviour.

## Test commands and results

```bash
# build (never bare `swift build`)
xcrun --toolchain XcodeDefault swift build --build-tests          # exit 0

# RED, before implementation — filter confirmed to match both tests
xcrun --toolchain XcodeDefault swift test --skip-build \
  --filter "PublicRepositoryReadStaleGenerationTests/(testDataVersionDriftAloneTriggersReAdmissionNotRejection|testStalePinIsNeverRecordedAsAnAdmissionFailure)"
# exit 1 — both cases ran; testStalePinIsNeverRecordedAsAnAdmissionFailure failed at
# PublicRepositoryReadStaleGenerationTests.swift:248 and at
# SQLitePreMigratedAccountDirectory.swift:1742 (suppression throw)

# GREEN, brief's filter — 13 cases matched, all passed
xcrun --toolchain XcodeDefault swift test --skip-build --filter "StaleGeneration"   # exit 0

# full suite, redirected to a file, never piped
xcrun --toolchain XcodeDefault swift test --skip-build > suite1.log 2>&1
# SUITE_EXIT=0
```

Suite accounting (per the counting rule — `Test Case '-[...]' passed` lines, **not** summed
`Executed N tests`):

- `passed = 1432`, `failed = 0`
- `grep "Some test targets reported failures"` → no match
- all **11** xctest bundles reported a final `Test Suite '<name>.xctest' passed`, so no target
  crashed and truncated the log
- `SwanXRPCPipethroughTests` ran 32 cases and passed; the 1-in-3 `NIOAsyncWriter` crash recorded in
  the ledger did **not** reproduce (it was addressed earlier today per `flake-fix-report.md`)

## Deliberately not done

- **No third read attempt** on repeated drift. Bounded by design; see Ambiguity 4.
- **The dead re-pin at `PublicRepositoryReadStore.swift:438-443` was not deleted**, only documented.
- **W2 / relay activation not started**, as instructed.
- No client-visible change of any kind. The 503 body remains exactly
  `{"error":"temporarily_unavailable"}`; all new information is server-side (and this task adds no
  new log line — it reuses `logPublicReadAdmissionFailure`, which still journals the
  `.generationPinStale` refusal at `warning` as before).
- No `swiftformat` run. No mutating git. No `@unchecked Sendable` / `nonisolated`. 4-space
  indentation throughout.

## Concerns

1. **`admitPublicRepositoryGeneration`'s `data_version` re-pin (438-443) is dead code today.** I
   documented it rather than removing it. A reviewer may reasonably prefer deletion. If admission
   is ever split across transactions it becomes live, and it is now demoted rather than
   cache-poisoning — but it will still cost that one request a 503.
2. **`recheckPublicRepositoryGenerationWithoutGate`'s `data_version` guard (now ~906-911) is
   likewise unable to newly fire**, because `requirePublicRepositoryGenerationWithoutGate` checked
   the same transaction-frozen value at the top of the same transaction. I left it and did not
   document it, to keep the diff proportionate. Worth a follow-up comment if reviewers want the
   two treated identically.
3. **`testStalePinIsNeverRecordedAsAnAdmissionFailure` reaches its condition through the injected
   verifier**, not through a genuine pin race — because no genuine one is reachable (see
   Reachability). It tests what the *directory* does with a `.generationPinStale` admission
   failure, which is the behaviour under change; it does not and cannot test that such an admission
   failure occurs naturally.
4. **The 250 ms backoff is still wall-clock and still shared per DID.** Nothing in this task
   changes that; `testReAdmissionHappensOnceNotInALoop` and `testBackoffDoesNotDelayRecovery` sleep
   500 ms, so those two remain the slowest cases in the file and are timing-sensitive under heavy
   parallel load.
5. **The exhaustive switch is 30 lines for one `true`.** Deliberate (compile-enforced
   classification), but it is the largest single block in the diff and a reviewer preferring
   `default: false` would cut it to three lines at the cost of that enforcement.

---

## Fix-round test commands and results (`04c68d89fb0a`)

```bash
xcrun --toolchain XcodeDefault swift build --build-tests            # exit 0

# targeted, both affected suites — filter confirmed to match (17 cases ran)
xcrun --toolchain XcodeDefault swift test --skip-build \
  --filter "PublicRepositoryRead(StaleGeneration|Diagnostics)Tests" > t1.log 2>&1   # exit 0

# falsification: both consumers reverted to `unavailableReason`
xcrun --toolchain XcodeDefault swift test --skip-build \
  --filter "PublicRepositoryReadStaleGenerationTests/testReasonlessAdmissionFailureIsNamedAndBounded" \
  > tF.log 2>&1                                                     # exit 1, as predicted

# full suite, redirected, never piped
xcrun --toolchain XcodeDefault swift test --skip-build > suite.log 2>&1
# SUITE_EXIT=0
```

- `passed = 1434` (`Test Case '-[...]' passed` lines, **not** summed `Executed N tests`), up 2 from
  1432 — exactly the two tests added this round.
- `failed = 0`; `grep -c "Some test targets reported failures"` → `0`.
- All **11** xctest bundles reported `Test Suite '<name>.xctest' passed`, so no target crashed and
  truncated the log.

## Fix-round concerns

1. **Scope expansion still needs controller ratification** — see Finding 1 above. The out-of-list
   files are now larger, not smaller, than the round that was flagged for it; the difference is
   that they are flagged, tabulated, and each has a stated revert cost.
2. **`projectionBoundExceeded` is a new operator-facing journal token.** Any alert rule or saved
   query written against `unclassified` for over-budget accounts will stop matching the replayed
   refusal. The golden list records it deliberately, which is the whole point of that test, but it
   is a real operator-visible change and should be in the release note.
3. **The bound now applies to a genuinely permanent failure.** An account over
   `maximumGenerationIndexEntries` is unadmittable until an operator intervenes, and it will now
   re-pay one full index walk every 250 ms rather than on every read. That is a ~large constant-factor
   improvement, not a fix — the account is still unreadable, and nothing in this task series
   surfaces "this account is over a static bound" anywhere but the journal. Worth a W2 backlog item.
4. **`testReasonlessAdmissionFailureIsNamedAndBounded` sleeps 500 ms**, joining the two existing
   wall-clock-sensitive cases in that file. It is now the third slowest test there and is the third
   candidate to flake under heavy parallel load.
5. **The reason-less path is still driven through the injected verifier**, not through a genuine
   100k-row index. Reproducing the real producer needs either 100_000 index rows or ~8 MiB of
   collection names, and `PublicRepositoryReadLimits` is not injectable. The test therefore pins
   what the *directory* does with a reason-less admission failure — the behaviour under change —
   and not that the preflight produces one. The production chain to that throw is traced by
   inspection above (`:259` → `:917` → `:924` → `:533`/`:556`).
