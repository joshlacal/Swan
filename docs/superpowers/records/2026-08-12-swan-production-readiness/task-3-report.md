# Task 3 report — evict rather than fail when a post-mutation refresh errors

> **Fix round applied 2026-08-12** — commit `af6c92c82874`, *SwanSQLite: bound
> cold-cache public reads with the admission backoff*. All three review
> findings addressed. See [Fix round](#fix-round-af6c92c82874) at the end; the
> original report body below is unchanged except where a claim it made is now
> false, which is called out inline.

## What changed, per file

### `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift`

`refreshPublicReadGenerationAfterMutation(did:database:)` no longer throws. It is
now `async` (non-throwing) and wraps its whole body in a `do`/`catch`:

- **Success** — unchanged: `refreshPublicReadGeneration` publishes the new
  generation and clears the DID's negative-cache entry, exactly as before.
- **`CancellationError`** — caught first, before the generic catch, mirroring the
  ordering in `refreshPublicReadGeneration`. The generation is evicted (it is
  stale either way — the commit is durable) but **nothing is journalled**, so a
  caller hanging up never appears as an admission refusal.
- **Anything else** — the DID's entry is removed from `publicReadGenerations` and
  one `warning` is emitted through the existing
  `Self.logPublicReadAdmissionFailure` helper. No second log shape was invented.

Two pre-refresh guards that previously refused silently now name themselves via a
new `private static func namedPostMutationRefreshFailure(_:did:)`, which logs the
reason and returns the error to be thrown:

- `controlStore.account(did:)` throwing → `.controlStoreFailure` (this was
  previously an untyped throw that propagated with no journal line at all);
- `controlStore.account(did:)` returning `nil` → `.controlRowChanged` (previously
  thrown unlogged).

Net journalling contract: **every** post-mutation refresh failure now leaves
exactly one line naming the cause (from `refreshPublicReadGeneration`, or from
`namedPostMutationRefreshFailure` for the two guards above it) followed by one
line naming the consequence (`postMutationRefreshFailed`). Cause first, then
eviction.

Two `internal` read-only test seams were added on the actor:

- `cachedPublicReadGenerationID(did:) -> UUID?`
- `hasLivePublicReadReadmissionBackoff(did:) -> Bool`

Both are `internal` (module-scoped, reachable only via `@testable import`), never
called by production code, and widen no public API.

Call site (`SQLiteGenerationRefreshingPublicMutationStore.applyPublicRepositoryMutation`)
changed from `try await directory.refreshPublicReadGenerationAfterMutation(...)`
to `await ...`, with a scope note explaining why only the refresh may fail
quietly.

### `Sources/SwanStorage/PublicRepositoryReadDirectory.swift`

Added one case to `PublicReadUnavailableReason`, in a new
`// MARK: Post-mutation publication` section:

```swift
case postMutationRefreshFailed
```

Rationale for adding a token rather than reusing an existing one: without it the
journal shows only the underlying guard's line, which is byte-identical to a
read-path refusal for an account that reads fine — an operator has no way to see
that a *write path* stopped publishing. The doc comment states explicitly that
this case never refuses a request. It is a server-side diagnostic like every
other case; the client-visible body is untouched (see below).

### `Tests/SwanSQLiteTests/PublicRepositoryReadDiagnosticsTests.swift`

Added `"postMutationRefreshFailed"` to the golden list in
`testJournalTokensMatchTheGoldenList` (29 → 30 tokens).

### `Tests/SwanSQLiteTests/PublicRepositoryReadStaleGenerationTests.swift`

Extended the Task 2 suite in place, reusing `makeFixture()`, `CountingPLCVerifier`
and its `rejectEverything()` / `acceptEverything()` / `admissionCount`. The only
fixture change is additive: `Fixture` now carries `signingKey` (the genesis P-256
key, previously constructed and discarded) so the write-side tests can sign a real
commit against the repository the fixture installed.

New helper `applyOneRecord(_:recordKey:)` drives one real `app.bsky.feed.post`
create through the **same seam HTTP uses** —
`directory.generationRefreshingPublicMutationStore(did:)` → `reserve` →
`PublicRepositoryEngine.apply` → `applyPublicRepositoryMutation` — and returns the
`CommittedPublicRepositoryMutation` the request reports to its caller. A private
`MutationFixtureFailure` error keeps a fixture setup fault from being mistaken for
an assertion under test. Monotonic reservation clocks come from a `Mutex<UInt64>`.

Three tests:

1. `testFailedPostMutationRefreshDoesNotFailTheMutation` — warm the read cache,
   `verifier.rejectEverything()`, then apply a record. Asserts the mutation
   *request* returns a `CommittedPublicRepositoryMutation`, that its revision
   actually advanced (not a no-op), that it carries one record result, and that
   `loadPublicRepositoryState()` agrees with what the caller was told. This is the
   request's answer, not merely the absence of an internal throw.
2. `testFailedPostMutationRefreshEvictsRatherThanCachingStale` — asserts a
   generation *was* cached beforehand (precondition), then after the failed
   refresh asserts `cachedPublicReadGenerationID(did:)` is **`nil`** (gone, not
   merely different), asserts `hasLivePublicReadReadmissionBackoff(did:)` is
   `false`, then `acceptEverything()` and reads immediately — well inside the
   250 ms window — and asserts the read serves the revision the mutation
   committed.
3. `testSuccessfulPostMutationRefreshPublishesRatherThanEvicting` — added as the
   inverse guard: eviction must be the failure path only. Asserts the healthy
   path publishes a *new* generation id and that the following read costs zero
   admissions.

## Ambiguity 2 — which structure was touched

**Touched: `publicReadGenerations`, the positive generation cache.** Removed with
`removeValue(forKey: did)` in both catch arms.

**Not touched: `publicReadReadmissionFailures`, the negative cache.** Recording an
entry there would be actively harmful. That structure is consulted by
`readmitPublicReadGeneration` and, while live, *answers* with a refusal rather
than re-running the admission. The whole recovery design here is "next read
admits from cold", so poisoning the negative cache would convert a self-healing
cache miss into up to 250 ms of guaranteed `503`s for an account whose write just
succeeded — for no benefit, since the cold path (`activePublicReadContext` →
`refreshPublicReadGeneration`) does not consult it anyway. Falsification F3 below
pins this.

> **Corrected in the fix round.** The clause "for no benefit, since the cold
> path does not consult it anyway" was true of the code as shipped in
> `aacf6010`, and it destroyed the argument it was attached to: a cache the
> cold path ignores cannot suppress a cold admission, so the stated harm did
> not exist. That was review finding 2 — and the same missing mechanism was
> finding 1's bug seen from the other side. `af6c92c8` routes the cold path
> through the negative cache, which makes the harm real and the paragraph
> above true. Falsification **F5** below demonstrates it directly. The
> shipped comment now states the mechanism *and* the second, independent
> reason the reviewer identified.

## Ambiguity 4 — exact scope of the catch

The `do`/`catch` lives entirely inside `refreshPublicReadGenerationAfterMutation`
and spans exactly three operations:

1. `controlStore.account(did:)`,
2. the `guard let account` on its result,
3. `refreshPublicReadGeneration(account:database:)`.

Everything on the durable-commit path is **outside** it and still propagates from
`applyPublicRepositoryMutation` untouched:

- `firehoseFence.apply(did:signingGeneration:)`,
- `database.applyPublicRepositoryMutation(reservation:prepared:firehose:)`,
- `database.applyPublicRepositoryMutation(reservation:prepared:)`.

Those all run before the `await` on the refresh and their errors return to the
caller exactly as before. A write that did not happen can still never be reported
as one that did. The `reserve` / `abandon` / blob paths in the same wrapper are
untouched.

`CancellationError` keeps its dedicated arm ahead of the generic one, matching
`refreshPublicReadGeneration`.

## Falsification pass

Each mutation was applied to the shipped implementation, built, and the suite
re-run; then the file was restored from a pristine copy.

| # | Injected defect | Result |
|---|---|---|
| F1 | Rethrow the refresh error (the pre-task behaviour) | Both new tests **fail**. Reason exactly as predicted: `failed: caught error: "unavailable(reason: …identityFactsMalformed)"` raised out of the mutation request. |
| F2 | Swallow the error but do **not** evict | `testFailedPostMutationRefreshEvictsRatherThanCachingStale` **fails** twice, exactly as predicted: `XCTAssertNil failed: "5677C9DE-…"` (generation left cached), then the recovery read refuses with `unavailable(reason: …repositoryStateMismatch)` — the non-re-admissible reason, i.e. the account is dark until some later write happens to refresh successfully. `testFailedPostMutationRefreshDoesNotFailTheMutation` still passes, confirming the two tests cover different halves of the fix. |
| F3 | Evict *and* record a `publicReadReadmissionFailure` | `XCTAssertFalse failed - evicting the positive generation must not write a negative-cache entry`. Ambiguity 2 is genuinely pinned rather than merely asserted in prose. |

After restore: `grep -rn FALSIFICATION Sources/ Tests/` → no hits; full suite
green (below).

## Test commands and results

Build (never bare `swift build`, never `swiftformat`):

```
xcrun --toolchain XcodeDefault swift build --build-tests    # exit 0
```

Targeted:

```
xcrun --toolchain XcodeDefault swift test --skip-build \
  --filter PublicRepositoryReadStaleGenerationTests > .../t1.log 2>&1
```

exit 0; filter matched and ran **9** cases in
`PublicRepositoryReadStaleGenerationTests` (6 pre-existing + 3 new), all passed —
verified by reading the `Test Case '-[…]'` lines, not by trusting the filter.

Full suite:

```
xcrun --toolchain XcodeDefault swift test --skip-build > .../full.log 2>&1
```

- exit code **0**
- `Test Case '-[…]' passed` lines: **1429** (baseline 1426 + the 3 new cases)
- `Test Case '-[…]' failed` lines: **0**
- `Some test targets reported failures`: **0 occurrences**
- xctest targets started: **11** (SwanAccountExport, SwanAccounts, SwanCLI,
  SwanCore, SwanHTTP, SwanInterop, SwanOAuth, SwanPublicFirehose,
  SwanPublicRepository, SwanSpaces, SwanSQLite)

Output was redirected to files throughout; nothing was piped through `tail`.

## Constraints checked

- `swiftformat` never run. 4-space indentation throughout the touched files.
- No `@unchecked Sendable`, no `nonisolated`. The new members are ordinary
  actor-isolated methods; the build is clean under Swift 6 strict concurrency
  (only the two pre-existing `NoUsage` warnings in `PublicRepositoryStore.swift`
  and `SwanCommand.swift` remain).
- **Client-visible body unchanged.** `PublicReadUnavailableReason` is a
  server-side diagnostic only; every case still maps to
  `503 {"error":"temporarily_unavailable"}`. The new case is never even reachable
  as a *refusal* — it is only ever logged, since this path no longer throws.
- Phase 1 proxying, credential isolation and peer-pinning untouched.
- jj only; no mutating git commands.

## Deliberately not done

- **No new negative-cache or backoff behaviour on the write path.** Considered and
  rejected for the reason in Ambiguity 2 above.
- **No retry of the refresh.** The next read re-admits; retrying inside the
  mutation would put admission work on the write's latency budget for no
  correctness gain.
- **No change to `preopenedPublicMutationStore`.** It returns the raw account
  database and never had a refresh step, so it is out of scope; it is documented
  as requiring HTTP adapters to bind lifecycle themselves.
- **The brief's two stubs were written as three tests.** The third
  (`…PublishesRatherThanEvicting`) is the inverse guard: without it, "always
  evict, never publish" would pass both required tests while costing every read
  after every write a full admission.

## Concerns

1. **New journal token.** `postMutationRefreshFailed` is the 30th case in an enum
   whose doc comment frames it as "the exact guard that refused a public
   repository read". This one never refuses anything — it records that a *write's*
   refresh failed. The doc comment says so explicitly and it sits under its own
   MARK, but it is a mild widening of the enum's meaning. If that is unwanted, the
   alternative is to drop the case and re-log the underlying reason, which costs
   the operator the ability to distinguish a write-path publication failure from a
   read-path refusal.
2. **Test seams in production code.** `cachedPublicReadGenerationID(did:)` and
   `hasLivePublicReadReadmissionBackoff(did:)` exist only for the tests. They are
   `internal` and read-only, but they are surface that production does not use.
   They were added because ambiguity 2 requires distinguishing *evicted* from
   *replaced*, which is not observable from the read path — F2 above shows the
   behavioural half of that assertion, but "gone vs. replaced-with-a-valid-one"
   needs the direct read.
3. **`generationRefreshingPublicMutationStore` has no other test coverage in the
   repo.** Before this task, `grep` found zero callers outside
   `SQLitePreMigratedAccountDirectory.swift` — no test and no SwanHTTP call site.
   The new tests are therefore the first coverage of that wrapper at all. Worth
   confirming separately that the live HTTP mutation path actually routes through
   it rather than through `preopenedPublicMutationStore`; if it does not, the
   production write path is not publishing generations at all, which would be a
   larger finding than this task. **Not investigated — out of scope here.**
4. **No production verification.** This is a library-level change with no running
   Swan instance exercised; evidence is the unit suite plus the falsification
   pass. Confirming the eviction in a live journal requires a deployment and a
   deliberately failing refresh.

---

## Fix round `af6c92c82874`

Three review findings, all IMPORTANT, all addressed. Findings 1 and 2 turned out
to be one defect seen from two sides, so they share a fix.

### Finding 1 — eviction opened a hole in the Task-2 backoff

*Verdict: correct, and the more serious of the three.*

The review is right about the mechanism and right that Task 3 created the state.
`bootstrap` (140-197) admits every active account or fails startup,
`installAccount` writes both maps together, and `revokeAndDrainAccount` / `close`
remove the database as well — so before this task, "open database, no cached
generation" was reachable only through a control-row change, which is transient.
Task 3's `removeValue(forKey: did)` made it a *steady* state for an account whose
post-mutation refresh keeps failing for a persistent reason, and every anonymous
read then landed on `activePublicReadContext`'s cold branch, which called
`refreshPublicReadGeneration` bare.

**Fix.** The backoff consult, the single-flight and the failure recording were
extracted out of `readmitPublicReadGeneration` into a new

```swift
private func admitPublicReadGenerationForRequest(
    account: AccountControlAccount,
    database: SQLiteAccountDatabase
) async throws -> SQLiteVerifiedPublicRepositoryGeneration
```

and **both** request-time callers now go through it:

- `activePublicReadContext`'s cold branch (previously bare), and
- `readmitPublicReadGeneration`, which keeps only its "someone already
  re-admitted while this request was reading" short-circuit and then delegates.

Nothing else changed. `bootstrap` does not call `refreshPublicReadGeneration` at
all — it admits inline via `validatePublicRepositoryAdmission` — so startup
admission is untouched and cannot be suppressed by a negative entry. Every
remaining caller of `refreshPublicReadGeneration` is now either the shared
single-flight task or the post-mutation refresh, which is a write and
deliberately unbounded-by-backoff (it runs once per commit, not once per read).

The cold path also inherits single-flighting as a consequence. That is a
strengthening, not a behaviour change anyone depended on: the joining request
still re-checks `generation.controlAccount == account` and fails closed on a
different control row, exactly as re-admission already did.

**Naming.** The private structures keep their `Readmission` names. Every
request-time admission on the read path *is* a re-admission — bootstrap already
admitted the account, and the only route into `databases` without a generation is
this task's eviction — so the name stayed accurate and a rename would have been
churn across four members for no gained truth.

### Finding 2 — the negative-cache rationale asserted a mechanism the code lacked

*Verdict: correct as written, and it is the same defect as finding 1.*

The decision not to write a negative-cache entry was right; the reason given for
it was false, because the cold path ignored the cache. Two ways to make the
comment true were available: weaken it to the reviewer's alternative reason, or
give the code the mechanism. Finding 1 required the latter independently, so the
comment's original claim is now simply true — and the shipped comment states
**both** reasons rather than only the one that survives:

1. the cold read now goes through `admitPublicReadGenerationForRequest`, which
   refuses without admitting while an entry is live, so an entry written from the
   write path would convert a self-healing cache miss into a guaranteed window of
   `503`s for an account whose write just succeeded; **and**
2. the reason recorded would not be a read refusal at all, and no cold-path
   failure clears it — the only clearing site is `refreshPublicReadGeneration`'s
   publish — so it would go on to suppress a legitimate later re-admission under
   a cause no read ever asked about.

The comment now names the two tests that pin the two halves, so a maintainer can
check the claim rather than trust it.

The test comment at the old lines 396-397 was rewritten the same way. It no
longer says "because no entry was written" as if that were self-evidently
load-bearing; it points at `testColdCacheReadsAreBoundedByTheBackoff`, which is
the test that makes it load-bearing.

### Finding 3 — public API doc stated the opposite of the shipped behaviour

*Verdict: correct, straightforwardly.*

`generationRefreshingPublicMutationStore`'s doc still promised that "a successful
commit is not returned to HTTP until the new state has been fully re-admitted and
atomically published", which Task 3 deliberately stopped being true. Rewritten to
say what the store now guarantees, which is weaker but still worth stating: every
commit runs the republication step before responding, and the step either
publishes the new generation or evicts the stale one — a successful commit is
never returned with the *pre-mutation* generation still answering reads.

The stale restatement in the blob-surface comment (old 2391-2397) was rewritten
to match: the reason to keep the wrapper on the upload path is that bypassing it
skips the republication step entirely and leaves the pre-mutation generation
cached, which is the same failure the wrapper exists to prevent.

### New test

`testColdCacheReadsAreBoundedByTheBackoff` in
`Tests/SwanSQLiteTests/PublicRepositoryReadStaleGenerationTests.swift`. It drives
the account into the cold state through the only door that produces it — a failed
post-mutation refresh — asserts as *preconditions* that the generation is gone
and that the write path did **not** prime the negative cache (without which the
first read would be suppressed and the test would prove nothing), then asserts:

- the first cold read costs exactly one admission and records the backoff entry;
- all five read shapes immediately afterwards refuse with the same reason and add
  **zero** admissions;
- past the window, with the verifier accepting again, the account is served from
  cold at a cost of exactly one further admission.

The last assertion matters: the bound must not become a second way for an account
to stay dark, which is the failure mode Task 2's `testBackoffDoesNotDelayRecovery`
covers for the re-admission path and nothing covered for the cold path.

### Falsification pass (fix round)

Each defect was injected into the shipped file, built, the suite re-run, then the
file restored from a pristine copy. `grep -rn FALSIFICATION Sources/ Tests/`
returns no hits afterwards.

| # | Injected defect | Result |
|---|---|---|
| F4 | Revert the cold branch to `refreshPublicReadGeneration` bare — the state as reviewed | `testColdCacheReadsAreBoundedByTheBackoff` **fails** twice, exactly as the finding predicts: `XCTAssertTrue failed - a failed cold admission must record the backoff entry`, then `XCTAssertEqual failed: ("6") is not equal to ("1") - cold reads inside the backoff window must add no admissions`. Six admissions for six reads — the unbounded per-read cost, measured. |
| F5 | Keep the fix, but *also* record a negative entry from the eviction path | Two tests **fail**, which is the point: `testFailedPostMutationRefreshEvictsRatherThanCachingStale` reports `XCTAssertFalse failed - evicting the positive generation must not write a negative-cache entry` **and then** its recovery read — taken after `acceptEverything()` — throws `identityFactsMalformed`, the *write path's* reason, at an account that is now perfectly admittable. That is the harm the comment claims, demonstrated rather than asserted. Under the pre-fix code this second failure could not happen at all, which is precisely why the comment was false before. |

F1-F3 from the original round were not re-run; nothing they cover was touched.

### Test commands and results (fix round)

```
xcrun --toolchain XcodeDefault swift build --build-tests      # exit 0
xcrun --toolchain XcodeDefault swift test --skip-build \
  --filter PublicRepositoryReadStaleGenerationTests > …/t1.log 2>&1
xcrun --toolchain XcodeDefault swift test --skip-build > …/full.log 2>&1
```

Targeted: exit **0**; the filter matched and ran **10** cases (9 before, plus
`testColdCacheReadsAreBoundedByTheBackoff`), all passed — confirmed by reading
the `Test Case '-[…]'` lines rather than trusting the filter.

Full suite:

- exit code **0**
- `Test Case '-[…]' passed` lines: **1430** (1429 + the one new case)
- `Test Case '-[…]' failed` lines: **0**
- `Some test targets reported failures`: **0 occurrences**
- xctest targets started: **11**, unchanged

Output was redirected to files throughout; nothing was piped through `tail`.

### Constraints

`swiftformat` never run. 4-space indentation. No bare `swift build`/`swift test`.
No `@unchecked Sendable`, no `nonisolated` — `admitPublicReadGenerationForRequest`
is an ordinary actor-isolated method and the moved code is byte-identical to what
it replaced apart from one local rename (`readmission` → `admission`). No change
to any client-visible body: the public-read 503 is still exactly
`{"error":"temporarily_unavailable"}`, and no journal token was added or removed
this round, so the golden list in `PublicRepositoryReadDiagnosticsTests` is
untouched. Phase 1 proxying, credential isolation and peer-pinning untouched. jj
only.

### Concerns after the fix round

1. **Concern 3 above still stands and is now more pointed.** The cold path is
   only reachable in production if the live HTTP mutation path actually routes
   through `generationRefreshingPublicMutationStore` rather than
   `preopenedPublicMutationStore`. If it routes through the latter, neither the
   eviction nor this backoff ever runs in production and the real defect is
   larger than either task. Still not investigated — out of scope for a fix
   round, but it should not stay unanswered.
2. **The backoff now gates the first read after a control-row change.** An
   account deactivated and reactivated within 250 ms of a failed admission will
   see the earlier failure's reason rather than re-admitting. This is the same
   trade Task 2 accepted for the re-admission path, applied consistently — and
   `refreshPublicReadGeneration` clears the entry on any publish, so recovery
   that has an event to hang off still does not wait. Noting it because the
   cold path previously had no such gate at all.
3. **Still no production verification.** Unchanged from concern 4 above.
