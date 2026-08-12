# Task 2 report — re-admit a stale public-read generation instead of failing

## What changed, per file

### `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift`

**New state: `publicReadReadmissions: [String: Task<SQLiteVerifiedPublicRepositoryGeneration, any Error>]`.**
At most one in-flight re-admission per DID. Cleared in `close()` and for the
revoked DID in `revokeAndDrainAccount(did:)`. Neither clears by cancelling: the
re-admission task's own post-await guards (`!isClosed`,
`databases[did] === database`, control-row equality) already refuse to publish a
generation once the DID leaves `databases`, and cancelling a live SQLite query
would only add a second failure mode. Dropping the handle is enough.

**New `withPublicReadGeneration(_:_:)`.** The whole fix. It resolves the read
context, runs the caller's read, and — only when the read refuses with
`.generationPinStale` — re-admits once and runs the read a second time.

**New `readmitPublicReadGeneration(account:database:replacing:)`.** Single-flight
re-admission. It first takes a free ride if another request already published a
newer generation for this DID (`current.id != stale.id` and
`current.controlAccount == account`); then consults the negative cache; then
joins or starts the one in-flight admission task for that DID; and finally
refuses with `.controlRowChanged` if the shared admission verified a control row
this request did not resolve.

**New negative cache (review finding F1).**
`publicReadReadmissionFailures: [String: PublicReadReadmissionFailure]`, holding
the reason and an expiry `ContinuousClock.Instant`, written by
`recordPublicReadReadmissionFailure(did:error:)` when the shared re-admission
throws a `PublicRepositoryReadError`. See the dedicated section below.

**All five public read entry points converted** — `publicRepositoryStatus`,
`publicRepositoryDescriptionOutcome`, `publicRepositoryRecordOutcome`,
`publicRepositoryRecordsOutcome`, `publicRepositoryCAROutcome`. Each one's body
(the generation-validated read, its error mapping, and its
`recheckPublicAccount`) moved verbatim into a `withPublicReadGeneration` closure.
The mapping of untyped storage errors to `.storageFailure` stays *inside* the
closure, so a raw SQLite error can never be mistaken for `.generationPinStale`.

The CAR path additionally moved its spool-admission `reserve` inside the closure.
That is deliberate: the existing error paths release the lease before throwing,
so a re-admitted retry starts from a released budget instead of double-charging
the account against the shared `PublicRepositorySpoolAdmission`.

### `Tests/SwanSQLiteTests/PublicRepositoryReadStaleGenerationTests.swift` (new)

Four tests plus a fixture that bootstraps a real
`SQLitePreMigratedAccountDirectory` over a genesis-only account, and a
`CountingPLCVerifier` that counts admissions and can be armed to reject.

Nothing else was touched. No new `PublicReadUnavailableReason` case was added, so
the golden list in `PublicRepositoryReadDiagnosticsTests` is unchanged (it still
pins 29 tokens, and still passes). No new log site was added either — a failed
re-admission goes through `refreshPublicReadGeneration`, whose existing
`catch`/`logPublicReadAdmissionFailure` journals the reason that fired. The 503
body is untouched.

## F1: negative caching for failed re-admission

**The problem.** A failed admission never assigns `publicReadGenerations[did]`,
so `activePublicReadContext` keeps handing back the same stale generation and
every following read re-enters re-admission. For a permanently-unadmittable
account that meant a full admission per anonymous public read — the complete
record-index walk in `preflightPublicReadProjectionWithoutGate` (up to 100k
entries), the MST projection verify, and PLC verification. A fast 503 became a
slow one, on endpoints the whole network can reach once Swan is announced to a
relay.

**Backoff shape: flat, 250 ms, per DID.** Justification:

- *Flat, not exponential.* The property that dominates here is that a stale
  account heals itself; that is the entire point of Task 2. A growing backoff
  buys a diminishing amount of saved work in exchange for a recovery delay that
  compounds with the number of failures — which is the outage reintroduced in a
  slower form. A constant window makes the worst case a constant, statable in
  the doc comment and impossible to reason about wrongly.
- *250 ms specifically.* It caps wasted admissions at four per second per DID no
  matter how much anonymous traffic arrives — the same order as a healthy
  account's own control-row churn, so the wasted work is bounded at a rate the
  system already sustains. And it is far below any client's or relay's retry
  interval, so no caller can observe the added latency as a stall.
- *Recovery does not wait for it when there is an event to hang off.* The clear
  is placed on the single line that publishes a generation, immediately after
  `publicReadGenerations[account.did] = generation` inside
  `refreshPublicReadGeneration`. That is the only publish point in the type, so
  every publisher retires the entry: a cold-cache refresh, a successful
  re-admission, and `refreshPublicReadGenerationAfterMutation` (which calls that
  same function) alike. `revokeAndDrainAccount` and `close()` clear it too.
- *The free-ride check runs before the negative check*, so a generation another
  request already published always beats an unexpired window.

**It suppresses work, never admission.** While an entry is live the read still
refuses, with the same `PublicReadUnavailableReason` the re-run admission would
have produced and the same `{"error":"temporarily_unavailable"}` body, and it is
still journalled per request through the same
`logPublicReadAdmissionFailure`. The entry is never consulted to serve anything —
there is no code path from a negative entry to a generation. A `CancellationError`
is deliberately not recorded: a caller hanging up is not evidence about the
account.

**Memory is bounded.** The key space is already bounded by hosted accounts, not
by anonymous input: only an active, startup-preopened DID reaches this code, and
`activePublicReadContext` refuses anything else with `.accountNotPreopened` far
earlier. On top of that the dictionary is capped at 4096 entries; on a new
insert at the cap it first drops expired entries, and if every slot is still
live it declines to record rather than grow. Declining is safe — the only
consequence is that the DID redoes the admission next read, which is exactly the
behaviour that shipped before the cache existed.

**Tests.** `testFailedReAdmissionIsNotRepeatedWithinTheBackoffWindow` fails the
first read (one admission), then runs all five read shapes immediately and
asserts zero additional admissions *and* that every shape still refuses with the
same reason. `testBackoffDoesNotDelayRecovery` makes the account unadmittable,
takes the refusal, makes it admittable again, and asserts the next read past the
window is served at the cost of exactly one admission — and that the read after
that costs none, proving the successful publish retired both the stale pin and
the negative entry. `testReAdmissionHappensOnceNotInALoop` was reshaped for the
window: one read costs exactly one admission, and a second read past the window
costs exactly one more, so the bound is per read and permanent rather than an
artifact of the cache.

Falsified: with the negative-cache branch disabled, the window test fails with
6 admissions instead of 1 — and takes 3.1 s instead of 0.1 s, which is F1's cost
made visible.

## Ambiguity 3: the concurrency decision

**Re-admission is single-flighted per DID.**

The directory is an actor, but `refreshPublicReadGeneration` awaits the control
store and the account database, so the actor is reentrant across it. A foreign
commit invalidates one account's pin for *every* concurrent reader at the same
instant, so the per-request shape is a stampede by construction: N concurrent
public reads each running a full admission — record-index walk, block
materialization, PLC verification, commit authentication — against the single
SQLite connection they all share, which serializes them anyway. That converts a
liveness fix into a latency cliff exactly when the account is busiest.

Single-flighting is no weaker than admitting per request, for three reasons:

1. The shared result is a fully verified generation — it went through the same
   admission a cold start runs.
2. A joiner that resolved a different control row than the shared admission
   verified is refused with `.controlRowChanged` rather than served.
3. The joiner's retried read re-validates every pin (identity, file identity,
   `data_version`, repository state) against the generation it was handed,
   before a byte is produced.

There is also a cheaper path before the join: if some other request already
published a newer generation for this DID, the current request just uses it. In
the 8-way concurrency test this is what makes eight readers cost exactly one
admission rather than eight.

Cancellation is deliberately *not* inherited: the admission runs in an
unstructured `Task`, so one client hanging up does not cancel the admission the
other seven are waiting on.

## How re-admission is bounded

Structurally, not incidentally. In `withPublicReadGeneration` the caller's
`attempt` closure is written out **twice, on a straight line**: once on the
generation from `activePublicReadContext`, then — only in the
`.generationPinStale` branch — once on the re-admitted generation. There is no
loop, no recursion, and no counter. Whatever the second attempt throws is what
the caller sees. It is not possible to reach a third attempt without editing the
function to add one.

Per request that is at most one `refreshPublicReadGeneration` call from the
re-admission path (plus, on a cold cache, the one `activePublicReadContext`
already made). `testReAdmissionHappensOnceNotInALoop` pins this against an
account whose re-admission always fails: four reads produce exactly four
admissions, and the assertion is two-sided — more means a retry loop, fewer means
the stale generation was served or the re-admission was skipped.

## Why re-admission cannot serve a genuinely unadmittable account

Three independent reasons, each sufficient:

1. **Only one reason opens the door.** The `catch` is filtered on
   `error.unavailableReason == .generationPinStale`. Every other refusal —
   `.identityStageNotSubmitted`, `.commitAuthenticationFailed`,
   `.projectionMismatch`, `.controlRowChanged`, `.blockMaterializationFailed`,
   `.storageFailure`, all of them — propagates out of the first attempt
   untouched. Re-admission never sees them, so it cannot convert them.

2. **Re-admission is not a weaker admission — it is the same one.** It calls
   `refreshPublicReadGeneration`, the identical function that admits an account
   with a cold cache and that startup bootstrap effectively reproduces. It
   re-checks `isClosed`, active status, preopened identity, the configured
   identity verifier, the database path, and the exact active control row on
   *both* sides of `admitPublicRepositoryGeneration`, which itself re-verifies
   PLC genesis, the preparation journal stage, key references, terminal identity,
   the projection, and the repository commit signature, and then
   `verifyPublicIdentityIntent` re-checks the durable preparation intent in the
   control store. The set of accounts re-admission accepts is therefore exactly
   the set a cold start accepts. It is definitionally not widened, because it is
   not a different predicate.

3. **The generation is not trusted after admission either.** The retried read
   runs the same `requirePublicRepositoryGenerationWithoutGate` /
   `recheckPublicRepositoryGenerationWithoutGate` pin validation and the same
   `recheckPublicAccount` as the first attempt. A generation that admitted but no
   longer matches still refuses.

`testGenuinelyUnadmittableAccountStill503sWithTheGuardThatFired` is the
empirical half of this argument: one foreign commit both drifts the pin (so re-admission is
attempted) and regresses the PLC preparation journal below `.submitted` (so
re-admission must fail). All five read shapes refuse with
`.identityStageNotSubmitted` — the guard that actually fired — never with
`.generationPinStale` and never with a success. And the refusal is durable: a
later read refuses identically, because a failed admission never assigns
`publicReadGenerations[did]`. That test passes both with and without the
negative cache, which is the "must not change what is served" property holding.

### Review findings F2–F4

- **F2** — the vestigial `touchingRepositoryState:` parameter on
  `commitFromSecondConnection` is gone; the "touches no repository state"
  contract now lives in the helper's doc comment, where it is not pretending to
  be an assertion.
- **F3** — `testGenuinelyUnadmittableAccountStill503sAndLogsWhy` is renamed
  `testGenuinelyUnadmittableAccountStill503sWithTheGuardThatFired`. It asserts
  the reason survives to the caller, which is what it actually checks. Asserting
  the log emission itself would mean `LoggingSystem.bootstrap`, which is
  process-global and one-shot across all eleven test targets — not worth the
  coupling for a proxy that is already tight.
- **F4** — `testForeignConnectionCommitDoesNotBreakPublicReads` now opens a third
  connection as an observer and asserts `PRAGMA data_version` actually moved
  across the foreign commit. Without it, a future SQLite or schema change that
  stopped the scratch commit from moving the pin would leave every test in the
  file passing while testing nothing.

## Tests

Falsification first. The implementation was temporarily neutered (the
`.generationPinStale` catch changed to rethrow) and rebuilt:

```
xcrun --toolchain XcodeDefault swift build --build-tests
xcrun --toolchain XcodeDefault swift test --skip-build \
    --filter PublicRepositoryReadStaleGenerationTests
```

**exit 1 — all four tests failed**, and failed for the right reason: the reads
threw `unavailable(reason: .generationPinStale)` permanently after the foreign
scratch-table commit, and the re-admission counter read 0 instead of 4. That is
the outage, reproduced. The catch was then restored.

New suite, with the fix, run three times:

```
xcrun --toolchain XcodeDefault swift test --skip-build \
    --filter PublicRepositoryReadStaleGenerationTests
```
`exit 0`, 6 `Test Case '-[...]' passed` on each of three consecutive runs (the
8-way concurrency assertion and the two timing-sensitive backoff tests are
exact, so the suite was repeated to check for flake).

Full suite:

```
xcrun --toolchain XcodeDefault swift build --build-tests
xcrun --toolchain XcodeDefault swift test --skip-build > full.log 2>&1
```
`exit 0` · **1426** `Test Case '-[...]' passed` · **0** failed · **11** targets ·
**0** occurrences of `Some test targets reported failures`.

Baseline was 1420 passed / 0 failed / 11 targets. 1426 − 1420 = the six new
tests; no existing test changed state.

## Deliberately not done

- **No test that `refreshPublicReadGenerationAfterMutation` specifically clears
  the negative entry.** Driving it needs a full public repository mutation
  through the directory (reserve, engine apply, sign, commit), and the method is
  `fileprivate`. The coverage is structural instead: the clear is on the only
  line in the type that publishes a generation, and that method's entire body is
  a call to the function containing it. The window-expiry path is tested
  directly.
- **No new `PublicReadUnavailableReason` case.** Re-admission reuses
  `.controlRowChanged` for the joiner mismatch, which is what actually happened.
  Adding a case would have meant editing the golden list, and the incident that
  motivated it — an operator unable to tell which guard fired — is already served
  by the existing token.
- **No new log site.** Every re-admission failure already passes through
  `refreshPublicReadGeneration`'s catch and
  `logPublicReadAdmissionFailure`. Adding a second warning would have
  double-logged the same failure per request.
- **No cancellation of in-flight re-admissions on close/revoke.** Explained
  above; the existing post-await guards already fail closed.
- **No change to the post-commit refresh path**
  (`refreshPublicReadGenerationAfterMutation`). It was already correct — it is
  what accidentally ended the live outage — and touching it was out of scope.
- **No proxying, credential-isolation, or peer-pinning code touched.** Phase 1 is
  untouched.
- **`swiftformat` was not run**, per the standing prohibition.

## Concerns

1. **A successful re-admission invalidates concurrent in-flight reads.**
   `recheckPublicAccount` requires `publicReadGenerations[did]?.id ==
   generation.id`, so a request still reading against the superseded generation
   fails its post-read recheck with `.accountNotPreopened`. This is pre-existing
   — `refreshPublicReadGenerationAfterMutation` has always had it, and it is one
   plausible source of the live incident's *first* 503 — but re-admission makes
   generation turnover more frequent, so the window is hit more often. It is
   self-healing (the losing request's next read re-admits and succeeds) and
   strictly better than a permanent 503, but it means a foreign commit can still
   produce a small burst of transient 503s under concurrency rather than zero.
   Worth a follow-up: `recheckPublicAccount` arguably wants to accept "the
   generation I read against, or any generation that has since superseded it,"
   rather than identity on `id`. I did not change it here because it is a
   correctness-sensitive guard outside this task's scope.

2. **`refreshPublicReadGeneration` can still publish a generation after
   `close()`.** Its last `isClosed` check is followed by an `await` on the
   control store before `publicReadGenerations[did] = generation`. Pre-existing
   and unchanged by this task; noted because re-admission exercises that path
   more often.

3. **Two of the new tests sleep past the 250 ms window** (500 ms each, for
   margin). They are timing-dependent by nature — the property under test is a
   time window. They were run three times consecutively without flake, and the
   margin is 2x, but a badly overloaded machine could in principle see the
   *first* pair of reads in the window test span 250 ms and produce a spurious
   extra admission. If that ever shows up, the fix is to lengthen the margin,
   not to loosen the assertion.

4. Concerns 1 and 2 from the original report (the `recheckPublicAccount`
   generation-identity window, and `refreshPublicReadGeneration` publishing
   after `close()`) were adjudicated by review as acceptable and harmless
   respectively, and are left as-is. Concern 3 (the foreign connection being a
   real second `SQLiteAccountDatabase`) was adjudicated as faithful to the
   production trigger rather than a proxy; it is now also backed by the explicit
   `data_version` precondition from F4.
