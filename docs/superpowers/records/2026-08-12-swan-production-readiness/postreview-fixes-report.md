# Post-review fixes — Swan production readiness

Date: 2026-08-12
Branch HEAD at start: `b533ccf956e9`
Toolchain: `xcrun --toolchain XcodeDefault swift build --build-tests` / `swift test`

## Result

| Finding | Status | Commit |
|---|---|---|
| F1 — `getLatestCommit` / `getRepoStatus` reach the 100k walk with no admission lease | Fixed | `7b5d92d35801` |
| F2 — eviction creates a state that bypasses the backoff | **Already fixed at HEAD**, verified by falsification | — (`af6c92c82874`, earlier on this branch) |
| F3 — unbounded warning-log volume on the anonymous read path | Fixed | `fe23b71312a2` |
| F4 — two log sites disagree about which reason a 503 carries | Fixed | `988f422fd783` |

Commit order: `7b5d92d35801` (F1) → `988f422fd783` (F4) → `fe23b71312a2` (F3).
F4 was landed before F3 because both touch `SwanPublicRepositoryReadXRPC.swift`
in different functions; keeping the trivial one first makes either revertible on
its own.

Full suite after all three commits: exit 0, **1489** `Test Case '-[…]' passed`,
0 failed, 9 skipped, 11 targets, no `Some test targets reported failures`.
Baseline was 1484 + 5 new tests.

## F1 — admission lease on the two sync reads

`Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift`.

Both routes now reserve from `jsonReadAdmission` before calling their handler,
release on the throwing path, and hand the lease to `publicReadJSON` so it lives
until the response body drains — the same three-part shape `describeRepo`,
`getRecord` and `listRecords` use. The reservation is
`maximumGetRecordResponseBytes`, and the same constant is passed as
`maximumBytes` so the reservation and the encode ceiling agree, as they do at
every sibling. Both outputs are a CID plus a revision, so the narrower of the two
existing constants costs nothing and keeps relay traffic from reserving the
16 MiB `listRecords` budget per call.

Test: `PublicRepositoryReadHTTPTests.testSyncReadRoutesShareBoundedProcessAdmission`.
An admission with `maximumConcurrentReads: 1` is saturated by a directly held
lease; both routes must answer `503 {"error":"temporarily_unavailable"}` **and**
must not reach the directory (a new `syncOutcomeRequestCount` on the test
directory proves the second half — a 503 that still walked the index would be
the bug wearing the right status code). Releasing the lease restores 200s.

Falsification: replaced the `getRepoStatus` reservation with
`let lease: PublicRepositoryJSONReadLease? = nil`, verified the mutation was on
disk *after* the build, ran the test → red for the expected reason
(`200 OK` where 503 was required; `syncOutcomeRequestCount` 1 instead of 0;
final count 3 instead of 2). `getLatestCommit`, still leased, kept refusing —
so the red is attributable to the mutated route alone. Restored, rebuilt, green.

## F2 — already fixed on this branch

`activePublicReadContext` at HEAD already routes the cold-cache branch through
`admitPublicReadGenerationForRequest`, which consults and records
`publicReadReadmissionFailures`, and `recordPublicReadReadmissionFailure` still
excludes `.generationPinStale`. The fix landed earlier on this branch as
`af6c92c82874` "SwanSQLite: bound cold-cache public reads with the admission
backoff", with cover at
`PublicRepositoryReadStaleGenerationTests.testColdCacheReadsAreBoundedByTheBackoff`.

Verified rather than assumed: reverted the cold branch to call
`refreshPublicReadGeneration` bare and re-ran that test → red with exactly the
finding's shape — `6` admissions where `1` is required, and no backoff entry
recorded after the first cold failure. Restored; the working copy is byte
identical to HEAD for that file, and no commit was made for F2.

## F3 — journal volume bounded by distinct failure, not request rate

Approach: **the full line once per window, a count thereafter — at both layers,
each using the window it already has or the smallest one it needs.**

Storage (`SQLitePreMigratedAccountDirectory`): the suppressed path no longer
re-emits `logPublicReadAdmissionFailure`. `PublicReadReadmissionFailure` gains
`suppressedReads`, incremented per suppressed request, and
`retirePublicReadReadmissionFailure(did:)` drops the entry and emits one
`public read admission refusals suppressed` line carrying the DID, the reason
and the count. It runs at the two places the entry legitimately ends: lazily at
expiry, and at the publish that clears it on recovery. So one window costs at
most two lines — the named admission failure that opened it (already emitted
before this change) plus the rollup. Nothing is lost: the opening line already
carries the DID and reason, and the only fact the per-request lines added was
how much traffic ran into the window, which is one integer. Teardown paths
(`revokeAndDrainAccount`, `close`) still drop entries silently, documented at
the helper.

HTTP (`SwanPublicRepositoryReadXRPC`): new `PublicReadDiagnosticThrottle`, keyed
on `method|reason` — the pair the line actually carries — with a one-second
window. The first refusal of a pair journals immediately; identical ones inside
the window are counted and folded into the next window's line as
`suppressedRepeats`. A *different* method or reason is never delayed or hidden
by an ongoing failure, so a second, distinct problem arriving during the first
stays visible. The key space cannot be grown by request input (method is a
literal at each call site, reason is a `PublicReadUnavailableReason` or
`PublicReadHandlerGuard` raw value); `maximumKeys` restates that as an invariant
and, if it were ever reached, declines to *track* rather than to log — the
fallback is the previous behaviour, not silence.

The 503 body is untouched everywhere: `{"error":"temporarily_unavailable"}` on
every request, journalled or not.

Tests:
- `PublicRepositoryReadStaleGenerationTests.testSuppressedReadsAreCountedRatherThanJournalledPerRequest` —
  16 reads inside one backoff window produce exactly one journal line; recovery
  produces exactly one more (the rollup). The admission count is asserted at 1
  as a precondition, so a window that expired mid-loop fails the test instead of
  making the line count prove nothing.
- `PublicRepositoryReadHTTPTests.testPublicReadDiagnosticThrottleReportsRepeatsOncePerWindow` —
  the throttle's contract, driven with an injected `now` so it is deterministic:
  first admits, repeats suppressed, other pairs unaffected, repeats reported once
  with their count and not carried forward twice.
- `PublicRepositoryReadHTTPTests.testRepeatedUnavailableReadsJournalOnceNotOncePerRequest` —
  twelve identical 503s over the router write **at least one and at most two**
  lines. Both bounds matter: the upper one is the finding, the lower one is the
  earlier work's promise that no 503 leaves unexplained.

Journal volume is measured through two test seams that production never reads:
`publicReadAdmissionJournalLineCount()` on the directory and
`publicReadDiagnosticJournalLines` in `SwanHTTP`, each incremented at the single
site that writes a line. Counting at the *emission* site, not inside the
throttle, is what makes the wiring test able to fail in both directions.

Falsification (storage): restored `logPublicReadAdmissionFailure` on the
suppressed path → red, `17` lines where `1` is required. Restored, green.

Falsification (HTTP): first attempt bypassed the throttle call entirely, which
turned the counter off rather than turning the volume up — it went red on the
*lower* bound. That was a bad mutation, not a bad test, and it exposed that the
counter belonged at the emission site rather than inside the throttle; the code
was restructured accordingly. Second attempt kept the throttle wired but ignored
its refusal (`?? 0`, log regardless) → red for the real reason: `12` lines where
`≤ 2` is required. Restored, green.

## F4 — one name per 503

`publicReadDiagnosticToken` now classifies through `admissionFailureReason`
rather than `unavailableReason`, matching the storage layer. `resourceLimitExceeded`
carries no reason of its own, so a read refused by the projection preflight used
to journal `reason=projectionBoundExceeded` from storage and
`reason=unclassified` from HTTP. Request-shape errors still answer `nil` there,
so they still fall through to `unclassified`, and they never reach this function
anyway — the routes map them to 400. The function is now internal because
nothing about the token reaches a response body, so only a direct assertion can
observe it.

Test: `PublicRepositoryReadHTTPTests.testPublicReadDiagnosticTokenNamesReasonlessAdmissionRefusals`.

Falsification: reverted the accessor → red, `unclassified` where
`projectionBoundExceeded` is required. Restored, green.

## Notes / residual concerns

- The HTTP throttle is process-wide state shared by every public-read route.
  Tests that assert on it call `resetForTesting()` first. Nothing else in the
  suite reads it, and the reset only clears windows, never behaviour.
- `PublicReadDiagnosticThrottle` uses `Synchronization.Mutex`. The comment on
  `PublicRepositoryJSONReadAdmission` says the codebase avoided `Mutex` pending a
  consistent minimum Linux toolchain; `Mutex` is stdlib from Swift 6.0 (SE-0433)
  and the package requires Swift 6.1, so this should be fine on the Linux
  deployment target, but it has not been compiled for Linux here. `Mutex` is
  already used in this repo's test code. The alternative was `@unchecked Sendable`
  with `NSLock`, which the task forbids.
- The two layers bound the journal with different windows — the storage side
  reuses the existing 250 ms admission backoff, the HTTP side has its own 1 s
  window. That is deliberate (each uses the window it already owns) but means a
  fully dark account can, worst case, produce a rollup line every 250 ms from
  storage plus one line per second per method from HTTP. Both are bounded by the
  rate at which real admissions are attempted, not by request rate.
- F1 narrowed both sync routes' encode ceiling from the 16 MiB `listRecords`
  default to the 8 MiB `getRecord` constant. Neither output can approach either
  bound, but it is a behaviour change on paper.
- Verification is test-level only. No deployment or live relay traffic was
  exercised; confirming F1 under real relay load requires running the announced
  service.
