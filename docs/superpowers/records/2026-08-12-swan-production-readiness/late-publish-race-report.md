# IMPORTANT-1 — the late-publish wedge race

Finishing a partially-complete fix left uncommitted at parent `fc11540f4d3e`.

## The defect

`refreshPublicReadGeneration` in
`Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift` published
`publicReadGenerations[did] = generation` after re-checking `isClosed`, database
identity, control row, status, and file path — but nothing that observes
`public_repository_state`, and a generation carries only a `UUID`, so two
generations cannot be ordered against each other.

Two uncoordinated publishers exist: the request path (single-flighted through
`readmitPublicReadGeneration`) and `refreshPublicReadGenerationAfterMutation`.
The failing interleaving:

1. A reader's re-admission `T1` completes `admitPublicRepositoryGeneration`
   against the pre-commit snapshot, then suspends at the control-store round
   trip in `verifyPublicIdentityIntent`.
2. A write commits and its post-mutation refresh republishes (or fails early
   and evicts).
3. `T1` resumes, passes every guard — a repository write moves neither the
   control row nor, when committed on the directory's own connection,
   `PRAGMA data_version` — and publishes its **pre-commit** generation over the
   fresher one.
4. `activePublicReadContext` compares only `controlAccount == account`, so every
   subsequent read hits that cached generation and fails
   `state == generation.description.state` with `.repositoryStateMismatch`.
5. `.repositoryStateMismatch` is not change detection: not retried, not evicted,
   not negative-cached. **Permanent 503 for that account** until the next
   successful write or a process restart.

## What the prior implementer had already done

All of this was present and uncommitted in the working copy:

- `publicReadGenerationPublishSequence: [String: UInt64]`, a per-DID monotonic
  invalidation counter.
- `publishPublicReadGeneration` / `evictPublicReadGeneration` /
  `advancePublicReadPublishSequence` helpers, with every publish and every
  eviction moving the sequence.
- `advancePublicReadPublishSequence(did:)` as the first statement of
  `refreshPublicReadGenerationAfterMutation`, before its first suspension.
- A sample of the sequence at the top of `refreshPublicReadGeneration` and a
  re-check immediately before the publish, throwing
  `.generationPublishSuperseded`.
- The new `PublicReadUnavailableReason.generationPublishSuperseded` case in
  `Sources/SwanStorage/PublicRepositoryReadDirectory.swift`, added to
  `isChangeDetection`.
- A test-only `publicReadPublishBarrier` seam plus
  `setPublicReadPublishBarrier`, awaited between the admission and the intent
  verification.

No test, and no commit.

## Audit

Each item below was checked against the file, not assumed.

### Every write to `publicReadGenerations` goes through the helpers — correct as written

`grep` for `publicReadGenerations[` / `.removeValue` / `.removeAll` finds five
mutation sites and four read sites. All five mutations are accounted for:

- `installAccount`'s transferred-database arm (line ~490) — converted. The old
  `publicReadGenerations[did] = publicGeneration` assigned an *optional*, so
  `nil` already removed the key; the new `if let publicGeneration { publish }
  else { evict }` is behaviour-identical plus the sequence move. Correct, and
  the sequence move is necessary: installing a transferred database must beat an
  admission still in flight against the pre-transfer one.
- The permanent-revocation path (line ~1102) — converted to `evict`.
- Both post-mutation refresh failure arms (lines ~1594, ~1596) — converted.
- `publishPublicReadGeneration` / `evictPublicReadGeneration` themselves.
- `close()` (line ~1140) advances the sequence for every DID that has a cached
  generation, then `removeAll()`. A DID with an in-flight admission but *no*
  cached generation is not advanced — but that is not a hole: after `close()`
  the admission's own post-barrier `guard !isClosed` and
  `guard databases[did] === database` both fire first.

The four read sites (`cachedPublicReadGenerationID`, `activePublicReadContext`,
`readmitPublicReadGeneration`, and two `?.id ==` recheck guards) are read-only
and correctly left alone.

### `.generationPublishSuperseded` handling by callers — correct as written

- `refreshPublicReadGenerationAfterMutation` converts it into an eviction, not a
  failed mutation: the throw lands in the generic `catch`, which evicts and
  journals `.postMutationRefreshFailed`. The mutation itself already committed
  and returns success. Correct.
- `withPublicReadGeneration` cannot loop on it. The reason can only be raised by
  `refreshPublicReadGeneration`, which is reached from
  `activePublicReadContext` (before `attempt` ever runs) or from
  `readmitPublicReadGeneration` — which *is* the second attempt's admission, not
  an `attempt`. Neither position can re-enter the retry. The bound stays
  structural: `attempt` appears exactly twice on a straight line, no loop, no
  recursion.

The one behavioural cost, which the prior implementer documented deliberately:
the losing reader's own request 503s once. That is not a regression — before the
fix that same reader published stale and then failed its *own* second attempt
with `.repositoryStateMismatch`, so it 503'd either way. The difference is that
nobody else is wedged afterwards.

### `isChangeDetection` membership — correct as written

The property gates two things and both are right for this reason:

- `withPublicReadGeneration` retries change detection. As shown above, this
  reason cannot reach that retry from either raise site, so membership is inert
  there.
- `recordPublicReadReadmissionFailure` refuses to record change detection.
  Membership is load-bearing here: recording a lost publish race would suppress
  admissions for the whole 250 ms backoff window on the strength of a scheduling
  accident. Asserted by the new test.

The `switch` in `isChangeDetection` is exhaustive with no `default`, and the new
case was added to the `true` arm.

### Exhaustive switches elsewhere — one real gap, fixed

`PublicReadUnavailableReason` is switched over in exactly two places, both in
`PublicRepositoryReadDirectory.swift`, and both still compile.

But the enum is `CaseIterable` with `String` raw values, and
`Tests/SwanSQLiteTests/PublicRepositoryReadDiagnosticsTests.swift:50`
`testJournalTokensMatchTheGoldenList` asserts the full raw-value set against a
hand-maintained golden list — deliberately, so that adding a reason forces a
line to be added on purpose. The prior work did not add it, so that test would
have failed. **Fixed**: added `"generationPublishSuperseded"` to the golden
list.

### One stale doc comment — fixed

`withPublicReadGeneration`'s doc still said `isChangeDetection` "is
`.generationPinStale` and nothing else". The prior implementer updated the
corresponding prose in `PublicRepositoryReadDirectory.swift` but not this one.
**Fixed**, and the correction also records *why* the new reason cannot reach
that retry.

Nothing else in the production change needed altering. The sequence design, the
placement of the advance before the first suspension, the placement of the
re-check in the same actor turn as the publish, the wrapping `&+`, and the
per-DID (rather than directory-wide) keying are all correct as written.

## The test

`Tests/SwanSQLiteTests/PublicRepositoryReadStaleGenerationTests.swift` —
`testAdmissionSuspendedAcrossACommitDoesNotRefillTheCache`. Fourteenth test in
the file; the first with two publishers in flight at once, which was the gap.

Mechanism, deterministic and sleep-free:

1. `makeFixture()`, then a warm read so a generation is cached.
2. `commitFromSecondConnection` drifts `PRAGMA data_version`, so the next read
   must re-admit rather than answer from cache. That re-admission is `T1`.
3. A `PublishRendezvous` actor is installed through
   `setPublicReadPublishBarrier`. It holds the **first** arrival only and lets
   every later one through — a rendezvous that held all of them would deadlock
   on the writer's own post-mutation refresh.
4. `T1` starts in a `Task`; the test awaits `waitForArrival()`, then asserts the
   verifier's admission count moved by exactly 1, so a reader that never parked
   fails the precondition instead of silently racing nothing.
5. Still holding `T1`, the test runs `applyOneRecord` — a real signed commit
   through the same `generationRefreshingPublicMutationStore` the HTTP mutation
   path uses — to completion, including its post-mutation refresh, and captures
   the generation ID that refresh published.
6. `release()`, then `T1`'s result is awaited.

Assertions: `T1` refuses with `.generationPublishSuperseded`; that reason is
change detection; **no** backoff window was opened (asserted *before* the reads
below, so their success cannot be a window merely expiring); the cached
generation ID still equals the writer's; four consecutive `getRepoStatus` reads
serve the committed revision; and `describeRepo`, `listRecords` and `getRepo`
are likewise unwedged, since the state pin is shared by every
generation-validated read shape.

Both seams used are `internal` and test-only: `setPublicReadPublishBarrier` and
the pre-existing `cachedPublicReadGenerationID` /
`hasLivePublicReadReadmissionBackoff`. `publicReadPublishBarrier` is `nil` in
every production configuration and unreachable from outside the module.

### Negative control

The sequence comparison was neutralised — and only that comparison, by changing
`guard publicReadPublishSequence(did: account.did) == admittedAtSequence` to
`guard admittedAtSequence == admittedAtSequence`, leaving the throw, the reason,
and every other guard in place.

This was done **inside the Linux container's staged copy only**, never in the
shared checkout: several agents are working in this repository concurrently, and
a temporarily broken guard sitting in a shared working copy is something another
lane could snapshot. The container's copy is thrown away with the volume.

Rebuild, then the same test. Three failures, exactly as predicted, quoted from
`/private/tmp/swan-lane-late-publish-race/linux-negative.log`:

```
Tests/SwanSQLiteTests/PublicRepositoryReadStaleGenerationTests.swift:799: error:
  XCTAssertEqual failed:
  ("Optional(SwanStorage.PublicReadUnavailableReason.repositoryStateMismatch)")
  is not equal to
  ("Optional(SwanStorage.PublicReadUnavailableReason.generationPublishSuperseded)")
  - an admission whose snapshot was invalidated mid-flight must refuse to publish

Tests/SwanSQLiteTests/PublicRepositoryReadStaleGenerationTests.swift:825: error:
  XCTAssertEqual failed:
  ("Optional(D645ACB8-B904-4644-8467-87304E4DC2FC)") is not equal to
  ("Optional(22E696E2-364B-419E-94E8-AA14450CD623)")
  - the superseded admission must not have overwritten the fresher generation

<EXPR>:0: error: threw error
  "unavailable(reason: SwanStorage.PublicReadUnavailableReason.repositoryStateMismatch)"

Test Case 'testAdmissionSuspendedAcrossACommitDoesNotRefillTheCache' failed (0.129 seconds)
	 Executed 1 test, with 3 failures (1 unexpected) in 0.129 (0.129) seconds
```

That is the wedge exactly as described: the reader publishes over the writer's
generation (two different UUIDs), and the very first read afterwards throws
`.repositoryStateMismatch` — permanently, since nothing on that path retries,
evicts, or negative-caches it.

The same three failures were reproduced earlier on macOS with *different*
generation UUIDs, which is itself the check that neither run is a stale or
foreign log: the UUIDs are minted per run, so two runs agreeing on the failure
shape while disagreeing on the UUIDs cannot both be the same captured output.

## Suite result

`xcrun --toolchain XcodeDefault swift test`, whole suite, no `--filter`, output
not piped through `tail`. Run **twice**, independently, both into
`/private/tmp/swan-lane-late-publish-race/` (see "Evidence provenance" below for
why):

| | `macos-suite2.log` | `macos-suite3.log` |
|---|---|---|
| exit code | **0** | **0** |
| passed | **1490** | **1490** |
| failed | **0** | **0** |
| skipped | **9** | **9** |
| targets | **11** | **11** |
| `Some test targets reported failures` | 0 | 0 |
| `testAdmissionSuspendedAcrossACommitDoesNotRefillTheCache` | passed | passed |
| `testJournalTokensMatchTheGoldenList` | passed | passed |

1490 = the 1489 baseline + the one new test. Both runs also carry 6 swift-testing
tests in 1 suite, passing; the 1489 baseline counts XCTest cases only.

The two runs serialized on the SwiftPM `.build` lock rather than overlapping —
each log contains exactly one `Another instance of SwiftPM ... waiting` line — so
neither was reading a `.build` the other was writing.

Note for anyone repeating this: the pass-count grep must include the closing
quote — `Test Case '-\[.*\]' passed`. Dropping it matches nothing and reports 0
passes on a green run. I hit this and briefly recorded 0 passes on a green suite.

### One unrelated hang, under load

An earlier attempt at the full suite **hung for 29 minutes** in
`SwanOAuthTests` / `PLCSpaceCredentialSingleFlightTests`, with the box at load
average 17.8 (seven other agents building and testing concurrently). It was
killed and re-run; both clean runs above passed that target normally.

Not caused by this change — the target is OAuth credential single-flight and
shares no code with public-read admission. Recorded because it is a real hazard
for anyone timing this suite under contention, and because the first suspicion
on seeing it should not be "the new concurrency test is flaky". `waitForFetchCount`
in that file *does* carry a 2-second deadline, so the hang is somewhere else in
it; I did not chase it further, as it is outside this lane.

Note that killing a hung `swift test` leaves the `swift-test` driver holding the
`.build` lock — the next run then blocks on `Another instance of SwiftPM (PID: …)
is already running`. Kill that PID too.

## Linux build

The deployment target is Linux and macOS green is not sufficient — a prior fix
in this same file compiled on macOS and failed on Linux with `non-sendable
result type 'T' cannot be sent from nonisolated context`.

Built with the image the repo's own `Dockerfile` pins,
`swift:6.1-jammy@sha256:12be34a341945adb64914405ed7b568fcb2d35edbd63a3755007e47dce59456e`,
with the same system packages that `Dockerfile` installs (`libsodium-dev`,
`pkg-config`, `libsecret-1-dev`, `libglib2.0-dev`), and with `Swan` + `Petrel`
copied into the container filesystem rather than built in place on the bind
mount.

**`swift build --build-tests` on Linux: exit 0, `Build complete! (490.32s)`** —
a full cold build of a freshly staged copy, not an incremental rebuild, so
nothing was served from cache. No Sendable diagnostic of any kind.

The tests were then also *run* on Linux, which is stronger than the brief asked
for. From `/private/tmp/swan-lane-late-publish-race/linux-positive.log`:

- `PublicRepositoryReadStaleGenerationTests` — 15 tests, 0 failures.
- `PublicRepositoryReadDiagnosticsTests` — 4 tests, 0 failures.
- Named individually for the record:
  `testAdmissionSuspendedAcrossACommitDoesNotRefillTheCache` **passed**
  (0.15 s) and `testJournalTokensMatchTheGoldenList` **passed** on
  `aarch64-unknown-linux-gnu`.

### One pre-existing Linux-only break, not mine — now fixed by another lane

`swift build --build-tests` on Linux fails on
`Tests/SwanSQLiteTests/AccountPermanentDeletionSQLiteTests.swift:260`:

```
error: 'async' call cannot occur in a defer body
```

The line is `defer { try? await database.close() }`. macOS Swift accepts it;
Linux Swift 6.1 rejects it. It is the **only** bare `await`-in-`defer` in the
package — every other one in `Tests/` and `Sources/` wraps the call in a
`Task { }`, which is legal. The file is untouched by this change, and the break
predates it.

It mattered here only because that file is in the same module as the new test, so
the module could not be type-checked on Linux until it was dealt with. On my
first pass I neutralised it **in the container's staged copy only** (`sed` on the
volume, to the `Task { }` form its siblings already use) and never in the
repository, since it is outside this task's scope.

It has since been fixed properly in the repository by another lane, in commit
`29ce8202` *"SwanSQLiteTests: wrap the one await-in-defer that Linux rejects"*.
**The Linux figures reported above are from a staged copy that already contains
that fix and required no patching of any kind.**

Production deploys were never affected — `Dockerfile` runs
`swift build -c release --product swan`, which does not build tests.

### Environment notes for whoever runs this next

- Building directly on the macOS bind mount fails at `Copying Fixtures` with
  `NSCocoaErrorDomain Code=512` on `Tests/SwanOAuthTests/Fixtures`. That is a
  bind-mount resource-copy failure, not a compile error. Copy into the container
  first.
- The copy must exclude `.build` **unanchored**. macOS `tar` and the GNU `tar`
  inside the container disagree about exclude anchoring: `--exclude='./.build*'`
  misses `Petrel/Server/.build` (2.3 GB) and `Petrel/.claude` (4.1 GB), and the
  copy then fills the container disk before the build starts. `--exclude=.build
  --exclude=.build-* --exclude=.claude --exclude=_trash --exclude=.venv` brings
  the payload to 2.0 GB.
- Docker Desktop's VM here is **8 GB RAM / 4 CPU**, not the host's 128 GB. I use
  `-j 2`, which completes reliably.
- **Always `docker run --name <something-lane-specific>`.** Another agent ran
  `docker ps -q --filter ancestor=swift:6.1-jammy | xargs docker kill`, which
  matches every lane's container rather than its own. One of my earlier attempts
  died with exit 137 (SIGKILL); I originally attributed that to the 8 GB VM
  OOM-killing the build, and I cannot now distinguish the two — SIGKILL looks
  identical either way. **Correction to my first report: the exit-137 run should
  be treated as void, cause unknown, not as evidence about memory.** Nothing else
  rests on it; the results reported here come from named containers that ran to
  completion and printed `Build complete!` with exit 0, which a killed container
  cannot do.
- Staging the two source trees in a named volume makes retries cheap, and
  baking the `Dockerfile`'s four `apt` packages into a throwaway image avoids a
  flaky `apt-get update` (exit 100) on every attempt.
- The Linux container never bind-mounts `.build`. Both source trees are mounted
  read-only and copied into a container-local volume, so a Linux build cannot
  interfere with a concurrent macOS `swift test` against the same checkout.

## Evidence provenance

Every number in this report was re-established after it emerged that
`/private/tmp/claude-501/.../scratchpad/` and `/tmp` are **shared by all
concurrent agents**, so a log written to a generic path can be silently clobbered
by another lane and still read as perfectly self-consistent.

My first pass wrote to `/tmp/swan-test.log`, `/tmp/swan-linux.log`,
`/tmp/swan-neg.log` and similar — all exposed. Everything was therefore re-run
from scratch into `/private/tmp/swan-lane-late-publish-race/`, which nothing else
writes to:

| Claim | Log | Runs |
|---|---|---|
| macOS suite green, 1490/0/9/11 | `macos-suite2.log`, `macos-suite3.log` | 2 |
| Linux `--build-tests` green (cold, 490 s) | `linux-positive.log` | 1 |
| Linux tests pass, 19/0 | `linux-positive.log` | 1 |
| Guard-removed failure | `linux-negative.log` | 1 (+1 earlier on macOS) |

The re-run reproduced the original figures exactly (1490 / 0 / 9 / 11, twice),
so the first pass appears not to have been clobbered — but that is a conclusion
drawn *after* re-running from a private path, not an inference from inspecting
the old logs, which is not something a clobbered log permits.

One correction I should make plainly rather than quietly: the Linux command in
my brief (`-v "$PWD":/src` against `swift:6.1`) genuinely cannot work — the
`.package(path: "../Petrel")` dependency at `Package.swift:25` sits outside the
mount, and the four `libsecret`/`libsodium` dev packages are missing. **I did not
use that command.** I hit both failures, diagnosed them, and built the working
invocation documented above, so no Linux result in this report — first pass or
re-run — was ever produced by it.

## Concerns

1. **A lost publish race costs the losing reader one 503.** Deliberate and
   documented, and strictly better than the previous behaviour (that reader
   failed anyway, and everyone else stayed wedged). It could be removed by
   having `admitPublicReadGenerationForRequest` fall back to the freshly-cached
   generation on `.generationPublishSuperseded` — the same short-circuit
   `readmitPublicReadGeneration` already performs before admitting. I did not
   implement it: it widens a live production fix for an availability nicety, and
   the current behaviour self-heals on the next request. Worth considering
   separately if relay traffic makes lost races common enough to show up in the
   journal.
2. **Two concurrent post-mutation refreshes will make the loser evict the
   winner's fresh generation** (its throw lands in the eviction catch). Safe —
   an eviction only costs the next read a cold admission, and never leaves a
   stale pin — but it does journal a `.postMutationRefreshFailed` line that
   names a race rather than a failure. Cosmetic; noted so it is not mistaken for
   a real refresh failure during an incident.
3. Nothing in this change touches a client-visible body. The 503 body remains
   exactly `{"error":"temporarily_unavailable"}`; `.generationPublishSuperseded`
   is a journal token only.
