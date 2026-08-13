# L5 — lifecycle-firehose-fence (F37)

Lane files: `Sources/SwanSQLite/PublicLifecycleEmitter.swift`,
`Sources/SwanAccounts/AccountOperatorService.swift`,
`Tests/SwanSQLiteTests/PublicLifecycleEmitterTests.swift`.

## Verdict — F37 CONFIRMED, both halves, exactly as filed

The asymmetry is real and I reproduced its relay-visible consequence
deterministically before changing any production logic.

At the sealed tree:

- `emitActivation` committed its lifecycle batch at
  `PublicLifecycleEmitter.swift:69-71` and then called `enqueueHeadSync` at
  `:72-78` with **no** authorization fence around it.
- `emitReactivationSync` read the generation at `:100` with
  `currentLifecycleGeneration` — a plain read on its own connection gate, not
  a fence — and then called `enqueueHeadSync` at `:101-107`, also unfenced.
- `emitManualSync` is the only one of the three that wrapped the same call in
  `control.withActiveAccountFirehoseAuthorization(did:)` (`:113`), taking the
  generation from the fence closure.

The fence is the load-bearing control. `withActiveAccountFirehoseAuthorization`
(`Sources/SwanSQLite/AccountControlStore.swift:2465-2486`) opens the control
write transaction, re-reads the account, rejects on
`!account.status.authorizesAccount` with `AccountControlStoreError
.invalidTransition` (`:2475-2477`), and reads
`account_lifecycle_generation` inside that same transaction (`:2478-2482`).
Its own doc comment at `:2457-2464` states the property the two unfenced
emitters were missing: "the authorization check and the generation read
therefore linearize together".

### Why an unfenced sync becomes relay-visible

The sequencer orders per DID by generation
(`Sources/SwanSQLite/PublicFirehoseSequencer.swift:150-163`): with both an
account-outbox head and a pending lifecycle batch present it picks the account
row only when `accountGeneration < lifecycleGeneration`. A sync row inserted
*while* the superseding lifecycle batch is still pending is therefore ordered
correctly by construction.

The hole is the `(.some, nil)` arm at `:159-160`. Once the deactivation's
`#account(active:false)` batch has been **drained**, there is no pending batch
left to compare against, so any sync row that lands afterwards — however stale
its generation — is unconditionally sequenced next. That is the exact window
the two unfenced emitters leave open: the batch commit (or the generation
read) happens, the account-database read, CAR build and outbox insert happen
outside any transaction, and a deactivation can commit *and* fully drain in
between.

## The reactivation swallow — verified, not assumed

The lane brief asked me to confirm that the reactivation status write has
really committed before the swallow point, and to report rather than ship if
it has not. It has.

`AccountOperatorService.reactivate` calls `transition(...)` at `:347-354`;
`transition` (`:445-468`) awaits
`store.transitionStatus(did:to:declaration:emitting:now:)` and returns its
result. The SQLite implementation
(`Sources/SwanSQLite/AccountControlStore.swift:2266-2404`) is
`withConnectionGate { transaction { ... } }`, and
`SQLiteControlDatabase.transaction`
(`Sources/SwanSQLite/OAuthControlStore.swift:1456-1471`) issues
`BEGIN IMMEDIATE`, runs the body, issues `COMMIT`, and only then returns —
rolling back on any throw. So control returns to `reactivate:355` only after
the status row **and** the `#account(active:true)` batch enqueued in the same
transaction (`AccountControlStore.swift:2375-2400`, whose comment states "the
batch commits or rolls back with the status write") are durable.

Therefore the swallow at `AccountOperatorService.swift:362-374` is correct:

- The reactivation is already durable and already announced. Failing the
  operator's command because the *follow-up* head announcement lost a race
  would report a false negative for work that actually happened.
- A raced deactivation's own `#account(active:false)` batch is the correct
  announcement of the account's real state, and it is durable too.
- Only `AccountControlStoreError.invalidTransition` is swallowed. Every other
  error — `PublicLifecycleEmitterError.accountUnavailable`,
  `.missingRepositoryHead`, `.missingCommitBlock`, storage failures — still
  propagates, so this is not a blanket `try?`.

## Changes

1. `PublicLifecycleEmitter.swift` — `emitActivation` and
   `emitReactivationSync` now wrap `enqueueHeadSync` in
   `control.withActiveAccountFirehoseAuthorization(did:)` and take the
   generation from the fence closure, structurally identical to
   `emitManualSync`. `emitReactivationSync`'s separate
   `currentLifecycleGeneration` read is gone — the fence's in-transaction read
   replaces it. Both gained the same `AccountControlStoreError.notFound →
   PublicLifecycleEmitterError.accountUnavailable(did)` mapping
   `emitManualSync` already had, so an unknown DID keeps producing the error
   type it produced before the fence existed.
2. `PublicLifecycleEmitter.swift` — the type doc comment now states the fence
   invariant and the drained-batch failure mode, so the next reader does not
   re-derive the asymmetry.
3. `AccountOperatorService.swift` — the `invalidTransition` swallow described
   above, with the reasoning inline.
4. `PublicLifecycleEmitterTests.swift` — two new deterministic-race tests plus
   two test-only hooks (`beforeActivationAuthorization`,
   `beforeReactivationAuthorization`) added beside the existing
   `beforeManualAuthorization`. The private barrier actor was renamed
   `ManualAuthorizationBarrier` → `LifecycleAuthorizationBarrier` since all
   three tests now use it.

`emitRotationIdentity` was deliberately left alone: it enqueues only a
lifecycle batch and never touches the account outbox
(`PublicLifecycleEmitter.swift:107-123`), which
`testEmitRotationIdentityBumpsGenerationAndEmitsIdentityItemOnly` already
pins. There is no head sync to fence.

Per the brief, no generation-vs-durable-current rejection was added to
`PublicFirehoseSequencer`.

## Test mechanism

`testActivationSyncLosesDeterministicRaceToDeactivation` and
`testReactivationSyncLosesDeterministicRaceToDeactivation`, both in
`Tests/SwanSQLiteTests/PublicLifecycleEmitterTests.swift`.

No sleeps, no timing tolerance. The interleaving is forced by a continuation
barrier (`LifecycleAuthorizationBarrier`), mirroring the existing
`testManualSyncLosesDeterministicRaceToDeactivation` at `:375-409`:

1. The emitter is constructed with a hook that parks the emitting task at
   exactly the point the fence now occupies.
2. The test awaits `waitUntilParked()`, so the interleaving is established by
   the continuation, not by a race the scheduler might win either way.
3. While the task is parked, the test deactivates via
   `control.transitionStatus(..., emitting: .init(operationID: ...))` — note
   the `emitting:` argument, which the pre-existing manual-sync race test does
   not pass. Without it no `#account(active:false)` is produced and the
   ordering property being tested cannot be observed at all.
4. The test then runs `sequencer.drainAll(...)` to completion, asserting the
   exact step count. This is the step that closes the sequencer's ordering
   window: the deactivation batch drains while the account outbox is still
   empty, leaving the `(.some, nil)` arm as the only path a late sync row can
   take.
5. The barrier releases, the emission is awaited, and the test asserts
   `AccountControlStoreError.invalidTransition`, an empty account outbox, and
   a final `drainAll` of **0** steps.
6. The load-bearing assertion is stated as the relay sees it: the full
   `firehose.events(after: 0, limit: 20)` **kind sequence**, plus the tail
   `sourceKey`. `FirehoseStoredEvent` carries `kind` and `sourceKey`
   (`Sources/SwanSQLite/SQLiteFirehoseDatabase.swift:42-51`), so this asserts
   over what is actually sequenced onto the public log rather than over an
   emitter-internal state.

## Evidence provenance

Every number below was re-established after two infrastructure problems came
to light, and none of it is carried over from the first pass:

1. The per-session scratchpad under `/private/tmp/claude-501/…/scratchpad/` is
   **shared by all eight lanes** — I confirmed 408 files in it, spanning
   Aug 10-13, with generic names (`baseline.log`, `build.log`, `build2.log`)
   that several lanes chose independently. My files were `L5-`-prefixed, but a
   clobbered log is self-consistent and undetectable by inspection, so the
   prefix is not proof. All logs are now written to
   `/private/tmp/swan-lane-L5-lifecycle-firehose-fence/`, which nothing else
   writes to.
2. This lane has been rebased onto **`29ce8202`** ("SwanSQLiteTests: wrap the
   one await-in-defer that Linux rejects"), the central fix for the Linux
   blocker reported below. Lane commit is now `0ad16546`.

So the suite counts changed for a legitimate reason — the base moved from
`75e7b509` to `29ce8202`, picking up seven other lanes' commits — and the
earlier 1490 figure is superseded rather than corrected.

## Exact pre-fix failure

Re-derived on the rebased base, not quoted from the earlier run. I reverted
**only** the fence in `PublicLifecycleEmitter.swift` (keeping the two test
hooks, so the tests still compile), rebuilt, and ran the three race tests:
exit code 1, **1 passed / 2 failed**. The fenced manual-sync test passed and
both new ones failed — precisely the coverage gap the scan identified. The
fence was then restored with `jj restore` and the working copy verified clean.

```
PublicLifecycleEmitterTests.swift:468: error: -[… testActivationSyncLosesDeterministicRaceToDeactivation] : XCTAssertEqual failed:
  ("[…identity, …account, …account, …sync]")
  is not equal to
  ("[…identity, …account, …account]")
  - no #sync may be sequenced after the #account(active:false) that supersedes it
Test Case '-[… testActivationSyncLosesDeterministicRaceToDeactivation]' failed (3.642 seconds).
Test Case '-[… testManualSyncLosesDeterministicRaceToDeactivation]' passed (0.055 seconds).
PublicLifecycleEmitterTests.swift:535: error: -[… testReactivationSyncLosesDeterministicRaceToDeactivation] : XCTAssertEqual failed:
  ("[…identity, …account, …sync, …account, …sync]")
  is not equal to
  ("[…identity, …account, …sync, …account]")
  - no #sync may be sequenced after the #account(active:false) that supersedes it
Test Case '-[… testReactivationSyncLosesDeterministicRaceToDeactivation]' failed (0.062 seconds).
```

That assertion is the finding itself: the last frame on the public firehose is
a `#sync` announcing a repository head for a generation the already-sequenced
`#account(active:false)` superseded. That is what a relay consuming
`swan.place` would have observed. Full log:
`/private/tmp/swan-lane-L5-lifecycle-firehose-fence/prefix-race.log`.

## Determinism — 20 consecutive runs

Because this lane's deliverable is an interleaving test, and because a run
that overlapped another lane's container being killed would read as flakiness
rather than as signal, the two race tests were run repeatedly on the restored
fence rather than once:

- **20 consecutive invocations**, each `swift test --skip-build --filter
  "PublicLifecycleEmitterTests/test.*LosesDeterministicRaceToDeactivation"`.
- **20/20 exit 0. 60 passed, 0 failed** across the 20 runs (3 cases each).
- Zero occurrences of `Some test targets reported failures` in any of the 20
  logs.

There is no timing tolerance in the tests to be lucky about: the interleaving
is established by a continuation barrier that the emitting task cannot pass
until the test releases it, so the sequencer drain always happens while the
sync insert is suspended. The 20 runs confirm the harness, not the property.

## Suite result

`xcrun --toolchain XcodeDefault swift test --skip-build` (after an explicit
`swift build --build-tests`), redirected to a file in the private log
directory, **exit code 0**:

| | |
|---|---|
| `^Test Case .* passed` | **1492** |
| `^Test Case .* failed` | **0** |
| `^Test Case .* skipped` | **9** |
| `Test Suite '….xctest' passed` | **11** |
| `Test Suite '….xctest' failed` | **0** |
| `Some test targets reported failures` | **0 occurrences** |
| swift-testing | 6 tests in 1 suite passed; 11 empty runs |

Counted with `grep -cE "^Test Case .* passed"`. Note the counting recipe
circulated to the lanes, `grep -c "Test Case '-\[.*\] passed"`, matches
nothing at all — the real line has an apostrophe between `]` and ` passed`
(`Test Case '-[Suite testName]' passed (0.004 seconds).`). It returns 0 on a
fully green log, which is the worst possible failure shape for a counting
recipe. I hit this early and used `…\]' passed` before reporting any figure,
so no number in this report ever came from the broken pattern. Exit code and
the `Some test targets reported failures` grep remain the primary signals.
No output was piped through `tail`.

Baseline arithmetic: the brief quotes 1489 passed at the sealed base. This run
is on a **different base** (`29ce8202`, seven lanes ahead of `75e7b509`), so
the two are not comparable and I am not claiming a delta against 1489. What
holds unconditionally: 0 failed, 11/11 targets green, no failure marker.

## Linux build

**`swift build --build-tests` on Swift 6.1 Linux: exit 0, `Build complete!
(330.70s)`, zero `error:` lines, `SwanPackageTests.xctest` linked.**
`Compiling SwanSQLiteTests …` appears 32 times, including this lane's
`PublicLifecycleEmitterTests.swift`, with no diagnostics against it. Log:
`/private/tmp/swan-lane-L5-lifecycle-firehose-fence/linux-final.log`.

Command, run after the macOS suite had finished (not concurrently) and with a
**named** container so it cannot be caught by an image-filtered `docker kill`:

```
docker run --rm --name swan-L5 \
  -v …/Petrel:/workspace/Petrel \
  -v …/Swan-L5-lifecycle-firehose-fence:/workspace/Swan \
  -w /workspace/Swan swift:6.1-jammy bash -lc \
  'apt-get update && apt-get install -y --no-install-recommends \
     libsodium-dev pkg-config libsecret-1-dev libglib2.0-dev && \
   swift build --build-tests --scratch-path /workspace/Swan/.build-linux'
```

`.build-linux` is covered by `.gitignore:2` (`.build-*/`), so it leaves the
working copy clean.

### Correcting my own earlier diagnosis

My first report said building **from a macOS bind mount** fails during
resource copying, citing `NSCocoaErrorDomain Code=512 …
NSSourceFilePathErrorKey=…/Tests/SwanOAuthTests/Fixtures`. **That diagnosis was
wrong and I am withdrawing it.** The command above builds from a bind mount and
copies those same fixtures without complaint.

The actual rule is narrower: **the scratch path must be on the same filesystem
as the sources.** My three failures all put it elsewhere — a named Docker
volume, then the container's own layer — while the working recipe keeps it
inside the bind-mounted workspace. Same-mount copying works; cross-mount
directory copying out of virtiofs is what fails. The elaborate
copy-the-tree-into-the-container workaround I described is unnecessary; use
`--scratch-path <workspace>/.build-linux`.

### The Linux blocker, now fixed centrally

Before `29ce8202`, `--build-tests` could not compile on Linux for **any** lane:
`Tests/SwanSQLiteTests/AccountPermanentDeletionSQLiteTests.swift:260` was a
bare `defer { try? await database.close() }`, which Swift 6.1 on Linux rejects
with `'async' call cannot occur in a defer body` while the macOS Xcode
toolchain accepts it. It was the only such site missing its `Task { }` wrapper.
This lane is rebased onto that fix, which is why a Linux test build is
obtainable here at all. My earlier "verified by patching it inside a throwaway
container" is superseded by this real build against the real fix.

### Caveat

This host is Apple Silicon, so the container built
`aarch64-unknown-linux-gnu` (confirmed: no `x86_64` triple appears in the
log), not the `x86_64` deployment target. Nothing in this lane is
architecture-sensitive — no unsafe pointer work, no endianness, no
platform-conditional code — but the claim is "Linux-green on aarch64", not
"x86_64-verified".

## Notes for the merge

- **No deadlock introduced.** The fence holds the control-plane write
  transaction while `enqueueHeadSync` reads the *account* database and builds
  a CAR. That is exactly what `emitManualSync` already did, and the production
  account source
  (`SQLitePreMigratedAccountDirectory.publicFirehoseAccountDatabases`,
  `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift:317-329`) is an
  in-memory dictionary read on the directory actor — it never re-enters the
  control database. No network I/O is performed inside the fence, so the
  contract at `AccountControlStore.swift:2436-2438` is respected. (That file
  was read only; it is owned by another lane.)
- **Activation-path error surface.** A raced deactivation now fails
  `emitActivation`. On the management HTTP route
  (`Sources/SwanHTTP/SwanManagementPLCProvisioning.swift:309-334`) the
  existing catch-all already maps any emission error to the retryable
  `PLCAccountActivationError.unavailable`, so no new error case and no wider
  client-visible body. On `PLCAccountActivationService.swift:157-166` the
  error propagates, which the comment at `:150-156` already documents as the
  intended behaviour for a thrown emission.
- **Linux gate.** `swift build --build-tests` is now satisfiable on the
  pinned toolchain (post-`29ce8202`) and passes here. Note separately that
  `Dockerfile:14` builds `swift build -c release --product swan` and never
  builds tests, so the library/executable build is what actually ships.
- **Coverage gap, deliberately not closed.** The `AccountOperatorService`
  swallow has no direct test: the operator-service tests live in
  `Tests/SwanCLITests/AccountOperatorServiceTests.swift`, which is outside
  this lane's file list. Its `RecordingLifecycleEmitter` (`:474-501`) never
  throws, so the existing suite exercises the non-raced path only. A test
  driving a throwing emitter through `reactivate` belongs in that file and
  should be added by whoever owns it.
- **Indentation.** `PublicLifecycleEmitter.swift` and
  `AccountOperatorService.swift` are 4-space files and the edits match.
  `Tests/SwanSQLiteTests/PublicLifecycleEmitterTests.swift` is a 2-space file
  (as are its `SwanSQLite` neighbours `LifecycleEventOutboxStore.swift`,
  `PublicFirehoseSequencer.swift`, `SQLiteFirehoseDatabase.swift`); the new
  tests match the file they live in rather than the program-wide default.
- `swiftformat` was not run.
