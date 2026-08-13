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

## Exact pre-fix failure

Both tests were written and run against the unfenced emitters first (only the
two hooks were added at that point; the fence was not). `swift test --filter
"PublicLifecycleEmitterTests/test.*LosesDeterministicRaceToDeactivation"`,
exit code 1 — the fenced manual-sync test passed, both new ones failed, which
is precisely the coverage gap the scan identified:

```
Test Case '-[SwanSQLiteTests.PublicLifecycleEmitterTests testActivationSyncLosesDeterministicRaceToDeactivation]' started.
PublicLifecycleEmitterTests.swift:457: error: ... : failed - a deactivated account published an activation sync
PublicLifecycleEmitterTests.swift:462: error: ... : XCTAssertTrue failed - the raced activation sync must not become durable
PublicLifecycleEmitterTests.swift:466: error: ... : XCTAssertEqual failed: ("1") is not equal to ("0")
PublicLifecycleEmitterTests.swift:468: error: ... : XCTAssertEqual failed: ("[...identity, ...account, ...account, ...sync]") is not equal to ("[...identity, ...account, ...account]") - no #sync may be sequenced after the #account(active:false) that supersedes it
PublicLifecycleEmitterTests.swift:473: error: ... : XCTAssertEqual failed: ("Optional("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa|sync|activation|req-raced")") is not equal to ("Optional("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa|account|deact-during-activation")")
Test Case '-[...testActivationSyncLosesDeterministicRaceToDeactivation]' failed (3.346 seconds).
Test Case '-[...testManualSyncLosesDeterministicRaceToDeactivation]' passed (0.065 seconds).
Test Case '-[...testReactivationSyncLosesDeterministicRaceToDeactivation]' started.
PublicLifecycleEmitterTests.swift:524: error: ... : failed - a deactivated account published a reactivation sync
PublicLifecycleEmitterTests.swift:529: error: ... : XCTAssertTrue failed - the raced reactivation sync must not become durable
PublicLifecycleEmitterTests.swift:533: error: ... : XCTAssertEqual failed: ("1") is not equal to ("0")
PublicLifecycleEmitterTests.swift:535: error: ... : XCTAssertEqual failed: ("[...identity, ...account, ...sync, ...account, ...sync]") is not equal to ("[...identity, ...account, ...sync, ...account]") - no #sync may be sequenced after the #account(active:false) that supersedes it
PublicLifecycleEmitterTests.swift:540: error: ... : XCTAssertEqual failed: ("Optional("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa|sync|reactivation|react-raced")") is not equal to ("Optional("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa|account|deact-during-reactivation")")
Test Case '-[...testReactivationSyncLosesDeterministicRaceToDeactivation]' failed (0.066 seconds).
```

The fourth assertion in each is the finding itself: the last frame on the
public firehose is a `#sync` announcing a repository head for a generation the
already-sequenced `#account(active:false)` superseded. That is what a relay
consuming `swan.place` would have observed.

After the fence, all 16 `PublicLifecycleEmitterTests` cases pass, including
the two new ones and the pre-existing manual-sync race test.

## Suite result

`xcrun --toolchain XcodeDefault swift test --skip-build` (after an explicit
`swift build --build-tests`), output redirected to a file, **exit code 0**:

| | |
|---|---|
| `Test Case '-[…]' passed` | **1490** |
| `Test Case '-[…]' failed` | **0** |
| `Test Case '-[…]' skipped` | **9** |
| `Test Suite '….xctest' passed` | **11** |
| `Test Suite '….xctest' failed` | **0** |
| `Some test targets reported failures` | **0 occurrences** |
| swift-testing | 6 tests in 1 suite passed; 11 empty runs |

Counted with `grep -c "Test Case '-\[.*\]' passed"`, not by summing
`Executed N tests` lines. No output was piped through `tail`.

One honest discrepancy to record: the brief states a 1489-passed baseline, and
this lane adds exactly 2 test cases, so a 1489 baseline predicts 1491. The
observed 1490 implies the sealed baseline **in this workspace** is 1488. My
changes cannot remove a test case — no test method was deleted, and the only
rename was of a file-private helper actor
(`ManualAuthorizationBarrier` → `LifecycleAuthorizationBarrier`) — so the
likeliest explanation is that the quoted 1489 was measured on a slightly
different tree than `75e7b509`. What matters for the gate holds either way:
0 failed, 11/11 targets green, no failure marker, and strictly more passing
cases than the stated baseline.

## Linux build

**Result: both changed source files compile on the deployment toolchain, and
the test target compiles too once one pre-existing line outside this lane is
patched. The program's stated Linux recipe cannot pass as written, for a
reason that predates this lane.**

Three things had to be corrected before any Linux result was obtainable, and
they are worth recording for the other lanes:

1. `swift:6.1-jammy` is missing Swan's system dependencies. Swan's own
   `Dockerfile:3-9` installs `libsodium-dev pkg-config libsecret-1-dev
   libglib2.0-dev` before building. The stock image fails at link
   configuration. I used `swan-linux-build:6.1-jammy`, which is exactly
   `swift:6.1-jammy` plus that one `apt-get install` layer (verified with
   `docker history --no-trunc`).
2. Building **from a macOS bind mount fails** during resource copying,
   regardless of where the scratch path points:
   `NSCocoaErrorDomain Code=512 … NSSourceFilePathErrorKey=…/Tests/
   SwanOAuthTests/Fixtures, NSUserStringVariant=["Copy"]`. Reproduced with the
   scratch path on a named Docker volume and again on the container layer. The
   fix is to copy the sources into the container first
   (`tar -C /src --exclude=.build … | tar -C /work -xf -`) and build from
   there.
3. The Docker VM disk is shared and was at 93% with several lanes building
   concurrently; a container-layer `.build` exhausted it mid-compile (`error:
   … No space left on device`). Point `--scratch-path` at a host bind mount
   outside the repo.

### What passed

- **`swift build` (library + `swan` executable), Swift 6.1 Linux — exit 0,
  `Build complete!`.** This is the real deployment gate: `Dockerfile:14` runs
  `swift build -c release --product swan` and never builds tests. It compiles
  both files this lane changed (`SwanSQLite`, `SwanAccounts`).
- **`swift build --build-tests` — exit 0, all test targets linked**, after
  patching exactly one pre-existing line (see below). The log shows
  `Compiling SwanSQLiteTests PublicLifecycleEmitterTests.swift` with no
  diagnostics against it.

### The pre-existing blocker

Unpatched, `swift build --build-tests` fails on Swift 6.1 Linux with `error:
'async' call cannot occur in a defer body` at
`Tests/SwanSQLiteTests/AccountPermanentDeletionSQLiteTests.swift:260`. Every
error in the log comes from that one file and no other
(`grep -o '^/work/lane/[^:]*:.*error:' | sed 's/:.*//' | sort -u` returns a
single path). The line is `defer { try? await database.close() }`; all ~25
sibling occurrences across the suite are written `defer { Task { try? await
… } }`, which is legal. The macOS Xcode toolchain accepts the bare form, so
this has been invisible on macOS.

Consequence for the program: **the mandated
`docker run … swift build --build-tests` gate has never passed on Swan's own
pinned Linux toolchain.** The fix is to wrap that one line in `Task { }` to
match its siblings. `Tests/SwanSQLiteTests/AccountPermanentDeletionSQLiteTests
.swift` is outside this lane's file list, so I did not change it in the repo —
I patched it only inside the throwaway container copy to prove the failure is
confined to it. Whoever owns that file should land the one-line fix.

### Caveat

This host is Apple Silicon, so the container built `aarch64-unknown-linux-gnu`,
not the `x86_64` deployment target. That limitation applies to the program's
own recipe as written and was not introduced here. Nothing in this lane is
architecture-sensitive (no unsafe pointer work, no endianness, no
platform-conditional code), but the claim is "Linux-green on aarch64", not
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
