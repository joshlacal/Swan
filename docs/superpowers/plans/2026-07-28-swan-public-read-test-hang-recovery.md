# Swan Public Read Test-Hang Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore a deterministic `PublicRepositoryReadHTTPTests` test gate, finish the independent Task 43 rereview, and resume public-repository implementation without mistaking a SwiftPM/toolchain failure for an HTTP test deadlock.

**Architecture:** Treat package resolution, compilation, code signing, and XCTest execution as four separate gates. Use one coherent Xcode toolchain/SDK and one fresh scratch directory, permit only one SwiftPM writer at a time, and use `--skip-build` plus per-test filters to prove whether any source-level test hang exists. Do not change production or test code until a built XCTest process reproduces a specific timeout.

**Tech Stack:** Swift Package Manager, Swift 6, XCTest, Xcode beta command-line tools, jj, Hummingbird 2, SQLiteNIO.

## Global Constraints

- Repository: `/Users/joshlacalamito/Developer/Catbird+Petrel/Swan`.
- VCS: jj is the sole history writer; Git is read-only.
- Preserve commit `66bf469bf53b` / change `sszozlvrwxwq`.
- The tracked handoff is `docs/superpowers/plans/swan-spaces-interoperability-alpha-handoff-2026-07-28.md`.
- Do not run concurrent SwiftPM builds against the same scratch directory.
- Do not delete `.build`, `.build-task43`, source files, package pins, or user data during diagnosis.
- Do not count a manually re-signed stale XCTest bundle as canonical acceptance evidence.
- Do not begin Task 44 until Task 43 passes independent rereview.
- Docker/Linux/Compose remain unavailable and must not be claimed.

## Observed failure, 2026-07-28

The apparent test hang is currently a build-infrastructure hang:

- orphaned process:
  `/Users/joshlacalamito/Library/Developer/Toolchains/swift-6.2.3-RELEASE.xctoolchain/usr/bin/swift-test --filter PublicRepositoryReadHTTPTests`;
- it was reparented to PID 1 and held the default `.build` SwiftPM lock;
- no XCTest process had launched;
- its active child spent more than ten minutes compiling the
  `swift-crypto` package manifest;
- that child mixed standalone Swift 6.2.3 with the Xcode-beta macOS 27 SDK;
- another `swift package` command reported:
  `Another instance of SwiftPM is already running using '.../Swan/.build'`;
- the stale `.build-task43` `SwanHTTPTests.xctest` bundle cannot be loaded
  because it is missing a code signature.

Therefore the agent must recover SwiftPM before inspecting Hummingbird,
SQLite, async teardown, or test code.

---

### Task 1: Stop the orphaned SwiftPM build and release the package lock

**Files:**

- Read: `docs/superpowers/plans/swan-spaces-interoperability-alpha-handoff-2026-07-28.md`
- Read: `.superpowers/sdd/swan-spaces-interoperability-alpha/task-43-report.md`
- Modify: none

**Interfaces:**

- Consumes: the current process table and the default `.build` lock.
- Produces: a workspace with no orphaned Swan `swift-test`, compiler child, or competing SwiftPM writer.

- [ ] **Step 1: Verify the repository and working copy**

Run:

```sh
cd /Users/joshlacalamito/Developer/Catbird+Petrel/Swan
jj status
jj log -r '@ | @- | @--' --no-graph
```

Expected:

- clean working copy;
- tracked handoff at `@-`;
- Task 43 implementation `66bf469bf53b` immediately below it.

- [ ] **Step 2: Re-resolve the exact stuck process**

Run:

```sh
pgrep -fal '^/Users/joshlacalamito/Library/Developer/Toolchains/swift-6[.]2[.]3-RELEASE[.]xctoolchain/usr/bin/swift-test --filter PublicRepositoryReadHTTPTests$'
ps -axo pid,ppid,etime,state,%cpu,command | rg 'swift-test|swift-frontend|swiftc|xctest'
```

Expected:

- zero or one exact matching orphan;
- if it exists, its parent is PID 1 and no `xctest` process is running.

Stop and report instead of killing anything if more than one exact match
appears or if another active agent owns the process.

- [ ] **Step 3: Terminate only the exact orphan**

After Step 2 proves there is exactly one unowned exact match, run:

```sh
pkill -TERM -f '^/Users/joshlacalamito/Library/Developer/Toolchains/swift-6[.]2[.]3-RELEASE[.]xctoolchain/usr/bin/swift-test --filter PublicRepositoryReadHTTPTests$'
```

Wait no more than ten seconds while polling:

```sh
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  pgrep -fal 'swift-test --filter PublicRepositoryReadHTTPTests|swift-crypto-manifest' || break
  sleep 1
done
```

If the manifest compiler remains orphaned, re-list it and terminate only the
child whose full command ends in `swift-crypto-manifest`. Do not use a broad
`pkill swift`, and do not kill SourceKit, Xcode, or unrelated builds.

- [ ] **Step 4: Prove the lock owner is gone**

Run:

```sh
pgrep -fal 'swift-test --filter PublicRepositoryReadHTTPTests|swift-crypto-manifest|SwanHTTPTests[.]xctest'
lsof +D /Users/joshlacalamito/Developer/Catbird+Petrel/Swan/.build 2>/dev/null | head -40
```

Expected:

- no orphaned test/compiler process;
- no active SwiftPM process writing the default `.build`.

Do not delete lock files speculatively. SwiftPM's process lock clears when the
owner exits.

---

### Task 2: Establish one coherent toolchain and a fresh scratch build

**Files:**

- Read: `Package.swift`
- Read: `Package.resolved`
- Create during build only: `.build-task43-repro/`
- Modify: none

**Interfaces:**

- Consumes: Xcode-beta's `XcodeDefault` Swift compiler and macOS SDK as one coherent pair.
- Produces: a freshly compiled, signed `SwanHTTPTests.xctest` independent of the stale `.build-task43` bundle.

- [ ] **Step 1: Record the exact coherent toolchain**

Run:

```sh
env -u SDKROOT -u TOOLCHAINS \
  DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  /usr/bin/xcrun --toolchain XcodeDefault swift --version

env -u SDKROOT -u TOOLCHAINS \
  DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  /usr/bin/xcrun --toolchain XcodeDefault --show-sdk-path
```

Expected:

- both commands resolve through `/Applications/Xcode-beta.app`;
- Swift and SDK come from the same Xcode installation.

Do not use the standalone Swift 6.2.3 executable with the Xcode-beta SDK for
this recovery run.

- [ ] **Step 2: Prove root-manifest evaluation is healthy**

Run:

```sh
env -u SDKROOT -u TOOLCHAINS \
  DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  /usr/bin/xcrun --toolchain XcodeDefault swift package dump-package >/dev/null
```

Expected: exit 0 in well under one minute.

If this command waits for `.build`, Task 1 is incomplete. If its own manifest
compiler consumes CPU for more than one minute, stop it, capture the full
compiler command and process sample once, and report an environment/toolchain
blocker. Do not edit Swan code.

- [ ] **Step 3: Resolve dependencies into a fresh scratch directory**

Run:

```sh
env -u SDKROOT -u TOOLCHAINS \
  DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  /usr/bin/xcrun --toolchain XcodeDefault swift package \
  --scratch-path .build-task43-repro resolve -v
```

Expected:

- pinned dependencies resolve;
- local `../Petrel` is used;
- `Package.resolved` remains unchanged.

Run `jj status` immediately afterward and stop if any tracked source or pin
changed.

- [ ] **Step 4: Build tests without running them**

Run:

```sh
env -u SDKROOT -u TOOLCHAINS \
  DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  /usr/bin/xcrun --toolchain XcodeDefault swift build \
  --scratch-path .build-task43-repro \
  --build-tests --jobs 1 -v
```

Expected:

- compilation completes;
- no XCTest case runs;
- serial compilation avoids the previously observed artifact/code-sign race.

The agent should emit a progress update every 60 seconds. If output stops for
more than 120 seconds, interrupt the command, inspect the live child process,
and classify the stall by its exact command before retrying.

- [ ] **Step 5: Verify the newly built HTTP test bundle is signed**

Run:

```sh
find .build-task43-repro -type d -name 'SwanHTTPTests.xctest' -print
find .build-task43-repro -type d -name 'SwanHTTPTests.xctest' \
  -exec codesign --verify --deep --strict {} \;
```

Expected:

- exactly one test bundle;
- `codesign --verify` exits 0.

If the fresh serial build again produces an unsigned bundle, preserve the
scratch directory and capture the build log. A manual ad-hoc signature may be
used only to determine whether XCTest itself runs; it does not satisfy the
canonical Task 43 gate. Prefer an Xcode-driven package test build for the
acceptance rerun if this Xcode beta/SwiftPM signing defect repeats.

---

### Task 3: Separate XCTest execution from compilation

**Files:**

- Read: `Tests/SwanHTTPTests/PublicRepositoryReadHTTPTests.swift`
- Modify only after a source-level hang is proven: `Tests/SwanHTTPTests/PublicRepositoryReadHTTPTests.swift`
- Modify only after a source-level hang is proven: `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift`

**Interfaces:**

- Consumes: the signed test products from Task 2.
- Produces: either a passing eight-test HTTP class or one exact reproducible hanging test method.

- [ ] **Step 1: Run the class without rebuilding**

Run:

```sh
env -u SDKROOT -u TOOLCHAINS \
  DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  /usr/bin/xcrun --toolchain XcodeDefault swift test \
  --scratch-path .build-task43-repro \
  --skip-build --jobs 1 \
  --filter PublicRepositoryReadHTTPTests -v
```

Expected:

- eight tests execute;
- zero failures;
- the process exits instead of returning to manifest compilation.

If this passes, the original “hang” is closed as a SwiftPM/toolchain/build
artifact failure. Do not edit HTTP code.

- [ ] **Step 2: If the class stalls, run the simplest individual method**

Run:

```sh
env -u SDKROOT -u TOOLCHAINS \
  DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  /usr/bin/xcrun --toolchain XcodeDefault swift test \
  --scratch-path .build-task43-repro \
  --skip-build --jobs 1 \
  --filter 'PublicRepositoryReadHTTPTests/testDeferredAndWrongMethodRoutesRemainFinite' -v
```

Expected: one passing test.

- [ ] **Step 3: Bisect the remaining methods one at a time**

Use the same command shape with each exact filter:

```text
PublicRepositoryReadHTTPTests/testJSONReadRoutesResolveDIDAndHandleAndIgnoreAuthorizationHeaders
PublicRepositoryReadHTTPTests/testDescribeRepoReportsAliasMismatchAndRejectsServiceOriginMismatch
PublicRepositoryReadHTTPTests/testGetRecordExactCIDListPaginationAndMalformedInput
PublicRepositoryReadHTTPTests/testMalformedPublicReadSelectorsAndParametersAreBadRequests
PublicRepositoryReadHTTPTests/testRepoStatusKnownLifecycleValuesAndGetRepoNeverPrepareInactiveSpool
PublicRepositoryReadHTTPTests/testListRecordsRejectsForgedOutOfOrderDirectoryProjection
PublicRepositoryReadHTTPTests/testGetRepoStreamsPinnedNonEmptyCARThroughStrictImporter
```

Allow at most 60 seconds without output per individual method. After
interrupting a real test stall, immediately run:

```sh
pgrep -fal 'SwanHTTPTests[.]xctest|xctest'
```

Only if an XCTest process is still present, capture one short sample of that
exact process. Do not sample a manifest compiler and call it an HTTP hang.

- [ ] **Step 4: Inspect only the proven hanging lifecycle**

For a real individual-test timeout, inspect:

- whether `app.test(.router)` entered its closure;
- which `client.execute` call began but did not return;
- whether `SQLiteControlDatabase.close()` was reached;
- whether the CAR spool body writer called `finish`;
- whether temporary fixture cleanup is waiting on an open descriptor;
- whether a service task or event loop remains alive after assertions.

Add temporary timestamped test logging locally if necessary. Do not commit
diagnostic logging. Make the smallest source/test fix only after the awaited
operation is identified.

- [ ] **Step 5: Regression-test any genuine source fix**

Run the exact formerly hanging method, the full
`PublicRepositoryReadHTTPTests` class, and `SwanHTTPTests`.

Expected:

- exact method passes;
- eight public-read HTTP tests pass;
- complete HTTP suite passes;
- process exits cleanly with no residual XCTest or Swan fixture process.

Commit a source fix only if Task 3 proved a source-level hang. Use jj:

```sh
jj commit -m 'fix(http): close public read test lifecycle'
```

Do not create a commit for deleting scratch artifacts or terminating orphaned
processes.

---

### Task 4: Restore the Task 43 acceptance gate

**Files:**

- Read: `.superpowers/sdd/swan-spaces-interoperability-alpha/task-43-brief.md`
- Read: `.superpowers/sdd/swan-spaces-interoperability-alpha/task-43-review.md`
- Read: `.superpowers/sdd/swan-spaces-interoperability-alpha/task-43-report.md`
- Modify after reviewer verdict: `.superpowers/sdd/swan-spaces-interoperability-alpha/progress.md`

**Interfaces:**

- Consumes: a deterministic test runner and Task 43 commit `66bf469bf53b`, plus any independently justified lifecycle-fix descendant.
- Produces: an independent Task 43 PASS or exact actionable findings.

- [ ] **Step 1: Re-run the focused non-stress gates**

Using the coherent toolchain and the single fresh scratch directory, run:

```sh
env -u SDKROOT -u TOOLCHAINS \
  DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  /usr/bin/xcrun --toolchain XcodeDefault swift test \
  --scratch-path .build-task43-repro --jobs 1 \
  --filter PublicRepositoryReadHTTPTests

env -u SDKROOT -u TOOLCHAINS \
  DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  /usr/bin/xcrun --toolchain XcodeDefault swift test \
  --scratch-path .build-task43-repro --jobs 1 \
  --filter PublicRepositoryReadDirectoryTests
```

Expected:

- HTTP: 8 passed;
- directory: 7 passed and the explicit 256 MiB test skipped by default.

- [ ] **Step 2: Run direct decoder and PLC identity gates**

Run:

```sh
env -u SDKROOT -u TOOLCHAINS \
  DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  /usr/bin/xcrun --toolchain XcodeDefault swift test \
  --scratch-path .build-task43-repro --jobs 1 \
  --filter RepositoryMSTValidationTests

env -u SDKROOT -u TOOLCHAINS \
  DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  /usr/bin/xcrun --toolchain XcodeDefault swift test \
  --scratch-path .build-task43-repro --jobs 1 \
  --filter PLCOperationTests
```

Expected: zero failures.

- [x] **Step 3: Re-run the real 256 MiB gate once**

Run only after the focused suites are stable:

```sh
env -u SDKROOT -u TOOLCHAINS \
  SWAN_RUN_256MIB_PUBLIC_GET_REPO=1 \
  DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  /usr/bin/xcrun --toolchain XcodeDefault swift test \
  --scratch-path .build-task43-repro --jobs 1 \
  --filter 'PublicRepositoryReadDirectoryTests/testOptIn256MiBProductionDirectoryGetRepoHasBoundedRSS'
```

Expected:

- one pass;
- at least 256 MiB streamed;
- peak RSS delta below 128 MiB;
- HTTP writes no larger than 64 KiB.

- [x] **Step 4: Run immutable profile/interoperability checks**

Run:

```sh
Scripts/verify-profile.sh
node interop/reference-public-repository-car.mjs \
  --reference .interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354 \
  --fixture fixtures/permissioned-data-0016-2026-07-03/public-repository-nonempty-car.json
git diff --check
jj status
```

Expected:

- profile verified;
- reference public CAR verified;
- no whitespace errors;
- clean or intentionally scoped working copy.

## 2026-07-28 execution evidence

The original hang was environmental: orphaned Swift 6.2.3 `swift-test`
processes held the default SwiftPM state while compiling manifests against the
Xcode-beta SDK. The exact processes were terminated, and a fresh scratch tree
was resolved and built with Xcode-beta Swift 6.4, `--jobs 1`.

- XCTest bundle code-signature verification passed.
- `PublicRepositoryReadHTTPTests`: 8 tests passed in 0.202 seconds.
- Opt-in 256 MiB production-directory CAR/RSS test: passed in 11.075 seconds.
- Complete prebuilt Swift suite: exit 0 after the `swan` executable was made
  available at the CLI tests' expected `.build/debug/swan` path. The suite's
  only skips are the existing lab/environment-gated cases.
- `swan lab validate`: passed for pinned reference SHA
  `3f6c96d5d2d25438bd40fa89d6ecc37865f8e354`.
- Offline lab matrix: passed and wrote a sanitized artifact.
- Docker/Compose is not installed in this environment; live cross-host Swan /
  TypeScript matrix execution remains an external gate and must not be marked
  complete from these local results.

- [ ] **Step 5: Complete the interrupted independent rereview**

The reviewer must compare the exact final Task 43 commit against the original
brief and the five findings already recorded in `task-43-review.md`.

PASS requires no blocking or medium finding in:

- externalized bounded CAR traversal;
- aggregate spool admission/release;
- pinned pagination;
- direct DAG-CBOR conversion;
- authenticated PLC identity and honest rotation fail-closed behavior;
- the validity of the 256 MiB RSS/HTTP evidence.

On PASS, update the progress ledger to mark Task 43 complete. On any finding,
remediate the same Task 43 change and repeat this task before proceeding.

---

### Task 5: Resume code work at Task 44

**Files:**

- Read: `.superpowers/sdd/swan-spaces-interoperability-alpha/task-44-brief.md`
- Modify per brief: `Sources/SwanPublicRepository/`
- Modify per brief: `Sources/SwanStorage/`
- Modify per brief: `Sources/SwanSQLite/`
- Modify per brief: `Sources/SwanAccounts/`
- Modify per brief: `Sources/SwanHTTP/`
- Modify per brief: `Sources/swan/main.swift`
- Test per brief: corresponding test targets

**Interfaces:**

- Consumes: independently approved Task 43 public reads, Task 39 mutation preparation, Task 41 durable reservation/application, account key storage, and DPoP OAuth authorization.
- Produces: explicit-rkey `com.atproto.repo.putRecord` and `com.atproto.repo.deleteRecord`; all other deferred public mutation/blob methods remain closed.

- [ ] **Step 1: Re-read the complete frozen Task 44 brief**

Do not reinterpret Task 44 from this recovery plan. The canonical contract is:

```text
.superpowers/sdd/swan-spaces-interoperability-alpha/task-44-brief.md
```

- [ ] **Step 2: Start with RED endpoint/authentication tests**

Prove:

- real routes remain closed without explicit public-write runtime composition;
- exact method/path DPoP authorization;
- `.accountOAuth`, exact `atproto` scope, and subject/repository equality;
- opaque unknown, remote, inactive, and cross-account behavior.

- [ ] **Step 3: Add RED durable mutation tests**

Prove:

- create-via-put, update-via-put, and delete;
- same-CID put and missing delete are no-ops before swap checks;
- complete `swapRecord`/`swapCommit` matrix;
- bounded no-swap CAS retry and no retry with caller swaps;
- reservation abandonment without revision reuse;
- exact replay binding.

- [ ] **Step 4: Implement only explicit-rkey put/delete**

Preserve the target dependency graph, use generated server contracts, convert
AT values directly without JSON round-tripping, reject typed blobs, and
re-fetch lifecycle/key references before signing and applying.

Keep `createRecord`, `applyWrites`, `uploadBlob`, and `getBlob` unavailable.

- [ ] **Step 5: Verify, commit, and independently review Task 44**

Run the exact focused and broad suites required by the Task 44 brief, profile
verification, the pinned CAR verifier, and `git diff --check`.

Commit with jj and record the change/commit IDs and exact test counts.
Independent review is mandatory before starting public blobs or batch writes.

## Completion criteria

This recovery plan is complete when:

1. no orphaned SwiftPM process holds `.build`;
2. one coherent Xcode toolchain/SDK builds a freshly signed test bundle;
3. `--skip-build --filter PublicRepositoryReadHTTPTests` executes eight tests
   and exits;
4. any genuine individual source-level hang has an exact regression test and
   minimal reviewed fix;
5. Task 43 receives an independent PASS;
6. Task 44 begins from its frozen brief, not from speculative hang debugging.
