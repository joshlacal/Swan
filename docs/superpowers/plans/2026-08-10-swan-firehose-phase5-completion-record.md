# Swan Firehose Phase 5 Completion Record (Task 7 Execution)

Date: 2026-08-10
Head tree: `55aa5d51a0e85dab29f6e75b91db9a00f417c10d` (clean working copy; every
gate below ran against this exact tree)
Parent plan: `docs/superpowers/plans/2026-08-08-swan-firehose-phase4-corrective-phase5-relay.md`

Per the parent plan, this record distinguishes local static verification, the
pinned reference-relay runtime proof, the recovery proofs, the `getRepo?since`
observation, and what remains unproven. A green Task 7 alone does not make
Phase 5 complete: the independent whole-branch review is still open, and live
deployment remains a separate activation gate.

## 1. Local static verification (all green)

- `interop/fetch-reference-indigo.sh` repopulated the pinned Indigo source
  cache (commit `8b43a326dbbb394f63b6d68761553cdfe25532de`, archive SHA-256
  `bc6f57e6…78fdd0b` verified); `interop/verify-reference-indigo.sh` and
  `interop/verify-reference-indigo-vendor.sh` green after
  `interop/materialize-reference-indigo-vendor.sh` rebuilt the vendor closure
  through the digest-pinned Go image.
- `Scripts/verify-interop-lab.sh`: interop-lab and reference-relay effective
  Compose invariants plus static invariants OK.
- Mutation suites: `Scripts/test-verify-interop-lab.sh` (verifier mutation
  tests + bootstrap lookup fail-closed tests) and
  `Scripts/test-reference-relay-acceptance.sh` (artifact validation + runner
  mutation tests) both OK.
- Protected profile/wire gates on the head tree: `Scripts/verify-profile.sh`
  green; `Scripts/verify-wire-generation.sh` and
  `Scripts/verify-public-wire-generation.sh` green against the pinned Petrel
  generator workspace (`@-` = `c2a1cdbee8c621c7682416114700f032cc7e2b37`),
  "verified without worktree mutation". Note: the pinned generator commit is
  now also an ancestor of Petrel `main` (`fe67a38f882c`) via a merge that
  preserved its commit ID; the workspace pin is unchanged.

## 2. Pinned reference-relay runtime proof

`Scripts/run-reference-relay-acceptance.sh` executed the ordered scenario
against the byte-pinned Indigo relay image in the Compose lab (colima /
docker 29.5.2). Artifact: `artifacts/live/reference-relay-acceptance.json`
(schema 2, mode 0600, aggregate/digest-only), SHA-256
`be3175cb5eb803e68f54a3750014d37d6c59efe909ee414c4f7e9fc50286457b`, bound to
`swanHead` `55aa5d51…` and Indigo image ID `5030c2fd94fb…`. Status: `passed`;
success marker `REFERENCE RELAY ACCEPTANCE OK`; independent verifier passed
all six checks (canonical frames, ordered lifecycle, cursor recovery,
repository commits, getRepo mode, final MST equality).

All ten ordered steps completed in order: fresh_state (relay volume removed,
`listHosts` count 0) → crawl → subscription_open → admission_sync →
public_host_entry → account_activation → activation_lifecycle → first_commit →
offline_five_commit_recovery → manual_sync. Event census exact:
`identity ×1, account ×1, activation sync ×1, commit ×6, manual sync ×1` in
the required kind order; capture helper ran through the final required frame.

## 3. Cursor and forced-sync recovery proof

- Five commits were created while relay→Swan subscription was severed via
  toxiproxy. On reconnect the relay recovered exactly five (relay sequences
  6–10, first delivered 6, upstream cursor 5), with 0 duplicates and 0 gaps.
- Final repository equality: relay and Swan agree on revision
  (`3msqccctvbl22`), commit CID, data CID, and MST digest; `equal: true`.
- Forced `swan firehose force-sync` produced a clean relay resynchronization
  (`manualSync.observed && clean`).

## 4. getRepo?since observation

The pinned relay never issued `getRepo?since`; recovery ran in
`subscribe_repos_cursor_only` mode (connection observations: ordinal 1 live
with nil upstream cursor, ordinal 2 backfill from cursor 5). The plan's
fail-closed `since` branch was therefore never entered and revision-aware
block selection remains unexercised and unimplemented — acceptable per the
plan because the branch is fail-closed, but it is unproven behavior if a
future relay revision starts issuing `since`.

## 5. Full-suite receipt on the exact head tree

`xcrun swift test` (Xcode beta toolchain, Swift 6.4, macOS 27.0 SDK) on the
head tree after the runtime proof: **3,993 XCTest tests + 6 Swift Testing
tests, 0 failures, exit 0**. The only "failed" strings in the log are a
pkg-config search-path warning and an intentional announcer-backoff test log
line. (Four earlier suite invocations died from an unrelated concurrent
process issuing machine-wide `pkill -9 -f swift-frontend`; after it was
stopped and the corrupted `.build/out` was moved aside, the suite ran clean.)

## 6. Environment notes

- The lab's `swan-interop-alpha` volumes had to be recreated before the
  passing run: the 2026-08-08/09 session had initialized the Swan key store
  under an ephemeral secrets directory that no longer exists, so
  `ServeLocalSpaceRuntime` could not open it with any surviving KEK. Old
  volume state was archived outside the repository, volumes were removed, and
  the stack re-initialized freshly from a persistent owner-only secrets
  directory. The scenario's own fresh-state guarantee (relay volume removal)
  was additionally enforced by the runner as designed.

## 7. Review remediation amendments (2026-08-10, whole-branch review findings)

The independent whole-branch review returned REJECT on two record gaps (no
code defects; every code-level invariant it tested held). This section
remediates both, plus one minor reconciliation.

### 7a. Completion-anchor storage/retention ruling (plan Task 1.5)

Ruling: completed lifecycle batches and public-firehose source-key completion
anchors are retained **indefinitely**. They exist as exact-replay idempotence
and conflict-detection anchors: a retry after the global append has committed
must still prove exact idempotence against the retained material, and exact
source-key reuse with any non-time semantic difference must still fail closed
as a conflict. Completed rows contain only already-public firehose material,
so indefinite retention has no confidentiality cost. Pending scans, FIFO
leasing, and sequencer selection all filter `completed = 0`; replay lookups
intentionally do not. Any future pruning requires a separately designed
tombstone that preserves the same conflict checks — a pruning change without
that design must be rejected in review. Code contract:
`SwanSQLite.migratePublicFirehoseCompletionAnchorsIfNeeded` and
`LifecycleEventOutboxStore.completeLifecycleBatch` doc comments.

### 7b. Task 3 corrective exit-gate receipts (re-executed)

The corrective wave's original Task 3 gate receipts were not retained in the
repository, so the gate was re-executed in full on 2026-08-10 (22:23–22:32 Z),
foreground and sequential with no overlapping SwiftPM invocations, at commit
`75f4684d` — whose only delta from `55aa5d51` is this record document; the
compiled source tree is identical. Toolchain: Apple Swift 6.4
(swiftlang-6.4.0.27.1). Literal receipts:

- Step 0 `xcrun swift build --build-tests`: exit 0, warnings 2 (pkg-config
  search-path warnings from the `petrel` dependency; none from Swan source).
- Step 1, lifecycle idempotence regression, 25 separate process invocations of
  `xcrun swift test --skip-build --filter PublicLifecycleEmitterTests`: every
  run exit 0, executed 14 (class-suite summary), failures 0, skips 0
  (25/25 identical).
- Step 2, focused suites (`--skip-build`, sequential; exit 0 / failures 0 /
  skips 0 for every suite; class-suite executed counts):
  PublicLifecycleEmitterTests 14, LifecycleEventOutboxStoreTests 20,
  PublicFirehoseOutboxStoreTests 19, PublicFirehoseCommitEnqueueTests 10,
  PublicFirehoseSequencerTests 18, AccountAuthorizationLeaseTests 4,
  PLCAccountRotationServiceTests 4, PLCAccountPreparationServiceTests 11
  (the file's other class, PLCAccountActivationServiceTests, is outside the
  filter), AccountOperatorServiceTests 9, PublicRepositoryMutationHTTPTests 20.
- Step 3 `xcrun swift build`: exit 0, warnings 2 (same pkg-config pair).
- Step 4 full unfiltered `xcrun swift test`: exit 0; 3,993 XCTest tests, 0
  failures, 0 skipped; 6 Swift Testing tests, 0 failures.
- Step 5 profile hash and generated-wire manifest checks: `verify-profile.sh`
  exit 0 ("profile lexicons verified"); `verify-wire-generation.sh` and
  `verify-public-wire-generation.sh` exit 0 ("verified without worktree
  mutation") against the pinned generator workspace.
- Step 6 protected-path diff `a9bbd311..55aa5d51` over `Profiles/`,
  `Scripts/public-wire-generation-common.sh`, `Sources/SwanPublicWire/`:
  zero changed-file rows.

No flake occurred in any step. Receipt-transparency notes (two numeric
corrections, both caught during the whole-branch review loop): a first gate
pass the same hour produced identical exit codes but its per-run count
extraction read the wrong (empty) bundle summary line, so steps 1–2 were
re-executed with a zero-executed guard; that rerun's extraction then summed
XCTest's three per-run summary levels (class suite, `.xctest` bundle,
"Selected tests"), overstating every count by exactly 3x — the counts above
are the class-suite summary values (verified directly, e.g.
`Test Suite 'PublicLifecycleEmitterTests' passed … Executed 14 tests`), which
is the correct extraction. Exit codes, 0-failure/0-skip results, nonzero
execution, and 25/25 identical runs were unaffected by either extraction
defect. Task 0's standalone reproduced-failure record was
likewise never retained; the reproduction survives as the Task 1 RED
regressions (activation/rotation retry with later invocation time, retry
after sequencing with unchanged generation and global-event count) in
`PublicLifecycleEmitterTests` and `PublicFirehoseOutboxStoreTests`.

### 7c. Artifact field reconciliation

The acceptance artifact intentionally emits digest-only fields (DID digest,
`orderedKinds`, aggregate counts) instead of the plan's literal "ordered
source keys" and per-commit five-commit deltas: the artifact policy is
aggregate/digest-only with no DID, handle, path, or record value, and the
per-commit deltas are proven inside the independent verifier's
`repository_commits` check rather than serialized into the artifact.

## 8. Still unproven / open gates

- **Independent whole-branch review** of the Phase 4 corrective + Phase 5
  work: OPEN. Phase 5 may not be called complete until it passes.
- Public Linux deployment: no Linux-native execution of the relay acceptance
  scenario; all runtime proof above is macOS/colima (linux/arm64 containers).
- `bsky.network` / real-crawler interoperability: unproven; only the pinned
  Indigo revision was exercised.
- Revision-aware `getRepo?since` handling: unexercised (see §4).
- Live deployment remains a separate activation gate requiring explicit
  authorization.
