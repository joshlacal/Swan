# Swan Spaces Interoperability Alpha — handoff

Date: 2026-07-28

## Resume point

Work in:

`/Users/joshlacalamito/Developer/Catbird+Petrel/Swan`

This is a jj-colocated repository. Use jj as the only history writer. Do not
use Git to commit, reset, check out, or create worktrees.

Current source state:

- working copy is clean;
- the tracked handoff document is the commit at `@-`;
- implementation commit/change immediately below it:
  `66bf469bf53b` / `sszozlvrwxwq`;
- description: `feat(public-repo): expose durable public read HTTP`.

Start with:

```sh
cd /Users/joshlacalamito/Developer/Catbird+Petrel/Swan
jj status
jj log -r '@ | @- | @--' --no-graph
```

Do not rewrite or abandon `66bf469bf53b`. It is the amended Task 43 commit
that includes both the original implementation and its first remediation.

## Canonical documents

Read these before changing code:

1. Master plan:
   `docs/superpowers/plans/swan-spaces-interoperability-alpha.md`
2. Progress ledger:
   `.superpowers/sdd/swan-spaces-interoperability-alpha/progress.md`
3. Task 43 brief:
   `.superpowers/sdd/swan-spaces-interoperability-alpha/task-43-brief.md`
4. Task 43 report:
   `.superpowers/sdd/swan-spaces-interoperability-alpha/task-43-report.md`
5. Task 43 review:
   `.superpowers/sdd/swan-spaces-interoperability-alpha/task-43-review.md`
6. Frozen next-task brief:
   `.superpowers/sdd/swan-spaces-interoperability-alpha/task-44-brief.md`

The `.superpowers` files are intentionally local/ignored execution records.
This handoff is tracked so the resume point is durable.

## Current gate: Task 43 rereview

Task 43 implements six durable public read/sync endpoints:

- `com.atproto.repo.describeRepo`
- `com.atproto.repo.getRecord`
- `com.atproto.repo.listRecords`
- `com.atproto.sync.getLatestCommit`
- `com.atproto.sync.getRepo`
- `com.atproto.sync.getRepoStatus`

Public mutation and blob routes remain explicitly unavailable.

The first independent review failed with five findings:

1. `getRepo` materialized complete MST/topology structures.
2. Concurrent unauthenticated spools had no aggregate disk admission.
3. `listRecords` order/cursor semantics were opposite the pinned TypeScript
   implementation.
4. Record output crossed a prohibited CBOR-to-JSON bridge.
5. `describeRepo` synthesized identity metadata instead of authenticating
   durable PLC identity.

Commit `66bf469bf53b` remediates all five:

- SQLite TEMP-backed breadth-first export externalizes queue, duplicate
  detection, bounds/layers, node order, record order, and reconstructed index;
  CAR framing reads one block at a time.
- A process-global/per-account spool admission lease is reserved before file
  creation and released on completion, failure, cancellation, abandonment, or
  deinitialization.
- Pagination matches pinned TypeScript behavior: default descending with
  `< cursor`, reverse ascending with `> cursor`, and the last returned rkey is
  emitted even for the final non-empty page.
- Canonical DAG-CBOR is decoded directly into `ATProtocolValueContainer`,
  preserving links, bytes, safe integers, nested arrays/objects, booleans, and
  null without JSON round-tripping.
- `describeRepo` reconstructs and verifies the signed, submitted PLC genesis
  operation through an acyclic `SwanStorage`/`SwanAccounts` verifier seam,
  binds it to the submitted control intent, key references, handle, service
  origin, and public genesis commitment, and emits the pinned ECDSA-2019 DID
  document shape.

The rereview of `66bf469bf53b` was started and then deliberately interrupted
to prepare this handoff. It has no verdict yet. The immediate next action is a
fresh independent rereview of the exact commit. Do not start Task 44 until
Task 43 passes.

The rereviewer should specifically inspect:

- `Sources/SwanSQLite/PublicRepositoryBoundedExport.swift` for hidden
  repository-sized arrays, exact breadth-first order, TEMP-table cleanup,
  corruption handling, and index/body agreement;
- `PublicRepositorySpoolAdmission` and `PublicRepositoryCARSpool` for global
  and per-account admission plus idempotent release on every terminal path;
- the pinned pagination fixture at
  `Tests/Fixtures/permissioned-data-0016-2026-07-03/public-list-records-pagination.json`;
- direct decoder edge tests in
  `Tests/SwanPublicRepositoryTests/RepositoryMSTValidationTests.swift`;
- PLC genesis reconstruction, operation-CID/intent binding, pinned DID
  document formatting, tamper tests, and rotation fail-closed behavior;
- the validity of the opt-in 256 MiB RSS test, including its concurrent peak
  sampler and non-aggregating HTTP body writer.

If rereview passes, update the progress ledger to mark Task 43 complete with
commit `66bf469bf53b`, then begin Task 44. If it finds anything, remediate in
the same jj change `sszozlvrwxwq`, rerun the same reviewer, and do not advance
until it passes.

## Task 43 verification already recorded

The implementation report records:

- focused HTTP: 8 passed;
- focused SQLite directory: 7 passed, 1 normal opt-in skip;
- direct decoder and PLC verifier: 2 passed;
- production runtime composition: 1 passed;
- `SwanPublicRepositoryTests`: 99 passed;
- `SwanSQLiteTests`: 99 executed, 2 opt-in skips, 0 failures;
- `SwanHTTPTests`: 107 passed;
- profile verification: passed;
- pinned TypeScript public CAR verifier: passed;
- diff check: passed.

The opt-in test was also run explicitly:

```sh
SWAN_RUN_256MIB_PUBLIC_GET_REPO=1 \
  swift test --filter \
  PublicRepositoryReadDirectoryTests/testOptIn256MiBProductionDirectoryGetRepoHasBoundedRSS
```

It passed in 9.865 seconds. The test builds 300 unique approximately 900 KiB
public records, continuously samples current RSS through directory preparation
and HTTP-body drain, asserts a peak delta below 128 MiB, discards the HTTP body
without aggregation, and enforces writes no larger than 64 KiB.

Re-run focused evidence during rereview. Re-run broad suites after any code
change.

## Task 43 retained identity boundary

Swan currently has a durable authenticated PLC genesis projection, not
durable authenticated PLC rotation history. Public identity reads therefore
fail closed if current account key references no longer match the genesis
projection. Do not synthesize a rotated DID document.

A later task must persist and authenticate PLC rotation history before rotated
accounts can serve `describeRepo`. This is an explicit limitation, not
permission to weaken verification.

## Next implementation: Task 44

The complete Task 44 contract is already frozen in:

`.superpowers/sdd/swan-spaces-interoperability-alpha/task-44-brief.md`

Task 44 is limited to OAuth-authorized, explicit-rkey:

- `com.atproto.repo.putRecord`
- `com.atproto.repo.deleteRecord`

Keep `createRecord`, `applyWrites`, `uploadBlob`, and `getBlob` unavailable.

Pinned TypeScript semantics already verified locally:

- same-CID put is a no-op before swap checking;
- missing delete is a no-op before swap checking;
- stale swaps on real mutations return `InvalidSwap`;
- only real mutations emit a commit.

Important Task 44 design constraints:

- add an explicit public-write runtime capability; do not couple it to
  `--enable-local-space-interop`;
- require exact method/path-bound DPoP OAuth, `.accountOAuth`, exact `atproto`
  scope, and subject equal to the locally resolved DID;
- authorize before disclosing whether a repository selector is hosted;
- convert Petrel `ATProtocolValueContainer` to `PublicRecord` directly and
  strictly, without JSON round-tripping;
- add a missing `$type`, reject a mismatched `$type`, and reject typed blob
  references until the public blob lifecycle exists;
- use Task 39 preparation and Task 41 durable reservation/application;
- add reservation abandonment without revision reuse;
- retry boundedly only when no caller swap was supplied;
- re-fetch account lifecycle and current signing-key reference before every
  real signature and immediately before apply;
- no-op paths must not reserve, sign, mutate SQLite, or create replay state.

Use tests first and require an independent review after committing Task 44.

## Work remaining after Task 44

The master plan is not complete. At minimum, the remaining sequence is:

1. `createRecord` and `applyWrites`, including durable omitted-rkey allocation
   and atomic multi-write responses.
2. Public blob upload/download with staged streaming upload, content-addressed
   storage, public-reference promotion tied atomically to record commits,
   bounded streaming reads, cleanup, and public/private namespace isolation.
3. Durable authenticated PLC rotation history and rotated `describeRepo`.
4. Interop runner hardening: scenarios must assert data exchange/convergence,
   not merely probe endpoint availability, and must exit nonzero when the
   artifact says failure.
5. Live Swan/TypeScript producer-consumer matrix for records, credentials,
   commits, blobs, incremental sync, compaction-gap full recovery, corrupted
   traffic rejection, and reverse authority placement where supported.
6. Security and isolation closure, including public/private collision,
   logs/metrics/errors, SSRF/OAuth negative matrix, crash recovery, account
   lifecycle, export/restore, and notification replay.
7. Clean-cache macOS and Linux acceptance, then the full Compose matrix.

Known interop harness gaps from the last audit:

- the scenario runner currently probes endpoints rather than proving complete
  data semantics;
- an artifact can say `failed` while the CLI exits successfully;
- Compose offline mode can therefore appear successful;
- Swan's Compose healthcheck checks executable existence rather than service
  readiness;
- `service_started` ordering can race Caddy CA/readiness;
- sanitized matrix fixtures beyond public genesis are still missing.

## Environment constraints

At this handoff:

- Docker, Podman, and Colima are unavailable;
- no Swift Linux SDK is installed;
- live Compose and Linux acceptance have not been run and must not be claimed;
- macOS Swift tests are the currently available local verification surface.

A disposable verification build briefly filled the data volume. Only the two
task-created directories `.build-root43` and `.build-root43-remediate` were
deleted. Source, the default `.build`, and user data were untouched. The volume
subsequently reported ample free space, but check before running another
large opt-in gate:

```sh
df -h .
du -sh .build .build-task43 2>/dev/null
```

Avoid creating another full dependency checkout unless necessary. Prefer the
existing default `.build` cache. Do not delete `.build-task43` while another
process is using it.

## Stop conditions and truthfulness

Do not declare Swan ready for full public/private testing until all of these
are true:

- public mutation and blob routes are real and independently reviewed;
- the live cross-implementation data matrix passes;
- public/private isolation is proven through HTTP, CAR, blobs, logs, metrics,
  errors, export, restore, and recovery;
- clean-cache macOS and Linux suites pass;
- the full Compose lab passes from pinned sources/checksums.

Current truthful status: permissioned surfaces and durable public read/sync
are substantially implemented; Task 43 awaits rereview; public mutations and
public blobs remain closed; live Compose/Linux interop remains unproven.

## Follow-up verification: 2026-07-28

The Task 43 rereview and the next public-data slice were completed after this
handoff was written. The current successor change is
`babf71b8 fix(public): enforce blob namespace at mutation boundary`.

- Public `createRecord`, `putRecord`, and `applyWrites` now reject raw blob
  links that do not have a reachable public CAS reference. Permissioned-only
  references cannot be promoted implicitly by a public record write.
- The authenticated HTTP test proves a public raw link commits, a
  permissioned-only raw link returns `InvalidRequest`, public `sync.getBlob`
  streams the bytes, and a permissioned-only blob is not publicly reachable.
- The original `swift test --filter PublicRepositoryReadHTTPTests` filter now
  completes 8/8 when invoked with the Xcode toolchain and `--jobs 1`; the
  earlier apparent hang was SwiftPM dependency resolution in the default
  process state. The opt-in 256 MiB bounded-RSS test also passed.
- The macOS suite, pinned CAR verifier, profile verifier, static Compose
  verifier, and verifier mutation tests pass. Docker/Compose, Linux, and the
  semantic cross-host matrix remain unrun in this environment.

The earlier “public mutations and public blobs remain closed” sentence above
is retained as historical context for the handoff snapshot; the dated
follow-up note and `2026-07-28-swan-public-blob-reference-isolation.md` are the
authoritative current status. Durable PLC rotation history and semantic live
interoperability are still required before alpha completion.

## Follow-up verification: durable PLC rotation history

The next local slice is now implemented in the current working copy:

- `plc_identity_operations` is a per-account SQLite/WAL linear history with
  CID-idempotent insertion, conflicting-body rejection, restart persistence,
  and generation/parent constraints.
- `SwanPublicPLCGenesisVerifier.verifyIdentityHistory` reconstructs and
  verifies the genesis plus every signed rotation, rejects branches, gaps,
  non-canonical bodies, tombstones, and invalid terminal aliases/services,
  and returns the authenticated terminal DID document facts.
- Account rotation uses `PLCAccountRotationService`; it provisions the next
  generation, records the exact pending operation before network I/O, verifies
  the remote audit/state, and promotes control references with a generation
  compare-and-swap. A retry recovers a pending operation after a crash.
- Public `describeRepo`/repository description consumes the authenticated
  terminal identity while preserving the genesis commit binding. Legacy
  genesis-only rows remain supported; a history row without the history
  verifier fails closed.
- Local tests cover rotated identity verification and rejection cases,
  SQLite idempotency/restart behavior, control-key CAS promotion, and the
  rotated public repository description.

Focused verification (Xcode toolchain, SwiftPM `--jobs 1`) passed:

- `PLCOperationTests.testPublicIdentityHistoryAuthenticatesRotationAndRejectsBranches`
- `PLCIdentityHistorySQLiteTests.testHistoryIsLinearIdempotentAndSurvivesRestart`
- `PublicRepositoryRotatedIdentityTests.testPublicDescriptionUsesAuthenticatedTerminalPLCIdentity`
- `PLCAccountRotationServiceTests.testRotationPersistsPendingHistoryAndPromotesControlGeneration`
- `ManagementPLCProvisioningRuntimeHTTPTests.testConcreteManagementRoutesPrepareActivateRetryAndAdmitWithoutRestart`
- `PLCAccountPreparationCLITests.testRotatePLCUsesDurableHistoryAndReturnsOnlySanitizedIdentity`
- `PublicRepositoryReadHTTPTests` (8/8), including the filtered command that
  previously appeared to hang under default SwiftPM resolution
- `PublicRepositoryReadDirectoryTests.testOptIn256MiBProductionDirectoryGetRepoHasBoundedRSS`

The complete serialized macOS suite now passes with exit code 0. The
timestamp-independent history replay fix also makes repeated activation and
rotation retries idempotent across process restarts. The negative PLC signature
test was made deterministic after a random-signature edge case was observed.

Static/profile checks pass:

- `Scripts/verify-profile.sh`
- `Scripts/verify-interop-lab.sh`
- `Scripts/test-verify-interop-lab.sh`
- `git diff --check`

This does not close the alpha. A local/live PLC-client recovery run still
needs to be performed against the supported fixture, and the operator/CLI
surface is implemented but has not yet been exercised against that live
fixture. Semantic cross-host interop, Docker/Compose, Linux, Petrel
regeneration, and the remaining public/private acceptance matrix are still
outstanding.
