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

The offline semantic gate is also now available and passing:

```sh
env -u SDKROOT -u TOOLCHAINS \
  DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  /usr/bin/xcrun --toolchain XcodeDefault swift test --jobs 1 \
  --filter SwanInteropTests.testLocalSemanticInteropExercisesDurableConvergenceRecoveryAndIsolation
```

`swan lab semantic --output artifacts/swan-swan-semantic.json` writes the same
summary-only artifact from two independent durable SQLite roots. It proves
local replay, ordering, retention-gap recovery, CAR validation, credentials,
and blob namespace isolation, but it is deliberately labeled
`swan-durable-to-swan-durable`; it is not a substitute for the live
Swan/TypeScript matrix.

This does not close the alpha. A local/live PLC-client recovery run still
needs to be performed against the supported fixture, and the operator/CLI
surface is implemented but has not yet been exercised against that live
fixture. Semantic cross-host interop, Docker/Compose, Linux, Petrel
regeneration, and the remaining public/private acceptance matrix are still
outstanding.

## Follow-up verification: Task 43 rereview and reference-host smoke

The independent Task 43 rereview is now recorded in
`.superpowers/sdd/swan-spaces-interoperability-alpha/task-43-rereview-2026-07-28.md`.
The scoped public-read verdict is **PASS** on macOS: the filtered HTTP suite
executed 8/8 tests, the opt-in 256 MiB RSS gate passed, and the complete
serialized suite passed with exit code 0.

The pinned TypeScript source cache was also booted in a disposable localhost
runtime using temporary PostgreSQL and Valkey services. A sanitized smoke run
proved reference-host account creation, authenticated public `createRecord`,
`getRecord`, `listRecords`, and `sync.getRepo` responses. `uploadBlob` returned
the expected staged blob response; a retrieval attempt before a valid record
reference returned `Blob not found`, and an invalid plain-text profile
attachment was rejected. No cross-host Swan/TypeScript exchange is claimed by
this smoke run, and all temporary service processes were stopped afterward.

## Follow-up verification: stateful live runner and bounded private transfers

The current Swan successor commits extend the harness beyond endpoint probes:

- `d484298b` adds the callable `swan lab live` command. Public mode performs a
  selector-bound `repo.putRecord`/`repo.getRecord` round trip; permissioned
  mode exchanges a member delegation for a space credential and performs a
  `space.createRecord`/`space.getRecord` round trip. Artifacts contain only
  statuses, commitments, sizes, and response digests.
- `0ec5467e` fixes the live client's XRPC path construction to use the actual
  `/xrpc/<nsid>` target. A direct test covers the NSID and canonical query
  ordering used by DPoP-bound requests.
- The explicit 256 MiB local transfer gates pass for permissioned CAR spooling,
  private CAS blob streaming, and staged CAR import. The public production
  directory RSS gate also remains green.
- The complete serialized macOS suite passes after the live-client fix, as do
  `swift build`, profile verification, the static Compose verifier, its
  mutation tests, both pinned TypeScript public CAR/genesis verifiers, and the
  offline durable Swan-to-Swan semantic artifact.

The live runner is now executable when two hosts and disposable credentials
are supplied, but no claim of cross-host convergence is made from these local
checks. Docker/Compose, a Linux Swift environment, and a live
Swan-to-pinned-TypeScript public/permissioned matrix are still unavailable in
this workspace (`docker`, `podman`, and `colima` are not installed). Those
external gates must be run before the alpha can be marked complete.

## Follow-up verification: Compose readiness gates

The lab topology was hardened after the stateful runner review. The Swan
container now includes the small runtime `curl` dependency needed for a
bounded `GET /health` healthcheck. The pinned reference PDS and PLC use their
native `/_health` endpoints through Node's built-in fetch. Compose ordering
now requires a healthy PLC before the reference PDS, a healthy reference PDS
before Toxiproxy setup, and a healthy Swan listener before Caddy. The static
topology verifier and its mutation tests enforce these contracts. This is
static/readiness evidence only; Docker execution remains unavailable in the
current workspace.

The readiness hardening is committed as
`90ad537dd42ad1f90baf8b4572411d9709b3293c`. The serialized macOS package
suite on that clean parent executed 602 tests with 0 failures and 5 expected
skips (four opt-in 256 MiB/cache gates and the environment-gated lab
validation). The filtered `PublicRepositoryReadHTTPTests` command executed
8/8, and the static/profile/interop verifiers remained green.

## Follow-up verification: Linux Compose and cross-host permissioned proof

The Docker/Compose environment became available later on 2026-07-28. The
clean-cache Linux aarch64 lab now passes the following gates:

- Caddy local TLS, Mailpit, Toxiproxy, the pinned reference PDS/PLC, and Swan
  all report healthy; PLC-backed Swan account bootstrap completes before the
  listener accepts traffic.
- Stateful Swan-to-Swan public and permissioned round trips return matching
  CIDs. Public/private HTTP and CAR isolation checks show no permissioned CID
  or private-only blob through public routes.
- The sanitized six-mode fault matrix covers offline, disconnected, delayed,
  duplicated, reordered, and corrupted traffic (156 convergence comparisons,
  416 endpoint events) across Swan and the pinned reference host. This is
  transport/profile evidence, not complete TypeScript semantic convergence.
- A disposable TypeScript member account passed public record create/read/list
  on the reference PDS. It then wrote a permissioned record on that host,
  received a Swan-issued space credential from the Swan authority, and read
  the same CID from the TypeScript member host with
  `--permissioned-read-host member`. The authority used an explicit static
  public-key pin for the remote delegation; no private material or tokens were
  persisted in the repository.
- A fresh disposable TypeScript member account also passed the terminal
  `space.listRepoOps` boundary with `--permissioned-list-ops` and
  `--permissioned-list-ops-exclude-values`: one operation and its signed
  commit returned HTTP 200, and Swan verified the LtHash commitment, the
  deniable content-binding MAC, and the ES256K context signature against the
  static public-key pin. The sanitized artifact reported
  `syncCommitVerified: true` and `syncValuesIncluded: false`. The pinned
  TypeScript value-including form remains a known reference defect
  (`ambiguous column name: space` in its joined query), so the lab does not
  silently turn that failure into a false complete-values claim.

The runner/API and Compose lifecycle fix are committed in
`ea47ba82` (`feat(interop): select permissioned repository read host`), on top
of `fa391bee` (`fix(interop): validate public and permissioned Linux lab`). The
Compose fix keeps the complete `swan-data-init` shell script in one argument;
without it, `/bin/sh -ec` treated `install` flags as positional parameters and
the service failed with “missing file operand.” The restored normal Compose
stack is healthy after the fix.

The alpha is still not complete. Full TypeScript public repository import,
dynamic remote DID/PLC/JWKS resolution, value-bearing incremental updates,
compaction-gap recovery, blobs, reverse authority placement, and the complete
cross-implementation security/lifecycle/export matrix remain follow-up gates.

## Final verification after the Task 43 rereview handoff

The proposal-0016 content-binding implementation and immutable profile pin are
now aligned: Swan uses the pinned one-block HKDF-Expand/HMAC-SHA-256 behavior,
and the fixed cross-language vector passes. The serialized macOS suite passes
with zero failures (including the CLI export/restore tests after refreshing
their preferred `.build-task19`/`.build-task20` binaries), as do profile
verification, the 18-check semantic lab, the static interop verifier and its
mutation suite, and `PublicRepositoryReadHTTPTests` (8/8).

The Linux Compose Swan image was rebuilt from this source and restarted. Caddy,
the reference PDS/PLC, and Swan are healthy; `/health` returns `OK` through
local TLS and the reference PDS returns version `0.5.7`. This refresh does not
close the remaining TypeScript semantic, dynamic-key, blob, reverse-authority,
or full lifecycle/security gates listed above.

## Follow-up verification: reference typed-blob probe and PLC key seam

A disposable pinned-TypeScript reference-only run now passes its standard
public typed-blob flow: account provisioning, blob upload, an
`app.bsky.feed.post` commit, unauthenticated record retrieval, and streamed
blob retrieval all returned the expected status and bytes. This is reference
host evidence only. It does not prove Swan/TypeScript convergence. Swan's
public codec now accepts the modern typed blob object with strict
shape/CID/MIME/size validation; a live reference-account CAR import and
receiver-side public-blob promotion remain open.

The public repository verifier now accepts canonical low-S secp256k1 commit
signatures while Swan's local writer remains P-256. PLC `did:key` decoding and
`PLCPublicRepositoryCommitKeyResolver` have focused tests for the pinned
TypeScript secp256k1 key, missing-key rejection, and invalid repository
identities. The importer still takes an explicit verification key; live
remote DID/PLC discovery and a TypeScript CAR import remain open gates.

## Follow-up verification: modern typed-blob acceptance and live Swan round trip

The public repository boundary now accepts the modern typed blob shape from
Petrel's JSON decoder (`.unknownType("blob", ...)`) and preserves its nested
raw CID link without a JSON round trip. Strict codec tests cover wrong shape,
unsafe MIME, negative size, and the direct decoder path.

The rebuilt Linux Compose Swan image passed the typed public fixture after the
runner selected the active DID from Swan's durable account registry: upload,
typed `repo.putRecord`, unauthenticated `repo.getRecord`, and streamed
`sync.getBlob` all returned HTTP 200; the record CID matched and the 25-byte
blob was verified. The summary-only artifact is
`artifacts/live-typed-blob.json`. The stale external DID selector that caused
the first `RepoNotFound` result was not copied into the fixture or logs.

This closes Swan's local modern typed-blob boundary but does not yet claim
reference-PDS-to-Swan blob convergence or full alpha completion.

## Follow-up verification: live reference CAR import and managed-target fix

The pinned TypeScript PDS was exercised with a fresh disposable account,
public `image/png` blob, and a valid typed `app.bsky.feed.post` record. Swan
then fetched `com.atproto.sync.getRepo` over the Compose TLS network and
imported the CAR into a newly installed target account. The sanitized artifact
reported HTTP 200, one record, three reachable blocks, and a verified commit.

The first importer attempts failed with `SQLiteReadOnly`: `swan lab
import-public` had opened the target with
`SQLiteAccountDatabaseOpenMode.existingPortableExportSource`, which is correct
for export but cannot stage writes. The command now opens the normal managed
account database, preserving the read-only export mode for export-only paths.
The CAR import gate is closed; fetching and promoting referenced blob bytes
into the receiver's public blob namespace remains a separate follow-up.

## Follow-up verification: dynamic PLC import and receiver blob promotion

The rebuilt Compose Swan image now passes the previously open receiver-side
blob seam. A disposable managed target used the pinned reference PLC resolver
with the explicit laboratory origin/host allowlist, fetched the reference
`com.atproto.sync.getRepo` CAR over local TLS, and then promoted its one raw-CID
blob. The reference `sync.getBlob` request includes both required selectors,
`did` and `cid`; the response is streamed through an owner-only temporary file,
checked for a non-JSON content type, and adopted only when the resulting public
CAS CID equals the requested CID. The sanitized artifact reports HTTP 200,
three reachable blocks, one record, and `promotedBlobCount: 1`.

The implementation is in `PublicRepositoryCARReplication.swift`, with
`publicRepositoryBlobCIDs()` extracting typed raw links one record at a time
from the durable MST projection. The public-blob promotion path is an
explicit opt-in (`--promote-public-blobs`) after CAR publication; it does not
promote permissioned references. Focused Swift tests and the macOS build pass,
and the live Compose proof passes. The alpha remains open for value-bearing
incremental updates, compaction-gap/full-CAR recovery, reverse authority, and
the complete cross-implementation OAuth/security/lifecycle/export matrix.

## Current resume point: 2026-07-29

The current Swan jj working copy is clean. The latest committed slice is
`17fe2ed5439a2b335d82f292f0a65a770de82836`
(`feat(interop): promote public blobs after CAR import`). Task 44's explicit-
rkey public `putRecord`/`deleteRecord` capability, subsequent public
`createRecord`/`applyWrites` and blob lifecycle work, PLC rotation history, and
the stateful live-runner/runtime hardening are already present in the ancestor
history; do not restart those tasks from the old resume paragraph above.

The latest verified evidence is:

- `swift test --jobs 1` passed all affected Swift targets with zero failures;
  the normal suite reported 1 skipped opt-in test in `SwanSpacesTests`, 1 in
  public CAR staging, 1 in the public-read directory suite, and 1 environment-
  gated lab-validation skip. The explicit 256 MiB public-directory RSS test
  passed.
- `PublicRepositoryReadHTTPTests` passed 8/8, the canonical `sync.getBlob`
  `did`+`cid` path test passed, and the typed raw-link SQLite projection test
  passed.
- `Scripts/verify-profile.sh`, `Scripts/verify-interop-lab.sh`, the offline
  semantic lab, and `git diff --check` passed.
- The rebuilt Compose lab passed a disposable dynamic-PLC reference CAR import
  and receiver public-blob promotion: HTTP 200, one record, three reachable
  blocks, verified commit, and `promotedBlobCount: 1` in the ignored sanitized
  artifact `artifacts/reference-public-import-live.json`.

Continue from this clean commit by closing or explicitly documenting the
remaining cross-implementation gates: a complete Swan/TypeScript semantic
matrix for records, credentials, blobs, incremental sync, compaction-gap CAR
recovery, corrupted traffic, and reverse authority where the pinned branch
supports it; then run the clean-cache macOS/Linux acceptance and full Compose
matrix. The pinned TypeScript values-including `listRepoOps` SQLite ambiguity
is an upstream divergence already recorded in the profile and must not be
silently represented as a passing values test.
