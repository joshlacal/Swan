# SDD ledger — plan: docs/superpowers/plans/2026-08-12-swan-production-readiness.md

Spec: docs/superpowers/specs/2026-08-12-swan-production-readiness-design.md
Working in the main jj working copy (no separate workspace); jj snapshots every
invocation and `jj op undo` is the recovery path.

BASE for Task 1: recorded below at dispatch time.

## Task 1 — name the failing guard in logs
BASE: 77153b50af97
Implementer commit: 3cbf43e8d2e3 "SwanSQLite: name the guard that fails public-read admission"
Review 1 (opus): SPEC ✅ / QUALITY request-changes. 0 Critical, 4 Important, 6 Minor.
  Confirmed good: 11 required cases present with exact names; zero bare `.unavailable`
  remain (associated value makes it compile-enforced); 503 body byte-identical; log
  level `warning`; selector allow-listed before logging; no Sendable/isolation change;
  the two brief-named tests exercise a real SQLite DB and a genuine second connection.
Fix round 1 dispatched: F1 compound guard at SQLitePreMigratedAccountDirectory:1434-1439
  (4 conditions -> 1 name, on the exact path that failed live); F2 identity reasons
  leaking onto record-index reads; F3 five unlogged 503 exits + false doc comment at
  SwanPublicRepositoryReadXRPC:681; F4 weakened assertion in AdmissionIntegrityTests:82-85;
  F5 tautological token test; F6 wrapper swallowing CancellationError as .projectionMismatch.
Task 1: minor (deferred): `.admissionBudgetExhausted` used for constructor validation
  (PublicRepositoryReadDirectory.swift:439,548,699)
Task 1: minor (deferred): `.malformedProjectionValue` on aggregate-byte overflow
  (PublicRepositoryReadDirectory.swift:392)
Task 1: minor (deferred): `.storageFailure` on export column decodes
  (PublicRepositoryBoundedExport.swift:433,440,451)
Task 1: minor (deferred): several new throw lines exceed the file's ~80-col convention
Controller note: implementer's enum grew to 25 cases vs the brief's 11. Reviewer judged
  this forced, not YAGNI — `.unavailable` had ~60 throw sites beyond the 11 admission
  guards. Accepted.
Controller note: my first suite run was piped through `tail -60`, so the captured counts
  were meaningless. Exit code was 0. Re-running with full capture.

### Pre-existing flake found while verifying Task 1 (NOT caused by Task 1)
`SwanHTTPTests.SwanXRPCPipethroughTests` crashes the xctest process with
`NIOCore/NIOAsyncWriter.swift:177: Fatal error: Deinited NIOAsyncWriter without
calling finish()` -> signal 5. Reproduced 1 run in 3 (isolated filter, 31 tests;
crash lands around `testParserRefusedQueryBytesNeverReachTheHandler`, test 19).
Task 1's diff touches no pipethrough source or test, so this predates it.
Consequence: `swift test` exits 1 with ZERO `Test Case ... failed` lines. Counting
only failed-case lines reports a false green. Check the exit code AND the trailing
"Some test targets reported failures:" line.
BLOCKS Task 6 (route-before-auth) — that task edits SwanXRPCPipethrough.swift, and a
1-in-3 crashing target makes its verification meaningless. Fix the flake first.
Controller trap hit: piping `swift test` through `tail` masks the exit code with
`tail`'s. Always redirect to a file, then read the file.

Fix round 1 commit: 27bcfeac3872 "SwanSQLite: split the last compound public-read
guards and log every 503"
Re-review (sonnet): all six ADDRESSED, no new problems.
  F1 four-way split -> .directoryClosed / .accountNotActive / .accountNotPreopened /
    .publicIdentityVerifierUnconfigured; same split also applied to the post-admission
    recheck and recheckPublicAccount.
  F2 the three row-readers now take a REQUIRED `reason:` param, so a missed call site
    cannot compile; record-index columns report .recordIndexMalformed.
  F3 all seven exits route through publicReadUnavailable; only one raw
    publicReadError(.serviceUnavailable) remains, inside that function; doc comment
    corrected.
  F4 asserts .publicIdentityVerifierUnconfigured specifically.
  F5 replaced with a hand-written 29-string golden Set, diffed both directions.
  F6 split into verifyProjectionWithoutGate (preserves the historical corruptRepository
    contract) + namedProjectionVerificationWithoutGate; CancellationError rethrown
    untouched; generic catch -> .storageFailure; block corruption -> .blockMaterializationFailed,
    matching the classifier the directory already used.
  PublicRepositoryStore.swift (+49, outside the brief's file list): justified — it is
    where F6's blanket catch actually lived.
Suite after fix round: build exit 0; 1389 passed, 0 failed; test exit 1 SOLELY from the
  pre-existing SwanXRPCPipethroughTests crash.
Task 1: complete

## Inserted task — fix the SwanXRPCPipethroughTests process crash
Commit: a1cd756cf842 "SwanHTTP: complete a round trip before feeding parser-refused
query bytes" (test file only, +33).
Root cause: the test opened a connection and never completed a request on it. When the
refused request threw and hard-cancelled the service group, a connection already accepted
by the kernel but not yet delivered to the server's async inbound stream was dropped in
NIOAsyncChannelHandler._deliverReads; channelActive then released the last reference to
that server-side child NIOAsyncChannel's never-finished NIOAsyncWriter, whose deinit is a
preconditionFailure. Fix: complete one well-formed 404 round trip per iteration first.
Assertion strengthened, not loosened — "not delivered" could previously be satisfied by a
connection the server never served.
Suite now: exit 0, 1420 passed, 0 failed, all 11 targets. (1420 vs 1389 = the previously
truncated SwanHTTPTests tail now running.)
KNOWN HAZARD (carried forward, not fixed): the same upstream swift-nio/hummingbird race is
reachable in the running server — SwanCommand puts the public app in a ServiceGroup with
firehose/recovery services; if one throws, ServiceLifecycle hard-cancels the group and a
connection accepted at that instant would trap the process. Fault-during-fatal-shutdown
only. Remediation needs an upstream patch or vendoring Hummingbird. Revisit before W3
turns the firehose on, since W3 adds services to that same group.

## Task 2 — re-admit a stale generation instead of failing
BASE: a1cd756cf842
Implementer commit: 0af9b5f51b54 "SwanSQLite: re-admit a stale public-read generation
instead of failing"
Suite verified by controller: exit 0, 1424 passed, 0 failed, 11 targets (baseline 1420 + 4).
Review (opus): SPEC ✅ / QUALITY approve. 0 Critical, 1 Important, 4 Minor.
  LAUNDERING SAFETY: safe. `.generationPinStale` has exactly 3 producers, all pure pin
    comparisons (PublicRepositoryReadStore.swift:441,880,909); untyped errors are mapped
    to .storageFailure inside each closure before the catch sees them; re-admission runs
    refreshPublicReadGeneration -> admitPublicRepositoryGeneration, the same predicate,
    not a weaker one; the retry re-validates all four pins + recheckPublicAccount.
    Cross-account/row/superseded serving blocked 3 ways, incl. FULL-FIELD Equatable on
    the control row and `publicReadGenerations[did]?.id == generation.id`.
  SINGLE-FLIGHT: sound. defer clears the map on throw and return; store-before-first-
    suspension holds because Task{} inherits actor isolation; joiner across a changed
    control row fails closed; no handle is ever cancelled (unstructured Task, intended).
  BOUND: structural — `attempt` written twice on a straight line, no loop/recursion.
  Concern 1 (transient 503 burst) adjudicated ACCEPTABLE: window is one control-store
    query vs an admission costing orders of magnitude more; under uniform staleness (the
    real production shape) there is no burst — 8 concurrent readers, 8 successes, 1
    admission. Pre-existing window; refreshPublicReadGenerationAfterMutation has always
    republished on every write.
  Concern 2 (publish after close) HARMLESS: resurrected entry unreachable because
    resolvePublicAccount throws .directoryClosed first; no SQLite use-after-close (the
    connection gate serializes).
  Concern 3 (test proves the trigger) YES: the production trigger IS "a second descriptor
    is opened against the account DB", so the test is the production shape, not a proxy.
    Revision-equality assertions would fail with .repositoryStateMismatch if any foreign
    commit had touched repository state.
Fix round 1 dispatched: F1 negative-cache failed re-admission (a permanently-unadmittable
  account currently pays a full record-index walk up to 100k entries + MST verify + PLC
  verify on EVERY public read, driven by anonymous callers — matters because W3 exposes
  these endpoints to the whole network); F2 dead `touchingRepositoryState:` param;
  F3 test name claims a log assertion it doesn't make; F4 assert data_version actually moved.
Deferred by ruling: recheckPublicAccount "my generation or any that superseded it";
  close() not awaiting in-flight admission handles; the three residual one-attempt 503
  paths at :1497/:1506/:1538.

Fix round 1 commit: c92c1b07266c "SwanSQLite: back off after a failed public-read
re-admission"
Re-review (sonnet): all four ADDRESSED, no new problems.
  F1 flat 250ms per-DID window, deliberately NOT exponential (a compounding backoff trades
    saved work for a recovery delay that grows with failure count = the outage in slower
    form). recovery-not-delayed VERIFIED by trace: the single publish site clears the
    entry in the same synchronous stretch after its last await; the only other
    publicReadGenerations writer (admitActivatedAccount) is on a mutually exclusive
    branch; both sites that remove a DID from `databases` also purge the failure map, so
    a DID cannot re-enter carrying a stale entry. serves-nothing-new VERIFIED: the branch
    rethrows the identical recorded reason and still journals per request; no HTTP file
    touched. Memory VERIFIED: cap checked only on new-key insert, O(n) eviction only at
    capacity, decline-to-record fallback, keyed strictly per DID.
    CancellationError excluded structurally two ways: the catch is typed to
    PublicRepositoryReadError so raw cancellation never matches, and `catch is
    CancellationError` is ordered BEFORE the generic catch so it cannot be relabelled
    .storageFailure and leak in.
  F2 param dropped, all 6 call sites updated, zero references remain.
  F3 renamed to ...Still503sWithTheGuardThatFired. LoggingSystem.bootstrap argument
    judged SOUND — it is process-global and one-shot across 12 test targets in one
    `swift test` process, so bootstrapping here would clobber logging for the other 11.
  F4 third non-writing connection reads PRAGMA data_version before/after and asserts it
    moved. Scoped to the primary regression test; the other five call sites still leave
    it implicit.
  Timing tests: FALSE-RED RISK ONLY, no path to a false green — Task.sleep is a lower
    bound so the 500ms sleeps can only over-satisfy the 250ms window, and the count
    assertions are structural, not timing-derived.
Suite verified by controller: exit 0, 1426 passed, 0 failed, 11 targets.
Task 2: complete

## Tasks 3(fix)/4/6/7/8/9/10 — executed via workflow wf_9003f399-4f8
Commits, in order:
  af6c92c82874  SwanSQLite: bound cold-cache public reads with the admission backoff   (T3 fix)
  04c68d89fb0a  SwanSQLite: name and bound reason-less public read admission failures  (T3 fix)
  6961078b7c43  SwanSQLite: treat data_version movement as change detection            (T4)
  310c32cf3519  SwanHTTP: route before authenticating so missing routes 404            (T6)
  0fe20ba330e5  SwanHTTP: implement unauthenticated resolveHandle                      (T7)
  c148cae0f9a8  SwanHTTP: bound resolveHandle admission and align its registration     (T7 fix)
  7a8cc47e7c97  SwanHTTP: serve public blob reads from the read path                   (T8)
  4ecd9e1ad34e  SwanHTTP: bound and cover the public blob read route                   (T8 fix)
  705e2b411210  SwanHTTP: serve did.json and stop advertising unsupported invites      (T9)
  3b36c442bc9e  SwanHTTP: drive public route registration from the loaded profile      (T10)
Suite at branch head 3b36c442bc9e, verified by controller: build exit 0, test exit 0,
1479 passed, 0 failed, 0 target failures, 0 crashes.
History is linear; timestamps strictly increasing, no interleaving.

### Task 10 ruling (coordinator) — BOTH premises in the plan's D10 were wrong
1. `--profile` structurally CANNOT name a public profile: ProtocolProfile.init(data:)
   hard-requires an `id` prefixed `permissioned-data-` plus crypto/oplogRetention/
   proposalCommit fields the public artifacts lack.
   RULED: add a SIBLING `--public-profile`, do NOT widen ProtocolProfile. Loosening a
   type so one flag means two families is the shape behind two prior prod security bugs.
2. The spec's claim that "the permissioned surface correctly iterates the loaded profile"
   is FALSE — SwanHTTP.swift:875 hardcodes PermissionedData0016.methods too. Neither
   surface was profile-driven. Out of scope for T10; BACKLOG ITEM.
3. RULED: default public surface stays public-data-testing-2026-07-27. Moving to 08-06
   would flip six com.atproto.server.* methods and subscribeRepos from 404 to 503 —
   a surface change smuggled into a surface-selection task, immediately before a security
   scan and federation that both read the served surface as input.
4. The registry had to live OUTSIDE Sources/SwanPublicWire/ — that file is byte-pinned by
   both generated-wire manifests AND the verifier rejects any unlisted .swift in that
   directory, so even a new file there breaks profile verification.

### Security investigation: `com.atproto.server.*` has no wildcard guard — REFUTED
Claim was that the six email methods fall past every guard into xrpcPipethrough.
Sub-claim TRUE (no wildcard guard; unguarded: server.*, admin.*, temp.*, moderation.*,
label.*, lexicon.*). Consequence FALSE.
SwanXRPCProxyRouting.swift:75-79 is an ALLOW-LIST — proxyablePrefixes = app.bsky.,
chat.bsky., tools.ozone.; proxyableMethods = moderation.createReport, label.queryLabels.
`com.atproto.*` is absent ON PURPOSE, with a source comment saying why. Routing now runs
BEFORE auth and before body buffering, so an unregistered com.atproto.server.* NSID gets
404 EndpointUnavailable with the POST body never buffered and no socket opened.
Empirically pinned already: SwanXRPCPipethroughTests.swift:927 posts
{"identifier":...,"password":"hunter2"} to createSession AND resetPassword under
`atproto-proxy: did:web:attacker.example#svc` with a RESOLVABLE attacker DID doc, and
asserts 404 with no upstream contact. 44 tests, 0 failures at HEAD.
NOT introduced by this work: SwanXRPCProxyRouting.swift is 0-files-changed vs 77153b50af97.
Net effect of routing-before-auth on this class: 401 -> 404. More informative, not more
permissive.
Residual (neither blocks the relay):
  R1 SwanXRPCProxyRouting.swift:59-63 carries a STALE COMMENT claiming the 20260727
     descriptor loop registers an unavailable stub for com.atproto.server.resetPassword.
     False at HEAD and false at 77153b50af97 — 20260727 has no com.atproto.server.*
     entries. Asserts a second layer of protection that does not exist; could talk a
     future reviewer out of a real concern. FIX BEFORE THE SECURITY SCAN.
  R2 server.*/admin.*/temp.* are refused by the allow-list alone, vs two independent
     gates for repo.*/sync.*/identity.*. Adding "/xrpc/com.atproto.server.*" to
     registerUnknownPublicEndpointGuards is safe (every server.* route Swan registers is
     an exact path, and exact beats .* in the trie). Defense in depth, not a fix.
