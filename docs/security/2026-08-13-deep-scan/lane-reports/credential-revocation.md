# Lane report — C3 space credential revocation (L12 partial)

Cluster: `docs/security/2026-08-13-deep-scan/clusters/C3-space-credential-revocation.md`
Program: `docs/security/2026-08-13-deep-scan/REMEDIATION-PROGRAM.md` §3 L12, §4 item 8, §5.
Workspace: `Swan-sec-credential-revocation`, based on `fc11540f4d3e`.

**Scope note.** This lane was re-scoped mid-flight after the verification pass
landed. An earlier commit on this branch implemented a different F03 mechanism (a
durable credential-grant registry); it has been **abandoned**, not reverted, so it
leaves no trace in history. §6 records what it established that is still useful to
whoever builds the watermark.

---

## 1. Status

| Finding | Verdict | Disposition |
|---|---|---|
| F14 | CONFIRMED | **Fixed**, committed |
| F03 part 1 (short lease) | CONFIRMED | **Partially shipped** — issuance default bounded; the `swan serve` flag half is blocked, see §4 |
| F03 part 2 (`iat > updated_at` watermark) | CONFIRMED | **Blocked on file ownership**, not built. Design and traps in §5 |
| F08 | CONFIRMED | **Not fixed separately, by design** — subsumed by F03, see §3 |
| F39 | CONFIRMED | **Out of scope** — accepted risk, documented in L13 |

---

## 2. F14 — signing key fenced against lifecycle change (fixed)

`LocalAccountSpaceCredentialSigningKeyResolver.signingKey` read the account row
and key references (`SpaceCredentialAuthority.swift:207-212`), `await`ed
`keyStore.key(for:)` (`:213`), and returned the private key without looking
again. The caller signs a credential immediately on return, so a deactivation,
permanent-deletion revocation, or key rotation committing inside that suspension
yielded a credential authorized only by stale facts — one that then outlives the
revocation that should have prevented it.

The argument is entirely internal to the file: the two *verification* resolvers
apply exactly this fence, each with a comment explaining why
(`:304-317`, `:397-410`). The signing path was the odd one out. Coverage was
asymmetric in the same direction — `LocalCredentialAuthorityFailClosedTests`
gives the verification resolvers 17 fail-closed tests including a mid-read
lifecycle flip (`:320`), while the signing resolver had **zero** behavioural
tests and appeared only as a constructor argument in happy-path fixtures.

**Fix:** after the key-store read, re-read the account and key references and
require unchanged, still authorizing, and matching signing/rotation generations.

**Failure mode is a throw, not `nil`.** `nil` from this resolver means "no such
managed authority" and is a fall-through; a state that changed underneath us is a
hard negative that must not be mistaken for absence.
`SwanSpaceCredentialXRPC.swift:153-157` already maps `SwanError.unavailable`
without widening the client-visible body. A test pins that the unmanaged-DID case
still returns `nil`, so the two cannot be collapsed later.

**Not** wrapped in `withActiveAccountAuthorization`: that API's own contract at
`AccountControlStore.swift:2436-2438` forbids I/O inside it, and this path does a
keystore file read plus an ES256 sign. The program already flags that remediation
string as boilerplate pasted onto five unrelated findings (§1 of the program).

### Observed pre-fix failures

Verified by reverting only `Sources/SwanOAuth/SpaceCredentialAuthority.swift` to
`fc11540f4d3e` and re-running the same tests — not inferred from an earlier run:

```
SpaceCredentialSigningFenceTests.swift:39: error: ... testAccountDeactivationDuringKeyStoreReadDoesNotYieldSigningKey :
  XCTAssertNil failed: "SpaceCredentialAuthoritySigningKey(authority: "did:plc:abcdefghijklmnopqrstuvwx", keyID: "#atproto_space", privateKey: ...)"
  - the resolver must re-read account lifecycle after the key-store suspension

SpaceCredentialSigningFenceTests.swift:58: error: ... testKeyRotationDuringKeyStoreReadDoesNotYieldSigningKey :
  XCTAssertNil failed: "SpaceCredentialAuthoritySigningKey(authority: "did:plc:abcdefghijklmnopqrstuvwx", keyID: "#atproto_space", privateKey: ...)"
  - the resolver must re-read the key generation after the key-store suspension
```

The two regression guards (`testUnracedResolutionStillReturnsTheAuthoritySigningKey`,
`testUnmanagedAuthorityStillFallsThroughAsNil`) passed pre-fix, as intended.

**Test mechanism:** deterministic seams, no sleeps. An `AccountKeyStore` wrapper
commits the deactivation (or provisions generation 2 and rotates the control-store
references) *inside* `key(for:)` — the same technique as the existing
`LifecycleFlippingPublicKeyStore` at `LocalCredentialAuthorityFailClosedTests.swift:707-737`.

---

## 3. F08 — not fixed separately, and that is the right call

I had built a pre-signing policy re-check for F08. It is gone with the abandoned
commit, and I agree it should be.

The reasoning is the program's and it holds: an attacker who wins the race
receives a credential **identical to one obtainable microseconds earlier**, which
stays valid for its whole lifetime regardless. Closing the race narrows the window
in which a credential can be *minted* while changing nothing about how long an
already-minted one keeps working. That is the F03 problem, and any fix for F03 —
either half — subsumes it:

- With the short lease (§4), the race's value is bounded to the same window as
  every other outstanding credential.
- With the watermark (§5), a credential minted after the removal linearizes behind
  the `updated_at` bump and is refused on its first read. F08 closes for free.

Shipping a separate fence would have added a durable write to the issuance path to
buy a strictly smaller improvement than the fix it sits next to.

---

## 4. F03 part 1 — issuance lifetime bounded (partially shipped)

`DurableSpaceCredentialAuthority.Configuration.standard` defaulted to
`PermissionedDataJWT.spaceCredentialLifetime`, i.e. two hours. Because a space
credential names no reader and is never re-checked against membership, **its
lifetime is the revocation window**.

**Shipped:** a `Configuration.defaultLifetime` of 300 s, used by `.standard` and by
the no-argument initializer. Composition builds `DurableSpaceCredentialAuthority`
without a configuration (`SwanHTTP.swift:641-646`), so this is the deployed
default.

The acceptance ceiling is deliberately untouched.
`PermissionedDataJWT.spaceCredentialLifetime` stays at two hours, which is what
`createSpaceCredential` enforces as a maximum and what `verifySpaceCredential`
accepts. That constant is interop-visible: the pinned TypeScript PDS at commit
`3f6c96d5d2d25438bd40fa89d6ecc37865f8e354` mints two-hour credentials
(`packages/space/src/credential.ts:21-27`) that Swan verifies in the
`reference-authority-dynamic-credential` acceptance scenario
(`Scripts/run-reference-member-dynamic-delegation-acceptance.sh:641`). Lowering
the ceiling would break that; lowering only what Swan issues does not. A test pins
both halves separately so they cannot drift together.

No wire change, no migration, no schema change.

### Blocked half: the `swan serve` flag

The program asks for the lifetime to be **exposed as a `swan serve` flag**. That
requires `Sources/swan/SwanCommand.swift`, which the program assigns to the
**L9 deployment-hardening lane** (§3, `**Files:**` list at line 169, closing
F17/F36). The hard constraint is "no file appears in two lanes", so I did not
touch it.

This matters and is not cosmetic: shipping the shorter default without the knob
means an operator who finds 300 s too aggressive has **no supported way to raise
it** short of a rebuild. Either dispatch the flag to L9 as a one-line addition
alongside its other `SwanCommand.swift` work, or hand me the file once L9 is done.
The `Configuration` type already validates the full admissible range, so the flag
is pure plumbing.

---

## 5. F03 part 2 — the watermark is blocked on file ownership

**I did not build it.** Not written, not held back pending the over-revocation
decision — never started, because it cannot be built from the files this lane may
touch. No code is waiting on that decision.

Do not confuse this with the abandoned commit: that implemented a *different*
mechanism (a durable credential-grant registry keyed on `jti`), which is gone. Not
one line of the `iat > updated_at` watermark exists.

The gate needs the space's `updated_at`. That value exists in exactly one place:
the `permissioned_simple_space_authorities.updated_at` column, read inside
`loadSimpleSpace` in `Sources/SwanSQLite/SwanSQLite.swift` and **discarded there**
(it is validated against `created_at` and never surfaced). Verified absent from
every candidate projection:

- `DurableSimpleSpaceState` carries `space` and `revision` only (`SwanSQLite.swift:1435-1443`).
- `SimpleSpace` carries `uri`, `owner`, `configuration`, `members`, `isDeleted` (`SwanSpaces.swift:1846-1852`).
- `AuthenticatedSimpleSpaceDescription` — the only projection `AuthorizedSimpleSpaceDirectory` returns — carries `space` and `configuration` (`AuthorizedSimpleSpaceDirectory.swift:141-149`).
- `grep` for `updatedAt` across `Sources/SwanSpaces/` and `Sources/SwanStorage/AuthorizedSimpleSpaceDirectory.swift`: no hits.

So surfacing it requires **both**:

1. `Sources/SwanSQLite/SwanSQLite.swift` — to project the column. That file is
   assigned to **L11** (§3 `**Files:**`, line 179) and is not in L12's list at all.
2. `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift` — to expose it on
   the directory the HTTP seams hold. In L12's list, but under **concurrent edit**
   and explicitly off-limits to me.

A `revision`-based watermark is not an escape: the credential carries no revision
to compare against. `iat > updated_at` works *precisely because* `iat` is already
in the claim set, which is also why it needs no wire change.

### Two things whoever builds it must get right

**(a) The units do not match, and getting it wrong fails silently in either
direction.** `updated_at` is **microseconds** —
`simpleSpaceTimestamp` returns `Int(date.timeIntervalSince1970 * 1_000_000)`
(`SwanSQLite.swift:9075-9084`) and `touchSimpleSpace` writes exactly that
(`:9165-9183`). `iat` is **seconds** — `Int64(now.timeIntervalSince1970)`
(`SwanOAuth.swift:554`). A naive `claims.iat > updatedAt` is always false and
silently revokes every credential for every space; flipping the comparison to
"fix" it silently revokes nothing. Convert explicitly at the seam and test both
directions.

**(b) There are eight credential-bearing routes, not four.** The program says
"the four verifier seams" and "all four call sites"; the file list is right but
the count undercounts. Verified surface:

| nsid | selector | reaches `SpaceAuthorizationPolicy`? |
|---|---|---|
| `com.atproto.space.getRecord` | `SwanSpaceXRPC.swift:648` | yes (`SwanSQLite.swift:11047`) |
| `com.atproto.space.listRecords` | same | yes |
| `com.atproto.space.getBlob` | `SwanSpaceBlobXRPC.swift:216` | yes |
| `com.atproto.space.getRepo` | `SwanSpaceRepositorySyncXRPC.swift:299` | yes |
| `com.atproto.space.getLatestCommit` | same | yes |
| `com.atproto.space.listRepoOps` | same | yes |
| `com.atproto.space.listRepos` | `SwanSpaceNotificationXRPC.swift:523` | **no** — inline check at `SwanSQLite.swift:6648-6652` |
| `com.atproto.space.registerNotify` | same | **no** — inline check at `SwanSQLite.swift:6717-6721` |

The last two bypass `SpaceAuthorizationPolicy` entirely, and `registerNotify` is a
durable **write** gated on a `.read` grant (`SwanSQLite.swift:6745-6760`). A shared
check placed inside `SpaceAuthorizationPolicy.require` would miss both.
`SwanSpaceNotificationXRPC.swift` is in L12's file list, so the lane does cover
them — but the check belongs at the credential-verification seam, which all eight
pass through, rather than at the policy.

This is not theoretical: when I placed the check at the verification seam in the
abandoned commit, the composition test failed specifically on
`com.atproto.space.registerNotify` and `com.atproto.space.listRepos` — direct
evidence that those two are live credential surfaces.

### The property that needs Josh's sign-off

The watermark **over-revokes by design**. `touchSimpleSpace` bumps `updated_at`
on *every* membership and policy mutation — `addSimpleSpaceMember`,
`removeSimpleSpaceMember`, `setSimpleSpaceClientAccess`,
`setSimpleSpaceManagingAppAccess`, `updateSimpleSpace`, `patchSimpleSpace`,
`deleteSimpleSpace`. So **adding** a member invalidates every live credential held
by every *existing* member of that space, forcing all of them to re-run the
delegation exchange mid-session. On an active space this is not a rare event.

One mitigation is already in the data model and worth knowing: duplicate mutations
are explicit no-ops that do **not** bump the revision or the timestamp
(`SwanSQLite.swift:1431-1434`), so a repeated `addMember` is free. That does not
help the genuine-edit case.

With part 1 shipped, the exposure the watermark closes is now "up to 300 s of
post-removal read access" rather than "up to two hours". That materially changes
the trade — it is the difference between accepting a five-minute window and
accepting mid-session re-exchange for every reader on every membership edit. Worth
re-deciding on those terms rather than the original two-hour framing.

---

## 6. What the abandoned registry commit established (still useful)

The abandoned mechanism recorded, per issued credential, a digest of its `jti`
plus reader, client, and authority revision, and re-checked it on read. It worked
— seven tests, full suite green — but it needed a schema migration and edits to
both contested SQLite files, and the program's watermark achieves the same
revocation with neither. Dropping it is correct.

Three findings from that work outlive it:

1. **The eight-route surface count** in §5(b), and the evidence that
   `listRepos`/`registerNotify` are live credential surfaces.
2. **The unit mismatch** in §5(a).
3. **Cost of any per-read authority lookup.** Measured on the M4 Max, 500
   iterations × 5 interleaved rounds: baseline verification 527 µs/read; with one
   extra indexed authority lookup 1092 µs/read (**≈2.1×**, +565 µs). The added
   `SELECT` was not the cost — the `preopened…`/`require…StillAvailable` bracket
   around it was (`SQLitePreMigratedAccountDirectory.swift:2372-2390`, `:2405-2416`),
   which performs an account-status lookup plus a filesystem stat on each side.
   The watermark will pay the same bracket cost unless it reads through a cheaper
   path. Budget for roughly a doubling of per-read authorization latency, and
   consider folding the pre/post checks into the read transaction.

---

## 7. Verification

### Evidence integrity — one number withdrawn

Every log in this lane was originally written to the session scratchpad under
`/private/tmp/claude-501/…/scratchpad/`. That directory is **shared by all eight
lanes**, not per-agent: it holds 402 files, many predating this session and
written by other lanes (`a.swift`, `apidiff2.log`, `baseline-build.log`,
`build-f1.log`, …). Concurrent redirects to the same filename clobber each other,
and a fully-clobbered log looks entirely self-consistent.

I audited my own logs rather than assuming either way, using my lane's unique test
class names as a provenance marker:

| Log | Verdict |
|---|---|
| final suite (1496/0/9/11) | **authentic** — 10 hits for `SpaceCredentialSigningFenceTests`, 8 for `SpaceCredentialLifetimeTests` |
| pre-assertion-fix run (1495/1) | authentic — same markers |
| F14 pre-fix and post-fix runs | authentic — same markers |
| earlier Linux run (`PRODUCTS_OK`, `LANE_TEST_TARGETS_OK`) | authentic — 9 references to this workspace, no other workspace path |
| **baseline (1489)** | **CLOBBERED** — the file now contains a dependency-fetch log with **zero** test-case lines |

**Withdrawn:** my own measurement of the 1489 baseline. I cannot substantiate it
and am not going to restate it as if I had. The 1489 figure in the lane brief
stands on its own authority, and my result is *consistent* with it — 1496 − 7 new
tests (4 in `SpaceCredentialSigningFenceTests`, 3 in `SpaceCredentialLifetimeTests`)
= 1489 — but that is arithmetic, not an independent measurement. If an
independently measured baseline is wanted, it needs a full run at
`fc11540f4d3e`; say the word and I will do it.

Everything below was re-run from scratch into
`/private/tmp/swan-lane-sec-credential-revocation/`, which nothing else writes to.

### Suite (re-established)

`xcrun --toolchain XcodeDefault swift build --build-tests` then
`xcrun --toolchain XcodeDefault swift test --skip-build`, redirected to
`/private/tmp/swan-lane-sec-credential-revocation/suite-final.log`:

```
exit code 0
1496 passed
0 failed
9 skipped
11 targets
"Some test targets reported failures" — absent
```

Both checks were run — exit code *and* the failure-summary string — because a
crashing target exits 1 with zero failed-case lines. Note the counting recipe in
the lane brief, `grep -c "Test Case '-\[.*\] passed"`, matches nothing: the log
line is `Test Case '-[Suite testName]' passed`, with a quote between `]` and
` passed`.

**One pre-existing test changed:**
`SpaceCredentialAuthorityTests.testLocalAuthorityIssuesAndVerifiesPinnedCredentialWithoutSQLiteSecrets`
asserted the issued lifetime was `7_200`. That is precisely the property part 1
changes, so the assertion now reads `300` with the reason recorded inline. It was
the *only* fallout across the whole suite — verified by a full run before the
assertion was touched (1495 passed, 1 failed, that one).

**Linux: GREEN.** `swift build --build-tests` → **exit 0, zero errors,
`Build complete! (514.43s)`**. Log:
`/private/tmp/swan-lane-sec-credential-revocation/linux-final.log`.

This is the committed tree, rebased onto `29ce8202` (the central fix for the
`await`-in-`defer` break described below). `SwanOAuth/SpaceCredentialAuthority.swift`
— the only source file this lane changes — compiled at step `[3610/3666]`, and
`SwanOAuthTests`, which holds both new test files, built as part of the run.
`SwanPackageTests.xctest` linked.

Command (the brief's form, corrected for two deterministic failures found
earlier in this lane):

```
docker run --rm --name swan-cred \
  -v <parent>/Petrel:/workspace/Petrel \
  -v <parent>/Swan-sec-credential-revocation:/workspace/Swan \
  -w /workspace/Swan swift:6.1-jammy bash -lc \
  'apt-get update && apt-get install -y --no-install-recommends \
     libsodium-dev pkg-config libsecret-1-dev libglib2.0-dev && \
   swift build --build-tests --scratch-path /workspace/Swan/.build-linux'
```

Four things this recipe encodes, each learned from a failure:

1. **Mount the parent's `Petrel` explicitly.** `Package.swift:25` is
   `.package(path: "../Petrel")`, outside a single-directory bind mount.
2. **Install the system libraries** `Dockerfile:4-9` installs, or the build stops
   at `Petrel/Sources/CLibSecretShim/shim.c:2: fatal error: 'libsecret/secret.h' file not found`.
3. **Put the scratch path *inside* the bind mount.** With it outside, SwiftPM
   fails deterministically copying the `Tests/SwanOAuthTests/Fixtures` resource
   (`Package.swift:235`) with `NSCocoaErrorDomain Code=512 … NSUserStringVariant=["Copy"]`.
   Reproduced twice at the same step. `.build-*/` is already gitignored
   (`.gitignore:2`), so `.build-linux` needs no cleanup and cannot collide with
   the macOS `.build`.
4. **Keep the container mount path stable across runs.** Reusing a `.build`
   populated under a different path gives
   `error: PCH was compiled with module cache path … but the path is currently …`
   plus `missing required module 'SwiftShims'` (14 errors).

5. **Check `Package.resolved` after every container run, and restore rather than
   commit if it drifted.** A Linux run rewrote it to **34 pins, dropping
   `swift-configuration`** — committing that would break the macOS build for
   whoever merged the lane. This is especially dangerous under jj, where the
   working copy *is* a commit, so a container-rewritten manifest sitting there
   gets swept into whatever you seal next. Guard:
   `grep -c '"identity"' Package.resolved` should be **35**; if not,
   `jj restore Package.resolved`. Verified for this lane: 35 pins with
   `swift-configuration` present in the working copy and in all three commits,
   and `Package.resolved` appears in none of them.

Two further environmental failures, neither fixable from inside a lane, are worth
recording for whoever schedules these: a sibling lane regenerating the **shared**
`Petrel` checkout mid-compile (`error: input file '…/ChatBskyConvoDefs.swift' was
modified during the build`), and simple CPU starvation when six lane containers
run at once — an earlier attempt never escaped `apt`.

**On the `await`-in-`defer` break.** This lane found it and reported it as
pre-existing rather than assuming its own work caused it; verification was
`jj file show -r fc11540f4d3e … | diff -q` against the sealed base (identical).
It is now fixed centrally in `29ce8202`, which this stack is rebased onto. Before
that fix, `swift build --build-tests` could not succeed on Linux for any lane on
any branch.

(`git show <rev>:<path>` is unusable in this shell — it is shimmed to a Python
interpreter and prints an error to stdout. `jj file show` was used instead.)

**Files touched** (both commits): `Sources/SwanOAuth/SpaceCredentialAuthority.swift`,
`Tests/SwanOAuthTests/SpaceCredentialSigningFenceTests.swift` (new),
`Tests/SwanOAuthTests/SpaceCredentialLifetimeTests.swift` (new), and this report.
No edit to `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift`,
`Sources/SwanSQLite/SwanSQLite.swift`, or `Sources/swan/SwanCommand.swift`.
F23 and F46 untouched.

---

## 8. Decisions needed

1. **The `swan serve` lifetime flag** (§4) — needs `Sources/swan/SwanCommand.swift`,
   owned by L9. Without it the shorter default is not operator-adjustable.
2. **The watermark's over-revocation property** (§5) — needs Josh, and is worth
   re-deciding now that part 1 has cut the exposure from two hours to five minutes.
3. **Unblocking the watermark** (§5) — needs `SwanSQLite.swift` (L11) and
   `SQLitePreMigratedAccountDirectory.swift` (concurrent edit) assigned to whoever
   builds it. It cannot be built from L12's currently-available files.
4. **Nothing outstanding on verification.** Linux is green (§7) and the suite is
   green. Both items previously listed here are closed: the
   `await`-in-`defer` break is fixed centrally in `29ce8202`, and the Docker
   recipe in §7 now encodes the four things that made earlier attempts fail.
   Worth propagating that recipe to the other lanes — three of its four points
   are not lane-specific.
