# F01 — permissioned blob namespace

Cluster `C1-permissioned-blob-namespace` · finding `csf_0feb001d0f16298db4902b47`
Workspace `Swan-sec-blob-namespace`, based on `fc11540f4d3e`.

> **Revision note.** An earlier version of this report stated a macOS suite
> result of 1496 passed and a passing Linux build. **Those numbers are
> withdrawn.** They were read from logs in the shared scratchpad
> (`/private/tmp/claude-501/.../scratchpad/`), which eight lanes write to under
> colliding names, and I cannot prove they were mine. Everything numeric below
> was re-measured into `/private/tmp/swan-lane-sec-blob-namespace/`, which
> nothing else writes to. Two other corrections to that version are marked
> **[corrected]** in place.

---

## 1. Verdict

**PARTIALLY CONFIRMED — I agree with the verification pass, including the
downgrade to medium.** The mechanism is real and I reproduced it end to end
before changing anything; the HIGH framing overstated who can reach it.

I re-derived the mechanism independently and reached the same four links
(citations at `fc11540f`): the only authenticated upload route hard-codes
`.public` (`SwanPublicRepositoryMutationXRPC.swift:109-112`, guard at `:137`);
`putBlobLocked` makes that a durable edge at `SwanSQLite.swift:7564-7572`;
anonymous `sync.getBlob` admits on a bare namespace-edge join with no record
predicate (`SwanSQLite.swift:7925-7978`, route at
`SwanPublicRepositoryReadXRPC.swift:903-942`); and only a *successful*
permissioned commit removes the edge (`SwanSQLite.swift:9930-9941`).

**Permissioned uploads share the public route exactly.** There is one
`uploadBlob` handler in the tree; `SwanSpaceBlobXRPC.swift` is read-only; and
`LiveInterop.swift:1657` `uploadPermissionedBlob` posts to the same path as
`uploadPublicBlob` at `:1598`.

**I did not re-derive the three mitigating controls, and I should have.** The
verification pass is right that there is no CID-enumeration endpoint, that
permissioned CIDs never reach `public_event_outbox`, and that the real
confidentiality delta is against a *formerly* authorized reader who kept the
CID — not against the anonymous internet. My original report reasoned about
severity from the invariant alone and did not go looking for the controls that
bound reachability. That is the weaker half of my analysis and the redirect is
a fair correction to it.

### One factual correction to the verification pass

The C1 verdict and REMEDIATION item 11 both say serving unreferenced public
uploads "matches the reference PDS". **It does not.** Upstream `atproto`'s PDS
stores an upload under a temp key — `packages/pds/src/actor-store/blob/transactor.ts:62`
calls `blobstore.putTemp(...)` — and only `makePermanent` at `:278` moves it
into the CID-addressed store during a record commit. `getBlob` resolves through
`blobstore.getStream(cid)` (`actor-store/blob/reader.ts:40`), which raises
`BlobNotFoundError` for an upload no record has committed.

This matters because that claim is load-bearing for open decision (b) — whether
Swan should keep serving unreferenced public blobs. The honest framing is that
Swan's current behaviour **diverges from** the reference PDS, and the question
is whether to keep the divergence, not whether to introduce one. I am not
re-arguing the decision; it is the maintainer's. I am correcting the premise it
would be taken on.

---

## 2. What I built, and one thing I need to correct about the redirect

**I did not add an NSID, a route, or any wire-format change, and the earlier
work was not the `com.atproto.space.uploadBlob` proposal the redirect vetoes.**

The redirect asks me to stop building `com.atproto.space.uploadBlob` because of
the public protocol profile bump, the re-pin, and the client migration it
forces. That objection is correct, and it does not describe my change. Verified,
not asserted:

- Every `com.atproto.*` string added across both commits is an **existing**
  NSID appearing in comments and test code — `repo.uploadBlob`,
  `sync.getBlob`, `repo.createRecord`, `space.getBlob`. Zero new ones:
  `jj diff --from fc11540f --to @ | grep '^+' | grep -oE 'com\.atproto\.[a-z]+\.[a-zA-Z]+' | sort -u`
- No lexicon, wire, route-registration, or profile file is touched by the diff.
- `PublicProtocolProfileVerifierTests` — which pins the profile, lexicon, and
  generated-wire SHA-256 triples — passes **unchanged**, 14 cases green. Adding
  an NSID is exactly what that test exists to catch.
- `BlobNamespace` is an internal Swift enum in `SwanStorage`. Adding a case to
  it is not observable on the wire. `com.atproto.repo.uploadBlob`'s request and
  response are byte-identical before and after; no client changes.

So the cost the redirect is avoiding is not a cost this change carries. What the
change *does* do is answer open decision (b) in the affirmative — an upload no
record references stops being anonymously fetchable — and **that is a real
decision that is genuinely the maintainer's**, which is why it is in §6 rather
than presented as settled.

The verification pass also objects that a staged design "re-opens the exact
hazard the design doc's *Deliberate boundary* was written to prevent (a record
write implicitly promoting a blob into the public namespace)". I checked this
against my implementation and it does not hold: the promotion query admits only
`namespace_kind IN ('public','staged')`, so a blob carrying only a `space` edge
is rejected with `publicBlobNotReachable` and a public record write cannot
promote permissioned bytes. The existing `testPublicRecordLinksRequirePublicBlobReachability`
asserts precisely that and passes. The design doc's own sentence anticipates
this: *"A future staged-upload design may add atomic record-linked promotion,
but it must preserve this fail-closed boundary."* It is preserved.

None of that overrides the sequencing call. The doc reserves the staged design
as future work and the program says wait; that is a legitimate decision and I
am not going to take it unilaterally. See §6 for what I need.

### Current commit layout

| Commit | Contents |
|---|---|
| `2cd5f8e0` | Staged upload namespace — the part under decision |
| (working copy) | **The GC sweep** — what the redirect asked for |

They are ordered, not independent, because both use the same `created_at`
column on `blob_namespace_references` and I unified rather than shipping two
overlapping timestamp columns. **If you want the staged half dropped, say so
and I will re-split**: the GC half then stands alone on a two-statement
migration (`ALTER TABLE ... ADD COLUMN created_at` via the existing
`addAccountColumnIfMissing` at `SwanSQLite.swift:3271`, plus the backfill)
instead of the table rebuild. That is mechanical and I have deliberately kept
the sweep free of any dependency on `.staged` so it survives the split.

---

## 3. The GC sweep

`purgeUnreferencedPublicBlobReferences(now:)` in `Sources/SwanSQLite/SwanSQLite.swift`.

A public edge is collected only if **all four** hold:

1. `namespace_kind = 'public'`;
2. `created_at` older than `publicBlobReferenceGracePeriodSeconds` (**14 days**);
3. no `space` edge exists for the same CID;
4. the CID is absent from the public repository's own blob-link projection.

Then `removeBlobReference(BlobReference(cid:, namespace: .public))` — reusing
the existing reclamation path exactly as the redirect specified, so the sweep
inherits `withPrivateBlobLifecycleLock`, the remaining-reference check, and the
crash-safe `reclaiming`-intent unlink rather than reimplementing any of it.

**One deviation from the redirect's wording, deliberate.** It specified
"whose CID fails `publicRepositoryContainsBlobCIDWithoutGate`". I use
`publicRepositoryBlobCIDs()` once per sweep instead and test membership in the
resulting set. Same question, same walk, same bounds — but
`publicRepositoryContainsBlobCIDWithoutGate` walks and decodes the entire
record index *per CID asked*, so the per-candidate form is O(candidates × repo)
where the set form is O(repo). With a candidate cap of 16 that is up to a
16× difference on a path that can run during an upload.

### What drives it

Two request-path drivers, **no background service and no new durable ledger**:

1. **Every account database open** — the recovery block in `init`
   (`SwanSQLite.swift:1919-1921`) and `migrate()`.
2. **Before each staged upload**, alongside the staged expiry sweep, in
   `putStreaming`.

Cost in the steady state is one indexed, `LIMIT 16`-bounded query that returns
nothing; the repository projection is **skipped entirely** when no candidate is
old enough, which is the normal case. Failure is swallowed and returns 0 — a
repository too large to project keeps every edge, because collecting on a
partial answer would delete live blobs. Opportunistic maintenance must never
fail an upload.

**If neither driver ever fires again**, the residue is bounded by
`AccountBlobQuota` (10 000 references / 1 GiB, `SwanStorage.swift:23-26`) and is
a quota cost, never a disclosure. That is the property that keeps this from
becoming the unbounded ledger the same scan flags elsewhere.

### What "aged" means, and why a live request is safe

`created_at` is stamped on the edge at every insert site (four: `putBlobLocked`,
the space and public inserts in `promotePermissionedBlobReferences`, and the
public insert in `PublicRepositoryStore`). A **NULL is never swept**, so a
writer that forgets to stamp an edge leaks storage rather than deleting a live
blob — the fail-safe direction.

Three independent protections against sweeping something in flight:

1. **The 14-day grace period.** A real upload-to-commit gap is seconds; this is
   six orders of magnitude of headroom, and it is the only thing protecting a
   client that uploads Monday and posts Friday. I set it deliberately generous
   because the two errors are not symmetric: too eager deletes a live blob out
   from under a pending record, too patient holds some bytes longer.
2. **The lifecycle lock.** `removeBlobReference` takes
   `withPrivateBlobLifecycleLock(digestHex:)` — the same lock `putBlobLocked`
   holds across its stage-and-commit — so a sweep cannot interleave with an
   in-flight upload of that digest.
3. **Fail-closed commit.** The public commit re-derives reachability inside its
   own transaction. If an edge did vanish mid-apply, the commit fails with
   `publicBlobNotReachable` rather than committing a record pointing at nothing.

**Residual race, stated rather than papered over.** The referenced-set snapshot
is taken before the per-candidate removals. A public record committed inside
that window, for a blob whose edge is *already* older than 14 days, could have
its freshly-restored edge collected. The consequence is a broken image
recoverable by re-upload, not corruption or disclosure. Closing it fully means
predicating the delete on the MST inside a single write transaction, which puts
the repo walk back inside the lock. I judged that a bad trade for a race that
needs a fourteen-day-old blob to be referenced within milliseconds of a sweep;
if you disagree it is a contained change.

### Is `removeBlobReference` refcount-aware? — verified, not assumed

Read at `SwanSQLite.swift:7503-7564`:

- It deletes **only** the exact `(cid, namespace_kind, space_uri)` row.
- It then runs `SELECT 1 FROM blob_namespace_references WHERE cid = ? LIMIT 1`.
  **Any** surviving edge of **any** kind stops reclamation — it returns without
  touching the payload row or the file.
- Only with zero remaining edges does it delete `blob_payloads` and then check
  `hasFileBackedPayloadWithoutGate(digestHex:)` (`:7926`), which keeps the
  physical file when another *logical* CID (a legacy `sha256:` alias) still maps
  to the same digest.

**Two accounts uploading identical bytes share nothing**, so the question does
not even arise across accounts: each account has its own SQLite database, and
the CAS file path is namespaced by `accountBlobNamespace` = `SHA256(accountDID)`
(`:10046`), which is also part of the lifecycle lock key (`:7413-7421`).
Identical bytes from two accounts are two files under two directories tracked in
two tables. Collecting one account's edge cannot reach the other's.

Within one account, `testPublicSweepNeverCollectsABlobAPermissionedRecordOwns`
proves the shared-CID case directly: the same payload put to both `.public` and
`.space(...)`, public edge backdated a year, sweep collects nothing and the
payload survives.

---

## 4. Migration

**Required.** `migrateStagedBlobNamespaceIfNeeded`, version 15
(`SwanSQLite.swift:2820`), following the rename/recreate/copy/drop pattern of
version 7 (`migrateSpaceNotificationReceiptScopeIfNeeded`), with the marker in
`permissioned_repository_migrations` and the call placed in `migrateWithoutGate()`
alongside the other fourteen.

Effect on the deployed database (one real account, real rows):

- Adds `created_at` and widens the `namespace_kind` CHECK. SQLite cannot alter a
  CHECK in place, hence the rebuild.
- **Every inherited row is stamped with the upgrade instant** — not NULL, not
  zero. A zero would make every blob the account already serves instantly
  collectable. This way nothing changes on deploy, and the historical orphans
  this finding is about become collectable one grace period (14 days) later.
  Asserted by `testPreStagedSchemaUpgradePreservesExistingEdges`.
- No row changes kind. No blob bytes move. The table is a per-account reference
  index bounded by `AccountBlobQuota.maximumReferences`, not a payload store.
- Runs inside the existing single migration transaction; a crash rolls back to
  the v14 shape and retries on next open.
- Driven by the **observed table shape** (`PRAGMA table_info`), not the marker
  alone — a restored database can carry a marker for a shape it does not have,
  and a table without `created_at` fails every upload.
  `testPreV4BlobSchemaRestartDefersLegacyBodyMaterialization` caught exactly
  this during development.

If the staged half is dropped, this collapses to `addAccountColumnIfMissing` +
backfill, with no rebuild.

---

## 5. Tests — 11 new cases

Kept from the earlier work, per the redirect ("keep the tests about
reachability after an abandoned apply"):

| Test | Target |
|---|---|
| `testAbandonedUploadNeverBecomesAnonymouslyFetchable` | SwanHTTPTests |
| `testUploadedBlobIsNotAnonymouslyFetchableBeforeAPublicRecordReferencesIt` | SwanHTTPTests |
| `testSameCIDReuploadAfterPermissionedPromotionStaysPrivate` | SwanHTTPTests |
| `testUploadedBlobIsAnonymouslyFetchableOnceAPublicRecordReferencesIt` | SwanHTTPTests (regression guard) |

New for the sweep, in `PermissionedBlobRepositoryReachabilityTests`:

| Test | Asserts |
|---|---|
| `testAgedPublicEdgeNoRecordReferencesIsCollected` | aged orphan → edge gone, payload reclaimed, quota returned |
| `testAgedPublicEdgeAPublicRecordReferencesSurvivesTheSweep` | **the guard**: a real signed public commit referencing the blob, edge backdated a year, sweep collects nothing and bytes still serve |
| `testPublicEdgeInsideItsGracePeriodIsNotCollected` | a fresh upload survives long enough to be committed |
| `testPublicSweepNeverCollectsABlobAPermissionedRecordOwns` | a `space` edge disqualifies the CID |

Plus three supporting the staged half (`testExpiredStagedReferenceIsPurgedWithItsPayload`,
`testPromotedBlobSurvivesTheStagedSweep`, `testPreStagedSchemaUpgradePreservesExistingEdges`).

### Observed pre-fix failure

Measured against the unmodified tree before any change: exit 1, three failures,
every one an anonymous unauthenticated `GET /xrpc/com.atproto.sync.getBlob`
returning `200 OK` with the payload where `404` was asserted —

```
…testUploadedBlobIsNotAnonymouslyFetchableBeforeAPublicRecordReferencesIt]
  XCTAssertEqual failed: ("200 OK") is not equal to ("404 Not Found")
…testAbandonedUploadNeverBecomesAnonymouslyFetchable]
  XCTAssertEqual failed: ("200 OK") is not equal to ("404 Not Found")
…testSameCIDReuploadAfterPermissionedPromotionStaysPrivate]   (twice)
  XCTAssertEqual failed: ("200 OK") is not equal to ("404 Not Found")
```

The second assertion inside the re-upload test — "a promoted permissioned blob
is not anonymously readable" — **passed** pre-fix, independently confirming that
a successful promotion does remove the edge and that the exposure is
specifically the staging, abandonment, and re-upload windows.

### The test at `PermissionedBlobRepositoryReachabilityTests.swift:515-518`

It positively asserted `XCTAssertTrue(publicAfterReupload)` — that same-CID
re-upload restores anonymous reachability.

**My reading: it documents the mechanism, it does not assert a contract.** It is
a setup precondition for the assertion the test actually cares about, four lines
later: that a *second* permissioned write removes the recreated edge ("private
idempotency must not bypass staged public-reference cleanup"). The contract is
"a promotion is never bypassed".

- **As shipped** (staged half present) I **inverted** it, because re-upload now
  lands in `staged` and never restores public reachability. Leaving it would
  assert behaviour the code no longer has.
- **If the staged half is dropped**, the answer changes to **amend, not
  invert**: the assertion stays true — a re-upload does recreate the public edge
  — and the honest amendment is a comment recording that the edge is now bounded
  by the sweep, plus `testAgedPublicEdgeNoRecordReferencesIsCollected` as the
  companion proving the bound. I will make that change as part of the re-split.

---

## 6. Open decisions

1. **Keep or drop the staged half (`2cd5f8e0`)?** It is not a wire change (§2),
   so the profile/re-pin/client-migration cost the redirect weighed does not
   apply. What it does cost is the table rebuild and a promotion step in the
   public commit path, and what it decides is open question (b) — an upload no
   record references stops being anonymously fetchable. Note the premise for
   (b) in the program doc is wrong on the reference-PDS point (§1). **I need a
   yes/no; on "drop" I re-split so GC lands alone.**
2. **14-day grace period** — a value I chose, not derived. It is the whole
   safety margin for upload-then-commit-later.
3. **Retroactive cleanup is now automatic**, which is a change from my earlier
   report where I flagged it as needing your decision. Inherited edges are
   stamped at upgrade, so historical orphans are collected 14 days after
   deploy, not immediately. If you want them kept indefinitely, that is a
   one-line change to the backfill.

Not blocking, but worth a finding of its own: **deleting the last public record
that references a blob still leaves its public edge.** Pre-existing and
unchanged by this work — the sweep now bounds it at 14 days instead of forever,
which is an improvement, not a fix.

---

## 7. Results

All measured into `/private/tmp/swan-lane-sec-blob-namespace/`, which no other
lane writes to.

**macOS** — `xcrun --toolchain XcodeDefault swift build --build-tests`, then
`swift test --skip-build`:

```
exit 0
1500 passed   0 failed   9 skipped   11 targets
grep -c "Some test targets reported failures" → 0
```

Baseline 1489/0/9/11; delta is exactly the eleven new cases. Counts are XCTest
cases (`^Test Case .*' passed`), never summed `Executed N tests` lines.

An earlier attempt at this same run exited **143 (SIGTERM)** with 944 passed
across 7 of 11 targets and **zero** reported failures — a killed run that reads
as a clean smaller suite. It was discarded on the exit code, not on inspection.
That is the second time in this lane a truncated run looked green; the exit code
is the only reliable signal.

**Linux** — see §8.

### [corrected] Two errors in the earlier version of this report

- I wrote that "an amd64 build under QEMU on this host OOM-killed (exit 137)".
  **I never ran an amd64 build.** The exit-137 run was aarch64. And given the
  stray `docker kill` notice, SIGKILL was probably that kill, not memory
  pressure — my OOM diagnosis was unsupported either way.
- The withdrawn 1496/passing-Linux figures, per the note at the top.

---

## 8. Linux

`swift:6.1-jammy` pinned to the digest in the repo's own `Dockerfile:1`, with
the four system packages that Dockerfile installs
(`libsodium-dev pkg-config libsecret-1-dev libglib2.0-dev`), container named
`swan-blob`, run only after the macOS suite finished.

| Build | Result |
|---|---|
| `swift build` — every `Sources/` target plus the `swan` executable | **exit 0**, `Build complete! (451.07s)`, 0 errors |
| `swift build --target SwanHTTPTests` — the four new HTTP tests | **exit 0**, `Build of target: 'SwanHTTPTests' complete!`, 0 errors |
| `swift build --build-tests` — whole graph | **exit 1**, one pre-existing error |

The whole build produces **exactly one distinct error**, and it is neither mine
nor new:

```
Tests/SwanSQLiteTests/AccountPermanentDeletionSQLiteTests.swift:260:37:
  error: 'async' call cannot occur in a defer body
```

That line is `defer { try? await database.close() }`. Verified pre-existing:
`jj file show -r fc11540f` returns the identical line at the sealed parent, and
`jj diff --from fc11540f --to @` touches that file zero times. It is a Swift 6.1
language rule the macOS Xcode toolchain accepts and Linux does not. My own
SwanSQLite test file compiled inside the same module before it —
`[51/85] Compiling SwanSQLiteTests PermissionedBlobRepositoryReachabilityTests.swift`.

**Worth raising as its own finding: the Linux test target has not compiled on
this repo for some time, so `swift test` has never run on the deployment
platform.** That is a standing gap in the project's verification story, not
something this change introduced.

The bind-mount form in the original brief cannot work for this package, for the
reasons the lead has since confirmed: `Package.swift:25` is
`.package(path: "../Petrel")`, outside the mount, and SwiftPM's resource copy of
`Tests/SwanOAuthTests/Fixtures` fails across a macOS Docker bind mount with
`NSCocoaErrorDomain Code=512`. I tar both trees into the container instead.
`-j 2` is required: the default `-j 4` exhausts the 7.7 GiB Colima VM.

**Architecture is aarch64, not x86_64** — Colima on Apple Silicon. The failure
class this constraint exists to catch (Linux Foundation and
concurrency/`Sendable` divergence from Darwin) is architecture-independent, but
I did not build x86_64 and am not claiming I did.

### Reproducing

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel
docker build -t swan-linux-build:6.1-jammy - <<'EOF'
FROM swift:6.1-jammy@sha256:12be34a341945adb64914405ed7b568fcb2d35edbd63a3755007e47dce59456e
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      --no-install-recommends libsodium-dev pkg-config libsecret-1-dev libglib2.0-dev \
    && rm -rf /var/lib/apt/lists/*
EOF
docker run --rm --name swan-blob -v "$PWD":/ws:ro \
  -v /private/tmp/swan-lane-sec-blob-namespace/linuxwork:/work \
  swan-linux-build:6.1-jammy bash -c '
    set -e
    tar -C /ws --exclude=.build --exclude=.git --exclude=.jj -cf - \
      Swan-sec-blob-namespace Petrel | tar -C /work -xf -
    cd /work/Swan-sec-blob-namespace && swift build -j 2
  '
```

---

## 9. Constraints

| | |
|---|---|
| `swiftformat` | never run |
| Mutating git commands | none; `jj describe` / `jj new` only |
| Files deleted | none |
| Other workspaces touched | none |
| Indentation | 4-space throughout |
| Client-visible error bodies | unchanged — no new codes, no widened detail |
