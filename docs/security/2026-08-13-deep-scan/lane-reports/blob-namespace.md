# F01 — permissioned blob namespace leak

Cluster: `C1-permissioned-blob-namespace` · finding `csf_0feb001d0f16298db4902b47` · HIGH ·
`permissioned-data-disclosure`

Workspace: `Swan-sec-blob-namespace`, based on `fc11540f4d3e`.

---

## 1. Verdict: CONFIRMED

The claim holds against the source, and it holds empirically — three tests written
against the unmodified tree fail by serving bytes that should not have been
reachable. This is not a paper finding.

### The four links in the chain, at `fc11540f4d3e`

**(a) The only authenticated upload route hard-codes the public namespace.**
`Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:109-112` calls
`blobStore.putStreaming(namespace: .public, …)`, and
`:137` then asserts `guard case .public = reference.namespace`. There is no
parameter, header, or query value by which a caller could ask for anything else.

**(b) That immediately creates a durable public edge.**
`Sources/SwanSQLite/SwanSQLite.swift:7564-7572` (`putBlobLocked`) inserts
`blob_namespace_references(cid, namespace_kind, space_uri)` with
`namespace_kind = 'public'` inside the same transaction that records the payload.
The row is durable the moment the upload response is written.

**(c) Anonymous `com.atproto.sync.getBlob` serves anything with that edge.**
`Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift:903-942` resolves the DID,
calls `publicBlobMetadata(cid:)`, then `publicBlob(cid:)`. Both land in
`publicBlobMetadataIfReachable` (`SwanSQLite.swift:7925-7978`), whose entire
admission test is

```sql
FROM blob_payloads JOIN blob_namespace_references USING(cid)
WHERE blob_payloads.cid = ? AND namespace_kind = ? AND space_uri = ?
```

with `namespace_kind = 'public'`. There is no repository-record reachability
check anywhere on this path — deliberately, per the comment at
`SwanPublicRepositoryReadXRPC.swift:836-838` ("a blob is content-addressed and
carries no MST revision, so it stays out of the admission machinery").

**(d) The edge is removed only inside a *successful* permissioned commit.**
`promotePermissionedBlobReferences` (`SwanSQLite.swift:9895-9975`), reached only
from `apply(space:author:…)` at `:3498`, deletes the public edge at `:9934-9940`
and only when `publicRepositoryContainsBlobCIDWithoutGate` says no public record
justifies it. Anything that prevents that transaction from committing — validation
failure, quota rejection, revision CAS conflict, connection loss, process death,
or a user who simply never posts — leaves the public edge in place with no expiry
and no sweeper. `grep` finds no staged-edge reaper of any kind in the tree.

### Does a permissioned upload share the public upload route?

**Yes, and this is the whole finding.** There is exactly one `uploadBlob` HTTP
handler in the tree (`SwanPublicRepositoryMutationXRPC.swift:48`, registered at
`:512`); the only other hits for the NSID are the interop *client* and the
unavailable-route stub. Permissioned blobs have their own authenticated *read*
route — `com.atproto.space.getBlob` in `Sources/SwanHTTP/SwanSpaceBlobXRPC.swift`
— but **no** corresponding write route. `Sources/SwanInterop/LiveInterop.swift:1657`
confirms this from the client side: `uploadPermissionedBlob` posts to
`/xrpc/com.atproto.repo.uploadBlob`, the same path as `uploadPublicBlob` at
`:1598`.

So a client attaching an image to a permissioned-space record has no way to
express that intent at upload time, and the server has no way to infer it. Every
such blob is published to the anonymous namespace first and privatised later, if
at all.

### On the existing test

`Tests/SwanSQLiteTests/PermissionedBlobRepositoryReachabilityTests.swift:511-518`
(pre-fix) uploads a payload, promotes it into a space, re-uploads the identical
payload, and asserts `XCTAssertTrue(publicAfterReupload)`.

**That assertion documents the bug; it does not assert a contract.** It is a
setup precondition for the assertion the test actually cares about, at `:529`:
that a *second* permissioned write removes the recreated edge ("private
idempotency must not bypass staged public-reference cleanup"). The contract is
"a promotion is never bypassed". The `XCTAssertTrue` is the author writing down
the mechanism they had to defend against, not a behaviour anyone wanted. It is
also the sharpest available evidence for the finding: the repository's own tests
state that re-uploading identical bytes restores anonymous reachability, and that
nothing removes it again until some unrelated later write happens to run.

I retargeted that test rather than deleting it (§4).

### What the scan slightly overstates

The scan's likelihood text says exploitation needs "CID knowledge or derivation".
That is right, and it is the only thing standing between this and trivial
exploitation — `getBlob` takes a raw CID and CIDs are not enumerable from any
Swan surface I could find. The severity is carried by the invariant, not by
discoverability: a PDS that offers permissioned spaces is claiming those bytes
are not public, and a SHA-256 preimage of *known or low-entropy content* is not a
secret. I agree with HIGH, on that basis rather than on ease of discovery.

---

## 2. Design

### Chosen: staged upload namespace, promoted inside the commit

`BlobNamespace` gains a third case, `.staged`
(`Sources/SwanStorage/SwanStorage.swift:6-25`), backed by
`namespace_kind = 'staged'` in `blob_namespace_references`.

- `uploadBlob` writes `.staged`
  (`SwanPublicRepositoryMutationXRPC.swift:110-120`, guard at `:147`).
- Anonymous `sync.getBlob` is **completely unchanged** — it still reads only
  `namespace_kind = 'public'`. The read path stays exactly as narrow as it was;
  it simply stops finding uploads there.
- A validated public record commit promotes staged → public, atomically, inside
  the commit transaction:
  `promoteValidatedPublicBlobReferencesWithoutGate`
  (`Sources/SwanSQLite/PublicRepositoryStore.swift:754-828`), called from
  `applyPublicRepositoryMutation` at `:531`. This is the same statement that
  already re-checked reachability under the storage serialization boundary, so
  the promotion inherits its fencing against a concurrent permissioned write.
- A permissioned record commit consumes the staged edge unconditionally and adds
  the space edge (`SwanSQLite.swift:10133-…`, in `promotePermissionedBlobReferences`).
- The authenticated mutation surface validates a record's declared
  `size`/`mimeType` against `uploadedBlobMetadata(cid:)`
  (`SwanSQLite.swift:7440`), which reads public-or-staged. This is a new method
  on `StreamingBlobStore` and is deliberately **not** on
  `PublicRepositoryReadBlobStore` — that protocol is the one-method allow-list
  the anonymous route is handed, and widening it would reintroduce the hole from
  the other end.
- Abandoned staged edges expire (§3).

This matches the reference implementation. Upstream `atproto`'s PDS stores an
upload under a temp key (`packages/pds/src/actor-store/blob/transactor.ts:62`,
`putTemp`) and only calls `makePermanent` (`:278`) when a record commit
references it, so `sync.getBlob` on an uncommitted upload fails there too.
Swan diverged from the protocol's own behaviour, not just from its stated
invariant.

### Why the alternatives lost

**Record-reachability check on the anonymous read.** The obvious "fix the sink"
approach — make `sync.getBlob` serve only blobs some validated public record
references — is what upstream effectively does, and it would close all three
exposure windows without a new namespace. I rejected it on cost: the only
existing "does a public record reference this CID" query is
`publicRepositoryContainsBlobCIDWithoutGate`
(`Sources/SwanSQLite/PublicRepositoryReadStore.swift:163-239`), which keyset-pages
the entire record index, decodes every record block, and extracts every blob link.
Running that per anonymous image request converts the network-facing avatar path
into a full repository scan — a DoS handed to unauthenticated callers. Making it
cheap means a `record_blob` index plus a **backfill over the live account's
existing records**, which is a far more dangerous migration than the one I wrote:
get the backfill wrong and every image the deployed instance serves goes dark.

**A separate `blob_staging` table** (avoids touching the `CHECK` constraint, so no
table rebuild). Rejected because it forks every invariant that currently works
uniformly over one edge table: the payload-GC "any references left?" test
(`SwanSQLite.swift:7305-7309`), quota admission
(`admitBlobQuotaWithoutGate`), and the portable-export inventory would each need a
second branch. Quota is the dangerous one — staged edges that don't count against
`AccountBlobQuota.maximumReferences` are precisely the "new unbounded durable
ledger" this task warns against. One rebuild of a small index table costs less
than three permanently forked code paths.

### The coexistence question

Edges are keyed `(cid, namespace_kind, space_uri)` within a **single per-account**
database, and the CAS file path is namespaced by `SHA256(accountDID)`
(`SwanSQLite.swift:9813-9815`), so two accounts uploading identical bytes share
neither an edge table nor a physical file. Cross-account dedup does not exist and
nothing here changes that.

Within one account, `public`, `space`, and `staged` edges for one CID coexist
freely. Removing one leaves the payload alive while any edge remains; the payload
row and the CAS file are reclaimed only when the last edge goes
(`removeBlobReference`, `SwanSQLite.swift:7305-7333`), under the per-digest
lifecycle lock with the existing crash-safe `reclaiming` intent. The staged sweep
reuses `removeBlobReference` rather than deleting rows directly, precisely so it
inherits all of that.

Ordering matters in both promotion paths, and both delete the staged edge
**before** admitting quota for the new one, so a promotion never transiently
charges the account for two edges and can never fail a commit that was already
within quota at upload time.

---

## 3. Expiry — what drives it, and what if nothing does

`purgeExpiredStagedBlobReferences(now:)` (`SwanSQLite.swift:7470`) deletes staged
edges older than `stagedBlobReferenceLifetimeSeconds` (**7 days**), at most
`maximumStagedBlobReferencePurge` (**64**) per sweep, and reclaims any payload the
expired edge was the last reference to.

Two drivers, both request-path, **no new background service**:

1. **Every account database open** — the migration/recovery block in `init`
   (`SwanSQLite.swift:1919-1920`) and `migrate()`.
2. **Immediately before every new staged upload**
   (`putStreaming`, `SwanSQLite.swift:7269-7274`). The account generating staging
   pressure is the one that clears it, and sweeping *before* quota admission means
   an expired edge cannot hold that account at its reference ceiling.

**If neither ever runs again**, the residue is bounded and non-confidential: a
staged edge is never anonymously reachable, and
`AccountBlobQuota.maximumReferences` (10 000, conservative default) caps how many
can exist. A missing sweep degrades to a storage-quota cost, never to disclosure.
That is the property I was aiming for — staging must not be able to become the
kind of unbounded durable ledger this scan flags elsewhere.

Re-staging an already-staged CID **refreshes** its timer
(`putBlobLocked`, the `DO UPDATE SET staged_at = excluded.staged_at WHERE
excluded.staged_at IS NOT NULL` clause). A second upload is an equally unclaimed
fresh intent, and restarting a timer can never widen reachability. The `WHERE`
clause is what keeps a committed `public`/`space` row untouched.

---

## 4. Tests

Seven new cases. Four are the ones this task specified; three cover machinery the
fix introduces and that I would otherwise only be asserting in prose.

### The four required (HTTP level, `Tests/SwanHTTPTests/PublicRepositoryMutationHTTPTests.swift`)

These drive real `com.atproto.repo.uploadBlob`, `com.atproto.repo.createRecord`,
and `com.atproto.sync.getBlob` requests through the fixture that registers both
the mutation and read surfaces — the same route registration production uses, not
a storage-layer stand-in.

| Test | Asserts |
|---|---|
| `testUploadedBlobIsNotAnonymouslyFetchableBeforeAPublicRecordReferencesIt` | upload → `getBlob` is 404 |
| `testAbandonedUploadNeverBecomesAnonymouslyFetchable` | upload → `createRecord` rejected (declared size ≠ stored size) → `getBlob` still 404 |
| `testSameCIDReuploadAfterPermissionedPromotionStaysPrivate` | upload → permissioned `apply` → re-upload identical bytes → 404 at every step |
| `testUploadedBlobIsAnonymouslyFetchableOnceAPublicRecordReferencesIt` | **regression guard**: upload → `createRecord` accepted → `getBlob` 200 with exact bytes and `content-length` |

### Three supporting (`Tests/SwanSQLiteTests/PermissionedBlobRepositoryReachabilityTests.swift`)

- `testExpiredStagedReferenceIsPurgedWithItsPayload` — backdates `staged_at`
  through a direct SQLite connection, sweeps, asserts the edge *and* the payload
  row are gone and that an unexpired sibling edge is untouched.
- `testPromotedBlobSurvivesTheStagedSweep` — a promoted blob has nothing left to
  sweep and stays readable through `permissionedBlob`.
- `testPreStagedSchemaUpgradePreservesExistingEdges` — rewrites the reference
  table into its pre-v15 shape *with the v15 marker still present*, reopens, and
  asserts every existing edge keeps its exact kind, the already-public blob is
  still served, and a staged upload now works.

### Retargeted

`testRepeatedPrivatePromotionRemovesRecreatedPublicStagingReference` →
`testRepeatedPrivatePromotionNeverPublishesARecreatedStagedReference`. Both
uploads now use `.staged` (what the HTTP route actually does), and the
`XCTAssertTrue(publicAfterReupload)` that documented the defect is now
`XCTAssertFalse`. I kept the case and its history rather than deleting it — the
contract it was reaching for is still the right one; it is now enforced at the
upload instead of repaired afterwards.

### Observed pre-fix failure

Built and run against the unmodified tree. Exit 1, **1490 passed, 3 failed**
(1489 baseline + the one guard case that correctly passed before the fix):

```
PublicRepositoryMutationHTTPTests.swift:1015: error: -[… testUploadedBlobIsNotAnonymouslyFetchableBeforeAPublicRecordReferencesIt]
  XCTAssertEqual failed: ("200 OK") is not equal to ("404 Not Found")
  - an uploaded blob must not be anonymously readable before a public record references it

PublicRepositoryMutationHTTPTests.swift:1081: error: -[… testAbandonedUploadNeverBecomesAnonymouslyFetchable]
  XCTAssertEqual failed: ("200 OK") is not equal to ("404 Not Found")
  - a rejected apply must not leave a durable public edge

PublicRepositoryMutationHTTPTests.swift:1149: error: -[… testSameCIDReuploadAfterPermissionedPromotionStaysPrivate]
  XCTAssertEqual failed: ("200 OK") is not equal to ("404 Not Found")
  - a staged upload is never anonymously readable

PublicRepositoryMutationHTTPTests.swift:1149: error: -[… testSameCIDReuploadAfterPermissionedPromotionStaysPrivate]
  XCTAssertEqual failed: ("200 OK") is not equal to ("404 Not Found")
  - re-uploading identical bytes must not restore anonymous reachability
```

Every failure is the same shape: an anonymous, unauthenticated `GET
/xrpc/com.atproto.sync.getBlob` returned `200 OK` with the payload. Note the
*second* assertion inside `testSameCIDReupload…` — "a promoted permissioned blob
is not anonymously readable" — **passed** pre-fix, which independently confirms
the scan's account that a successful promotion does remove the edge and that the
exposure is specifically the staging, abandonment, and re-upload windows.

---

## 5. Migration

**A migration is required.** `blob_namespace_references.namespace_kind` carries
`CHECK(namespace_kind IN ('public', 'space'))`, and SQLite cannot replace a CHECK
in place, so an existing database rejects every `staged` insert until the table is
rebuilt.

`migrateStagedBlobNamespaceIfNeeded` (`SwanSQLite.swift:2822`), version **15**,
follows the repository's existing pattern exactly — the same rename / recreate /
copy / drop shape as `migrateSpaceNotificationReceiptScopeIfNeeded` (version 7),
with the marker recorded in `permissioned_repository_migrations` and the call
placed in `migrateWithoutGate()` alongside the other fourteen.

### Effect on the deployed database (one real account, real rows)

- **Rebuild**: rename to `blob_namespace_references_v14`, create the widened table
  (kind now allows `staged`, plus a nullable `staged_at`), `INSERT … SELECT cid,
  namespace_kind, space_uri, NULL`, drop the old table, create the partial index.
- **No existing row changes meaning.** Every committed row is `public` or `space`
  and stays exactly that with `staged_at` NULL. Both new CHECKs are satisfied by
  every pre-existing row by construction.
- **Nothing the account currently serves stops being served.** A public edge
  survives verbatim, so `sync.getBlob` answers identically the instant after the
  upgrade. This is asserted by `testPreStagedSchemaUpgradePreservesExistingEdges`.
- **No blob bytes move.** The table is a per-account reference index bounded by
  `AccountBlobQuota.maximumReferences`; the payload store and the CAS files are
  untouched.
- Runs inside the existing single migration transaction, so a crash mid-upgrade
  rolls back to the v14 shape and retries on next open.

Two robustness notes I hit and fixed rather than papered over:

1. The migration is driven by the **observed table shape** (`PRAGMA table_info`
   for `staged_at`), not by the marker alone. A restored or repaired database can
   carry a marker for a shape it does not have, and a reference table without
   `staged_at` fails *every upload*. `testPreV4BlobSchemaRestartDefersLegacyBodyMaterialization`
   caught exactly this and is the reason the check is shape-first. The marker now
   only records that the work was done.
2. The partial index is created **by the migration, not by the base schema
   statement list**. A pre-v15 database still has a table without `staged_at` when
   those statements run, and `CREATE INDEX … (staged_at)` would fail the whole
   schema transaction.

---

## 6. Results

**macOS** — `xcrun --toolchain XcodeDefault swift build --build-tests`, then
`swift test --skip-build`:

```
exit 0
1496 passed   0 failed   9 skipped   11 targets
grep -c "Some test targets reported failures" → 0
```

Baseline was 1489 / 0 / 9 / 11. Delta is exactly the seven new cases; no
pre-existing test changed status.

**Linux** — `swift:6.1-jammy`, pinned to the exact digest in the repo's own
`Dockerfile:1`, with the same four system packages that Dockerfile installs
(`libsodium-dev pkg-config libsecret-1-dev libglib2.0-dev`):

| Build | Result |
|---|---|
| `swift build` — every `Sources/` target plus the `swan` executable | **exit 0**, `Build complete!`, 0 errors |
| `swift build --target SwanHTTPTests` — the four new HTTP tests | **exit 0**, `Build of target: 'SwanHTTPTests' complete!` |
| `swift build --build-tests` — whole graph | **exit 1**, one pre-existing error (below) |

The single Linux error is **not mine and not new**:

```
Tests/SwanSQLiteTests/AccountPermanentDeletionSQLiteTests.swift:260:37:
  error: 'async' call cannot occur in a defer body
```

That is `defer { try? await database.close() }`. It is byte-identical at the
sealed parent `fc11540f` (`jj file show -r fc11540f`), is in a file this change
does not touch, and is a Swift 6.1 language rule the macOS Xcode toolchain accepts
and Linux does not. My own SwanSQLite test file compiled fine inside the same
module — `[3778/3833] Compiling SwanSQLiteTests PermissionedBlobRepositoryReachabilityTests.swift`
— before the module hit that error. Worth raising as its own finding: the Linux
test target has not compiled on this repo for some time, so **`swift test` has
never run on the deployment platform.**

Two caveats stated plainly:

- **Architecture is aarch64, not x86_64.** The Docker host here is Colima on
  Apple Silicon (4 CPUs / 7.7 GiB). The failure class this constraint exists to
  catch — Linux Foundation and Swift-concurrency/`Sendable` divergence from Darwin
  — is architecture-independent, but I did not build x86_64 and am not claiming I
  did. An amd64 build under QEMU on this host OOM-killed (exit 137).
- The bind-mount form in the task (`-v "$PWD":/src -w /src`) cannot work for this
  package: `Package.swift:25` declares `.package(path: "../Petrel")`, outside the
  mount, and SwiftPM's resource copy of `Tests/SwanOAuthTests/Fixtures` fails
  across a macOS Docker bind mount with `NSCocoaErrorDomain Code=512`. I tar the
  sources into the container instead. Worth fixing in the task's standing
  instructions.

---

## 7. Residual — one decision for the maintainer

**Pre-existing orphaned public edges on the deployed instance are not
retroactively revoked, and I did not do that unattended.**

The fix stops all *new* exposure. It does not go back and delete public edges
created before the upgrade for blobs that were uploaded and never committed to a
public record — including any that a permissioned record already owns and whose
edge a later permissioned write has not yet repaired. Those rows survive the
migration verbatim and remain anonymously fetchable by CID.

I chose not to clean them in the migration. The cleanup is expressible — walk
`publicRepositoryBlobCIDs()` and delete any `public` edge it does not justify,
which is exactly the authority `promotePermissionedBlobReferences` already trusts
for this decision — but it deletes *serving* edges on a live federated PDS, during
a schema migration, unattended, with a projection that can throw
`resourceLimitExceeded` on a large repository. Getting it wrong takes images
offline for the whole network. That is a supervised operator action, not a startup
side effect.

**What I need from you:** whether to add that reconciliation, and if so whether it
should be an operator-invoked one-shot or wired into startup. Until then, the
existing repair still runs opportunistically — any permissioned write touching a
CID removes a public edge no public record justifies
(`promotePermissionedBlobReferences`).

The inventory query for deciding is small on a one-account instance:

```sql
SELECT cid FROM blob_namespace_references WHERE namespace_kind = 'public';
```

cross-referenced against the CIDs reachable from `public_repository_record_index`.

Two smaller notes, neither blocking:

- **The 7-day staged lifetime is a tunable I picked, not a derived value.**
  `stagedBlobReferenceLifetimeSeconds`. It trades composer-draft tolerance against
  storage residue; expiry is idempotent to recover from (the client re-uploads,
  and CAS makes that free), so the cost of being wrong is low in both directions.
- **Deleting the last public record that references a blob still leaves its public
  edge.** Pre-existing behaviour, unchanged by this work, and out of scope — but
  it is the same class of defect (an edge outliving its justification) and worth a
  finding of its own.

---

## 8. Verification appendix

| Item | Result |
|---|---|
| Pre-fix run (new tests, unmodified source) | exit 1 · 1490 passed · 3 failed |
| Post-fix macOS suite | exit 0 · 1496 passed · 0 failed · 9 skipped · 11 targets |
| `Some test targets reported failures` in post-fix log | 0 occurrences |
| Linux `swift build` (sources + `swan` product) | exit 0 · 0 errors |
| Linux `swift build --target SwanHTTPTests` | exit 0 |
| Linux `swift build --build-tests` | exit 1 · one pre-existing error at `AccountPermanentDeletionSQLiteTests.swift:260`, identical at `fc11540f` |
| Linux architecture actually built | aarch64, **not** x86_64 (see §6) |
| `swiftformat` | never run |
| Mutating git commands | none; committed with `jj describe` / `jj new` |
| Files deleted | none |

### Reproducing the Linux build

```bash
cd /Users/joshlacalamito/Developer/Catbird+Petrel
docker build -t swan-linux-build:6.1-jammy - <<'EOF'
FROM swift:6.1-jammy@sha256:12be34a341945adb64914405ed7b568fcb2d35edbd63a3755007e47dce59456e
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      --no-install-recommends libsodium-dev pkg-config libsecret-1-dev libglib2.0-dev \
    && rm -rf /var/lib/apt/lists/*
EOF
docker run --rm -v "$PWD":/ws:ro -v /some/writable/host/dir:/work \
  swan-linux-build:6.1-jammy bash -c '
    set -e
    tar -C /ws --exclude=.build --exclude=.git --exclude=.jj -cf - \
      Swan-sec-blob-namespace Petrel | tar -C /work -xf -
    cd /work/Swan-sec-blob-namespace && swift build -j 2
  '
```

`-j 2` matters: the default `-j 4` OOM-kills (exit 137) in a 7.7 GiB VM.
