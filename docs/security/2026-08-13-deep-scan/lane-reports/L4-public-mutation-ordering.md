# L4 — public-mutation-ordering

Closes **F26** and the answerable half of **F43**. Developed against `75e7b509`
and rebased onto **`29ce8202`**, the central fix for the `await`-in-`defer` site
that made `swift build --build-tests` impossible on Linux for every lane. Every
line citation below was read in this workspace, not carried over from the scan.

Files changed:

- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift`
- `Sources/SwanHTTP/SwanJSONWriteBody.swift`
- `Tests/SwanHTTPTests/PublicRepositoryMutationHTTPTests.swift`
- `Tests/SwanHTTPTests/PublicRouteSurfaceProfileSelectionTests.swift` — one
  expectation, outside the lane's original file list, edited on the team lead's
  explicit approval. See §4.

> **Client-visible change on a live federated route.** An anonymous or
> badly-credentialed request to `putRecord` / `createRecord` / `applyWrites` /
> `deleteRecord` is now answered **401** before its body is admitted or parsed,
> where a well-formed-but-wrong JSON envelope previously got **400**. No
> authenticated request changes status, and no error body was widened. Flagged
> here so it surfaces in merge review rather than only in a diff.

---

## 1. F26 — CONFIRMED, and the prescribed remedy was incomplete

### The finding as filed

Confirmed. Before this change `withPublicMutationInput` reserved a
`PublicRepositoryJSONWriteAdmission` lease and collected up to 1 MiB *before*
any authorization ran:

- `withAdmittedJSONWriteResponse` reserves first thing and holds the lease for
  the whole scope — `SwanJSONWriteBody.swift:329-333` post-change (`reserve`,
  then `defer { lease.release() }`), collecting at `:336-341` under
  `policy.totalBodyTimeout`. Unchanged by this lane; only its caller's ordering
  moved.
- Production policy is 30 seconds — `SwanJSONWriteBody.swift:13-15`.
- The pool is eight concurrent leases / 8 MiB — `PublicRepositoryReadDirectory.swift:710-720`,
  reserved at `:722-736`. At 1 MB per public mutation both dimensions bind at eight.
- `PublicRepositoryJSONWriteAdmission.processShared` (`:665`) is also the pool
  used by the AppView pipethrough (`SwanXRPCPipethrough.swift:152`), the
  permissioned space writes (`SwanSpaceXRPC.swift:351`), account email
  (`SwanAccountEmailXRPC.swift:352`), preferences (`SwanActorPreferencesXRPC.swift:121`)
  and the simple-space surface (`SwanSimpleSpaceXRPC.swift:26`).

I confirmed the load-bearing claim myself rather than taking it from the
program: `SwanOAuthResourceAuthorizer.authorize` reads only the `Authorization`
and `DPoP` headers, and its own doc comment says so —
`SwanOAuthResourceAuthorization.swift:71-75` ("Used solely for `Authorization`
and `DPoP` headers"), body of the method `:82-161`. Nothing in it touches
`request.body`. So the old order bought nothing.

### A trap the program's phrasing hides: authorize exactly once

The brief says "hoist the header-only OAuth/DPoP check ahead of
`withAdmittedJSONWriteResponse`" and "keep the repo/selector binding check at
`:338-342` where it is". Read literally — hoist a check, leave the existing
`authorizedTarget` call in the handlers — that is **broken**, and every public
write would 401.

`authorize` is not idempotent. It durably claims the DPoP proof's `jti`:
`OAuthDPoPProofValidator.validate` calls `tokenService.claimDPoP(jti:expiresAt:now:)`
and throws "DPoP proof was replayed" when the claim fails —
`Sources/SwanOAuth/OAuthProofValidation.swift:116-119`. A second `authorize`
for the same request is indistinguishable from a replay, and
`SwanOAuthResourceAuthorization.swift:296-304` maps it to `.denied`.

So the hoist had to be a **single-authorization refactor**, not an added check:

- New `authorizedPublicMutationSubject(request:path:capability:)`
  (`SwanPublicRepositoryMutationXRPC.swift:412-432`) performs the one
  header-only authorization and returns the subject. Its doc comment records
  the once-per-request requirement and cites the `jti` claim.
- `authorizedTarget` / `authorizedSubject` / `authorizedContext` are replaced by
  `mutationTarget(selector:subject:)` (`:351-360`), which keeps **only** the
  repo/selector binding and lifecycle predicate — the half that genuinely needs
  the decoded body — exactly where the brief asked for it to stay.
- `put`, `create`, `applyWrites` and `delete` now take `subject: String` instead
  of `request: Request`; `withPublicMutationInput` gained a `path:` parameter and
  passes the subject through to the operation closure (`:595-680`).
- Route paths are now derived as `"/xrpc/\(nsid)"` from the same NSID constants
  used to register the routes, instead of five hand-copied string literals, so
  the DPoP `htu` binding cannot drift from the registered path
  (`SwanPublicRouteSurfaceGating.swift:51` builds the route the same way).
- `uploadBlob` keeps its single pre-stream authorization and now calls the same
  helper (`:77-81`).

### The remedy as written does not actually close the denial

This is the substantive finding of the lane, and it is not in the scan or the
program.

`drainRejectedRequestBody` reserves from the pool it is handed —
`SwanJSONWriteBody.swift:275-278` — and although it reserves only one byte, the
reservation is still counted against the pool's **concurrency** dimension:
`reserve` guards `leases.count < maximumConcurrentWrites` before it checks bytes
(`PublicRepositoryReadDirectory.swift:726-735`). The drain runs under the same
30-second body deadline (`:281-290`).

So hoisting alone moves anonymous slow bodies from the entry side of
`processShared` to the exit side and the denial survives intact: eight refused
slow bodies hold all eight slots for 30 seconds, and authenticated writes and
the AppView pipethrough still get 503. A test that only asserted "the check
moved" would have passed over a live vulnerability.

The repository already contains the right answer for exactly this shape. The
loopback management listener keeps a **separate** drain pool and says why —
`PublicRepositoryReadDirectory.swift:673-680`: "Separate, deliberately small
capacity for draining unauthorized management request bodies. An unauthenticated
slow body can consume this pool, but it cannot reserve the pool used after
operator-secret authentication succeeds."

I mirrored that for the public write surface:
`publicMutationRejectedDrainAdmission` (`SwanJSONWriteBody.swift:230-263`), eight
concurrent, one byte per drain. All three public-surface drain sites now use it —
the JSON command path (`SwanPublicRepositoryMutationXRPC.swift:636-641`) and both
`uploadBlob` drains (`:65`, `:74`). Leaving `uploadBlob`'s drains on the shared
pool would have left the identical hole open one route over.

This is **not** the "dedicated pool instance" the brief called the weaker
fallback. That fallback was giving the *write* path its own pool while still
sharing with the pipethrough; the write path here still uses `processShared`,
which is what keeps the aggregate authenticated bound honest. What is isolated
is the pool for bodies that have *already been refused*.

Sizing: concurrency matches the write pool so a well-behaved client's rejected
command is no more likely to lose its keep-alive than an accepted command is to
be refused. The byte dimension is inert at one byte per drain.

One follow-up for whoever owns the merge: the drain pool is a file-level
constant rather than an injected dependency, because
`SwanPublicRepositoryMutationCapability.swift` and `SwanHTTP.swift` belong to
other lanes and this lane must not touch them. Threading it through the
capability beside `jsonWriteAdmission` — the way every other admission on this
surface is supplied — is the right shape once the lanes converge. It is a
mechanical change and nothing depends on the constant being global.

### The general lesson

**An admission control that drains its rejections through the pool it is
protecting is not a control.** The pool is emptied by whoever is refused, not by
whoever is admitted, so the refusal path re-acquires exactly the capacity the
admission path just denied. The hoist looks correct in isolation, the drain looks
correct in isolation, and the composition is a no-op. Worth checking in the other
admission lanes: any refusal path that "cleans up" through a shared limiter has
this shape, and a test asserting only that the check moved earlier will pass over
it. The distinguishing test is the one that keeps hostile traffic in flight and
demands the *legitimate* request still succeed.

### What happens when the isolated drain pool itself saturates

The failure mode this fix could introduce, stated explicitly because it borders
F05 (listener-slot exhaustion). It is bounded and does not leak a listener slot.

When `publicMutationRejectedDrainAdmission` has no capacity,
`drainRejectedRequestBody` does not wait: it calls `termination.terminate()` and
throws immediately (`SwanJSONWriteBody.swift:275-278`). That handle is
`SwanHTTPRequestContext.jsonWriteBodyTermination` (`SwanHTTP.swift:45-59`), which
hands the inbound body to `SwanJSONWriteBodyDrainHandler`. That handler discards
the remaining body at the channel level while the response is written, and
force-closes the channel 50 ms after the request deadline
(`SwanJSONWriteBodyDrainHandler.swift:79-96`); the fallback when the handler is
absent is `close(mode: .input)`. So the request is answered 503 without waiting
for its body, and the connection is either drained to completion or closed — it
is never left half-read pinning an accept slot.

This is the same path every pre-lease header rejection on this surface already
takes (`SwanPublicRepositoryMutationXRPC.swift:606`, `:613`), so it introduces no
new channel behaviour. The cost of saturation is a lost keep-alive on a request
that had already failed authorization.

Pinned by `testRejectedDrainRefusalTerminatesIncompleteBodyBoundedly`, which
holds every drain lease, sends an unauthenticated incomplete body against a
10-second body deadline, and requires the 503 to arrive in under one second.

### Client-visible change

An anonymous or badly-credentialed JSON command is now answered `401` (or a
nonce challenge) instead of `400`/`503`, before the body is parsed. No error
body was widened; the same `publicMutationResponse` cases are reused.

---

## 2. F43 — CONFIRMED; half shipped, half is a maintainer decision

### Confirmed

`uploadBlob` resolves the target and requires `status == .active` only in its
preflight (`SwanPublicRepositoryMutationXRPC.swift:82-87`), then streams up to
256 MiB (`:52`, `:111-138`) and adopts the blob with no further lifecycle check.
Adoption is a durable CAS write:
`SQLiteAccountDatabase.putStreaming` → `putBlobLocked`
(`Sources/SwanSQLite/SwanSQLite.swift:7127-7181`), inserting `blob_payloads` and
`blob_namespace_references` at `:7552-7572`.

### Shipped

After `putStreaming` returns, the target is re-resolved and re-checked
(`SwanPublicRepositoryMutationXRPC.swift:139-157`); a target that is missing, no
longer the authorized subject, or no longer `.active` throws
`PublicMutationFailure.notFound` → 404 `RepoNotFound`. A request that raced a
deactivation no longer certifies a usable blob.

The check is placed before the CID/namespace validation so no successful shape
of the response can be produced from a revoked lifecycle.

### Not shipped: `blobStore.remove(reference)`. `remove` is **not** refcount-aware.

The brief asked me to verify this before wiring it in. It does not hold, so I did
not ship the call.

How I established it — three independent pieces of evidence:

1. **Schema.** `blob_namespace_references` is
   `PRIMARY KEY(cid, namespace_kind, space_uri)` with columns `cid`,
   `namespace_kind`, `space_uri` and **no count column** —
   `Sources/SwanSQLite/SwanSQLite.swift:1041-1050`.
2. **Insert.** Adoption is
   `INSERT ... ON CONFLICT(cid, namespace_kind, space_uri) DO NOTHING` —
   `:7564-7572`. A second upload of identical bytes into the public namespace
   creates no second row and increments nothing. `admitBlobQuotaWithoutGate`
   confirms the intent: an already-present reference "contributes zero,
   preserving CAS dedup" (`:7593-7597`, `:7621-7641`).
3. **Delete.** `removeBlobReference` (`:7284-7345`) deletes that single row
   unconditionally (`:7295-7304`), then checks for *other namespaces* before
   deleting the payload (`:7305-7309`) and for *other logical CIDs* on the same
   physical file before unlinking (`:7320-7328`).

So `remove` is aware of cross-namespace and CAS-alias sharing, and blind to two
uploads of the same bytes into the *same* namespace. `Tests/SwanSQLiteTests/SwanSQLiteTests.swift:1966-1988`
pins exactly that: one `put(payload, namespace: .public)`, one
`remove(publicReference)`, and the public read is immediately `nil` while the
space reference survives.

The destructive path this creates is ordinary, not exotic. One account, one
database:

1. The account uploads image X and publishes a record referencing CID X.
2. Later the client re-uploads the identical bytes — a retry, a repost, the same
   avatar. Adoption dedups to the same row.
3. An operator deactivation lands mid-stream.
4. A `remove` here deletes the only public reference row for CID X. The
   already-published record's blob stops being servable, and if no other
   namespace holds the CID the payload and CAS file are reclaimed too.

Note the scan's own framing calls the blob "content-addressed and anonymously
retrievable by CID", i.e. the same property that makes removal look safe is what
makes it unsafe.

No safe removal is constructible from this lane's files. Knowing whether *this*
request created the row requires either a reference count on
`blob_namespace_references` or an upload-scoped provisional reference, both of
which live in `Sources/SwanSQLite/SwanSQLite.swift`. The record-reachability
predicate that would answer it,
`publicRepositoryContainsBlobCIDWithoutGate` (`SwanSQLite.swift:9921`), is
private to that module and not on any protocol reachable from `SwanHTTP`.

**Decision needed (§4 addition):** F43's reclamation half needs a refcounted or
upload-scoped reference in the SQLite blob store before it can land. Until then
a raced upload leaves orphan bytes, bounded by `AccountBlobQuota`
(`Sources/SwanStorage/SwanStorage.swift:23-26`). The program's F01 sweep — "a
sweep deleting aged public references whose CID fails
`publicRepositoryContainsBlobCIDWithoutGate` and has no space reference" — is
the correct owner of those bytes and reclaims them without needing to know which
request wrote them.

`AccountControlStore.swift:2436-2438`'s prohibition was honoured: no 256 MiB
stream is wrapped in the control write transaction. The re-check is a plain
directory read after the stream has completed.

---

## 3. Tests

Five tests added to `Tests/SwanHTTPTests/PublicRepositoryMutationHTTPTests.swift`.
The first four were written and run before the fixes.

**Observed pre-fix failures.** Re-established after review by restoring the
pre-fix `SwanPublicRepositoryMutationXRPC.swift` from `75e7b509` over the final
test file, rebuilding, and running the four tests — so this is the current test
code against the original production code, captured in
`/private/tmp/swan-lane-L4-public-mutation-ordering/pre-fix.log`. Line numbers
below are from that run and match the final file.

```
PublicRepositoryMutationHTTPTests.swift:748: error: testAuthenticatedWriteSucceedsWhileUnauthenticatedSlowBodiesAreInFlight :
  XCTAssertEqual failed: ("Snapshot(activeLeases: 2, reservedRequestBytes: 2000000)")
  is not equal to ("Snapshot(activeLeases: 0, reservedRequestBytes: 0)")
  - anonymous bodies must not hold the shared JSON write pool
PublicRepositoryMutationHTTPTests.swift:766: error: testAuthenticatedWriteSucceedsWhileUnauthenticatedSlowBodiesAreInFlight :
  XCTAssertEqual failed: ("503 Service Unavailable") is not equal to ("200 OK") - {"error":"temporarily_unavailable"}
PublicRepositoryMutationHTTPTests.swift:698: error: testUnauthenticatedJSONMutationIsDeniedWithoutReservingAWriteLease :
  XCTAssertEqual failed: ("503 Service Unavailable") is not equal to ("401 Unauthorized") - {"error":"temporarily_unavailable"}
PublicRepositoryMutationHTTPTests.swift:881: error: testUploadBlobRefusesAdoptionWhenAccountDeactivatesDuringStream :
  XCTAssertEqual failed: ("200 OK") is not equal to ("404 Not Found")
  - {"blob":{"$type":"blob","mimeType":"application/octet-stream","ref":{"$link":"bafkreigbbuwpq6myo4zjjpyfy43uc75glgoaiuzuidflvpg7asgmdxarii"},"size":12}}
PublicRepositoryMutationHTTPTests.swift:886: error: testUploadBlobRefusesAdoptionWhenAccountDeactivatesDuringStream :
  XCTAssertEqual failed: ("nil") is not equal to ("Optional("RepoNotFound")")
```

Three failed, one passed: `testInvalidAuthJSONMutationCompleteBodyPreservesKeepAliveForNextRequest`
passes against the pre-fix code too, which is the point of it — see below. Note
also the timing signature of the F26 reproduction: it takes **32.5 seconds**
against the pre-fix code, because the authenticated write sits waiting on a pool
the anonymous bodies own, and **0.086 seconds** after it.

- `testAuthenticatedWriteSucceedsWhileUnauthenticatedSlowBodiesAreInFlight` is
  the one that matters: two real anonymous sockets hold unfinished 1 MiB bodies
  against a two-slot write pool while an authenticated `createRecord` must still
  return 200. Readiness is polled on "the bodies reached *some* pool" so that the
  pool identity remains the assertion rather than the trigger.
- `testUnauthenticatedJSONMutationIsDeniedWithoutReservingAWriteLease` holds the
  only write lease externally; a 503 would prove the body was admitted first.
- `testUploadBlobRefusesAdoptionWhenAccountDeactivatesDuringStream` drives the
  lifecycle race through a status sequence on the test directory, and
  deliberately asserts that one `blob_namespace_references` row **remains** —
  pinning the residual above rather than papering over it.
- `testInvalidAuthJSONMutationCompleteBodyPreservesKeepAliveForNextRequest`
  **passed before the change as well**. It is a regression guard, not a
  reproduction: it holds the property that hoisting authorization must not turn
  a well-behaved client's rejected command into a connection reset, mirroring
  `testUploadBlobInvalidAuthCompleteBodyPreservesKeepAliveForNextRequest`.
- `testRejectedDrainRefusalTerminatesIncompleteBodyBoundedly` was added after
  review, to pin the failure mode the isolated drain pool introduces rather than
  asserting it in prose. Also a guard rather than a reproduction: the drain pool
  does not exist before the fix.

`executeUploadThenHealthOnSameConnection` was generalized into
`executeMutationThenHealthOnSameConnection(port:path:headers:body:)`; the
original name is kept as a thin wrapper so the two existing upload tests are
untouched.

**Post-fix, `PublicRepositoryMutationHTTPTests`:** exit 0, 25 passed, 0 failed
(`mutation-class-final.log`).

---

## 4. Suite and build results

**Evidence provenance.** An earlier version of this report quoted
"1491 passed / 2 failed" and "1492 passed / 1 failed" from logs written to the
shared `/private/tmp/claude-501/.../scratchpad/` directory, which all eight lanes
write to under colliding generic filenames. Those numbers are **withdrawn** — not
because they were shown to be another lane's, but because a clobbered log is
self-consistent and cannot be audited after the fact. Every number below was
re-established from `/private/tmp/swan-lane-L4-public-mutation-ordering/`, which
only this lane writes to. The F26/F43 code findings and the `:552` status change
are code readings and never depended on a log.

The same applies to the earlier Linux claim, with one correction that is mine
rather than the shared directory's. That claim was **not** produced by the
command in the lane brief — that command cannot run here, and this lane never
reported a result from it. It came from a corrected invocation of my own, but it
used a deps-preinstalled image another lane had built, and I did not check the
container's architecture. It was `aarch64`. Both problems are fixed below: stock
image, explicit `apt-get install`, named container — and the architecture is now
stated rather than glossed.

The pre-fix failures in §3 were also re-captured rather than quoted from the old
log, by restoring `SwanPublicRepositoryMutationXRPC.swift` from `75e7b509` over
the final test file and rebuilding.

**macOS full suite, on the rebased tree** — exit 0, **1495 passed / 0 failed /
9 skipped / 11 targets** (`suite-rebased.log`).

Before the rebase, the same suite was exit 0, **1494 passed / 0 failed /
9 skipped / 11 targets** on three consecutive runs (`suite-run1.log`,
`suite-run2.log`, `suite-run3.log`). Baseline at `75e7b509` was 1489 passed; this
lane adds 5 tests, and the extra case in the rebased count comes from the
commits `29ce8202` brought in, not from this lane.

**On the counting method**, since a broken recipe circulated: the pattern in the
lane briefs, `grep -c "Test Case '-\[.*\] passed"`, matches nothing — the real
line is `Test Case '-[Suite testName]' passed (0.0s)`, with a `'` between `]` and
` passed`. It returns 0 on every log in this lane's directory. I hit that on the
first run, treated a zero count as implausible rather than as a result, and
switched to `^Test Case '-\[.*\]' passed`. Cross-checked against the team lead's
corrected `^Test Case .* passed`: both give **1494** on all three pre-rebase runs and
**1495** on the rebased run, and both give **0** failures. The withdrawn 1491/1492 figures were produced with the
correct pattern too — they were withdrawn for log provenance, not for counting.

### The `:552` expectation, and why editing it was correct

`SwanHTTPTests.PublicRouteSurfaceProfileSelectionTests.testANarrowerProfileRemovesRealHandlersNotOnlyGates`
failed before the edit with
`XCTAssertEqual failed: ("401 Unauthorized") is not equal to ("400 Bad Request")`
at `Tests/SwanHTTPTests/PublicRouteSurfaceProfileSelectionTests.swift:552`. The
file is outside this lane's assigned list; the team lead approved the edit after
independently checking that the other three `.badRequest` assertions in that test
(`:541`, `:557`, `:563`) are GET probes on `getRecord` / `resolveHandle` and are
unaffected.

The probe posts an **anonymous** `{}` to `putRecord`. Its purpose is to prove a
live handler answered — 400 live / 404 absent / 503 gated — and 401 preserves
that discrimination exactly. No client can depend on the old status: every caller
who saw 400 there was unauthenticated and was going to be rejected regardless,
and `uploadBlob` on the same surface has always answered 401 at that point.

The comment was rewritten rather than just the expectation. The old text
explained the 400 as coming from "the route's own request validation before any
storage is consulted" — precisely the reasoning this change invalidates, and a
stale explanation beside a corrected expectation is how someone later "fixes" it
back. The new text states what the probe now relies on and names F26 so the
ordering is not silently reverted.

### The OAuth transport failure — observed once, cause indeterminate

Recorded for whoever owns `Sources/SwanOAuth/`. This lane cannot fix it, does not
claim it is benign, and **offers no reproduction count**, because the only
observation came from a window in which the environment was demonstrably unsound.

- Exact failure:
  `Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:141: error: -[SwanOAuthTests.NIOPeerPinnedOAuthPostTransportTests testDocumentTransportTimeoutCompletesAndClosesUnresponsivePeer] : failed: caught error: "I/O on closed channel"`
- **Observed once. Cause indeterminate.** During that window the Docker VM was
  out of disk (one lane's build died at `ld.gold` with ENOSPC), an image-wide
  `docker kill` took down containers belonging to lanes that had not issued it,
  and the shared log directory was being clobbered between lanes. Any
  re-run or non-reproduction from that window is discarded rather than counted:
  a number I cannot source is worse than no number.
- What can be sourced: it did not appear in the clean full-suite runs recorded
  above. That is stated as an observation, not as evidence of absence — a
  load-sensitive timeout test is exactly what an unsound machine perturbs in
  both directions.
- This lane modifies no OAuth code. Its source-side files are
  `SwanHTTP/SwanPublicRepositoryMutationXRPC.swift` and
  `SwanHTTP/SwanJSONWriteBody.swift`, plus two `SwanHTTPTests` files; nothing in
  `SwanOAuth`, and nothing in any NIO transport or channel-lifecycle code.
- Why it should not be closed as a flake: an intermittent "I/O on closed channel"
  in a *timeout* test is the shape of a real channel-lifecycle race — a close
  racing an in-flight write — and that is the behaviour the test exists to pin.
  Handing this to the file's owner rather than dismissing it.

**Linux — `swift:6.1-jammy`, `aarch64`, log `linux-final.log`.**

State the architecture plainly: `swift:6.1-jammy` resolves to **arm64** on this
Apple Silicon host, so **this is not a build on the x86_64 deployment target**.
Nobody should read "Linux verified" in this report as "verified on the deployment
architecture". The team lead is running one `--platform linux/amd64` build of the
merged result as a merge gate; a per-lane emulated build is not worth the cycle
time, and the one this lane started was killed for that reason. (It left two QEMU
core dumps, 300 MB, in the workspace root — moved out to
`/private/tmp/swan-lane-L4-public-mutation-ordering/killed-qemu-cores/` rather
than committed or deleted.)

What arm64 Linux does buy is the thing that actually separates Linux from macOS
for this change: Foundation/Glibc differences, `Sendable` and strict-concurrency
diagnostics that differ by toolchain, and platform-conditional code. Swift 6.1
here is also stricter than the local 6.2 — which is exactly what caught the
`await`-in-`defer` break.

- `swift build --build-tests` (whole package) → **exit LINUX_FINAL_PLACEHOLDER**.

This is the first run on which the whole-package command could succeed at all.
Until `29ce8202`, `Tests/SwanSQLiteTests/AccountPermanentDeletionSQLiteTests.swift:260`
was the only one of ~140 `await`-in-`defer` sites in the repository missing its
`Task { }` wrapper; macOS accepts an async call in a defer body and Swift 6.1 on
Linux does not, so `--build-tests` could not compile on Linux for **any** lane on
**any** branch, including the sealed base. This lane's stack is rebased onto that
fix. An earlier `NSCocoaErrorDomain Code=512` resource-copy failure for
`Tests/SwanOAuthTests/Fixtures` also disappeared once the scratch path moved
inside the bind mount.

Mechanical notes for whoever repeats this — the Linux command distributed with
the lane briefs cannot work as written, and six separate things had to be fixed:

1. `Package.swift:25` is `.package(path: "../Petrel")`, outside the bind mount.
   The dependency has to be mounted too, at a path where `<workspace>/../Petrel`
   resolves to it — `/workspace/Swan` + `/workspace/Petrel` is the clearest form.
2. The stock `swift:6.1-jammy` image lacks `libsecret-1-dev`, `pkg-config`,
   `libsodium-dev` and `libglib2.0-dev`; without them the build dies in
   `Petrel/Sources/CLibSecretShim/shim.c:2`.
3. Docker Desktop on this machine does not share `/private/tmp`. A mount from
   there appears as an **empty directory** inside the container rather than
   failing — a snapshot of Petrel mounted that way silently produced
   "`/Petrel/Package.swift` doesn't exist", and a mounted shell script appeared
   as a directory. Anything a container must read has to live under `/Users`.
4. The Linux build rewrites `Package.resolved` (SwiftPM 6.1 drops
   `swift-configuration`). Restored with `jj restore Package.resolved`; it is
   not part of this lane's diff. Use `--scratch-path` and never let a Linux
   container build into `.build` while a macOS `swift test` is running against
   the same directory.
5. The default image is `aarch64` on Apple Silicon. `--platform linux/amd64`
   would be required to validate the deployed architecture; under QEMU it is
   slow enough that the merged result is the right place to do it once, and a
   killed emulated build drops multi-hundred-megabyte core dumps into the
   workspace root that jj will refuse to snapshot.
6. Keep the container's workspace path stable across runs and put
   `--scratch-path` inside the bind mount; a scratch path in the container's own
   `/tmp` rebuilds everything each time and made SwiftPM fail to stage test
   resources.

Containers were named (`--name swan-L4`) so no other lane's
`docker kill $(docker ps -q --filter ancestor=swift:6.1-jammy)` can take them
down, and so this lane can never take down another's.

---

## 5. Rejected

- **A dedicated write pool for public mutations.** The brief's stated fallback.
  Rejected: it does not need to be taken, because the hoist is possible, and it
  would weaken the aggregate authenticated bound.
- **Removing the adopted blob on a lost lifecycle race.** See §2.
- **Reordering the DPoP `jti` claim.** Hoisting authorization also hoists the
  durable `jti` claim ahead of body collection. This is not a new exposure: the
  claim was always reachable by any caller willing to send a complete small
  body, and it is now reached slightly earlier by the same callers. It is the
  same shape as F06 on a different route and belongs to L3, not here.
- **Draining without a lease.** Would remove a deliberate, documented control
  (`SwanJSONWriteBody.swift:271-274`) and would also change the management
  listener's behaviour, whose drain path shares the helper.
