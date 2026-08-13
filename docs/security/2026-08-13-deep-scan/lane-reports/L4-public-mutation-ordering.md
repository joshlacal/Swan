# L4 — public-mutation-ordering

Closes **F26** and the answerable half of **F43**. Verified against the tree at
`75e7b509`. Every line citation below was read in this workspace, not carried
over from the scan.

Files changed:

- `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift`
- `Sources/SwanHTTP/SwanJSONWriteBody.swift`
- `Tests/SwanHTTPTests/PublicRepositoryMutationHTTPTests.swift`

---

## 1. F26 — CONFIRMED, and the prescribed remedy was incomplete

### The finding as filed

Confirmed. Before this change `withPublicMutationInput` reserved a
`PublicRepositoryJSONWriteAdmission` lease and collected up to 1 MiB *before*
any authorization ran:

- `withAdmittedJSONWriteResponse` reserves first thing and holds the lease for
  the whole scope — `SwanJSONWriteBody.swift:293-297` (`reserve`, then
  `defer { lease.release() }`), collecting at `:300-305` under
  `policy.totalBodyTimeout`.
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
  (`SwanPublicRepositoryMutationXRPC.swift:412-437`) performs the one
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
`SwanJSONWriteBody.swift:240-244` — and although it reserves only one byte, the
reservation is still counted against the pool's **concurrency** dimension:
`reserve` guards `leases.count < maximumConcurrentWrites` before it checks bytes
(`PublicRepositoryReadDirectory.swift:726-735`). The drain runs under the same
30-second body deadline (`:246-254`).

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
`publicMutationRejectedDrainAdmission` (`SwanJSONWriteBody.swift:230-253`), eight
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
be refused. The byte dimension is inert at one byte per drain. A refusal
terminates the connection, which is the correct outcome for a request that has
already failed authorization.

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
(`SwanPublicRepositoryMutationXRPC.swift:141-157`); a target that is missing, no
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

Four tests added to `Tests/SwanHTTPTests/PublicRepositoryMutationHTTPTests.swift`.
Written and run before the fixes.

**Observed pre-fix failures** (`swift test --skip-build --filter PublicRepositoryMutationHTTPTests/...`):

```
PublicRepositoryMutationHTTPTests.swift:748: error: testAuthenticatedWriteSucceedsWhileUnauthenticatedSlowBodiesAreInFlight :
  XCTAssertEqual failed: ("Snapshot(activeLeases: 2, reservedRequestBytes: 2000000)")
  is not equal to ("Snapshot(activeLeases: 0, reservedRequestBytes: 0)")
  - anonymous bodies must not hold the shared JSON write pool
PublicRepositoryMutationHTTPTests.swift:766: error: testAuthenticatedWriteSucceedsWhileUnauthenticatedSlowBodiesAreInFlight :
  XCTAssertEqual failed: ("503 Service Unavailable") is not equal to ("200 OK") - {"error":"temporarily_unavailable"}
PublicRepositoryMutationHTTPTests.swift:698: error: testUnauthenticatedJSONMutationIsDeniedWithoutReservingAWriteLease :
  XCTAssertEqual failed: ("503 Service Unavailable") is not equal to ("401 Unauthorized") - {"error":"temporarily_unavailable"}
PublicRepositoryMutationHTTPTests.swift:836: error: testUploadBlobRefusesAdoptionWhenAccountDeactivatesDuringStream :
  XCTAssertEqual failed: ("200 OK") is not equal to ("404 Not Found")
  - {"blob":{"$type":"blob","mimeType":"application/octet-stream","ref":{"$link":"bafkrei…"},"size":12}}
PublicRepositoryMutationHTTPTests.swift:841: error: testUploadBlobRefusesAdoptionWhenAccountDeactivatesDuringStream :
  XCTAssertEqual failed: ("nil") is not equal to ("Optional("RepoNotFound")")
```

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

`executeUploadThenHealthOnSameConnection` was generalized into
`executeMutationThenHealthOnSameConnection(port:path:headers:body:)`; the
original name is kept as a thin wrapper so the two existing upload tests are
untouched.

**Post-fix, `PublicRepositoryMutationHTTPTests`:** exit 0, 24 passed, 0 failed.

---

## 4. Suite and build results

**macOS full suite** — exit 1, **1492 passed / 1 failed / 9 skipped / 11 targets**
(baseline 1489 passed; +4 new tests, −1 failure).

The single failure is explained and is not a regression in this lane's code:

`SwanHTTPTests.PublicRouteSurfaceProfileSelectionTests.testANarrowerProfileRemovesRealHandlersNotOnlyGates`
at `Tests/SwanHTTPTests/PublicRouteSurfaceProfileSelectionTests.swift:552`:
`XCTAssertEqual failed: ("401 Unauthorized") is not equal to ("400 Bad Request")`.
The probe posts an **unauthenticated** `{}` to `putRecord` and expects 400, to
distinguish live route (400) from absent (404) from placeholder gate (503). With
authorization hoisted, an anonymous caller is refused 401 before the envelope is
parsed — which is the intended behaviour and still distinguishes all three.
**The fix is to change that one expectation to `.unauthorized` and update the
adjacent comment.** That file is in no lane's file list, so under the
lane-isolation rule I did not edit it; raised with the team lead.

One earlier run also showed
`SwanOAuthTests.NIOPeerPinnedOAuthPostTransportTests.testDocumentTransportTimeoutCompletesAndClosesUnresponsivePeer`
failing with "I/O on closed channel" at
`Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift:141`. It passes on
re-run and did not recur in the final run: a timing flake in a module this lane
does not touch.

**Linux (`swift:6.1-jammy`, the image the `Dockerfile:1` pins):**

- Production library: `swift build` → **exit 0**.
- `swift build --target SwanHTTPTests` (the target containing all three changed
  files' consumers) → **exit 0**.
- `swift build --build-tests` over the whole package fails to compile
  `Tests/SwanSQLiteTests/AccountPermanentDeletionSQLiteTests.swift:260`:
  `error: 'async' call cannot occur in a defer body` (`defer { try? await database.close() }`).
  Accepted by the local Swift 6.2 toolchain, rejected by the deployment image's
  Swift 6.1. That file is byte-identical to `75e7b509` in this workspace — this
  lane modified three files and none of them is in `SwanSQLiteTests` — so it is
  pre-existing and unrelated. Worth flagging to the program: the brief's Linux
  command cannot currently return 0 for **any** lane.

Mechanical notes for whoever repeats this: the local Petrel path dependency must
be mounted (`-v "$PWD/../Petrel":/Petrel:ro`, because `/src/../Petrel` resolves to
`/Petrel`); Docker Desktop does not share `/private/tmp` on this machine, so a
scratchpad mount silently appears empty inside the container; and the Linux build
rewrites `Package.resolved` (it drops `swift-configuration`), which was restored
with `jj restore Package.resolved` and is not part of this lane's diff.

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
  (`SwanJSONWriteBody.swift:236-239`) and would also change the management
  listener's behaviour, whose drain path shares the helper.
