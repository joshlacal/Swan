# Task 8 — Move public blob reads off the write flag

Commit: `7a8cc47e7c97` — `SwanHTTP: serve public blob reads from the read path`
Fix round: `4ecd9e1ad34e` — `SwanHTTP: bound and cover the public blob read route`
Baseline: `c148cae0f9a8`, suite exit 0.

> **Fix round (four IMPORTANT review findings).** See
> [Fix round](#fix-round-review-findings) at the end of this report. All four
> findings were accepted and fixed; no finding was skipped or argued away.
> Everything above that section describes the original commit and is left
> unedited except where a statement it makes is now false — those are marked
> **[superseded]**.

## Outcome

`com.atproto.sync.getBlob` is now registered by `registerPublicRepositoryReadEndpoints`,
governed by the same single condition as every other public read route
(`publicRepositoryReadDirectory != nil`). The mutation block no longer registers it,
and the `publicRepositoryMutations != nil && nsid == "com.atproto.sync.getBlob"`
special case in `SwanHTTP.swift` is gone.

In production this means `--enable-public-repository-mutations` is no longer the
hidden switch for avatar and image serving: the CLI passes
`publicRepositoryReadDirectory: directory` unconditionally, so blobs are served on
every Swan that exposes public reads at all.

## Changes per file

### `Sources/SwanStorage/SwanStorage.swift`
**[superseded — the protocol now has two methods; see the fix round.]**
Added `PublicRepositoryReadBlobStore` — a one-method, read-only protocol
(`publicBlob(cid:) -> PublicBlob?`) — and made `StreamingBlobStore` refine it
(the duplicate `publicBlob` declaration on `StreamingBlobStore` was removed as
now-inherited). The anonymous read route is handed *this*, never a
`StreamingBlobStore`/`BlobStore` that can also write, adopt, or delete. That is the
allow-list the binding constraints asked for; the previous route held the account's
writable `PublicRepositoryMutationStore` and downcast it to `StreamingBlobStore`.

### `Sources/SwanStorage/PublicRepositoryReadDirectory.swift`
- New `PublicRepositoryReadBlobTarget` (`did`, `status`, `store: any PublicRepositoryReadBlobStore`),
  throwing-validated on DID canonicity and status canonicity like its sibling projections.
- New **required** protocol method
  `publicRepositoryBlobOutcome(did:) -> PublicRepositoryReadOutcome<PublicRepositoryReadBlobTarget>`.
  Deliberately *not* a defaulted extension: a default returning `.notFound` would let a
  conformer silently serve no images at all, which is exactly the failure class being
  fixed. Documented that implementations must not admit or pin a repository generation
  for it.

### `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift`
Implemented `publicRepositoryBlobOutcome(did:)`. It resolves the control row via the
existing `resolvePublicAccount`, requires a startup-preopened `databases[did]`, then
maps status. Ordering is preopened-before-lifecycle, matching what the mutation
directory did (`generationRefreshingPublicMutationStore` also keys on `databases[did]`),
so a non-preopened account stays indistinguishable from an unhosted one.
It does **not** go through `withPublicReadGeneration`: a blob is content-addressed and
carries no MST revision, so putting image serving behind the admission gate that failed
permanently on 2026-08-12 would add risk and buy nothing. This preserves today's
behaviour exactly — the old route never touched generation admission either.

### `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift`
Removed the `blobPath` GET route and its wrong-method guards (a comment records why the
block is intentionally empty of `getBlob`). Removed `PublicBlobParameters`,
`publicBlobParameters`, `publicBlobRequestHasNoBody`, `publicBlobLifecycleError` (moved
or replaced). `maximumPublicBlobTransferBytes` and `safePublicBlobMIMEType` are now
internal rather than private, because upload (still here) and download (now on the read
path) must agree on the same bound and the same MIME sanitiser.

### `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift`
- `com.atproto.sync.getBlob` added to `publicReadNSIDs` and to the wrong-method guard
  path list.
- Three new `PublicReadHandlerGuard` cases so each blob 503 names its own cause in the
  journal: `blobStreamAdmissionExhausted`, `blobStorageFailure`, `blobLengthOutOfBounds`.
  These are HTTP-layer guards; the `PublicReadUnavailableReason` golden list in
  `Tests/SwanSQLiteTests/PublicRepositoryReadDiagnosticsTests.swift` is untouched because
  no storage reason was added.
- The route itself, with the original order of operations preserved: no-body check →
  strict canonical `did`/`cid` parse → directory resolve → lifecycle → reserve stream
  lease → open blob → length bound → stream with the lease released by the writer's
  `defer`. Added a defence-in-depth `resolved.did == parameters.did` check.
- Three new parameters on `registerPublicRepositoryReadEndpoints`: `blobStreamAdmission`,
  `blobRequestBodyAdmission`, `blobRequestBodyPolicy`.
- Moved `PublicBlobParameters` / `publicBlobParameters` / `publicBlobRequestHasNoBody`
  here, the latter now taking an admission + policy directly instead of a mutation
  capability.

Every 503 on the route leaves through the existing `publicReadUnavailable` helper, so it
is journalled with method + reason + (DID-validated) selector. **The client-visible body
is unchanged**: `503 {"error":"temporarily_unavailable"}`. The old exit was
`authenticatedGetSpaceJSON(status, ["error": code])` and the new one is
`jsonResponseWithStatus(status, body: ["error": code])` — both `JSONEncoder`-encode a
single-key dictionary with `application/json` + `no-store`, so the bytes are identical.

### `Sources/SwanHTTP/SwanHTTP.swift`
Passes `blobStreamAdmission` / `jsonWriteAdmission` / `jsonWriteBodyPolicy` into the read
registration; deletes the getBlob special case in the profile loop (replaced by a comment
explaining what used to be there).

### `Sources/SwanHTTP/SwanPublicRepositoryMutationCapability.swift`
Removed `blobStreamAdmission` — after the move it was dead, and a field on the mutation
capability named for blob *streaming responses* would misdescribe the capability. The
server-level `SwanHTTPServer.blobStreamAdmission` (fed by the CLI from the preopened
directory) is unchanged and now feeds the read surface.

### Tests
- **New** `Tests/SwanHTTPTests/PublicBlobReadRegistrationTests.swift` (4 tests).
- `PublicBlobDIDBindingTests`: `PublicBlobTestDirectory` now conforms to both directory
  protocols and is passed as `publicRepositoryReadDirectory` too. All four existing
  assertions (exact-DID binding, query validation, lifecycle-before-bytes, admission
  fail-closed + lease release) pass unmodified against the moved route.
- `PublicRepositoryMutationHTTPTests`: `TestMutationDirectory` gained the read-directory
  conformance so `testPublicRecordLinksRequirePublicBlobReachability` can still read its
  uploaded blob back. Its blob outcome deliberately does not arrive at the mutation
  `barrier`.
- `PublicRepositoryReadHTTPTests.testDeferredAndWrongMethodRoutesRemainFinite`: `getBlob`
  moved out of the deferred list; it now asserts a live route's `400 InvalidRequest` for a
  parameterless request.
- `ServePermissionedRuntimeCompositionTests`: `getBlob` moved from the deferred (503) list
  into the live-read (400) list. This is the CLI composition — reads on, writes off — and
  it is the test that most directly pins the bug being fixed.
- `PublicHandleResolutionHTTPTests` and `PublicRepositoryReadHTTPTests` fakes: added the
  new protocol method.

## Ambiguity in the brief, and how it was resolved

1. **"Backed by the read directory."** `PublicRepositoryReadDirectory` had no blob
   accessor, so this could not be taken literally without a protocol change. The
   alternatives were (a) a separate optional blob-directory parameter, or (b) discovering
   the capability by downcasting the read directory. Both reintroduce conditional
   capability registration — the shape the binding constraints and D7 explicitly call out
   as having caused two prior production bugs — so I added the method as a **required**
   protocol requirement instead. Registration is then governed by exactly one condition.
   Cost: three test fakes had to implement it.

2. **The brief's test body is too weak to fail.** `XCTAssertNotEqual(response.status, .notFound)`
   passes *today*: with mutations off, `getBlob` answers `503 public_streaming_pending`
   from `registerUnavailablePublicEndpoint`, not 404. The brief's Step 2 "Expected: 404"
   is wrong about the pre-state. I kept the brief's assertion verbatim inside the test and
   added the assertions that actually bite — `200 OK`, exact bytes, `Content-Length`,
   `X-Content-Type-Options: nosniff` — plus an assertion that the mutation surface really
   is off (`XCTAssertNil(server.publicRepositoryMutations)` and `uploadBlob → 503
   public_streaming_pending`), so the 200 cannot be explained by writes being on.

3. **`.active` in the lifecycle branch.** The old `publicBlobLifecycleError` mapped
   `.active → "InvalidRequest"`; the read surface's shared `publicLifecycleError` maps it
   to `"RepoNotFound"` via its default. `.active` is unreachable in a `.lifecycle` outcome
   (both the SQLite implementation and the fakes return `.active(target)` for it), so I
   used the shared read-path helper rather than duplicating a mapping for an unreachable
   case.

## Falsification

Four independent breaks, each built and run.

**F1 — remove `"com.atproto.sync.getBlob"` from `publicReadNSIDs`, keep the route.**
Result: hard crash, `Hummingbird/EndpointResponder.swift:27: Fatal error: GET already has
a handler`, suite exit 1 with `Some test targets reported failures: SwanHTTPTests`. Not
the 503 I predicted — better. The gate-skip is load-bearing *and* enforced at router
construction, so a future edit that installs the route without the skip fails loudly at
startup rather than silently. (Also a reminder of the "crash produces zero failed-case
lines" trap: this run had exactly one `started` line and no `failed` line.)

**F2 — remove `"/xrpc/com.atproto.sync.getBlob"` from the wrong-method guard list.**
Result: **all four new tests still passed.** My `testGetBlobAnswersOnlyGETOnTheReadSurface`
does not pin the exact-path guards, because `registerUnknownPublicEndpointGuards`'
`com.atproto.sync.*` wildcard returns the identical `404 public_endpoint_unavailable`. I
restored the guards (every other read route has them, and relying on a wildcard staying in
place is not a property I want to depend on) and rewrote the test's doc comment to state
what it actually pins — the observable contract, not the mechanism. Reported here rather
than papered over.

**F3 — `BlobNotFound` 404 → `RepoNotFound` 400 on the missing-blob path.**
Result: suite exit 1.
`PublicBlobReadRegistrationTests.testUnknownCIDIsBlobNotFoundOnTheReadSurface` failed
(`"400 Bad Request"` vs `"404 Not Found"`, `"RepoNotFound"` vs `"BlobNotFound"`), and the
pre-existing `PublicBlobDIDBindingTests` lifecycle/exact-DID tests failed with the same
mismatch. Expected reason, exactly.

**F4 — restore the original bug**: `getBlob` removed from `publicReadNSIDs`, from the
guard list, and the route path renamed so the read surface installs nothing, letting the
profile loop re-install the 503 gate.
Result: suite exit 1.
`testGetBlobIsServedWhenPublicMutationsAreDisabled` failed with
`("503 Service Unavailable") is not equal to ("200 OK")` and
`("36 bytes") is not equal to ("35 bytes")` — the 503 body being served instead of the
blob — and `testUnknownCIDIsBlobNotFoundOnTheReadSurface` failed with
`("Optional("public_streaming_pending")") is not equal to ("Optional("BlobNotFound")")`.
All four `PublicBlobDIDBindingTests` failed the same way. This is the decisive one: the
new test fails for precisely the production symptom it was written to catch.

All four breaks were reverted; the committed tree is the F0 state, rebuilt and re-run.

`testGetBlobIsNotServedWhenPublicReadsAreDisabled` passed under every break, as it should:
it asserts the *status quo* for a server with no read directory and exists to stop a future
change from over-registering the route, not to detect this one.

## Commands and results

```
xcrun --toolchain XcodeDefault swift build --build-tests      # exit 0
xcrun --toolchain XcodeDefault swift test --skip-build \
  --filter PublicBlobReadRegistrationTests                    # exit 0, 4 passed
xcrun --toolchain XcodeDefault swift test --skip-build \
  --filter PublicBlobDIDBindingTests                          # exit 0, 4 passed
xcrun --toolchain XcodeDefault swift test --skip-build        # exit 0
```

Filters were verified to have matched (4 named `Test Case '-[...]' passed` lines each, not
a silent zero-match success). All output was redirected to files; nothing was piped through
`tail`.

Full suite (final, at the committed tree):
- exit code **0**
- `Test Case '-[...]' passed` lines: **1457**
- `Test Case '-[...]' failed` lines: **0**
- `Some test targets reported failures`: **not present**
- `Fatal error`: **not present**

The intermediate full-suite run had 1454 passed / 3 failed; those three were
`PublicRepositoryMutationHTTPTests.testPublicRecordLinksRequirePublicBlobReachability`,
`PublicRepositoryReadHTTPTests.testDeferredAndWrongMethodRoutesRemainFinite`, and
`ServePermissionedRuntimeCompositionTests.testExactServeCompositionRetainsConfigurationAndInstallsAllRoutes`
— all three were pinning the old registration, and all three were updated to assert the
new (correct) behaviour rather than being weakened. Baseline before this task would have
been 1453 passed; the +4 are the new file.

`swiftformat` was **not** run. No mutating git command was run; the commit was made with
`jj describe` + `jj new`. No file was deleted.

## Deliberately not done

- **Relay activation** — out of scope, not started.
- **Task 10 (`--profile` on the public surface)** — route registration still iterates the
  hardcoded `PublicDataTesting20260727`. Touching it here would have collided with that
  task.
- **No sync methods added.** `listRepos`, `getBlocks`, `listBlobs` are untouched; indigo
  never calls them.
- **Phase 1 proxying / credential isolation / peer pinning** — untouched.
- The three new `PublicReadHandlerGuard` tokens are not pinned by a golden-list test.
  `PublicReadUnavailableReason` has one; the HTTP-layer guard enum does not, and adding
  that machinery was out of scope. `blobStreamAdmissionExhausted` is exercised end-to-end
  by `testGetBlobFailsClosedWhenAdmissionIsHeldAndReleasesAfterResponse`;
  `blobStorageFailure` and `blobLengthOutOfBounds` are not directly exercised.
- No live verification against the deployed server. This is a route-registration change
  with no UI; the CLI composition test
  (`ServePermissionedRuntimeCompositionTests`) is the closest thing to an end-to-end
  assertion available in-repo. A deployed check would be:
  `curl -sS -o /dev/null -w '%{http_code}' 'https://swan.catbird.blue/xrpc/com.atproto.sync.getBlob?did=<did>&cid=<cid>'`
  → expect `200`, and the same call on a build with `--enable-public-repository-mutations`
  omitted → still `200`.

## Concerns

1. **`PublicRepositoryReadDirectory` gained a required member.** Any out-of-tree conformer
   breaks at compile time. That is intentional (fail loud, not silent), but it is a source
   break on a `public` protocol.
2. **F2 exposed that my verb test does not pin what its name suggests.** I kept the test
   with an honest doc comment rather than deleting it or inflating the claim. If the
   `com.atproto.sync.*` wildcard is ever narrowed, the exact-path guards become the only
   thing standing between a `POST /xrpc/com.atproto.sync.getBlob` and the AppView proxy,
   and nothing in the suite would catch their removal.
3. **[superseded — fixed in the fix round, and it was not a naming issue.]**
   **`getBlob` still collects the request body under `jsonWriteAdmission`** on a GET. That
   is preserved from the old route (a caller who sends a body at an anonymous route must
   not stream unmetered bytes), but it does mean a public *read* consumes from a budget
   named for writes. Worth a rename at some point; changing the budget here would have
   been a behaviour change outside this task.
4. **Blob reads bypass generation admission entirely.** This matches the previous
   behaviour and is deliberate (see the SQLite doc comment), but it does mean a blob can
   be served from an account whose repository generation cannot currently be admitted. For
   avatars and images that is the desired trade; it is stated here so it is a decision on
   the record rather than an accident.
5. **`.active` inside a `.lifecycle` outcome** would now answer `RepoNotFound` where the
   old route answered `InvalidRequest`. Unreachable in every current implementation, but
   it is a behavioural difference if a future directory returns it.

---

# Fix round (review findings)

Four IMPORTANT findings from two independent reviewers. **All four were
accepted as real and are fixed.** I have no disagreement to record with any of
them; the only thing I would add to the reviewers' framing is noted under F3.

Suite at the fix-round commit: exit **0**, **1463** `Test Case '-[...]' passed`
lines, **0** failed, no `Some test targets reported failures`, no `Fatal error`,
no `Assertion failed`. Baseline for this round was 1457, and the round adds six
tests.

## F1 + F2 — the production `publicRepositoryBlobOutcome(did:)` had zero coverage

Both reviewers landed on the same falsification: replace the body of
`SQLitePreMigratedAccountDirectory.publicRepositoryBlobOutcome(did:)` with
`return .notFound` and the entire suite stayed green, while every avatar on the
deployed server would answer `400 RepoNotFound`. Correct — every one of the five
call sites in `Tests/` was a hand-written fake, and the one composition test
that used the real directory sent a parameterless `GET` that returned `400` from
query parsing before the directory was ever consulted.

Fixed on two levels, both against real objects.

**Directory level** — `Tests/SwanSQLiteTests/PublicRepositoryReadDirectoryTests.swift`,
two new tests on the existing real fixture (real control store, real
startup-preopened SQLite inventory, real genesis/generation admission):

- `testPublicBlobOutcomeServesRealPreopenedAccountBytesAndTrueLength` — stores a
  real public blob through the directory's own preopened handle, asserts
  `.active` with `target.did == did` and `status == .active`, then asserts the
  returned store yields the exact metadata size, the exact MIME type, the exact
  declared `contentLength`, and the exact bytes when streamed. It also asserts a
  blob held only in a permissioned namespace is absent from both the body and
  the metadata projection.
- `testPublicBlobOutcomeRefusesUnhostedNonPreopenedNonDIDAndClosedDirectory` —
  every refusal path on the real directory: an unhosted DID (`.notFound`); an
  account registered as active *after* bootstrap so it has a control row and no
  preopened database (`.notFound`); that same account after deactivation, still
  `.notFound`, which is what pins the reviewers' "preopened-before-lifecycle"
  ordering claim; a handle selector (throws `.invalidSelector`); a deactivated
  preopened account (`.lifecycle`, DID/status/nil-revision asserted); and a
  closed directory (throws a named unavailable reason).

**HTTP level** — `Tests/SwanHTTPTests/PublicBlobReadRegistrationTests.swift`,
`testGetBlobServesRealPreopenedDirectoryBytesEndToEnd`. This composes a
`SwanHTTPServer` the way `serve` composes one — real `SQLiteControlDatabase`,
real `SQLitePreMigratedAccountDirectory.bootstrap`, public writes off — stores a
real blob in the account's preopened database, and asserts `200`, exact bytes,
exact `Content-Length`, and `Content-Type: image/png` over the real router. It
also asserts an unhosted DID answers `400 RepoNotFound` through the same
production projection rather than borrowing alice's bytes.

The fixture uses `publicIdentityVerifier: nil` — the directory's documented
public-repository-disabled mode — because a blob needs no repository generation.
That keeps the fixture to the seam under test while still running the exact
production `publicRepositoryBlobOutcome(did:)`, control-row resolution and
preopened-inventory lookup included.

**Falsification (run, not asserted).** With `return .notFound` inserted at the
top of `publicRepositoryBlobOutcome`, suite exit 1 and *three* of the new tests
fail — both directory tests and the end-to-end HTTP one — while every
fake-backed blob test still passes, which is precisely the blind spot the
reviewers described. Reverted; the committed tree is the unmutated state.

## F3 — the route reserved a fixed 256 MiB per request

Accepted in full, including the reviewer's arithmetic: with the production
defaults (`1 GiB` global, `512 MiB` per account) a fixed
`maximumPublicBlobTransferBytes` reservation caps the image path at two
concurrent blob reads per account and four per server, and starves
`com.atproto.sync.getRepo` out of the same instance.

`PublicRepositoryReadBlobStore` now carries `publicBlobMetadata(cid:)` alongside
`publicBlob(cid:)` — the metadata-only accessor the previous diff dropped. It
exposes no body, path, descriptor, database, or namespace reference, so it does
not widen the anonymous surface; `StreamingBlobStore` inherits both. The route
now:

1. reads the blob's true length via `publicBlobMetadata`,
2. answers `404 BlobNotFound` for an absent CID (now *before* reserving anything),
3. refuses a zero or over-ceiling declared length with `blobLengthOutOfBounds`,
4. reserves exactly `metadata.size`,
5. opens the blob, and refuses with `blobLengthOutOfBounds` if the opened body's
   `contentLength` is anything other than the declared size — a blob is
   content-addressed and immutable, so a mismatch means the reservation does not
   cover the transfer and no byte leaves.

A 5 KiB avatar now reserves 5 KiB. The per-account lease count (16) becomes the
operative concurrency bound for small blobs instead of the byte budget.

Test: `testGetBlobReservesTheBlobsTrueLengthAndNotTheTransferCeiling`
pre-reserves all but 1 KiB of a production-shaped per-account budget and asserts
a small blob is still served, then asserts the admission returns to exactly the
pre-held reservation. Falsified by restoring the ceiling reservation: that test
fails (`503` instead of `200`) and no other test does. Reverted.

**The one thing I would add to the reviewers' framing.** Moving the metadata
lookup ahead of the reservation means an anonymous caller can probe CIDs without
consuming transfer budget. That is deliberate and, I argue, not a regression:
the route already performs an unreserved control-store lookup for every
anonymous request (inside `publicRepositoryBlobOutcome`), so "storage is touched
before admission" was already true on this path; the added work is one indexed
`SELECT` that materializes no payload, the same one `publicBlobExists` runs; and
it *removes* the previous behaviour where probing a nonexistent CID reserved
256 MiB for the duration of the lookup. Recorded here so it is a decision on the
record rather than an accident.

## F4 — an anonymous GET held one of eight process-shared JSON *write* leases

Accepted. `publicBlobRequestHasNoBody` reserved from
`PublicRepositoryJSONWriteAdmission.processShared` — eight leases, shared with
`SwanSpaceXRPC`, `SwanSimpleSpaceXRPC`, `SwanAccountEmailXRPC`,
`SwanActorPreferencesXRPC` and the general request-body path — and held it for
`policy.totalBodyTimeout` (30 s) while a chunked, never-terminated body was
collected. Eight such requests denied every authenticated JSON command for 30 s,
sustainably, at a route that had previously answered a static 503 and collected
nothing. My original Concern #3 framed this as a naming issue; that was wrong,
and the reviewer is right that this diff is what made it reachable.

Three changes, and the fix is an allow-list rather than a deny-list — the route
is *given* its own bounded pool instead of being trusted to behave inside a
shared one:

- **A separate pool.** `PublicRepositoryJSONWriteAdmission.publicBlobReadProcessShared`
  (64 concurrent, 64 KiB) — deliberately its own instance, following the
  existing `managementRejectedProcessShared` precedent. Each check reserves one
  byte, so the byte dimension is inert and the concurrency dimension is the
  bound. It is wider than `processShared` because a stalled reader here holds a
  single byte and its own listener slot, which the connection limit already
  bounds. `SwanHTTPServer` exposes it as `publicBlobRequestBodyAdmission` (new
  defaulted init parameter, so it can be injected in tests) and passes it to the
  read registration; `registerPublicRepositoryReadEndpoints` defaults to it too,
  so a future caller cannot reintroduce the shared pool by omission.
- **A short deadline.** `SwanJSONWriteBodyPolicy.noRequestBodyDefault` (2 s).
  `getBlob` expects no body, so there is nothing legitimate to wait for beyond
  the end of the request stream; the 30 s a 1 MiB command needs was pure
  attacker budget here.
- **Header-first refusal.** A body declared by `Transfer-Encoding` (any value) or
  by a non-zero `Content-Length` is refused from the headers alone — the inbound
  stream is terminated, no lease is taken, and no byte is read. `Transfer-Encoding`
  is the shape that mattered: it declares a body with no length, so the generic
  collector could not reject it up front and instead admitted it and waited out
  the deadline.

`publicBlobRequestHasNoBody` became `publicBlobRequestBody`, returning
`.absent` / `.present` / `.unavailable`. A saturated pool or an expired body
deadline is now a capacity refusal — the shared `publicReadUnavailable` 503 exit,
journalled under the new `blobRequestBodyAdmissionExhausted` guard — instead of a
`400` blaming a well-formed request. **The client-visible 503 body is unchanged:
`{"error":"temporarily_unavailable"}`**, and the new guard token is an HTTP-layer
`PublicReadHandlerGuard` case, so the `PublicReadUnavailableReason` golden list in
`PublicRepositoryReadDiagnosticsTests` is untouched by design.

Tests:
- `testGetBlobNeitherConsumesNorIsBlockedByTheSharedJSONWritePool` — a server
  built with a one-lease `jsonWriteAdmission`, that lease held, must still serve
  the blob `200`, and the shared pool's lease count must be unchanged by the
  request.
- `testGetBlobAnswers503WhenItsOwnRequestBodyPoolIsSaturated` — with the route's
  own pool held, `503 temporarily_unavailable` (not `400`), and `200` again once
  released, with the pool back to zero leases.

Falsified by pointing the route back at `jsonWriteAdmission`: both tests fail and
nothing else does. Reverted.

## Files touched in this round

- `Sources/SwanStorage/SwanStorage.swift` — `publicBlobMetadata(cid:)` added to
  `PublicRepositoryReadBlobStore`; the now-inherited duplicate removed from
  `StreamingBlobStore`.
- `Sources/SwanStorage/PublicRepositoryReadDirectory.swift` —
  `publicBlobReadProcessShared`.
- `Sources/SwanHTTP/SwanJSONWriteBody.swift` — `noRequestBodyDefault`.
- `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift` — right-sized
  reservation, metadata/length agreement check, tri-state body outcome,
  header-first refusal, new guard case, new defaults.
- `Sources/SwanHTTP/SwanHTTP.swift` — `publicBlobRequestBodyAdmission` property
  and init parameter, wired into the read registration.
- `Tests/SwanSQLiteTests/PublicRepositoryReadDirectoryTests.swift` — 2 new tests.
- `Tests/SwanHTTPTests/PublicBlobReadRegistrationTests.swift` — 4 new tests,
  fixture gains admission injection and a real-directory `LiveFixture`.

## Commands and results (fix round)

```
xcrun --toolchain XcodeDefault swift build --build-tests            # exit 0
xcrun --toolchain XcodeDefault swift test --skip-build \
  --filter "PublicRepositoryReadDirectoryTests/testPublicBlobOutcome"  # exit 0, 2 passed
xcrun --toolchain XcodeDefault swift test --skip-build \
  --filter PublicBlobReadRegistrationTests                          # exit 0, 8 passed
xcrun --toolchain XcodeDefault swift test --skip-build              # exit 0
```

Every filter was verified to have matched named `Test Case '-[...]' passed`
lines rather than silently matching nothing. All output was redirected to files;
nothing was piped through `tail`. `swiftformat` was **not** run. No mutating git
command was run — the commit is `jj describe` + `jj new`. No file was deleted.

Full suite at the committed tree: exit **0**, **1463** passed, **0** failed,
`Some test targets reported failures` absent, `Fatal error` absent,
`Assertion failed` absent.

## Still open after this round

- **No live verification.** Unchanged from the original report: this is a route
  and admission change with no UI. The deployed check remains
  `curl -sS -o /dev/null -w '%{http_code}' 'https://swan.catbird.blue/xrpc/com.atproto.sync.getBlob?did=<did>&cid=<cid>'`
  → expect `200` on a build without `--enable-public-repository-mutations`.
- The three older `PublicReadHandlerGuard` tokens and the new fourth are still
  not pinned by a golden-list test; `blobStorageFailure` and
  `blobLengthOutOfBounds` remain unexercised end-to-end.
- `PublicRepositoryReadDirectory` remains a source break for any out-of-tree
  conformer, and `PublicRepositoryReadBlobStore` now is too.
