# Task 7 — Implement `com.atproto.identity.resolveHandle`

Commits:
- `0fe20ba330e5` — "SwanHTTP: implement unauthenticated resolveHandle"
- `c148cae0f9a8` — "SwanHTTP: bound resolveHandle admission and align its
  registration with the public read surface" (**fix round**, see the last
  section — it supersedes parts of what follows)

Parent (baseline): `310c32cf3519`

Full suite after the fix round: **exit 0**, **1453** `Test Case '-[...]' passed`
lines, 0 `Test Case '-[...]' failed` lines, 0 `Some test targets reported
failures`. Baseline was 1438; the 15 new cases account for the whole delta.
(The first commit measured 1451 / 13 new.)

---

## What changed, per file

### `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift` (+171 / -9)

1. **`SwanPublicHandleResolutionCapability`** (new, `public struct`, `Sendable`).
   Holds `any AccountControlStore` privately and exposes exactly one internal
   method:

   ```swift
   func activeDID(forCanonicalHandle handle: String) async throws -> String?
   ```

   It rejects a non-canonical handle without touching storage (the store's own
   `account(canonicalHandle:)` *throws* `invalidInput` on one, which would have
   turned a malformed request into a 503), then returns the DID only when
   `account.status.authorizesAccount` — which in this codebase is exactly
   `status == .active`. This is the allow-list at the trust boundary: the control
   store is a very wide type (credentials, recovery envelopes, email delivery
   leases, key references) and only this one projection of one row escapes it to
   the anonymous surface.

2. **`registerPublicHandleResolutionEndpoint(on:capability:)`** (new). Registers
   `GET /xrpc/com.atproto.identity.resolveHandle` plus the eight wrong-method
   guards for that exact path. The handler:
   - parses with the existing strict `publicReadQuery(request, required: ["handle"])`
     (rejects unknown params, duplicates, fragments, oversize queries);
   - folds wire case via `AccountIdentifiers.canonicalHandle` — handles are
     case-insensitive on the wire and canonical in storage;
   - answers `200 {"did":"…"}`;
   - answers `400 {"error":"InvalidRequest"}` for a malformed handle, an unhosted
     handle, and a non-active handle — all three indistinguishable, matching the
     reference PDS and refusing to leak this host's moderation state;
   - answers `503 {"error":"temporarily_unavailable"}` only if the control store
     itself fails, through the shared `publicReadUnavailable` exit so it is
     journalled.

   It performs **no** DNS/PLC/DID/HTTP resolution and reserves **no** JSON read
   lease — the response is one DID, and reserving the shared multi-megabyte
   budget would let `listRecords` traffic starve the method every login depends
   on. It passes an explicit 4 KiB encode bound rather than inheriting the 16 MiB
   `listRecords` default.

3. **`PublicReadHandlerGuard.handleDirectoryUnavailable`** (new case). This enum
   is HTTP-layer-only and has no golden-list test, so
   `testJournalTokensMatchTheGoldenList` and `PublicReadUnavailableReason` are
   untouched — deliberately, since none of the generation-admission reasons can
   be the cause of a resolveHandle failure.

4. **`registerPublicReadWrongMethodGuards(on:path:)`** — extracted from the
   existing inline loop at the end of `registerPublicRepositoryReadEndpoints` so
   the new route registers the identical guard shape rather than a second copy.
   Behaviour of the six existing paths is byte-identical.

5. **`isInstalledPublicHandleResolutionMethod(_:)`** (new) — see the ambiguity
   note below.

### `Sources/SwanHTTP/SwanPublicUnavailableXRPC.swift` (+8)

Added `"/xrpc/com.atproto.identity.*"` to `registerUnknownPublicEndpointGuards`.
Every method in that namespace is Swan's own to implement or refuse;
`updateHandle`, `signPlcOperation`, and friends must answer 404 from Swan rather
than be swept into the AppView proxy, which would hand a third party a handle or
a PLC operation request. The exact `resolveHandle` route out-ranks the wildcard.

### `Sources/SwanHTTP/SwanHTTP.swift` (+22)

- New stored `public let publicHandleResolution: SwanPublicHandleResolutionCapability?`,
  formed in `init` from the existing (previously unstored) `accountControlStore`
  parameter.
- `buildRouter` registers the endpoint when that capability is present, in the
  public-read section but **outside** the `if let publicRepositoryReadDirectory`
  block.
- The `PublicDataTesting20260727` descriptor loop gains a `continue` keyed on
  `publicHandleResolution != nil && isInstalledPublicHandleResolutionMethod(…)`,
  mirroring the existing mutation/email patterns.

Production wiring needed no change: `SwanCommand.makeServer` already passes
`accountControlStore: accountControlStore`.

### `Tests/SwanHTTPTests/PublicHandleResolutionHTTPTests.swift` (new, 620 lines)

13 cases, all with real assertions against decoded/raw wire bytes. No existing
test needed editing (see "Existing tests" below).

---

## How I resolved ambiguity in the brief

> **Superseded by the fix round.** The two deviations described immediately
> below were reverted in `c148cae0f9a8`: the handler is now registered from
> `registerPublicRepositoryReadEndpoints` and the NSID is now in
> `publicReadNSIDs`, both literally as the brief specified. The paragraphs are
> kept because the *reasoning* about the four capability combinations is still
> what makes the new predicate correct. Read the fix-round section for what
> ships.

**Two related deviations, one decision.** The brief said to register the handler
"from `registerPublicRepositoryReadEndpoints`" and to "add the NSID to
`publicReadNSIDs`". I did neither literally.

`registerPublicRepositoryReadEndpoints` requires a `PublicRepositoryReadDirectory`,
so registering there would make resolveHandle's *existence* conditional on the
repository read directory. That is precisely the coupling the brief's own test
`testResolveHandleDoesNotRequireGenerationAdmission` exists to forbid — and the
one that would have made this method go dark alongside everything else on
2026-08-12. The route is therefore its own registration function, in the same
file (it needs that file's `private` helpers: `publicReadQuery`,
`publicReadJSON`, `publicReadError`, `publicReadResponse`, `publicReadUnavailable`,
`PublicReadHandlerGuard`), called from the same section of `buildRouter`, keyed
on its own capability.

Given that, adding the NSID to `publicReadNSIDs` would have been actively wrong.
That set has exactly one consumer — `isInstalledPublicReadMethod` at
`SwanHTTP.swift:972` — and that consumer is gated on
`publicRepositoryReadDirectory != nil`. A server with a read directory but no
control store would then have skipped the NSID's method-correct unavailable gate
while registering no route for it. So the set keeps its meaning ("installed by
the read directory") with a comment saying why resolveHandle is absent, and the
sibling predicate `isInstalledPublicHandleResolutionMethod` carries the new
method. This is correct for all four capability combinations. No profile in
`SwanPublicWire` declares any `com.atproto.identity.*` method today, so this is
future-proofing rather than a live fix either way.

**Unknown handle → `InvalidRequest`, not 404.** The brief named the test
(`testResolveHandleRejectsUnknownHandleWithInvalidRequest`) but not the status.
The reference PDS answers `InvalidRequest` (HTTP 400) for an unresolvable handle,
and callers depend on that, so `400 {"error":"InvalidRequest"}` it is.

**Non-active accounts do not resolve.** Not specified in the brief. The reference
PDS's `resolveHandle` excludes deactivated and taken-down accounts, and this
codebase's own `AccountControlStatus.authorizesAccount` is `self == .active`.
Using that property rather than a literal keeps the two definitions from drifting.

**Case folding.** Not mentioned in the brief; added because handles are
case-insensitive on the wire and canonical in storage, and without it any client
echoing a user's capitalisation gets a 400. Falsified (see D below).

**`ResolveHandleOutput`.** No generated wire type exists for this NSID and none
was requested, so the test declares a private `Decodable` struct of that exact
name and decodes the response into it. It is never constructed by the test; the
happy-path case additionally pins the complete raw body so a field added later
cannot silently leak an account fact.

---

## Falsification

Four independent breaks, each rebuilt and run against
`--filter PublicHandleResolutionHTTPTests`, each restored afterwards. Every one
failed for the predicted reason and only the predicted tests failed.

| # | Break | Result |
|---|---|---|
| A | Removed `"/xrpc/com.atproto.identity.*"` from `registerUnknownPublicEndpointGuards` | exit 1, 11 passed / **2 failed**: `testOtherIdentityMethodsReturn404NotUnauthorized` (`("") is not equal to ("{"error":"public_endpoint_unavailable"}")` — the namespace fell through to Hummingbird's bodiless 404) and `testResolveHandleIsAbsentWithoutAnAccountControlStore` |
| B | Dropped the `account.status.authorizesAccount` gate | exit 1, 11 passed / **2 failed**: `testResolveHandleDoesNotResolveNonActiveAccounts` (`("200 OK") is not equal to ("400 Bad Request") - for deactivated`, and the body leaked the real DID) and `testCapabilityResolvesOnlyActiveAccountsByCanonicalHandle` (`XCTAssertNil failed: "did:plc:6u6rzv6fk3ga37kgs3tybgdk"`) |
| C | Removed `AccountIdentifiers.canonicalHandle` folding (`let canonicalHandle = rawHandle`) | exit 1, 12 passed / **1 failed**: `testResolveHandleFoldsWireCaseToTheCanonicalHandle` (`("400 Bad Request") is not equal to ("200 OK") - for Swan.Place`) |
| D | Made the handler reserve from the injected `PublicRepositoryJSONReadAdmission` before answering | exit 1, 12 passed / **1 failed**: `testResolveHandleAnswersWithTheJSONReadBudgetFullyReserved` (`("503 Service Unavailable") is not equal to ("200 OK")`) |

D required temporarily *adding* a parameter to plumb the admission in, which is
itself the point: the shipped signature cannot reach the shared read budget.

After restoring, `grep -n "falsification\|FALSIFICATION"` over all three source
files returns nothing, and `jj diff --stat` matches the intended four-file change.

---

## Test commands and results

```
xcrun --toolchain XcodeDefault swift build --build-tests    # BUILD_EXIT=0, 0 "error:" lines
xcrun --toolchain XcodeDefault swift test --skip-build --filter PublicHandleResolutionHTTPTests
    # EXIT=0, 13 passed, 0 failed
xcrun --toolchain XcodeDefault swift test --skip-build      # SUITE_EXIT=0
    # 1451 "Test Case '-[...]' passed", 0 failed, 0 "Some test targets reported failures"
```

All runs redirected to files (never piped through `tail`); exit codes captured via
`echo $? > …` from a detached shell because the full suite exceeds the 10-minute
foreground tool timeout. Every filter run was checked for a non-zero passed count,
so no filter silently matched nothing.

The 13 new cases:

- `testResolveHandleAnswersUnauthenticated` — 200, decoded `did`, exact body, content-type
- `testResolveHandleIgnoresCredentialHeaders` — `Authorization` + `DPoP` present, still 200
- `testResolveHandleFoldsWireCaseToTheCanonicalHandle` — three capitalisations
- `testResolveHandleRejectsUnknownHandleWithInvalidRequest` — unhosted, two near-misses, and the DID
- `testResolveHandleRejectsMalformedAndMissingParameters` — 9 request shapes
- `testResolveHandleDoesNotResolveNonActiveAccounts` — 5 lifecycle statuses
- `testResolveHandleRefusesEveryOtherHTTPMethod` — 5 verbs
- `testResolveHandleDoesNotRequireGenerationAdmission` — see below
- `testResolveHandleAnswersWithTheJSONReadBudgetFullyReserved`
- `testOtherIdentityMethodsReturn404NotUnauthorized` — 8 NSIDs × 2 verbs
- `testResolveHandleIsAbsentWithoutAnAccountControlStore`
- `testCapabilityResolvesOnlyActiveAccountsByCanonicalHandle`
- `testHandleUniquenessIsEnforcedBeforeResolution`

`testResolveHandleDoesNotRequireGenerationAdmission` installs a
`PermanentlyUnadmittablePublicReadDirectory` that throws
`.unavailable(reason: .generationPinStale)` from every method — the 2026-08-12
state exactly — asserts `describeRepo`, `getRepoStatus`, and `getLatestCommit` all
return `503 {"error":"temporarily_unavailable"}`, and *then* asserts resolveHandle
returns 200. The 503 control is what makes the 200 meaningful.

The brief's literal fixture values are used verbatim: handle `swan.place`, DID
`did:plc:6u6rzv6fk3ga37kgs3tybgdk`.

## Existing tests

No existing test was modified. I expected
`SwanXRPCPipethroughTests.testUnknownNSIDReturns404NotUnauthorized` to break,
because it asserts the body `{"error":"EndpointUnavailable"}` for
`/xrpc/com.atproto.identity.resolveHandle`. It does not: its `withPipethrough`
helper builds a bare `Router` with only the pipethrough capability registered, so
the new namespace guard is not in that router at all. The two other tests naming
resolveHandle (`SwanXRPCPipethroughTests` line ~1306, `SwanXRPCProxyRoutingTests`
line 140) assert only `.notFound` / `.unrouted`, both still true.

Production behaviour change worth noting: on a fully assembled server, an
unimplemented `com.atproto.identity.*` method now answers
`404 {"error":"public_endpoint_unavailable"}` instead of the pipethrough's
`404 {"error":"EndpointUnavailable"}`. Same status, different opaque body; the
proxy allow-list already refused the namespace, so nothing that used to be proxied
stopped being proxied.

## Deliberately not done

- **No relay activation.** Nothing in this change touches relay, crawl
  announcement, or `subscribeRepos`.
- **No new sync methods.** Per the established facts, Indigo's relay calls only
  `describeServer`, `getRepoStatus`, and `listHosts`.
- **`com.atproto.sync.getBlob` left in the mutation block.** It is a real bug
  (an operator disabling public writes also disables avatar/image serving) but it
  is not Task 7.
- **`--profile` still does not affect the public side.** The hardcoded
  `PublicDataTesting20260727` loop is unchanged; I added a `continue` to it rather
  than rewriting it, since that is a separate task's surface.
- **No `PublicReadUnavailableReason` case added**, so the golden list in
  `Tests/SwanSQLiteTests/PublicRepositoryReadDiagnosticsTests.swift` is untouched.
- **No error-body widening.** The 503 body remains exactly
  `{"error":"temporarily_unavailable"}`; the new guard name is server-side log
  only, emitted through the existing `publicReadUnavailable` helper.
- **No `swiftformat` run.** 4-space indentation throughout, hand-matched to the
  surrounding files.
- **No mutating git.** `jj describe` + `jj new` only.

## Concerns

1. **resolveHandle is now available whenever an account control store is
   configured, independent of `--enable-public-*` flags.** I judged this correct —
   handle→DID for an active account is public protocol data, already published in
   the PLC directory and the DID document, and login/discovery cannot work without
   it. But it is a genuine widening of the anonymous surface on a server that
   previously exposed none, and it is an enumeration oracle for "does this handle
   exist and is it active here". If that is not wanted, the gate is one `if let`
   in `buildRouter`. Worth an explicit decision rather than inheriting mine.

2. **`.desynchronized` and `.throttled` accounts do not resolve.** These read to
   me as relay/repo sync-health signals rather than account lifecycle, and an
   argument exists that such an account should still resolve its handle. I
   followed `AccountControlStatus.authorizesAccount` (active-only) for consistency
   with the rest of the codebase, and pinned the choice in
   `testResolveHandleDoesNotResolveNonActiveAccounts`. If the intended semantics
   differ, one predicate and one test list change.

3. **`.deleting` / `.deleted` are covered only through the capability's
   `authorizesAccount` gate**, not end-to-end over HTTP: `transitionStatus`
   deliberately refuses to reach those states (permanent deletion is its own
   multi-resource workflow), so an HTTP-level test would have to drive
   `beginDeletion`. The gate is a single boolean shared with every other status,
   so I judged the extra fixture not worth it — noting it so the gap is visible.

4. **No live verification against the running service.** This is a library/route
   change verified by the test suite only; nothing was deployed to
   swan.catbird.blue. A live check would be
   `curl -s 'https://swan.catbird.blue/xrpc/com.atproto.identity.resolveHandle?handle=<hosted-handle>'`
   expecting `{"did":"did:plc:…"}`, plus the same for an unknown handle expecting
   `400 {"error":"InvalidRequest"}` and for a bogus verb expecting
   `404 {"error":"public_endpoint_unavailable"}`.

5. **`SwanHTTPServer.publicHandleResolution` is `public`.** It follows the
   surrounding capability properties, but it does mean the capability type and its
   `init(controlStore:)` are part of SwanHTTP's public API. The resolving method
   itself is internal, so an external caller can construct the capability but
   cannot query it.

---

# Fix round — commit `c148cae0f9a8`

Three IMPORTANT findings from two independent reviewers. All three are fixed;
none is disputed. Reviewer finding #1's own suggested resolution ("needs an
explicit accept") is **not** what I did — I removed the need for an accept by
complying with the brief instead, because the widening it describes is real and
narrowing costs nothing in production.

Files changed: `Sources/SwanHTTP/SwanPublicRepositoryReadXRPC.swift`,
`Sources/SwanHTTP/SwanHTTP.swift`,
`Tests/SwanHTTPTests/PublicHandleResolutionHTTPTests.swift`.

## Finding 1 — registration was not in `registerPublicRepositoryReadEndpoints`

**Fixed by complying.** `registerPublicRepositoryReadEndpoints` gained two
parameters:

```swift
handleResolution: SwanPublicHandleResolutionCapability? = nil,
handleResolutionAdmission: PublicRepositoryJSONReadAdmission =
    publicHandleResolutionAdmission
```

and calls `registerPublicHandleResolutionEndpoint` at its end when the
capability is present. `buildRouter` no longer has a separate registration
block; it passes `handleResolution: publicHandleResolution` into the existing
`if let publicRepositoryReadDirectory` call
(`Sources/SwanHTTP/SwanHTTP.swift:952-966`).

The reviewer was right on both counts, and I want to record that my original
justification was partly wrong:

- The route's *existence* is now keyed on the public read directory, so an
  embedding with a control store but no public read surface no longer serves an
  anonymous handle→DID existence/active oracle. That was the real substance of
  the finding.
- The reviewer's correction of my reasoning is accurate. I claimed
  `testResolveHandleDoesNotRequireGenerationAdmission` forbade the coupling. It
  does not: that test installs a directory that is *present* and refuses every
  call, so it constrains dependence on the directory's **health**, not on its
  **presence**. Those are different couplings and I conflated them. The health
  independence — the whole point of shipping this ahead of W1 — is untouched:
  the handler still never calls the directory, never admits a generation, and
  the test still asserts 503 from three repository routes and 200 from
  resolveHandle in the same router.

To make that independence impossible to lose by accident, the test fixture's
**default** read directory is now `PermanentlyUnadmittablePublicReadDirectory()`
rather than `nil`. Every case in the file therefore runs on a server whose
repository reads are permanently dark, so no case can pass by depending on a
healthy directory.

Production is unchanged: `SwanCommand.makeServer` passes
`publicRepositoryReadDirectory: directory` unconditionally
(`Sources/swan/SwanCommand.swift:965`) — it is not behind a `--enable-public-*`
flag — so resolveHandle stays live on the deployed service.

New test: `testResolveHandleIsAbsentWithoutAPublicReadDirectory` — a server with
a control store and no read directory answers `404
{"error":"public_endpoint_unavailable"}` for the NSID.
`testResolveHandleIsAbsentWithoutAnAccountControlStore` still pins the other
half.

## Finding 2 — NSID was missing from `publicReadNSIDs`

**Fixed by complying, without reintroducing the hole the omission avoided.**
`"com.atproto.identity.resolveHandle"` is now a member of `publicReadNSIDs`
(`SwanPublicRepositoryReadXRPC.swift:24`), and the single consumer became
capability-aware:

```swift
func isInstalledPublicReadMethod(
    _ nsid: String,
    handleResolutionInstalled: Bool
) -> Bool {
    guard publicReadNSIDs.contains(nsid) else { return false }
    return nsid != resolveHandleNSID || handleResolutionInstalled
}
```

`isInstalledPublicHandleResolutionMethod` is deleted; the descriptor loop in
`buildRouter` now has one block instead of two, passing
`handleResolutionInstalled: publicHandleResolution != nil`.

This is correct in all four capability combinations, which was the whole content
of the original objection:

| read directory | control store | route registered | unavailable gate installed |
|---|---|---|---|
| no | no | no | yes (route absent, gate correct) |
| no | yes | no | yes |
| yes | no | no | **yes** — the case the old membership would have broken |
| yes | yes | yes | no (live route answers) |

Still inert today: no profile in `SwanPublicWire` declares any
`com.atproto.identity.*` method, so no descriptor reaches either branch. The set
now means what its name says, and the exception is expressed once, in the
predicate, with a doc comment forbidding direct use of the set.

## Finding 3 — unmetered anonymous path into the control-database gate

**Fixed.** This was the only finding with a live production consequence, and the
scenario as written is reachable: `activeDID` →
`SQLiteControlDatabase.account(canonicalHandle:)` → `withConnectionGate` →
`ControlSQLiteConnectionGate.acquire()`, which is depth-1 and throws
`SwanError.unavailable("control database admission capacity is exhausted")` at
whichever caller arrives once `maximumQueuedWaiters` (128) is reached — including
a `createSession` or a DPoP/token lookup. Concurrency on the route was bounded
only by `SwanHTTPConfiguration.maximumConnections` (256, never overridden).

The route now reserves before touching the store:

```swift
guard let lease = admission.reserve(
    maximumResponseBytes: resolveHandleMaximumResponseBytes
) else {
    return publicReadUnavailable(
        reason: PublicReadHandlerGuard.responseAdmissionExhausted.rawValue,
        method: resolveHandleNSID,
        selector: selector
    )
}
defer { lease.release() }
```

from a **dedicated** `PublicRepositoryJSONReadAdmission`
(`publicHandleResolutionAdmission`, `maximumConcurrentReads: 8`), not
`.processShared`. That keeps both properties the reviewer asked for:

- **Bounded** — at most 8 anonymous requests can be inside the control gate at
  once, exactly the ceiling anonymous traffic already had through the shared read
  admission before this route existed. 8 ≪ 128, so this route can no longer be
  the reason the gate refuses a login.
- **Not starvable by `listRecords`** — it is a separate instance, so a fully
  reserved 16 MiB repository read budget cannot deny handle resolution. That
  property is still pinned by
  `testResolveHandleAnswersWithTheJSONReadBudgetFullyReserved`, which drains a
  1-read shared admission and still expects 200.

Two honest notes on the choice:

- The byte dimension of the reused admission is inert here. Its initializer
  requires `maximumReservedResponseBytes >= maximumListRecordsResponseBytes`
  (16 MiB), and this route reserves 4 KiB, so only the concurrency dimension
  binds. I reused the type rather than writing a second limiter because the task
  constraints say to consume existing machinery; the doc comment says plainly
  which dimension is doing the work.
- The lease is released by `defer` at the end of the `do` block rather than
  handed to `publicReadJSON`. The 4 KiB body is encoded eagerly, so the
  reservation covers exactly what needs covering — the storage call and the
  encode — and every exit path (200, 400, 503, thrown) releases through one
  statement. `PublicRepositoryJSONReadLease.release()` is idempotent, so this
  cannot double-release.

The client-visible body on exhaustion is the unchanged
`503 {"error":"temporarily_unavailable"}`; the new information is the existing
`responseAdmissionExhausted` guard token in the server-side journal — no new
`PublicReadUnavailableReason` case, so the golden list is still untouched.

New test: `testResolveHandleBoundsConcurrentControlStoreAdmission` builds a bare
router with a 1-slot admission and asserts, in order: 200 with the bound free →
`XCTUnwrap` an outstanding lease → 503 with the exact body → `activeLeases == 1`
(the route did not take one it could not get) → release → 200 again →
`activeLeases == 0` (no leak). Both directions are covered, so neither "never
reserves" nor "never releases" can pass it.

## Verification

```
xcrun --toolchain XcodeDefault swift build --build-tests    # BUILD_EXIT=0, 0 "error:" lines
xcrun --toolchain XcodeDefault swift test --skip-build --filter PublicHandleResolutionHTTPTests
    # EXIT=0, 15 "Test Case '-[...]'" starts, 15 passed, 0 failed
xcrun --toolchain XcodeDefault swift test --skip-build      # SUITE_EXIT=0
    # 1453 "Test Case '-[...]' passed", 0 "... failed", 0 "Some test targets reported failures"
```

Output redirected to files, never piped through `tail`; exit codes captured with
`echo $? > …` from a detached shell. The filtered run was checked for a non-zero
count so the filter cannot have silently matched nothing. The full suite was
re-run *after* the final source edit and rebuild, so the reported numbers
correspond to the committed tree.

No `swiftformat`. No mutating git — `jj describe` + `jj new` only. No file
deleted.

## What the fix round did **not** change

- The handler's behaviour on every input the previous round pinned: 200 shape and
  exact body, 400 `InvalidRequest` for unknown/malformed/non-active/DID-as-handle,
  case folding, wrong-method 404s, the `com.atproto.identity.*` namespace guard,
  and independence from generation admission. All 13 original cases still pass
  unmodified.
- Phase 1 proxying, credential isolation, and peer pinning.
- The public-read 503 body.
- `PublicReadUnavailableReason` and its golden list.

## Concerns after the fix round

1. **Original Concern #1 is resolved**, not merely accepted: the anonymous
   surface no longer widens on an embedding that configured a control store for
   its own login and no public reads.
2. **New, small:** an operator who wants public reads *off* but handle
   resolution *on* now has no way to express that. I judge that the right
   default (allow-list at the trust boundary; the brief's design), but it is a
   real configuration that is no longer reachable. If it is ever wanted, the seam
   is one call-site parameter in `buildRouter`.
3. **8 concurrent reads is a judgement call**, chosen to match the ceiling
   anonymous traffic already had rather than derived from a measurement. It is
   two orders below the gate's 128-waiter failure point and above any plausible
   legitimate concurrency for a single-connection control database, but nothing
   in the tree measures the real arrival rate.
4. Original Concerns #2 (`.desynchronized` / `.throttled` do not resolve), #3
   (`.deleting` / `.deleted` covered only at the capability), #4 (no live
   verification against swan.catbird.blue), and #5 (`publicHandleResolution` is
   `public` API) are unchanged and still stand.
