# Task 6 — Route before authenticating

**Status:** DONE
**Commit:** `310c32cf3519` — `SwanHTTP: route before authenticating so missing routes 404`
(2 files, +335 −26. The report itself is under `.superpowers/`, which is gitignored in
this repo, so it is on disk but deliberately not in the commit.)
**Baseline:** suite exit 0, HEAD `04c68d89fb0a`, 1434 passed
**After:** suite exit 0, **1438** passed, 0 failed, 0 `Some test targets reported failures`, 11/11 xctest bundles reported `passed`

---

## What changed

### `Sources/SwanHTTP/SwanXRPCPipethrough.swift` (`handleSwanXRPCPipethrough`)

The routing block (`pipethroughProxyHeader` + `SwanXRPCProxyRouter(...).route(...)` +
the `.denied`/`.unrouted` → 404, `.malformedProxyHeader` → 400 switch) moved from
below `authorizedPipethroughSubject` to immediately above it. Nothing else in the
handler moved. Step comments renumbered to match the new order:

| step | before | after |
|---|---|---|
| 1 | NSID parse | NSID parse |
| 2 | **authentication** | **routing** (pure) |
| 3 | routing | **authentication** |
| 3b → 4 | query admission | query admission |
| — | body buffer, concurrency lease | body buffer, concurrency lease |
| 4 → 5 | endpoint selection (**first network I/O**) | endpoint selection (**first network I/O**) |
| 5 → 6 | service token | service token |
| 6 → 7 | outbound request build | outbound request build |
| 7 → 8 | peer-pinned send | peer-pinned send |

The two comment blocks that asserted the old ordering as a *safety property*
("Authentication comes before routing … so an anonymous caller can never make Swan
open a socket") were rewritten rather than deleted, because the property is still
true and still load-bearing — it is just now carried by step 3 sitting above step 5
rather than above step 2. The new comment states explicitly why routing may run
first (`SwanXRPCProxyRouter` is pure; `pipethroughProxyHeader` reads one inbound
header and takes no trust decision) and names the resolver as the first step that
can reach the network.

No behaviour changed for authenticated requests. No error body changed. No route
registration, profile iteration, capability gating, proxying, credential isolation,
or peer-pinning was touched.

### `Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift`

Four tests added, plus two instrumented doubles.

**New test-double machinery**

- `PipethroughCallRecorder` — an `NSLock`-guarded counter, the counting sibling of
  the existing `PipethroughFlag`. Needed because the central claim of this task is
  *ordering*, and ordering is invisible to a status-code assertion: "404 because the
  router refused it" and "404 because the authorizer succeeded and then the router
  refused it" are the same response.
- `PipethroughAuthorizer` gained `attempts: PipethroughCallRecorder` (defaulted, so
  all 20-odd existing call sites are unchanged), incremented in
  `authorizePipethrough` only — not in `issuePipethroughNonce`, not in
  `authorizeActorPreferences`.
- `StubDIDDocuments` gained `fetches: PipethroughCallRecorder` (also defaulted),
  incremented in `documentJSON(forDID:)`. Resolution is the first step that opens a
  socket in production, so "was the resolver reached" is the observable stand-in for
  "did an anonymous caller cause outbound work".

**Tests**

1. `testUnknownNSIDReturns404NotUnauthorized` — anonymous (authorizer returns
   `.failure(.denied)`, the shape `SwanOAuthResourceAuthorizer` produces for a
   credential-less request) against four unimplemented NSIDs. Asserts `.notFound`
   **and** the exact body `{"error":"EndpointUnavailable"}` (so the 404 is provably
   the route surface's own opaque shape, not some other layer answering by
   coincidence), **and** `attempts.count == 0`, **and** zero outbound requests.

2. `testDeniedNamespaceReturns404WithoutTouchingCredentials` — `blue.catbird.*`,
   `com.atproto.space.*` (prefix denials) and `app.bsky.actor.getPreferences`
   (exact-NSID denial), each with an `atproto-proxy` header naming an attacker
   service. Deliberately uses a **succeeding** authorizer: a status-only assertion
   would pass either way, so the discriminating assertion is `attempts.count == 0`.
   Also re-asserts the identical `EndpointUnavailable` body across denied and
   unrouted, i.e. the existing non-enumerability property survives.

3. `testAnonymousCallerStillCannotCauseAnOutboundConnection` — the invariant the
   reordering must preserve. Three anonymous requests, all in proxyable namespaces:
   a resolve-path GET (`app.bsky.feed.getFeedSkeleton` with
   `atproto-proxy: did:web:feeds.example#bsky_fg`, and the DID document is stubbed to
   genuinely resolve, so an ordering mistake shows up as real work rather than as a
   400 for want of an endpoint), a default-AppView GET, and a POST with a body.
   Asserts 401 on each, `attempts.count == 3` (proving routing let them through to
   the authorizer, so the test is not passing for an unrelated 404), `fetches.count
   == 0`, and zero outbound requests.

4. `testProductionRouterAnswers404NotUnauthorizedToAnAnonymousProbe` — **not in the
   brief; added deliberately.** Builds the real `SwanHTTPServer` from the loaded
   `permissioned-data-0016-2026-07-30` profile with a denying pipethrough authorizer
   and probes `com.atproto.identity.resolveHandle`, `com.atproto.server.createSession`,
   `com.atproto.admin.getAccountInfo`, `com.atproto.temp.checkSignupQueue`, and
   `com.example.unknown.method` anonymously, plus `app.bsky.feed.getTimeline` as the
   counterpart that must still be 401. Rationale: the operational symptom this task
   exists to fix is a 401 from `buildRouter()`'s *composed* surface, and a
   capability-only test cannot demonstrate that, because it cannot show the fallback
   still being reached after every local registration has had its chance. Under
   falsification this test reported all five probes as 401 — the exact production
   symptom — which a capability-only test would only have shown by analogy.

---

## Ambiguity in the brief, and how it was resolved

- **The brief's test bodies 2 and 3 were empty stubs** (a comment and nothing else).
  Written in full, per the task instruction. In both cases the assertion that
  actually carries the claim is a call-count, not a status code — see above.

- **"No Authorization header"** cannot be expressed literally through this test
  harness: the authorizer is injected as a protocol double and never inspects
  `request.headers`. Modelled as `PipethroughAuthorizer(result: .failure(.denied))`,
  which is the outcome `SwanOAuthResourceAuthorizer` produces for a credential-less
  request. Test 4 gives this the production-router treatment so the modelling choice
  is not load-bearing on its own.

- **The brief names `com.atproto.identity.resolveHandle` as the 404 example.** It is,
  through the pipethrough fallback and through the composed production router (test 4
  confirms both). Note that `com.atproto.repo.*` and `com.atproto.sync.*` unknowns
  were *already* 404 in the composed router via
  `registerUnknownPublicEndpointGuards`, which wins in the trie — so those two
  namespaces are not part of what this change fixes. What it fixes is everything
  else that fell through to `/xrpc/**`: `com.atproto.identity.*`,
  `com.atproto.server.*`, `com.atproto.admin.*`, `com.atproto.temp.*`, and any
  unrecognised namespace. Probe NSIDs were chosen accordingly.

- **Brief line numbers (`:302, 317-349`)** matched the file as found; no drift.

---

## Falsification

Three independent breaks, each built and run, each restored by byte-identical file
copy afterwards (`diff -q` clean, `grep -c FALSIFICATION` → 0).

### A. Revert the ordering (authentication hoisted back above routing)

Expected: the two new 404 tests fail on status and on `attempts.count`; the invariant
test still passes (it constrains a property the old order also satisfied).

Observed, exactly:

```
testUnknownNSIDReturns404NotUnauthorized      FAILED
  ("401 Unauthorized") is not equal to ("404 Not Found")  ×4 URIs
  ("{"error":"Unauthorized"}") is not equal to ("{"error":"EndpointUnavailable"}")  ×4
  ("4") is not equal to ("0")            ← attempts.count
testDeniedNamespaceReturns404WithoutTouchingCredentials  FAILED
  ("3") is not equal to ("0")            ← attempts.count
testAnonymousCallerStillCannotCauseAnOutboundConnection  passed   (as predicted)
```

And against test 4, through the real production router:

```
testProductionRouterAnswers404NotUnauthorizedToAnAnonymousProbe  FAILED
  ("401 Unauthorized") is not equal to ("404 Not Found")   ×5 probes
  ("6") is not equal to ("1")            ← attempts.count
```

### B. Hoist the endpoint resolver above authentication

The invariant test passed both before and after the real change, so it had to be
shown non-vacuous. Moved the step-5 endpoint-selection `switch` above step 3, leaving
everything else alone.

Expected: `testAnonymousCallerStillCannotCauseAnOutboundConnection` fails on
`fetches.count`, and on that assertion specifically — not on the status codes, which
stay 401 either way.

Observed, exactly:

```
testAnonymousCallerStillCannotCauseAnOutboundConnection  FAILED
  SwanXRPCPipethroughTests.swift:1243: ("1") is not equal to ("0")   ← fetches.count
```

Line 1243 is `XCTAssertEqual(fetches.count, 0)`. The anonymous caller caused exactly
one DID-document fetch. The invariant test bites.

### C. (implicit) The tests were red before the implementation

Written and run before the source change: tests 1 and 2 failed with the same
signatures as falsification A; test 3 passed, as a preserved invariant should.

---

## Exact commands and results

```bash
xcrun --toolchain XcodeDefault swift build --build-tests          # exit 0

# Brief's three tests, filter verified to match (3 named cases in output)
xcrun --toolchain XcodeDefault swift test --skip-build \
  --filter "SwanXRPCPipethroughTests/(testUnknownNSIDReturns404NotUnauthorized|testDeniedNamespaceReturns404WithoutTouchingCredentials|testAnonymousCallerStillCannotCauseAnOutboundConnection)"
# before implementation: exit 1 — 2 failed, 1 passed
# after  implementation: exit 0 — 3 passed

xcrun --toolchain XcodeDefault swift test --skip-build \
  --filter "SwanXRPCPipethroughTests/testProductionRouterAnswers404NotUnauthorizedToAnAnonymousProbe"
# exit 0 — 1 passed (filter matched, case name present in output)

xcrun --toolchain XcodeDefault swift test --skip-build > suite.log 2>&1
# SUITE_EXIT=0
```

Full suite, judged by exit code and by grep, output redirected to a file and never
piped through `tail`:

| metric | value |
|---|---|
| suite exit code | **0** |
| `Test Case '-[...]' passed` lines | **1438** (baseline 1434 + 4 new) |
| `Test Case '-[...]' failed` lines | 0 |
| `Some test targets reported failures` | 0 occurrences |
| `Test Suite '<name>.xctest' passed` | 11 of 11 bundles — no target crashed and truncated the log |

All four new cases confirmed present as `passed` in the full-suite log, not only
under the filter.

`swift build` was never run bare; `swiftformat` was never run. Every filter was
verified to have matched by reading the named test cases back out of the log.

---

## Deliberately not done

- **No relay activation.** Out of scope by instruction and untouched.
- **No new sync methods.** Indigo's relay makes three outbound XRPC calls and needs
  none of `listRepos`/`getRepo`/`getBlocks`/`getRecord`/`listBlobs`; nothing here adds
  route registrations of any kind.
- **`com.atproto.sync.getBlob` registered inside the mutation block** (avatar/image
  serving dies when `--enable-public-repository-mutations` is off) — a real bug, but
  it is a route-*registration* defect, not a route-*ordering* one. Not touched; it
  belongs to a later W2 task.
- **`--profile` being inert on the public side** (hardcoded `PublicDataTesting20260727`
  iteration) — same reasoning. Not touched.
- **No new `PublicReadUnavailableReason` case**, so the golden list in
  `testJournalTokensMatchTheGoldenList` needed no update. This task never reaches the
  public-read path.
- **No error-body widening.** The public-read 503 body is untouched; the pipethrough's
  own bodies are byte-identical to before.

---

## Concerns

1. **A new, narrow observable distinction for anonymous callers.** Previously every
   NSID reaching `/xrpc/**` answered 401 to an anonymous prober. Now a *proxyable*
   NSID answers 401 and a non-proxyable one answers 404, so an anonymous prober can
   read off the proxyable set. I judge this acceptable and worth stating explicitly:
   the property the design actually protects — that `.denied` and `.unrouted` are
   indistinguishable, so Swan's *reserved* namespaces cannot be enumerated — is
   preserved and now directly asserted (test 2 pins the identical
   `EndpointUnavailable` body across both). The proxyable set is a static
   compile-time allow-list (`app.bsky.`, `chat.bsky.`, `tools.ozone.`, plus two exact
   `com.atproto.*` NSIDs) in open-source code, so it discloses nothing that reading
   the repo would not. Flagging it because it is a genuine change in what an
   unauthenticated observer can learn, and reviewers should agree rather than
   discover it.

2. **Two failure modes moved from 401 to 400 for anonymous callers**: a malformed
   `atproto-proxy` header and a duplicated one are now decided before authentication.
   Neither reads a credential, opens a socket, buffers a body, or takes a concurrency
   slot, and both were already 400 for authenticated callers. Existing tests
   (`testMalformedProxyHeaderIsRejectedWithoutContactingUpstream`,
   `testDuplicateProxyHeaderIsRejectedWithoutContactingUpstream`,
   `testConflictingDuplicateProxyHeadersAreRejected`) still pass unchanged.

3. **The 404 surface is still not complete after this task.** This change fixes the
   `/xrpc/**` fallback only. NSIDs that have a *local* registration still answer that
   registration's shape — e.g. `com.atproto.repo.getRecord` answers 503
   `public_data_pending`, `com.atproto.space.getSpace` answers 503
   `permissioned_data_pending`, and unknown `com.atproto.repo.*`/`com.atproto.sync.*`
   answer 404 `public_endpoint_unavailable`. So "every unimplemented NSID now 404s
   with one body" is *not* true, and Tasks 7-10 should not assume it. What is now
   true: nothing that falls through to the pipethrough answers 401 for want of a
   route.

4. **The three concurrency/ordering assertions rest on `NSLock`-guarded counters
   read after `app.test(.live)` returns.** Each test issues its requests
   sequentially on one connection and reads the counters only after the closure
   completes, so there is no read-during-write window. Called out because
   `SwanXRPCPipethroughTests` has a documented history of teardown races
   (`testParserRefusedQueryBytesNeverReachTheHandler`'s `NIOAsyncWriter` note); none
   of the new tests throw from inside `client.execute`, which is what triggers that
   path, and the full suite was run to completion with all 11 bundles reporting.

---

## Files touched

- `/Users/joshlacalamito/Developer/Catbird+Petrel/Swan/Sources/SwanHTTP/SwanXRPCPipethrough.swift`
- `/Users/joshlacalamito/Developer/Catbird+Petrel/Swan/Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift`
