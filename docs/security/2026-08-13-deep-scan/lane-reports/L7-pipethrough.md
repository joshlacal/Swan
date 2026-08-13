# Lane L7 — pipethrough hygiene (F35, F07)

- **Workspace:** `/Users/joshlacalamito/Developer/Catbird+Petrel/Swan-L7-pipethrough`
- **Base commit:** `c1a71eb38adf` ("Swan: merge the L6, L10 and L11 security lanes")
- **Logs:** `/private/tmp/swan-lane-L7-pipethrough/`
- **Status:** DONE. Build clean, full macOS suite green on a clean re-run.

## ⚠️ Client-visible behaviour change on a live federated endpoint

**Swan's XRPC pipethrough no longer forwards the upstream `Location` header.**
A client calling `/xrpc/...` with an `atproto-proxy` header that hits an
upstream 3xx now receives the same 3xx **status** with **no `Location`**, so the
redirect is not followable. `content-type` is still forwarded; `cache-control:
no-store` is still set. No status code, error name or error body changed.

This was filed as needing Josh's decision (program §4 item 7). The standing
recommendation was "drop it"; the brief instructed me to proceed on that
default. **This was made on the recommended default, not on an explicit
answer.** It is a one-line revert (`("location", .location)` back into the
`forwarded` table in `pipethroughResponse`) plus re-inverting one test.

The concrete case that is lost is an upstream absolute redirect to a CDN — that
is what the pre-existing test was written around. The case that motivated the
change is a *relative* `Location` (`/xrpc/com.atproto.server.createSession`,
`../admin`): resolved against the request URL by a following client, it re-enters
`swan.place` carrying Swan credentials, at a path a third-party upstream chose.
That is why this is not filed as a classic open redirect.

Per the brief I did **not** add a same-host restriction as an alternative: it
forbids the CDN case the existing test invents and has no principled boundary.

---

## What I verified independently

### The upstream citation (F35) — brief was correct

The brief asked me to cite parity with
`atproto/packages/pds/src/pipethrough.ts:527-531` and not to take the line
numbers on faith. I checked the pinned checkout at
`/Users/joshlacalamito/Developer/Catbird+Petrel/atproto/packages/pds/src/pipethrough.ts`:

- `527`–`531` is exactly `const RES_HEADERS_TO_FORWARD = [ 'atproto-repo-rev',
  'atproto-content-labelers', 'retry-after', ]`.
- The `content-*` family is forwarded by the `responseHeaders` generator
  immediately below (lines 534–549: `content-length`, `content-encoding`,
  `content-type`, `content-language`).
- `grep -n 'Location\|location'` over the whole file returns only
  `content-type` / `content-encoding` / `content-length` hits. There is no
  `location` anywhere in upstream's forward path.

So Swan's post-change forwarded set (`content-type` only) is a strict subset of
upstream's. I wrote that shape into the comment rather than copying the brief's
sentence.

### The Swan line-number citations — brief was correct

- `SwanXRPCPipethrough.swift:724` was `("location", .location)`; the comment was
  at `:718-721`. Both correct.
- `SwanXRPCPipethroughTests.swift`: the test body ran `884–914`; the doc comment
  starts at `881`. The brief said `884-914`, which is the body, not the comment.
  Immaterial.
- `SwanServiceEndpointResolver.swift`: `Document` at `:21-28`, the decode guard
  at `:43-45`, `services.first(where:)` at `:47-50`. All correct.

### Blast radius of requiring `document.id`

`SwanServiceEndpointResolver` / `SwanDIDDocumentFetching` have exactly three
consumers (`grep -rn --include='*.swift'` over `Sources` + `Tests`):
`Sources/SwanHTTP/SwanXRPCPipethrough.swift:403`,
`Sources/swan/SwanCommand.swift:2808` (construction only), and the two test
files. Every DID-document fixture in `SwanXRPCPipethroughTests.swift`
(8 of them, at lines 407/439/561/932/987/1047/1187/1382) already carried a
top-level `"id"` matching its dictionary key, so no fixture needed changing —
which is also why the pipethrough suite passes unmodified.

The DID reaching `endpoint(did:fragment:)` comes straight from the
`atproto-proxy` request header with no case folding or normalisation applied
along the way (`SwanXRPCPipethrough.swift:399-403`), so an exact string
comparison against `document.id` is the right comparison.

## What I changed

### `Sources/SwanHTTP/SwanXRPCPipethrough.swift` (F35)

Removed `("location", .location)` from the `forwarded` table in
`pipethroughResponse`. Rewrote the comment to cite the upstream parity above and
to state the relative-`Location`-steering framing and the rejected same-host
alternative.

### `Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift` (F35)

Renamed `testUpstreamLocationIsForwardedAndOtherHeadersAreNot` →
`testUpstreamLocationIsNotForwardedAndNeitherAreOtherHeaders` and inverted the
`Location` assertion to `XCTAssertNil`. The existing `Set-Cookie` assertion
(`XCTAssertNil(response.headers[.setCookie])`), the `content-type` assertion and
the `sender.recorded().count == 1` assertion are kept verbatim. I extended it to
loop over two upstream `Location` values — the original absolute CDN URL and a
relative `/xrpc/com.atproto.server.createSession` — so the case that actually
motivates the change is the one under test. The 302 status is still asserted to
reach the client.

### `Sources/SwanOAuth/SwanServiceEndpointResolver.swift` (F07)

1. Added `let id: String?` to `Document`. Optional so an `id`-less document
   decodes and is then rejected by the explicit guard, instead of failing decode
   and reaching the same answer by a different route.
2. Added `guard document.id == did` — byte-exact against the DID string as
   received, with a comment recording why normalising would be wrong (`%3A` port
   encoding and host case legitimately vary in `did:web`; any normalisation here
   would be a second, weaker grammar than the one
   `SwanPeerPinnedDIDDocumentFetcher` already used to derive the fetch URL).
3. Replaced `services.first(where:)` with `services.filter { ... }` +
   `guard matches.count == 1`.

### `Tests/SwanOAuthTests/SwanServiceEndpointResolverTests.swift` (F07)

Seven new tests:

| Test | Asserts |
|---|---|
| `testDocumentForADifferentSubjectIsRejected` | id mismatch → `.unresolvableService` |
| `testPercentEncodedPortDIDMatchesExactly` | `did:web:x.example%3A8443` resolves against an identically-spelled `id` |
| `testDecodedPortSpellingDoesNotMatchEncodedDocumentID` | the decoded spelling of the same authority does **not** match — pins the no-normalisation decision so a later "helpful" normalisation fails loudly |
| `testDocumentWithoutAnIDIsRejected` | absent `id` → rejected |
| `testDuplicateServiceIDsAreRejected` | two `#bsky_appview` entries → rejected |
| `testFragmentDeclaredBothShortAndFullyQualifiedIsRejected` | `#frag` + `did:...#frag` is the same id, also rejected |
| `testDuplicateOnAnUnrelatedFragmentStillResolves` | a duplicate on `#other` does not deny `#bsky_appview` |

**Decision on a nil/absent `id`: rejected.** `id` is required by DID Core, so a
document that will not name its own subject is malformed rather than
permissive, and the entire point of F07 is that the fetch path proves *where* a
document came from but not *whose* it is. Accepting an `id`-less document would
leave an opt-out of the binding that any hostile `did:web` host could take.

Not done, per the brief: no PLC audit-chain verification inline. I agree with
the refusal — two extra HTTPS fetches plus chain verification on every
third-party pipethrough request is the wrong place for it.

## Commands run, and their results

Scratch dir `/private/tmp/swan-lane-L7-pipethrough/` (this lane only).

```
xcrun --toolchain XcodeDefault swift build --build-tests
  → exit 0,  grep -cE 'error:' build.log = 0
  → /private/tmp/swan-lane-L7-pipethrough/build.log

xcrun --toolchain XcodeDefault swift test --skip-build      # run 1
  → exit 1
  → grep -c "Some test targets reported failures" = 1
  → grep -cE "^Test Case .* passed"                = 1577
  → 1 failure, unrelated (see below)
  → /private/tmp/swan-lane-L7-pipethrough/test-full.log

xcrun --toolchain XcodeDefault swift test --skip-build \
  --filter NIOPeerPinnedOAuthPostTransportTests/testPostTransportRejectsResponseBeyondConfiguredBound
  → 3 consecutive runs, each exit 0, failure-string 0, 1 test passed
  → retry-1.log, retry-2.log, retry-3.log

xcrun --toolchain XcodeDefault swift test --skip-build      # run 2, full suite
  → exit 0
  → grep -c "Some test targets reported failures" = 0
  → grep -cE "^Test Case .* passed"                = 1578
  → grep -cE "^Test Case .* failed"                = 0
  → /private/tmp/swan-lane-L7-pipethrough/test-full-2.log
```

`grep -c '"identity"' Package.resolved` = **35** (unchanged; no container run
was performed in this lane).

### The run-1 failure

```
SwanOAuthTests.NIOPeerPinnedOAuthPostTransportTests
  testPostTransportRejectsResponseBeyondConfiguredBound
  Sources/SwanOAuth/NIOPeerPinnedOAuthPostTransport.swift:221:
    failed: caught error: "I/O on closed channel"   (9.078 seconds)
```

A loopback-socket race in a file this lane does not touch and does not link
against differently — my diff is confined to the pipethrough response-header
table and the DID-document decode. It passed 3/3 in isolation and 1/1 on the
clean full re-run. Five lanes were building and testing on this machine
concurrently, which is the likeliest cause of the 9-second stall. I am recording
it rather than suppressing it: **run 1 was not green**, and the green result I
am reporting is run 2.

## Disagreements / notes for the brief's author

1. **Scope of the duplicate-id rejection.** The brief says "rejecting a document
   that declares duplicate service ids". I implemented the narrower reading it
   also states — "a filter that requires exactly one match" — so a duplicate on
   an *unrelated* fragment does not deny the requested one. Rejecting the whole
   document on any duplicate anywhere is defensible but strictly more
   deny-prone for no gain against this threat: the ambiguity that can be
   exploited is the one in the selection. `testDuplicateOnAnUnrelatedFragment
   StillResolves` pins this choice, so flipping it later is a one-test change.
   Flagging it because the two readings differ.
2. **The brief's `Tests/.../SwanXRPCPipethroughTests.swift:884-914` citation**
   is the test body; the doc comment I was asked to rewrite starts at `881`.
   Everything else the brief cited was exact.
3. **F35 remains a decision, not a finding.** I proceeded on the recommended
   default as instructed, but nothing in the code or the upstream comparison
   settles whether Swan wants to keep the absolute-CDN-redirect case. If the
   answer comes back "keep it", revert the one table entry.

## Open questions

- Does Josh accept the `Location` drop? It is live-federated client-visible and
  was explicitly flagged as needing his call.
- Should the duplicate-service-id rejection be document-wide rather than
  scoped to the requested fragment? (See disagreement 1.)
