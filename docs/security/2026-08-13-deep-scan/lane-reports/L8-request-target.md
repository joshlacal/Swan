# Lane L8 — outbound request-target construction (F22 residual)

**Workspace:** `/Users/joshlacalamito/Developer/Catbird+Petrel/Swan-L8-request-target`
**Base commit:** `c1a71eb38adf`
**Date:** 2026-08-13
**Status:** DONE — build clean, full macOS suite green.

---

## 1. Independent confirmation of the NIO validator claim (F22 refutation)

**CONFIRMED.** The brief's claim holds against the pinned checkout.

Evidence, read from this workspace's own resolved checkout
(`.build/checkouts/swift-nio`, swift-nio **2.101.3**, revision
`0b18836bd8b0162e7e17a995a3fbee20ed8f3b2b` per `Package.resolved`):

1. All four Swan client pipelines call
   `channel.pipeline.syncOperations.addHTTPClientHandlers()` with no arguments
   (`grep -rn "addHTTPClientHandlers" Sources/` → `SwanProxyHTTPTransport.swift:291`,
   `NIOPeerPinnedOAuthDocumentTransport.swift:98`,
   `NIOPeerPinnedOAuthPostTransport.swift:169`,
   `NIOPeerPinnedATHandleHTTPTransport.swift:118`; the remaining hits are the
   doc comments this lane added). No call site passes
   `enableOutboundHeaderValidation` or an upgrader.
2. `Sources/NIOHTTP1/HTTPPipelineSetup.swift:672`, the dispatching
   `_addHTTPClientHandlers`, defaults to `enableOutboundHeaderValidation: true`
   and `upgrade: nil`, so our calls take the fast arm at line 704 onward. That
   arm builds the handler array unconditionally as
   `[requestEncoder, ByteToMessageHandler(responseDecoder), requestHeaderValidator]`
   where `requestHeaderValidator = NIOHTTPRequestHeadersValidator()`. The other
   arm, `_addHTTPClientHandlersFallback`, also appends the validator whenever
   `enableOutboundHeaderValidation` is true — so both arms install it for
   Swan's call shape.
3. `Sources/NIOHTTP1/HTTPHeaderValidator.swift:25` —
   `NIOHTTPRequestHeadersValidator.write(context:data:promise:)` guards
   `Self.uriOnlyContainsAllowedCharacters(head.uri)` and fails the write with
   `HTTPParserError.invalidHeaderToken` before forwarding. The allowed byte set
   is the RFC 9112 request-target grammar (ALPHA / DIGIT / `-._~` / gen-delims /
   sub-delims / `%`). CR, LF, NUL, SP, all CTLs and all non-ASCII are rejected.
4. Ordering is correct for this to be a control: the validator is appended
   *after* the encoder in the array, so on the outbound path (tail → head) the
   validator sees the write first and the encoder never serialises a rejected
   head. The transports add their inbound response handler after
   `addHTTPClientHandlers()`, and it is a `ChannelInboundHandler` only, so it
   does not sit between the write site and the validator.

**Conclusion:** CRLF / header injection through the outbound request target is
not reachable in these transports. F22 as originally filed stays REFUTED. This
is now written into the doc comment of both new helper functions so nobody
re-derives it from the presence of the byte guard.

## 2. What actually remained, and what I changed

The real residual was a **same-origin request-target rewrite**. All three
peer-pinned NIO transports built their origin-form target from `url.path` and
`url.query`, both of which **percent-decode**. A URL whose path contains `%2F`,
`%3F`, `%23` or `%20` was therefore pinned and policy-checked as one resource
and requested as a different one.

Positive control, asserted in the new test suite
(`testOAuthTargetKeepsPercentEncodingAndReportsDenotedURL`):

```
URL(string: "https://pds.example/a%2Fb/c%3Fd/e%23f/g%20h?q=%2Fx").path
    == "/a/b/c?d/e#f/g h"     // the old target
```

That old string also contains a literal SP, so the old code path could not even
reach the peer for such a URL — `NIOHTTPRequestHeadersValidator` would have
failed the write with `invalidHeaderToken`. The user-visible effect was a
silently different resource for `%2F`/`%3F`/`%23`, and an opaque transport
failure for `%20`.

### Changes

| File | Change |
|---|---|
| `Sources/SwanOAuth/NIOPeerPinnedOAuthDocumentTransport.swift` | New internal `OAuthOriginFormRequestTarget` + `oauthOriginFormRequestTarget(_:failure:)`; `get()` derives the target from `components.percentEncodedPath` / `percentEncodedQuery` **before** the socket is opened; `makeRequest` now takes the target instead of the URL; `uri:` on the request head is `target.uri`; the response handler is constructed with `target.denotedURL`. |
| `Sources/SwanOAuth/NIOPeerPinnedOAuthPostTransport.swift` | Same, reusing the SwanOAuth helper. |
| `Sources/SwanAccounts/NIOPeerPinnedATHandleHTTPTransport.swift` | Same, via a module-local twin `ATHandleOriginFormRequestTarget` + `atHandleOriginFormRequestTarget(_:)` that throws `ATHandleVerificationError.verificationFailed`. |
| `Tests/SwanOAuthTests/OAuthRequestTargetTests.swift` | New — 11 tests. |

The `0x21 ... 0x7E` byte guard and the 8 192-byte cap were **added** to all
three (see disagreement #1 below), matching
`SwanProxyHTTPTransport.swift:234`. Every guard site carries a comment naming
`NIOHTTPRequestHeadersValidator` as the actual control.

`Sources/SwanOAuth/SwanProxyHTTPTransport.swift` (other lane, already correct)
and `Sources/SwanOAuth/OAuthRemoteFetch.swift` /
`Sources/SwanAccounts/ATHandleVerification.swift` (other lanes) were read only,
not edited.

### `responseURL` no longer echoes the request URL

`NIOPeerPinnedOAuthDocumentTransport.swift` previously passed the request `url`
straight into the response handler, so
`OAuthRemoteFetch.swift:652` — `response.responseURL.absoluteString == url.absoluteString`
— compared a value against itself. The same was true at
`OAuthRemoteFetch.swift:820` (poster) and
`ATHandleVerification.swift:514` (handle verifier).

All three now report the URL that the **emitted target** denotes: the emitted
`uri` string is split back apart on its first `?` and reassembled into a
`URLComponents` copy of the request's origin. The single normalization is
RFC 3986 §6.2.3 — origin form requires at least `/`, and an empty path in an
http(s) URI denotes the same resource as `/`, so an empty-path request URL
still compares equal.

Honest limit of this: in the happy path the reconstruction is *equal by
construction*, so the check is a round-trip self-check on the derivation
(it catches a future edit that stops round-tripping), not an independent
observation of the wire. A fully independent check needs a
`requestTarget: String` field on `OAuthRemoteHTTPResponse` /
`ATHandleHTTPResponse` and a caller-side comparison — both live in
`OAuthRemoteFetch.swift` and `ATHandleVerification.swift`, which this lane does
**not** own. Flagged as an open question rather than made.

## 3. Tests

`Tests/SwanOAuthTests/OAuthRequestTargetTests.swift`, 11 tests:

- 5 pure-derivation tests over both helpers: `%2F`/`%3F`/`%23`/`%20` path
  survive byte-for-byte, query survives, empty path becomes `/` without
  rewriting the reported URL, query on an empty path becomes `/?q=…`.
- 6 on-the-wire tests, two per transport, against a plaintext HTTP/1.1 peer on
  `127.0.0.1:0` that records the decoded request-target verbatim
  (`RequestTargetEchoPeer`). Plaintext avoids a certificate fixture; all three
  transports permit `http` for loopback (`localhost` for the two OAuth
  transports, a loopback literal for the handle transport). Each asserts the
  received URI **and** that `responseURL.absoluteString == url.absoluteString`.

## 4. Commands actually run, and results

All logs in `/private/tmp/swan-lane-L8-request-target/`.

| Command | Log | Result |
|---|---|---|
| `xcrun --toolchain XcodeDefault swift package resolve` | `resolve.log` | exit 0; `grep -c '"identity"' Package.resolved` = **35** before and after |
| `xcrun --toolchain XcodeDefault swift build --build-tests` (sources only) | `build-1.log` | exit 0, no `error:` |
| `xcrun --toolchain XcodeDefault swift build --build-tests` (with new tests) | `build-2.log` | exit 0, no `error:` |
| `xcrun --toolchain XcodeDefault swift test --skip-build --filter OAuthRequestTargetTests` | `test-lane.log` | exit 0; `grep -cE "^Test Case .* passed"` = **11**; `Executed 11 tests, with 0 failures` |
| `xcrun --toolchain XcodeDefault swift test --skip-build` (full macOS suite) | `test-full.log` | **exit 0**; `grep -c "Some test targets reported failures"` = **0**; `grep -cE "^Test Case .* passed"` = **1582**; `grep -cE "^Test Case .* failed"` = **0**; all 11 `.xctest` bundles report `passed` |

Both test runs used `--skip-build` only after a `--build-tests` build in the
same working tree.

`swiftformat` and `swiftlint` were **not** run. No git mutation was performed.
No Docker/Linux run was performed (the brief did not ask for one), so
`Package.resolved` was never at risk from a container.

## 5. Client-visible behaviour

No status code, error name, or response body changes. Two wire-level changes,
both toward correctness:

1. **The outbound request target now preserves percent-encoding.** For a URL
   whose path or query contains `%2F`, `%3F`, `%23` or `%20`, Swan now requests
   the resource that was actually pinned. Any upstream that was (accidentally)
   depending on the decoded spelling would see a different path. No Swan-issued
   URL in the tree has such a path today: the OAuth document fetcher requests
   operator/registration `client_id` and `jwks_uri` URLs, the poster requests
   configured notification endpoints, the handle transport requests
   `/.well-known/atproto-did`.
2. **New fail-closed rejections before any socket is opened**, for a URL whose
   percent-encoded target is not origin-form, exceeds 8 192 bytes, or contains
   a byte outside `0x21…0x7E`. Errors reuse the existing types:
   `SwanError.malformed("OAuth document request target is invalid")`,
   `SwanError.malformed("notification request target is invalid")`,
   `ATHandleVerificationError.verificationFailed`. Previously such a request
   opened a TCP/TLS connection first and then failed at NIO's validator with an
   opaque `unavailable`. The 503 body `{"error":"temporarily_unavailable"}` is
   untouched.

Edge case worth recording: a request URL with a bare trailing `?` (empty query)
emits a target with no `?` — same as before this change, and same as
`SwanProxyHTTPTransport` — and now reports a `responseURL` with no `?`, so the
callers' exact-URL comparison would reject it. That is fail-closed and no such
URL exists in the tree, but it is a behaviour delta.

## 6. Disagreements with the brief

1. **"Keep the existing `0x21...0x7E` charset guard" — there was no existing
   guard in any of the three files I own.** Proof, run at base
   `c1a71eb38adf`: `grep -rn "0x21" Sources/` returns **36** hits across the
   tree (positive control — `SwanProxyHTTPTransport.swift:234`,
   `OAuthProofValidation.swift:20`, `SwanCore.swift:202`, and 33 more — each
   file checked individually with
   `jj file show -r c1a71eb38adf <path> | grep -c 0x21`), and
   **none** of them is in `NIOPeerPinnedOAuthDocumentTransport.swift`,
   `NIOPeerPinnedOAuthPostTransport.swift`, or
   `NIOPeerPinnedATHandleHTTPTransport.swift`. I **added** the guard rather
   than keeping one, which is what "symmetry with `SwanProxyHTTPTransport`"
   requires. This is why item 5 lists new rejections.

2. **Three line-number citations are off.**
   - `SwanProxyHTTPTransport.swift:227-229` for the charset guard — the guard
     is at **234-236**; 225-233 is the percent-encoded target derivation.
   - `OAuthRemoteFetch.swift:607` for the exact-URL comparison — it is at
     **652**, and there is a **second** one at **820** (the notification
     poster) that the brief does not mention, plus a third at
     `ATHandleVerification.swift:514`. All three were tautological, not just
     the one cited.
   - The three target-construction citations (`128-132`, `205-209`, `159-163`)
     were **correct**.

3. **The brief scopes the `responseURL` fix to the document transport only
   (item 3) but then asks the tests to cover all three (item 4).** I fixed all
   three, since the identical tautology existed in the post and handle
   transports.

## 7. Open questions

1. Closing the tautology *properly* — an explicit `requestTarget: String` on
   `OAuthRemoteHTTPResponse` / `ATHandleHTTPResponse` compared by the caller —
   requires edits to `Sources/SwanOAuth/OAuthRemoteFetch.swift` and
   `Sources/SwanAccounts/ATHandleVerification.swift`, owned by other lanes. Not
   made. Whoever owns those files should decide.
2. `AsyncHTTPClientOAuthTransport` (`OAuthRemoteFetch.swift`) is the fourth
   client path and is not peer-pinned; its `responseURL` handling was not in
   scope for this lane and I did not audit it.
3. The `oauthOriginFormRequestTarget` / `atHandleOriginFormRequestTarget` pair
   is a deliberate duplication: SwanAccounts does not depend on SwanOAuth, and
   the shared home would be `SwanCore`, which this lane does not own. Worth
   collapsing into SwanCore in a follow-up.
