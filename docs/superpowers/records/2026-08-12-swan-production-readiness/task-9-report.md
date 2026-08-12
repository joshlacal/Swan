# Task 9 — Serve `did.json` and stop advertising invite codes

Plan: `docs/superpowers/plans/2026-08-12-swan-production-readiness.md`
Brief: `.superpowers/sdd/2026-08-12-swan-production-readiness/task-9-brief.md`
Baseline: suite exit 0, HEAD `4ecd9e1ad34e`.

## What changed, per file

### `Sources/SwanHTTP/SwanHTTP.swift`

1. **`SwanHTTPConfiguration` gains `inviteCodeRequired: Bool`** (defaults to
   `false`, added last in the initializer's parameter list so every existing
   call site is source-compatible). The struct stays `Sendable, Equatable`.

2. **New `SwanServiceIdentity` (internal, `Sendable, Equatable`)** — the single
   derivation of Swan's own service identity from `configuration.publicURL`:
   - `did` = `did:web:<lowercased host>`, with `%3A<port>` appended when the
     public URL names a port other than its scheme's default.
   - `serviceEndpoint` = the `scheme://host[:port]` origin, rebuilt from
     components rather than taken from `absoluteString`, so a configured
     trailing slash or path never leaks into the advertised endpoint.

3. **New `/.well-known/did.json` route**, registered immediately before the
   OAuth well-knowns in `buildRouter()` (the brief said "beside the OAuth
   well-knowns"). `GET` returns the DID document; `OPTIONS` returns the shared
   CORS preflight. Both reuse the existing `oauthMetadataJSONResponse` /
   `oauthMetadataCORSPreflightResponse` helpers, so the document is served with
   the same `application/json` + `no-store` + wildcard-CORS shape as the other
   discovery documents and no second response helper was invented.

4. **New `SwanServiceDIDDocument` / `SwanServiceDIDServiceEntry`** (both
   file-private) — `@context: ["https://www.w3.org/ns/did/v1"]`, `id`, and one
   service entry `{"id":"#atproto_pds","type":"AtprotoPersonalDataServer",
   "serviceEndpoint":<origin>}`.

5. **`com.atproto.server.describeServer` now reads both values from the same
   places as the document**: `did: serviceIdentity.did` (was
   `"did:web:\(publicURL.host ?? "localhost")"`) and
   `inviteCodeRequired: inviteCodeRequired` (was the literal `true`).

### `Tests/SwanHTTPTests/SwanServiceIdentityHTTPTests.swift` (new, 7 tests)

| Test | What it pins |
|---|---|
| `testWellKnownDidJSONResolvesTheServiceDID` | 200, `application/json`, `id == "did:web:swan.place"`, a service entry of type `AtprotoPersonalDataServer` with `id "#atproto_pds"` and endpoint `https://swan.place`, and the DID `@context` |
| `testDescribeServerDoesNotClaimInviteCodesAreRequired` | `inviteCodeRequired == false` on the default configuration |
| `testDescribeServerAdvertisesInviteCodesOnlyWhenConfigured` | a configured `true` reaches the wire — this is what stops the fix from being one hardcoded literal traded for another |
| `testDescribeServerAndDidDocumentPublishTheSameServiceDID` | the two routes agree, checked on both `https://swan.place` **and** `https://swan.place:8443` |
| `testServiceDIDEncodesANonDefaultPort` | `did:web:127.0.0.1%3A3000` and endpoint `http://127.0.0.1:3000` from both routes |
| `testDidDocumentIsCORSReadableAndMethodCorrect` | `Access-Control-Allow-Origin: *` on GET, `204` on OPTIONS, `404` on POST/PUT/PATCH/DELETE |
| `testServiceIdentityNormalizesEquivalentPublicURLs` | the derivation directly: explicit default port, trailing slash, and mixed-case host all normalize to one identity; non-default ports on both schemes are encoded |

The test file's `withRunningServer` helper closes the `SQLiteControlDatabase`
on the failure path as well as the success path. This is not incidental: the
first run of these tests crashed the whole `SwanHTTPTests` target with
`SQLiteConnection was not closed before deinitializing` the moment one
assertion threw, which is exactly the "crashing target truncates everything
after it" failure mode the task constraints warn about.

## Ambiguity in the brief, and how it was resolved

1. **The brief's test bodies use APIs this repo does not have** —
   `client.get(...)`, `response.decode(...)`, and a bare `describeServer()`.
   The repo's harness is `HummingbirdTesting`'s
   `client.execute(uri:method:) { response in ... }`. The assertions were kept
   verbatim in meaning (`status == .ok`, `doc.id == "did:web:swan.place"`,
   `doc.service.contains { $0.type == "AtprotoPersonalDataServer" }`,
   `XCTAssertFalse(...inviteCodeRequired)`) and the plumbing rewritten to the
   real harness.

2. **`DIDDocument` cannot be used as the decode target.** The brief writes
   `response.decode(DIDDocument.self)`. The only `DIDDocument` reachable here
   is Petrel's, and its stored properties (`id`, `service`, …) are `internal`
   to the Petrel module, so a Swan test cannot read them. The tests decode the
   served bytes into a small `Decodable` mirror declared in the test file. It
   decodes the server's actual response; nothing is constructed and then
   asserted against itself.

3. **`did:web` and non-default ports.** The brief only asks for
   `did:web:swan.place`. The pre-existing `describeServer` literal dropped the
   port entirely, which is correct for production (`https://swan.place`) and
   wrong for any ported deployment: `did:web:swan.place` resolves to
   `https://swan.place/.well-known/did.json`, a *different* origin from the one
   serving on `:8443`. Since both routes now had to agree on one string anyway,
   the derivation encodes the port as `%3A<port>` per the did:web method spec.
   This changes `describeServer.did` only for deployments whose public URL
   carries a non-default port; `https://swan.place` is byte-identical to
   before. `Sources/SwanOAuth/SwanServiceEndpointResolver.swift` already
   decodes `%3A` when it resolves a `did:web`, so Swan's own resolver round-
   trips the value it now publishes.

4. **"Derive from configuration" for `inviteCodeRequired`, with no CLI flag.**
   The value is now a `SwanHTTPConfiguration` field defaulting to `false`, and
   no `swan serve` flag sets it. That is deliberate: `grep -rni invite` over
   `Sources/` finds no issuance, redemption, or enforcement anywhere in Swan,
   so an operator-settable flag would only let someone advertise a requirement
   the server cannot enforce — the same class of lie the task is removing, in
   the opposite direction. The field exists so that whoever lands enforcement
   flips the advertisement in the same assembly, rather than editing a route
   body. Noted as a concern below.

5. **Served unconditionally rather than gated.** The document is derived
   entirely from `publicURL`, contains no key material and no account data, and
   is the public half of an identity Swan already advertised through
   `describeServer`. There is nothing here to gate, and a gate would be a new
   way for the public read surface to go dark — which is the failure this whole
   phase exists to prevent.

## Falsification

Three rounds. Each broke the change, rebuilt, ran the filter, then restored.

**Round A — drop the `%3A<port>` encoding, and re-hardcode
`inviteCodeRequired: false`.** Expected: the port test fails, and the
"only when configured" test fails; everything else passes.

```
testDescribeServerAdvertisesInviteCodesOnlyWhenConfigured  FAILED  XCTAssertTrue failed
testServiceDIDEncodesANonDefaultPort                       FAILED  ("did:web:127.0.0.1") is not equal to ("did:web:127.0.0.1%3A3000")
testDescribeServerAndDidDocumentPublishTheSameServiceDID   passed
testDescribeServerDoesNotClaimInviteCodesAreRequired       passed
testDidDocumentIsCORSReadableAndMethodCorrect              passed
testWellKnownDidJSONResolvesTheServiceDID                  passed
```

As expected. Note the second one: the naive "just change `true` to `false`"
fix is caught, which is the whole point of that test existing.

**Round B — change the service type to `AtprotoPersonalDataServerX`, and make
`describeServer` format its own DID again.** Expected: the document test fails
on the missing service type; the identity-agreement test fails.

```
testWellKnownDidJSONResolvesTheServiceDID   FAILED  XCTAssertTrue failed; XCTUnwrap failed: expected non-nil value of type "WellKnownDIDService"
testServiceDIDEncodesANonDefaultPort        FAILED  ("did:web:127.0.0.1") is not equal to ("did:web:127.0.0.1%3A3000")
testDescribeServerAndDidDocumentPublishTheSameServiceDID   passed   <-- GAP
```

**This round found a real gap.** The agreement test was written against
`https://swan.place` only, where the independent formatting
`"did:web:\(publicURL.host ?? "localhost")"` happens to produce the same string
as the shared derivation. It therefore could not detect the drift it exists to
detect. The test was extended to run against `https://swan.place:8443` as well.

**Round C — re-apply only the "`describeServer` formats its own DID" break,
against the strengthened test.** Expected: the agreement test now fails.

```
testDescribeServerAndDidDocumentPublishTheSameServiceDID  FAILED
  ("did:web:swan.place") is not equal to ("did:web:swan.place%3A8443")
  ("did:web:swan.place%3A8443") is not equal to ("did:web:swan.place")
```

Gap closed. All three breakages restored; `jj diff` after restore shows only
the intended change.

## Commands and results

```
xcrun --toolchain XcodeDefault swift build --build-tests          # exit 0, 0 errors
xcrun --toolchain XcodeDefault swift test --skip-build --filter SwanServiceIdentityHTTPTests
                                                                  # exit 0, 7/7 passed
xcrun --toolchain XcodeDefault swift test --skip-build            # exit 0
```

The filter matched and named all 7 tests in its `xctest -XCTest ...` invocation
(verified from the log, not assumed).

Full suite, from `suite-final.log` (redirected to a file, never piped):

- `SUITE_EXIT=0`
- `Test Case '-[...]' passed` lines: **1470** (baseline 1463 + 7 new)
- `Test Case '-[...]' failed` lines: **0**
- `grep -c "reported failures"`: **0** — no `Some test targets reported failures`
- 12 swift-testing runs, all `passed`

## Deliberately not done

- **No `swan serve --invite-code-required` flag.** Reasoning in Ambiguity §4.
- **No `verificationMethod` in the DID document.** Swan holds no service-level
  signing key to publish there, and emitting an empty or invented one would let
  a verifier believe a key was checked. Account signing keys belong in account
  DID documents, which this route never serves.
- **`availableUserDomains` still `[]`.** It is arguably as untruthful as the
  invite literal was, but the brief scoped this task to `inviteCodeRequired`
  and the honest value depends on handle-provisioning configuration that is not
  in `SwanHTTPConfiguration` today.
- **No relay activation.** Explicitly out of scope.
- **No change to the `/xrpc/**` authenticate-before-route ordering**, to
  `com.atproto.sync.getBlob`'s registration block, or to the hardcoded
  `PublicDataTesting20260727` profile iteration. Those are other tasks; nothing
  here touches them.
- **No change to Phase 1 proxying, credential isolation, or peer pinning.**
- **No change to any client-visible error body.** The public-read 503 body is
  untouched; `publicReadUnavailable`, `PublicReadUnavailableReason`, and the
  golden token list were not modified, so
  `testJournalTokensMatchTheGoldenList` needed no update.

## Concerns

1. **`inviteCodeRequired` has no writer.** Every construction of
   `SwanHTTPConfiguration` — including the CLI's single site at
   `Sources/swan/SwanCommand.swift:2952` — takes the `false` default. The field
   is therefore configuration in shape but a constant in practice until invite
   enforcement exists. I judged that better than a flag that advertises
   unenforced invites, but a reviewer may reasonably want the field dropped
   entirely in favour of a plain `false` with a comment. The test
   `testDescribeServerAdvertisesInviteCodesOnlyWhenConfigured` is what would
   have to be deleted along with it.

2. **`describeServer.did` changes for ported deployments.** Any Swan run with a
   non-default port in `--public-url` now reports `did:web:host%3Aport` where it
   previously reported `did:web:host`. Production (`https://swan.place`) is
   unaffected, and no test or fixture pinned the old value, but if any external
   consumer recorded the old dev-mode DID it will see a different string.

3. **`did.json` is served even when the public URL is not a resolvable did:web
   authority** (an `http://` loopback, or an IP literal). The document is inert
   in that case — nobody can resolve `did:web:127.0.0.1%3A3000` — and it keeps
   dev and production shaped identically, but it does mean the route never
   fails closed. If a reviewer prefers an allow-list here, the natural gate is
   "https scheme and a DNS-name host", reusing
   `SwanServiceEndpointResolver.isValidWebAuthority`'s rules.

4. **`SwanServiceIdentity` is `internal`, not `private`.** It is used only
   inside `SwanHTTP.swift` plus the `@testable` unit test that covers its
   normalization rules. If the direct unit test is considered surplus, the type
   can drop to file-private.

5. **No live verification.** This is a route-registration change verified by
   the in-process Hummingbird router harness; it has not been exercised against
   the deployed `swan.catbird.blue` / `swan.place` instance. Confirming the real
   thing needs `curl -sS https://swan.place/.well-known/did.json` and
   `curl -sS https://swan.place/xrpc/com.atproto.server.describeServer` after a
   deploy, checking that `.id` and `.did` are both `did:web:swan.place` and that
   `inviteCodeRequired` is `false`.
