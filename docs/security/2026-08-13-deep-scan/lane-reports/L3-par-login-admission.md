# Lane L3 — PAR and login admission

Closes F06 and F41 from `docs/security/2026-08-13-deep-scan/clusters/C10-preauth-resource-claims.md`.

Files touched, all three of them inside the lane:

- `Sources/SwanAccounts/AccountLoginAdmission.swift`
- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift`
- `Tests/SwanAccountsTests/AccountLoginHardeningTests.swift`

No file outside the lane was written. One additive line in `Sources/SwanHTTP/SwanHTTP.swift` (L1's file) is still outstanding; see [What is not closed](#what-is-not-closed).

---

## 1. Per-finding verdict

### F06 — CONFIRMED, fixed with a different mechanism than the program specified

Every step of the attack path resolves against the tree:

- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:214-231` (pre-change numbering) validated the DPoP proof immediately after form parsing, and `:233` loaded client metadata only afterwards. Client identity in PAR *is* that remote fetch, so nothing earlier in the handler establishes who the caller is.
- `Sources/SwanOAuth/OAuthProofValidation.swift:116-118` — `validate` computes `replayExpiresAt` and calls `tokenService.claimDPoP(jti:expiresAt:now:)` as the last step of proof validation. The proof carries an embedded `jwk` (`:71`), so the key is caller-generated; the only other gates are a live server nonce, `htm`/`htu`/`iat`, and an ES256 signature the caller makes itself.
- `Sources/SwanOAuth/DurableOAuthTokenService.swift:922-929` → `controlStore.claimDPoPReplay`.
- `Sources/SwanSQLite/OAuthControlStore.swift:1741-1797` — `claimReplay` inserts a row into `oauth_control_dpop_replays` after `requireInsertionCapacity(... maximumRows: oauthControlStorageLimits.dpopReplays)` at `:1769-1775`.
- `Sources/SwanSQLite/OAuthControlStore.swift:121` — `dpopReplays: 131_072`. `requireInsertionCapacity` (`:1197-1215`) throws once the table is at capacity, and it throws for *any* new digest, so exhaustion denies DPoP validation on PAR, token, revocation, and every resource route, not only on the route that filled it.

So the finding is real as filed: an unauthenticated caller allocates from a globally shared, capacity-bounded table before any client identity exists.

**Fixed** by charging a per-peer request budget at the top of each of the three handlers, before the DPoP proof is read:

- `Sources/SwanHTTP/SwanOAuthAuthorizationServerHTTP.swift:219-232` (PAR), `:537-550` (token), `:655-668` (revocation) — the admission check now sits between form parsing and `OAuthDPoPProofValidator(...).validate` at `:239`, `:553`, and `:671`.
- The shared helper is `oauthServerPeerAdmission` at `:746`, and the budget itself is `OAuthPeerAdmissionService` in `Sources/SwanAccounts/AccountLoginAdmission.swift`.

The jti claim was **not** reordered behind client validation, and the DPoP replay namespace was **not** partitioned per client: `claimDPoP` still takes the bare `jti` and the table remains global over it, as RFC 9449 §11.1 requires.

### F41 — CONFIRMED

- `Sources/SwanAccounts/AccountLoginAdmission.swift:25-27` (pre-change) declared `handleAttempts: Int = 10` and `pairAttempts: Int = 10`.
- `admit` consumes all three buckets on every attempt (`:130-134` pre-change), and `consumeProcess` reports limited as soon as *any* requested bucket is at its maximum (`:189-194` pre-change). The durable store does the same (`Sources/SwanSQLite/AccountLoginAdmissionStore.swift:243-251`).
- Consequence: one source spending its own 10-attempt pair budget against handle H also drives the handle-wide bucket to 10, and the handle bucket then rejects **every other source** for the rest of the 300 s window. 10 attempts / 300 s is ~0.033 req/s to hold indefinitely.

The handle bucket therefore contributed no brute-force protection that the pair bucket did not already impose on a single source, while granting that single source a repeatable account lockout.

**Fixed** by raising the default `handleAttempts` to 100 and leaving `pairAttempts` at 10.

**The trade, stated plainly.** This raises the online-guessing ceiling for one handle from 10 per 5 min (2,880/day) to 100 per 5 min (28,800/day) against Argon2id. Per-source guessing is unchanged at 10 per window. Against a strong password 28,800/day is not meaningful; against a weak one it is a real 10× increase. What it buys is that locking a handle now costs 10 distinct source addresses instead of one. This is the maintainer's call (§4 item 4 of the program); the code carries the recommended value and the reasoning is in the doc comment above the initializer, so reversing it is one literal.

---

## 2. Where the program's plan was wrong

The lane brief said to reuse the durable `AccountLoginAdmissionService` bucket with a new scope value, and that "the `scope` column is TEXT, so no migration is needed". I verified that before relying on it, and it does not hold. Three independent blockers:

1. **The column is TEXT with an enumerating CHECK.** `Sources/SwanSQLite/AccountLoginAdmissionStore.swift:9-10`:

   ```
   scope TEXT NOT NULL
       CHECK(scope IN ('handle', 'direct-peer', 'handle-peer-pair')),
   ```

   A fourth scope value fails the CHECK on INSERT. And because the DDL is `CREATE TABLE IF NOT EXISTS` (`:8`), the live control database keeps the constraint it was created with, so this needs a real table-rebuild migration on a production PDS — exactly the kind of change the brief was trying to avoid.

2. **A single-dimension durable request is not constructible.** `Sources/SwanStorage/AccountLoginAdmissionStore.swift:53-58` requires `buckets.count == AccountLoginRateLimitScope.allCases.count` and `scopes == Set(allCases)`. A PAR admission carrying one peer bucket cannot be built, and adding a case to the enum changes `allCases`, which changes that invariant for password login too.

3. **It would couple OAuth availability to login availability, in the same family as F41.** The durable table is globally capacity-bounded (`maximumDurableEntries` 100_000) and `capacityExhausted` fails closed into `AccountLoginAdmissionError.unavailable` (`Sources/SwanAccounts/AccountLoginAdmission.swift:313-314`, surfaced as 503 at `SwanOAuthAuthorizationServerHTTP.swift:395-402`). Routing unauthenticated OAuth peers into that table would hand anonymous traffic a path to deny password login. Fixing F06 that way would have created a new instance of the class F41 is about.

**So the admission is process-local instead**, built on the same fixed-window bucket shape as `AccountLoginAdmissionService.consumeProcess`. The window is 10 s rather than 5 min, so a process restart resetting it is not an evasion worth a schema change on a live federated PDS. No migration was needed and none was written.

One consequence worth naming: the new type lives in `SwanAccounts` next to the login admission rather than in `SwanHTTP` where it is used. That is partly kinship — it is the sibling of `AccountLoginAdmissionService` and reuses its reasoning — and partly that `Tests/SwanAccountsTests/AccountLoginHardeningTests.swift` is the only test file this lane owns.

---

## 3. What the admission does when the client-IP header is missing

`SwanLoginClientIdentityPolicy.clientIPAddress(directPeer:headers:)` (`Sources/SwanHTTP/SwanLoginClientIdentityPolicy.swift:44-62`) throws `.unavailable` when the accepted peer is a trusted proxy but `X-Swan-Client-IP` is absent, duplicated, or unparseable. Behind Cloudflare and Caddy that is the only usable identity, so this case has to be answered rather than assumed away.

**Decision: an unresolvable address is charged to one shared bounded bucket** — neither admitted nor rejected. `OAuthPeerAdmissionService.bucketKey(for:)` maps `nil` and any value that is not a plausible address literal to a single sentinel key that cannot collide with a real address (it begins with NUL, which the literal validator excludes).

Reasoning, since both alternatives are defensible and both are worse here:

- **Admitting** removes the control precisely in the state an attacker would aim for: whoever can make identity unresolvable would opt themselves out of the budget entirely. Not acceptable.
- **Rejecting** turns one proxy misconfiguration into total OAuth unavailability. This deployment has already had exactly that failure: every sign-in returned 503 because Caddy was not sending `X-Swan-Client-IP` while Swan ran with `--login-trusted-proxy-peer` (recorded as ADV-62, `docs/superpowers/plans/swan-adversarial-review-2026-07-30.md:130`). Reproducing that on PAR, token, and revocation would take the whole OAuth surface down rather than just interactive login.
- **A shared bounded bucket** keeps the ceiling unconditional — unidentified traffic in aggregate is capped at the same 600 per 10 s — while degrading to a single global budget instead of an outage. It is the same choice already made and documented for invalid handles at `Sources/SwanAccounts/AccountLoginAdmission.swift:232-235`, where attacker-varied invalid spellings collapse to one sentinel so they cannot inflate bucket cardinality.

### The deployed configuration was checked, not assumed

The lead asked whether the deployed policy is really the trusted-proxy variant rather than `.direct`, since the control is worthless if it is not. It is:

- `docker-compose.yml:100-101` passes `--login-trusted-proxy-peer` / `172.30.0.2`, and `Sources/swan/SwanCommand.swift:2133-2137` turns that list into the policy. With an empty list the policy is `.direct`; with a peer it is the trusted-proxy variant.
- `Scripts/verify-interop-lab.sh:550` and `:1308` **assert** the compose block declares exactly one `--login-trusted-proxy-peer`, so this is machine-checked rather than conventional.

Better than that, the header is not client-forgeable and the unresolvable path is not client-reachable:

- `interop/Caddyfile:10` is `header_up X-Swan-Client-IP {http.request.remote.host}` — **overwrite**, not the `+` append form. A client sending its own `X-Swan-Client-IP` has it replaced, so it cannot produce the duplicate-value case that makes `clientIPAddress` throw.
- `Scripts/verify-interop-lab.sh:669` and `:676` assert both halves of that: no `header_up -X-Swan-Client-IP` delete-after-set, and the set line in exactly the overwrite form. The delete-after-set spelling is what caused ADV-62, and it is now pinned against.

So on the deployed configuration the sentinel bucket catches **operator misconfiguration only** — which is exactly the case where failing closed would be an outage and failing open would cost nothing, because no attacker can steer traffic into it. That makes the shared-bucket choice cheap rather than merely defensible.

Direct-origin traffic is unaffected either way: when the socket peer is not a trusted proxy, the policy returns that peer's own address and never consults the header (`SwanLoginClientIdentityPolicy.swift:52-54`), so per-peer accounting holds for anything bypassing Caddy.

**Test coverage and its limit.** `testUnresolvedClientAddressesShareOneBoundedBucket` covers the admission half: `nil` and non-literal values collapse to one bucket, that bucket is capped, and an identifiable peer is unaffected by its exhaustion. It does not drive `SwanLoginClientIdentityPolicy` itself, because `SwanLoginClientIdentityPolicy` lives in `SwanHTTP` and `Tests/SwanAccountsTests` does not depend on `SwanHTTP` — adding that dependency means editing `Package.swift`, which is outside this lane. The composition of the two is verified by reading `oauthServerPeerAdmission`, which is three lines.

## 4. Rate

`OAuthPeerAdmissionPolicy.defaultAttempts = 600` over `defaultWindow = 10` seconds, matching the per-IP budget the deployment's Cloudflare rule already applies to `/xrpc/*` — the routes this covers are the ones that rule does not reach. Both are named constants with a comment recording that the right value depends on how Catbird behaves when PAR answers 429, because a client that retries tightly makes a smaller budget worse rather than better. Changing it is one edit, and `testOAuthPeerAdmissionDefaultsAreOneNamedEditAwayFromTheCDNBudget` pins the current pair so a change is deliberate.

Refusals answer `429` with the existing `temporarily_unavailable` body — no new error string, no widened body — plus `Retry-After`. The three routes share one budget because they claim from one replay table; splitting it per route would triple what a peer can allocate.

---

## 5. Exact pre-fix failures

### F41, before raising the constant

```
AccountLoginHardeningTests.swift:329: error: -[...testDefaultPolicyGivesTheHandleBucketHeadroomOverOnePeerPair] : XCTAssertGreaterThan failed: ("10") is not greater than ("10") - a handle bucket no larger than one pair bucket is a single-IP account lockout
AccountLoginHardeningTests.swift:335: error: -[...testDefaultPolicyGivesTheHandleBucketHeadroomOverOnePeerPair] : XCTAssertEqual failed: ("10") is not equal to ("100")
AccountLoginHardeningTests.swift:376: error: -[...testExhaustedPairBucketLeavesHandleHeadroomForADifferentPeer] : XCTAssertEqual failed: ("rateLimited") is not equal to ("allowed") - one peer spending its own pair bucket must not lock the handle for every other source
```

`testExhaustedPairBucketLeavesHandleHeadroomForADifferentPeer` is the invariant test the program asked for, and it is the point of the change: it drives one peer through its whole pair budget and then asserts a *different* peer still reaches password verification for the same handle. It fails on the old constants and passes on the new ones. `testHandleLockoutCostsTheHandleToPairRatioInDistinctPeers` pins the other half — the handle bucket must still close once its whole budget is spent — using an explicit small policy, so it holds under any default.

### F06, with the control neutered

The admission is new code, so the honest demonstration that its tests are load-bearing is to remove the control and watch them fail. With `admit` short-circuited to `return .allowed`, five of the six tests fail:

```
AccountLoginHardeningTests.swift:462: ...RefusesPastTheBudgetAndReopensTheNextWindow : XCTAssertEqual failed: ("allowed") is not equal to ("rateLimited") - an unauthenticated peer must stop allocating replay capacity at its budget
AccountLoginHardeningTests.swift:487: ...BudgetsDoNotLeakBetweenPeers : XCTAssertEqual failed: ("allowed") is not equal to ("rateLimited")
AccountLoginHardeningTests.swift:523: ...UnresolvedClientAddressesShareOneBoundedBucket : XCTAssertEqual failed: ("allowed") is not equal to ("rateLimited") - unresolved peers must share one bounded bucket, never bypass the budget
AccountLoginHardeningTests.swift:558: ...RefusesNewPeersOnlyWhileTheTableIsLive : XCTAssertEqual failed: ("allowed") is not equal to ("rateLimited") - a table full of live windows must refuse rather than evict a live bucket
AccountLoginHardeningTests.swift:590: ...TreatsABackwardsClockAsInsideTheOpenWindow : XCTAssertEqual failed: ("allowed") is not equal to ("rateLimited") - a backwards clock must not hand out a free window reset
```

The sixth, the constants pin, passes under the mutation as expected — it asserts configuration, not behaviour.

---

## 6. What is not closed

1. **PAR's budget is global, not per-peer, until one line lands in `Sources/SwanHTTP/SwanHTTP.swift`.** `registerOAuthAuthorizationServerPAREndpoint` had no access to the client-identity policy, and its only call site is `SwanHTTP.swift:819-824`, which belongs to lane L1. The parameter is declared optional with a `nil` default so that file compiles untouched; with `nil`, every PAR request lands in the shared unidentified bucket and the ceiling is one global 600 per 10 s. That still closes F06 as filed — the jti allocation rate is bounded, and the failure mode drops from "exhaust the global replay table and break DPoP everywhere" to "deny PAR" — but it is not the intended shape. The fix is `loginClientIdentityPolicy: loginClientIdentityPolicy,` added to the existing call; the value is already in scope one line above. Token and revocation are per-peer today, because their registration function already receives the policy. Refusals log `"identity": "unwired"` so the degraded state is visible in production logs rather than silent.

2. **There is no HTTP-route regression test.** The admission is unit-tested six ways, but the load-bearing property — that the refusal happens *before* `OAuthDPoPProofValidator.validate` claims a jti — is only established by reading `SwanOAuthAuthorizationServerHTTP.swift:219/239`, `:537/553`, `:655/671`. A test that asserts it would belong in `Tests/SwanHTTPTests/OAuthPARHTTPTests.swift`, which this lane does not own. Whoever owns that file next should add one: drive 601 PAR requests from one peer and assert the 601st answers 429 with no new row in `oauth_control_dpop_replays`.

3. **Sibling routes that claim a jti pre-authentication are not covered, deliberately.** Grep for `OAuthDPoPProofValidator(` finds four other call sites:
   - `Sources/SwanHTTP/SwanOAuthResourceAuthorization.swift:109` claims the jti before `validateAccess` (`:126-129`), by design, so a caller with a syntactically valid but bogus access token also allocates. Those are `/xrpc/*` routes and are inside the Cloudflare per-IP rule, which is why the program scoped this lane to `/oauth/*`. Worth revisiting only if that rule is removed.
   - `Sources/SwanHTTP/SwanLocalhostOAuthHTTP.swift:350` and `:456`, and `Sources/SwanHTTP/SwanOAuthPARHTTP.swift:128`, belong to the localhost profile. `SwanHTTP.swift:816-830` registers either the authorization-server endpoints or the localhost ones, never both, and the deployed configuration sets `--enable-oauth-authorization-server`. Not reachable on swan.place today; they would need the same treatment if that profile were ever deployed.

4. **Nothing was found that the program missed and no control was "fixed" that already existed.** The one place I checked specifically for that was the invalid-handle sentinel: it already collapses attacker-varied spellings, so the new admission mirrors it rather than reinventing it.

---

## 7. Verification

**Toolchain:** `xcrun --toolchain XcodeDefault swift ...` throughout, `--build-tests` before every `--skip-build`. `swiftformat` was never run.

**Baseline** (`75e7b509`, before any change): 1,489 XCTest cases, of which **1 failed** — `SwanOAuthTests.NIOPeerPinnedOAuthPostTransportTests.testPostTransportRejectsResponseBeyondConfiguredBound`, "I/O on closed channel" after 11.8 s. It is a NIO timing flake in a file this lane does not touch, and it passed on both later runs. The program's stated baseline of 0 failures did not reproduce on the first run here.

**After the change:** exit code **0**, **1,498 passed, 0 failed, 9 skipped, 11 targets**, and no `Some test targets reported failures` line anywhere in the log. 1,498 = the 1,489 baseline cases plus the 9 added here, so nothing was lost. Judged by exit code *and* by grepping the log for the target-failure note; output was redirected to a file and never piped through `tail`. Pass counts come from `Test Case '-[...]' passed` lines, not from summing `Executed N tests`.

### A measurement hazard worth recording

The session scratchpad is **shared by every lane agent**, not per-agent: 374 files, some dating to Aug 10, with predictable names like `baseline.log` and `baseline-test.log`. Concurrent `>` redirects from different lanes interleave into the same file.

This produced a wrong result before it was caught. A full-suite log that appeared to be this lane's contained none of the nine cases added here, and instead contained eight `SwanHTTPTests.PublicFirehoseStreamingHTTPTests` cases — `testFirehoseReservationLeavesThreeQuartersOfTheListenerBudget`, `testSaturatedFirehoseReservationRefusesSurplusAndLeavesHTTPServable`, `testOutboundCommitFramesAboveMaxFrameSizeArriveUnfragmented`, and `testWebSocketMaxFrameSizeBoundsInboundClientFrames` replacing `testWebSocketMaxFrameSizeAtLeastFrameLimit`. That is lane L1's F05 and F11 work, in a file this lane never built. Two earlier oddities have the same cause: a `Swan-L1-firehose-admission/Package.swift` path inside what looked like this lane's build log, and a `Some test targets reported failures` note naming a target whose own summary reported zero failures.

The `.build` directories *are* per-workspace — every compile command cited this workspace — so only the evidence was contaminated, never the build. Every number above comes from a private log directory outside the shared scratchpad. Anyone reading another lane's report should check where its logs were written before trusting its counts.

**One cross-lane side effect, disclosed.** A first Linux attempt bind-mounted this workspace read-write, and SwiftPM inside the container re-resolved and rewrote the host `Package.resolved`, dropping the `swift-configuration` pin. That is a file outside this lane. It was restored with `jj restore --from @- Package.resolved` and the final suite was re-run against the restored file; the working copy contains only the four intended files. Later Linux attempts mount read-only.

### Linux

The program's suggested `docker run --rm -v "$PWD":/src -w /src swift:6.1-jammy swift build --build-tests` cannot work for this package:

- `Package.swift:25` is `.package(path: "../Petrel")`, which falls outside the bind mount. The first attempt failed immediately with `the package at '/Petrel' cannot be accessed`.
- The build needs `libsodium-dev pkg-config libsecret-1-dev libglib2.0-dev` — the exact set `Dockerfile:4-9` installs — which the stock image does not carry.
- On an Apple Silicon host the image resolves to **aarch64**, not the x86_64 deployment target, unless `--platform linux/amd64` is passed.

The working form mounts both repositories read-only, copies them into the container so no host file can be rewritten, and builds there:

```
docker run --rm \
  -v <repo>/Petrel:/src/Petrel:ro \
  -v <lane-workspace>:/src/Swan:ro \
  swift:6.1-jammy bash -lc 'apt-get update && \
    apt-get install -y --no-install-recommends libsodium-dev pkg-config libsecret-1-dev libglib2.0-dev && \
    mkdir -p /workspace && \
    tar -C /src -cf - --exclude=.build --exclude=.git --exclude=.jj Petrel Swan | tar -C /workspace -xf - && \
    cd /workspace/Swan && swift build --build-tests'
```

**Result, stated exactly.** On `swift:6.1-jammy` (`Swift version 6.1.3 (swift-6.1.3-RELEASE)`, `aarch64-unknown-linux-gnu`):

| Command | Exit |
|---|---|
| `swift build --product swan` | **0** |
| `swift build --target SwanAccounts --target SwanHTTP` | **0** |
| `swift build --build-tests` | **1** |

The two targets this lane changes, and the whole deployable product, compile clean on the Linux toolchain. `--build-tests` fails, and it fails at the sealed commit for a reason that has nothing to do with this lane:

```
/workspace/Swan/Tests/SwanSQLiteTests/AccountPermanentDeletionSQLiteTests.swift:260:37: error: 'async' call cannot occur in a defer body
```

`Tests/SwanSQLiteTests/AccountPermanentDeletionSQLiteTests.swift:260` is `defer { try? await database.close() }`. `jj diff --name-only` on this change lists four files and that is not one of them. The local macOS toolchain is Swift 6.4 (`swiftlang-6.4.0.27.1`), which accepts `await` in a `defer` body — the enclosing test compiles and passes on macOS, `passed (0.023 seconds)` — while the Swift 6.1 image that `Dockerfile:1` pins for the deployment image rejects it. Until somebody who owns `Tests/SwanSQLiteTests/` hoists that close out of the `defer`, **no lane can satisfy a `--build-tests` Linux gate**, and any lane reporting one should check whether its command piped through `tail`, which reports `tail`'s exit status rather than the build's.

**Two limits on this result, stated rather than glossed.** First, `swift:6.1-jammy` on an Apple Silicon host resolves to **aarch64, not the x86_64 deployment target**; `--platform linux/amd64` was not used, so x86_64 specifically is *not* verified here, and the brief's own command would not have verified it either. Second, one earlier attempt died with `ld.gold: fatal error: No space left on device` rather than a compile error — Docker's VM is close to full (`docker system df`: 106.8 GB images, 77.4 GB build cache). Nothing was pruned, since that cache may belong to other lanes.
