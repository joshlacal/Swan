# L6 — signer fences and service JWT

Closes F04, F15, F16, F32, F44, F45. Based on `77bab90c5e79`.

All line citations below are against the tree as merged at `77bab90c5e79`, not
against the scan's pre-merge numbering.

---

## 1. Per-finding verdict

### F04 — service JWT maximum lifetime is reachable only through `iat` — **CONFIRMED, fixed**

`SpaceServiceJWT.Claims.iat` is `Int64?` (`Sources/SwanOAuth/SpaceServiceAuthentication.swift:291`)
and `validateShape` (`:456-466`) never requires it. `verify` enforced only a
*lower* bound on `exp` (`:405-407`, `exp >= now - skew`); the entire
maximum-lifetime control lived inside `if let issuedAt` at `:408-419`. A
correctly signed token with no `iat` and an arbitrarily distant `exp` therefore
passed signature, issuer, audience, method, shape, expiry and JTI checks with no
freshness bound at all. `DurableSpaceServiceAuthenticationVerifier` then returned
that distant `expiresAt` to the caller (`:222`).

Fix: an unconditional ceiling next to the existing floor —
`latestExpiration = now + skew + maximumLifetime`, both additions via
`addingReportingOverflow`, rejecting any `exp` above it. Every accepted token is
now capped at `skew + maximumLifetime` (360 s on the standard configuration)
whether or not `iat` is present. The `if let issuedAt` block is retained
unchanged as the tighter bound for tokens that carry one; it now reuses the
`latestIssuedAt` value the new check already computes.

**No wire change.** `iat` is still not required — decision 6 in §4 of the
program, taken as recommended. Swan is already stricter than the pinned
reference verifier, which never inspects `iat`; the `exp` cap closes the gap
without the interop cost. The regression test asserts explicitly that a no-`iat`
token whose expiry is inside the window still verifies.

### F16 — composite service-key resolver falls through to a pin for a revoked local DID — **CONFIRMED, fixed**

The scan's remediation string for this finding is boilerplate about PLC audit
chains and duplicate service IDs and touches none of the cited code. Ignored, as
directed.

Verified mechanism: `LocalAccountSpaceServicePublicKeyResolver.publicKey`
(`:76-89` pre-fix) collapsed five distinct negatives into one `return nil` —
unmanaged DID, malformed issuer, missing account, non-authorizing account,
missing key references, and absent public-key metadata.
`CompositeSpaceServicePublicKeyResolver.resolve`
(`Sources/SwanOAuth/PermissionedResolverComposition.swift:206-216`) funnels that
into `uniqueVerificationKey` (`:219-234`), whose `(nil, .some(key))` case returns
the pin. So a pin overlapping a locally managed DID becomes authoritative the
moment that account is deactivated.

Fix: `nil` is now returned **only** on proven absence — the DID is not a service
issuer DID at all, or `accounts.account(did:)` returns `nil`. Every other
negative throws `SwanError.unavailable`, mirroring
`LocalAccountSpaceCredentialPublicKeyResolver` (`SpaceCredentialAuthority.swift:270-343`)
and `LocalAccountSpaceDelegationPublicKeyResolver` (`:364-441`), whose comments
already state this contract.

**HTTP behaviour — verified, not assumed.** `serviceAuthentication`
(`Sources/SwanHTTP/SwanSpaceNotificationXRPC.swift:573-576`) catches
`SwanError.unavailable` into `AuthenticatedSpaceNotificationFailure.unavailable`,
which `authenticatedSpaceNotificationResponse` (`:646-654`) renders as 503 with
the fixed body `temporarily_unavailable`. No route change and no widened body.
The one observable difference is that this already-failing request answers 503
instead of 401. That is the intended distinction — terminal revocation is not
"unknown issuer" — and it matches what the two sibling resolvers already do.

I also fenced the `publicKeyStore.publicKey` suspension in this resolver. Both
sibling resolvers fence exactly that read (`SpaceCredentialAuthority.swift:328-341`,
`:421-434`); leaving the third unfenced would have recreated the copy-drift this
lane exists to remove.

### F15 / F32 / F44 / F45 — four copies of one unfenced signing path — **CONFIRMED, fixed**

Each issuer read account lifecycle and key references, `await`ed the key store,
then signed, with no post-await re-check:

| Finding | Site (pre-fix) | Artefact signed |
|---|---|---|
| F15 | `ProxyServiceAuthentication.swift:143-152` | 60 s proxy service JWT, AppView pipethrough |
| F32 | `SpaceServiceAuthentication.swift:250-255` | 60 s service JWT for notification transports |
| F44 | `SpaceDelegationTokenIssuer.swift:42-51` | delegation token for `getSpaceCredential` |
| F45 | `SpaceRepositoryCommitSigner.swift:49-58` | proposal-0016 signed reader commit |

Two of them carried `// Do not perform an await after this point`
(`ProxyServiceAuthentication.swift:149-151`, `SpaceDelegationTokenIssuer.swift:48-50`)
on the line immediately above `try await keyStore.key(...)`.
`SpaceRepositoryCommitSigner.swift:20-24` claimed the repeated check meant "a
stale request cannot sign after deactivation" — true only of a request stale on
arrival, not of one that becomes stale during the read the comment sits above.

All three comments are corrected independently of the security value.

### Shared-helper design

One method on `DurableAccountDirectory`, not four copied bodies:

- `AuthorizingAccountSnapshot` (`Sources/SwanAccounts/DurableAccountDirectory.swift:27-45`)
  — the whole `AccountControlAccount` row plus both `AccountKeyReference`s. Both
  are already `Equatable`, so the fence is one `==` over the complete state
  rather than a hand-picked subset that the next reader has to audit.
- `authorizingAccount(did:)` (`:177-198`) — account + key references in **one**
  control-store read. `nil` means absent or not authorizing.
- `requireUnchangedAuthorizingAccount(did:expected:)` (`:200-231`) — re-reads and
  throws `SwanError.unavailable` on any difference, including a read failure.
- `keyReferences(of:)` (`:233-259`) — the projection `keyReferences(did:)`
  already performed, factored out so the two entry points cannot drift. The only
  behavioural change is that the reference now names `account.did` rather than
  the validated input DID; those are equal by construction.

Each issuer replaced its two-read prologue with one `authorizingAccount(did:)`
and gained one `requireUnchangedAuthorizingAccount` immediately after the
key-store await. **The read count per issuance is unchanged: two before, two
after.** That is why the fence is not a cost (§3).

`withActiveAccountAuthorization` was **not** used, per the lane brief and §1 of
the program: it would hold the control-DB write gate across a key-store file
read and an ES256 sign, which `AccountControlStore.swift:2436-2438` explicitly
forbids, and would serialize the pipethrough behind a single write gate.

---

## 2. Tests

### Pre-fix failures, as observed

`swift test --filter 'SignerLifecycleFenceTests|testServiceJWTWithoutIssuedAtCannotOutliveTheConfiguredMaximum'`
→ exit 1, **2 passed / 8 failed**:

```
SignerLifecycleFenceTests.swift:45:  ... testServiceAuthenticationIssuerRefusesAfterDeactivationDuringKeyRead : failed - service authentication issuer signed across a deactivation
SignerLifecycleFenceTests.swift:66:  ... testServiceAuthenticationIssuerRefusesAfterKeyRotationDuringKeyRead : failed - service authentication issuer signed with a superseded generation
SignerLifecycleFenceTests.swift:89:  ... testProxyServiceTokenIssuerRefusesAfterDeactivationDuringKeyRead : failed - proxy token issuer signed across a deactivation
SignerLifecycleFenceTests.swift:109: ... testDelegationTokenIssuerRefusesAfterDeactivationDuringKeyRead : failed - delegation issuer signed across a deactivation
SignerLifecycleFenceTests.swift:128: ... testRepositoryCommitSignerRefusesAfterDeactivationDuringKeyRead : failed - commit signer signed across a deactivation
SignerLifecycleFenceTests.swift:206: ... testDeactivatedManagedIssuerIsTerminalNotAFallThrough : failed - a deactivated managed issuer must not resolve as absent
SignerLifecycleFenceTests.swift:259: ... testOperatorPinDoesNotSurviveDeactivationOfTheOverlappingLocalAccount : failed - the pin outlived the local account it overlaps
SwanOAuthTests.swift:403: ... testServiceJWTWithoutIssuedAtCannotOutliveTheConfiguredMaximum : XCTAssertThrowsError failed: did not throw an error
SwanOAuthTests.swift:414: ... testServiceJWTWithoutIssuedAtCannotOutliveTheConfiguredMaximum : XCTAssertThrowsError failed: did not throw an error
```

The two that passed pre-fix are the guards that the fix must not break:
`testUnmanagedAndMalformedIssuersStillFallThroughAsNil` and
`testUnracedIssuanceStillSucceedsOnEveryFencedSigner`.

### Race construction

Deterministic interleaving, no sleeps. `DeactivatingKeyStore` and
`RotatingKeyStore` wrap the real `FileAccountKeyStore` and commit the lifecycle
transition (or the key rotation, via `AccountKeyProvisioner` +
`control.rotateAccountKeys`) *inside* `key(for:)`, i.e. inside the exact
suspension the finding names. Same shape as the sibling suite
`SpaceCredentialSigningFenceTests`, which fences the space-credential signing
resolver.

### New files and cases

- `Tests/SwanOAuthTests/SignerLifecycleFenceTests.swift` (**new file**, 9 cases)
  — the four signer fences, key rotation as well as deactivation on one of them,
  the F16 resolver contract, and the fall-through and unraced-happy-path guards.
  A new file rather than an addition to the 1866-line `SwanOAuthTests.swift`;
  it collides with no other lane's file list.
- `Tests/SwanOAuthTests/SwanOAuthTests.swift` — `testServiceJWTWithoutIssuedAt...`
  (F04): distant `exp` with no `iat`, one second past the ceiling, the in-window
  no-`iat` interop guard, a Swan-minted token, and the still-tighter `iat` path.
- `Tests/SwanOAuthTests/PermissionedResolverCompositionTests.swift` —
  `testTerminalLocalNegativeIsNotAFallThroughToThePin`: the composition seam for
  all three composites, plus the startup-preflight case (§4). The `Static*`
  stubs gained a `failing:` map so a resolver can express a terminal negative at
  all.

### Suite result

Full suite, `swift test --skip-build`, exit **0**, `Some test targets reported
failures` count **0**:

| | passed | failed | targets |
|---|---|---|---|
| baseline (merged tree) | 1543 | 0 | 11/11 |
| this lane | **1554** | **0** | **11/11** |

Delta **+11 passed, +0 failed** — exactly the 11 cases added.

Linux: `swift build --build-tests` in `swift:6.1-jammy`, **Build complete
(379.98s), exit 0**. Result is **aarch64** (`uname -m` in-container), not amd64.
The container rewrote `Package.resolved` from 35 `"identity"` entries to 34, as
expected; restored with `jj restore` and re-verified at 35 before committing.

---

## 3. Measured pipethrough cost

`LocalAccountProxyServiceTokenIssuer.issueProxyServiceToken` is the highest-QPS
signer on the box. Measured on the real stack — `SQLiteControlDatabase` +
`FileAccountKeyStore` + `DurableAccountDirectory` — 4,000 iterations per sample,
200-iteration warmup, fenced and pre-fix arms **interleaved A/B/B/A across 8
rounds** against an inline replica of the pre-fix body.

Interleaving is load-bearing. A sequential A-then-B layout first reported the
fenced arm 45% *slower* (691 vs 482 µs) and, in the other ordering, *faster* (466
vs 529 µs). Both were measurement drift.

| statistic | fenced | pre-fix | delta |
|---|---|---|---|
| median, run 1 | 512.9 µs | 529.2 µs | −16.3 µs |
| median, run 2 | 560.5 µs | 489.4 µs | +71.1 µs |
| **minimum, run 1** | 468.0 µs | 462.1 µs | **+5.9 µs** |
| **minimum, run 2** | 466.9 µs | 459.8 µs | **+7.1 µs** |

The medians disagree in sign across runs, so they do not resolve the difference.
The minimum is the noise-robust statistic here and puts the cost at
**≈ +6 µs, about 1.3%, on a ~465 µs operation.**

**Not material, and the structural reason is stronger than the measurement:
the request does the same two control-store reads it always did.** The lane
brief anticipated three; it is two, because `authorizingAccount(did:)` collapses
the old `account(did:)` + `keyReferences(did:)` pair — which read the same row
twice — into one read, and the fence spends the read that saved. One control read
measures **85.9–88.5 µs** on this fixture, so an actual third read would have
cost ~19%, an order of magnitude more than observed. The residual ~6 µs is
consistent with one extra actor hop, not a database round trip.

Signing (ES256) plus the encrypted key-store file read dominate at roughly 290 µs
of the ~465 µs total. No alternative design is proposed; there is nothing to
trade away.

The benchmark is deliberately **not** committed — a wall-clock assertion in the
suite would be flaky. It is preserved at
`/private/tmp/swan-lane-L6-signer-fences/ZZProxyIssuerCostBenchmark.swift.scratch`.

---

## 4. Notes for the maintainer

1. **Startup fail-closed, new.** `CompositeSpaceServicePublicKeyResolver.init`
   preflights every pin through the local resolver
   (`PermissionedResolverComposition.swift:186-193`). Post-fix, a pin that
   overlaps a locally managed but non-authorizing DID makes **construction**
   throw, where it previously succeeded and silently adopted the pin. That is
   the correct fail-closed reading of decision 14 in §4 of the program, and it
   is asserted by a test. It is unreachable on swan.place today: pins come only
   from `--notification-config` (`SwanCommand.swift:240-286`), which is not set,
   so `SwanCommand.swift:838-841` never constructs the composite at all and the
   local resolver is used directly. Worth knowing before that flag is ever
   turned on with a pin for a local DID.

2. **Decision 14 answered by implementation.** "Is an operator pin meant to
   survive local account suspension?" — implemented as **no**, matching the
   contract the credential and delegation resolvers already state in their own
   comments. Reversing it means reverting the resolver, not adjusting a knob.

3. **Decision 6 taken as recommended.** `iat` is not required. Only the
   unconditional `exp` cap landed.

4. **F31 is untouched and still open.** The deletion service JWT remains unbound
   to a space; that is a wire-format question routed to §4 decision 10, not this
   lane.

5. **`SpaceCredentialAuthority.swift` was not modified** (L12 owns it). Its F14
   signing fence is already present in the merged tree at `:220-243` and is what
   the shared helper was modelled on. If L12 lands further work there, that
   hand-written fence is now a candidate to collapse onto
   `requireUnchangedAuthorizingAccount(did:expected:)` — five bodies would
   become one.
