# Task 10 — Make the profile selection control the public route surface

**Commits:**
- `3b36c442bc9e` — `SwanHTTP: drive public route registration from the loaded profile` (first round, judged SPEC NON-COMPLIANT)
- `ba8f4e929fc8` — `SwanHTTP: make the selected public profile remove routes, not only add gates` (fix round)
- `30ed439aa5e4` — `SwanHTTP: correct the false resetPassword stub claim in the proxy-routing comment` (coordinator ruling 3)

**Baseline:** `705e2b411210`, suite exit 0, 1479 passed.
**Result:** suite exit 0, **1484** `Test Case '-[…]' passed`, **0** failed, **0** occurrences of
`Some test targets reported failures`, **0** `error: -[` lines. 1493 started − 9
environment-gated skips (each with an explicit `' skipped (` line) = 1484. Counted from a
redirected log; nothing piped through `tail`.

The +5 is exactly the five new cases in
`Tests/SwanHTTPTests/PublicRouteSurfaceProfileSelectionTests.swift` (9 → 14).

---

## Coordinator rulings, on the record

**1. `--public-profile` as a sibling flag: CONFIRMED.** `--profile` is not widened.
Recorded as an intentional spec deviation. `ProtocolProfile.init(data:)`
(`Sources/SwanCore/SwanCore.swift:80-91`) hard-requires `id.hasPrefix("permissioned-data-")`
plus `crypto`/`oplogRetention`/`proposalCommit`/`migrationCompatibility`; none of the four
shipped `Profiles/public-data-testing-*.json` artifacts carry those fields, so `--profile`
structurally cannot name a public profile. Relaxing `ProtocolProfile` to span both families
would ripple into `swan verify`, the permissioned pins, and `describeServer`, and is its own
task.

**2. Default surface at `public-data-testing-2026-08-06`: UPHELD**, reversing the earlier
ruling that it must stay at `2026-07-27`. See §The load-bearing argument below — the
coordinator asked for explicit confirmation and it is confirmed, with a live probe.

**3. The reviewers' `confirmEmail` pipethrough finding is wrong.** The
`com.atproto.server.*` guard I added is **defense in depth, not the fix for a live hole**.
See §Disagreement, recorded.

---

## What changed in the fix round, per finding

### CRITICAL — `--public-profile` took production down on deploy

`Sources/swan/SwanCommand.swift`. The option was `var publicProfile: String =
"Profiles/public-data-testing-2026-07-27.json"` — a working-directory-relative path. The
runtime image's `WORKDIR` is `/var/lib/swan`, the data volume, which carries no `Profiles/`
directory, and there is no fallback resolution anywhere in `Sources`. Every checked-in serve
invocation passes an absolute `--profile` and no `--public-profile`, so every containerized
`swan serve` would have exited 64 before binding a listener.

Fixed by making the flag genuinely optional and file-free:

- `var publicProfile: String?`. Omitted means `SwanPublicRouteSurface.default`, resolved with
  **zero filesystem access**. It is not a fallback — nothing reaches it after a failed read or
  a rejected id.
- The value may now be a **registered profile id** as well as a path, so a deployment that
  does not mount `Profiles/` can still pin its surface explicitly.
  `Serve.isProfilePath(_:)` distinguishes the two syntactically (contains `/`, or ends
  `.json`) rather than by trying one and falling back, so a misspelled id reports
  "no registered route surface" naming the id instead of "unreadable file".

**Verified against the real binary, from a directory containing no `Profiles/`** — this is the
evidence that matters, and it is the exact condition the first round could not see because
falsification D ran from the package root:

| invocation (cwd has no `Profiles/`) | result |
|---|---|
| `serve` (flag omitted) | **boots**, binds `127.0.0.1:39311`, logs `publicProfile=public-data-testing-2026-08-06 publicMethodCount=19 publicServedMethodCount=20` |
| `serve --public-profile public-data-testing-2026-07-30` | **boots**, `publicMethodCount=18 publicServedMethodCount=19` |
| `serve --public-profile public-data-testing-2026-08-06` | **boots**, `publicMethodCount=19` |
| `serve --public-profile public-data-testing-2099-01-01` | refuses: `--public-profile is unusable: public protocol profile 'public-data-testing-2099-01-01' has no registered route surface in this build` |
| `serve --public-profile Profiles/public-data-testing-2026-08-06.json` | refuses: `…is unreadable` — the path form is still a path, and a missing path is still a refusal |

No compose file, script, or deployment doc needed updating, because the default now requires
no file. `docker-compose.yml`, `interop/docker-compose.reference-relay.yml`, the seven
acceptance scripts, and the netcup unit all continue to work unmodified.

`testThePublicSurfaceIsSelectableWithNoProfilesDirectoryOnDisk` pins all five rows.

### IMPORTANT ×2 — the surface gated only the 503 stubs, not the live routes

This was the substantive finding and it was correct. `configuration.publicRouteSurface.methods`
drove only `registerUnavailablePublicEndpoint`. The four real registrations
(`registerPublicRepositoryReadEndpoints`, `registerPublicRepositoryMutationEndpoints`,
`registerPublicFirehoseStreamingEndpoint`, `accountEmailXRPC?.register`) never consulted it,
so the control worked in the widening direction only and the `publicMethodCount` log line
counted gates rather than served endpoints.

Fixed by making the surface the filter for every public registration:

- `SwanPublicRouteSurface` gains `declaredMethodNSIDs`, the named constant
  `outOfProfilePublicMethods`, and `servedMethodNSIDs = declared ∪ outOfProfile`. The latter
  is the complete allow-list of public NSIDs any assembly may install a handler for. It is
  derived from the private registry and cannot be assembled by a caller, so this remains an
  allow-list at the trust boundary.
- New `Sources/SwanHTTP/SwanPublicRouteSurfaceGating.swift`: `Router.getIfServed(_:in:use:)`
  and `postIfServed`. They take an **NSID**, not a path, so the gate and the route cannot
  disagree about which method is being installed.
- `registerPublicRepositoryReadEndpoints` and `registerPublicRepositoryMutationEndpoints` take
  a **required, non-defaulted** `servedMethods: Set<String>`. A defaulted parameter would have
  let the single production call site keep compiling while silently serving the full set
  again — the exact regression shape. `SwanAccountEmailXRPCServer.register` likewise; its
  public standalone `register(on:)` passes `Self.methodNSIDs` explicitly rather than
  defaulting.
- Wrong-method guards are registered only for installed routes, so an unserved method is
  indistinguishable from one this build does not implement.
- The firehose upgrade is gated at its single call site in `buildRouter` rather than inside
  `PublicFirehoseStreamingRoute.swift`, which is the one public-surface file written in the
  2-space style; keeping the condition in the 4-space file avoids mixing indentation inside
  it. `publicSubscribeReposNSID` is a literal because the wire generator emits no enum for a
  subscription, and `testSubscribeReposLiteralMatchesTheShippedDescriptor` pins the string
  against the shipped descriptor list so a typo fails the suite rather than silently disabling
  the route.

**`com.atproto.identity.resolveHandle` is the one deliberate exception**, and it is now
enumerated instead of implicit. It appears in no profile artifact's `endpoints` array, yet the
read surface registers it, because login on every client depends on it. Gating it on a profile
declaration would delete handle resolution from every deployment with no profile able to
restore it. `outOfProfilePublicMethods` names it, and
`testTheOnlyRouteOutsideEveryProfileIsResolveHandle` asserts it is the *only* member and that
no registered profile declares it.

**The test gap the reviewer named is closed.** `withRouter` assembles zero runtimes, which is
the one configuration where the gap is invisible. Two new cases fix that:

- `testANarrowerProfileRemovesRealHandlersNotOnlyGates` assembles a read directory, a mutation
  directory and signer, an account-email server, and a firehose streaming runtime, then
  selects `2026-07-27` and asserts `POST com.atproto.server.requestPasswordReset` → **404**
  and `GET com.atproto.sync.subscribeRepos` → **404** *while those runtimes are present*, and
  that `getRecord`/`putRecord`/`resolveHandle` stay live (400 from their own request
  validation — a status that distinguishes live route from absent route from 503 gate in one
  assertion). The same assembly under `2026-08-06` gets the email and subscription routes back.
- `testRegistrationFunctionsInstallNothingOutsideTheServedSet` drives the three registration
  functions directly with an empty served set on a bare router with no namespace guards, so a
  404 can only mean "no route". Every shipped profile declares all five mutation methods and
  all seven repository reads, so no pair of shipped profiles can express "reads off, writes
  on"; this is the only way to pin that the filter is the gate rather than a coincidence of
  the current artifacts.

### IMPORTANT ×2 — default surface disagreed with the attested profile

`SwanPublicRouteSurface.default` moves from `public-data-testing-2026-07-27` to
`successorProfileID` / `PublicDataTesting20260805.methods`, i.e.
`public-data-testing-2026-08-06`.
`testDefaultSurfaceIsTheProfileThisBuildAttests` asserts
`SwanPublicRouteSurface.default.profileID == OfflineProtocolProfileVerifier.publicProfileID`,
so `swan verify` and `swan serve` can no longer answer differently for the same build.
`Package.swift` adds `SwanInterop` to `SwanHTTPTests` for that one assertion (no cycle:
`SwanInterop` does not depend on `SwanHTTP`).

The startup log now carries `publicServedMethodCount` alongside `publicMethodCount`. The two
differ by `resolveHandle`; logging only the declared count would understate the served surface
by one, which is the class of thing that line exists to stop.

---

## The load-bearing argument for moving the default — confirmed

The coordinator asked me to confirm this plainly rather than let it be inferred. **It is
correct.**

Combining the real-handler gating (change 2) with a `2026-07-27` default would have
**filtered the six `com.atproto.server.*` email routes out of the live deployment**, which
runs `--enable-email-recovery` (`docker-compose.yml:109`). `PublicDataTesting20260727` has
twelve methods and not one `com.atproto.server.*` entry, so the filter would have removed six
routes that deployment serves today. That is a live functional regression — password recovery
and email confirmation stop existing — not a stylistic question about which constant to name.

This is not reasoned; it is measured. Both runs below are the real binary, both with
`--enable-email-recovery` and a valid proof key, differing only in the public surface:

```
publicProfile=public-data-testing-2026-07-27
POST com.atproto.server.requestEmailConfirmation -> {"error":"public_endpoint_unavailable"} [404]
POST com.atproto.server.confirmEmail             -> {"error":"public_endpoint_unavailable"} [404]
POST com.atproto.server.requestEmailUpdate       -> {"error":"public_endpoint_unavailable"} [404]
POST com.atproto.server.updateEmail              -> {"error":"public_endpoint_unavailable"} [404]
POST com.atproto.server.requestPasswordReset     -> {"error":"public_endpoint_unavailable"} [404]
POST com.atproto.server.resetPassword            -> {"error":"public_endpoint_unavailable"} [404]

publicProfile=public-data-testing-2026-08-06  publicMethodCount=19
POST com.atproto.server.requestEmailConfirmation -> {"error":"InvalidRequest"} [400]
POST com.atproto.server.confirmEmail             -> {"error":"InvalidRequest"} [400]
POST com.atproto.server.requestEmailUpdate       -> {"error":"InvalidRequest"} [400]
POST com.atproto.server.updateEmail              -> {"error":"InvalidRequest"} [400]
POST com.atproto.server.requestPasswordReset     -> {"error":"InvalidRequest"} [400]
POST com.atproto.server.resetPassword            -> {"error":"InvalidRequest"} [400]
```

400 `InvalidRequest` is the real handler rejecting an empty `{}` body. 404
`public_endpoint_unavailable` is the namespace guard answering because no route exists.

Consistency with the attested id is the *secondary* reason. The primary reason is that the
other choice breaks production email recovery.

---

## Endpoint-by-endpoint: what an external caller observes

Live flag set as checked in: `--enable-public-repository-mutations`,
`--enable-local-space-interop`, `--enable-email-recovery`, and **no**
`--enable-public-firehose` (W3 step 2 adds it). The public read directory is passed
unconditionally.

Two comparisons matter and they are different questions. Column A is what the live box does
**today, before this task**. Column B is what it does **after this commit** (default
`08-06`). Column C is the counterfactual the coordinator vetoed: this commit's gating with the
`07-27` default.

| method | A: today (pre-task) | B: after, default `08-06` | C: rejected, `07-27` |
|---|---|---|---|
| `repo.describeRepo`, `repo.getRecord`, `repo.listRecords` | live handler | **unchanged** | unchanged |
| `repo.applyWrites`, `createRecord`, `deleteRecord`, `putRecord`, `uploadBlob` | live handler | **unchanged** | unchanged |
| `sync.getBlob`, `getLatestCommit`, `getRepo`, `getRepoStatus` | live handler | **unchanged** | unchanged |
| `identity.resolveHandle` | live handler | **unchanged** (out-of-profile constant) | unchanged |
| `server.requestEmailConfirmation`, `confirmEmail`, `requestEmailUpdate`, `updateEmail`, `requestPasswordReset`, `resetPassword` | live handler | **unchanged** — live handler | **404, routes gone — regression** |
| `sync.subscribeRepos` | 404 (`com.atproto.sync.*` guard; runtime off) | **unchanged** — 404 | 404 |
| every other `com.atproto.server.*` (`createSession`, `createAccount`, `getSession`, …) | 404, body `{"error":"EndpointUnavailable"}` from the pipethrough's routing refusal | 404, body `{"error":"public_endpoint_unavailable"}` from Swan's own guard — **status identical, body string changes** | same as B |
| `com.atproto.server.describeServer` (GET) | live handler (exact route) | **unchanged** — exact routes outrank the new `server.*` wildcard | unchanged |
| `app.bsky.*`, `chat.bsky.*`, `tools.ozone.*` | pipethrough | **unchanged** | unchanged |

So column B is **byte-identical to today on every endpoint except the 404 body string for
unimplemented `com.atproto.server.*` methods.** Selecting the surface became real without
changing what the live box serves — which is what the first round claimed and could not
deliver.

**One correction to the coordinator's expectation.** `subscribeRepos` does **not** go
404 → 503 `public_data_pending` under `08-06`. `registerUnavailablePublicEndpoint`
(`Sources/SwanHTTP/SwanPublicUnavailableXRPC.swift:28`) returns early for `descriptor.kind ==
.subscription` and registers nothing at all, so with the firehose runtime off the method stays
404 from the `com.atproto.sync.*` wildcard guard whichever profile is selected. Verified in the
live probe above under `08-06`:
`GET com.atproto.sync.subscribeRepos -> {"error":"public_endpoint_unavailable"} [404]`.
Declaring the subscription changes the served surface only once
`--enable-public-firehose` is on, at which point the WebSocket upgrade route is registered
**because** the profile declares it — that is the W3 seam, and it now runs through the
selection instead of around it.

For deployments with **no** account-email runtime (the acceptance scripts, the reference-relay
compose file), the six email methods move 404 → **503 `public_data_pending`**, method-correct:
POST gets the 503 gate, every other verb gets 404. No script or interop expectation asserts a
404 on those paths; grepped `Scripts/`, `interop/`, `docs/`.

---

## Disagreement, recorded

**The reviewers' finding that `com.atproto.server.confirmEmail` "falls past every guard into
`xrpcPipethrough` and is forwarded to the AppView with its request body — the same fail-open
forwarding class as the prior plaintext-password incident" is factually wrong.** The
coordinator independently reached the same conclusion. Evidence:

- `SwanXRPCProxyRouter.proxyablePrefixes` (`Sources/SwanHTTP/SwanXRPCProxyRouting.swift:73-77`)
  is `app.bsky.`, `chat.bsky.`, `tools.ozone.` and nothing else;
  `proxyableMethods` adds exactly `com.atproto.moderation.createReport` and
  `com.atproto.label.queryLabels`. `com.atproto.*` is excluded **by design**, with the comment
  above it naming the plaintext-password incident as the reason the gate was inverted from a
  deny-list to this allow-list.
- The allow-list check runs **before** the proxy header is parsed and before authentication,
  so an unregistered `com.atproto.server.*` NSID is `.unrouted` → 404 with the POST body never
  read and no socket opened.
- Already pinned empirically at `Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift:927`,
  which posts `{"identifier":…,"password":"hunter2"}` to `createSession` and `resetPassword`
  under an `atproto-proxy` header naming a *resolvable* attacker DID document and asserts 404
  with no upstream contact.

I added `/xrpc/com.atproto.server.*` to `registerUnknownPublicEndpointGuards` anyway, and it is
in the diff — but it is **defense in depth, not a closed credential leak**. `server.*`,
`admin.*` and `temp.*` rested on the proxy allow-list alone while `identity.*`, `repo.*` and
`sync.*` had two independent gates; this gives `server.*` the second gate. Recording it as
"closed a credential leak" would teach the next reader that this class of bug was reachable
here, and the next real one would get discounted.

**Comment repair, per ruling 3.** `Sources/SwanHTTP/SwanXRPCProxyRouting.swift:59-63` asserted
that the `PublicDataTesting20260727` descriptor loop registers an unavailable stub for
`com.atproto.server.resetPassword`, so it was "covered either way". That was false when
written and false at the branch base — `20260727` declares twelve methods and no
`com.atproto.server.*` entry, so no stub ever existed for it. It claimed a second layer that
did not exist, in the file a security reviewer opens first. Replaced with the correction plus
a pointer to the real second layer (the new wildcard guard) and an explicit note that
`admin.*` and `temp.*` still rest on the allow-list alone.

---

## Carried forward from the first round, still true

- The allow-list registry, the private memberwise init, the failable `init?(profileID:)`, and
  the artifact-agreement tests are unchanged and still hold.
- `SwanPublicRouteSurface` lives in `Sources/SwanHTTP/`, not `Sources/SwanPublicWire/`,
  because `OfflineProtocolProfileVerifier.verifyGeneratedWireSources` rejects any unlisted
  `.swift` file under `SwanPublicWire`, so even a *new* file there breaks verification of the
  very profile it would serve. `SwanPublicRouteSurfaceGating.swift` is in `SwanHTTP` for the
  same reason.
- No public-read 503 body was touched; `{"error":"temporarily_unavailable"}` is unchanged.
- Nothing in Phase 1 proxying, credential isolation, or peer-pinning was modified.
- `swiftformat` was never run. 4-space indentation throughout the new and edited files.

## Still open, for the backlog

1. **The permissioned surface still ignores `--profile`.** `SwanHTTP.swift` iterates a
   hardcoded `PermissionedData0016.methods` exactly as the public loop used to. An operator
   who passes `--profile Profiles/permissioned-data-0016-2026-07-03.json` gets the 07-30
   permissioned surface regardless. Ruled out of scope for this task; unfixed.
2. **Nothing advertises the public profile on the wire.** `describeServer.swanProfile` reports
   the *permissioned* id. A relay or AppView cannot discover the public contract from the
   wire; the only signal is the startup log. Now that the surface is genuinely selectable this
   is a more meaningful gap than when it was constant.
3. **One uncovered line remains.** The `publicRouteSurface: publicRouteSurface` argument at the
   single `makeServer` call site in `Serve.run()` is not covered by an automated test —
   deleting it would compile, because the parameter defaults. It is covered by the live binary
   probes above (12/18/19-method splits and the endpoint table), but not in CI. `run()` binds
   listeners and opens databases, so it is not unit-testable without restructuring it.
