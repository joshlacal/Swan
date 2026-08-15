# Swan Scoped App Passwords and Legacy Sessions — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the official Bluesky app sign in to swan.place with an app password whose authority is narrower than the account.

**Architecture:** A second *credential type* over the existing authorization model. The OAuth scope grammar and evaluator (`SwanScopePermissions`) already exist and are live; this plan wires them to the atproto method surface, then adds a legacy bearer credential that produces its own `AuthorizationContext` case and is evaluated by that same matcher. No second authorization model.

**Tech Stack:** Swift 6 strict concurrency, Hummingbird router, GRDB/SQLite control DB, libsodium Argon2id, existing `SwanCore/OAuthScopes/`.

**Base revision:** `d30738e4` (workspace `Swan-merge3`) — the integrated tip. **Not** `d58a7583`, which lacks `Sources/SwanCore/OAuthScopes/` entirely.

**Source spec:** `docs/superpowers/specs/2026-08-12-swan-scoped-app-passwords-design.md` (status: Draft for review). **Read the Spec Deltas section below before the spec** — three of its decisions are stale or reversed.

---

## Spec Deltas (measured 2026-08-15 against `d30738e4`)

The spec was written 2026-08-12, two days before the OAuth scopes Phase 2 program landed. Four of its statements no longer describe the tree. These deltas govern where they conflict with the spec.

**Δ1 — D2 is half-done.** The spec says "A scope grammar, an NSID-keyed matcher, and enforcement at every guard site are new work." The grammar and matcher now **exist and ship**: `Sources/SwanCore/OAuthScopes/` with all eight families, and `SwanScopePermissions` exposes `allowsRepo`/`requireRepo`, `allowsRPC`/`requireRPC`, `allowsBlob`/`requireBlob`, `allowsAccount`/`requireAccount`, `allowsIdentity`/`requireIdentity`, `allowsSpace`/`requireSpace`, `allowsSpaceListing`.

**Enforcement is what remains, and it is genuinely unwired.** Measured call-site counts outside `ScopePermissions.swift`:

| Method | Sources/ | Tests/ |
|---|---|---|
| `requireRepo` | **0** | 0 |
| `requireRPC` | **0** | 0 |
| `requireBlob` | **0** | 0 |
| `requireAccount` | **0** | 0 |
| `requireIdentity` | **0** | 0 |
| `requireSpace` | 0 | 1 |

Only `allowsSpace` / `allowsSpaceListing` are wired, into the permissioned-space surface. **Every atproto method the Bluesky app touches is unenforced.** Task 1 is therefore a prerequisite for the whole feature and is worth landing on its own merits.

**Δ2 — D3's payload type changed.** The spec sketches `case accountLegacySession(subject: String, scopes: Set<String>)`. `AuthorizationContext.accountOAuth` now carries a parsed value, not raw strings (`SwanSpaces.swift:229`):

```swift
case accountOAuth(subject: String, permissions: SwanScopePermissions)
```

The legacy case must match: `case accountLegacySession(subject: String, permissions: SwanScopePermissions)`. Parsing happens once at the authentication boundary, never per predicate.

**Δ3 — D6 is REVERSED, and the reversal is ratified and shipped.** The spec says "return `403` with the machine-readable required scope." The later OAuth permission-scopes design explicitly overrode this. `ScopePermissions.swift:585-596`:

> Upstream's `ScopeMissingError` is `expose = true` with `status = 403` and echoes the needed scope to the caller; **Swan deliberately does not (§9-D6)**. Every HTTP adapter maps this to its own opaque per-route code and logs `needed` server-side at `.info` with the route path (§6.5.8).

`ScopeDenied` carries `needed` for the *server log only*. **This plan follows §9-D6, not the app-password spec's D6.** Consequence: the spec's stated mitigation for its own Risk 4 ("too-narrow presets fail invisibly") is gone, so the **"Bluesky app" preset (Task 8) carries the entire mitigation** and must be got right.

> ⚠️ **Maintainer decision required before Task 6.** If you want the needed-scope echoed to app-password callers, that is a deliberate, narrow exception to §9-D6 and must be ruled on explicitly — do not let an implementer infer it. Default if unruled: follow §9-D6 (opaque denial).

**Δ5 — enforcement required a `transition:` port first (found while executing Task 1).**
Transition scopes are flat cases in `AtprotoScope`, so they produce no `.repo` /
`.rpc` / `.blob` grant. Wiring `requireRepo` without a port would have denied
**every credential in the wild**: Catbird's `AuthManager`, nest's `default.toml`
and Petrel all request `atproto transition:generic [transition:chat.bsky]`, and
the live server advertises exactly those in `scopes_supported`.

Upstream solves this with `ScopePermissionsTransition`, a subclass whose
`allows*` overrides let transition scopes stand in for the modern families. The
PDS constructs it **unconditionally** for every OAuth credential
(`auth-verifier.ts:658`) — there is no "transition mode" to select — so Swan
folds the arms into the base matcher rather than mirroring a hierarchy with one
inhabitant. Ported in Task 1: `allowsRepo`/`allowsBlob` (any, on
`transition:generic`), `allowsRPC` (the three-arm `chat.bsky.` split),
`allowsAccount` (`transition:email` → exactly `email`+`read`). **`allowsSpace`
gets NO arm** — upstream overrides it to `super` purely to make the omission a
decision, and Swan has a second reason: an app password with no declared scopes
defaults to `transition:generic`, so an arm there would hand every legacy bearer
credential the permissioned-data surface.

Consequence for Task 8: the `privileged: false` default (`transition:generic`)
already grants the whole repo/blob/non-chat-RPC surface, so the "Bluesky app"
preset's risk is narrower than feared — but `atproto` ALONE now denies writes,
which is upstream's rule and is a live behaviour change.

**Δ4 — "four call sites" is now ~20.** The spec's D3 argues from four `.accountOAuth` guard sites. There are approximately twenty across `SwanSpaces`, `SwanHTTP`, `SwanSQLite`, and `SwanOAuth`. This *strengthens* D3 — the compile-error forcing function is worth more, not less — but it makes Task 5 substantially larger than the spec implies. Budget for it.

---

## Global Constraints

- **Never run `swiftformat` in this repo.** It strips `: Sendable` and emits non-compiling code.
- **Never run bare `swift build` / `swift test`.** Use `xcrun --toolchain XcodeDefault swift …`. Run `--build-tests` before any `--skip-build`.
- Judge a suite by exit code **and** by grepping for `Some test targets reported failures`. Never pipe a test run through `tail`.
- 4-space indentation. Swift 6 strict concurrency; explicit `self` in closures.
- **Never widen a client-visible error body.** New denials reuse the existing opaque per-route codes.
- jj is the sole history-writing authority. No mutating git commands. `jj new` immediately after sealing each task.
- Don't delete files — move to `_trash/`.
- macOS green is **not** sufficient; the deployment target is Linux x86_64 (build on netcup, see `reference_swan_linux_docker_build_recipe`).
- **The OAuth path's DPoP requirements do not change.** Nothing in this plan may relax a check on the OAuth path. `DurableOAuthTokenService.validateAccess` keeps its hard DPoP thumbprint requirement; no nullable `dpopJKT`.
- New feature is off by default behind `--enable-legacy-sessions`, with a startup interlock (see Task 3).

---

## File Structure

**Create:**
- `Sources/SwanAccounts/AppPasswordRecord.swift` — row type, scope validation, presets
- `Sources/SwanAccounts/DurableAppPasswordStore.swift` — Argon2id-hashed storage in the control DB
- `Sources/SwanOAuth/DurableLegacySessionService.swift` — sibling of `DurableOAuthTokenService`; family/rotation/revocation
- `Sources/SwanOAuth/LegacySessionJWT.swift` — `at+jwt` mint/verify, HMAC over the legacy signing key
- `Sources/SwanHTTP/SwanLegacySessionXRPC.swift` — `createSession`/`refreshSession`/`getSession`/`deleteSession`
- `Sources/SwanHTTP/SwanAppPasswordXRPC.swift` — `createAppPassword`/`listAppPasswords`/`revokeAppPassword`
- `Sources/SwanHTTP/ScopeEnforcement.swift` — the adapter mapping `ScopeDenied` → each route's existing opaque code
- Tests mirroring each of the above under `Tests/`

**Modify:**
- `Sources/SwanSpaces/SwanSpaces.swift:219-238` — add the `accountLegacySession` case
- `Sources/swan/SwanCommand.swift` — `--enable-legacy-sessions`, `--legacy-session-signing-key-file`, interlock
- `Sources/SwanHTTP/SwanHTTP.swift:1098` — register legacy routes **before** `registerUnknownPublicEndpointGuards`
- `Sources/SwanHTTP/SwanXRPCPipethrough.swift:~394` — scope check strictly before the service-token mint
- ~20 `.accountOAuth` match sites — state a position for the new case

---

## Task 1: Wire scope enforcement to the repo surface

**Prerequisite for everything else.** Independently valuable: it closes Δ1 for the OAuth path whether or not legacy sessions ship.

**Files:**
- Create: `Sources/SwanHTTP/ScopeEnforcement.swift`
- Create: `Tests/SwanHTTPTests/ScopeEnforcementTests.swift`
- Modify: `Sources/SwanHTTP/SwanPublicRepositoryMutationXRPC.swift:460`

**Interfaces:**
- Consumes: `SwanScopePermissions.requireRepo(_:)`, `RepoPermission.Target`, `ScopeDenied`
- Produces: `func enforce<T>(_ body: () throws -> T, route: String, logger: Logger) rethrows -> T` — catches `ScopeDenied`, logs `needed` at `.info` with the route path, rethrows the route's own opaque error

- [ ] **Step 1: Write the failing test** — a permissions value granting `repo:app.bsky.feed.like?action=create` must be denied `app.bsky.feed.post` create, and the denial must surface the route's existing opaque code, **not** the needed scope.

```swift
@Test func postCreateDeniedWhenOnlyLikeGranted() throws {
    let permissions = try SwanScopePermissions(rawScopes: ["atproto", "repo:app.bsky.feed.like?action=create"])
    #expect(!permissions.allowsRepo(.init(collection: "app.bsky.feed.post", action: .create)))
    let error = #expect(throws: ScopeDenied.self) {
        try permissions.requireRepo(.init(collection: "app.bsky.feed.post", action: .create))
    }
    #expect(error?.needed.contains("app.bsky.feed.post") == true)
}
```

- [ ] **Step 2: Run it and confirm it fails** — `xcrun --toolchain XcodeDefault swift test --filter ScopeEnforcementTests`. Confirm the *exact* `RepoPermission.Target` initializer against `Sources/SwanCore/OAuthScopes/Families/RepoPermission.swift` and correct the test if the label differs; do not change the production type to fit the test.
- [ ] **Step 3: Add the enforcement adapter** in `ScopeEnforcement.swift`, mapping `ScopeDenied` to the route's existing opaque code and logging `needed` server-side per §6.5.8.
- [ ] **Step 4: Call `requireRepo` at `SwanPublicRepositoryMutationXRPC.swift:460`**, immediately after the `.accountOAuth` binding, before any mutation work.
- [ ] **Step 5: Add the undeclared-route-denies test** (D5): a route with no declared scope requirement denies rather than defaults permissive.
- [ ] **Step 6: Run the full SwanHTTP + SwanCore suites.** Existing OAuth sessions must not regress — a full-access credential still passes every site.
- [ ] **Step 7: Seal, then `jj new` immediately.**

---

## Task 2: Wire enforcement to the blob and RPC surfaces

**Files:** Modify the blob upload path and `Sources/SwanHTTP/SwanXRPCPipethrough.swift`. Test: `Tests/SwanHTTPTests/ScopeEnforcementPipethroughTests.swift`

**Interfaces:** Consumes Task 1's `enforce`. Produces the D4 ordering guarantee.

D4 is exact and load-bearing: the check goes **after authentication and strictly before the service-token mint** at `SwanXRPCPipethrough.swift:~394`. It must **not** be folded into `SwanXRPCProxyRouter.route`, which is pure and caller-independent by design. Required order:

```
1. parse NSID
2. route()                        — caller-independent  -> 404
3. authenticate -> AuthorizationContext                 -> 401
4. scope check (subject's scopes vs NSID)               -> 403
5. resolve / MINT / send
```

- [ ] **Step 1: Write the failing test** — a credential without `rpc:app.bsky.feed.getTimeline` is refused, and **no service token is minted**. Assert on the mint not happening, not merely on the status code; a test that only checks 403 passes even if the token was minted and discarded.
- [ ] **Step 2: Run it, confirm it fails.**
- [ ] **Step 3: Insert `requireRPC`** at the point named above, with `lxm` bound to the parsed NSID.
- [ ] **Step 4: Wire `requireBlob`** on the upload path.
- [ ] **Step 5: Run SwanHTTP suite. Seal, `jj new`.**

---

## Task 3: Legacy signing key, feature flag, and startup interlock

**Files:** Modify `Sources/swan/SwanCommand.swift`. Test: `Tests/SwanTests/LegacySessionInterlockTests.swift`

**Interfaces:** Produces `--enable-legacy-sessions` and `--legacy-session-signing-key-file`.

**Swan does not use Doppler — it has zero Doppler references.** Secrets are owner-only files mounted at `/run/secrets/swan-runtime/`, selected by a `--*-key-file` flag. Mirror `--email-proof-key-file` exactly (`SwanCommand.swift:2022, 2437-2448, 3005`), which is already "Owner-only mounted base64url 32-byte HMAC key required by `--enable-email-recovery`".

```swift
@Option(
    name: .customLong("legacy-session-signing-key-file"),
    help: "Owner-only mounted base64url 32-byte HMAC key required by --enable-legacy-sessions"
)
var legacySessionSigningKeyFile: String?
```

- [ ] **Step 1: Write the failing interlock tests** — three cases, all refusing to boot: (a) `--enable-legacy-sessions` with no key file; (b) key file present but empty/whitespace; (c) key file given *without* the enable flag. Mirror the `emailProofKeyFile` guards at `SwanCommand.swift:2437-2448`.
- [ ] **Step 2: Run, confirm they fail.**
- [ ] **Step 3: Add the option, the guards, and the key load.** Reuse the existing owner-only secret-file reader (`secretFile:` idiom) — do not hand-roll file permission checks.
- [ ] **Step 4: Run. Seal, `jj new`.**

**Deployment note (do not perform in this task):** shipping this later requires a new file in `/srv/swan/secrets/` and two new flags in `/etc/systemd/system/swan.service`. **Adding a flag the deployed binary does not know is a boot loop** — see `reference_swan_deploy_verify_unit_flags`. Unit and image must move together.

---

## Task 4: App-password storage

**Files:** Create `Sources/SwanAccounts/AppPasswordRecord.swift`, `Sources/SwanAccounts/DurableAppPasswordStore.swift`. Test: `Tests/SwanAccountsTests/DurableAppPasswordStoreTests.swift`

**Interfaces:**
- Consumes: `LibsodiumArgon2idHasher` (`Sources/SwanAccounts/PasswordHashing.swift:38`), `AccountControlStore`'s existing credential idiom, the existing off-thread executors.
- Produces: `create(did:name:scopes:) -> (record, plaintextShownOnce)`, `list(did:)`, `revoke(did:id:)`, `verify(did:password:) -> AppPasswordRecord?`

D7: hash with `LibsodiumArgon2idHasher`, rows in the control DB alongside `accounts`. Plaintext is returned exactly once at creation and never stored.

- [ ] **Step 1: Write failing tests** — create→verify round trip; wrong password rejected; revoked password rejected; plaintext never persisted (assert the stored column does not contain it); `list` echoes `scopes`.
- [ ] **Step 2: Run, confirm failing.**
- [ ] **Step 3: Add the migration.** Check `reference_mls_ds_reviewed_migration_fixed_target`-style constraints for this repo before writing it — confirm whether Swan's control-DB migrations are a fixed target in the same way, and if so land the migration in its own change.
- [ ] **Step 4: Implement the store** against the existing credential idiom. Argon2id verification runs on the existing off-thread executor, not the event loop.
- [ ] **Step 5: Run SwanAccounts suite. Seal, `jj new`.**

---

## Task 5: The `accountLegacySession` case (compile-error forcing function)

**Files:** Modify `Sources/SwanSpaces/SwanSpaces.swift:219-238` and every site the compiler flags (~20). Test: `Tests/SwanSpacesTests/LegacySessionDenialTests.swift`

**Interfaces:** Produces `AuthorizationContext.accountLegacySession(subject:permissions:)`.

Per Δ2:

```swift
case accountLegacySession(subject: String, permissions: SwanScopePermissions)
```

The point of this task is that it **does not compile** until every switch states a position. `SpaceAuthorizationPolicy.require` switches all cases with no `default:`.

- [ ] **Step 1: Write the failing test first** — the permissioned-space surface **denies** `.accountLegacySession`. This is the spec's required compile-time gate.
- [ ] **Step 2: Add the case.** Build and collect the full list of errors — that list *is* the reviewable surface D3 exists to produce.
- [ ] **Step 3: Resolve every site by DENYING**, with a one-line comment naming why. **Do not opt any site in during this task.** Opting in is a separate, deliberate decision per site; a task that both introduces the case and grants it authority defeats the entire mechanism.
- [ ] **Step 4: Record the site list** in the task report so the reviewer can audit each decision.
- [ ] **Step 5: Full build + full suite. Seal, `jj new`.**

---

## Task 6: `DurableLegacySessionService` and the `at+jwt` mint

**Files:** Create `Sources/SwanOAuth/DurableLegacySessionService.swift`, `Sources/SwanOAuth/LegacySessionJWT.swift`. Tests alongside.

**Interfaces:** Consumes Task 3's signing key, Task 4's store. Produces `issue(did:permissions:)`, `refresh(refreshJwt:)`, `revoke(family:)`, `validateAccess(accessJwt:) -> AuthorizationContext`.

D8: a **sibling** of `DurableOAuthTokenService`, with its own tables, reusing its *design* — family/rotation/revocation with reuse detection and family-wide revocation, digests at rest, never plaintext. Read `Sources/SwanOAuth/DurableOAuthTokenService.swift` as the model. **Do not modify it.**

Access JWT: `typ: at+jwt`, `sub` = DID, `aud` = service DID, plus a `scope` claim.

- [ ] **Step 1: Write failing tests** — mint/verify round trip; wrong signature rejected; expired rejected; refresh rotates; **reuse of a rotated refresh token revokes the whole family**.
- [ ] **Step 2: Run, confirm failing.**
- [ ] **Step 3: Implement**, modelled on the OAuth service.
- [ ] **Step 4: Add the D5 refresh test** — refresh **re-derives scope from the app-password row**, never from the session row, so editing a password narrows live sessions on next refresh and revoking it kills them. Refresh may never widen: identical scope set or nothing.
- [ ] **Step 5: Run. Seal, `jj new`.**

---

## ✅ Task 7's blocker was WRONG — Petrel already has the types

An earlier revision of this plan recorded Task 7 as blocked on the SHA-pinned
21-lexicon wire inventory. **That was a mistake and the blocker does not exist.**

`SwanPublicWire` indeed has no session types — but `Petrel` does, and Swan
already depends on it: `ComAtprotoServerCreateSession`, `RefreshSession`,
`GetSession`, `DeleteSession`, with exactly the shapes the spec calls for
(`identifier`/`password`/`authFactorToken`/`allowTakendown` in, and
`accessJwt`/`refreshJwt`/`handle`/`did`/`didDoc` out). Eighteen files in
`SwanHTTP` already `import Petrel`, and `SwanAccountEmailXRPC` already registers
the email family from Petrel's `ComAtprotoServer*` types.

So the session endpoints use Petrel's generated types, no pinned manifest is
touched, and no maintainer decision is required. The pinned inventory guards the
permissioned-data wire; this family is not part of it.

## Task 7: The session endpoints

**Files:** Create `Sources/SwanHTTP/SwanLegacySessionXRPC.swift`. Modify `Sources/SwanHTTP/SwanHTTP.swift:1098`. Tests alongside.

**Registration order is the subtle part.** `registerUnknownPublicEndpointGuards` closes `/xrpc/com.atproto.server.*` with a flat 404. Exact routes outrank a `<prefix>.*` guard in Hummingbird's trie **regardless of registration order** — that is how `describeServer` survives today. So register exact routes for the four NSIDs and **leave the prefix guard intact**. Do not weaken or remove it.

`createSession` accepts `identifier`, `password`, `authFactorToken`, `allowTakendown`; returns `accessJwt`, `refreshJwt`, `handle`, `did`, `didDoc`. The `didDoc` drives the client's endpoint update and is not optional in practice.

D7: `createSession` calls `DurableAccountDirectory.authenticateForLogin` (`Sources/SwanAccounts/DurableAccountDirectory.swift:286`) rather than growing a second login path — it is already enumeration-resistant with exactly one Argon2id verification on every path. It returns `AccountLoginAuthenticationOutcome` (`.authenticated` / `.rejected`) and throws `AccountLoginAuthenticationError.unavailable` separately, so **infrastructure failure must not be reported as bad credentials**.

- [ ] **Step 1: Write failing tests** — createSession with a valid app password returns all five fields; bad password rejected; **unknown account and bad password are indistinguishable in body and in timing shape**; `unavailable` surfaces as 503, not 401; the four endpoints are reachable while every other `com.atproto.server.*` NSID still 404s.
- [ ] **Step 2: Run, confirm failing.**
- [ ] **Step 3: Implement the four endpoints.** Rate-limit `createSession` (D7 — a guessable-length secret with no second factor).
- [ ] **Step 4: Verify the guard still holds** — assert `com.atproto.server.resetPassword` and `createAccount` remain 404.
- [ ] **Step 5: Run. Seal, `jj new`.**

---

## Task 8: Presets, scope validation at creation, and the management endpoints

**Files:** Create `Sources/SwanHTTP/SwanAppPasswordXRPC.swift`; extend `AppPasswordRecord.swift`. Tests alongside.

**Interfaces:** Consumes Task 4's store and the existing grammar parser.

D6 (surviving half): validate scopes at creation and **reject** unparseable ones. tranquil never calls its own validator, so a bad scope silently grants nothing while telling the user it worked.

Backward-compatible default when `scopes` is absent: `privileged: false` → `transition:generic`; otherwise `transition:generic transition:chat.bsky`.

Presets:

| Preset | Scopes |
|---|---|
| Full | none (unrestricted) |
| Read-only | `rpc:app.bsky.*?aud=* rpc:chat.bsky.*?aud=* account:status?action=read` |
| Post-only | `repo:app.bsky.feed.post?action=create blob:*/*` |
| **Bluesky app** | repo write across `app.bsky.*`, blob upload, `rpc:app.bsky.*`, `rpc:chat.bsky.*` when DMs are wanted, `rpc:` for the video service |

> ⚠️ **Per Δ3, the "Bluesky app" preset now carries the entire mitigation for Risk 4.** The client never inspects scopes, and the denial is opaque, so a too-narrow preset surfaces as unexplained 403s mid-session with nothing in the response to explain them. Derive this preset from the **measured** traffic in Task 10, not from a guess, and treat any 403 observed there as a preset defect until proven otherwise.

- [ ] **Step 1: Write failing tests** — unparseable scope rejected at creation; each preset parses; the `privileged` defaults; `listAppPasswords` echoes `scopes`; the three load-bearing grammar details hold (`rpc:*?aud=*` rejected outright; `aud` matching strips `#fragment`; `.*` is dot-boundary, not `starts_with`).
- [ ] **Step 2: Run, confirm failing.**
- [ ] **Step 3: Implement** the three endpoints and the preset table.
- [ ] **Step 4: Run. Seal, `jj new`.**

---

## Task 9: Close the `getServiceAuth` laundering hole

**Files:** Modify the `getServiceAuth` path. Test: `Tests/SwanHTTPTests/ServiceAuthLaunderingTests.swift`

This is D5's real finding and the sharpest security item in the plan. `getServiceAuth` converts a narrow PDS credential into a token a *different* service honours. tranquil checks `lxm` only when supplied, and requires it only for OAuth — so a scoped app password that simply **omits** `lxm` falls through with no check and receives a token with `lxm: None`, which the audience honours for any method. Its own "post-only" preset, granting zero `rpc:` scopes, can obtain one.

**Swan requires `lxm` from every non-full-access credential and validates both `aud` and `lxm` against the granted `rpc:` scopes.**

- [ ] **Step 1: Write the failing tests** — (a) non-full-access credential omitting `lxm` is **refused**, not defaulted; (b) `lxm` outside granted `rpc:` scopes refused; (c) `aud` outside granted scopes refused; (d) a full-access credential still works; (e) the post-only preset cannot obtain a service token.
- [ ] **Step 2: Run, confirm failing.**
- [ ] **Step 3: Implement.** `aud` matching strips the `#fragment` — `did:web:api.bsky.app` matches `…#bsky_appview`.
- [ ] **Step 4: Run. Seal, `jj new`.**

---

## Task 10: Live verification against the official Bluesky app

**Per this project's rules, a clean build is not "done" and a green suite is not "done."** This task is the deliverable.

- [ ] **Step 1: Build for Linux x86_64 natively on netcup** — it cannot be cross-built on the Mac (`swiftc` SIGILLs under qemu). Follow `reference_swan_linux_docker_build_recipe`: scratch path **outside** the bind mount, and check `Package.resolved` is still 35 pins afterward.
- [ ] **Step 2: Pre-flight the unit flags** — diff `/etc/systemd/system/swan.service`'s flags against the new binary's `serve --help` per `reference_swan_deploy_verify_unit_flags`. Task 3 adds two flags, so **the unit and the image must be updated together or the service boot-loops.**
- [ ] **Step 3: Tag the outgoing image** `swan:rollback-<date>-<letter>` before cutting over. Capture a baseline: `describeServer`, and `getHostStatus` from `bsky.network`.
- [ ] **Step 4: Deploy, then verify** the container is up and the public surface is unchanged.
- [ ] **Step 5: Create a "Bluesky app" preset password** and sign in from the official Bluesky app to swan.place.
- [ ] **Step 6: Exercise and record** — load a timeline, post, upload an image, and with a privileged password open DMs. **Capture every 403.** Per Δ3 the client cannot explain them, so each one is a preset or enforcement defect to be diagnosed from the server-side `needed` log, not from the client.
- [ ] **Step 7: Confirm session resume** — `refreshSession` is called on every resume and automatically on any 401. Kill and relaunch the app; it must not require re-login.
- [ ] **Step 8: Re-check federation** — `getHostStatus` must be back to `active`. If a boot loop occurred, `requestCrawl` to restore it.
- [ ] **Step 9: Record the result**, including the final preset scope string, in a completion record beside this plan.

---

## Self-Review

**Spec coverage:** D1 → Tasks 1, 2, 8 (shared grammar, already built; this wires it). D2 → Tasks 1, 2 (narrowed by Δ1). D3 → Task 5. D4 → Task 2. D5 → Tasks 6, 9, and the undeclared-route-denies step in Task 1. D6 → Task 8 for the validate-at-creation half; the denial half is **superseded by Δ3**. D7 → Tasks 4, 7. D8 → Task 6. Endpoint surface → Tasks 7, 8, 9. Presets → Task 8. Testing → distributed. Non-goals respected: no account creation, no second authorization model, no DPoP change.

**Known gap:** `createAccount` remains 404 and `describeServer` reports `availableUserDomains: []`, so a Bluesky-app user can sign in to an operator-provisioned account but cannot create one. That is the separate OAuth account-creation work and is deliberately out of scope here.

**Ordering:** Tasks 1-2 before 5-7 — enforcement must exist before a credential relies on it, or legacy sessions ship with the same all-or-nothing authority the feature exists to avoid. Task 3 before 6. Task 4 before 6 and 7. Task 9 may run any time after Task 2 but must land before Task 10.
