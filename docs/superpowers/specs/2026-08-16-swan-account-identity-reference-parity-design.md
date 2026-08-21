# Swan account, identity, and reference parity design

**Date:** 2026-08-16  
**Status:** Authoritative design for the account/identity program; design only  
**Supersedes:** `2026-08-12-swan-account-management-ui-design.md` and
`2026-08-12-swan-scoped-app-passwords-design.md`

This document is the contract for Tasks 2–9 of
`docs/superpowers/plans/2026-08-16-swan-account-identity-reference-parity.md`.
It freezes the interfaces, security boundaries, lane ownership, and evidence
requirements. It does not authorize a push, deployment, relay activation,
production-secret change, DNS change, or external CAPTCHA widget.

## 1. Current source reality

The design starts from the checked-in, security-remediated tree rather than the
two 2026-08-12 drafts.

| Area | Current reality | Consequence for this program |
|---|---|---|
| Account control | `DurableAccountDirectory` and `SQLiteControlDatabase` persist accounts, Argon2id verifiers, lifecycle state, key references, email state, recovery outbox, and bounded login admission. `authenticateForLogin` performs one verifier check and distinguishes rejection from unavailable infrastructure. | Reuse these boundaries; do not create a second password verifier or login-rate-limit path. |
| HTTP account surface | The public router has bounded account-email XRPC and OAuth/browser surfaces. There is no self-service `createAccount`, no `/account/api/*`, and no static account portal. | The management API and portal are new, isolated construction. |
| Public signup advertisement | `SwanHTTPConfiguration.inviteCodeRequired` is configuration and defaults to `false` because Swan has no invite issuance, redemption, or enforcement today. | Never advertise an invite requirement until enforcement and single-use storage ship together. |
| Identity | Current account provisioning is PLC-oriented; handle validation and public PLC identity verification are present. `did:web` claims, external-control revalidation, and identity-update APIs are absent. | BYO `did:web` is a new method-specific binding; it must not reuse PLC mutation authority. |
| Authorization | `AuthorizationContext` currently has `.public`, `.accountOAuth`, space delegation/read/credential, and service cases. OAuth remains DPoP-bound. | Add management and legacy cases deliberately, with exhaustive switches and no default. Cookies never enter XRPC authorization. |
| Migration | Account-control schema evolution is assembled by the existing SQLite control-store migration path, including email/recovery and login-rate-limit capacity guards. | One integration owner alone edits shared migration functions and migration ordering. |
| Security posture | The source carries bounded body admission, route-surface selection, public-read generation fences, trusted login peer handling, peer-pinned outbound transports, and lifecycle/signing fences. These are prerequisites, not proof that this program is deployed. | New account paths inherit those controls and add their own isolation, CSRF, origin, rate, and step-up tests. |

The pinned local reference is the checkout at
`/Users/joshlacalamito/Developer/Catbird+Petrel/atproto`. Its account lexicons
remain the wire compatibility authority for `createAccount`, session methods,
and app-password methods. Its OAuth provider API supplies the comparison shape
for sign-up/sign-in, device and OAuth session management, same-origin checks,
and double-submit CSRF; it is not copied as implementation.

## 2. Four-release program

The approved milestones are fixed product boundaries, not deployment approvals.
Dependencies may be staged internally, but implementation notes must not move
features between milestones. Each milestone gets a sealed jj checkpoint and
local evidence before the next begins.

1. **M1 — compatibility + portal.** This milestone includes signup policy,
   invites and email recovery/proof, PLC and BYO `did:web`, legacy sessions,
   scoped app passwords, and the complete static account portal. Shared
   contracts and migrations are prerequisites, not a separate product
   milestone.
2. **M2 — MFA.** This milestone includes passkeys, TOTP, recovery codes,
   authentication-strength rules, and fresh step-up enforcement across M1
   management, OAuth, legacy-password, and sensitive account operations.
3. **M3 — remaining reference breadth.** This milestone includes identity,
   repo/sync, admin, moderation, and other reference-compatible API breadth
   not required to complete M1 or M2.
4. **M4 — operations.** This milestone includes metrics/readiness, backup and
   restore drills, rotation/recovery evidence, Linux/browser/client/network
   acceptance artifacts, and final integration/handoff.

No milestone is a production cutover. The 2026-08-12 UI draft is expanded from
“credentials only” into the M1 portal, and the scoped-password draft is the M1
legacy-auth contract. Neither permits widening OAuth or cookie-authenticating
XRPC.

## 3. Account HTTP contract

### 3.1 Routing and credential isolation

Hummingbird remains the only production runtime. A build-only SvelteKit project
uses `adapter-static` and emits static files; the production image has no Node
runtime or SvelteKit server.

| Method and path | Authentication | Purpose |
|---|---|---|
| `GET /account` and `GET /account/*` | none | Static portal shell/fallback. |
| `GET /account/api/bootstrap` | pre-auth | Issues/refreshes a pre-auth CSRF cookie and returns its one-time bootstrap token; no account data or session is returned. |
| `GET /account/api/signup/policy` | none | Exact advertised `SignupPolicy`, allowed handle domains, and enabled capabilities. |
| `POST /account/api/signup/email/request` | none | Rate-limited verification-email request; always generic `202` for syntactically valid input. |
| `POST /account/api/signup/authorize` | none | Validates policy proof and returns a short-lived, one-time `verificationCode` bound to the submitted handle/email/identity. |
| `POST /account/api/signup` | one-time signup authorization | Consumes authorization atomically and creates the account; returns the portal management session and reference-compatible account summary. |
| `POST /account/api/login` | password in JSON | Enumeration-resistant password login; sets management cookie and returns CSRF token plus account summary. |
| `GET /account/api/session` | management cookie | Current account, identity method, lifecycle state, factors, and session strength. |
| `POST /account/api/logout` | management cookie | Revokes the current management session and clears cookies. |
| `GET/POST /account/api/profile` | management cookie / fresh step-up for writes | Handle, email, password, and profile lifecycle operations. |
| `GET/POST/DELETE /account/api/identity` | management cookie / fresh step-up | View, claim, revalidate, or release the account identity binding. |
| `GET /account/api/app-passwords` | management cookie | List metadata only; never secrets. |
| `POST /account/api/app-passwords` | management cookie + fresh step-up | Create one scoped app password and return its secret exactly once. |
| `DELETE /account/api/app-passwords/:name` | management cookie + fresh step-up | Revoke by canonical name and all derived legacy sessions. |
| `GET /account/api/sessions` | management cookie | OAuth families, legacy sessions, and management sessions, with no tokens or secrets. |
| `DELETE /account/api/sessions/:id` | management cookie + fresh step-up | Revoke one owned session/family. |
| `POST /account/api/sessions/revoke-others` | management cookie + fresh step-up | Revoke every other session, never the current management session. |
| `GET /account/api/scope-presets` | management cookie | Preset names, descriptions, and canonical scope strings. |
| `POST /account/api/scopes/validate` | management cookie | Parse and normalize a candidate scope set without issuing a credential. |
| `GET /account/api/factors` | management cookie | Factor metadata, never TOTP secrets or recovery codes. |
| `POST/DELETE /account/api/factors/passkeys/:id` | management cookie + fresh step-up | Enroll/remove passkeys; assertion is required for step-up. |
| `POST/DELETE /account/api/factors/totp` | management cookie + fresh step-up | Enroll, verify, rotate, or remove encrypted TOTP. |
| `POST /account/api/factors/recovery-codes/rotate` | management cookie + fresh step-up | Replace hashed one-time recovery codes and return them once. |
| `POST /account/api/step-up` | management cookie | Re-authenticate password or a configured factor and record fresh strength/time. |
| `GET/POST /account/api/connected-apps` | management cookie / fresh step-up for revocation | OAuth grants and revocation; no DPoP token material. |
| `GET/POST /account/api/export` and `/migration` | management cookie + fresh step-up | Export/restore preparation and bounded migration actions. |
| `POST /account/api/lifecycle/delete` | management cookie + fresh step-up | Begin permanent deletion using existing deletion primitives. |

Unknown `/account/api/*` paths return `404`; they never fall through to the SPA
fallback. Unknown `/account/*` non-API paths may return the static fallback.
The API route trie is registered before the fallback and tested for precedence.

### 3.2 Cookie, CSRF, origin, and headers

The management credential is an opaque, uniformly random 256-bit session ID.
Only a keyed digest and bounded metadata are stored. It is not an OAuth token,
legacy session, app password, or browser OAuth-consent cookie.

* Session cookie: `__Secure-swan_management`, `HttpOnly; Secure;
  SameSite=Strict; Path=/account`, no `Domain`, bounded idle and absolute
  lifetimes, and rotation on login and privilege transition.
* Pre-auth bootstrap cookie: `swan_csrf_pre`, `Secure; SameSite=Strict;
  Path=/account`, no `Domain`, non-HttpOnly solely so the portal can echo it
  as `X-Swan-CSRF`. `GET /account/api/bootstrap` returns the matching token;
  the token is short-lived, single-use for a successful authentication or
  signup commit, and may be refreshed without account disclosure. If an
  `Origin` is present on bootstrap it must equal the configured public origin;
  a present `Sec-Fetch-Site` must be `same-origin` or `none`.
* Every `POST`/`PUT`/`PATCH`/`DELETE` under `/account/api/*`, including login,
  email request, signup authorization, and final signup, requires JSON content
  type, an `Origin` exactly equal to the configured public URL origin (scheme,
  host, and effective port), `Sec-Fetch-Site: same-origin` or `none`, and a
  constant-time match of the pre-auth or management CSRF cookie/header. Missing
  origin, fetch-site, cookie, or header is rejected. CORS is not enabled and
  no credentialed wildcard response is allowed.
* On successful login or final signup, the pre-auth token is consumed and both
  the management session and its rotated `swan_csrf` token are issued in the
  same response. Once a management session exists, mutations use only
  `swan_csrf`; a pre-auth token cannot be replayed to create another session.
  Safe `GET` requests do not require CSRF but still authenticate the cookie,
  except the deliberately public bootstrap/policy GETs.
* Management cookies are considered only under `/account/api/*`. Bearer,
  DPoP, OAuth, service, and app-password credentials are rejected there.
  `/xrpc/*` continues to accept its existing bearer/DPoP context only; it
  never reads the management cookie. This is an authorization invariant, not
  merely a route convention.
* Account responses use the account CSP (`default-src 'none'`, scripts/styles
  self and build hashes, `connect-src 'self'`, `frame-ancestors 'none'`,
  `base-uri 'none'`). OAuth pages retain their script-free strict CSP.
  Sensitive responses use `Cache-Control: no-store` and do not log passwords,
  CSRF values, tokens, app-password secrets, or recovery codes.

### 3.3 Failure behavior

All JSON errors use a stable machine `code`, a safe human message, and an
optional `requiredScope` or `retryAfter`; they never echo a password, token,
secret, raw DID document, or provider response.

| Condition | Response |
|---|---|
| Missing/malformed/expired/revoked credential, or wrong password | `401` with generic `authentication_required`; login timing and body do not reveal account existence. |
| Wrong origin, CSRF, fetch-site, or credential family | `403` with generic `request_not_allowed`; do not distinguish which check failed to an attacker. |
| Missing factor or stale step-up | `403` with `factor_required` or `step_up_required` and an allowed-factor list only. |
| Suspended/deactivated/takedown account | `403` with `account_unavailable`; reads of public repository data remain governed by existing public lifecycle rules. |
| Valid authentication but insufficient scope/ownership | `403` with `insufficient_scope`; XRPC adapters include the machine-readable required scope. |
| Invalid field, DID document, scope, or proof | `422` with field-safe validation codes. |
| Duplicate handle/email/name or consumed claim | `409` without disclosing the other account. |
| Rate limit | `429` with bounded `Retry-After`; no unbounded durable row creation. |
| Storage, verifier, SMTP, resolver, or key-store outage | `503` with opaque `service_unavailable`; no fallback to weaker auth or unbounded retry. |

## 4. Signup and identity contracts

### 4.1 `SignupPolicy`

The shared contract is an exhaustive enum:

```text
SignupPolicy.closed
SignupPolicy.inviteRequired
SignupPolicy.openProtected
```

The policy and its advertisement are one configuration value. `closed`
advertises no public signup and rejects the signup endpoints. `inviteRequired`
requires a valid single-use invite and bounded login/signup rate admission; it
does not require Turnstile by default. `openProtected` requires both a verified
email proof and server-side Turnstile verification for every account creation.
Deployments may add stricter requirements, never weaker ones. Phone
verification is not part of this program. `describeServer.inviteCodeRequired`
is derived as `policy == .inviteRequired`, and is never set independently.

Authorization is two phase, with durable pending state so downstream failure
does not burn a proof or invite:

1. `signup/email/request` sends a bounded authenticated-SMTP verification
   message when the policy requires email. Syntactically invalid input is
   rejected; valid unknown and known addresses get the same response and
   timing. A proof is short-lived and bound to email and requested handle.
2. `signup/authorize` validates handle/domain/password preconditions, reserves
   (but does not consume) the invite and email proof, verifies Turnstile
   `siteverify` for the exact configured action/hostname when required, and
   creates a durable pending authorization keyed by a caller-supplied
   idempotency/request ID. The pending row records `issued`, `committing`,
   `committed`, or `failed`, an expiry/lease, and the exact policy, handle,
   email, identity claim, and client-IP admission bucket. A lease expiry
   releases reservations; it does not mark proof consumed.
3. `signup` retries the same request ID against that pending row. One SQLite
   transaction creates the account, identity binding, key references, and
   initial session, then marks the invite/proof and pre-auth CSRF consumed and
   the pending row `committed`. If key provisioning or another downstream
   dependency fails before that transaction, the row is `failed`/retryable and
   reservations remain available; if the commit succeeded, retries return the
   same sanitized account/session result. A different request ID cannot mint a
   second identity from the same proof or invite.

The reference `com.atproto.server.createAccount` adapter maps its
`verificationCode`, `inviteCode`, `email`, `handle`, `did`, `password`,
`recoveryKey`, and `plcOp` fields into this authorization. It returns the
reference session shape only after the local account and key transaction is
durable. Unsupported `verificationPhone` is rejected explicitly rather than
silently ignored.

### 4.2 PLC and BYO `did:web`

PLC remains Swan-controlled identity: existing PLC preparation/activation,
reserved signing/rotation references, and export/restore continuity remain the
authority. A user may instead claim an externally controlled `did:web` only
through the following one-time binding. Signup and authenticated existing-account
claim/replacement use one shared durable `DidWebClaimTransaction` service; they
do not have separate nonce-consumption or binding-write paths.

The transaction takes a caller idempotency key, target DID/handle, requested
document, and (for an existing account) a fresh step-up receipt. Its state is
`reserved`, `pendingValidation`, `committing`, `committed`, `failed`, or
`expired`. The shared sequence is: reserve the exact Swan key and one-time
nonce; fetch and validate the exact DID, handle, reserved key, PDS endpoint,
and temporary claim service; then atomically persist a new binding or replace
the existing binding while appending its prior digest/key/claim to history and
consuming the nonce. Existing-account claim/replacement must re-check the
step-up receipt at commit and requires `stepUp(password)` when MFA is disabled
or `stepUp(passwordPlusTOTP|passwordPlusPasskey)` when MFA is enabled.

Reservation expiry releases the key/nonce reservation without consuming it.
Storage or downstream failure before the commit transaction leaves the nonce
unconsumed and the pending operation retryable; it never silently burns proof.
A retry with the same idempotency key and identical input returns the same
sanitized committed result, while a different input for that key is `409`.
After commit, retries do not refetch or mint a second binding. These semantics
apply identically to signup's account-creation transaction and an existing
account's identity claim/replacement transaction.

1. A reservation operation returns Swan's reserved repository public signing
   key (the exact key ID, key type, and encoded public key bytes) and a fresh
   32-byte one-time claim nonce. Swan never asks an external assertion key to
   sign this claim. The canonical claim bytes are the length-delimited UTF-8
   tuple `did`, `at://handle`, configured public PDS URL, key ID, encoded
   reserved public key, nonce, and expiry, prefixed with the exact domain
   separator `swan.didweb.claim.v1\0`. Each text field is UTF-8 preceded by a
   big-endian `u64` byte length; nonce is exactly 32 raw bytes and expiry is a
   big-endian `u64` Unix-millisecond value. The tuple order and byte encoding
   are frozen and hashed with SHA-256 for the claim receipt.
2. The submitted DID is syntactically canonical and the DID document is fetched
   through the hardened `did:web` resolver at the method-defined HTTPS URL;
   redirects, non-HTTPS endpoints, private/special-purpose resolved peers, and
   subject changes are rejected. The document must contain exact `id == did`,
   exact `alsoKnownAs` entry `at://handle`, the exact reserved Swan signing
   key returned by reservation (matching key ID/type/encoded bytes, with
   `controller == did` and the key ID referenced from `assertionMethod`), the
   exact `AtprotoPersonalDataServer` endpoint equal to Swan's canonical public
   PDS URL, and one temporary `SwanDidWebClaim` service with
   `id == did + "#swan-claim"` and endpoint exactly
   `publicURL + "/.well-known/swan/did-web-claim/" + base64url(nonce)`.
   The nonce is consumed atomically with the shared claim transaction. The
   reserved key is a binding check, not an external assertion-signature
   requirement; no alternate document key can satisfy the claim.
3. Swan stores a method-neutral `did:web` binding with the RFC 8785/JCS
   canonical JSON document-byte digest, claim-receipt digest, reserved-key
   identity, and last valid revalidation. Swan does not create, rotate, delete,
   or otherwise claim authority over the user's domain, DNS, DID document, PLC,
   or external keys.
4. Revalidation is required before writes and new token issuance. A default
   24-hour grace permits bounded continuity after a transient resolver outage;
   a document mismatch or expired grace fences writes and new tokens while
   preserving public reads under the existing lifecycle policy. Any document
   rotation, reserved-key change, endpoint change, or handle change requires a
   new reservation, fresh canonical claim bytes/nonce, and a new temporary
   claim service; continuity retains the prior digest and claim in history and
   never accepts an unclaimed replacement. Export artifacts retain method,
   digest, key identity, claim receipt, and rotation history.

No `did:web` path may fall back to PLC signing or operator key custody. Handle
change, domain release, and permanent deletion require fresh step-up and an
explicit external-control policy; they never silently mutate the external DID.

## 5. Sessions, scopes, and factors

### 5.1 Credential families

The authorization model names credential family and subject explicitly:

```text
ManagementSession(id, subject, issuedAt, expiresAt, lastStepUpAt, strength)
LegacySession(id, familyID, subject, appPasswordID?, scopes, issuedAt, expiresAt)
OAuthSession(familyID, subject, clientID, scopes, dpopJKT, issuedAt, expiresAt)
OAuthBrowserSession(id, subject?, requestURI, csrf, expiresAt)
```

`AuthorizationContext` gains `.accountManagement`, `.accountLegacySession`,
and any browser-only context required by the OAuth page, with exhaustive
switches. `.accountOAuth` remains DPoP-bound. Legacy sessions use sibling
durable tables, family rotation, reuse detection, digest-at-rest storage, and
family-wide revocation; they never add a nullable DPoP field to OAuth rows.

The shared scope grammar/evaluator covers OAuth and app passwords. `atproto`,
`transition:*`, `repo:*`, `blob:*`, `rpc:*`, `account:*`, `identity:*`, and
`include:*` follow the pinned reference syntax, including rejection of
`rpc:*?aud=*`, fragment-stripping for audience matching, dot-boundary prefix
matching, and fail-closed undeclared routes. Empty, missing, malformed, or
invalidly expanded scopes deny. The evaluator interface is
`evaluate(credential, canonicalMethod, declaredMethodPolicy)`, and every
request follows this order: authenticate the credential, canonicalize the
method and evaluate its declared policy, then invoke the local handler or mint
an upstream service token. No handler or service-token mint occurs before a
successful evaluation. A method absent from the declaration is denied.

The only full-access value is the non-user-supplied internal sentinel
`ScopeGrant.fullAccessV1`; it is never represented by an empty scope, the
`atproto` identity scope, a wildcard, or a missing declaration. It may be put
on a credential only by the explicit full-access issuance policy. Refresh,
`include:` expansion, app-password editing, OAuth consent, and service-token
minting cannot upgrade a non-full grant to this sentinel. `getServiceAuth`
requires an `lxm` and matching `aud` for every non-full-access credential.
Refresh re-derives scope from the app-password row and never widens it. A
denial is `403` with the required machine scope. Permissioned-space code must
explicitly deny `.accountLegacySession`; app passwords and OAuth cannot widen
or inherit one another's authorization context.

App-password secrets are Argon2id-hashed, shown once, rate-limited at
`createSession`, and absent from all list/log/error paths. The official-client
wire adapters implement `createSession`, `refreshSession`, `getSession`,
`deleteSession`, `getServiceAuth`, and app-password create/list/revoke against
the pinned lexicons. Existing OAuth code remains DPoP-only.

### 5.2 Authentication strength and factors

```text
AuthenticationStrength.none
AuthenticationStrength.password
AuthenticationStrength.passwordPlusTOTP
AuthenticationStrength.passwordPlusPasskey
AuthenticationStrength.emailRecovery
AuthenticationStrength.scopedAppPassword
AuthenticationStrength.stepUp(base: password|passwordPlusTOTP|passwordPlusPasskey,
                               factor, verifiedAt)
```

Strength ordering is `none < emailRecovery < password < passwordPlusTOTP /
passwordPlusPasskey < stepUp`; `scopedAppPassword` is incomparable and valid
only for its stored legacy scopes. TOTP and passkey are the only MFA upgrades.
Once any factor is enabled, password login for management, OAuth, or a legacy
password session must include a valid `authFactorToken` assertion before a
full session/token is minted. An app-password login remains a scoped legacy
alternative only; it cannot create a management session, OAuth token, or
full-access grant and does not disable the MFA requirement elsewhere.
OAuth browser consent and token issuance re-check the account's factor state;
an authorization request cannot reuse a pre-MFA browser session after a factor
is enabled.

Passkeys provide MFA and step-up only; passwordless sign-in is out of scope.
TOTP uses an encrypted envelope with a key held outside the control database.
Recovery codes are random, hashed, single-use, atomically consumed, and
replaced as a complete set. WebAuthn checks RP ID, origin, challenge,
user-verification, signature, and monotonic counter. Factor enrollment,
removal, export, password/email/handle/DID changes, app-password operations,
migrations, and deletion require a fresh step-up (default ten-minute age).
The required fresh strength is `stepUp(passwordPlusTOTP|passwordPlusPasskey)`
for factor removal, email/password/handle/DID changes, app-password creation or
revocation, export, migration, connected-app revocation, and deletion whenever
MFA is enabled; with MFA disabled, a fresh `stepUp(password)` is sufficient
for the operations that do not establish identity authority. Email recovery or
a recovery code alone can revoke sessions and initiate password recovery but
can never remove a factor, authorize identity/domain changes, or authorize
deletion. Password recovery preserves enrolled factors until an explicit,
separately authorized factor change.

## 6. Frontend and verification boundaries

`web/` is a small SvelteKit `adapter-static` project. Node is used only in the
builder stage (`npm ci`, locked dependency tree, `npm run build`); the Swift
runtime serves baked assets and has no Node executable. The portal sections are
overview/profile, security/factors, recovery, sessions/devices, connected
apps, scoped app passwords, export/migration, and lifecycle. It calls only
`/account/api/*`, uses same-origin fetch, never stores a secret in local
storage, and renders one-time secrets with an explicit copy/download warning.

Required evidence includes route-precedence and auth-isolation tests, cookie
attributes, exact Origin and CSRF tests, CSP separation, one-time secret tests,
scope enforcement, factor replay/concurrency tests, and Playwright flows over
local HTTPS fixtures. A clean build or route-existence test is not live
acceptance. Official-client post/read/delete, session revoke, and identity
claim/revalidation flows are required where the local reference lab permits;
unexecuted network and deployment gates must remain listed.

## 7. Migration and jj workspace ownership

The integration workspace is
`/Users/joshlacalamito/Developer/Catbird+Petrel/Swan-account-program`.
Each lane is a jj workspace created with `jj workspace add`; Git is read-only.
No lane edits another lane's path, and no lane pushes or deploys.

| Lane | Owned paths | Explicitly not owned |
|---|---|---|
| Task 2 foundation (serial) | The integration owner executes Task 2 in the integration workspace: shared contract files/tests plus the reserved shared SQLite migrations, `Package.swift`, and exhaustive authorization-context switches. | No Task 2 lane/workspace is created; later parallel lanes may not edit these reserved paths. |
| Task 3 identity | New `did:web`/identity-binding files and tests. | Shared contracts, migration, router, PLC existing files unless an integration patch is requested. |
| Task 4 onboarding | Signup policy/service, invite/proof, SMTP adapter, lifecycle adapters, and tests. | Migration, router assembly, live Turnstile widget, production secrets. |
| Task 5 legacy auth | Scope grammar/evaluator, app-password service, legacy session service/adapters, and tests. | OAuth DPoP token-family implementation and shared migration. |
| Task 6 portal/API | `web/**`, account HTTP adapters, static asset handler, portal tests, and auth CSS. | Shared router/Dockerfile; those arrive as an integration patch. |
| Task 7 factors | WebAuthn/TOTP/recovery/step-up services, audit events, and tests. | Portal router assembly and shared migration. |
| Task 8 parity/ops | Remaining adapters, moderation integration, metrics/health, backup/restore drills, and disposable evidence scripts. | Production mutation and other lanes' owned implementation. |
| Integration owner | `Sources/SwanSQLite/AccountControlStore.swift`, `Sources/SwanSQLite/OAuthControlStore.swift` migration invocation/order, `Package.swift`, `SwanHTTP.buildRouter`/`Sources/swan/SwanCommand.swift`, generated-wire regeneration checkpoints, and `Dockerfile`. | Lane-owned behavior except conflict reconciliation. |

Task 2 is intentionally serial because its migration numbers, package graph,
and authorization enum cases are the integration spine. After Task 2 is sealed,
Tasks 3–8 may run in their listed non-overlapping workspaces, but they may not
edit the reserved migration, `Package.swift`, or authorization-switch paths;
they submit integration patches to the owner. The integration owner alone
changes router/runtime/Docker wiring and reconciles final conflicts.

Control-database migrations are additive and bounded. New tables have explicit
foreign keys and delete behavior, capacity limits, indexes, and reserved
migration numbers recorded before implementation. The integration owner alone
changes migration order or shared schema. No lane edits generated Petrel/Swan
wire output by hand.

## 8. Non-deploy scope and design exit criteria

This design task changes documentation only. It does not change Swift,
TypeScript, generated wire files, migrations, Docker, Caddy, DNS, secrets,
Turnstile configuration, reference checkouts, production data, or relay state.
Later implementation tasks may run local/disposable tests and local HTTPS
fixtures. They may not push, deploy, activate federation, change production
configuration, or submit external forms without separate authorization.

Before this design is considered complete, the author must verify that the two
2026-08-12 drafts point here, all contracts above have an owner, no route or
credential family is implicit, no `TODO`/placeholder remains in the contract,
and no wording claims a build, live flow, security scan, or deployment that was
not run for this revision.
