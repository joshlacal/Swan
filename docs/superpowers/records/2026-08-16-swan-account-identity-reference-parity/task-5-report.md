# Task 5 — scoped app passwords and legacy sessions

## Review correction round

The follow-up review required a second correction round. The lane now denies
undeclared methods even for the internal full-access credential, rejects all
`include:*` values until an expansion registry exists, revokes derived
families on scope edits, preserves absolute family expiry on refresh, uses
per-secret random-salt/versioned Argon2id digests, CSPRNG tokens, mandatory
runtime keys, injected login admission, and injected management-session plus
step-up authorization. Access and service credentials are signed/verifiable
JWTs with issuer, audience/method, `iat`, `exp`, and `jti` claims; access JWTs
carry the durable session ID for cross-replica lookup. Password sessions use
an internal marker evaluated only against the explicit full-access method
registry; app-password management adapters consume a typed opaque XRPC
authorization context, never a browser cookie. App-password login CAS-checks
the active row and scope snapshot while atomically updating `lastUsedAt` and
creating the derived family/session.

## Final integration patch

The integration owner must extend the shared `AuthorizationContext` foundation
with `.accountLegacySession(grant: LegacyAccessGrant, ...)` and preserve the
grant as a typed value through bearer authentication. The router must reject a
missing or unknown grant, reject a scoped token presented as full access, and
reject a full-access token whose method is absent from the registered policy.
The lane intentionally does not edit the shared owner file or router assembly.

## Lane scope

Implemented from foundation `884b92fd` in the `Swan-account-legacy-auth` lane.
No shared migration, package manifest, router assembly, command assembly,
Dockerfile, generated wire, or OAuth DPoP family source was changed.

## Implemented

- `SwanScope` is the single parser for OAuth/app-password scope values. It
  rejects empty/malformed values and `rpc:*?aud=*`, canonicalizes fragments,
  validates two-label-or-longer namespace prefixes separately from full NSIDs,
  applies dot-boundary method matching and bounded audience matching, and
  exposes explicit preset values without treating user input as
  `fullAccessV1`.
- `SwanScopeEvaluator` authenticates the declared method policy boundary and
  fails closed for undeclared methods, missing scopes, empty grants, and
  unauthorized full-access credentials.
- The explicit full-access registry includes the currently registered
  repo/blob/sync, identity, feed, notification, and chat methods used by the
  parity surface; unknown methods and broad prefixes remain denied.
- `referenceLegacy` reuses that explicit registry with preset-compatible
  `repo:*`, `blob:*`, `identity:read`, and AppView/chat `rpc:` requirements;
  service-auth accepts only a requested integer expiry 1–60 seconds ahead and
  passes it unchanged to the signed issuer.
- `LegacyAuthService` creates/list/edits/revokes app passwords, presents a
  generated secret only from create, stores versioned random-salt Argon2id
  digests, and
  issues the sibling legacy session family. Refresh rotates lineage, re-reads
  current app-password scopes, and rejects replay after atomic family
  revocation. App-password revocation revokes every derived family/session.
- `SQLiteControlDatabase` implements the existing `AppPasswordStore` and
  `LegacySessionStore` tables in a new extension file; no migration was added.
- `SwanLegacyAuthXRPCAdapter` provides pure reference-shaped adapters for
  create/refresh/get/delete session, service auth, and app-password
  create/list/revoke. Router registration is intentionally an integration
  owner handoff.
- Focused tests cover grammar/audience boundaries, declaration enforcement,
  one-time secret behavior, refresh narrowing, replay reuse revocation, and
  derived-session revocation; an adapter test checks pinned session wire
  fields. The correction round adds negative include/undeclared-full-access
  checks and management/factor/admission injection coverage.

## Integration handoff

The integration owner should add `SwanLegacyAuthXRPCAdapter` to the XRPC
runtime and route bearer authentication to `AuthorizationContext.accountLegacySession`.
The owner must keep management cookies isolated to `/account/api/*`, preserve
OAuth DPoP-only handling, and make the password/factor policy call the frozen
`authFactorToken` interfaces before minting password sessions. The app-password
management portal can call the service through its own step-up gate.

## Verification

`swiftc -frontend -parse` passed for all new lane Swift files and `git diff
--check` passed. The focused SwiftPM suite was authored before production
implementation and its first invocation was attempted test-first, but the
shared workspace build did not reach the test diagnostics because concurrent
builds corrupted the SwiftPM clang dependency cache; a later affected-target
build also stopped on local temporary-volume exhaustion while compiling
unrelated Hummingbird sources. `SwanStorage`, `SwanSQLite`, and `SwanAccounts`
targets did compile successfully in the lane scratch tree before that disk
limit. Re-run the focused tests with the integration owner's consolidated
scratch path after the other workspace builds finish.

No push, deployment, external network flow, or production mutation was run.
