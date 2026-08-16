# Task 5 — scoped app passwords and legacy sessions

## Lane scope

Implemented from foundation `884b92fd` in the `Swan-account-legacy-auth` lane.
No shared migration, package manifest, router assembly, command assembly,
Dockerfile, generated wire, or OAuth DPoP family source was changed.

## Implemented

- `SwanScope` is the single parser for OAuth/app-password scope values. It
  rejects empty/malformed values and `rpc:*?aud=*`, canonicalizes fragments,
  applies dot-boundary method matching and bounded audience matching, and
  exposes explicit preset values without treating user input as
  `fullAccessV1`.
- `SwanScopeEvaluator` authenticates the declared method policy boundary and
  fails closed for undeclared methods, missing scopes, empty grants, and
  unauthorized full-access credentials.
- `LegacyAuthService` creates/list/edits/revokes app passwords, presents a
  generated secret only from create, stores only deterministic account-bound
  Argon2id 32-byte digests, and
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
  fields.

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
