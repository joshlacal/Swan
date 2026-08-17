# Swan Account Program Runtime-Integration Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the integrated account-program seams at `2ca80d27` into a production-composed Milestone 1 runtime without widening credential trust or route fallbacks.

**Architecture:** One integration owner assembles concrete services in `SwanCommand`, passes explicit bundles into `SwanHTTPServer`, and registers local account/XRPC routes before unavailable guards and proxy fallback. Supporting agents own non-overlapping concrete facades and focused tests, not shared assembly.

**Tech Stack:** Swift 6.1, Hummingbird 2, SQLiteNIO, NIO TLS, static portal assets, jj workspaces.

**Spec:** `docs/superpowers/specs/2026-08-16-swan-account-identity-reference-parity-design.md`

## Global Constraints

- Integration owner exclusively edits `Package.swift`, shared migrations, `SwanHTTP.swift`, `SwanCommand.swift`, `Dockerfile`, and final rebases.
- `/account/api/*` must be registered before `/account/*`; both must precede broad fallback.
- Exact local XRPC methods must be registered before unknown-public guards and `/xrpc/**` proxy.
- Management cookies never authenticate XRPC; OAuth/legacy/app-password credentials never authenticate account APIs.
- Disabled or incompletely assembled capabilities fail closed and are not advertised as available.
- No production secrets or external service mutations are part of this plan.

---

## Required registration order

```text
health and reserved discovery
/account/api/*
/account/* assets and navigation fallback
exact local account/identity/legacy XRPC methods
existing OAuth and public repository surfaces in their established order
unknown public endpoint guards
/xrpc/** pipethrough/proxy fallback
```

## Task 1: Freeze runtime composition tests

**Files:**
- Create: `Tests/SwanCLITests/SwanAccountProgramCompositionTests.swift`
- Modify: `Tests/SwanHTTPTests/AccountPortalSecurityHTTPTests.swift`
- Modify: focused legacy/onboarding HTTP tests under `Tests/SwanHTTPTests`

**Produces:** Red tests that use the same construction path as `swan serve` and prove route precedence, configuration truth, and credential isolation.

- [ ] Add a test server factory that calls the production composition function rather than directly constructing lane adapters.
- [ ] Assert `/account/` serves the compiled bundle when enabled and cannot shadow `/account/api/bootstrap`, `/xrpc/*`, OAuth, health, discovery, or WebSockets.
- [ ] Assert `createSession` and `createAccount` are local only when their durable services are assembled; otherwise they remain a stable local refusal rather than proxying credentials.
- [ ] Assert `describeServer.inviteCodeRequired` is derived from the same `SignupPolicy` used by signup admission.
- [ ] Run the focused tests and record the expected pre-composition failures.

## Task 2: Add typed startup configuration

**Files:**
- Modify: `Sources/swan/SwanCommand.swift`
- Modify: configuration tests under `Tests/SwanCLITests`

**Produces:** Validated portal path, signup policy, Turnstile secret reference, SMTP mode/host/port/TLS/auth references, DID revalidation interval/grace, and explicit feature enablement.

- [ ] Add `--account-portal-directory` with a container default matching `/usr/local/share/swan/account` and a validated local override.
- [ ] Parse `closed`, `inviteRequired`, and `openProtected` into one `SignupPolicy`; reject incomplete open-protected configuration.
- [ ] Add authenticated SMTP configuration that cannot silently fall back to Mailpit outside explicit lab mode.
- [ ] Validate HTTPS public origin for the portal and `did:web` claim endpoint.
- [ ] Keep secret values out of descriptions, logs, errors, and test snapshots.

## Task 3: Assemble onboarding and SMTP

**Files:**
- Modify: `Sources/swan/SwanCommand.swift`
- Modify: `Sources/SwanHTTP/Task4AccountLifecycleXRPC.swift`
- Create: a focused production provisioning writer in `Sources/SwanAccounts` or `Sources/SwanSQLite` without moving shared migration ownership
- Test: onboarding HTTP and SQLite transaction tests

**Consumes:** `SignupService`, `SQLiteSignupTransactionCoordinator`, migration v8 tables, existing account/identity/session stores.

**Produces:** Atomic account + identity + session + proof/invite/result creation and exact signup/lifecycle HTTP adapters.

- [ ] Implement the connection-scoped foundation writer required by `SQLiteSignupTransactionCoordinator`.
- [ ] Prove an injected failure at each write rolls back account, identity, management session, invite/proof consumption, and finalization result together.
- [ ] Construct Turnstile and authenticated SMTP only for the selected policy/mode.
- [ ] Start the durable email outbox worker with bounded leases/retries and shutdown handling.
- [ ] Register exact account-creation/lifecycle routes and rerun enumeration/Turnstile/security tests.

## Task 4: Assemble legacy sessions and app passwords

**Files:**
- Modify: `Sources/swan/SwanCommand.swift`
- Modify: `Sources/SwanHTTP/SwanLegacyAuthXRPC.swift`
- Modify: `Sources/SwanHTTP/SwanHTTP.swift` only through the integration owner
- Test: `Tests/SwanAccountsTests/ScopedLegacyAuthTests.swift`
- Test: new production-routing tests under `Tests/SwanHTTPTests`

**Produces:** LIVE `createSession`, `refreshSession`, `getSession`, `deleteSession`, `getServiceAuth`, and app-password management routes.

- [ ] Construct `LegacyAuthService` with durable store, account resolver, login admission, mandatory signing/HMAC secrets, management authorizer, and factor policy.
- [ ] Preserve `AuthorizationContext.accountLegacySession` as a distinct typed grant through bearer authentication.
- [ ] Register exact generated methods and deny undeclared methods before proxy fallback.
- [ ] Verify rotation, replay-family revocation, scope re-derivation, restart, app-password revocation, and OAuth DPoP invariance.

## Task 5: Assemble the account portal

**Files:**
- Create: production facade implementing `SwanAccountPortalServing` under `Sources/SwanHTTP` or `Sources/SwanAccounts`
- Modify: `Sources/swan/SwanCommand.swift`
- Modify: `Sources/SwanHTTP/SwanHTTP.swift` only through the integration owner
- Test: `Tests/SwanHTTPTests/AccountPortalSecurityHTTPTests.swift`
- Test: `web/tests/portal.spec.ts`

**Produces:** A reachable static portal and durable account API backed by real account/OAuth/legacy/identity/lifecycle services.

- [ ] Implement every protocol method with explicit authorization and stable typed errors; do not use an in-memory fallback.
- [ ] Construct `SwanManagementSessionRuntime` from SQLite pre-auth/session/CSRF stores.
- [ ] Pass `SwanAccountPortalHTTP` through the existing optional server hook.
- [ ] Add a production-construction test proving the Docker/static directory path is actually used.
- [ ] Run Playwright against the Swift server using `SWAN_PORTAL_TEST_URL`, not only the disposable fixture.

## Task 6: Assemble `did:web` lifecycle

**Files:**
- Modify: `Sources/swan/SwanCommand.swift`
- Create or modify focused identity HTTP adapter files under `Sources/SwanHTTP`
- Test: `Tests/SwanAccountsTests/SwanDidWebIdentityTests.swift`
- Test: new identity route/admission tests under `Tests/SwanHTTPTests`

**Produces:** LIVE reserve/claim/reverify/rotate/remove flows plus background continuity enforcement.

- [ ] Construct the durable signing-key reservation provider and atomic identity service.
- [ ] Register the public one-time claim endpoint before fallback routes.
- [ ] Start and stop `SwanDidWebRevalidationScheduler` with the application lifecycle.
- [ ] Connect suspended identity state to write admission and new-token issuance while preserving public reads.
- [ ] Verify 24-hour default grace, restart, mismatch suspension, recovery, and exact claim consumption.

## Task 7: Milestone 1 integrated gate

**Files:**
- Modify: `Dockerfile` only if the final runtime path differs from the verified build-stage path
- Create: sanitized acceptance records under `docs/superpowers/records/2026-08-16-swan-account-identity-reference-parity/`

- [ ] Run full Swift and frontend suites.
- [ ] Build the complete pinned Linux x86_64 runtime image and inspect it for portal assets and absence of Node.
- [ ] Run invite and open signup, recovery, app-password, legacy refresh/revoke, portal, and BYO `did:web` against the Swift server.
- [ ] Run an official-client restart/refresh/revoke flow where locally available.
- [ ] Seal a jj checkpoint and report every external gate still open; do not push or deploy.
