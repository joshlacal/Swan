# Swan Account, Identity, and Reference-Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring Swan to reference-compatible account onboarding and management, then add BYO `did:web`, stronger authentication, remaining protocol parity, and production-operational evidence without pushing or deploying.

**Architecture:** Hummingbird remains the only production application runtime and serves a static SvelteKit build plus isolated cookie-authenticated account APIs. Shared account, identity, session, and authentication-strength contracts are introduced before independent lanes; one integration owner alone edits control-database migrations, package manifests, router assembly, and the final Dockerfile.

**Tech Stack:** Swift 6.1, Hummingbird 2, SQLiteNIO, Swift Crypto/CryptoKit, NIO TLS, SvelteKit with `adapter-static`, TypeScript, Playwright, jj workspaces.

**Spec:** `docs/superpowers/specs/2026-08-16-swan-account-identity-reference-parity-design.md`

## Execution status at checkpoint `2ca80d27` (2026-08-16)

This plan has produced a reviewed, locally verified integration checkpoint, but it has **not** produced a production-composed four-milestone release. Tasks 1-8 delivered designs, storage/domain implementations, static UI, adapters, and operational seams. Task 9 integrated those lanes, centralized migration v8, added the portal router hook and static Docker build stage, and passed the full local Swift/frontend gates.

The remaining work is production composition and external acceptance: `SwanCommand` does not construct the portal, signup, legacy-auth, `did:web`, MFA, authenticated-SMTP, or Task 8 reference services; Task 8 manifest entries remain `registered: false`. Use the layered handoff beginning at `docs/superpowers/handoffs/2026-08-16-swan-account-program-handoff.md` rather than interpreting unchecked boxes or lane-local “implemented” language as runtime availability.

## Global Constraints

- Use jj as the sole history writer. Use only `jj workspace add`; never mutate Git.
- Follow test-driven development: record a focused failing test before production code and the passing command afterward.
- One integration owner exclusively edits shared SQLite migration functions, `Package.swift`, `SwanHTTP.buildRouter`, runtime assembly in `SwanCommand.swift`, and `Dockerfile`.
- Never hand-edit generated Petrel or Swan wire types. Change lexicons and regenerate only after a jj checkpoint.
- OAuth access tokens remain DPoP-bound. Legacy bearer sessions use a distinct authorization context and storage family.
- Cookies authenticate only `/account/api/*`; they never authenticate `/xrpc/*`. OAuth, legacy, and app-password credentials never authenticate `/account/api/*`.
- Node is build-only. The production image contains no Node runtime or SvelteKit server.
- Open signup requires both verified email and server-side Turnstile verification. Invite signup is rate-limited and does not require CAPTCHA by default.
- BYO `did:web` remains externally controlled. Swan verifies the binding but never claims domain rotation or deletion authority.
- Passkeys provide MFA and step-up only; passwordless sign-in is outside this program.
- Preserve public reads when external DID identity is suspended; block writes and new token issuance.
- No push, deployment, relay activation, production-secret mutation, or external Turnstile widget creation is authorized.

---

### Task 1: Refresh and freeze the program design

**Files:**
- Create: `docs/superpowers/specs/2026-08-16-swan-account-identity-reference-parity-design.md`
- Modify: `docs/superpowers/specs/2026-08-12-swan-account-management-ui-design.md`
- Modify: `docs/superpowers/specs/2026-08-12-swan-scoped-app-passwords-design.md`

**Produces:** The authoritative account API, signup, identity, session, MFA, frontend, and execution boundaries used by every later task.

- [ ] Reconcile both older drafts with the approved four-release program and current security-remediated source.
- [ ] Define the exact `/account/api/*` route groups, cookie/CSRF/origin contract, `SignupPolicy`, signup authorization, BYO `did:web` claim, session/factor types, and failure behavior.
- [ ] Define migration ownership and non-overlapping jj workspace paths.
- [ ] Self-review for placeholders, contradictions, stale assumptions, and accidental deployment authorization.
- [ ] Commit the design with jj and immediately run `jj new`.

### Task 2: Add shared contracts and migration spine

**Files:**
- Create focused contract files under `Sources/SwanStorage`, `Sources/SwanAccounts`, and `Sources/SwanOAuth`.
- Modify shared SQLite migrations, `Package.swift`, authorization-context switches, and corresponding focused tests only in the integration workspace.

**Produces:** `SignupPolicy`, identity method/binding types, management and legacy session identifiers, `AuthenticationStrength`, scope policy interfaces, factor protocols, reserved migration numbers, and fail-closed authorization cases.

- [ ] Write focused tests that fail because the shared types, exhaustive authorization cases, and migration tables are absent.
- [ ] Add the smallest domain/storage interfaces required by Tasks 3-7.
- [ ] Add additive bounded control-database tables with foreign-key cleanup and capacity limits.
- [ ] Run focused storage/account/OAuth suites, then seal the foundation commit and branch lane workspaces from it.

### Task 3: Implement PLC and BYO `did:web` identity

**Ownership:** Identity services, DID document validation, reserved signing keys, identity continuity, export/restore identity artifacts, and focused tests. Do not edit shared migration or router files.

**Produces:** Method-neutral identity verification plus PLC and externally controlled `did:web` providers consumed by onboarding and public-repository admission.

- [ ] Add failing tests for exact document ID, `alsoKnownAs`, reserved key, PDS endpoint, one-time claim, mismatch suspension, grace expiry, rotation, and archive compatibility.
- [ ] Implement reference-compatible signing-key reservation and bounded one-time BYO-domain claims.
- [ ] Replace PLC-only admission assumptions with method-specific verified identity bindings.
- [ ] Add 24-hour default revalidation grace, preserving reads while fencing writes/token issuance on mismatch.
- [ ] Extend versioned export/restore identity artifacts without changing existing PLC archives.

### Task 4: Implement onboarding, invites, production SMTP, and account lifecycle

**Ownership:** Signup policy/services, invite store/service, Turnstile verifier abstraction, authenticated SMTP transport, email update/recovery integration, account lifecycle XRPC adapters, and focused tests. Do not create a live Turnstile widget or edit shared runtime assembly.

**Produces:** Closed, invite-required, and open-protected signup; single-use signup authorization through `verificationCode`; reference lifecycle endpoints; production-neutral authenticated SMTP.

- [ ] Add failing tests for policy advertisement, invite atomicity, CAPTCHA/email proof consumption, duplicate account races, rollback, SMTP TLS/auth, retry/idempotency, and recovery-wide revocation.
- [ ] Implement Turnstile siteverify behind an injected bounded HTTP verifier; reject missing, failed, expired, duplicate, wrong-hostname, and wrong-action results.
- [ ] Implement verified-email signup authorization and reference-compatible `createAccount` for PLC and preverified BYO `did:web` identities.
- [ ] Implement authenticated STARTTLS/implicit-TLS SMTP configuration without weakening the Mailpit lab transport.
- [ ] Complete email update and self-service lifecycle services using existing deletion/export primitives.

### Task 5: Implement scoped app passwords and legacy sessions

**Ownership:** Scope grammar/evaluator, app-password service, legacy session family, reference session/app-password XRPC adapters, and focused tests. Do not edit OAuth DPoP token-family code except through frozen interfaces.

**Produces:** Official-client-compatible `createSession`, `refreshSession`, `getSession`, `deleteSession`, `getServiceAuth`, and app-password create/list/revoke.

- [ ] Add failing grammar and method-enforcement tests, including wildcard/audience boundary cases and undeclared-route denial.
- [ ] Add failing family rotation, reuse detection, refresh re-derivation, revocation, and secret-at-rest tests.
- [ ] Implement the distinct legacy authorization context and sibling durable session service.
- [ ] Implement the four scope presets and one-time secret presentation.
- [ ] Verify official-client wire shapes against the pinned reference lexicons.

### Task 6: Implement account APIs, static SvelteKit portal, and OAuth redesign

**Ownership:** New `web/**`, account HTTP adapters, static asset handler, portal tests, and shared auth CSS. Shared router/Dockerfile wiring is delivered as an integration patch for the integration owner.

**Produces:** Same-origin static portal, isolated management sessions, account/device/app-password/connected-app/lifecycle screens, and script-free redesigned OAuth pages.

- [ ] Add failing HTTP tests for route precedence, auth isolation, cookie attributes, CSRF, exact Origin, CSP separation, and session revocation.
- [ ] Implement opaque revocable management sessions and the frozen `/account/api/*` contract.
- [ ] Scaffold `adapter-static` with no server routes and add frontend type/lint/unit tests.
- [ ] Build portal sections for overview, profile/security, recovery, sessions/devices, connected apps, app passwords, export/migration, and lifecycle actions.
- [ ] Share design tokens with server-rendered OAuth HTML without adding scripts or widening OAuth CSP.
- [ ] Add Playwright flows over local HTTPS fixtures.

### Task 7: Implement MFA and step-up

**Ownership:** WebAuthn verification, TOTP, recovery codes, factor services, audit events, step-up policy, and focused tests. Consume management-session interfaces from Task 6.

**Produces:** Passkey MFA, encrypted TOTP, hashed one-time recovery codes, and fresh step-up for sensitive account actions.

- [ ] Add failing RFC 6238, drift/replay, recovery-code concurrency, and WebAuthn origin/RP/challenge/UV/signature/counter tests.
- [ ] Implement encrypted TOTP envelopes and one-time recovery-code replacement/consumption.
- [ ] Implement bounded, atomic WebAuthn challenges and passkey enrollment/assertion/removal.
- [ ] Attach authentication strength and time to management/OAuth authorization state.
- [ ] Require fresh step-up for email, password, handle/DID, MFA, app-password, export, migration, and deletion operations.
- [ ] Ensure password recovery revokes sessions but preserves enrolled factors.

### Task 8: Complete reference API breadth and operational evidence

**Ownership:** Remaining identity/repo/sync/admin adapters, moderation integration acceptance, metrics/health, backup/restore automation, and disposable evidence scripts. No production mutation.

**Produces:** A generated reference-parity matrix and reproducible local/Linux/browser/client/network acceptance artifacts.

- [ ] Add behavior-parity tests for identity update/PLC operations, import/list-missing-blobs, sync enumeration, admin lifecycle, and moderation delivery.
- [ ] Add bounded readiness/metrics for HTTP errors, auth, email, signup, identity revalidation, outbox lag, firehose, and backup age.
- [ ] Add disposable backup/restore and signing-key rotation drills.
- [ ] Run the full Swift suite, frontend checks/build, Linux x86_64 pinned-toolchain image, reference interop, browser flows, and official-client flow where locally available.
- [ ] Record exactly which live network/deployment gates remain unexecuted; do not infer them from route or test existence.

### Task 9: Integration, review, and handoff

- [ ] Rebase reviewed lane commits onto the integration spine in dependency order: identity, onboarding, legacy auth, portal, MFA, parity/ops.
- [ ] Resolve only true integration conflicts; preserve each lane's owned behavior and evidence.
- [ ] Run a whole-program security/code review and one bounded fix/re-review cycle.
- [ ] Re-run all applicable verification from Task 8 on the integrated tree.
- [ ] Seal the integrated jj change, immediately run `jj new`, and report local commit IDs and unexecuted external gates. Do not push or deploy.
