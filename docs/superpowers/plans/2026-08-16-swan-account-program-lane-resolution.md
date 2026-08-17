# Swan Account Program Lane-Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each implementation lane a self-contained continuation card with current state, owned files, residual deliverable, tests, and integration boundary.

**Architecture:** Lanes may develop and review non-overlapping services in isolated jj workspaces. A single integration owner consumes reviewed commits and alone changes shared runtime/migration/package/router/Docker files.

**Tech Stack:** Swift/Hummingbird/SQLite, SvelteKit/Playwright, Docker, jj workspaces.

**Spec:** `docs/superpowers/specs/2026-08-16-swan-account-identity-reference-parity-design.md`

## Global Constraints

- Base new work on integrated commit `2ca80d27`, not an old lane tip.
- Agents are not alone in the codebase; never rewrite or revert another lane's work.
- Lane-local “implemented” means source capability, not LIVE runtime availability.
- Do not edit shared integration files unless explicitly assigned integration ownership.
- Each lane ends with focused tests, a read-only review, a sealed jj commit, and an integration note.

---

## Lane 0: Integration owner

**Current state:** migration v8, required package dependencies, optional portal router hook, route precedence, Docker frontend stage, and consolidated fixes are integrated. `SwanCommand` does not assemble the new services.

**Exclusive files:**
- `Package.swift`
- `Sources/SwanSQLite/AccountControlSchema.swift`
- `Sources/SwanSQLite/AccountControlStore.swift`
- `Sources/SwanSQLite/AccountProgramIntegrationMigration.swift`
- `Sources/SwanHTTP/SwanHTTP.swift`
- `Sources/swan/SwanCommand.swift`
- `Dockerfile`

**Next deliverable:** execute the runtime-integration plan, consume reviewed lane commits in dependency order, and maintain one availability matrix.

- [ ] Reserve shared-file ownership before spawning lane agents.
- [ ] Require tests through production construction paths before labeling routes LIVE.
- [ ] Integrate storage/identity first, legacy auth second, portal/account APIs third, MFA fourth, parity last.

## Lane 1: Identity and BYO `did:web`

**Resolution:** **INTEGRATED SEAM**. Atomic claim storage, signing reservations, exact DID-document proof, peer-pinned resolution, grace/suspension, rotation/removal, scheduler, and export snapshots exist. Production construction, routes, scheduler lifecycle, and token/write admission coupling are missing.

**Owned files:**
- `Sources/SwanAccounts/SwanDidWebIdentity.swift`
- `Sources/SwanAccounts/SwanDidWebClaimEndpoint.swift`
- `Sources/SwanSQLite/SQLiteDidWebReservationProvider.swift`
- `Sources/SwanSQLite/SwanIdentityBindingStore.swift`
- identity/export focused tests

**Do not edit:** shared migration, router, `SwanCommand`, `Dockerfile`.

**Next deliverable:** a concrete identity HTTP/runtime bundle consumed by the integration owner.

- [ ] Add failing route tests for reserve, claim, reverify, rotate, and remove.
- [ ] Add admission tests proving suspension blocks writes/new tokens but not public reads.
- [ ] Provide construction inputs and lifecycle hooks without editing shared assembly.
- [ ] Re-run `SwanDidWebIdentityTests` and SQLite atomic transaction tests.

## Lane 2: Onboarding, recovery, and SMTP

**Resolution:** **INTEGRATED SEAM**. Signup policy, invites, proof verification, Turnstile transport, durable authorization/outbox, authenticated SMTP abstractions, lifecycle services, and pure XRPC adapters exist. The atomic foundation writer, runtime routes, production SMTP selection, and outbox lifecycle are missing.

**Owned files:**
- `Sources/SwanAccounts/Task4Onboarding.swift`
- `Sources/SwanSQLite/Task4OnboardingSQLite.swift`
- `Sources/SwanHTTP/Task4AccountLifecycleXRPC.swift`
- `Tests/SwanAccountsTests/Task4OnboardingTests.swift`

**Next deliverable:** an atomic provisioning writer and runtime-ready onboarding bundle, with no shared router edits.

- [ ] Add rollback tests spanning account, identity, session, invite/proof, and result rows.
- [ ] Implement the connection-scoped foundation writer required by the assembled coordinator.
- [ ] Add a deadline-capable authenticated NIO SMTP transport if the existing abstraction lacks a production conformer.
- [ ] Add worker restart/lease/retry/idempotency tests.

## Lane 3: Legacy auth and scoped app passwords

**Resolution:** **INTEGRATED SEAM**. Scope grammar/evaluator, finite generated registry, Argon2id app-password storage, durable token families, rotation/reuse detection, signed credentials, and pure XRPC adapters exist. Production resolver/keys/admission/service construction and routes are missing.

**Owned files:**
- `Sources/SwanAccounts/ScopedLegacyAuth.swift`
- `Sources/SwanStorage/SwanScope.swift`
- `Sources/SwanStorage/DeclaredMethodScopePolicy.swift`
- `Sources/SwanStorage/GeneratedLegacyMethodRegistry.swift`
- `Sources/SwanStorage/LegacyAccessGrant.swift`
- `Sources/SwanSQLite/LegacyAuthStore.swift`
- `Sources/SwanHTTP/SwanLegacyAuthXRPC.swift`

**Next deliverable:** a runtime bundle exposing concrete handlers and bearer-auth verification to the integration owner.

- [ ] Add production-routing tests for all six session/service methods and app-password management.
- [ ] Prove a scoped token cannot become full access and undeclared methods always fail closed.
- [ ] Prove refresh/replay/revocation across database reopen.
- [ ] Keep OAuth DPoP verification untouched.

## Lane 4: Account portal and OAuth presentation

**Resolution:** **INTEGRATED SEAM**. Static SvelteKit bundle, account shell/screens, session/pre-auth/CSRF storage/runtime, account HTTP adapter, OAuth CSS/CSP, security tests, and fixture Playwright tests exist. No production `SwanAccountPortalServing` conformer exists, and `SwanCommand` does not pass the portal bundle.

**Owned files:**
- `web/**`
- `Sources/SwanHTTP/SwanAccountPortalHTTP.swift`
- `Sources/SwanAccounts/SwanManagementSessionRuntime.swift`
- `Sources/SwanSQLite/AccountPortalSessionStore.swift`
- portal/OAuth presentation tests

**Next deliverable:** a concrete portal service facade plus Swift-server Playwright evidence.

- [ ] Implement the portal facade against real account/OAuth/legacy/identity/lifecycle stores.
- [ ] Preserve exact Origin, one-time pre-auth, CSRF, cookie path, CSP, and credential isolation.
- [ ] Add tests that use the production facade rather than `PortalMemoryService`.
- [ ] Run Playwright with `SWAN_PORTAL_TEST_URL` against Hummingbird.

## Lane 5: MFA and step-up

**Resolution:** **INTEGRATED SEAM**. TOTP, WebAuthn, recovery codes, factor storage, factor tokens, audit events, and step-up policy exist with focused tests. Portal enrollment, legacy-login enforcement, and sensitive-operation enforcement are missing.

**Owned files:**
- `Sources/SwanAccounts/MFAFactors.swift`
- `Sources/SwanStorage/Task7MFAStorageContracts.swift`
- `Sources/SwanSQLite/AccountFactorStore.swift`
- `Tests/SwanAccountsTests/Task7MFATests.swift`

**Entry condition:** stable LIVE management sessions from Milestone 1.

**Next deliverable:** portal factor APIs and an enforcement matrix connected through frozen interfaces.

- [ ] Add end-to-end factor enrollment/assertion/removal tests through account APIs.
- [ ] Add `authFactorToken` legacy-login tests through production routing.
- [ ] Enumerate every sensitive operation and prove stale/insufficient strength is rejected.
- [ ] Verify password reset preserves factors while revoking sessions.

## Lane 6: Reference parity

**Resolution:** **DEFERRED**. Identity/admin/repo/sync/import/moderation adapters and a generated manifest exist, but every new entry is `registered:false`. Import correctly remains unassembled without the full durable CAR/MST verifier.

**Owned files:**
- `Sources/SwanAccounts/ReferenceIdentityAndAdminAdapters.swift`
- `Sources/SwanPublicRepository/PublicRepositoryReferenceSurface.swift`
- `Sources/SwanPublicRepository/PublicRepositoryReferenceImport.swift`
- `Sources/SwanInterop/ModerationServiceAdapter.swift`
- `docs/superpowers/records/2026-08-16-swan-account-identity-reference-parity/task-8-reference-parity-manifest.json`

**Entry condition:** LIVE Milestones 1-2 authorization and identity services.

**Next deliverable:** resolve manifest entries one at a time with exact reference behavior and production storage.

- [ ] Connect `importRepo` to the existing complete staging verifier/publisher; never use the in-memory conformance model in production.
- [ ] Verify created-time+DID keyset cursors, CAR output, missing-CID failure, and deduplication semantics.
- [ ] Assemble typed moderation with actionable correlation lookup and versioned key management.
- [ ] Flip `registered` only after route and behavior acceptance.

## Lane 7: Operations and acceptance

**Resolution:** **EXTERNAL GATE OPEN**. Disposable backup/restore and rotation scripts plus readiness/metrics seams exist, but runtime assembly and live drills are absent.

**Owned files:**
- `Scripts/task8-disposable-backup-restore.sh`
- `Scripts/task8-disposable-key-rotation.sh`
- `Scripts/test-task8-disposable-drills.sh`
- operational records and non-shared metric/readiness implementations

**Entry condition:** intended runtime surfaces assembled locally.

**Next deliverable:** sanitized, reproducible evidence—not synthetic success—from disposable environments.

- [ ] Assemble readiness/metrics from real bounded sources without identifiers or secrets.
- [ ] Run full Linux image, read-only container, SMTP, backup/restore, rotation, browser, official-client, federation/AppView/moderation, and load gates.
- [ ] Record exact commands, revisions, timestamps, skipped coverage, and artifact paths.
- [ ] Keep push/deploy as a separately authorized final gate.
