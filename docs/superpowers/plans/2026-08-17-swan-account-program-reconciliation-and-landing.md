# Swan Account-Program Reconciliation and Landing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reconcile account-program commit `30b751b6a083` with current `main` at `d0e8e114c0de`, close the account runtime and acceptance gaps, and advance local `main` only after every gate passes.

**Architecture:** Use a provenance-preserving two-parent jj merge with `main` as the canonical OAuth, legacy-session, app-password, CORS, generated-profile, and startup-interlock authority. Port the account portal, onboarding, MFA, SMTP, and `did:web` capabilities onto those services, then validate the frozen candidate locally, on isolated native Linux, with an official client, and through a sealed security review.

**Tech Stack:** Swift 6.1/6.4, Hummingbird 2, SQLiteNIO, NIO TLS, SvelteKit, Playwright, Docker, jj.

**Spec:** `docs/superpowers/specs/2026-08-16-swan-account-identity-reference-parity-design.md`

## Global Constraints

- Luna at max effort owns implementation, tests, harnesses, and remediation.
- Sol at high effort owns topology, architecture, task, and final reviews.
- Daybreak Blue at high effort owns security reviews of frozen revisions.
- Shared runtime/router/migration files are edited serially by one integration owner.
- `main`'s typed OAuth/legacy authorization model is the sole authority.
- Current-main database compatibility is mandatory; the unshipped account-program schema is not.
- Account APIs remain same-origin and CORS-disabled.
- Deferred Milestone 3 methods remain unregistered and account runtime remains explicitly opt-in.
- No push, deployment, production restart, relay activation, or live `swan.place` probing is authorized.
- Netcup authorization covers isolated build/test activity only.

---

### Task 1: Establish and audit the integration topology

**Produces:** A two-parent integration workspace, frozen source identities, and a reconciliation ledger for shared files and apparent deletions.

- [ ] Record clean status, full parent revisions, ancestry, and source trees.
- [ ] Create the integration working-copy commit with parents `d0e8e114c0de` and `30b751b6a083`; exclude `0c04c519`.
- [ ] Inventory jointly changed paths and account for every main-only path that a tip-to-tip diff presents as deleted.
- [ ] Stop on source movement, unexplained dirt, missing ancestry, unexpected deletion, or generated-profile drift.
- [ ] Obtain a Sol topology review before Task 2.

### Task 2: Unify authentication, authorization, and storage

**Produces:** One canonical typed auth stack and additive account/MFA/identity schema compatible with populated current-main databases.

- [ ] Preserve `SwanScopePermissions`, `DurableLegacySessionService`, `SwanLegacySessionXRPCServer`, `AppPasswordCredentials`, main's `AppPasswordStore`, and typed `AuthorizationContext.accountLegacySession`.
- [ ] Retire the account branch's duplicate `SwanScope`, `LegacyAuthService`, raw scope-set authorization, duplicate legacy routes, and incompatible legacy/app-password tables.
- [ ] Adapt portal app-password and legacy-session behavior to the canonical services, including narrowing, replay-family revocation, and service-JWT binding.
- [ ] Rebuild account/MFA/identity migrations around current-main tables and test fresh plus populated-main upgrades.
- [ ] Preserve current profiles and generated wire sources without hand edits or downgrades.
- [ ] Obtain a Sol auth/storage review before Task 3.

### Task 3: Compose the production runtime and route policy

**Produces:** Explicit opt-in account runtime with correct route precedence, same-origin portal APIs, durable onboarding/SMTP, management sessions, and scheduler lifecycle.

- [ ] Preserve main's OAuth lexicon resolution, DPoP enforcement, legacy key-file interlock, notification resolution, public XRPC CORS, and route behavior.
- [ ] Register reserved discovery, account API, account assets, exact local account/identity/legacy XRPC, existing OAuth/repository routes, unknown guards, then proxy fallback.
- [ ] Exclude `/account` and `/account/api` from global CORS preflight and response decoration.
- [ ] Compose startup configuration, durable signup transaction, authenticated SMTP/outbox lifecycle, management sessions, portal assets, `did:web` scheduler, and additive MFA services.
- [ ] Fail startup on incomplete production SMTP configuration without Mailpit fallback.

### Task 4: Complete portal projections and identity enforcement

**Produces:** Token-free durable portal projections and real `did:web` write/token admission.

- [ ] Add projections for management/legacy sessions, OAuth apps, app passwords, factors, and identity; remove empty session and nil OAuth placeholders.
- [ ] Make revocation account-bound, idempotent, appropriately step-up protected, and immediately effective.
- [ ] Add a narrow durable identity-admission interface and inject it into repository mutation plus OAuth/legacy token issuance.
- [ ] Preserve PLC-only and active behavior; deny writes/new tokens for suspended or failed-grace `did:web` identities while preserving public reads; fail closed on store/resolver failure.
- [ ] Add restart, concurrency, revocation-race, duplicate-cookie, hostile-origin, migration, and route-fallback regressions using red-green TDD.

### Task 5: Add disposable end-to-end acceptance

**Produces:** A sanitized real-server acceptance harness and evidence records.

- [ ] Start real HTTPS `swan serve` with disposable SQLite, Caddy, isolated Turnstile fixtures, and authenticated TLS SMTP.
- [ ] Exercise signup, email proof, recovery-wide revocation, app-password lifecycle, bearer refresh, replay revocation, portal inventory/revocation, restart, and full `did:web` lifecycle.
- [ ] Generate ephemeral SMTP credentials and require AUTH plus STARTTLS or implicit TLS without external delivery.
- [ ] Run Playwright against the real Swift server.
- [ ] Update handoff, milestone, Task 7, and sanitized acceptance records only for gates actually passed.

### Task 6: Run local, container, native-Linux, and official-client gates

**Produces:** Complete verification receipts for a frozen candidate.

- [ ] Run generated-profile/wire verification, focused account and main regressions, full Swift build/test, and all frontend/browser checks.
- [ ] Build and inspect the complete local `linux/amd64` runtime image, including read-only startup, portal assets, and absence of Node/npm.
- [ ] Copy the frozen tree to a unique netcup temporary directory; build/test natively without production source, data, secrets, image tags, service units, restarts, or deployment.
- [ ] Record production service health before and after native-Linux work.
- [ ] Run the user-assisted official Bluesky-client sign-in, restart/refresh, portal-revocation, and immediate-access-loss flow.

### Task 7: Freeze and security-review the candidate

**Produces:** A sealed Daybreak Blue diff scan for exact `d0e8e114c0de..H` and any reviewed remediation.

- [ ] Freeze clean candidate `H` with both-parent ancestry, tree identity, reconciliation ledger, and dynamic receipts.
- [ ] Run the `security_diff_scan` preflight and stop unless ready.
- [ ] Review every changed/deleted file plus preservation diffs against `30b751b6a083`, covering credential isolation, OAuth scope laundering, routing, migrations, signup/SMTP, `did:web`, revocation, secrets, and container contents.
- [ ] Require sealed report, SARIF, complete coverage, no unresolved high/critical findings, and no deferred auth/identity/migration questions.
- [ ] Send validated remediation to Luna, freeze a new revision, rerun affected evidence, and rerun Daybreak review.

### Task 8: Final review and local landing

**Produces:** Final Sol approval and, only if every gate passes, a local `main` advance.

- [ ] Sol reviews code, evidence, security artifacts, ancestry, ledger rulings, and reconciliation coverage.
- [ ] Address final load-bearing findings with one Luna fix wave and one scoped Sol re-review.
- [ ] Advance local `main` only when native Linux, authenticated SMTP, official-client revocation, sealed security review, and final review all pass.
- [ ] Leave push and deployment untouched.
