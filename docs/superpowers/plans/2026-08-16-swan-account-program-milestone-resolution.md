# Swan Account Program Milestone-Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Divide the master program into four release-quality increments with explicit entry conditions, current state, and exit evidence.

**Architecture:** Each milestone consumes the durable/runtime guarantees of the previous milestone. Domain seams may be prepared in advance, but a milestone is complete only when its user-visible behavior is production-composed and accepted.

**Tech Stack:** Swift/Hummingbird/SQLite, static SvelteKit, Playwright, Docker, disposable interop environments.

**Spec:** `docs/superpowers/specs/2026-08-16-swan-account-identity-reference-parity-design.md`

## Global Constraints

- Preserve the authorization-context and route-isolation constraints from the master plan.
- Use one enforced `SignupPolicy` as the source for behavior, portal advertisement, and `describeServer`.
- Do not register a partial reference method to improve a parity count.
- Keep push/deploy separate from implementation and local acceptance.

---

## Status matrix

| Milestone | Current resolution | What exists | What blocks completion |
|---|---|---|---|
| 1 — compatibility and portal | **INTEGRATED SEAM** | Signup/invite/proof services, SMTP abstraction/outbox, legacy sessions, app passwords, `did:web`, portal bundle/API adapter, migration v8 | Production service construction, exact routes, authenticated SMTP configuration, atomic provisioning writer, portal service, scheduler/admission wiring, real client/browser acceptance |
| 2 — stronger authentication | **INTEGRATED SEAM** | TOTP, WebAuthn/passkey, recovery codes, factor tokens, audit and step-up services | Portal/login composition and enforcement across all sensitive operations |
| 3 — reference breadth | **DEFERRED** | Storage-neutral adapters, tests, and generated manifest | All new manifest entries remain `registered:false`; import and runtime health are deliberately unassembled |
| 4 — operational parity | **EXTERNAL GATE OPEN** | Disposable script seams and existing unrelated runtime facilities | Complete Linux image and all live SMTP/client/network/backup/load/observability evidence |

## Milestone 1: Compatibility and portal

**Entry condition:** checkpoint `2ca80d27` with migration v8 and clean local suite.

**Execution slices:**

- [ ] M1-A: Construct startup account configuration, enforced signup policy, durable services, and authenticated SMTP.
- [ ] M1-B: Register `createAccount`, lifecycle, legacy session, app-password, reserve-signing-key, and `did:web` claim routes in exact order.
- [ ] M1-C: Implement the production `SwanAccountPortalServing` facade and pass `SwanAccountPortalHTTP` from `SwanCommand`.
- [ ] M1-D: Start the `did:web` revalidation scheduler and connect suspension to token/write admission while preserving reads.
- [ ] M1-E: Run invite/open signup, recovery, email update, app-password, session/device/app revocation, BYO `did:web`, restart, and official-client flows.

**Exit condition:** every M1 surface is LIVE, `describeServer` is accurate, production SMTP is exercised, and portal revocation signs out a real client.

## Milestone 2: Stronger authentication

**Entry condition:** Milestone 1 management sessions and legacy login are stable and restart-tested.

**Execution slices:**

- [ ] M2-A: Add portal endpoints for TOTP, passkey, and recovery-code enrollment/verification/removal.
- [ ] M2-B: Issue and consume factor tokens through legacy login and management step-up.
- [ ] M2-C: Apply fresh step-up to email, password, handle/DID, MFA, app-password, export, migration, deactivation, and deletion.
- [ ] M2-D: Verify replay, concurrency, factor preservation after password recovery, audit redaction, and restart behavior.

**Exit condition:** MFA-enabled password login cannot mint a legacy session without `authFactorToken`; scoped app passwords retain their intended alternative path; every sensitive portal action demonstrates the required freshness.

## Milestone 3: Remaining reference breadth

**Entry condition:** Milestones 1-2 are LIVE so identity/admin operations can reuse real authorization and step-up.

**Execution slices:**

- [ ] M3-A: Register exact PLC identity-update and operator lifecycle routes.
- [ ] M3-B: Connect repo/sync reads to durable projections with reference-compatible keyset and CAR semantics.
- [ ] M3-C: Connect `importRepo` only through the existing full CAR/MST verifier and atomic staging publisher.
- [ ] M3-D: Assemble moderation delivery with pinned transport, key/version management, typed reference payloads, and actionable lookup.
- [ ] M3-E: Regenerate the parity manifest from registered routes and compare behavior with the pinned reference.

**Exit condition:** manifest entries are `registered:true` only where exact local/reference acceptance passes; unsupported surfaces stay declared unavailable.

## Milestone 4: Operational parity

**Entry condition:** all intended protocol surfaces are assembled locally.

**Execution slices:**

- [ ] M4-A: Assemble account/readiness metrics without identifiers or secrets.
- [ ] M4-B: Build and start the pinned Linux x86_64 image read-only; prove static assets are present and Node is absent.
- [ ] M4-C: Run SMTP, backup/off-host encryption, clean-host restore, and key-rotation drills.
- [ ] M4-D: Run official-client and browser acceptance with restart and revocation.
- [ ] M4-E: Run relay subscription/force-sync, AppView visibility, moderation delivery, federation post/read/delete, and load/admission tests.

**Exit condition:** sanitized evidence exists for every required gate; any skipped gate remains explicitly open in the release report.
