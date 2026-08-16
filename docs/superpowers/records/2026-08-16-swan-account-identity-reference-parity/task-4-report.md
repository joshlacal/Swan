# Task 4 onboarding lane report

Baseline: `884b92fd` (foundation). Lane: `Swan-account-onboarding`.

## Delivered

- `SignupPolicyService` and derived `SignupPolicyDescription` advertise
  `inviteCodeRequired` only for `inviteRequired`; `closed`, `inviteRequired`,
  and `openProtected` have explicit Turnstile/email semantics.
- `SignupInviteService` creates/generates bounded codes and stores only a
  domain-separated HMAC-SHA256 digest. `SignupAuthorizationStore` receives a
  new SQLite extension hook (`migrateTask4OnboardingSchema`) with atomic
  invite/email-proof reservation, lease release, idempotent authorization
  finalization, and bounded expiry cleanup.
- `TurnstileVerifier` validates a missing/failed/expired/duplicate token,
  exact hostname and action, and fail-closed transport/timeout behavior behind
  `TurnstileHTTPTransport`; `URLSessionTurnstileTransport` is an optional
  bounded HTTPS adapter. No widget or live call was created.
- `AuthenticatedSMTPDelivery` adds injected authenticated STARTTLS/implicit-TLS
  configuration, certificate-hostname requirement, auth-mechanism selection,
  bounded retry, idempotency, and cancellation declaration while retaining the
  existing Mailpit lab transport untouched.
- `SignupService`, `AccountEmailUpdateService`, recovery-wide revocation hooks,
  `AccountLifecycleService`, and reference-shaped lifecycle/create-account XRPC
  adapters are added without changing router/runtime assembly or generated wire.
- `SignupEmailProofService` issues random bounded verification codes and stores
  only an email/handle-bound HMAC digest for the authorization step.

## Tests and verification

Red tests were recorded first in `Tests/SwanAccountsTests/Task4OnboardingTests.swift`;
the initial focused run was blocked by concurrent SwiftPM builds in other lanes.
Source parse and `swiftformat` pass. A clean isolated Swift build could not be
completed because independent lane scratch checkouts exhausted the shared disk
while cloning `swift-crypto` (`No space left on device`).

## Integration patch for owner

1. Invoke `SQLiteControlDatabase.migrateTask4OnboardingSchema()` from the
   shared migration spine under the reserved Task 4 migration version, after
   foundation tables and before any adapter claims signup rows.
2. Construct `SignupPolicyService`, `SignupInviteService`, and (for
   `openProtected`) `TurnstileVerifier` in runtime assembly; inject a bounded,
   peer-validated transport and production secret through existing secret
   plumbing. Keep `describeServer.inviteCodeRequired` derived from policy.
3. Wire `SignupService` and `SwanAccountLifecycleXRPCAdapter` into the router
   and map their typed errors to the frozen generic `401/403/409/422/429/503`
   account API responses. Do not authenticate `/xrpc/*` with cookies.
4. Supply the foundation bundle that atomically creates the account,
   identity binding, and management session before calling the SQLite
   finalization transaction. Integrate the revocation hooks with OAuth,
   legacy, app-derived, and management session stores.
5. For production SMTP, provide an authenticated NIO TLS transport implementing
   `AuthenticatedSMTPTransport`; keep `MailpitSMTPDelivery` as the lab-only
   mode. Never log credentials, tokens, or message bodies.

## Unexecuted external gates

No live Turnstile, external email relay, production secret/configuration,
router deployment, Docker build, Linux x86_64 build, official-client flow,
network acceptance, push, or deploy was run.

## Correction review evidence

Correction commit aligns the SQLite extension with the foundation schema:
`signup_authorizations.authorization_id` and `signup_invites.invite_digest`;
the lane no longer defines either shared table. Reservations, pre-account
email proofs, and persisted finalization results use separate extension tables.
Finalization now uses an explicit `issued/failed -> committing` CAS, validates
the canonical request digest, consumes proof/invite rows, persists the result,
and only then marks `committed` in one transaction. Retries return the stored
account DID and management session.

Invite-required and open-protected authorization now require a canonical email
and proof digest. Turnstile tokens reserve capacity before the transport await,
expire from a bounded reservation set, and release on all failure paths. The
default URLSession siteverify transport accepts only Cloudflare's exact HTTPS
authority/path. Lifecycle adapters require an explicit operator or
management-session authorization context. Authenticated SMTP now has a
certificate-hostname-checked network transport seam plus per-attempt deadlines.

Source parse, SwiftFormat, and `git diff --check` passed. Focused Swift tests
were not rerun because another lane's Xcode-beta SwiftPM rebuild/test was still
active and the shared volume had fallen to approximately 4.5 GiB free; racing
it would invalidate the evidence.
