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

## Second review correction evidence (2026-08-16)

- Proof reservations and finalization now compare the persisted email and handle, enforce the authorization lease, reject future authorization timestamps, and digest all authorization/session/CSRF/pre-auth and management-session metadata for idempotency.
- Turnstile reservations are acquired before the injected transport await, bounded to 1024 with expiry cleanup, and future challenge timestamps fail closed. The URL transport accepts only the exact Cloudflare HTTPS authority/path.
- Authorization lifetime is bounded to 1–900 seconds, identity validation uses canonical supported DID validation, invite mode has a bounded token-bucket admission seam, and signup email requests persist proof plus a durable lane outbox row in one transaction with an enumeration-resistant accepted response.
- SMTP no longer uses process-memory deduplication; its deterministic idempotency key is passed to the durable outbox transport. Recovery revocation attempts all credential classes and aggregates failures. Lifecycle adapters require verifier-issued opaque capabilities, and create-account requires an authorization pipeline and verified email code.

The frozen foundation still owns account, identity, session, and management side effects. The lane now exposes `SignupAtomicFinalizationStore.makeFinalizationTransaction` and a concrete `SQLiteSignupFinalizationTransaction`; integration must pass that object to the foundation and invoke `commit()` within the foundation's durable transaction (or shared transaction coordinator) so those side effects and proof/invite consumption are one commit. Full build, live Turnstile/SMTP, outbox worker, wire-flow, and production gates remain unexecuted.

Final-review correction: signup now fails closed unless the store conforms to the atomic transaction seam. `SQLiteSignupTransactionCoordinator` exposes a transaction-scoped writer object over one connection and rolls back writer failures; the foundation integration must implement the writer and perform account/identity/session plus Task 4 finalization SQL through that context. The lane does not claim atomic account creation until that writer is installed. The email outbox now carries a deterministic delivery ID, authenticated protected envelope, pending/lease/attempt state, and is designed for claim/retry workers. Turnstile used-token TTL is bounded and any future challenge timestamp is rejected. Lifecycle capabilities carry nonce, expiry, action and step-up binding and require durable verifier consumption before each operation. Email updates fail closed without an atomic association/outbox store. SMTP exposes a channel-level deadline protocol for the NIO transport; the existing task-group fallback is not considered production-safe.

The former generic callback/transaction protocols are deprecated and are no longer selected by `SignupService`; only `SignupFinalizationCoordinator` is accepted. The coordinator integration remains explicitly unassembled until foundation account, identity, session, invite, proof, and result writes are implemented on the same connection.

Latest gate correction adds AES-GCM envelope opening, a lease-fenced outbox worker with bounded exponential retry scheduling and max attempts, strict Turnstile hostname/action/timeout bounds, and production SMTP construction requiring deadline-capable TLS connections. The coordinator remains fail-closed until the parent foundation supplies the transaction-scoped writer that performs all foundation and Task 4 SQL on the held connection; no nested reacquisition is treated as atomic.

Adapter completion adds outbox handle/AAD consistency checks, explicit cancellation propagation before retry, a delivery-ID SMTP overload for durable workers, a Mailpit-only lab configuration, and a trusted peer-IP extractor protocol. The coordinator's foundation writer remains the required integration point for same-connection Task 4 CAS/consume/result SQL.

Release correction removes the default SQLite coordinator conformance. Only `AssembledSQLiteSignupCoordinator`, constructed with a transaction-scoped foundation writer, can satisfy finalization; plain SQLite therefore fails closed before consumption. The outbox worker opens/authenticates the protected code envelope with delivery ID, email, and handle before invoking SMTP with the durable delivery ID as the idempotency key. Arbitrary public protected-envelope and peer-string construction paths were removed.

The service now receives the finalization coordinator explicitly rather than casting the authorization store, and the generic foundation argument was removed from finalize. `SocketAddressSignupPeerExtractor` derives buckets only from a typed transport peer address and a server HMAC secret. The assembled coordinator is the sole SQLite finalization implementation; its writer is responsible for canonical Task 4 CAS/consume/result SQL on the held connection.

The assembled coordinator now runs the foundation writer and the connection-scoped `finalizeTask4` helper in the same SQLite transaction; unavailable/transient coordinator errors no longer call `store.fail`, preserving the reservation for retry. `swift build --target SwanAccounts` completed successfully (only existing dependency deprecation warnings); `SwanSQLite` was blocked by unrelated clang dependency-scanner module-resolution failures.

Final P1 correction adds the public `SignupAuthorizationInput.make(...peer:)` factory and a SocketAddress/extractor authorization path; arbitrary raw bucket construction remains internal. Connection-scoped finalization now checks persisted handle, identity, and account fields and requires live authorization-owned invite/proof reservations in the final CAS transaction.

The coordinator now checks and returns a persisted finalization result before invoking the foundation writer. Invite consumption verifies expiry, retry reservation renewal is constrained to the same authorization/input digest and unconsumed material, and SQLite exposes durable invite persist/list methods through the lane persistence protocol.

Lifecycle invite issuance now requires durable hashed persistence before returning the raw code and supports operator-authenticated listing metadata. Reservation renewal rechecks underlying invite/proof expiry and consumption for owned leases. Turnstile URL validation rejects non-default ports, credentials, query, or fragment; envelope sealing accepts only key version 1.

Lease renewal now updates authorization plus every owned reservation with affected-row CAS checks and rolls back when material is expired/consumed. Purge removes retained failed/committed authorization/results and delivered/permanent-failed/expired outbox rows. Production SMTP delivery requires the deadline-capable transport and passes an absolute deadline to the channel; the prior task-group timeout path is no longer used.

Final transport correction adds deadline-bearing Turnstile verification (URLSession retains a bounded request timeout), deadline-bearing SMTP AUTH and SEND, lease-fenced outbox completion CAS, bounded 1–300 second delivery leases, and configurable purge batches capped at 1000. `swift build --target SwanAccounts` completed successfully with only pre-existing warnings.

Residual hardening adds remaining-deadline rejection and cancellation checks to URLSession siteverify, requires deadline-bearing SMTP connect/auth/send, removes the unsafe public authorization failure hook, applies affected-row lease CAS for outbox completion, and caps Turnstile/rate-admission state with fail-closed capacity.

Retention correction purges expired issued authorizations/owned reservations, consumed proofs after audit retention, expired invites, and redeemed invites after retention in bounded batches. Signup email issuance now generates the code internally with CSPRNG, persists only the digest plus protected envelope, and exposes submitted-code digest verification rather than a public raw-code issuance path.

Verification correction adds a persisted proof verifier that recomputes HMAC over submitted code/email/handle, requires an authorization-owned live reservation, and applies bounded attempts. Reservation/proof purge deletes use bounded key subqueries.

Final review correction wires the persisted verifier into `SignupService.authorize` when injected, fixes the sixth-attempt bypass, caps the attempt dictionary at 4096 with fail-closed admission, and caps SMTP attempt timeout at 300 seconds. `swift build --target SwanAccounts` completed successfully with pre-existing warnings.

Latest correction requires the proof verifier/service for `openProtected`, performs verification after the authorization-owned reservation is created, keys attempts by proof digest rather than authorization ID, adds the verification code to the typed peer overload, and rejects explicit Turnstile ports including `:443`. `BoundedSignupEmailProofVerifier` is now the production injectable implementation.
