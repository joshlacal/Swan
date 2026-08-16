# Task 7 MFA / step-up integration report

## Delivered in this lane

- `Sources/SwanAccounts/MFAFactors.swift`
  - RFC 6238 TOTP (SHA-1/SHA-256/SHA-512, six/eight digits, one-step default drift), constant-time comparison, durable per-account/factor replay CAS guard.
  - AES-GCM TOTP envelopes with a key-reference-only external key-store boundary.
  - High-entropy recovery-code generation, digest-only replacement, and single-use consumption through the storage contract.
  - Short-lived, durable, revocable, single-purpose tokens bound to session/account/factor/authentication strength.
  - WebAuthn ES256/P-256 registration and assertion checks: parsed attested COSE key, exact HTTPS origin/RP, client-data type/challenge/crossOrigin, RP hash, UP+UV, bounded strict DER (or fixed raw) ECDSA signature parsing without low-S enforcement, account/credential/purpose binding, one-time challenge and monotonic sign-count policy. Invalid assertions are validated before challenge consumption.
  - Freshness/MFA step-up policy and a bounded, durable, secret-redacting MFA audit seam.
- `Sources/SwanStorage/Task7MFAStorageContracts.swift`
  - Durable replay, factor-token, WebAuthn challenge lookup, and audit-store contracts.
- `Sources/SwanSQLite/AccountFactorStore.swift`
  - SQLite implementations for factor metadata, generic/WebAuthn challenges, TOTP envelopes/replay state, recovery digests, WebAuthn credential metadata, durable tokens/audit events, and atomic CAS/consume operations.
  - Save, reservation, replay-CAS, and assertion/enrollment transactions enforce active parent factor kind; cryptographic inputs are bounded before hashing/parsing.
  - WebAuthn assertion CAS plus challenge consumption is one transaction; enrollment reloads and validates the durable enrollment context, then consumes challenge plus inserts credential atomically. TOTP/recovery/WebAuthn atomic paths re-check active parent factor kind in SQL. Missing/invalid challenge-purpose context is corruption, never an assertion default.
- `Tests/SwanAccountsTests/Task7MFATests.swift`
  - RFC vectors, drift/replay/concurrency, recovery single-use, token/policy, WebAuthn registration/assertion negative cases, and SQLite durable round-trip/CAS coverage.

## Integration patch for Task 6 / HTTP owners

The lane intentionally does not modify router, portal/account HTTP, management-session, OAuth, generated-wire, migration, package, command, or deployment files. After this lane is merged, the integration owner should:

1. Construct `TOTPReplayGuard` with the durable replay store, then construct `TOTPFactorService` with the process key provider, factor store, and account's `TOTPSecretEnvelope`.
2. Reserve/consume `WebAuthnChallenge` through `WebAuthnChallengeStore`; include its account, factor, and purpose, and pass the configured HTTPS origin and RP ID to `WebAuthnVerifier`.
3. Issue `AuthenticationStrength.stepUp(...)` only after fresh password plus TOTP/passkey, then issue a matching durable `FactorTokenPurpose.stepUp` token bound to the active session. Recovery codes cannot issue step-up tokens.
4. Call `StepUpPolicy.authorize` for factor changes, identity/email/handle changes, exports, migrations, app-password and deletion operations. Email recovery and recovery codes may revoke sessions/recover a password but must not remove factors or change identity.
5. Emit only `MFAAuditEvent` values through `MFAAuditStore`; never log codes, challenges, signatures, bearer tokens, or plaintext TOTP/recovery material.

Management-session/OAuth HTTP integration remains an exact integration patch after Task 6 lands; it is not included here.

## Verification

`swift test --filter Task7MFATests` passed (10 tests, 0 failures; SwiftPM also selected unrelated targets with zero tests). This focused command rebuilt affected products; no full repository test suite was run.
