# Task 7 MFA / step-up integration report

## Delivered in this lane

- `Sources/SwanAccounts/MFAFactors.swift`
  - RFC 6238 TOTP (SHA-1/SHA-256/SHA-512, six/eight digits, one-step default drift), constant-time comparison, actor-isolated per-factor replay/CAS guard.
  - AES-GCM TOTP envelopes with a key-reference-only external key-store boundary.
  - High-entropy recovery-code generation, digest-only replacement, and single-use consumption through the storage contract.
  - Short-lived, single-purpose, account/factor-bound step-up tokens.
  - WebAuthn ES256/P-256 registration and assertion checks: exact HTTPS origin/RP, client-data type/challenge, RP hash, UP+UV, canonical signature, account/credential binding, one-time challenge and monotonic sign-count policy.
  - Freshness/MFA step-up policy and a bounded, secret-redacting MFA audit log.
- `Sources/SwanSQLite/AccountFactorStore.swift`
  - SQLite implementations for factor metadata, generic/WebAuthn challenges, TOTP envelopes, recovery digests, WebAuthn credential metadata, and atomic CAS/consume operations.
- `Tests/SwanAccountsTests/Task7MFATests.swift`
  - RFC vectors, drift/replay, recovery single-use, token/policy, WebAuthn signature/challenge, and SQLite round-trip/CAS coverage.

## Integration patch for Task 6 / HTTP owners

The lane intentionally does not modify router, portal/account HTTP, management-session, OAuth, generated-wire, migration, package, command, or deployment files. After this lane is merged, the integration owner should:

1. Construct `TOTPFactorService` with the process key provider and the account's `TOTPSecretEnvelope`.
2. Reserve/consume `WebAuthnChallenge` through `WebAuthnChallengeStore`; pass the configured HTTPS origin and RP ID to `WebAuthnVerifier`.
3. Issue `AuthenticationStrength.stepUp(...)` only after fresh password plus TOTP/passkey, then issue a matching `FactorTokenPurpose.stepUp` token.
4. Call `StepUpPolicy.authorize` for factor changes, identity/email/handle changes, exports, migrations, app-password and deletion operations. Email recovery and recovery codes may revoke sessions/recover a password but must not remove factors or change identity.
5. Emit only `MFAAuditEvent` values; never log codes, challenges, signatures, bearer tokens, or plaintext TOTP/recovery material.

Management-session/OAuth HTTP integration remains an exact integration patch after Task 6 lands; it is not included here.

## Verification

`swift build --target SwanSQLite` passed.

`swift test --filter Task7MFATests` passed (7 tests, 0 failures; unrelated test targets were selected with zero tests by SwiftPM's filter).
