# Swan Auth and Platform Plan

## Boundary

This plan covers account control, encrypted signing-key storage, PLC and
handle lifecycle, AT Protocol OAuth, and the loopback operator interface. It
does not add a browser administration console, external email delivery, or
production deployment.

## Sequenced work

1. Keep account signing/rotation keys behind `AccountKeyStore`; make password
   verification Argon2id and keep a versioned authenticated file envelope.
2. Make `control.sqlite` authoritative only for cross-account control state:
   account registry, metadata cache, PAR and authorization-code state, token
   hashes/families, and DPoP replay claims. Repository data stays per account.
3. Implement hardened client metadata/JWKS retrieval and validation: HTTPS
   (with the exact localhost development exception), address filtering on each
   resolution, no unsafe redirects, and bounded response resources.
4. Add PAR, S256 PKCE, ES256 DPoP nonce/replay controls, confidential-client
   `private_key_jwt`, code redemption, refresh rotation/reuse revocation, and
   revocation.
5. Add account creation, PLC genesis/rotation, public empty-repository setup,
   status transitions, Mailpit-only verification/recovery, and loopback
   operator commands.

## Current evidence

- `c8775f33` provides account identifier validation, Argon2id verification,
  encrypted key envelopes, create-only provisioning, explicit rotation, and
  crash-recoverable key installation.
- The account suite passes locally. Its native-library portability remains an
  explicit gate: local macOS testing uses Homebrew libsodium include/library
  paths, and Linux plus the minimum supported macOS have not yet been run.
- `OAuthTokenVault` and memory-only DPoP replay are compatibility scaffolds,
  not sufficient durable authorization state. The next implementation unit is
  the `control.sqlite` OAuth store with atomic token-family semantics.

## Acceptance gates

Negative tests must cover malformed client metadata, unsafe remote endpoints,
PAR/code expiry and reuse, PKCE mismatch, nonce challenge, DPoP and client
assertion replay, bad issuer/audience, JWKS rotation, concurrent refresh,
family revocation, account status, and key rotation. Real OAuth HTTP routes
remain fail-closed until these pass.
