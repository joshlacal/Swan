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
- `28c35493` adds the local, non-PLC account installation half: deterministic
  key references are paired with a verified empty public repository in the
  account's WAL database before an active control-plane row is written. Its
  commit-CID binding makes duplicate recovery and legacy-state rejection
  explicit without treating a matching timestamp as provenance.
- `swan account install-local` now exposes that exact offline installation
  workflow to an operator. It requires the operator capability, an
  owner-only password file, and a 32-byte URL-safe-base64 KEK supplied through
  `SWAN_ACCOUNT_KEK` and/or an owner-only mounted KEK file. It creates only
  encrypted file envelopes, the empty public genesis, and the local control
  row; PLC registration and remote handle verification remain explicitly
  outside this command.
- SQLite roots, account directories, database files, and SQLite WAL/SHM
  sidecars are now owner-only (`0700` directories and `0600` files). Swan
  validates every root and account path without following links and refuses
  pre-existing unsafe objects before SQLite opens them. macOS SQLite cannot
  open `/dev/fd/<directory-fd>/database`, so it receives a descriptor-validated
  absolute path beneath those owner-only directories; retained descriptors
  anchor validation and all sidecar operations.
- `5eb0d957` adds the separate bearer-authenticated loopback management
  listener and process lifecycle wiring. It does not make public OAuth routes
  available; those remain deliberately fail-closed pending the full HTTP
  authorization flow.
- The first live OAuth bridge is an explicit `--enable-localhost-par` lab
  option. It requires an HTTPS issuer and exposes only `POST /oauth/par` for
  virtual localhost public clients, using strict bounded forms and durable
  DPoP nonce/replay validation. Discovery, authorization, token, and
  revocation routes remain unavailable; PAR success is not a claim of a
  complete authorization server.
- The protected-resource foundation accepts only one DPoP authorization
  credential and proof, binds the proof to a configured route target and
  access-token hash, checks the durable token-family JKT, and rechecks the
  account lifecycle before it can create `AuthorizationContext.accountOAuth`.
  Resource authorization permits HTTPS public identities, with HTTP accepted
  only for `localhost`, `127.0.0.1`, or `::1` lab origins when Hummingbird is
  itself bound to literal `127.0.0.1` or `::1` on the same port; an invalid
  remote cleartext identity leaves permissioned routes closed. The typed
  authority `getSpace` route now uses this boundary.
- The account suite passes locally. Its native-library portability remains an
  explicit gate: local macOS testing uses Homebrew libsodium include/library
  paths, and Linux plus the minimum supported macOS have not yet been run.
- `OAuthTokenVault` and memory-only DPoP replay are compatibility scaffolds,
  not sufficient durable authorization state. `getSpace` combines the durable
  resource boundary with the pre-migrated account directory; request handling
  never creates or migrates account SQLite state. The server—not an external
  capability—constructs that route's authorizer from its canonical URL and
  OAuth runtime, so the DPoP `htu`, nonce issuer, token service, and handler
  cannot be miswired independently.
- PAR now has a durable browser-handoff primitive: an opaque request URI can
  retrieve only its live, unconsumed bound request, and final approval
  consumes that exact binding before issuing a code. This gives upcoming login
  and consent routes the original PAR DPoP, PKCE, redirect, scope, and
  confidential-client-key tuple without persisting browser sessions or
  reconstructing a DPoP proof from form input.

## Acceptance gates

Negative tests must cover malformed client metadata, unsafe remote endpoints,
PAR/code expiry and reuse, PKCE mismatch, nonce challenge, DPoP and client
assertion replay, bad issuer/audience, JWKS rotation, concurrent refresh,
family revocation, account status, and key rotation. Real OAuth HTTP routes
remain fail-closed until these pass.
