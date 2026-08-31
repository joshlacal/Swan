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
  an owner-only mounted KEK file. It creates only
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
- `--enable-localhost-par` remains a deliberately narrow PAR-only lab option.
  `--enable-localhost-oauth` is its separate, mutually-exclusive progression:
  it exposes PAR, browser login/consent, token, refresh, and revocation only
  for the AT Protocol virtual localhost public client. It requires an HTTPS
  issuer and an already-provisioned local account; it neither fetches remote
  client metadata nor accepts confidential clients. Discovery remains closed,
  so this cannot be mistaken for the complete public authorization server.
- The local browser bridge carries an HMAC-signed, ten-minute,
  `Secure; HttpOnly; SameSite=Lax` approval cookie containing only an opaque
  PAR URI, CSRF value, and (after password authentication) account DID. The
  database retains the original DPoP/PKCE/client/redirect binding but never a
  browser session, password, raw token, or proof. Approval atomically consumes
  that exact PAR before code issuance; token exchange and refresh prove a new
  ES256 DPoP proof, and refresh reuse revokes the durable family. The local
  revocation endpoint accepts DPoP-bound access or refresh tokens and returns
  oracle-free RFC 7009 success after revoking the entire matching family.
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
- PAR has a durable browser-handoff primitive: an opaque request URI can
  retrieve only its live, unconsumed bound request, and final approval
  consumes that exact binding before issuing a code. This preserves the
  original DPoP, PKCE, redirect, and scope facts without reconstructing a DPoP
  proof from form input.
- `--enable-oauth-authorization-server` is the separately opt-in complete
  authorization-server assembly. It constructs only when a durable account
  directory and hardened remote client-metadata loader are available, and it
  publishes both OAuth metadata documents only when its issuer and protected
  resource exactly match Swan's public URL. It registers PAR, browser
  login/consent, token, and revocation as one route bundle; a partial or
  mismatched assembly leaves discovery and every remote OAuth route closed.
- The complete server uses the durable metadata/JWKS cache and fresh hardened
  revalidation for token and revocation operations. Remote clients require
  HTTPS (apart from the explicit localhost lab exception), re-resolved and
  filtered DNS, bounded document reads, and no redirect following. The CLI
  exposes the localhost exception and literal network allowlist only as
  explicit authorization-server lab options.
- Remote public-client HTTP coverage proves metadata publication, PAR,
  browser approval, PKCE code exchange, exact redirect matching, refresh
  rotation/reuse family revocation, revocation, and deactivated-account
  refusal. Confidential HTTP coverage proves ES256 `private_key_jwt` requires
  the token endpoint as its exact audience and rejects replay. The durable
  OAuth suite additionally proves a same-`kid` JWK rekey/removal invalidates
  the confidential family before refresh. In-process resolver/transport
  fixtures prove private-address metadata is rejected before any outbound
  transport call; no test fetches an external endpoint.

## Acceptance gates

Negative tests must cover malformed client metadata, unsafe remote endpoints,
PAR/code expiry and reuse, PKCE mismatch, nonce challenge, DPoP and client
assertion replay, bad issuer/audience, JWKS rotation, concurrent refresh,
family revocation, account status, and key rotation. Remote-client and
confidential OAuth HTTP routes remain fail-closed until these pass; the
localhost virtual-client bridge has its own end-to-end negative coverage.
