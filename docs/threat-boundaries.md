# Swan threat boundaries

Permissioned data provides access control, not end-to-end confidentiality. A
repo or space host can read data it serves. Swan’s alpha therefore focuses on
preventing accidental public exposure and unauthorized cross-space access.

- `AuthorizationContext` is explicit: public, account OAuth, validated
  delegation exchange, self-only read, space credential, and service contexts
  are distinct. No repository API takes an authenticated boolean.
- Delegation JWTs are valid only for one short authority exchange and have no
  repository permission. They resolve exclusively through local or pinned
  `#atproto` keys; unknown issuers never cause DID/PLC/DNS/HTTP lookup.
- A space credential is read-only at the repo host. Writes require a scope
  covering the authenticated account’s own `(space, repo)`.
- The content-binding MAC is a deniable integrity check, never an author
  signature. `verifyContextSignature` and `verifyContentBinding` remain
  separate APIs.
- **The pinned HTTPS source origin is the exact-content integrity authority
  for permissioned repository content.** An author signature covers only
  `(space, author, rev, ikm)` — the content commitment is outside
  `SpaceCommitCodec.contextSigningBytes` — and the IKM ships in the clear in
  the wire commit block, so anyone who can serve or relay that block can
  substitute a commitment and recompute the MAC under the author's original
  signature. This is the pinned upstream proposal-0016 trust model
  (`bluesky-social/atproto`, `packages/space/src/commit.ts`), accepted as-is;
  changing it needs an upstream amendment plus a coordinated re-pin. The
  residual bound is equivocation/high-water detection at
  `Sources/SwanSQLite/SQLitePermissionedRemoteReplicaRecovery.swift:1541-1548`
  — a lower wire revision is `.staleRecovery`, and the same wire revision with
  a different commitment is `.equivocation` — so an origin cannot rewrite
  content it has already served at a given TID, only choose what it serves
  first. The recovery freshness witness comes from that same origin and is a
  freshness check, not corroboration.
- The PLC space-credential/delegation public-key cache has a 60 s bounded
  staleness (`Sources/SwanOAuth/PLCSpaceCredentialPublicKeyResolver.swift:105-106`,
  default `lifetime: 60`, ceiling 300 s) with active eviction of the cached
  entry when a refresh fails (`:477-486`). That 60 s is the accepted key-
  revocation latency window. It was deliberately not tightened to a refresh
  per verification: a remote bearer-token holder would then be able to drive
  one PLC directory request per presented credential, which is a network
  amplification primitive against the PLC directory.
- Account keys are encrypted in owner-only files with a process/mounted-secret
  master key. The master key, tokens, passwords, DPoP private keys, and IKM
  cannot be fixture or logging values.
- Remote OAuth metadata/JWKS retrieval must be HTTPS and reject unsafe
  destinations and redirects except explicit loopback laboratory settings.
- Operator management is a separate loopback listener protected by an operator
  secret; it is not a browser administration surface.

The current in-process HMAC credential authority exists only to exercise local
policy semantics. It is not a replacement for signed JWT delegation tokens or
space credentials on the wire.
