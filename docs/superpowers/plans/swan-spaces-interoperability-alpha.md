# Swan Spaces Interoperability Alpha

## Frozen inputs

- Proposal 0016: `1caad93dbb1f445396f6abf3b97eb4040345e78e`
- TypeScript implementation: `3f6c96d5d2d25438bd40fa89d6ecc37865f8e354`
- Petrel runtime baseline: `db84b2c9788aa38000ee3f134e21feffa8f351cd`
- Isolated Petrel generator revision: `d011ccf0029457434e659ec48c8024baa7b5c4e4`
- Profile: `Profiles/permissioned-data-0016-2026-07-03.json`

The profile pins the TypeScript source archive and a complete checksum manifest
for the `com.atproto.space` and `com.atproto.simplespace` lexicons. Normal
builds use checked-in sources. `interop/fetch-reference.sh` is the explicit,
checksum-verified way to populate the ignored reference cache.

## Sequenced work

1. Freeze profile and land Petrel’s isolated `space` declaration / server
   contract generator change without altering existing output by default.
2. Complete pure wire primitives: cross-language vectors, signed reader
   envelopes, canonical record DAG-CBOR/CIDs, two-root CAR writer/reader.
3. Make per-account SQLite authoritative for public/space records, LtHash,
   revision CAS, oplog, blobs, and atomic notification outbox; prove recovery.
4. Add account keys/PLC, Argon2id password verification, OAuth PAR/PKCE/DPoP,
   strict metadata fetch, and the loopback management listener.
5. Wire every pinned space/simplespace endpoint, stream CAR/blob payloads, and
   enforce account-state/public-private isolation.
6. Run the Compose matrix against the pinned TypeScript PDS under normal,
   delayed, duplicated, reordered, offline, and corrupted traffic.

## Current evidence

- Exact six-segment space record URIs are parsed.
- Checked-in Swift wire sources are regenerated from every verified pinned
  lexicon with the opt-in typed async `ServerHandler` contracts enabled.
- LtHash is 1,024 little-endian UInt16 lanes with modular add/remove; its empty
  commitment is checked against the pinned TypeScript test vector.
- Commit contexts use the proposal domain prefix, big-endian TLS vector lengths,
  ES256 context signatures, and HKDF-SHA256/HMAC-SHA256 content bindings.
- Full-recovery CARs use the required ordered two roots (signed commit then
  index), validate root/record CIDs, recompute LtHash from the index, and reject
  an altered record block before recovery data is returned.
- A batch is atomic in the in-memory repository; a SQLite WAL test proves
  oplog/outbox insertion and outbox recovery operations share one transaction.
- The local simple authority covers member-list, managing-app, public, and app
  allow-list decisions without granting credentials write power.
- `28c35493` installs a locally provisioned account only after its verified
  empty public-repository genesis is durable. The immutable public commit CID
  binds the separate control-plane row; interrupted installation recovers,
  legacy unbound control rows fail closed, and independent SQLite connections
  race to one registration without persisting password or private-key bytes.
- `aa1c6cc5` records a sanitized fixed public-genesis vector under this
  profile. Swift verifies the pinned TypeScript CAR and the TypeScript
  `verifyRepoCar` path verifies Swan's CAR. This also enforces canonical
  low-S ES256 repository signatures, because the pinned verifier rejects the
  mathematically valid high-S encoding accepted by Swift Crypto.
- The Compose laboratory now has a separate, cache-gated topology: Swan,
  source-pinned reference PDS and PLC images, Caddy local TLS, Mailpit,
  Toxiproxy, and a Swift scenario-runner. `interop/fetch-reference.sh` is the
  only source-population path; both image Dockerfiles verify the archive SHA
  before unpacking it and contain no source clone or curl. `swan lab validate`
  checks the same archive/source prerequisites without starting containers; `swan
  lab scenario --output ...` probes pinned profile endpoints on both hosts and
  records per-endpoint request/response summaries under a fixture policy that
  intentionally carries no credential, token, key, account, or blob payload data.
- The first non-authority record-read slice is live only behind the durable
  resource capability: `com.atproto.space.getRecord` and
  `com.atproto.space.listRecords` use generated server contracts, fixed-route
  DPoP validation, self-only OAuth subject/repository matching, and the
  startup-preopened SQLite directory. It implements the pinned list ordering,
  cursor, and `excludeValues` behavior, plus the credential-reader path and
  write/apply-writes flows. Cross-host behavior remains defined by the live
  interop matrix for end-to-end confidence. A profile-specific qualified
  `space:<type>?authority=...&skey=...&action=...` OAuth scope can now be
  issued as a narrow resource grant without adding the broad `atproto` token
  scope. Bare/default type scopes are rejected; the domain policy remains the
  exact space/collection authorization decision.
- The six authority-owned `com.atproto.simplespace` lifecycle/membership
  routes now use checked-in generated server contracts and the same
  startup-preopened DPoP/OAuth capability. They are available for local-authority
  lifecycle and membership workflows with managing-app and credential-aware policy
  checks; notifications and repository sync are available via their dedicated
  capability slices. SQLite migration v3 rebuilds legacy simple-space authority
  CHECK constraints and preserves all FK child facts,
  so a policy-only patch retains its omitted managing-app value and an empty
  wire value clears it. This is not evidence of cross-host SimpleSpace
  interoperability.
- Authority-issued space credentials now have a closed core/storage boundary.
  Swan locally issues ES256 compact JWTs with
  `typ=atproto-space-credential+jwt`, a fresh opaque bounded JTI, and a
  two-hour maximum lifetime. Verification also accepts the pinned TypeScript
  ES256K compact low-S form and the permitted `#atproto` account-key fallback
  when no `#atproto_space` key is published. Issuance first runs the durable
  startup-preopened `authorizeSimpleSpaceRead` policy, then resolves the
  active authority signing material only through `AccountKeyStore`; neither
  private key bytes nor reader-specific credential artifacts enter SQLite.
  Verification performs bounded compact-JWT inspection, exact issuer/space
  binding, pinned/local public-key selection, low-S signature validation, and
  clock checks before creating `AuthorizationContext.spaceCredential`. Remote
  DID/PLC key lookup and client-attestation JWKS validation are explicitly
  unavailable, so unverified app identity and unknown remote keys fail closed.
- `com.atproto.space.getSpaceCredential` now exchanges a bounded signed
  case-insensitive `Authorization: Bearer` delegation JWT for an
  authority-issued credential. Delegations require the proposal type,
  supported ES256 or ES256K algorithm, `#atproto` key ID, issuer, authority
  service audience, space subject, bounded opaque JTI, lifetime, low-S
  signature, and a local or pinned public key; unknown keys never trigger
  DID/PLC/DNS/HTTP resolution. The authority HMAC-binds and atomically reserves
  each verified JTI in `control.sqlite` before policy or signing, so a replay
  cannot mint a second credential even after restart. The exchange uses only
  the startup-preopened authority policy directory, then the existing durable
  credential authority.
  `getRecord` and `listRecords` accept either their existing DPoP OAuth path
  or an exact Bearer space credential. Credential reads are cross-repository
  only within their bound space and remain read-only; Bearer tokens never
  satisfy the DPoP OAuth authorizer. `getDelegationToken` is separately
  capability-gated: the local `serve` composition installs it only with
  durable DPoP OAuth, a startup-preopened account, and an account-key signer;
  the default/incomplete server remains closed.
- PLC identity history is now durable per account: genesis and signed
  rotations are stored as a linear CID-bound chain, verified fail-closed, and
  used by public repository description reads to expose the authenticated
  terminal DID document. Rotation records the pending operation before PLC
  network I/O and promotes control key generations with a compare-and-swap;
  local tests cover restart, idempotency, tampering, and rotated public reads.
- `swan lab semantic` and `LocalSemanticInteropRunner` now provide an offline
  Swan-to-Swan durable semantic gate. Two independent account roots exchange
  real oplog batches, reject duplicate and unordered delivery, force a
  retention-gap full snapshot, authenticate/corruption-test a two-root CAR,
  enforce a bound space credential, and verify public/private blob namespace
  isolation. The artifact is summary-only and explicitly does not claim that
  the pinned TypeScript PDS participated.
- The callable `swan lab live` runner now drives selector-bound public
  `repo.putRecord`/`repo.getRecord` and permissioned delegation/credential
  `space.createRecord`/`space.getRecord` flows. It keeps OAuth DPoP proofs and
  bearer credentials out of artifacts and compares returned record CIDs. Its
  XRPC path construction is covered directly, including DPoP-bound query
  ordering.
- Task 43's independent rereview is recorded under
  `.superpowers/sdd/swan-spaces-interoperability-alpha/task-43-rereview-2026-07-28.md`.
  Its scoped public-read verdict is PASS: `PublicRepositoryReadHTTPTests`
  executes 8/8, the opt-in 256 MiB production-directory RSS gate passes, and
  the serialized macOS suite passes.
- The explicit 256 MiB bounded-transfer gates pass for the permissioned CAR
  spool, private blob CAS stream, and staged CAR import. These are local
  memory/streaming gates; they do not replace Docker or Linux evidence.
- The pinned TypeScript source cache was booted in a disposable localhost
  smoke runtime. Account creation, authenticated public record creation,
  record read/list, and `sync.getRepo` succeeded. Blob upload remained staged
  until a valid record reference; the smoke result is reference-host evidence,
  not Swan/TypeScript convergence evidence.

## Completion gates

Completion still requires the full pinned XRPC surface, delegation minting at
the user PDS, durable repositories/CARs/blobs, OAuth and account
lifecycle, and Compose reference PDS/PLC/Caddy matrix, plus macOS/Linux verification.
The public-genesis vector is a narrow cross-language gate; it is not evidence
that the complete live interop matrix has passed.

## Compose laboratory evidence and live gates

- `Scripts/verify-interop-lab.sh` is an offline structural verifier for the
  cache SHA, source shape, topology membership, local-TLS/Toxiproxy route, and
  the no-network-source-fetch Dockerfile boundary. `SwanInteropTests` also
  covers cache-pin rejection and the sanitized scenario schema.
- The laboratory does not expose PLC, Mailpit, or Toxiproxy publicly. Caddy
  has only local-CA TLS routes for `swan.test` and `pds.test`; PDS traffic goes
  through its named Toxiproxy listener. No permissioned route gains a public
  fallback.
- Compose startup now uses real readiness probes: Swan must answer
  `GET /health`, the pinned reference PDS must answer `GET /xrpc/_health`, and
  the pinned PLC must answer `GET /_health`. The reference PDS waits for a
  healthy PLC, Toxiproxy setup waits for a healthy reference PDS, and Caddy
  waits for a healthy Swan listener before creating the TLS trust handoff.
- A live matrix is still unverified in this environment. It requires Docker
  Compose v2, locally supplied disposable secrets (never committed or included
  in artifacts), trust of Caddy's laboratory CA by the runner, and cross-host
  execution under the pinned faults. The scenario artifact records transport
  and endpoint status only and must not be interpreted as full protocol
  interoperability proof on its own.
