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
  checks the same archive/source prerequisites without starting containers;
  `swan lab scenario --output ...` emits a summary-only, planned-not-executed
  artifact whose type has no credential, token, key, request, response, or
  account-data field.
- The first non-authority record-read slice is live only behind the durable
  resource capability: `com.atproto.space.getRecord` and
  `com.atproto.space.listRecords` use generated server contracts, fixed-route
  DPoP validation, self-only OAuth subject/repository matching, and the
  startup-preopened SQLite directory. It implements the pinned list ordering,
  cursor, and `excludeValues` behavior, but does not yet implement
  credentials, cross-host reads, writes, CAR/blob transfer, or other profile
  endpoints. A profile-specific `space:` OAuth scope can now be issued as a
  narrow resource grant without adding the broad `atproto` token scope; the
  domain policy remains the exact space/collection authorization decision.

## Completion gates

Completion still requires the full pinned XRPC surface, signed delegation and
space credential JWTs, durable repositories/CARs/blobs, OAuth and account
lifecycle, generated wire sources, Compose reference PDS/PLC/Caddy matrix,
and macOS/Linux verification. The public-genesis vector is a narrow
cross-language gate; it is not evidence that the complete matrix has passed.

## Compose laboratory evidence and live gates

- `Scripts/verify-interop-lab.sh` is an offline structural verifier for the
  cache SHA, source shape, topology membership, local-TLS/Toxiproxy route, and
  the no-network-source-fetch Dockerfile boundary. `SwanInteropTests` also
  covers cache-pin rejection and the sanitized scenario schema.
- The laboratory does not expose PLC, Mailpit, or Toxiproxy publicly. Caddy
  has only local-CA TLS routes for `swan.test` and `pds.test`; PDS traffic goes
  through its named Toxiproxy listener. No permissioned route gains a public
  fallback.
- A live matrix is still unverified. It requires Docker Compose v2, locally
  supplied disposable secrets (never committed or included in artifacts),
  trust of Caddy's laboratory CA by the runner, and implementation of the
  remaining pinned endpoint/credential paths. The scenario artifact records
  intent only and must not be represented as a passing reference-PDS matrix.
