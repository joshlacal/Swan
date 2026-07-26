# Swan Spaces Interoperability Alpha

## Frozen inputs

- Proposal 0016: `1caad93dbb1f445396f6abf3b97eb4040345e78e`
- TypeScript implementation: `3f6c96d5d2d25438bd40fa89d6ecc37865f8e354`
- Petrel generator baseline: `db84b2c9788aa38000ee3f134e21feffa8f351cd`
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

## Completion gates

Completion still requires the full pinned XRPC surface, signed delegation and
space credential JWTs, durable repositories/CARs/blobs, OAuth and account
lifecycle, generated wire sources, Compose reference PDS/PLC/Caddy matrix,
and macOS/Linux verification. This document deliberately does not mark those
gates complete based on scaffolding or unit-only evidence.
