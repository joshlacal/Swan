# Swan Spaces and Interoperability Plan

## Boundary

This plan implements permissioned-space behavior, synchronization, and the
pinned two-host laboratory. It deliberately excludes general public record
CRUD, relay/firehose completeness, AppView integration, FoundationDB, and
Catbird UI work.

## Sequenced work

1. Use typed public and space URIs, credential grants, context signatures, and
   deniable content bindings. Keep reader-specific envelopes out of repository
   persistence.
2. Make each account's WAL database the authority for records, LtHash,
   revisions, blobs, oplogs, and notification outbox entries. Preserve separate
   public and private blob reference namespaces.
3. Implement local `simplespace` authority lifecycle and membership,
   credential issuance, CRUD/apply-writes, streamed CAR/blob responses, and
   independent self/member/managing-app/writer/public-policy checks.
4. Implement writer registration, idempotent notifications, incremental ops,
   compaction and full-CAR recovery, corruption rejection, and crash recovery
   from the durable outbox.
5. Wire all profile endpoints through generated contracts; no permissioned
   endpoint may fall through to a public handler.
6. Complete Compose with Swan, the source-pinned TypeScript PDS/PLC, Caddy
   TLS, Mailpit, Toxiproxy, and a Swift scenario runner. Record sanitized
   cross-implementation fixtures only.

## Current evidence

- `3a7c57b8` establishes per-account WAL repository tables, numeric CAS plus
  wire revisions, one-revision batches, ordered oplogs, atomic outbox writes,
  retention-gap snapshots, and durable blob namespace separation.
- `c7403e5b` aligns the generated incremental-op contract with required-null
  CIDs for deletes.
- The pinned `com.atproto.space.getRecord` and
  `com.atproto.space.listRecords` queries now have their first durable,
  self-repository-only HTTP adapters. They use the generated async
  `ServerHandler` contracts, fixed DPoP paths, and a startup-preopened SQLite
  repository directory; neither path can create, migrate, or reopen an
  account database for a request. The adapters validate duplicate/malformed
  query input before authorization, render only declared JSON fields with
  `Cache-Control: no-store`, and retain the pinned descending default
  `(collection,rkey)` pagination plus tolerant semantic cursor parsing.
  They expose no credential, service-auth, remote-repository, or cross-host
  behavior. Account OAuth is self-only; `atproto` is accepted as a broad
  grant and a bounded `space:` scope is passed to the domain policy for exact
  authority/skey/read/collection enforcement. The focused HTTP tests exercise
  SQLite-backed values, real durable OAuth tokens and signed DPoP proofs,
  narrow grants, foreign-repository opacity, lifecycle closure, replay, and
  no public-repository fallback.
- All unimplemented HTTP endpoints intentionally return generic authorization
  errors or `profile_endpoint_pending`; they are not interop evidence. The
  pinned TypeScript `com.atproto.space.getSpace` exception is now a typed,
  authenticated authority-only adapter. It is installed only after startup
  preopens the active account database set, and it accepts only an active
  `atproto`-scoped DPoP token whose subject equals the requested authority.
  It emits just the generated URI/config shape, rejects a mismatched storage
  projection, and maps foreign/missing/deleted spaces to the same 404. The
  route remains closed unless the server itself can bind the authorizer to its
  configured public URL and durable OAuth runtime.

## Acceptance gates

Run the pinned matrix in both authority directions under normal, delayed,
duplicate, reordered, disconnected, and corrupted traffic. Require
convergence, full-CAR recovery after compaction, no state mutation on corrupt
inputs, bounded-memory 256 MiB CAR/blob streams, and proof that public
exports/endpoints/logs never disclose permissioned records or private-only
blobs. Pass the same clean-cache matrix on macOS and Linux before declaring
the alpha complete.
