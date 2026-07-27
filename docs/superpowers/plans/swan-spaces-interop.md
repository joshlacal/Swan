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
  grant and only a qualified `space:<type>?authority=...&skey=...&action=...`
  scope is passed to the domain policy for exact authority/skey/read/collection
  enforcement. Bare/default type scopes are rejected rather than normalized.
  The focused HTTP tests exercise SQLite-backed values, real durable OAuth
  tokens and signed DPoP proofs, narrow grants, cross-authority denial,
  foreign-repository opacity, lifecycle closure, replay, and no
  public-repository fallback.
- The local self-repository write slice now exposes the generated
  `com.atproto.space.createRecord`, `putRecord`, `deleteRecord`, and
  `applyWrites` server contracts only through the same startup-preopened
  OAuth/DPoP capability. POST bodies are bounded to 1 MiB, duplicate-key
  checked before generated-contract decoding, canonically DAG-CBOR encoded,
  and never echoed in errors. The durable transaction preserves explicit
  create/update/delete intent through revision CAS, record/LtHash/oplog/outbox
  insertion, and rejects an invalid batch without a partial write. `putRecord`
  deliberately requires both create and update grants before SQLite chooses
  its branch. Swan does not yet implement lexicon schema validation, so
  `validate: true` is explicitly rejected rather than silently ignored;
  omitted or `false` requests receive structural AT-record validation only.
- The authority-owned SimpleSpace lifecycle slice now exposes the generated
  `com.atproto.simplespace.createSpace`, `updateSpace`, `deleteSpace`,
  `addMember`, `removeMember`, and `listMembers` contracts only through the
  same startup-preopened DPoP/OAuth capability. The exact pinned OAuth
  lifecycle vocabulary is `manage=create|update|delete`, distinct from record
  `action` grants; all scoped grants bind type, authority, and skey, while a
  broad `atproto` grant remains valid for the authority account. The adapter
  never opens a database on demand, performs non-destructive configuration
  patches transactionally, allocates omitted space keys safely, has
  deterministic bounded membership pages, and maps foreign-authority access
  to the opaque `SpaceNotFound` result. `checkUserAccess`, credentials,
  notifications, service auth, remote authority delegation, and sync remain
  explicitly closed. Focused tests use durable SQLite accounts, opaque OAuth
  tokens, and signed DPoP proofs for create/update/delete scopes, owner-removal
  rejection, malformed body/query closure, deactivation, vanished preopened
  DBs, and public-route isolation. Configuration patches retain an omitted
  managing-app identifier across policy-only transitions, as the pinned
  TypeScript handler does; SQLite migration v3 rebuilds the original
  policy-coupled CHECK (plus FK children) before allowing that valid state or
  an explicit empty-string clear. Focused tests cover the old-schema upgrade,
  `manage=update` membership/list operations, DPoP replay, and an oversized
  body delivered in streaming chunks.
- The credential foundation now includes the bounded authority exchange and
  credential read XRPC routes. `DurableSpaceCredentialAuthority` evaluates the authority's
  startup-preopened SQLite `authorizeSimpleSpaceRead` policy before obtaining
  the active account signing key through `AccountKeyStore`; it emits only a
  transient ES256 `atproto-space-credential+jwt` with `#atproto_space`, a
  fresh UUID JTI, and a two-hour maximum lifetime. The verifier bounds compact
  JWT parsing, requires the exact type/algorithm/key ID and authority/space
  binding, resolves only configured local or static pinned public keys, and
  returns `AuthorizationContext.spaceCredential` only after signature and
  clock checks. Remote DID/PLC key retrieval, client metadata/JWKS attestation
  verification remains unavailable; an allow-listed app therefore fails closed
  until a signed attestation policy is implemented. A delegation exchange
  accepts only a bounded Bearer JWT with the exact proposal type/algorithm/key
  ID, local/pinned user key, exact `authority#atproto_space_host` audience,
  space subject, clock bounds, and UUID JTI before it can enter durable policy
  evaluation. The issued credential is accepted by `getRecord`/`listRecords`
  without DPoP and can read another active preopened member repository only in
  its bound space. It cannot write records. `getDelegationToken` remains
  unavailable because user-PDS account-key OAuth binding is separate work.
  Focused tests cover durable public/member policy, app and managing-app
  denial, wrong issuer/key/audience/space, expiry/tampering, replay-compatible
  fresh credential issuance, cross-repository reads, duplicate/oversized
  bodies, write rejection, and no request-time DB opening.
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
