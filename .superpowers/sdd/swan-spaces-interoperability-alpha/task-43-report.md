# Task 43 — durable public repository read/sync HTTP report

Status: COMPLETE

## Delivered

- Installed production implementations for the six non-blob public read/sync
  methods:
  `describeRepo`, `getRecord`, `listRecords`, `getLatestCommit`, `getRepo`,
  and `getRepoStatus`.
- Added a narrow public-only storage projection and implemented it through the
  startup-preopened `SQLitePreMigratedAccountDirectory`. Request-time reads
  never open, create, migrate, repair, or remotely resolve an account
  database.
- Restricted repository truth to the durable public state, block, and record
  index tables plus non-secret account lifecycle/handle metadata.
- Added exact record CID matching, direct DAG-CBOR-to-AT-data-model decoding
  (including links, bytes, safe integer bounds, and nested values), strict
  canonical record validation, and pinned TypeScript pagination semantics:
  descending/`< cursor` by default, ascending/`> cursor` for `reverse=true`,
  with the last returned rkey as cursor.
- Added exact active/inactive lifecycle mapping and malformed wire parameter
  mapping. Public `repo.*` selectors accept canonical hosted DIDs or handles;
  pinned `sync.*` selectors remain DID-only.
- `describeRepo` now authenticates the complete submitted PLC genesis journal
  through `PLCOperationCodec`, binds its CID to the submitted control intent,
  current key references, and public genesis commitment, and emits the pinned
  PLC DID-document shape (ECDSA 2019 verification method, alias, and durable
  PDS service). Handle correctness is computed; configured/durable service
  origin mismatch fails closed.
- Replaced the materializing/double-validation `getRepo` path with a
  SQLite-TEMP-backed BFS. Node work, duplicate detection, bounds/layers,
  node/record encounter order, record expectations, and the reconstructed
  index are externalized inside the repository snapshot; only one decoded
  node or record body is resident. CAR order remains commit, breadth-first MST
  nodes, then first-seen record blocks.
- Added descriptor-backed, owner-only, unlinked public CAR spooling,
  64-KiB-bounded HTTP response writes, and process-wide/per-account spool
  admission reserved before file creation. Cleanup, cancellation, abandoned
  responses, and preparation failures release leases idempotently.
- Wired the preopened directory into the production `swan serve` composition.
  Public mutation and blob routes remain finite and unavailable.

## Isolation and failure evidence

- A real account database contains a permissioned record at the same
  collection/rkey as a public record plus a private-only record. Public
  record/list/CAR reads return only public bytes and CIDs.
- Bearer and DPoP headers do not alter public output.
- Removed and symlink-replaced account database paths, lifecycle transitions,
  unknown lifecycle values, closed directories, corrupt/forged projections,
  and CAR cancellation all fail closed without opening an outside target or
  retaining a spool.
- Tampered PLC signatures, DIDs, aliases, service facts, intent CIDs, and
  public index rows fail closed; simultaneous slow consumers are rejected by
  the configured spool budget and admitted after cleanup.
- The production runtime composition test proves the six public routes are
  live while public mutations and blobs remain unavailable.
- The HTTP `getRepo` response round-trips through the strict Task 40 importer
  using the pinned TypeScript non-empty public repository CAR.

## Verification

- Focused `PublicRepositoryReadHTTPTests`: 8 passed, 0 failures.
- Focused `PublicRepositoryReadDirectoryTests`: 7 passed, 1 opt-in skip,
  0 failures.
- Direct record-decoder and PLC genesis-verifier gates: 2 passed, 0 failures.
- Opt-in real 256-MiB production-directory-to-HTTP gate:
  `SWAN_RUN_256MIB_PUBLIC_GET_REPO=1`, 1 passed in 9.865 seconds. It built 300
  unique ~900-KiB records, continuously sampled current RSS through
  preparation and HTTP-body drain, enforced a <128-MiB peak delta, and
  enforced <=64-KiB HTTP writes without body aggregation.
- Production runtime public-route composition: 1 passed, 0 failures.
- Complete `SwanPublicRepositoryTests`: 99 passed, 0 failures.
- Complete `SwanSQLiteTests`: 99 executed, 2 skipped, 0 failures.
- Complete `SwanHTTPTests`: 107 passed, 0 failures.
- `Scripts/verify-profile.sh`: profile lexicons verified.
- Pinned Node public CAR verifier:
  `REFERENCE PUBLIC REPOSITORY CAR OK`.
- `git diff --check`: passed.

## Retained boundary

The durable PLC projection presently records only the authenticated submitted
genesis operation. If current account key references no longer match that
projection (for example after rotation), public identity reads fail closed.
Swan must not synthesize a rotated DID document; a later task must add durable
authenticated PLC rotation history before rotated identity can be served.

This task does not implement or claim public repository mutation, public blob
read/upload, relay/firehose completeness, Docker/Linux verification, or full
Swan alpha completion. Those surfaces remain deferred and fail closed.
