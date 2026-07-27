# Task 8 report — authenticated incremental repository sync reads

## Commit

- `185633ce59e916fd55595793beaf358b5f2d1eb5` —
  `feat(sync): add authenticated repository sync reads`
- `f53f95e96242805fc54e536abdc82c516a781d77` —
  `fix(sync): preserve shared-TID oplog batches`

## Delivered

- Registered generated async `ServerHandler` implementations for the pinned
  `com.atproto.space.getLatestCommit` and
  `com.atproto.space.listRepoOps` queries. They are opt-in capabilities: the
  ordinary profile route remains the existing no-store closed response unless
  a startup-preopened repository directory, OAuth runtime, and narrow
  account-key commit signer are all configured.
- Added domain-shaped preopened-storage projections for a repository's
  current LtHash commitment/revision and for an ordered wire-TID oplog page.
  The SQLite read path uses a stable read transaction, preserves
  `(revision, operation_index)` ordering, joins values only to matching live
  records, and returns a distinct retention-gap outcome without a snapshot.
  It never opens or migrates an account database on a request.
- Added `LocalAccountSpaceRepositoryCommitSigner`, a fixed-purpose
  `AccountKeyStore` capability that obtains only the active repository
  account's encrypted P-256 signing scalar immediately before creating a
  fresh reader-bound proposal-0016 commit envelope. It does not expose raw
  signing, key material, database handles, or a caller-chosen payload.
- Preserved the strict authorization split: exact `Bearer` credentials are
  verified only as space credentials and can read a credential-authorized
  foreign repository; `DPoP` remains exact OAuth/DPoP authorization and can
  read only the token subject's own repository. Foreign OAuth receives the
  opaque `SpaceNotFound` closure. Collection-scoped grants cannot access an
  aggregate repository sync read.
- Enforced strict singleton query parsing, a 1...1000 `limit` (default 100),
  fixed GET DPoP targets, no-store JSON errors, explicit nullable `cid` and
  `prev` JSON fields, fresh commits only on caught-up pages, and closed
  wrong-method/default routing. A retention gap returns an opaque 409
  `full_repo_recovery_required` response with no values.
- Validated all emitted revisions, collections, rkeys, CIDs, action/CID
  shapes, current record CID bindings, and DAG-CBOR values. Corrupt durable
  projections fail as generic unavailable responses without record bytes.
- Review repair: `since` is a revision-only cursor, so a direct SQL row limit
  could split an atomic multi-operation TID and make its remaining operations
  permanently unreachable after the client advanced `since`. The SQLite
  projection now uses `limit` to select its terminal revision, then extends
  that page through the entire revision batch. A page can therefore exceed
  `limit` only by the terminal batch; this is the documented, conservative
  compatibility behavior that preserves convergence. Such an overfull page
  omits the commit and the following empty page at that TID returns the fresh
  head commit, matching the existing caught-up handshake.

## Files changed

- `Sources/SwanStorage/AuthorizedSimpleSpaceDirectory.swift`
- `Sources/SwanSQLite/SwanSQLite.swift`
- `Sources/SwanSQLite/SQLitePreMigratedAccountDirectory.swift`
- `Sources/SwanOAuth/SpaceRepositoryCommitSigner.swift`
- `Sources/SwanHTTP/SwanHTTP.swift`
- `Sources/SwanHTTP/SwanSpaceRepositorySyncXRPC.swift`
- `Sources/SwanHTTP/SwanSpaceXRPC.swift`
- `Tests/SwanHTTPTests/RepositorySyncHTTPTests.swift`

## Verification

All commands ran from `/Users/joshlacalamito/Developer/Catbird+Petrel/Swan`.

| Command | Result |
| --- | --- |
| `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test --filter RepositorySyncHTTPTests` | PASS — 4 focused durable SQLite + OAuth/DPoP + encrypted-key HTTP tests. |
| `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test` | PASS — complete Swift package suite; 51 HTTP tests and all other package targets passed. |
| `Scripts/verify-profile.sh` | PASS — every pinned permissioned lexicon, including both sync endpoint lexicons, verified. |
| `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift run swan verify --profile Profiles/permissioned-data-0016-2026-07-03.json --source-root .` | PASS — `PROFILE OK` for the checked-in offline artifacts. |
| `git diff --check` | PASS before commit. |

The shared-TID repair additionally exercised a `limit=4` page whose terminal
revision contains two atomic writes: it returns all five eligible operations,
including both terminal siblings; a subsequent request with that TID returns
zero operations plus a verifiable fresh commit.

The expected local Petrel `libsecret-1` pkg-config warning and macOS
libsodium deployment-target linker warning remained non-fatal.

## Boundary retained

This bounded task does not implement `getRepo` or any full-CAR recovery
transfer, CAR/blob HTTP streaming, writer registration, notifications,
remote repository operation application, or cross-host synchronization.
The retention-gap response intentionally directs the caller to the later
`getRepo` recovery surface rather than manufacturing an incremental page.
