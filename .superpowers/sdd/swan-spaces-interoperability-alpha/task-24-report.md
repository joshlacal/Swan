# Task 24 — authenticated local `com.atproto.space.listSpaces`

## Implementation

- Added the value-free `AuthorizedHostedSpaceDirectory` projection with typed
  query/page DTOs. It returns only `SpaceURI`, `isOwner`, and final cursor;
  it has no record, CID, blob, policy, member, or account-inventory escape
  hatch.
- `SQLitePreMigratedAccountDirectory` selects only the authenticated active
  subject's startup-preopened account database and repeats active, shutdown,
  and regular-path checks. `SQLiteAccountDatabase.hostedSpaceURIs` uses a
  bounded `UNION` over live local authority rows and local repository-state
  rows. It reads only `space_uri`, applies SQL candidate filters/limit and
  then canonical `SpaceURI` validation plus lexical cursor paging. Deleted
  authority rows, recipient tombstones, and
  `missing-authority-policy-v1` closures are excluded before projection.
- Added `PermissionedSpaceScopeSyntax.permitsAggregateSpaceList`: `atproto`
  permits the request; a narrow grant must be exactly `action=read`,
  `skey=*`, and cover the requested type/authority dimensions. Omitting a
  request dimension requires a literal wildcard grant, so the route never
  obtains a broad result and filters it after authorization.
- Added the fixed-target DPoP/OAuth-only `SwanAuthenticatedSpaceListCapability`
  and generated `ComAtprotoSpaceListSpaces.ServerHandler` route. It rejects
  Bearer space credentials by using only the established DPoP resource
  authorizer. Strict query parsing rejects unknown/duplicate keys, malformed
  type/DID/cursor, foreign filtered cursors, and non-`1...100` limits.
- The generated `SpaceView` generic encoder injects `$type`, while this query
  declares a plain JSON object. The private route adapter preserves the exact
  generated handler input/output types and emits only the pinned public
  fields: `cursor`, `spaces[].uri`, and `spaces[].isOwner`.

## Focused coverage

`SpaceListHTTPTests` covers owner visibility without repository state, remote
member visibility only after local repository state, sorting/paging, type and
authority filters, strict query failures, aggregate scope allow/deny, DPoP
route binding through the existing fixed-target authorizer, Bearer rejection,
wrong method closure, and absence of record/CID/blob/policy/member/value
fields in success JSON.

## Verification

- `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test --filter SpaceListHTTPTests` — passed (2 tests).
- `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test --filter SwanSQLiteTests` — passed (70 tests; one existing opt-in 256 MiB blob stress test skipped).
- `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test` — passed (two existing opt-in 256 MiB stress tests skipped).
- `./Scripts/verify-profile.sh` — passed.
- `./Scripts/verify-interop-lab.sh` — passed static cache/topology invariants.
- The isolated workspace's relative cache location does not satisfy the wire
  verifier. The same read-only verifier succeeds from the canonical Swan
  checkout, where the pinned cache is available.

Docker and Linux were not run or claimed.

## Review repair

- The local-authority branch of `hostedSpaceURIs` now binds
  `permissioned_simple_space_authorities.owner_did` to the opened account.
  Rows marked as local authority must also have a `SpaceURI.authority` equal
  to that account DID; malformed or stale cross-account authority rows fail
  closed instead of exposing a foreign authority-owned space.
- The HTTP coverage now proves that a remote space is absent until this PDS
  persists its own repository state. It also checks DPoP proof absence,
  replay, and wrong fixed target; and checks the profile's closed response
  when the list capability is not provisioned.
- Independent storage-projection coverage proves de-duplication, deleted
  authority exclusion, recipient-tombstone exclusion, and the
  `missing-authority-policy-v1` restored-repository closure.

### Repair verification

- `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test --filter SpaceListHTTPTests` — passed (4 tests).
- `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test --filter SwanSQLiteTests` — passed.
- `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test` — passed (the two existing opt-in 256 MiB stress tests skipped).
- From the canonical Swan checkout: `./Scripts/verify-profile.sh`,
  `./Scripts/verify-interop-lab.sh`, and
  `PETREL_GENERATOR_ROOT=/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel-swan-generator ./Scripts/verify-wire-generation.sh` — passed.
