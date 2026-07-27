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
- `PETREL_GENERATOR_ROOT=/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel-swan-generator ./Scripts/verify-wire-generation.sh` reached verified source/checksum and generated-file inventory checks, then failed its existing `generated output lacks required ServerHandler contracts` gate. The checked-in wire contract used by this task does contain `ComAtprotoSpaceListSpaces.ServerHandler`; no generated source was changed in Task 24.

Docker and Linux were not run or claimed.
