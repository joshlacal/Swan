# Task 11 report — writer set, registration, and durable notifications

## Status

Implemented in jj change `tspqqnzl` (`feat: add durable space writer
notifications`). The report is included when the change is finalized; use
`jj log -r tspqqnzl` to resolve its current commit hash.

## Delivered

- Added a narrow `AuthorizedSpaceNotificationDirectory` contract and
  authority-account SQLite tables for writer state, notification
  registrations, receipt de-duplication, and durable recipient fanout. The
  writer state contains only repository DID, wire revision, and a 32-byte
  commitment. Registrations retain an opaque endpoint and optional repository
  filter. Neither data model admits record values, CAR bytes, credentials, or
  blob content.
- `notifyWrite` is idempotent by `(issuer, eventID)`, accepts monotonic writer
  revisions, ignores an older reordered revision after recording its receipt,
  and rejects a same-revision/different-commitment conflict atomically. A
  successful newer state update creates its recipient fanout in the same
  SQLite transaction. `notifySpaceDeleted` similarly records a durable opaque
  receipt and lifecycle fanout without applying remote operations.
- Added generated-contract Hummingbird adapters for `listRepos`,
  `registerNotify`, `notifyWrite`, and `notifySpaceDeleted`. List and
  registration require a verified scoped space credential. Write and deletion
  notifications require bounded, duplicate-free JSON plus an exact service
  JWT (`aud` and `lxm`), and all unsupported/wrong methods remain closed.
  Errors are opaque and response bodies do not echo credentials or contents.
- Added ES256/ES256K service-JWT issuance and verification with bounded compact
  JWT/JSON parsing and a durable receipt as the replay authority. The verifier
  shares strict key and clock validation with the OAuth JOSE implementation.
- Added a bounded JSON POST helper and AsyncHTTPClient transport that reuses
  the OAuth metadata SSRF policy: HTTPS except the exact lab localhost case,
  initial and post-resolution destination checks, private/link-local denial,
  redirects disabled, timeout/size bounds, and no response payload exposure.
  The transport is injected so a deployment can provide a connected-peer-aware
  implementation where the HTTP client cannot expose that peer.
- Added leased, retrying post-commit delivery workers for both the existing
  writer outbox and authority fanout. The workers commit lease state before
  invoking transport and persist bounded exponential retry state after a
  failure. Writer sends read only the current repository marker after the
  outbox lease; they never construct or send a record operation.
- Added `SwanNotificationRecoveryService`, a ServiceLifecycle service that
  starts both workers for every account database preopened at startup. It must
  be supplied explicit authority/registration destination maps, service JWT
  issuer, and hardened POST transport; untrusted registered endpoint text is
  never used directly as a destination or JWT audience.

## Tests

- `SpaceNotificationSQLiteTests.testWriterNotificationsAreIdempotentMonotonicAndNeverCarryValues`
  covers duplicate and reordered write delivery, monotonic state, same-TID
  commitment conflict, one fanout row, and no record-value representation.
- `SpaceNotificationSQLiteTests.testFanoutWorkerRetriesOutsideTransactionsAndRecoversLease`
  proves a failed leased delivery retries, the transport observes no active
  write transaction, and a persisted lease is reclaimable for recovery.
- `SpaceNotificationSQLiteTests.testRegistrationReplacementAndDeletionCreateOnlyOpaqueFanout`
  verifies replacement wins by endpoint key and deletion fanout has no
  repository/revision/commitment/content fields.
- `SpaceNotificationHTTPTests` exercises real signed credential gating for
  list/registration, exact service-auth metadata for writes, duplicate JSON
  rejection, missing credential denial, wrong-method closure, and no
  credential/record leakage in output.
- `SwanOAuthTests.testBoundedJSONPosterRejectsPrivateDNSAndRebinding` proves
  private initial DNS resolution and a changed private post-resolution address
  are rejected before an unsafe delivery completes.

## Verification

All commands ran from
`/Users/joshlacalamito/Developer/Catbird+Petrel/Swan`.

| Command | Result |
| --- | --- |
| `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test --filter SpaceNotificationSQLiteTests` | PASS — 3 focused durability/order/retry/no-leakage tests. |
| `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test --filter SpaceNotificationHTTPTests` | PASS — generated-route credential and service-auth boundary tests. |
| `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test --filter SwanOAuthTests.testBoundedJSONPosterRejectsPrivateDNSAndRebinding` | PASS — post transport SSRF/DNS-rebinding test. |
| `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test` | PASS — complete Swift package suite; optional 256 MiB CAR/blob stress tests skipped because their explicit environment flags were not set. |
| `swift run swan verify --reference-directory .interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354` | PASS — `PROFILE OK: permissioned-data-0016-2026-07-03`. |
| `git diff --check` | PASS. |

The expected local Petrel `libsecret-1` pkg-config warning remains non-fatal.

## Remaining executable integration gap

`SwanNotificationRecoveryService` is fully configurable and performs startup
recovery when added to a `ServiceGroup`, but the current `swan serve` command
does **not** construct that service, parse notification transport/destination
configuration, or append it to its service list. Consequently, the reusable
worker implementation is present but the executable does not yet start
background delivery/recovery. This is a required follow-up before claiming
the alpha's startup recovery/background delivery acceptance gate. The omission
is intentional in this change: enabling outbound delivery with implicit or
unconfigured destinations/audiences would be unsafe.

## Boundary retained

This task does not apply remote operations, persist operation values/CARs in
notification state, configure `swan serve` outbound transports, or claim a
Docker/reference-host interoperability matrix. The last two require explicit
operator configuration and a Compose environment respectively.
