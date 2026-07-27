# Task 11 report — writer set, registration, and durable notifications

## Status

Implemented in jj change `tspqqnzl` (`feat: add durable space writer
notifications`). The report is included when the change is finalized; use
`jj log -r tspqqnzl` to resolve its current commit hash.

## Review repair

- `swan serve --notification-config <file>` now loads explicit
  operator-pinned space-credential and service-JWT public keys and validates
  declared authority/registration endpoint, audience, and final-peer facts.
  Only with that configuration are the four notification receiver routes
  installed. The key file contains public verification material only.
- `--enable-notification-delivery` currently exits before serving. The bundled
  AsyncHTTPClient POST adapter cannot observe the final connected peer and is
  explicitly unavailable as a notification transport; it must not be used to
  start the recovery worker. A hosting application may construct
  `SwanNotificationRecoveryService` with an injected peer-reporting transport,
  but live executable egress remains a required follow-up gate.
- Direct writer-to-authority notifications use `iss == repo` and
  `aud == space.authority`. Authority-to-recipient fanout uses
  `iss == space.authority`, retains the original writer in `repo`, and has the
  explicit configured recipient service DID as `aud`. A recipient that does
  not host the authority (or the named account) returns a successful no-op and
  never applies a remote operation, matching the pinned branch's intended
  best-effort behavior.
- A verified deletion now atomically stores a per-recipient tombstone and
  removes stale local writer outbox rows. Local repository apply, state,
  record, CAR, oplog, and private-blob entry points fail closed on that
  tombstone. Unknown/non-hosted recipients remain successful no-ops.

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
  Notification delivery additionally requires a non-nil final connected peer
  that occurs in both the pre-request and post-request approved DNS answer
  sets. The bundled AsyncHTTPClient adapter cannot provide that evidence and
  fails before it emits a notification request; it is not a notification
  delivery transport.
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
  private initial DNS resolution, a changed private post-resolution address,
  a final peer absent from the re-resolved set, and a nil final peer are all
  rejected.
- `SpaceNotificationHTTPTests` covers direct member-writer announcement,
  authority-signed fanout for a different writer, unknown-recipient write and
  deletion no-ops, strict route/auth closure, and no output leakage.
- `SpaceNotificationHTTPTests.testNotificationRecoveryServiceDrainsCommittedWriterAndAuthorityQueues`
  starts the real structured recovery service over committed writer-outbox and
  authority-fanout rows, proves both queues drain, and cancels the service.
- `SpaceNotificationSQLiteTests.testRecipientDeletionDurablyClosesLocalRepositoryAndClearsStaleOutbox`
  proves duplicate deletion is idempotent, clears committed stale outbox work,
  and closes subsequent local state reads and writes.

## Verification

All commands ran from
`/Users/joshlacalamito/Developer/Catbird+Petrel/Swan`.

| Command | Result |
| --- | --- |
| `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test --filter SpaceNotificationSQLiteTests` | PASS — 3 focused durability/order/retry/no-leakage tests. |
| `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test --filter SpaceNotificationHTTPTests` | PASS — generated-route credential and service-auth boundary tests. |
| `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test --filter SwanOAuthTests.testBoundedJSONPosterRejectsPrivateDNSAndRebinding` | PASS — post transport SSRF/DNS-rebinding test. |
| `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift build --target swan` | PASS — notification configuration-gated executable build. |
| `swift run swan serve --help` | PASS — exposes `--notification-config` and the intentionally unavailable `--enable-notification-delivery` gate. |
| `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test --filter SpaceNotificationHTTPTests` | PASS — direct/fanout/no-op HTTP contract and startup recovery service drain. |
| `CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib swift test` | PASS — complete Swift package suite; optional 256 MiB CAR/blob stress tests skipped because their explicit environment flags were not set. |
| `swift run swan verify --reference-directory .interop-cache/atproto-3f6c96d5d2d25438bd40fa89d6ecc37865f8e354` | PASS — `PROFILE OK: permissioned-data-0016-2026-07-03`. |
| `git diff --check` | PASS. |

The expected local Petrel `libsecret-1` pkg-config warning remains non-fatal.

## Remaining executable integration gate

`SwanNotificationRecoveryService` is fully configurable and tested with
injected transports, but the stock `swan serve` does **not** register it yet.
Its prior AsyncHTTPClient POST adapter could not report a final peer, so using
it would make a DNS-rebinding check advisory after network I/O. The repair
makes that adapter fail before a notification request and makes
`--enable-notification-delivery` a startup error. A concrete connector that
reports/pins the actual peer and feeds it through `OAuthBoundedJSONPoster` is
required before the executable may claim live cross-host delivery or attach
the background recovery service.

## Boundary retained

This task does not apply remote operations, persist operation values/CARs in
notification state, enable unverified outbound transport in `swan serve`, or
claim a Docker/reference-host interoperability matrix. A peer-verifying
connector and Compose environment remain separate requirements.
