# Swan architecture

Swan is a Swift-native permissioned-data interoperability laboratory. It is a
standalone package and jj repository; it does not modify or depend on Catbird
runtime state.

- `SwanCore` owns immutable profile validation, identifiers, typed errors, and
  safe logging.
- `SwanSpaces` owns URI parsing, LtHash, commit construction, policy decisions,
  per-`(account, space)` in-memory coordination, and later CAR/sync code.
- `SwanStorage` defines domain-oriented stores and blob/outbox boundaries.
- `SwanSQLite` is the durable account/control store. Account truth stays in
  account-local WAL databases; `control.sqlite` is control plane only.
- `SwanAccounts` and `SwanOAuth` own keys, account state, OAuth tokens, and
  remote metadata policy. They must not leak secrets to database logs or
  fixtures.
- `SwanHTTP` constructs all Hummingbird routes before creating the application.
  It is the only XRPC/OAuth adapter; domain modules do not accept HTTP types.

Actors coordinate in-process ordering and caches. SQLite constraints,
transactions, revision/CID compare-and-swap, and an atomic oplog/outbox write
are the durable correctness boundary. Network I/O is never performed while a
database transaction is open.

## Public/private split

Public repository records and permissioned records live in separate account
tables and reference namespaces. A content-addressed blob is public only while
it has a public reference; the presence of a space reference never enables a
public blob response. Public endpoints must not call a permissioned repository
method and permissioned routing never falls through to public routing.
