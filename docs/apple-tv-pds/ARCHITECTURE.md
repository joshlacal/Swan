# SwanTV: Swan PDS on Apple TV, durable state on OpenWrt

Cold-reader summary. Swan is our Swift AT Protocol PDS (`Swan/`). This
experiment runs Swan's real HTTP/XRPC/repo/OAuth logic on an Apple TV 4K
inside a tvOS Network Extension (a "packet tunnel provider", the only kind of
long-lived background process tvOS gives third parties), while every byte of
authoritative state lives on a USB disk attached to an OpenWrt router on the
same LAN. The Apple TV is the compute node; the router is a dumb, boring,
authenticated storage appliance (`swan-vault`). Local Apple TV storage is a
cache that tvOS may purge at any time, and the design treats it that way.

Governing documents: this file (design), `DECISION_LOG.md` (why), the rest of
this directory (evidence per lane). Evidence labels used throughout:
PROVEN (reproducible test in repo) / OBSERVED (seen once on real hardware or
tooling) / DOCUMENTED (Apple/vendor docs) / INFERRED / UNKNOWN / BLOCKED.

## Target topology

```
                 Internet / tailnet
                        │
          swan-netcup VPS (public HTTPS, reverse proxy)      ← M7
                        │ WireGuard / Tailscale
        ┌───────────────▼────────────────┐
        │ Apple TV 4K (AppleTV6,2, 3 GB) │
        │ tvOS 26.6                       │
        │  SwanTV.app  (config UI only)   │
        │  SwanTunnel.appex               │
        │    ├ WireGuard peer (M2)        │  overlay IP 10.77.0.2 (probe) / tailnet IP
        │    ├ Swan runtime (M4+)         │  Hummingbird HTTP on :8080
        │    ├ SQLite (cache copy)        │  control / <did> / firehose .sqlite
        │    └ WAL shipper + object client│  synchronous durability barrier
        └───────────────┬────────────────┘
                        │ LAN (Ethernet), HTTP + bearer PSK,
                        │ inside the router-terminated WireGuard tunnel once M2 lands
        ┌───────────────▼────────────────┐
        │ OpenWrt router + USB disk       │
        │  swan-vault (Rust, ~500 KB)     │  /srv/swan-vault/{db,objects}
        │  WireGuard hub (kernel)         │
        │  backups (cron, rsync/tar)      │
        └────────────────────────────────┘
```

## What runs where

| Concern | Apple TV (extension) | OpenWrt | Notes |
|---|---|---|---|
| XRPC/OAuth/repo/MST/signing/sequencing | yes | no | unchanged Swan modules |
| SQLite query execution | yes (local cache file) | no | SQLiteNIO vendors SQLite; builds for tvOS ≥13 (`sqlite-nio/Package.swift`) |
| Durable truth for SQLite | no | yes | snapshot + ordered WAL segments per database |
| Blobs, key envelopes | cache | yes | immutable content-addressed objects |
| Master KEK / operator secrets | bootstrap secret only | never | see `SECURITY.md` |
| Public ingress | via overlay | optional WG hub | `NETWORKING.md` |
| Backups | none | yes | `STORAGE_MODEL.md` |

## Storage seam decision (the load-bearing choice)

Swan's storage layer is ~60 fine-grained protocols in `SwanStorage`
(`grep '^public protocol' Sources/SwanStorage`), all implemented by three
SQLite actors (`SQLiteControlDatabase`, `SQLiteAccountDatabase`,
`SQLiteFirehoseDatabase`). Re-implementing those over HTTP (option A/C at the
protocol level) means rewriting SwanSQLite. Instead the seam is placed
*underneath SQLite*:

* Swan keeps executing SQL against local SQLite files exactly as today.
* Each SQLite actor already funnels every write through one
  `transaction { BEGIN IMMEDIATE … COMMIT }` helper
  (`OAuthControlStore.swift:1720`, `SwanSQLite.swift:10786`,
  `SQLiteFirehoseDatabase.swift:807`). A durability barrier inserted after
  `COMMIT` in those three helpers ships the transaction's WAL frames to
  `swan-vault` and waits for its fsync before returning to Swan, so no XRPC
  response can be sent before the write is durable off-device.
* `wal_autocheckpoint=0`; checkpoints happen only after the vault has
  acknowledged every frame. A WAL reset (new salt after `TRUNCATE`) is a
  first-class event in the vault protocol.
* Blob bytes (`BlobStore`/`StreamingBlobStore`, 5 methods) and key envelopes
  (`FileAccountKeyStore` under `keys/`) go to the vault as content-addressed
  objects *before* the SQLite row that references them commits.
* Cold start on an Apple TV whose cache was purged: download snapshot +
  segments per database, rebuild the local files, then serve.

This is the Litestream model, made synchronous. It keeps OpenWrt schema-blind
and keeps 100% of PDS logic on the Apple TV. It is PROVEN end to end on macOS
twice: against raw SQLite (`AppleTV/swan-vault/tests/wal_ship_selftest.py`)
and through Swan's own `SQLiteControlDatabase` with the barrier installed
(`swift test --filter SwanDurableStoreTests`). Details in `STORAGE_MODEL.md`.

Rejected alternatives are recorded in `DECISION_LOG.md` (D-002).

## Milestones and current status

| Milestone | Status | Evidence |
|---|---|---|
| M0 architecture characterized | done except hardware unknowns | this ledger; open questions in `DECISION_LOG.md` |
| M1 persistent hello world (extension serves HTTP while app suspended) | BLOCKED on hardware pairing (Q-1) | `AppleTV/SwanTV` builds for the tvOS SDK; NE entitlement provisioned; needs the Apple TV paired to Xcode |
| M2 tunnel-accessible server | not started (D-005) | `NETWORKING.md` |
| M3 remote durable state (write, kill, recover) | **PROVEN on macOS** end to end through Swan's own `SQLiteControlDatabase`; tvOS run pending M1 | `wal_ship_selftest.py`; `swift test --filter SwanDurableStoreTests` |
| M4 Swan `/health` from Apple TV | Swan server stack **compiles for arm64-apple-tvos** (Petrel guard patch + libsodium link still to vendor); not yet run | `RESOURCE_PROFILE.md` |
| M5–M9 | not started | |

## Repository layout for this experiment

```
Swan/AppleTV/SwanTV/          tvOS app + SwanTunnel packet tunnel extension (probes T0–T2)
Swan/AppleTV/swan-vault/      Rust storage daemon for OpenWrt + end-to-end proof
Swan/docs/apple-tv-pds/       this ledger
```
`Swan/Sources` changes so far: one additive `Package.swift` platform line, the
opt-in `installCommitBarrier(_:)` hook on the three SQLite actors (default
`nil`, behaviour unchanged), and the new `SwanDurableStore` target.
`swan serve` on macOS/Linux is unaffected.
