# Decision log

Format: id, date, decision, rationale, status (overridable-before-merge unless
noted), evidence. Open questions for Josh at the bottom with defaults.

## Decisions

**D-001 (2026-09-04) — Ledger and experimental code live in `Swan/`.**
`Swan/docs/apple-tv-pds/`, `Swan/AppleTV/SwanTV/` (tvOS app + extension),
`Swan/AppleTV/swan-vault/` (Rust daemon). Nothing under `Swan/Sources` changed
except one additive line in `Package.swift` (`.tvOS(.v18)` platform).
Rationale: the mission is Swan-on-tvOS; keeping probes beside the server keeps
the pin/version story in one repo. Overridable: could become its own repo.

**D-002 (2026-09-04) — Durability seam is *below* SQLite (synchronous WAL
shipping + content-addressed objects), not a re-implementation of Swan's
storage protocols.**
Rationale: SwanStorage has ~60 protocols implemented by three SQLite actors;
re-implementing them over HTTP is a rewrite of `SwanSQLite`. Each actor has a
single `transaction {}` helper, so a post-COMMIT barrier is a three-site
change. Vault stays schema-blind ("boring"). Alternatives rejected:
(A-protocol) HTTP implementations of SwanStorage protocols — too large, chatty
per-block reads; (B) PostgreSQL on OpenWrt — Swan is SQLite-only SQL and it
turns the router into the DB server; (SQLite on SMB/NFS) — forbidden by the
mission; (remote VFS) — custom SQLite VFS over HTTP is more code and slower
than shipping WAL frames. Evidence: PROVEN by `wal_ship_selftest.py`. Status:
adopted for M3; revisit only if the barrier latency on real hardware exceeds
client tolerance.

**D-003 (2026-09-04) — Vault daemon in Rust with `tiny_http`, one global lock,
JSON manifests with atomic rename, no embedded database.**
Rationale: 505 KB static-ish binary, no async runtime, a single-user PDS
commits a few times a second; manifests are tiny and rename+fsync is the
boring transactional primitive. Marked `ponytail:` in source with the upgrade
path (per-db locks). Overridable.

**D-004 (2026-09-04) — No TLS in the vault for now; PSK bearer over LAN, and
after M2 the vault binds to the WireGuard interface only.**
Rationale: the extension must run a genuine tunnel anyway; letting it
terminate at the router encrypts vault traffic on the wire without a second
crypto stack in a 500 KB daemon. Until M2, vault traffic is LAN-only and the
PSK will be rotated when M2 lands. Overridable: add rustls if M2 slips.

**D-005 (2026-09-04, deferred) — WireGuard implementation for M2.**
Default: boringtun via the monorepo's existing Rust→Swift toolchain
(`aarch64-apple-tvos`, tier 3, nightly + `-Zbuild-std`). Fallback:
wireguard-go/WireGuardKit (MIT) with a tvOS cross-build of the Go bridge.
Not needed for M1/M3/M4, so not decided. See `NETWORKING.md`.

**D-006 (2026-09-04) — The probe extension's placeholder tunnel
(10.77.0.0/24, packets counted and dropped) is research-only.**
It exists to measure lifetime/memory/listener reachability on hardware and is
labelled as such in `PacketTunnelProvider.swift`. It is replaced by the
WireGuard peer at M2 and must never ship. Not overridable (mission rule).

**D-007 (2026-09-04) — Petrel tvOS support is a guard-widening patch in
Petrel, applied to the local checkout; Swan's pin is bumped only after it is
pushed.**
Files: `Petrel/Package.swift` (+`.tvOS(.v18)`), `KeychainManager.swift`,
`AppleKeychainStore.swift`, `SecurityCompat.swift`, `ImageMetadataStripper.swift`
(`os(iOS) || os(macOS)` → `… || os(tvOS)`; iOS keychain branches → iOS or tvOS).
Note: the Petrel working copy also carries unrelated in-progress work
(`NetworkService.swift`, `HTTPErrorResponseTests.swift`); commit the tvOS
files path-restricted. Evidence: `Petrel-Package` builds for tvOS; `SwanHTTP`
builds for tvOS against pinned Petrel + patch.

**D-008 (2026-09-04) — P0 is `GET /health` + `describeServer`, not
`/xrpc/_health`.** Swan has no `_health` route (404 observed). Alias is a
one-liner if a client needs it. Overridable.

**D-009 (2026-09-04) — Team ID for signing is `44U2ZPNQPK`** (Catbird's), not
the `Z4RMCC749F` shown in the local signing identity's OU; xcodebuild reported
"No Account for Team Z4RMCC749F". Bundle IDs `blue.catbird.SwanTV`,
`blue.catbird.SwanTV.SwanTunnel`, App Group `group.blue.catbird.SwanTV`.

## Open questions (batched; each has a default so work continues)

**Q-1 Pair the Apple TV with Xcode.** Blocks M1 entirely. Apple TV
("Family Room", AppleTV6,2, tvOS 26.6) → Settings → Remotes and Devices →
Remote App and Devices; Mac → Xcode → Window → Devices and Simulators → pair
with the code on screen. After that: `xcodebuild -project
Swan/AppleTV/SwanTV/SwanTV.xcodeproj -scheme SwanTV -destination
'platform=tvOS,name=Family Room' -allowProvisioningUpdates build` will
register the device and mint profiles. Default if unanswered: everything
hardware-bound stays BLOCKED; storage and Swan-side work continue.

**Q-2 OpenWrt router: SSH access + architecture.** `ssh root@192.168.1.1`
refuses publickey; need Josh's key installed or a password. Need `uname -m`
and `cat /etc/openwrt_release` to pick the Rust target
(`aarch64-unknown-linux-musl` default; `mipsel-unknown-linux-musl` /
`armv7-unknown-linux-musleabihf` otherwise) and confirm `kmod-usb-storage`,
`block-mount`, `wireguard-tools` availability. Default: build `aarch64` musl
first; if the router is MIPS the daemon still builds (no arch-specific code).

**Q-3 USB disk.** Which disk/filesystem (ext4 recommended over exFAT for
fsync semantics)? Default: ext4, mounted at `/mnt/swan`, vault root
`/mnt/swan/vault`.

**Q-4 Public origin for M7.** Reuse `swan-netcup` (already on the tailnet)
as TLS terminator, hostname TBD. Default: yes, `swan-netcup`, hostname chosen
at M7.

**Q-5 Identity method for the test account.** `did:web` under the public
origin vs PLC via Swan's management provisioning. Default: did:web for
M5/M6 (no external dependency), PLC for M7 if federation needs it.
