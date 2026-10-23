# Apple TV PDS ledger

Swan running as the compute node on an Apple TV inside a tvOS packet tunnel
extension, with all authoritative state on an OpenWrt-attached USB disk.
Start with `ARCHITECTURE.md`, then `DECISION_LOG.md` (open questions at the
bottom).

| File | Content |
|---|---|
| `ARCHITECTURE.md` | topology, storage seam decision, milestone status |
| `DECISION_LOG.md` | decisions with rationale; batched questions with defaults |
| `STORAGE_MODEL.md` | state inventory/classification, vault protocol, proof, backup |
| `TRANSACTION_MODEL.md` | what must be atomic, forbidden states, barrier, restore |
| `TVOS_LIFECYCLE.md` | documented facts vs unknowns, probe design, hardware matrix |
| `NETWORKING.md` | LAN vs overlay vs vault paths, WireGuard options, ingress |
| `SECURITY.md` | threat model, secrets placement |
| `RESOURCE_PROFILE.md` | macOS baseline numbers, tvOS compile survey, measurement plan |
| `FAILURE_TESTS.md` | injection plan and results |
| `QUALIFICATION.md` | P0–P10 ladder mapped to Swan routes |

Executables:

* `Swan/AppleTV/SwanTV/` — tvOS app + `SwanTunnel` packet tunnel extension (probes T0–T2).
* `Swan/AppleTV/swan-vault/` — Rust storage daemon; `cargo build --release`;
  `python3 tests/wal_ship_selftest.py` is the end-to-end durability proof.
