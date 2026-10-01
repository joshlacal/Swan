# Failure injection plan and results

Invariants checked after every injected fault:

1. `getLatestCommit` rev/CID equals the last **acknowledged** write.
2. Firehose `seq` contains no event whose repo transaction is absent.
3. Every block referenced from the head is present (`sync.getRepo` CAR
   verifies with Petrel's reader).
4. No client received 2xx for a write that is not in the vault
   (`GET /v1/db/<did>/manifest` segment count vs client log).
5. Service recovers without manual repair, or the manual step is documented.

## Storage-layer faults (runnable now, macOS)

`AppleTV/swan-vault/tests/wal_ship_selftest.py` already covers: stale
generation, corrupted segment replay, idempotent replay, daemon restart.
Passed 2026-09-04 (see STORAGE_MODEL.md).

To add before M8 (each a few lines in the same script):

| Fault | Injection | Expected |
|---|---|---|
| Vault returns 500 mid-run | `--fault-every N` flag in daemon (test-only) | shipper retries; local WAL retains frames; no gap in seq |
| Delayed responses | `--delay-ms` | barrier deadline → 503 to client; no ack; catch-up on recovery |
| Disk full | tmpfs root of 2 MB | `atomic_write` fails → 500 → fence; after space freed, resume with same seq |
| Read-only disk | `chmod -w` root | same as disk full |
| Truncated segment file on disk | truncate a `.seg` | compaction detects SHA mismatch and refuses; restore refuses |
| Corrupted snapshot | flip a byte | snapshot SHA mismatch on restore → refuse to serve writes |

## Apple TV faults (hardware; after M3)

| Fault | During | Check |
|---|---|---|
| Unplug Ethernet | 100 `createRecord` loop | 503s appear; no 2xx without matching vault segment; after replug, loop resumes; invariants 1–4 |
| Kill vault daemon (`/etc/init.d/swan-vault stop`) | same | same |
| Reboot OpenWrt | same | same; plus USB remount ordering (daemon must start after mount) |
| Terminate extension (Stop Tunnel / jetsam via ballast) | mid-write | on restart: local WAL frames beyond vault `next_frame` are shipped before serving; invariants |
| Purge Apple TV cache (delete app, reinstall) | idle | cold-start restore; invariants; time to serve |
| Fill USB disk | blob upload loop | 507/503 before corruption; recovers after cleanup |
| Corrupt a test block on the router | idle | detected at compaction/restore; alert path |
| Drop 10 % packets (`tc netem` on router) | write loop | latency, no corruption |

## Results

None yet on hardware.
