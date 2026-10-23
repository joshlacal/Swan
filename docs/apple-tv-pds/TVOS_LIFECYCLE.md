# tvOS execution model: what is known, what must be measured

## Facts

| Claim | Class | Source |
|---|---|---|
| `NEPacketTunnelProvider` is available on tvOS 17.0+ | DOCUMENTED | developer.apple.com/documentation/networkextension/nepackettunnelprovider (availability block) |
| The tvOS Network Extension Xcode template offers only the packet-tunnel provider (no App Proxy / DNS proxy / filter option), unlike iOS/macOS | OBSERVED | `XcodeListTemplates` output for `com.apple.dt.unit.networkproviderextensiontvos` vs `…extensionios` (Xcode 27.0 27A5252f) |
| Entitlement required: `com.apple.developer.networking.networkextension` = `packet-tunnel-provider`; App Group used for the heartbeat file | DOCUMENTED | same Apple page; template-generated entitlements |
| Xcode automatic signing accepted the App IDs `blue.catbird.SwanTV` / `.SwanTunnel` with the NE entitlement for team 44U2ZPNQPK; profile generation then failed only because the team has no registered tvOS device | OBSERVED | `xcodebuild -allowProvisioningUpdates` output: "Your team has no devices from which to generate a provisioning profile" (no capability error) |
| The probe app + extension compile for tvOS 17 (simulator SDK, `BUILD SUCCEEDED`) | OBSERVED | `xcodebuild -destination 'generic/platform=tvOS Simulator'` |
| Third-party WireGuard tunnels ship on the tvOS App Store (WG Connect, Xlarva, Proton, IPVanish) so a long-lived packet tunnel is an accepted product category on tvOS | REPORTED | web search 2026-09-04 |
| Per-process memory ceiling for a tvOS packet tunnel provider | UNKNOWN | no Apple documentation; iOS folklore says ~50 MB; the probe measures it with `os_proc_available_memory()` + ballast |
| Extension survival across Apple TV sleep / TV off / reboot | UNKNOWN | to be measured; on-demand rule installed by the probe app |
| tvOS local storage: UserDefaults limited, Caches purgeable, no durable Documents guarantee | DOCUMENTED (App Review / tvOS storage guidance) | treated as the design baseline regardless: nothing authoritative is local |

Hardware on hand: Apple TV "Family Room", `AppleTV6,2` (Apple TV 4K 1st gen,
A10X, 3 GB RAM), tvOS 26.6, reachable at `Family-Room.local` (Bonjour
`_airplay._tcp`). **Not yet paired with Xcode** (`xcrun devicectl list devices`
shows no physical Apple TV). Pairing needs a human: Apple TV → Settings →
Remotes and Devices → Remote App and Devices; Mac → Xcode → Window → Devices
and Simulators → pair, enter the 6-digit code shown on the TV.

## Probe design (built, unexecuted on hardware)

`AppleTV/SwanTV/` — SwiftUI app `SwanTV` + packet tunnel extension
`SwanTunnel`, tvOS 17 deployment target, team 44U2ZPNQPK.

Extension (`SwanTunnel/`):

* `PacketTunnelProvider` brings up utun `10.77.0.2/32`, includes route
  `10.77.0.0/24`, MTU 1280, drains packets (counted, dropped) — a research
  placeholder until M2 replaces the loop with WireGuard.
* `ProbeServer` — `NWListener` on TCP 8080 inside the extension process.
  `GET /health` (JSON metrics), `GET /log` (journal tail), `GET /packets`,
  `GET /ballast/<MiB>` (touched allocation to find the jetsam ceiling).
* `ProbeLog` — append-only journal in the App Group container
  (`swantv-heartbeat.log`) + `os_log`. Events: `tunnel.start`,
  `tunnel.settings.applied`, `http.listener state=…`, `heartbeat` (30 s),
  `tunnel.sleep`, `tunnel.wake`, `tunnel.stop reason=N`, `ballast.step/held`.
* `ProcessMetrics` — `phys_footprint` (what jetsam counts), resident size,
  `os_proc_available_memory()`, implied limit, thread count, CPU seconds,
  thermal state, interface addresses.

App (`SwanTV/`): install/update the `NETunnelProviderManager` (with or without
`NEOnDemandRuleConnect`), start/stop, `sendProviderMessage` round-trip
("Query Provider"), heartbeat tail.

## Hardware qualification matrix (to fill; nothing below is PASS yet)

For each row record: extension alive (journal advancing) / `:8080/health` from
Mac on LAN / tunnel-IP reachability (after M2) / vault reachability / automatic
recovery / manual action needed / recovery time / journal excerpt.

| State | Alive | LAN HTTP | Tunnel HTTP | Vault | Auto-recover | Notes |
|---|---|---|---|---|---|---|
| App foreground | | | | | | |
| App backgrounded (Home button) | | | | | | |
| App force-quit (app switcher) | | | | | | |
| Apple TV idle 10 min | | | | | | |
| Screen saver | | | | | | |
| Apple TV sleep (menu → Sleep Now) | | | | | | |
| TV powered off, Apple TV left on | | | | | | |
| HDMI disconnected | | | | | | |
| Ethernet down/up | | | | | | |
| Router reboot | | | | | | |
| Apple TV reboot (on-demand rule on) | | | | | | |
| Apple TV reboot (on-demand rule off) | | | | | | |
| tvOS update | | | | | | |

Memory ceiling procedure: `for mb in 20 30 40 50 60 80 100 150 200; do curl
-s http://<tv>:8080/ballast/$mb | jq .impliedLimitBytes; done` until the
process dies; `curl :8080/log` after the extension restarts (or read the App
Group file via the app) gives the last `ballast.step` line. Also read
`impliedLimitBytes` from `/health` at idle: `os_proc_available_memory` already
reports the budget without provoking a kill.

Observation tools from the Mac once paired: Console.app device stream filtered
on subsystem `blue.catbird.SwanTV`; `xcrun devicectl device info processes
--device <udid>` for the extension PID; jetsam reports under Xcode → Devices →
View Device Logs (`JetsamEvent-*.ips`).

## Experiment records

None yet. Each hardware run appends: hypothesis, setup (tvOS build, app build
hash), commands, observed result with journal excerpt, classification,
implication, next experiment.
