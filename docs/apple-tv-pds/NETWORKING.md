# Networking

## Three separate paths, not one

1. **LAN listener (T2).** Inbound TCP to the Apple TV's real LAN address never
   traverses the utun; the kernel delivers it to whatever socket is listening.
   The extension's `NWListener` on :8080 is reachable from the LAN regardless
   of the tunnel. The tunnel's only role for this path is being the process
   that keeps the listener alive.
2. **Overlay/tunnel address (T3, M2).** Packets to the Apple TV's overlay IP
   arrive as encrypted UDP on the provider's own socket, are decrypted, and are
   injected with `packetFlow.writePackets`; the kernel routes them to the local
   listener. This is how Tailscale for Apple TV makes a TV reachable from a
   tailnet.
3. **Apple TV → vault (T4).** Plain LAN HTTP with a bearer PSK to the router.
   Once M2 lands and the router is the WireGuard hub, this traffic rides inside
   the tunnel and is encrypted on the wire without adding TLS to the daemon
   (decision D-004).

## Genuine VPN function (M2)

Requirement: the extension must perform a real network function, not exist to
keep a process alive. Plan: the extension is a WireGuard peer; the OpenWrt
router (kernel WireGuard, first-class in OpenWrt) is the hub; `swan-netcup`
(already on the tailnet, public IP) is a second peer for public ingress.

Candidate implementations (license → tvOS evidence → effort):

| Option | License | tvOS evidence | Integration | Notes |
|---|---|---|---|---|
| `wireguard-apple` / WireGuardKit + wireguard-go | MIT (kit), MIT (go) | README lists iOS/macOS only; third-party tvOS WireGuard apps exist, so a tvOS build of wireguard-go is achievable but needs a Go cross-build against the appletvos SDK (Go has no tvOS GOOS; builds use `GOOS=ios` + tvOS sysroot) | Swift package + external build target | Most mature userspace WireGuard on Apple; ~15–25 MB RSS reported on iOS |
| `libtailscale` / tsnet | BSD-3 | Tailscale ships a tvOS app; library tvOS build status UNKNOWN | cgo static lib | tsnet userspace `Listen` on the tailnet IP would let Swan listen *without* routing packets through utun at all; heavier memory (Go runtime + netstack) |
| `boringtun` (Cloudflare) | BSD-3 | Rust `aarch64-apple-tvos` is tier 3 (nightly, `-Zbuild-std`); monorepo already ships Rust→UniFFI→Swift for iOS (`catbird-mls/`) | `Tunn::encapsulate/decapsulate` fed from `packetFlow` | Smallest footprint; we own the packet loop; nightly toolchain cost |
| Pure Swift Noise/WireGuard | – | none production-ready | – | rejected |

Decision deferred to M2 (D-005): boringtun via the existing Rust toolchain is
the default unless the nightly requirement proves painful; wireguard-go is the
fallback with more prior art on Apple platforms. Neither is needed for M1/M3/M4.

## Public ingress (M7)

```
public DNS  pds.example ──▶ swan-netcup (Caddy/nginx, TLS)
                              └─ WireGuard/tailnet ─▶ Apple TV overlay IP :8080
```

AT Protocol needs: HTTPS PDS origin for `did:web`/PLC service endpoint,
`/.well-known/atproto-did` or DNS TXT for handle resolution, OAuth issuer ==
public origin (Swan enforces HTTPS issuer for the full OAuth server:
`swan serve --enable-oauth-authorization-server … requires an HTTPS public
issuer`). All satisfied by terminating TLS on the VPS and forwarding to the
overlay address; Swan's `--public-url` is the public origin and
`--login-trusted-proxy-peer` names the VPS.

Tailscale Funnel/Serve is an alternative that needs no VPS but couples the
public origin to `*.ts.net`; kept as a fallback.

## Not doing

* Exposing the Apple TV or the vault directly to the Internet.
* Bonjour/mDNS advertisement from the extension (not needed; LAN IP is enough).
