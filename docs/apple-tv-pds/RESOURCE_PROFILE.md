# Resource profile

## Baseline: full `swan serve` on macOS arm64 (OBSERVED 2026-09-04)

Build: `swift build -c release --product swan` (Swan @ working copy,
Petrel 5c42f603, Hummingbird 2.25.1, NIO 2.101.3, SQLiteNIO 1.12.10).
Run: `swan serve --port 3111 --data-directory … --oauth-server-key-file …`
(default surface: no OAuth AS, no firehose worker, no management listener).

| Metric | Idle after start | After 200 × `GET /health` |
|---|---|---|
| RSS (`ps -o rss`) | 27.5 MB | 27.9 MB |
| Physical footprint (`footprint`, what jetsam counts) | **8.5 MB** | – |
| Threads | 35 | – |
| Footprint breakdown | Malloc Small 4.4 MB, __DATA 1.0 MB, Stack 0.8 MB, Malloc Metadata 0.7 MB, __DATA_DIRTY 0.6 MB | |

Implication: a full Swan process sits an order of magnitude below the
folklore 50 MB extension ceiling at idle on macOS. tvOS numbers will differ
(different malloc, no shared cache reuse for package code, 16 KB pages both) but
this removes "Swan is obviously too big" from the risk list. The 35 threads
are the thing to trim: NIO `MultiThreadedEventLoopGroup.singleton` sizes to
core count plus SQLiteNIO thread pool plus Foundation; on a 3-core A10X inside
an extension, configure a 1–2 loop group (SwanHTTPServer takes its NIO config
from Hummingbird; check `SwanHTTPServiceLifecycle.swift`).

## tvOS compile survey (OBSERVED 2026-09-04, Xcode 27.0, tvOS 27.0 SDK, target tvOS 18)

* Swan `Package.swift` lacked a tvOS platform; Petrel declares tvOS 18 as its
  floor and Hummingbird-WebSocket tvOS 17. Added `.tvOS(.v18)` to Swan
  (comment marks it experiment-only).
* Petrel at the pinned revision fails on tvOS only because four files guard
  Apple code with `#if os(iOS) || os(macOS)` and `KeychainManager` has
  `#error("Unsupported platform")` for everything else. Widening those guards
  to include `os(tvOS)` (Security/ImageIO exist on tvOS; the iOS keychain
  branches are the right ones for tvOS) makes **all Petrel products build for
  tvOS** (`xcodebuild -scheme Petrel-Package -destination generic/platform=tvOS`
  → `BUILD SUCCEEDED`). Six-line change (`Package.swift`,
  `KeychainManager.swift`, `AppleKeychainStore.swift`, `SecurityCompat.swift`,
  `ImageMetadataStripper.swift`), applied in the local `Petrel/` working copy;
  needs upstreaming + Swan pin bump.
* With that Petrel (pinned revision 5c42f603 + the guard patch, mounted as a
  local package override in a throwaway workspace), **`SwanHTTP` and every
  module beneath it build for `arm64-apple-tvos`**: `xcodebuild -workspace …
  -scheme SwanHTTP -destination generic/platform=tvOS` → `BUILD SUCCEEDED`
  (2026-09-04); `Debug-appletvos/` contains `SwanHTTP.o`, `SwanSQLite.o`,
  `SwanAccounts.o`, `SwanOAuth.o`, `Hummingbird*.o`, `SQLiteNIO.o`,
  `Petrel*.o`. Zero Swan source changes were needed. Recipe:
  `jj workspace add /tmp/petrel-pinned -r 5c42f603` in `Petrel/`, apply the
  six-line guard patch, symlink it as `/tmp/pinned/Petrel` (package identity
  must match the directory name), reference `Swan/` and `/tmp/pinned/Petrel`
  from an `.xcworkspace`.
* Building against the *current* local Petrel main instead fails in three
  Swan call sites (`SpaceServiceAuthentication.swift:293/313/365`
  `requestBodyDigest`; `SwanSpaceRepositorySyncXRPC.swift:413/764/766`) —
  ordinary version skew, unrelated to tvOS; the pin bump will carry those.
* `CLibsodium` is a `systemLibrary` (pkg-config). Compiles against the
  Homebrew headers but **cannot link for a tvOS device**: needs
  `Clibsodium.xcframework` (swift-sodium ships one with tvOS slices, ISC
  licence) or a from-source build of libsodium for `arm64-apple-tvos`. Uses:
  Argon2id (`crypto_pwhash*`) in `PasswordHashing.swift` and
  `ScopedLegacyAuth.swift` only.
* `CATHandleDNS` links `resolv`; `libresolv.tbd` exists in the tvOS SDK.
* `UnixSignals` (swift-service-lifecycle) is used by the CLI only.

## What to measure on hardware (procedure in TVOS_LIFECYCLE.md)

| Stage | How |
|---|---|
| extension idle | `/health` footprintBytes, impliedLimitBytes, threads |
| listener only (probe) | same, after 1 000 curls |
| Swan initialized (M4) | same via Swan `/health` + provider message |
| SQLite + vault client initialized | after cold-start restore |
| single XRPC request / OAuth request / repo write / blob upload | footprint delta per request class; CPU seconds delta |
| WebSocket subscriber | footprint per open `subscribeRepos` |
| peak concurrent | `hey`/`oha` at 32 concurrent against `listRecords` |
| ceiling | ballast until jetsam; also read `os_proc_available_memory` at idle |
| CPU idle | `cpuSeconds` delta over 10 min idle (heartbeat cost) |
| tunnel crypto (M2) | throughput vs CPU on `iperf3` through the overlay |

Report each as: build id, tvOS version, value, method, classification.

## Known heavy pieces (from `Package.swift`), to profile before touching

Hummingbird + HummingbirdWebSocket, SwiftNIO (+SSL), AsyncHTTPClient
(SwanAccounts/SwanOAuth outbound), SQLiteNIO (vendored SQLite ~1.5 MB code),
Petrel + generated wire types (code size, mostly clean pages), swift-crypto.

The public firehose *consumer* is not part of `serve`; Swan only *emits*
`subscribeRepos` when `--enable-public-firehose` is set. Nothing on the Apple
TV needs to ingest the global firehose.
