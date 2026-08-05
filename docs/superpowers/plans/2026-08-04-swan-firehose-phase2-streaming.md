# Swan Firehose Phase 2: `subscribeRepos` WebSocket Streaming — Reviewed Implementation Plan

**Review status:** Revised after source-level review of Swan, Petrel, the pinned wire-profile regime, the pinned generator, and the `hummingbird-websocket` 2.7.0 API.

**Date:** 2026-08-05
**Workspace:** `/Users/joshlacalamito/Developer/Catbird+Petrel/.worktrees/swan-public-federation` (jj workspace `swan-public-federation`)
**Status:** Reviewed implementation plan (not yet implemented)

**Goal:** Serve `GET /xrpc/com.atproto.sync.subscribeRepos` as an unauthenticated WebSocket endpoint that streams the durable global log from `firehose.sqlite` — the log is the queue, the sequencer's in-process signal is a wakeup only, every connection owns a per-connection cursor state machine (live / backfill / error), slow consumers are dropped with a `ConsumerTooSlow` error frame, and the endpoint is added to the frozen public wire profile via the pinned regeneration regime.

**Governing design:** `docs/superpowers/specs/2026-08-04-swan-public-firehose-design.md` — the `subscribeRepos` section (lines ~232–313), the "Live delivery: the log is the queue" section (232–247), and "Cursor semantics on connect" (283–300). Phase 1 plan and completion record are authoritative for Phase 1 facts.

## Scope

Phase 2 must deliver:

1. **Dependency:** `hummingbird-websocket` 2.x pinned exact in `Package.swift`, aligned with the pinned `hummingbird` 2.25.1; server upgraded via `HTTPServerBuilder.http1WebSocketUpgrade` with a raised `maxFrameSize`.
2. **Public wire profile regeneration:** `com/atproto/sync/subscribeRepos` added to a new dated profile (`public-data-testing-2026-08-05`) through `Scripts/regenerate-public-wire.sh` (never hand-edited generated sources); 2026-07-30 trio frozen as byte-immutable legacy; all `Scripts/public-wire-generation-common.sh` inventory lists, counts, and sha256 constants updated; `public_wire_assert_contracts` counters moved 18 → 19.
3. **Subscription wire kind:** `PublicXRPCMethodKind` gains `.subscription`; `PublicDataTesting20260805.methods` (19 entries) ships `subscribeRepos` with kind `.subscription`; the generated `XRPCMethodDescriptor` (kind `"subscription"`) is consumed; the generated single-shot `ServerHandler` for subscriptions is present but **never used** (see D3).
4. **Wakeup fan-out:** an in-process `PublicFirehoseWakeupHub` implementing `PublicFirehoseWakeupSink`, wired into the sequencer at `SwanCommand.swift:2182` (`wakeup:` is currently `nil`), fanning out coalesced signals to per-connection subscriber loops.
5. **Log-as-queue tailer:** per-connection loop over `SQLiteFirehoseDatabase.events(after:limit:)`, `frame_bytes` shipped verbatim (no re-encoding), one state machine covering backfill and live with a gap/duplicate-free boundary, plus a bounded periodic poll as recovery (a lost wakeup loses nothing).
6. **Endpoint + framing:** `router.ws("/xrpc/com.atproto.sync.subscribeRepos", ...)` on the existing `Router<SwanHTTPRequestContext>`; `SwanHTTPRequestContext` gains `WebSocketRequestContext` conformance; cursor query-parameter validation; `#info`/error frames via `FirehoseFrameEncoder.infoFrame/errorFrame`; strict binary frames; `FutureCursor` and `ConsumerTooSlow` handling; plain GET / unknown-path upgrade behavior defined.
7. **Slow-consumer bounds:** seq-lag ceiling, backfill catch-up time budget, and per-write duration bound, all injectable; `ConsumerTooSlow` error frame + close.
8. **Shutdown behavior:** cancellation-driven exit of subscriber loops; no ping/heartbeat and no close-frame choreography (explicit non-goal, see below).
9. **Cursor semantics on connect** per design doc: no cursor → live; `cursor=0` → entire retained window with no `OutdatedCursor`, then live; cursor within retention → backfill then live; cursor > max → `FutureCursor` error frame + close; cursor older than retention → `OutdatedCursor` info frame then stream from oldest retained (code path present, unreachable until Phase 3 pruning); strictly-after semantics (`seq > cursor`, P0 compatibility decision recorded in the design).

### Explicit NON-GOALS (Phase 3+)

- WebSocket ping/liveness heartbeat (30 s auto-ping) — Phase 3.
- Graceful-shutdown close frames via a service-lifecycle hook — Phase 3; Phase 2 relies on cancellation + channel teardown.
- Retention pruning, `retained_from_seq` advance, per-DID deletion pruning, and therefore *delivered* `OutdatedCursor` behavior (the decision code path is implemented and unit-tested; it cannot trigger while retention is unbounded).
- `requestCrawl` announcer (Phase 4) and reference-relay acceptance proof (Phase 5).
- The `public_streaming_pending` (503) placeholders for `uploadBlob`/`getBlob`/`getRepo` stay as-is (data-streaming adapters are later-phase work; `subscribeRepos` is the only endpoint that moves from wildcard-404 to a real route).
- Any generator change or generator-pin repin (see D3 — verified unnecessary).
- Changing the placeholder loop in `buildRouter` from the legacy `PublicDataTesting20260727.methods` list (see D4).

## Architecture

```text
ACCOUNT/CONTROL OUTBOXES (SwanSQLite)
        │  (durable, Phase 1)
        ▼
PublicFirehoseSequencer (actor, SwanSQLite)
        │ appendBatch(..., now:) ────► SQLiteFirehoseDatabase (firehose.sqlite)
        │                                    │  firehose_events.frame_bytes  (complete frames, seq embedded)
        │ firehoseDidAppend(maxSeq:)         │
        ▼                                    ▼
PublicFirehoseWakeupHub (SwanHTTP)      per-connection tailer loop (SwanHTTP):
        │  coalesced signal                    rows = events(after: lastSent, limit: 1000)
        ▼  AsyncStream(.bufferingNewest(1))    if rows: send frame_bytes verbatim; lastSent = last.seq
   subscriber loop  ◄───────────────           else: await wakeup | poll(≈250 ms) | cancellation
        │                                      bounds: FutureCursor / OutdatedCursor / ConsumerTooSlow
        ▼
router.ws("/xrpc/com.atproto.sync.subscribeRepos") on Router<SwanHTTPRequestContext>
        │  HTTP1WebSocketUpgradeChannel (maxFrameSize = 5_000_000, autoPing disabled)
        ▼
   binary DAG-CBOR frames: header {"op":1,"t":"#commit|#sync|#identity|#account|#info"} + body
   errors: {"op":-1} + {error, message}
```

Component ownership:

- **SwanPublicFirehose** (no SwanSQLite dependency, cannot gain one — cycle: `SwanSQLite` → `SwanPublicFirehose`, Package.swift:116): frame encoding (`FirehoseFrameEncoder`), limits, frame material types. **Unchanged in Phase 2 except nothing at all** — the tailer reuses it read-only.
- **SwanSQLite**: `SQLiteFirehoseDatabase` (durable authority), `PublicFirehoseWakeupSink` protocol, sequencer. Phase 2 adds **one** read accessor: `retainedFromSeq()`.
- **SwanHTTP** (already depends on SwanSQLite, Package.swift:162): wakeup hub, tailer loop, cursor policy, ws route, server upgrade. New files:
  - `Sources/SwanHTTP/PublicFirehoseWakeupHub.swift`
  - `Sources/SwanHTTP/PublicFirehoseStreaming.swift` (tailer loop + cursor state machine + slow-consumer policy + limits)
  - `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift` (route registration + `SwanPublicFirehoseStreamingRuntime`)
- **swan target (SwanCommand.swift)**: constructs the hub, passes it as `wakeup:` to the sequencer, hands the runtime (database + hub + limits) to `SwanHTTPServer`, appends nothing new to the service group (the ws endpoint runs inside the existing `Application` service).

Connection state machine (per connection):

```text
parse cursor (strict decimal; malformed → reject upgrade, no websocket)
   → no cursor:      lastSent = maxSequencedSeq()              (live)
   → cursor == 0:    lastSent = 0                              (full window, no OutdatedCursor)
   → cursor > max:   send errorFrame("FutureCursor") + close   (FutureCursor)
   → cursor < oldestRetained: send infoFrame("OutdatedCursor"); lastSent = oldestRetained - 1
   → else:           lastSent = cursor                          (backfill)
loop:
   rows = events(after: lastSent, limit: 1000)
   if rows.isEmpty: await wakeup | poll(idlePollInterval) | cancellation
   else:
     if slow-consumer bounds exceeded: send errorFrame("ConsumerTooSlow") + close
     for row in rows: outbound.write(.binary(row.frameBytes))   // verbatim
     lastSent = rows.last.seq
```

## Decisions

### D1 — hummingbird-websocket version pin

**RECOMMENDATION:** `.package(url: "https://github.com/hummingbird-project/hummingbird-websocket.git", exact: "2.7.0")`.

Verified against the 2.7.0 tag: requires `hummingbird from: 2.24.0` (satisfied by the pinned exact 2.25.1), `swift-websocket from: 1.6.0`, `swift-nio-extras from: 1.22.0`, `swift-nio-ssl from: 2.5.0` (satisfied by exact 2.37.2). Products: `HummingbirdWebSocket` (server upgrade, `@_exported import WSCore`), `HummingbirdWSClient`, `HummingbirdWSTesting`, `HummingbirdWSCompression`.

**Alternatives:** 2.5.0 (min hummingbird 2.14.0) — older, misses the `HTTP1WebSocketUpgradeChannel.Configuration` API and the 2.6.0/2.7.0 HTTP/upgrade interop fixes (redirect-on-upgrade-after-http, 400 failed-upgrade, decoder config propagation); rejected. A source-dependency (vendored fork) — rejected, breaks the pin-everything regime. Note: resolution will newly pull `swift-websocket` and `swift-nio-extras`; record the resolved versions in `Package.resolved` and add explicit `exact` pins only if resolution picks unexpected versions (repo convention: direct pins only for directly imported products; SwanHTTP imports `HummingbirdWebSocket` only).

### D2 — ws route integration with `Router<SwanHTTPRequestContext>`

**RECOMMENDATION:** One router. `SwanHTTPRequestContext` gains `public let webSocket: WebSocketHandlerReference<SwanHTTPRequestContext>` (initialized in `init(source:)`, mirroring `BasicWebSocketRequestContext`) and conforms to `WebSocketRequestContext` (which requires `InitializableFromSource<ApplicationRequestContextSource>` — already satisfied via `RequestContext` — and `WebSocketContext`'s `logger`, satisfied via `coreContext`). `buildRouter()` registers the ws route; `buildApplication()` switches `.http1(configuration:)` → `.http1WebSocketUpgrade(webSocketRouter: router, configuration: .init(http1: <existing additionalChannelHandlers + idleTimeout>, ws: .init(maxFrameSize: 5_000_000, autoPing: .disabled, closeTimeout: .seconds(15), validateUTF8: true)))`.

Behavior verified from the 2.7.0 source (`WebSocketRouter.swift`, `WebSocketChannel.swift`):
- Upgrade request (has `Upgrade: websocket`): the upgrader consults the ws responder; the route returns `.ok` and stores the handler in `context.webSocket` → upgrade proceeds and `onUpgrade` runs as `@Sendable (WebSocketInboundStream, WebSocketOutboundWriter, WebSocketRouterContext<SwanHTTPRequestContext>) async throws -> Void`.
- Non-upgrade request to the same path: served by the normal responder; the ws route's `shouldUpgrade` returns `.dontUpgrade` when the `Upgrade` header is absent → **405** for plain GET.
- Upgrade request to an unknown path: 404 from the ws responder → failed upgrade → **400** + close.
- Exact route beats the `registerUnknownPublicEndpointGuards` wildcard (`/xrpc/com.atproto.sync.*`), per the existing precedence comment (SwanHTTP.swift:897–899); when the firehose runtime is absent the route is not registered and the wildcard 404 remains.
- `SwanJSONWriteBodyDrainHandler` is preserved via `HTTP1WebSocketUpgradeChannel.Configuration.http1.additionalChannelHandlers` (installed on the non-upgrade path only, which is correct for an HTTP body-drain handler).
- `maxFrameSize` default is 16 KiB — must be raised to ≥ `FirehoseFrameLimits.maximumFrameBytes` (5_000_000) or any real `#commit` frame fails with `messageTooLarge`.

**Alternatives:** a separate ws-only `Router<BasicWebSocketRequestContext>` — rejected: requires a second context type, duplicated route registration, and changes the plain-GET/unknown-path behavior surface for no benefit (hummingbird's docs merely prefer separation when there are many paths). Middleware-based `WebSocketUpgradeMiddleware` — equivalent mechanics, rejected as unnecessary indirection on a plain `Router`.

### D3 — generator subscription emission: **no generator change** (verified by execution)

**RECOMMENDATION:** Do not touch `Petrel-swan-generator`; do not repin `public_wire_expected_generator_commit` (c2a1cdbee8c621c7682416114700f032cc7e2b37).

Empirical proof (ran the pinned generator on the real pinned `subscribeRepos.json` in a temp manifest, `emit_server_contracts: true`): the generator **already emits** `XRPCMethodDescriptor(nsid: "com.atproto.sync.subscribeRepos", kind: "subscription", declaredErrors: ["FutureCursor","ConsumerTooSlow"])`, `Parameters { cursor: Int? }` (via `generate_query_parameters`), the `Message` union (`commit/sync/identity/account/info` cases with `$type` decoding), the `Error` enum, and the client `subscribeRepos(cursor:)` extension calling `networkService.subscribe(endpoint:parameters:)` — which exists in Petrel (`Sources/Petrel/Network/NetworkService.swift:2013`), so the generated client file compiles. Types used (`Bytes`, `DID`, `CID`, `TID`, `ATProtocolDate`) all exist in Petrel. `generate_server_contracts` runs for `main_def_type in ('query', 'procedure', 'subscription')` (swift_code_generator.py:552) and emits for subscriptions a **single-shot** `protocol ServerHandler { func handle(parameters:input:context:) async throws -> Message }` (line 626–631) — there is **no streaming-capable server-handler variant**; that generated protocol returns one `Message` and is structurally unusable for a firehose. Phase 2 treats it as intentionally-unused dead code (never referenced by SwanHTTP; documented in the completion record). The strict decoder used by tests (`FirehoseTestCBORReader`) and the server's verbatim `frame_bytes` shipping never touch it.

**Alternatives:**
- (a) Generator change: branch in `generate_server_contracts` to emit a distinct `ServerSubscriptionHandler` (e.g. `func stream(parameters:context:) async throws -> AsyncThrowingStream<Message, Error>`). Requires: new commit in the generator workspace, a new empty-child (the pin check at `public-wire-generation-common.sh:210–216` requires `parent(@) == pin` and an empty `@`), new pin in `common.sh:19` **and** `petrelGeneratorCommit` in the profile, plus byte-stable regeneration proof. Rejected for Phase 2: the streaming handler would still be unused by the actual implementation (the tailer needs `SQLiteFirehoseDatabase` + wakeup access, not a `Message` stream), and the profile-regime already carries enough mechanical risk (see Risks R1). Recorded as an optional Phase 3+ follow-up.
- (b) Exclude `subscribeRepos` from the generated server contract via manifest — no such per-lexicon knob exists; rejected.

### D4 — `PublicXRPCMethodKind` and the placeholder loop

**RECOMMENDATION:** Add `case subscription` to `PublicXRPCMethodKind` (SwanPublicWire.swift:3–6) and add `PublicDataTesting20260805.methods` (19 entries; `subscribeRepos` = `.subscription`, `inputEncoding: nil`, `outputEncoding: nil`, `declaredErrors: ["FutureCursor","ConsumerTooSlow"]`), leaving `PublicDataTesting20260730` frozen. **Keep** the `buildRouter` unavailable-placeholder loop iterating the legacy `PublicDataTesting20260727.methods` (SwanHTTP.swift:921–939): that list contains no `subscribeRepos` entry, so the loop needs no change and the wildcard guard (`registerUnknownPublicEndpointGuards`, GET 404) remains the disabled-fallback for `subscribeRepos`. Do **not** move the loop to the 2026-08-05 profile in Phase 2 (it would change the 503-vs-404 surface for the five `server.*` methods when email recovery is disabled — a behavioral change outside Phase 2 scope; revisit when a profile method is added that is not otherwise routed). `registerUnavailablePublicEndpoint`'s `isStreamingAdapter` list stays unchanged.

### D5 — WS test client

**RECOMMENDATION:** `HummingbirdWSTesting`'s `TestClientProtocol.ws(path:configuration:logger:handler:)` against **`.live`** servers (it `precondition`s on `port != nil`; connects `ws://localhost:<port>/<path>`; returns the close frame; binary messages arrive as `WebSocketDataFrame`s). `buildApplication` serves plaintext HTTP/1 — no TLS requirement — so `ws://` works on `client.port` (same pattern as `RemoteOAuthAuthorizationServerHTTPTests.swift:35–39`). `.router` (in-process) mode **cannot** test upgrades (no channel pipeline) — all ws tests are `.live`.

**Alternatives:** `URLSessionWebSocketTask` (Foundation, zero new deps, also viable against `ws://localhost:<port>`; close-code/close-reason inspection is clumsier) — acceptable fallback. `NIOWebSocketClient` (already resolved via the swift-nio direct pin) — viable but lowest-level; rejected as primary. Decision recorded: WSTesting primary, URLSession fallback if the WSClient dependency misbehaves in CI.

The frame assertions: because the server ships stored bytes verbatim, integration tests assert byte-for-byte equality with `SQLiteFirehoseDatabase.events(after:limit:).frameBytes` read from the same database in-process; a **minimal** two-object CBOR reader (header op/t + body, no trailing bytes) is added under `Tests/SwanHTTPTests` for `#info`/error frames. The full strict canonical reader (`Tests/SwanPublicFirehoseTests/FirehoseFrameTestDecoder.swift`) stays the authority for frame-level tests in `SwanPublicFirehoseTests` and is not moved (test targets cannot share code without a shared helper target; duplicating a thin reader is the pragmatic choice).

### D6 — tailer location

**RECOMMENDATION:** `SwanHTTP` (new files listed in Architecture). `SwanPublicFirehose` **cannot** host the tailer: it does not depend on `SwanSQLite` (Package.swift:91–97) and cannot start (cycle: `SwanSQLite` → `SwanPublicFirehose`, Package.swift:116). `SwanHTTP` already depends on `SwanSQLite` (Package.swift:162) and is the designated WebSocket/XRPC adapter per the design doc ("WebSocket/XRPC adapter in SwanHTTP"). Frame encoding stays in `SwanPublicFirehose` (public `FirehoseFrameEncoder`).

### D7 — cursor parameter validation

**RECOMMENDATION:** Strict decimal parse in the route's `shouldUpgrade` (reusing the strict-query house style of `strictAuthenticatedRecordQuery`, SwanSpaceXRPC.swift:1331–1359; query bounded at 8 KiB, single `cursor` key, no fragments). Non-decimal, negative, or > `FirehoseFrameLimits.maximumSequence` (`2^53 - 1`) → `shouldUpgrade` returns `.dontUpgrade` → upgrade rejected (400 over an attempted upgrade; 405 for plain GET). `FutureCursor` (cursor > current max seq) is detected **after** upgrade inside the handler (it needs an async `maxSequencedSeq()` read and per the design doc is delivered as an error frame, which requires an open websocket): send `FirehoseFrameEncoder.errorFrame(error: "FutureCursor", message: nil)`, then close. `cursor=0` → full window (no `OutdatedCursor`). Cursor older than retention → `infoFrame(name: "OutdatedCursor", message: ...)` then stream from oldest retained.

**Deviation flagged for Phase 5 verification:** strict-reject malformed cursors is stricter than the reference PDS's tolerant `parseInt`-style handling; the pinned-relay acceptance scenario will confirm the reference never sends garbage cursors (compatibility note, not a claim of spec conformance).

### D8 — slow-consumer bounds

**RECOMMENDATION:** A `PublicFirehoseStreamingLimits` struct (patterned after `FirehoseFrameLimits`), injectable per runtime, defaults: `pageSize = 1_000` (equals `SQLiteFirehoseDatabase.maximumCursorLimit`), `maximumSequenceLag = 50_000`, `maximumBackfillCatchUp = .seconds(120)`, `maximumWriteDuration = .seconds(30)`, `idlePollInterval = 0.25 s`. Enforcement in the tailer loop: after each page, if `maxSequencedSeq() - lastSent > maximumSequenceLag` **or** the accumulated backfill wall-clock exceeds `maximumBackfillCatchUp`, or a single `outbound.write` exceeds `maximumWriteDuration` → `errorFrame(error: "ConsumerTooSlow", message: <lag detail>)` then `outbound.close(.normalClosure, reason: "ConsumerTooSlow")`. (Close code choice is not specified by the event-stream spec; the pinned-relay acceptance scenario in Phase 5 is the place to confirm the reference's preference. Tests use injected zero/tiny bounds for determinism — see Task 4.)

### D9 — wakeup fan-out shape

**RECOMMENDATION:** `PublicFirehoseWakeupHub` — a `final class` (NSLock-guarded registry of continuations, or an actor; **actor recommended** for Swift 6 strict concurrency), `Sendable`, conforming to `PublicFirehoseWakeupSink` (`firehoseDidAppend(maxSeq:) async` — the exact protocol from `Sources/SwanSQLite/PublicFirehoseSequencer.swift:19–21`). API: `func subscribe() -> AsyncStream<Int64>` with `.bufferingNewest(1)` per subscriber (a missed wakeup is harmless — the poll loop recovers; buffering one element avoids unnecessary idle-polls). The sequencer invokes it exactly as today (`await wakeup?.firehoseDidAppend(maxSeq: seq)`, PublicFirehoseSequencer.swift:196/239). There is **no** in-process broadcast primitive anywhere in `Sources/` today — this is the first; keep it wakeup-only (never carries event bytes).

### D10 — shutdown behavior

**RECOMMENDATION:** Cancellation-driven teardown; **no** close-frame choreography in Phase 2. The `onUpgrade` handler runs two child tasks (inbound drain — consuming `WebSocketInboundStream` so pings/close frames are processed by the library — and the outbound tailer loop); both observe `Task.isCancelled` and exit promptly. On service-group shutdown the `Application` service stops the listener and channels close; the WS library performs the normal close handshake on teardown. No heartbeat, no graceful-close broadcast — those are Phase 3 liveness (design doc lines 302–309), recorded as an explicit non-goal. Tests assert prompt loop exit on cancellation and that a half-open connection is torn down when the listener stops.

## Global constraints

- Swift 6 strict concurrency; actors; 2-space indentation; XCTest, not Swift Testing.
- VCS: `jj` only; never mutate history with Git. Commit with path-restricted commands (`jj commit <paths> -m "firehose: …"`).
- All SQLite access via `connection.query(sql, bindings)` inside `withConnectionGate`/`transaction`; never two open database transactions; never network I/O inside a transaction.
- All public wire generated sources come from `Scripts/regenerate-public-wire.sh`; never hand-edit `Sources/SwanPublicWire/Generated/*`; the sha256 constants are updated only by running the regenerate/verify flow and recording the real hashes.
- The legacy profiles (2026-07-27 and, after Task 1, 2026-07-30) are byte-immutable.
- The generator workspace is read-only to Swan tasks; no generator commit, no pin change (D3).
- Work from `/Users/joshlacalamito/Developer/Catbird+Petrel/.worktrees/swan-public-federation`.
- Build: `swift build`. Focused test: `xcrun swift test --filter <TargetOrTest>` (from the worktree root).

---

## Task 0: Reconcile the design and land the plan

**Objective:** the Phase 2 contract is explicit and the plan document is committed before any code changes.

**Files:**
- Create: `docs/superpowers/plans/2026-08-04-swan-firehose-phase2-streaming.md` (this document).
- Verify: `docs/superpowers/specs/2026-08-04-swan-public-firehose-design.md` — confirm lines 249–300 say what this plan implements (they do) and that the Phase 3 items listed under "Liveness and retention (Phase 3)" are non-goals here.

**Steps:**
- [ ] Step 1: Commit this plan (`jj commit docs/superpowers/plans/2026-08-04-swan-firehose-phase2-streaming.md -m "firehose: phase 2 streaming plan"`).
- [ ] Step 2: Re-read the design's cursor section (283–300) and the Phase 1 completion record's "Explicitly unimplemented" section; record any drift here before Task 1.

**Acceptance:** the plan is committed; design/code inventory matches the completion record.

## Task 1: Dependency + public wire profile regeneration

**Objective:** `hummingbird-websocket` 2.7.0 is a resolved exact dependency; `subscribeRepos` enters the frozen profile as `public-data-testing-2026-08-05`; the whole regenerate/verify/test script suite passes; the module compiles with the new generated surface.

**Files:**
- `Package.swift` — add `.package(url: "https://github.com/hummingbird-project/hummingbird-websocket.git", exact: "2.7.0")`; `SwanHTTP` target gains `.product(name: "HummingbirdWebSocket", package: "hummingbird-websocket")`; `SwanHTTPTests` gains `.product(name: "HummingbirdWSTesting", package: "hummingbird-websocket")`. Commit the resulting `Package.resolved` (adds `swift-websocket`, `swift-nio-extras`).
- `Profiles/public-data-testing-2026-08-05.json` — `id: "public-data-testing-2026-08-05"`, `referenceImplementationCommit: 3f6c96d5d2d25438bd40fa89d6ecc37865f8e354` (unchanged — the pinned atproto commit already contains `subscribeRepos.json`), `petrelGeneratorCommit: c2a1cdbee8c621c7682416114700f032cc7e2b37` (unchanged), `petrelManifest`/`petrelManifestSHA256` unchanged (cb39d0c4… — the manifest content does not change), lexicons = the 20 existing + `com.atproto.sync.subscribeRepos` (ordered 21-file set), endpoints = 19, `inventorySemantics` text updated (21/19), `intentionalDivergences` gains the subscribeRepos entries below, and the three manifest SHA256 fields set to the real generated values.
- `Profiles/public-data-testing-2026-08-05.lexicons.sha256` (21 entries; the subscribeRepos entry hash from the pinned cache).
- `Profiles/public-data-testing-2026-08-05.generated-wire.sha256` (24 entries — 22 lexicon files + 2 client files; the file set is produced by the regenerator).
- `Scripts/public-wire-generation-common.sh`:
  - `public_wire_profile`/`public_wire_lexicon_manifest`/`public_wire_generated_manifest` → 2026-08-05 paths (lines 11–14);
  - `public_wire_expected_profile_id` → `public-data-testing-2026-08-05` (line 17);
  - new `public_wire_expected_profile_sha256` / `public_wire_expected_lexicon_manifest_sha256` / `public_wire_expected_generated_manifest_sha256` (lines 20, 22, 23 — petrel-manifest hash unchanged);
  - `public_wire_verify_legacy_profile_immutable` (lines 40–52): **add** the 2026-07-30 trio with its (now frozen) hashes next to the 2026-07-27 trio;
  - `public_wire_write_expected_lexicon_paths` (54–84): add `"com/atproto/sync/subscribeRepos.json"` (21 paths);
  - `public_wire_verify_profile_inventory` (86–143): 21 lexicons / 19 endpoints lists; "20-file set"/"18-method set" diagnostics → 21/19; `len(set) == 21/19`;
  - `public_wire_verify_source_manifest` (162–170): `20` → `21` (line count + uniqueness);
  - `public_wire_verify_checked_in_manifest` (247–270): `23` → `24` (two places);
  - `public_wire_stage_lexicons` (200): "20-file set" → 21;
  - `public_wire_assert_contracts` (272–277): both `18` → `19`.
- `Scripts/regenerate-public-wire.sh`, `Scripts/verify-public-wire-generation.sh`, `Scripts/test-public-wire-generation.sh` — **no structural edits** (they only source the common file; the unselected-lexicon fixture at test-public-wire-generation.sh:93–104 already proves extra `subscribeRepos` files are ignored and remains valid).
- `Sources/SwanPublicWire/SwanPublicWire.swift` — hand-maintained: `PublicXRPCMethodKind` gains `case subscription`; add `PublicDataTesting20260805.methods` (19 entries) with `subscribeRepos` descriptor; leave `PublicDataTesting20260727` and `PublicDataTesting20260730` untouched.
- Generated output (regenerated, never hand-edited): `Sources/SwanPublicWire/Generated/Lexicons/Com/Atproto/ComAtprotoSyncSubscribeRepos.swift` (new), `Client/ATProtoClient+SwanPublicWire.swift` and `Client/SwanPublicWireLexicons.swift` (modified).
- `Profiles/public-data-testing-2026-08-05.json` `intentionalDivergences` additions: (1) malformed-cursor rejection is stricter than the reference's tolerant cursor parsing; (2) `OutdatedCursor` delivery is dormant until Phase 3 pruning advances `retained_from_seq`.

**Steps:**
- [ ] Step 1: Add the Package.swift dependency and test products; `swift build` with the resolved graph (record `swift-websocket`/`swift-nio-extras` versions in `Package.resolved`).
- [ ] Step 2: Write the new profile JSON + lexicon manifest; update common.sh constants/inventory in one commit **without** touching generated sources yet.
- [ ] Step 3: Run `PETREL_GENERATOR_ROOT=/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel-swan-generator ./Scripts/regenerate-public-wire.sh`; commit the generated diff + new `generated-wire.sha256`; record the real hashes back into common.sh if they differ from the precomputed ones (they must match byte-for-byte — see R1).
- [ ] Step 4: Run `verify-public-wire-generation.sh` and `test-public-wire-generation.sh` from the worktree root.
- [ ] Step 5: Hand-edit `SwanPublicWire.swift` (`PublicXRPCMethodKind.subscription` + `PublicDataTesting20260805.methods`); `swift build`.

**Tests (Swift):**
- `SwanPublicWireTests` — extend the existing profile-consistency tests: `testPublicDataTesting20260805IncludesSubscribeReposSubscription` (descriptor kind `.subscription`, declared errors, nil encodings, 19 methods).
- No new frame tests here (frame behavior is Phase 1-covered).

**Verification:**
```bash
xcrun swift build
PETREL_GENERATOR_ROOT=/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel-swan-generator ./Scripts/verify-public-wire-generation.sh
PETREL_GENERATOR_ROOT=/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel-swan-generator ./Scripts/test-public-wire-generation.sh
xcrun swift test --filter SwanPublicWireTests
```

**Acceptance criteria:**
- `verify` and `test` script suites pass with the 2026-08-05 profile as successor and 2026-07-30 frozen legacy.
- `swift build` passes with 24 generated files; `ComAtprotoSyncSubscribeRepos.swift` present with `kind: "subscription"` descriptor; nothing else in `Generated/` changed except the two client files.
- `jj` working copy contains exactly: profile trio, common.sh, Package.swift + Package.resolved, generated diff, `SwanPublicWire.swift`.

## Task 2: Wakeup hub + tailer core

**Objective:** the fan-out primitive and the per-connection log-tail loop exist as pure SwanHTTP components with unit-level tests, independent of HTTP.

**Files:**
- New `Sources/SwanHTTP/PublicFirehoseWakeupHub.swift` — `actor PublicFirehoseWakeupHub: PublicFirehoseWakeupSink` with `firehoseDidAppend(maxSeq:) async` (protocol conformance, coalesced version bump + continuation resume) and `subscribe() -> AsyncStream<Int64>` (`.bufferingNewest(1)`).
- New `Sources/SwanHTTP/PublicFirehoseStreaming.swift`:
  - `public struct PublicFirehoseStreamingLimits: Sendable, Equatable` (D8 defaults; validated init like `PublicFirehoseSequencerConfiguration`).
  - `public enum PublicFirehoseCursorPolicy: Sendable` with `static func resolve(cursor: Int64?, maxSequencedSeq: Int64, retainedFromSeq: Int64?) -> Outcome` where `Outcome = { .live, .backfill(from: Int64), .fullWindow, .futureCursor, .outdatedCursor }` — pure, fully unit-testable (this is the design-doc cursor matrix, lines 285–292).
  - `PublicFirehoseTailer` — a `struct` holding `(database: SQLiteFirehoseDatabase, limits: PublicFirehoseStreamingLimits, logger)` with `func run(lastSent: Int64, outbound: (Data) async throws -> Void, waitForWakeup: () async -> Int64?) async` — the loop from the Architecture section; slow-consumer checks as pure `PublicFirehoseSlowConsumerPolicy.check(seqLag:backfillElapsed:writeDuration:) -> Bool`.
- `Sources/SwanSQLite/SQLiteFirehoseDatabase.swift` — add `public func retainedFromSeq() async throws -> Int64?` (reads `firehose_meta.retained_from_seq`; `nil` while Phase 1/2 never advances it). No schema change.
- Tests: new `Tests/SwanHTTPTests/PublicFirehoseStreamingTests.swift` (unit-level; no HTTP).

**Key APIs:** `SQLiteFirehoseDatabase.events(after:limit:)` (limit ≤ 1_000, cursor ≥ 0), `maxSequencedSeq()`, `FirehoseStoredEvent.frameBytes`; `FirehoseFrameEncoder.errorFrame/infoFrame`; `PublicFirehoseWakeupSink`.

**Tests:**
- `testCursorPolicyMatrix` — no cursor/live; 0/fullWindow; mid-window backfill; cursor == max; cursor > max → futureCursor; cursor < retained → outdatedCursor; cursor == retained → backfill.
- `testTailerBackfillThenLiveHasNoGapOrDuplicateAtBoundary` — seed events 1..5 into a real `SQLiteFirehoseDatabase` (temp dir), run tailer from cursor 3 against a recording outbound + injected wakeup; assert exactly 4,5 then a wakeup-appended 6 (no re-send).
- `testTailerShipsStoredFrameBytesVerbatim` — appended frame bytes equal delivered bytes exactly.
- `testTailerDroppedWakeupRecoversByPoll` — wakeup never fires; the idle poll still delivers a late append (inject `idlePollInterval` small).
- `testTailerConsumerTooSlowPolicy` — pure policy checks with injected zero/tiny bounds (lag, backfill budget, write duration).
- `testTailerCancellationExitsPromptly` — cancel the loop task mid-idle; returns without delivering.
- `testWakeupHubCoalescingAndFanOut` — N subscribers all observe the bump; burst appends coalesce to bufferingNewest(1).
- `testFirehoseRetainedFromSeqAccessor` (SwanSQLiteTests) — `nil` on a fresh DB; row present with value (raw SQL insert) returns it.

**Verification:**
```bash
xcrun swift build
xcrun swift test --filter PublicFirehoseStreamingTests
xcrun swift test --filter SQLiteFirehoseDatabase
```

**Acceptance criteria:** all unit tests pass; the tailer never calls any HTTP type; `PublicFirehoseWakeupHub` is the only fan-out primitive in `Sources/`.

## Task 3: Endpoint + framing

**Objective:** the ws route exists on the real router, the server accepts upgrades, cursor parsing and upgrade-path behavior are correct, frames are strict binary.

**Files:**
- `Sources/SwanHTTP/SwanHTTP.swift`:
  - `SwanHTTPRequestContext` (18–54): add `public let webSocket: WebSocketHandlerReference<SwanHTTPRequestContext>` (init in `init(source:)`) and `extension SwanHTTPRequestContext: WebSocketRequestContext {}` (logger already available).
  - `SwanHTTPServer` (296+): new optional stored property `public let publicFirehoseStreaming: SwanPublicFirehoseStreamingRuntime?` + init parameter (mirroring `publicRepositoryMutationDirectory`).
  - `buildRouter()` (686–947): when `publicFirehoseStreaming != nil`, register the ws route (D2); keep everything else unchanged.
  - `buildApplication()` (985–1007): `.http1` → `.http1WebSocketUpgrade(webSocketRouter: buildRouter()/router, configuration: .init(http1: <existing additionalChannelHandlers + idleTimeout>, ws: .init(maxFrameSize: 5_000_000, autoPing: .disabled, closeTimeout: .seconds(15), validateUTF8: true)))` (build the router once and reuse — note the current code calls `buildRouter()` inline; hoist to a local).
- New `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift`:
  - `public struct SwanPublicFirehoseStreamingRuntime: Sendable` — `database: SQLiteFirehoseDatabase`, `hub: PublicFirehoseWakeupHub`, `limits: PublicFirehoseStreamingLimits`.
  - `func registerPublicFirehoseStreamingEndpoint(on router: Router<SwanHTTPRequestContext>, runtime: …)` — `router.ws("/xrpc/com.atproto.sync.subscribeRepos", shouldUpgrade: { request, _ in … })`:
    - no `Upgrade: websocket` header → `.dontUpgrade`;
    - strict cursor parse (D7) — malformed → `.dontUpgrade`;
    - else `.upgrade([:])`;
    - `onUpgrade: { inbound, outbound, wsContext in … }`: resolve cursor policy (needs one `maxSequencedSeq()` and `retainedFromSeq()` read); send `FutureCursor` error frame + close; send `OutdatedCursor` info frame when applicable; then spawn two child tasks — inbound drain (iterate `inbound` to process client close/ping frames) and the tailer loop fed by `hub.subscribe()`; cancel the sibling when either ends.
- `Tests/SwanHTTPTests/PublicFirehoseStreamingHTTPTests.swift` — `.live` tests; fixture mirrors `RemoteOAuthAuthorizationServerHTTPTests.makeFixture` plus a temp-directory `SQLiteFirehoseDatabase` + `PublicFirehoseWakeupHub` injected via `SwanHTTPServer.init`; client via `HummingbirdWSTesting` (`client.ws(...)`) with a raw-binary handler.
- `Tests/SwanHTTPTests/FirehoseStreamingTestCBORReader.swift` — minimal strict two-object reader (header `op`/`t`, body; rejects trailing bytes) per D5.

**Tests:**
- `testSubscribeReposUpgradeSucceedsAndReceivesFrames` — connect, append 2 events via the in-process DB, read exactly 2 binary frames, decode header `op: 1` / `t: #commit`.
- `testSubscribeReposFrameBytesMatchStoredBytesVerbatim`.
- `testSubscribeReposPlainGetIsNotUpgraded` — 405, no upgrade.
- `testSubscribeReposMalformedCursorRejectsUpgrade` — `?cursor=abc`, `?cursor=-1`, `?cursor=99999999999999999999999` → failed upgrade (close), never a websocket.
- `testSubscribeReposUnknownPathUpgradeFails` — upgrade to `/xrpc/com.atproto.sync.getRepo` → 400/close, no websocket.
- `testSubscribeReposRouteAbsentWhenRuntimeMissing` — server without `publicFirehoseStreaming` → plain GET 404 (wildcard guard).
- `testSubscribeReposInboundDrainKeepsLoopAlive` — client sends a binary message; server loop continues delivering (no crash, no close).
- `testSubscribeReposClientCloseEndsTailer` — client closes; server loop exits; no leaks (assert via logging-free observation of a subsequent append not being written to a dead connection — i.e., tailer task completes).
- `testWebSocketMaxFrameSizeAtLeastFrameLimit` — `HTTP1WebSocketUpgradeChannel.Configuration.ws.maxFrameSize >= FirehoseFrameLimits.maximumFrameBytes` (unit assertion against the built configuration).

**Verification:**
```bash
xcrun swift build
xcrun swift test --filter PublicFirehoseStreamingHTTPTests
```

**Acceptance criteria:** upgrades succeed only for the exact path with a well-formed cursor; every delivered data frame is one binary WebSocket message containing the stored `frame_bytes`; plain GET / malformed cursor / unknown path behaviors match D2/D7; `swift build` clean under Swift 6 strict concurrency.

## Task 4: Cursor semantics + slow-consumer integration matrix

**Objective:** the design-doc cursor matrix and slow-consumer behavior proven over a real listener with the pinned strict frame decoder.

**Files:** extend `Tests/SwanHTTPTests/PublicFirehoseStreamingHTTPTests.swift` (no production changes expected).

**Tests:**
- `testSubscribeReposNoCursorStreamsLiveOnly` — seed 3 events before connect; connect without cursor; append 2 more; assert only the 2 live events arrive.
- `testSubscribeReposCursorZeroStreamsEntireWindow` — seed 3; `?cursor=0`; all 3 arrive in seq order, then live appends.
- `testSubscribeReposBackfillThenLiveBoundaryNoGapNoDuplicate` — seed 1..5; `?cursor=3`; assert 4,5 then live 6 with no duplicate 4/5 and no missing 6 (the design-doc boundary requirement, line 288–289; strictly-after semantics, lines 294–300).
- `testSubscribeReposCursorEqualsMaxYieldsNothingThenLive`.
- `testSubscribeReposFutureCursorErrorFrameAndClose` — `?cursor=<max+10>` → error frame `{"op":-1,"error":"FutureCursor"}` then close (assert close frame received).
- `testSubscribeReposOutdatedCursorDormantInPhase2` — `retainedFromSeq()` is `nil`; `?cursor=1` with empty/older state behaves per policy (backfill); the `OutdatedCursor` branch is exercised at the policy-unit level (Task 2) until Phase 3.
- `testSubscribeReposConsumerTooSlowErrorFrameAndClose` — runtime with `maximumSequenceLag = 0` (or `.zero` backfill budget); seed ≥ 2 events; connect with `cursor=0`; assert error frame `{"op":-1,"error":"ConsumerTooSlow"}` then close.
- `testSubscribeReposTwoConnectionsIndependentCursors` — two clients with different cursors see independent streams; one close does not affect the other.
- `testSubscribeReposLostWakeupLosesNothingOverHTTP` — pause delivery (don't read), append 3, resume reading; all 3 arrive in order (poll recovery), then close.

**Verification:**
```bash
xcrun swift test --filter PublicFirehoseStreamingHTTPTests
```

**Acceptance criteria:** full matrix green; each test asserts frame order, exact bytes, and close-frame behavior; no timing-dependent assertions (bounds are injected, not waited on).

## Task 5: Wiring + integration + docs

**Objective:** the feature flag wires the hub into the sequencer and the runtime into the server; CLI/service-lifecycle integration is covered; completion record written.

**Files:**
- `Sources/swan/SwanCommand.swift`:
  - ~1523–1527: extend the `--enable-public-firehose` help text ("…and serves `com.atproto.sync.subscribeRepos` WebSocket streaming").
  - ~2172–2195: create `PublicFirehoseWakeupHub()` before the sequencer; pass `wakeup: hub` (replacing `nil` at 2182); build `SwanPublicFirehoseStreamingRuntime(database: hub:)` and pass it to `SwanHTTPServer.init` (the `server` construction site) via the new optional parameter.
  - Shutdown paths (2366–2383): unchanged — `preopenedFirehoseDatabase.close()` already runs after the service group; the hub has no resources. Verify no other exit path needs the hub.
- `Sources/SwanHTTP/SwanPublicFirehoseSequencerService.swift` — unchanged (sequencer service already appended at 2352–2355).
- Tests:
  - Extend the Phase 1 service-wiring test in `SwanCLITests` (or `SwanHTTPTests` fixture used for wiring): `--enable-public-firehose` starts with the hub wired (assert via a subscribeRepos connection on the live CLI serve) — or, minimally, assert the serve path constructs the runtime without nil-traps (existing wiring test pattern).
  - `SwanPublicWireTests`: ensure `PublicDataTesting20260805` vs `PublicDataTesting20260730` vs `20260727` lists stay disjoint/frozen (extend existing profile tests if any).
- Docs:
  - New: `docs/superpowers/plans/2026-08-04-swan-firehose-phase2-completion-record.md` (structure per the Phase 1 completion record; capture: resolved dependency versions, final limits values, cursor/compat decisions incl. malformed-cursor deviation and close-code choice, the unused single-shot `ServerHandler` note, `retainedFromSeq()` accessor, non-goals delivered as dormant code).
  - Optionally note the Phase 3 hooks (heartbeat, close frames, pruning) in the design doc's Phase 2/3 boundary — no design-doc edits unless a decision above contradicts it.

**Verification (exit gate — run all from the worktree root):**
```bash
xcrun swift build
xcrun swift test --filter PublicFirehoseStreamingTests
xcrun swift test --filter PublicFirehoseStreamingHTTPTests
xcrun swift test --filter PublicFirehose          # Phase 1 suite still green
xcrun swift test --filter SwanSQLiteTests
xcrun swift test --filter SwanHTTPTests
xcrun swift test --filter SwanPublicWireTests
xcrun swift test                                  # complete suite
PETREL_GENERATOR_ROOT=/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel-swan-generator ./Scripts/verify-public-wire-generation.sh
PETREL_GENERATOR_ROOT=/Users/joshlacalamito/Developer/Catbird+Petrel/Petrel-swan-generator ./Scripts/test-public-wire-generation.sh
```

**Acceptance criteria:** full suite green; wire-regime scripts green against the 2026-08-05 profile with 2026-07-30 immutable; completion record committed; `--enable-public-firehose` documented as serving the endpoint (default-off preserved).

---

## Risks and mitigations

- **R1 — Profile-regime fragility (HIGH, mechanical).** Every constant in `public-wire-generation-common.sh` is a hard gate: wrong sha256s, a miscounted list (20/21/23/24, 18/19), or a byte-diff in the 2026-07-30 legacy trio fails the entire CI gate. Mitigation: do the regenerate in Task 1 Step 3 first against a scratch copy, diff the output, then write the real constants; run both `verify` and `test` scripts locally before committing; never hand-edit generated sources. The 2026-07-30 trio must not change during Phase 2 — freeze it the moment the successor profile lands (same commit).
- **R2 — hummingbird-websocket version/API drift (MEDIUM).** 2.7.0 is the current release (requires hummingbird ≥ 2.24.0; pinned 2.25.1 satisfies it); all APIs in this plan were read from the 2.7.0 tag sources (`WebSocketRouter.swift`, `WebSocketChannel.swift`, `WebSocketServerConfiguration.swift`, WSCore `WebSocketDataHandler`/`WebSocketOutboundWriter`/`WebSocketInboundStream`, `HummingbirdWSTesting`). Residual risk: package resolution ordering with `swift-nio-extras`/`swift-websocket` (unpinned transitives) and any platform quirk of `@_exported import WSCore`. Mitigations: exact `2.7.0` pin, commit `Package.resolved`, add exact pins for the two transitives if resolution misbehaves, keep the fallback WS test client (D5). HummingbirdTesting `.router` mode cannot test upgrades — `.live` only (documented, and existing tests already use `.live`).
- **R3 — Generator capability boundary (MEDIUM, now resolved).** Verified by execution that the pinned generator emits the subscription descriptor/Message union/client method, and that only the server-handler shape is single-shot (dead code, D3). If a later phase insists on a streaming generated contract, the documented path is a generator change + repin (D3 alternative (a)) — explicitly out of scope here.
- **R4 — Shutdown semantics (LOW, deliberate).** Phase 2 sends no close frames on graceful shutdown and no pings; a restart will appear as an abnormal closure to subscribers. Deliberate per design-doc Phase 3 boundary; subscriber loops exit on cancellation promptly (tested). A relay relying on graceful-close detection is a Phase 5 acceptance item.
- **R5 — Compat deviations (LOW, flagged).** (a) Strict malformed-cursor rejection vs reference tolerance; (b) `ConsumerTooSlow` close code `.normalClosure` vs any reference preference; (c) strictly-after cursor resumption (already recorded as the P0 compatibility decision in the design). All three are surfaced in the profile's `intentionalDivergences`/completion record and re-verified at Phase 5 relay acceptance.
- **R6 — `maxFrameSize` misconfiguration (LOW).** Default is 16 KiB; any real `#commit` (up to 5 MB) would fail the connection. Mitigated by an explicit configuration and the unit assertion `testWebSocketMaxFrameSizeAtLeastFrameLimit`.
- **R7 — Slow-consumer timing flakiness (LOW).** Integration tests use injected zero/tiny bounds and seeded data, never wall-clock waits; the policy itself is a pure function with unit tests.
- **R8 — Concurrent SQLite readers (LOW).** Many connections polling the same `firehose.sqlite` actor serialize through the existing connection gate; page size and poll interval bound the load; the hub prevents wakeup storms (coalesced signals, `.bufferingNewest(1)`).

## Exit gate

Task 5's verification block is the exit gate (exact commands above, run from the worktree root). After it passes:

1. Commit all Phase 2 changes (`jj commit <paths> -m "firehose: phase 2 streaming"` — split per task or one reviewed commit per the repo's convention; never touch history).
2. Write and commit `docs/superpowers/plans/2026-08-04-swan-firehose-phase2-completion-record.md` with the facts in Task 5's docs step: resolved dependency versions, final `PublicFirehoseStreamingLimits` values, the cursor/compat decisions, the dormant `OutdatedCursor`/`retained_from_seq` state, the unused generated `ServerHandler`, and the Phase 3 handoffs (heartbeat, graceful-close frames, pruning, deletion, `requestCrawl`, relay acceptance).
