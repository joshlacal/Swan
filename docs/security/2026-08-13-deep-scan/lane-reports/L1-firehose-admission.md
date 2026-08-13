# L1 — firehose admission

Closes **F11**, **F05**, **F33**, and **F13's route half**. Every claim below was
re-verified against the tree at `75e7b509` and against the pinned checkouts
before it was acted on; where the program document and the source disagreed,
the source is what is recorded here.

Files touched (the lane's five, nothing else):

- `Sources/SwanHTTP/SwanHTTP.swift`
- `Sources/SwanHTTP/PublicFirehoseStreamingRoute.swift`
- `Sources/SwanHTTP/PublicFirehoseStreaming.swift`
- `Sources/SwanHTTP/PublicFirehoseSubscriberAdmission.swift` (new)
- `Tests/SwanHTTPTests/PublicFirehoseStreamingHTTPTests.swift`

---

## F11 — inbound frame budget

**Verdict: CONFIRMED, and the program's reasoning is right with one correction
to its stated mechanism.**

Verified before changing the literal:

- `WebSocketServerConfiguration.maxFrameSize` reaches `NIOTypedWebSocketServerUpgrader`
  (`hummingbird-websocket/Sources/HummingbirdWebSocket/WebSocketChannel.swift:278`),
  which passes it to exactly one place —
  `ByteToMessageHandler(WebSocketFrameDecoder(maxFrameSize:))` at
  `swift-nio/Sources/NIOWebSocket/NIOWebSocketServerUpgrader.swift:325`. The
  decoder enforces it in `validateState(maxFrameSize:)`
  (`swift-nio/Sources/NIOWebSocket/WebSocketFrameDecoder.swift:200-206`).
- **Correction to the program.** The value is *not* passed "solely to
  `WebSocketFrameDecoder`". Hummingbird also threads it into
  `WebSocketHandler.Configuration`
  (`hummingbird-websocket/.../WebSocketChannel.swift:120, 210`), and
  `WebSocketHandler.handle` hands it to the outbound writer
  (`swift-websocket/Sources/WSCore/WebSocketHandler.swift:175`). So there *is*
  an outbound consumer of the value. The conclusion survives, because the
  outbound consumer that matters is method-specific:
  `WebSocketOutboundWriter.write(_:)`
  (`swift-websocket/Sources/WSCore/WebSocketOutboundWriter.swift:30-47`) emits a
  single `fin: true` frame and never reads `maxFrameSize`, while
  `writeBinaryMessage` (`:55-71`) is the one that fragments against it. Swan's
  tailer calls the former (`PublicFirehoseStreamingRoute.swift:498-500`), and
  `WebSocketHandler.write(frame:)` (`WebSocketHandler.swift:264-283`) performs
  no size check of its own. Lowering the literal therefore cannot truncate or
  fragment a `#commit`.
- That distinction is precisely why the second test the program asked for is the
  load-bearing one: the hazard is a future switch to `writeBinaryMessage`, which
  would start silently fragmenting every `#commit` above 4 KiB.

**Built.** `SwanHTTP.swift:1205` is now `maxFrameSize: 4_096`. The doc comment
above it (`:1181-1200`) was rewritten: the old text asserted the value "must
cover the largest stored firehose frame … the 16 KiB default would fail every
real `#commit` with `messageTooLarge`", which is false for the outbound
direction and would have talked the next reader out of the fix.

**Tests.** `testWebSocketMaxFrameSizeAtLeastFrameLimit` (which encoded the wrong
invariant) is replaced by:

- `testWebSocketMaxFrameSizeBoundsInboundClientFrames` — pins 4096 and pins that
  it is *below* `FirehoseFrameLimits.maximumFrameBytes`, so the old assertion
  cannot be reintroduced.
- `testOutboundCommitFramesAboveMaxFrameSizeArriveUnfragmented` — appends a
  65,744-byte `#commit` (64 KiB `diffCAR`), streams it over a live listener, and
  asserts one `.binary` frame with `fin == true`, byte-identical to the stored
  frame, with no `.continuation` frame anywhere on the wire.

**Pre-fix failures, observed:**

```
PublicFirehoseStreamingHTTPTests.swift:1573: XCTAssertEqual failed:
  ("5000000") is not equal to ("4096")
PublicFirehoseStreamingHTTPTests.swift:1578: XCTAssertLessThan failed:
  ("5000000") is not less than ("5000000")
PublicFirehoseStreamingHTTPTests.swift:1613: XCTAssertGreaterThan failed:
  ("65744") is not greater than ("5000000")
  - the fixture frame must exceed the inbound budget or this proves nothing
```

The third is the guard assertion refusing to let the unfragmented test claim
anything while the budget was still 5 MB.

---

## F05 — `subscribeRepos` admission

**Verdict: CONFIRMED, high, and the mechanism is exactly as the program states.**

Re-verified:

- `publicFirehoseUpgradeDecision` (`PublicFirehoseStreamingRoute.swift:177-231`
  at parent) is purely syntactic — upgrade header, no fragment, ≤8 KiB query, at
  most one strictly decimal `cursor`. No identity, no capacity.
- `buildRouter()` constructs `Router(context: SwanHTTPRequestContext.self)` with
  no middleware (`SwanHTTP.swift:760` at parent).
- `PublicFirehoseWakeupHub.subscribeWithFinish()` inserts unconditionally
  (`PublicFirehoseWakeupHub.swift:66`, read only — not edited).
- The decisive asymmetry: `AvailableConnectionsHandler.channelRead` calls
  `delegate.connectionOpened()` and registers the refund on
  `channel.closeFuture`
  (`hummingbird/Sources/HummingbirdCore/Server/AvailableConnectionsHandler.swift:98-112`);
  `read(context:)` returns **without** calling `context.read()` once the
  delegate stops accepting (`:117-123`). An upgraded WebSocket never closes on
  its own, so the accept socket stops being read for the whole listener.

**Built.**

- `Sources/SwanHTTP/PublicFirehoseSubscriberAdmission.swift` — a lease
  admission modelled on `PublicRepositoryJSONReadAdmission`
  (`SwanStorage/PublicRepositoryReadDirectory.swift:554-621`), using
  `Synchronization.Mutex` rather than the `NSLock`/`@unchecked Sendable` shape,
  which that type's own comment lists as the intended follow-up. `reserve()`
  returns `nil` when full; the lease is idempotent and refunds from `deinit` as
  well as from an explicit `release()`.
- Sizing lives in `SwanHTTPServer.init`
  (`SwanHTTP.swift:503-506`): `PublicFirehoseSubscriberAdmission(listenerBudget:
  configuration.maximumConnections)` → `max(1, budget / 4)` = **64 of 256**. It
  is sized there and not inside `SwanPublicFirehoseStreamingRuntime` because
  `maximumConnections` is what the reservation is a fraction *of*, and because
  the runtime is constructed in `Sources/swan/SwanCommand.swift`, which is L9's
  file — this lane changes no call site there.
- Acquisition is the first statement of `publicFirehoseOnUpgrade`
  (`PublicFirehoseStreamingRoute.swift:313-314`), with `defer { lease?.release() }`
  as the single release site — before the two cursor reads, before the hub
  subscription, and before either long-lived task. A refusal closes with
  **1013** (`:292`, `:335`) and emits a paired open/close observation with the
  new `CloseReason.subscriberCapacity`, so a refusal is visible to operators
  without being visible on the lexicon.
- `PublicFirehoseStreaming.swift:260-293` adds `writeWithinDeadline`, which
  races each `outbound(row.frameBytes)` against
  `Task.sleep(for: limits.maximumWriteDuration)` in a task group and throws
  `PublicFirehoseTailerError.writeTooSlow` when the sleeper wins. The post-hoc
  `writeDuration > limits.maximumWriteDuration` comparison it replaces bounded
  nothing: the case worth bounding is a write suspended inside the page, which
  never returns, so the comparison never ran. `run(lastSent:outbound:waitForWakeup:)`
  now takes `@escaping @Sendable` for `outbound` — required to hand it to a
  child task. All nine existing call sites in
  `Tests/SwanHTTPTests/PublicFirehoseStreamingTests.swift` (not a lane file)
  pass actor calls or `XCTFail` and compile unchanged.

**Rejected:**

- **A new `#error` name.** The lexicon defines only `FutureCursor` and
  `ConsumerTooSlow`; a new name is wire-visible and a relay may treat it as
  fatal rather than retryable. The program's stated fallback (1013) is
  reversible; taken.
- **Reserving in `shouldUpgrade`.** There is no release site there, and
  `.dontUpgrade` hard-codes 405
  (`hummingbird-websocket/Sources/HummingbirdWebSocket/WebSocketRouter.swift:92-93`).
- **A ceiling instead of a reservation.** A cap at `maximumConnections` would
  refuse the 257th subscriber and still let 256 subscribers stop `accept()`.
- **A per-peer quota** (the scan's boilerplate remediation). Every socket on the
  deployed box arrives from a Cloudflare address; the only usable identity is
  the `X-Swan-Client-IP` header, and the global reservation is the control that
  actually holds. This matches §2 of the program.

**How the reservation was proven to leave HTTP servable.**
`testSaturatedFirehoseReservationRefusesSurplusAndLeavesHTTPServable` builds a
live listener with `maximumConnections: 8` and a 2-slot firehose reservation,
holds both slots with real WebSocket subscribers, and then asserts, in order:

1. `snapshot == (activeSubscribers: 2, maximumConcurrentSubscribers: 2)`;
2. a third subscriber is closed with `.unknown(1013)` and receives **zero**
   firehose frames;
3. `hub.subscriberCount() == 2` — the refused socket never reached the hub;
4. **`GET /health` on the same listener still returns 200 `OK` while every
   firehose slot is held** — this is the property the fix exists for, not the
   refusal;
5. after both subscribers disconnect, `activeSubscribers` returns to 0.

`testFirehoseReservationLeavesThreeQuartersOfTheListenerBudget` states the
sizing as arithmetic (`256 − 64 == 192`) rather than as a literal at the call
site, and `testDisconnectedSubscriberRefundsItsReservation` pins the refund, so
the reservation cannot decay into a permanent lockout after the first 64
connections of a process's life.

**How the write deadline was proven to be a deadline.** The old and new shapes
both throw `writeTooSlow` for a write that takes 2 s under a 50 ms limit — the
thrown error does not distinguish them, so a test that only asserted the error
would have passed against the defect.
`testSlowOutboundWriteIsDroppedAtTheDeadlineNotAfterTheWrite` asserts the
*elapsed* time instead: it drives a real `PublicFirehoseTailer` with an
`outbound` that sleeps 2 s under a 50 ms limit, and requires the throw to land
in under 1 s. It completes in **0.082 s**; under the post-hoc comparison it
would have taken ~2 s. The genuinely unbounded case — a write that never
returns — is unreachable by the old code by construction, since control never
gets past the write to the comparison at all.

**Pre-fix failure, observed** (route accepting the admission but not consulting
it):

```
PublicFirehoseStreamingHTTPTests.swift:1624: XCTAssertEqual failed:
  ("Snapshot(activeSubscribers: 0, maximumConcurrentSubscribers: 2)")
  is not equal to ("Snapshot(activeSubscribers: 2, maximumConcurrentSubscribers: 2)")
PublicFirehoseStreamingHTTPTests.swift:1673: failed: caught error: "DeadlineExceeded()"
```

The second line is the surplus subscriber being admitted and streaming
indefinitely instead of being refused.

---

## F33 — lifecycle journal throttling

**Verdict: CONFIRMED as resource exhaustion.** The scan's own
`authorization-state-race` category and its remediation string (C12's
"linearize lifecycle/generation authorization") are both mis-assigned, as the
program says; neither was executed.

`PublicFirehoseSubscriptionObservation.log(to:)` wrote one `.info` line per open
and one per close, with no window of any kind, from an anonymous route.

**Built.** `PublicFirehoseStreamingRoute.swift:146` declares
`publicFirehoseDiagnosticThrottle` — its **own** `PublicReadDiagnosticThrottle`
instance with a 1-second window, deliberately not the public-read routes'
instance at `SwanPublicRepositoryReadXRPC.swift:1468` (read only; not edited).
Sharing one would let anonymous subscribe churn spend the suppression budget
that keeps a real public-read refusal visible. The type is reused rather than
re-implemented; the instance is not.

The key is `diagnosticKey` — `(cursorMode)` for an open and
`(closeCategory, closeReason)` for a close, crossed with `event` by the
throttle's own `method|reason` composition. It **excludes `connectionID`**,
which is a fresh UUID per socket and is exactly what made every record
unsuppressable. Suppressed repeats are folded into the next line as
`suppressed_repeats`, matching the sibling.

**Tests.** `testLifecycleDiagnosticKeyIgnoresConnectionIdentity` proves two opens
differing only in connection id collapse to one key and that the second is
suppressed, while a different cursor mode is admitted immediately in the same
window. `testConnectionChurnDoesNotSetTheJournalGrowthRate` runs 8 real
connect/stream/disconnect cycles through the live route with the **production**
observer and asserts the journal took ≤4 lines for 16 lifecycle records.

---

## F13 — route half

**Verdict: CONFIRMED, and a no-op today, as the program states.**

`SwanHTTP.swift:894-895` now iterates
`PermissionedData0016.methods.filter { profile.endpoints.contains($0.nsid) }`.
Both checked-in permissioned profiles carry the same 25 NSIDs, so nothing
changes on the deployed configuration. The `:980` unavailable-gate else branch
and the `:989` unknown-method guard are untouched, so a filtered-out method
falls through to `permissionedEndpointUnavailable()` (404) rather than to a bare
router 404.

**Test.** `testPermissionedRoutesFollowTheSelectedProfile` takes the real
`Profiles/permissioned-data-0016-2026-07-03.json`, removes one query endpoint
that no `intentionalDivergence` references, re-decodes it through
`ProtocolProfile(data:)`, and asserts the dropped NSID answers 404 while a
retained sibling still answers the method-correct 503. Without the filter the
dropped NSID answers 503 — i.e. Swan advertises as "pending" a method the
selected profile does not declare. The test lives in the firehose test file only
because lane ownership put `SwanHTTP.swift` in L1; a comment says so.

---

## Maintainer decisions hit

1. **1013 is not universally treated as backpressure by Swift peers.** The
   program's recommendation is sound and is what shipped, but
   `WebSocketStateMachine.receivedClose`
   (`swift-websocket/Sources/WSCore/WebSocketStateMachine.swift:71-83`) treats
   any `.unknown(code)` outside 3000–4999 as a **protocol error** and echoes
   `.protocolError`. A swift-websocket-based consumer therefore records the
   1013 correctly in its own close frame but answers with a protocol-error
   close. Practical impact on a refused subscriber is nil — Swan has already
   closed — but if a Swift-based `subscribeRepos` consumer is ever written
   against swan.place, it will log the refusal as a protocol violation rather
   than as backpressure. The alternative that avoids this is a code in
   4000–4999, which is "reserved for private use" and is *less* standard than
   1013. No change made; recording it because it is the one thing about the
   1013 default that is not obvious from the program's framing.
2. **§4 item 3 (F11 wire behaviour) still needs Josh.** Nothing in-repo sends a
   client-to-server data frame on `subscribeRepos`, and the protocol defines
   none, but swan.place carries live federated traffic. The change is one
   literal and is trivially reversible.
3. The default reservation (§4 item 2) was taken at the recommended 25%.
   `--max-connections` remains L9's item; an operator still has no knob for
   either number.

## Controls the program did not credit, and which were left alone

- The **inbound drain** at `PublicFirehoseStreamingRoute.swift:338` was not
  given a per-session byte or rate budget. With `maxFrameSize` at 4096 the
  per-socket decoder buffer is bounded at 4 KiB, and the listener reservation
  now bounds the number of such sockets to 64; adding a second counter would be
  a control for a hole the first two already close.
- `PublicFirehoseWakeupHub` was **not** given a capacity check. It is not a lane
  file, and the reservation already bounds its subscriber dictionary — a
  capacity check there would be a second gate for the same bound, and the test
  asserts a refused subscriber never reaches it.
- The idle tailer's ~2 SQLite reads per 250 ms per connection (the scan's
  amplification claim) is now bounded by the same 64-subscriber reservation. No
  polling change was made.

---

## Verification

- **Toolchain:** `xcrun --toolchain XcodeDefault swift build --build-tests` /
  `swift test --skip-build`. `swiftformat` was never run.
- **Baseline measured in-lane at `75e7b509`:** exit 1, **1488 passed, 1 failed,
  9 skipped**. The single failure is
  `SwanOAuthTests.NIOPeerPinnedOAuthPostTransportTests.testPostTransportRejectsResponseBeyondConfiguredBound`
  — `failed: caught error: "I/O on closed channel"` after 11.8 s, and the error
  line names a source path in `Swan-L3-par-login-admission`, i.e. it is
  concurrent-agent interference on a shared machine, not a property of this
  tree. The program's stated baseline of 1489/0 is what this reduces to with
  that one flake excluded. It is untouched by this lane (no L1 file is in
  `SwanOAuth`).
- **Post-change full suite:** exit **0**, **1497 passed, 0 failed, 9 skipped**,
  **11 targets**, zero occurrences of `Some test targets reported failures`, and
  zero `error:` lines. 1489 (the program's stated baseline) − 1 replaced test
  + 9 new tests = 1497, exactly.
- One earlier attempt at this run exited **143** (SIGTERM) partway through with
  0 failures recorded. That is the machine killing the process under load from
  the sibling lanes, not a result; it was discarded and the run repeated to
  completion rather than reported.

### Linux

Deployment target is Linux x86_64, so macOS green is not sufficient. Three
things had to be worked around before the command in the brief could run at
all, none of them caused by this lane:

1. `Package.swift:25` carries `.package(path: "../Petrel")`, so mounting only
   `Swan-L1-firehose-admission` fails with `the package at '/Petrel' cannot be
   accessed`. The mount must be the workspace root, exactly as `Dockerfile:10-12`
   copies both trees.
2. Stock `swift:6.1-jammy` lacks the system libraries `Dockerfile:4-9` installs.
   A cached `swan-linux-builder:6.1-jammy` image adds `libsodium-dev`,
   `pkg-config`, `libsecret-1-dev`, `libglib2.0-dev` — the same list.
3. `--scratch-path /work/…/.build-linux` keeps Linux artifacts from clobbering
   the macOS `.build`. `.build-*/` is already gitignored. **Note for the next
   agent:** the containerised resolve rewrites `Package.resolved` (it drops
   `swift-configuration`, which resolves only on the macOS platform condition).
   That file is outside this lane, so it was restored with
   `jj restore --from @- Package.resolved`, and the full macOS suite was re-run
   afterwards against the restored tree.

Results:

| Command | Result |
|---|---|
| `swift build` (all sources and products, incl. all four L1 source files) | **Build complete**, exit 0 |
| `swift build --target SwanHTTPTests` (the L1 test file) | **Build of target complete**, exit 0 |
| `swift build --build-tests` (every test target) | exit 1 — **one pre-existing, non-lane error** |

The `--build-tests` failure has exactly one unique error across the whole run:

```
Tests/SwanSQLiteTests/AccountPermanentDeletionSQLiteTests.swift:260:37:
  error: 'async' call cannot occur in a defer body
```

That is `defer { try? await database.close() }`, which the Xcode toolchain
accepts and Swift 6.1 does not. The file is not an L1 file and is unmodified by
this lane (`jj st` lists five source/test files, none in `SwanSQLite`), so this
is a property of the tree at `75e7b509`, not a regression — but it does mean the
brief's `swift build --build-tests` cannot succeed on `swift:6.1-jammy` at
baseline either, and someone should file it. The Sendable-shaped risk that
motivated the Linux gate is covered: every changed source file and the changed
test file compile clean on Linux, including the `@escaping @Sendable` closure
change on `PublicFirehoseTailer.run`.
