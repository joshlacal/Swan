# SwanHTTPTests process-kill fix: `Deinited NIOAsyncWriter without calling finish()`

Date: 2026-08-12
Scope: `Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift`

## Symptom

`xcrun --toolchain XcodeDefault swift test` exited 1 with zero failed test cases. The
`SwanHTTPTests` xctest process died with

```
NIOCore/NIOAsyncWriter.swift:177: Fatal error: Deinited NIOAsyncWriter without calling finish()
... SwanHTTPTests.xctest exited with unexpected signal code 5
```

on `testParserRefusedQueryBytesNeverReachTheHandler`. Because it is a `preconditionFailure`
and not an assertion, every case that would have run after it in the target was silently
skipped while the usual `Test Case '...' failed` count stayed at zero.

## Root cause

### Which writer, and whose

The unfinished writer belonged to the **in-process Hummingbird server harness** — specifically
to the `NIOAsyncChannel` that `HTTP1Channel.setup(channel:)` builds for an *accepted client
connection*. Not the test client (`HummingbirdTesting.TestClient` is a plain NIO pipeline and
owns no `NIOAsyncWriter`), and not the pipethrough's upstream stub (`RecordingProxySender` never
touches NIO).

The backtrace names the exact release point:

```
1  NIOAsyncWriter.InternalClass.deinit                 NIOAsyncWriter.swift:177
...
5  NIOAsyncChannelHandler.channelActive(context:)      AsyncChannelHandler.swift:139
...
24 BaseSocketChannel.becomeActive0(promise:)
25 closure #1 in closure #1 in ServerSocketChannel.channelRead0(_:)   SocketChannel.swift:421
```

`NIOAsyncChannelHandler` deliberately retains the writer until `channelActive`, at which point
NIO cedes ownership to whoever received the `NIOAsyncChannel`:

```swift
func channelActive(context: ChannelHandlerContext) {
    // Drop the writer ref, the caller is responsible for it now.
    self.writer = nil
    context.fireChannelActive()
}
```

If nobody else is holding that `NIOAsyncChannel` by then, `self.writer = nil` is the last
release, and `InternalClass.deinit` traps because `finish()` was never called.

### Which teardown edge skips `finish()`

The child `NIOAsyncChannel` is delivered to the server task through the *listening* channel's
async inbound stream. `NIOAsyncChannelHandler._deliverReads` drops buffered elements outright
when that stream's source is already gone:

```swift
guard let source = self.source else {
    self.buffer.removeAll()   // the accepted child NIOAsyncChannel is dropped here
    return
}
```

The source is finished when the listening channel goes inactive — which is what happens when
the service group is **cancelled** rather than gracefully shut down.

The full chain for this test:

1. Each loop iteration builds a fresh `Application` and calls `.test(.live)`. The framework
   fires `client.connect()` and then runs the body.
2. The body's only request carries a byte the HTTP/1 parser refuses, so `client.execute`
   throws instead of completing a round trip. **No request is ever served on that connection.**
3. Throwing out of the `.test(.live)` body propagates out of `LiveTestFramework.run`'s
   `withThrowingTaskGroup`, which cancels the `ServiceGroup` task — a hard cancel, not
   `triggerGracefulShutdown`. The logs show this as
   `Waiting on child channel: CancellationError()` and `Server shutdown error: Already closed`.
4. The listening channel closes; its inbound source finishes.
5. The TCP handshake had already completed in the kernel, but the server event loop had not yet
   run the accept through the pipeline. It now does: the child channel initializer builds a
   `NIOAsyncChannel` (writer created, never finished), `_deliverReads` finds `source == nil` and
   drops it, and `becomeActive0` → `channelActive` releases the last reference → trap.

So the window is exactly "connection accepted but not yet delivered, at the instant the server
is cancelled". It only opens for a test that never completes a round trip on its connection.
Every other test in the target completes at least one request, which is why the crash landed on
this one, and why running the target alone hit it only ~1 in 3 while the full suite (more load,
slower event loops, wider window) hit it every time.

### Test harness or production code?

The fault is in **third-party library code** (`swift-nio` `NIOAsyncChannelHandler` +
`hummingbird` `Server.run`), reached through a **test-harness ordering bug**. There is no Swan
production code on the path — `Sources/SwanHTTP` creates no `NIOAsyncChannel` and no
`NIOAsyncWriter`, and the failing edge is the accept path of Hummingbird's own server.

The same race is theoretically reachable in the running server: `Sources/swan/SwanCommand.swift`
puts the public application in a `ServiceGroup` alongside firehose/recovery services
(`SwanHTTPServiceLifecycle.makeServiceGroup`), and if any of those throws, ServiceLifecycle
cancels the group — the same hard-cancel edge. A connection accepted at that instant would trap
the process. This is a fault-during-fatal-shutdown, and fixing it means an upstream patch to
`NIOAsyncChannelHandler._deliverReads` (finish dropped writers instead of dropping them) or
vendoring Hummingbird, both far outside this change. It is recorded here as a known upstream
hazard, not remediated.

## What changed

One test, `testParserRefusedQueryBytesNeverReachTheHandler`. Each loop iteration now completes a
well-formed request on the connection *before* sending the refused bytes:

```swift
try await client.execute(uri: "/xrpc/com.example.unknown.method", method: .get) { response in
    XCTAssertEqual(response.status, .notFound, "for query \(query)")
}
```

`com.example.unknown.method` is an unrouted namespace, so it answers 404 from Swan itself and
never contacts upstream — `sender.recorded().count == 0` is untouched.

This closes the race at its source: a completed response proves the accept has already been
delivered to the server's inbound stream and is being served, so there is no undelivered child
channel left to drop when the subsequent throw cancels the group.

It also strengthens the test rather than weakening it. Previously "not delivered" could be
satisfied by a connection the server never served at all, which is a vacuous pass; now the
assertion reports on bytes a live, reading server saw and refused. **No assertion was loosened,
skipped, or removed.** The security property — parser-refused query bytes never reach the
handler, and nothing leaves this host — is asserted exactly as before, plus the guard-level
`isPercentEncodedQuery` checks.

### Diagnosis method

A throwaway probe (since removed) reproduced the crash deterministically outside the real test:
300 iterations of "fresh Application, one refused request, no round trip" crashed on all 3 runs;
the identical loop with a completed warm-up request survived 300 iterations × 3 runs with zero
crashes. That is what established the accept-during-cancel window as the cause rather than
anything in the pipethrough code.

## Verification

**1. Build**

`xcrun --toolchain XcodeDefault swift build --build-tests` — `Build complete!`

**2. Filtered target, five consecutive runs**

`xcrun --toolchain XcodeDefault swift test --skip-build --filter 'SwanHTTPTests.SwanXRPCPipethroughTests'`

| run | exit | `passed` lines | `failed` lines | `Fatal error` | `Some test targets reported failures` |
|-----|------|----------------|----------------|---------------|----------------------------------------|
| 1 | 0 | 31 | 0 | 0 | 0 |
| 2 | 0 | 31 | 0 | 0 | 0 |
| 3 | 0 | 31 | 0 | 0 | 0 |
| 4 | 0 | 31 | 0 | 0 | 0 |
| 5 | 0 | 31 | 0 | 0 | 0 |

The filter matched: 31 test cases per run, the expected count.

For contrast, the pre-fix baseline on the same command: run 1 exited 1 with only 18 passed
cases and a `Fatal error` line; runs 2–6 exited 0 with 31.

**3. Full suite**

`xcrun --toolchain XcodeDefault swift test --skip-build` redirected to a file (no `tail` in the
pipeline):

- process exit code: **0**
- `grep -c 'Some test targets reported failures'` → **0**
- `grep -c 'unexpected signal code'` → **0**
- `grep -c 'Fatal error'` → **0**
- passed cases, counted as `Test Case '-[...]' passed` lines: **1420**
- failed cases: **0**
- `SwanHTTPTests.xctest` suite: passed; all 11 xctest targets passed; `Test Suite 'All tests' passed`

1420 vs the previously reported 1389 is the truncated tail of `SwanHTTPTests` now running.

## Constraints observed

- No `swiftformat` was run.
- No bare `swift build` / `swift test`; every invocation used `xcrun --toolchain XcodeDefault`,
  and `--skip-build` only ever followed a `--build-tests` build.
- 4-space indentation, matching the file.
- No `@unchecked Sendable` or `nonisolated` was added.
- Nothing outside `Tests/SwanHTTPTests/SwanXRPCPipethroughTests.swift` was modified.
