import Foundation
import Hummingbird
import HummingbirdTesting
import HummingbirdWebSocket
import HummingbirdWSTesting
import Logging
import NIOCore
import Petrel
import SwanOAuth
import SwanPublicFirehose
import SwanSQLite
import XCTest
@testable import SwanCore
@testable import SwanHTTP

/// `.live`-server coverage for `com.atproto.sync.subscribeRepos`. All WebSocket
/// tests must run against a live listener (the in-process `.router` test has
/// no channel pipeline and cannot upgrade); the HummingbirdWSTesting client
/// connects `ws://localhost:<port>/<path>` and returns the close frame.
final class PublicFirehoseStreamingHTTPTests: XCTestCase, @unchecked Sendable {
  private let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
  private let time = "2026-08-04T12:00:00.000Z"
  private let rev = "3kabcdefghijklmno"
  private let epoch = Date(timeIntervalSince1970: 1_785_844_800)
  private let subscribePath = "/xrpc/com.atproto.sync.subscribeRepos"
  private let logger = Logger(label: "swan.public-firehose-http-tests")

  // MARK: - Fixture

  private struct Fixture {
    let server: SwanHTTPServer
    let firehose: SQLiteFirehoseDatabase
    let hub: PublicFirehoseWakeupHub
    let control: SQLiteControlDatabase
    let root: URL
  }

  private func makeFixture(
    limits: PublicFirehoseStreamingLimits? = nil,
    includeRuntime: Bool = true,
    port: Int = 3_000
  ) async throws -> Fixture {
    let root = FileManager.default.temporaryDirectory
      .appending(path: "swan-firehose-http-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
      at: root,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    let control = try await SQLiteControlDatabase(dataDirectory: root)
    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    let hub = PublicFirehoseWakeupHub()
    do {
      let profile = try ProtocolProfile.load(
        from: packageRoot().appending(
          path: "Profiles/permissioned-data-0016-2026-07-03.json"
        )
      )
      let oauthRuntime = try SwanOAuthRuntime(
        controlStore: control,
        serverKey: Data(repeating: 0x71, count: 32)
      )
      let streamingRuntime: SwanPublicFirehoseStreamingRuntime?
      if includeRuntime {
        streamingRuntime = SwanPublicFirehoseStreamingRuntime(
          database: firehose,
          hub: hub,
          limits: limits ?? PublicFirehoseStreamingLimits.standard,
          logger: logger
        )
      } else {
        streamingRuntime = nil
      }
      let server = SwanHTTPServer(
        profile: profile,
        configuration: .init(host: "127.0.0.1", port: port),
        oauthRuntime: oauthRuntime,
        publicFirehoseStreaming: streamingRuntime
      )
      return Fixture(
        server: server,
        firehose: firehose,
        hub: hub,
        control: control,
        root: root
      )
    } catch {
      try? await control.close()
      try? await firehose.close()
      throw error
    }
  }

  private func commitItem(sourceKey: String, seed: UInt8) -> FirehoseAppendItem {
    let commitCID = CID.fromDAGCBOR(Data([seed]))
    let material = PublicFirehoseCommitMaterial(
      did: did,
      rev: rev,
      since: nil,
      commitCID: commitCID.string,
      prevDataCID: nil,
      ops: [],
      time: time
    )
    return FirehoseAppendItem(
      sourceKey: sourceKey,
      batchID: nil,
      did: did,
      kind: .commit
    ) { seq in
      try FirehoseFrameEncoder.commitFrame(
        seq: seq,
        material: material,
        diffCAR: Data()
      )
    }
  }

  /// Appends one commit event and signals the wakeup hub exactly like the
  /// sequencer does in production (`firehoseDidAppend(maxSeq:)`); appends
  /// alone never wake subscribers.
  ///
  /// The default matches `epoch` above: Swift does not allow an instance
  /// member as a default parameter value, so the same literal is repeated
  /// here rather than written as `now: Date = epoch`.
  @discardableResult
  private func appendCommit(
    to firehose: SQLiteFirehoseDatabase,
    hub: PublicFirehoseWakeupHub,
    sourceKey: String,
    seed: UInt8,
    now: Date = Date(timeIntervalSince1970: 1_785_844_800)
  ) async throws -> FirehoseStoredEvent {
    let sequences = try await firehose.appendBatch(
      [commitItem(sourceKey: sourceKey, seed: seed)],
      now: now
    )
    if let maxSeq = sequences.max() {
      await hub.firehoseDidAppend(maxSeq: maxSeq)
    }
    let events = try await firehose.events(after: 0, limit: 1_000)
    return try XCTUnwrap(events.last { $0.sourceKey == sourceKey })
  }

  private actor WSFrameRecorder {
    private var frames: [WebSocketDataFrame] = []

    func record(_ frame: WebSocketDataFrame) {
      frames.append(frame)
    }

    func snapshot() -> [WebSocketDataFrame] {
      frames
    }
  }

  /// Captures the ephemeral port handed to `onServerRunning` when a fixture
  /// is built with `port: 0`, so a test running the application inside an
  /// explicit `ServiceGroup` can dial the real listener.
  private actor PortBox {
    enum Error: Swift.Error { case timeout }

    private var value: Int?

    func set(_ value: Int?) {
      self.value = value
    }

    func wait() async throws -> Int {
      let deadline = ContinuousClock.now + .seconds(5)
      while ContinuousClock.now < deadline {
        if let value { return value }
        try await Task.sleep(for: .milliseconds(10))
      }
      throw Error.timeout
    }
  }

  /// A minimal `TestClientProtocol` conformance carrying only the port
  /// HummingbirdWSTesting's `.ws(...)` helper actually reads. Hummingbird
  /// Testing's own `TestClient` does not conform to `TestClientProtocol`
  /// itself — only the private `Client` wrapper each test framework
  /// (`.live`, `.router`, `.ahc`) hands to its closure does — so a test that
  /// must drive its own `ServiceGroup` (and therefore cannot go through
  /// `app.test(.live)`) needs this same wrapper shape to reach
  /// `TestClientProtocol`'s `.ws(...)` helper. That helper dials its own
  /// independent connection via `WebSocketClient.connect(...)`; it never
  /// touches a wrapped `TestClient`, so this type does not hold one — an
  /// earlier version held an unused, connected `TestClient` here, which left
  /// a second, never-closed TCP connection open against the server and
  /// deadlocked `ServiceGroup` shutdown (the quiescing helper waits for every
  /// open child channel, including ones the test never exercises). The
  /// plain-HTTP path is never exercised by the WebSocket-only fixture that
  /// uses this type.
  private struct RawTestClient: TestClientProtocol {
    struct PlainHTTPUnsupported: Error {}

    let port: Int?

    func executeRequest(
      uri: String,
      method: HTTPRequest.Method,
      headers: HTTPFields,
      body: ByteBuffer?
    ) async throws -> TestResponse {
      throw PlainHTTPUnsupported()
    }
  }

  private func waitUntil(
    timeoutNanoseconds: UInt64 = 5_000_000_000,
    _ condition: @escaping @Sendable () async -> Bool
  ) async throws {
    let deadline = ContinuousClock.now + .seconds(
      Double(timeoutNanoseconds) / 1_000_000_000
    )
    while ContinuousClock.now < deadline {
      if await condition() { return }
      try await Task.sleep(nanoseconds: 10_000_000)
    }
    XCTFail("condition not met before deadline")
  }

  private struct DeadlineExceeded: Error {}

  /// Runs `operation` and fails the test if it does not complete before the
  /// deadline. Cancellation tears the WS connection down via the library's
  /// cancellation handler (closes the channel input), so a hung server loop
  /// cannot hang the test suite.
  private func awaitWithDeadline<Value: Sendable>(
    timeout: Duration = .seconds(10),
    _ operation: @escaping @Sendable () async throws -> Value
  ) async throws -> Value {
    try await withThrowingTaskGroup(of: Value.self) { group in
      group.addTask(operation: operation)
      group.addTask {
        try await Task.sleep(for: timeout)
        throw DeadlineExceeded()
      }
      defer { group.cancelAll() }
      guard let first = try await group.next() else {
        throw DeadlineExceeded()
      }
      return first
    }
  }

  /// Connects the WS test client, runs `sendOnConnect` once the upgrade
  /// completes, records every inbound frame, and closes after
  /// `closeAfterFrames` binary frames have arrived.
  private func runWSClient(
    _ client: any TestClientProtocol,
    path: String,
    recorder: WSFrameRecorder,
    sendOnConnect: @escaping @Sendable (WebSocketOutboundWriter) async throws -> Void = { _ in },
    closeAfterFrames: Int = .max
  ) async throws -> WebSocketCloseFrame? {
    try await client.ws(
      path,
      configuration: .init(maxFrameSize: 5_000_000),
      logger: Logger(label: "PublicFirehoseStreamingHTTPTests.ws-client")
    ) { inbound, outbound, _ in
      try await sendOnConnect(outbound)
      var seen = 0
      for try await frame in inbound {
        await recorder.record(frame)
        seen += 1
        if seen >= closeAfterFrames {
          try await outbound.close(.normalClosure, reason: nil)
          break
        }
      }
    }
  }

  /// Connects and records every inbound frame without ever initiating a
  /// close; the connection ends when the server closes, so the returned
  /// value is the server's close frame. Used for server-initiated
  /// terminations (`FutureCursor`, `ConsumerTooSlow`).
  private func runWSClientPassive(
    _ client: any TestClientProtocol,
    path: String,
    recorder: WSFrameRecorder
  ) async throws -> WebSocketCloseFrame? {
    try await client.ws(
      path,
      configuration: .init(maxFrameSize: 5_000_000),
      logger: Logger(label: "PublicFirehoseStreamingHTTPTests.ws-client")
    ) { inbound, _, _ in
      for try await frame in inbound {
        await recorder.record(frame)
      }
    }
  }

  /// Asserts a connection-control error frame against the real bytes:
  /// header `op == -1` with no `t`, body `error == <error>` and no message.
  private func assertErrorFrame(
    _ frame: WebSocketDataFrame,
    error: String,
    file: StaticString = #filePath,
    line: UInt = #line
  ) throws {
    XCTAssertEqual(frame.opcode, .binary, file: file, line: line)
    var reader = FirehoseStreamingTestCBORReader(Data(buffer: frame.data))
    let (header, body) = try reader.readFrame()
    XCTAssertEqual(reader.headerOp(header), -1, file: file, line: line)
    XCTAssertNil(reader.headerType(header), file: file, line: line)
    guard case .some(.text(let errorValue)) = reader.bodyValue(body, key: "error") else {
      return XCTFail("error frame must carry an error string", file: file, line: line)
    }
    XCTAssertEqual(errorValue, error, file: file, line: line)
    XCTAssertNil(reader.bodyValue(body, key: "message"), file: file, line: line)
  }

  /// Asserts a connection-control info frame against the real bytes: header
  /// `op == 1`, `t == "#info"`, body `name == <name>`.
  private func assertInfoFrame(
    _ frame: WebSocketDataFrame,
    name: String,
    file: StaticString = #filePath,
    line: UInt = #line
  ) throws {
    XCTAssertEqual(frame.opcode, .binary, file: file, line: line)
    var reader = FirehoseStreamingTestCBORReader(Data(buffer: frame.data))
    let (header, body) = try reader.readFrame()
    XCTAssertEqual(reader.headerOp(header), 1, file: file, line: line)
    XCTAssertEqual(reader.headerType(header), "#info", file: file, line: line)
    guard case .some(.text(let value)) = reader.bodyValue(body, key: "name") else {
      return XCTFail("info frame must carry a name", file: file, line: line)
    }
    XCTAssertEqual(value, name, file: file, line: line)
  }

  private func decodeFrameHeader(
    _ frame: WebSocketDataFrame
  ) throws -> (op: Int64, type: String?) {
    var reader = FirehoseStreamingTestCBORReader(Data(buffer: frame.data))
    let (header, _) = try reader.readFrame()
    return (try XCTUnwrap(reader.headerOp(header)), reader.headerType(header))
  }

  private func packageRoot() -> URL {
    URL(filePath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
  }

  // MARK: - Upgrade and framing

  func testSubscribeReposUpgradeSucceedsAndReceivesFrames() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      // Seed before connect and connect with `cursor=0` (full window) so the
      // delivery set is deterministic: the tailer always starts at sequence 0
      // regardless of when the server reads the log position during upgrade.
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "seeded-1", seed: 0x01
      )
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "seeded-2", seed: 0x02
      )
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.receive-frames")
      )
      try await app.test(.live) { client in
        let recorder = WSFrameRecorder()
        let wsTask = Task {
          try await self.runWSClient(
            client,
            path: "\(self.subscribePath)?cursor=0",
            recorder: recorder,
            closeAfterFrames: 2
          )
        }
        try await self.waitUntil { await recorder.snapshot().count == 2 }
        let closeFrame = try await self.awaitWithDeadline { try await wsTask.value }
        XCTAssertEqual(closeFrame?.closeCode, .normalClosure)
        let frames = await recorder.snapshot()
        XCTAssertEqual(frames.count, 2)
        XCTAssertTrue(
          frames.allSatisfy { $0.opcode == .binary },
          "every stored firehose frame must ship as one binary WebSocket message"
        )
        for frame in frames {
          let header = try self.decodeFrameHeader(frame)
          XCTAssertEqual(header.op, 1)
          XCTAssertEqual(header.type, "#commit")
        }
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  func testSubscribeReposFrameBytesMatchStoredBytesVerbatim() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "verbatim-1", seed: 0x03
      )
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "verbatim-2", seed: 0x04
      )
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.verbatim")
      )
      try await app.test(.live) { client in
        let recorder = WSFrameRecorder()
        let wsTask = Task {
          try await self.runWSClient(
            client,
            path: "\(self.subscribePath)?cursor=0",
            recorder: recorder,
            closeAfterFrames: 2
          )
        }
        try await self.waitUntil { await recorder.snapshot().count == 2 }
        _ = try await self.awaitWithDeadline { try await wsTask.value }
        let stored = try await fixture.firehose.events(after: 0, limit: 10)
        let delivered = await recorder.snapshot().map { Data(buffer: $0.data) }
        XCTAssertEqual(
          delivered,
          stored.map(\.frameBytes),
          "the server must ship stored frame_bytes byte-for-byte"
        )
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  // MARK: - Rejection paths

  func testSubscribeReposPlainGetIsNotUpgraded() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.plain-get")
      )
      try await app.test(.live) { client in
        try await client.execute(uri: self.subscribePath, method: .get) { response in
          XCTAssertEqual(response.status, .methodNotAllowed)
        }
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  func testSubscribeReposMalformedCursorRejectsUpgrade() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.malformed-cursor")
      )
      try await app.test(.live) { client in
        for cursor in ["abc", "-1", "99999999999999999999999"] {
          do {
            _ = try await client.ws(
              "\(self.subscribePath)?cursor=\(cursor)",
              configuration: .init(maxFrameSize: 5_000_000),
              logger: Logger(label: "PublicFirehoseStreamingHTTPTests.ws-client")
            ) { _, _, _ in
              XCTFail("upgrade must never complete for cursor=\(cursor)")
            }
            XCTFail("expected failed upgrade for cursor=\(cursor)")
          } catch {
            XCTAssertEqual(
              String(describing: error),
              "WebSocket upgrade failed",
              "cursor=\(cursor)"
            )
          }
        }
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  func testSubscribeReposUnknownPathUpgradeFails() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.unknown-path")
      )
      try await app.test(.live) { client in
        do {
          _ = try await client.ws(
            "/xrpc/com.atproto.sync.getRepo",
            configuration: .init(maxFrameSize: 5_000_000),
            logger: Logger(label: "PublicFirehoseStreamingHTTPTests.ws-client")
          ) { _, _, _ in
            XCTFail("upgrade on an unknown path must never complete")
          }
          XCTFail("expected failed upgrade on an unknown path")
        } catch {
          XCTAssertEqual(
            String(describing: error),
            "WebSocket upgrade failed"
          )
        }
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  func testSubscribeReposRouteAbsentWhenRuntimeMissing() async throws {
    let fixture = try await makeFixture(includeRuntime: false)
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.no-runtime")
      )
      try await app.test(.live) { client in
        try await client.execute(uri: self.subscribePath, method: .get) { response in
          XCTAssertEqual(response.status, .notFound)
          XCTAssertEqual(
            String(decoding: response.body.readableBytesView, as: UTF8.self),
            #"{"error":"public_endpoint_unavailable"}"#
          )
        }
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  // MARK: - Connection lifecycle

  func testSubscribeReposInboundDrainKeepsLoopAlive() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "drain-seeded", seed: 0x05
      )
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.inbound-drain")
      )
      try await app.test(.live) { client in
        let recorder = WSFrameRecorder()
        let wsTask = Task {
          try await self.runWSClient(
            client,
            path: "\(self.subscribePath)?cursor=0",
            recorder: recorder,
            sendOnConnect: { outbound in
              // A client data message must be consumed by the server's
              // inbound drain without disturbing the tailer.
              try await outbound.write(.binary(ByteBuffer(string: "client-hello")))
            },
            closeAfterFrames: 2
          )
        }
        try await self.appendCommit(
          to: fixture.firehose, hub: fixture.hub, sourceKey: "drain-live", seed: 0x06
        )
        try await self.waitUntil { await recorder.snapshot().count == 2 }
        _ = try await self.awaitWithDeadline { try await wsTask.value }
        let frames = await recorder.snapshot()
        XCTAssertEqual(frames.count, 2)
        for frame in frames {
          let header = try self.decodeFrameHeader(frame)
          XCTAssertEqual(header.op, 1)
          XCTAssertEqual(header.type, "#commit")
        }
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  func testSubscribeReposClientCloseEndsTailer() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.client-close")
      )
      try await app.test(.live) { client in
        let recorder = WSFrameRecorder()
        let wsTask = Task {
          try await self.runWSClient(
            client,
            path: self.subscribePath,
            recorder: recorder,
            sendOnConnect: { outbound in
              try await outbound.close(.normalClosure, reason: nil)
            }
          )
        }
        _ = try await self.awaitWithDeadline { try await wsTask.value }
        // The server loop must exit on the client close and release its hub
        // slot (a suspended hub `next()` is only resumed by finishing the
        // subscription, so this proves the tailer task completed).
        try await self.waitUntil { await fixture.hub.subscriberCount() == 0 }
        // A subsequent append must not be written to the dead connection.
        let postCloseSequences = try await fixture.firehose.appendBatch(
          [self.commitItem(sourceKey: "post-close", seed: 0x09)],
          now: self.epoch
        )
        if let postCloseMax = postCloseSequences.max() {
          await fixture.hub.firehoseDidAppend(maxSeq: postCloseMax)
        }
        try await Task.sleep(for: .milliseconds(200))
        let deliveredAfterClose = await recorder.snapshot()
        XCTAssertEqual(deliveredAfterClose.count, 0)
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  // MARK: - Cursor semantics and slow consumer

  func testSubscribeReposNoCursorStreamsLiveOnly() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      // Seeded before connect: `maxSequencedSeq()` at connect is 3, so the
      // no-cursor live tail starts at sequence 3 and the pre-connect
      // history cannot leak into the stream.
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "live-seed-1", seed: 0x11
      )
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "live-seed-2", seed: 0x12
      )
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "live-seed-3", seed: 0x13
      )
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.no-cursor-live")
      )
      try await app.test(.live) { client in
        let recorder = WSFrameRecorder()
        let wsTask = Task {
          try await self.runWSClient(
            client,
            path: self.subscribePath,
            recorder: recorder,
            closeAfterFrames: 2
          )
        }
        // The hub subscription is created after the cursor is resolved
        // against `maxSequencedSeq()`, so `subscriberCount == 1` proves the
        // tailer is already live at sequence 3 before anything is appended.
        try await self.waitUntil { await fixture.hub.subscriberCount() == 1 }
        let earlyFrames = await recorder.snapshot()
        XCTAssertTrue(
          earlyFrames.isEmpty,
          "a no-cursor connection must not deliver pre-connect history"
        )
        try await self.appendCommit(
          to: fixture.firehose, hub: fixture.hub, sourceKey: "live-4", seed: 0x14
        )
        try await self.appendCommit(
          to: fixture.firehose, hub: fixture.hub, sourceKey: "live-5", seed: 0x15
        )
        try await self.waitUntil { await recorder.snapshot().count == 2 }
        let closeFrame = try await self.awaitWithDeadline { try await wsTask.value }
        XCTAssertEqual(closeFrame?.closeCode, .normalClosure)
        let stored = try await fixture.firehose.events(after: 3, limit: 10)
        XCTAssertEqual(stored.map(\.seq), [4, 5])
        let delivered = await recorder.snapshot().map { Data(buffer: $0.data) }
        XCTAssertEqual(
          delivered,
          stored.map(\.frameBytes),
          "exactly the 2 live events must arrive, in order"
        )
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  func testSubscribeReposCursorZeroStreamsEntireWindow() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "window-seed-1", seed: 0x21
      )
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "window-seed-2", seed: 0x22
      )
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "window-seed-3", seed: 0x23
      )
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.cursor-zero")
      )
      try await app.test(.live) { client in
        let recorder = WSFrameRecorder()
        let wsTask = Task {
          try await self.runWSClient(
            client,
            path: "\(self.subscribePath)?cursor=0",
            recorder: recorder,
            closeAfterFrames: 4
          )
        }
        try await self.waitUntil { await recorder.snapshot().count == 3 }
        try await self.appendCommit(
          to: fixture.firehose, hub: fixture.hub, sourceKey: "window-live-4", seed: 0x24
        )
        try await self.waitUntil { await recorder.snapshot().count == 4 }
        let closeFrame = try await self.awaitWithDeadline { try await wsTask.value }
        XCTAssertEqual(closeFrame?.closeCode, .normalClosure)
        let stored = try await fixture.firehose.events(after: 0, limit: 10)
        XCTAssertEqual(stored.map(\.seq), [1, 2, 3, 4])
        let delivered = await recorder.snapshot().map { Data(buffer: $0.data) }
        XCTAssertEqual(
          delivered,
          stored.map(\.frameBytes),
          "cursor=0 must stream the whole window in seq order, then live"
        )
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  func testSubscribeReposBackfillThenLiveBoundaryNoGapNoDuplicate() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      for index in 1 ... 5 {
        try await self.appendCommit(
          to: fixture.firehose,
          hub: fixture.hub,
          sourceKey: "boundary-\(index)",
          seed: UInt8(0x30 + index)
        )
      }
      let seeded = try await fixture.firehose.events(after: 0, limit: 10)
      XCTAssertEqual(seeded.map(\.seq), [1, 2, 3, 4, 5])
      let backfillBytes = seeded.filter { $0.seq >= 4 }.map(\.frameBytes)
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.backfill-boundary")
      )
      try await app.test(.live) { client in
        let recorder = WSFrameRecorder()
        let wsTask = Task {
          try await self.runWSClient(
            client,
            path: "\(self.subscribePath)?cursor=3",
            recorder: recorder,
            closeAfterFrames: 3
          )
        }
        // Backfill first: exactly 4 and 5, strictly after the cursor.
        try await self.waitUntil { await recorder.snapshot().count == 2 }
        let firstTwo = await recorder.snapshot().map { Data(buffer: $0.data) }
        XCTAssertEqual(
          firstTwo,
          backfillBytes,
          "backfill from cursor=3 must deliver 4, 5 in order"
        )
        // Live append next: the boundary must have no gap and no duplicate.
        try await self.appendCommit(
          to: fixture.firehose, hub: fixture.hub, sourceKey: "boundary-6", seed: 0x36
        )
        try await self.waitUntil { await recorder.snapshot().count == 3 }
        let closeFrame = try await self.awaitWithDeadline { try await wsTask.value }
        XCTAssertEqual(closeFrame?.closeCode, .normalClosure)
        let liveSix = try await fixture.firehose.events(after: 5, limit: 10)
        XCTAssertEqual(liveSix.map(\.seq), [6])
        let delivered = await recorder.snapshot().map { Data(buffer: $0.data) }
        XCTAssertEqual(
          delivered,
          backfillBytes + liveSix.map(\.frameBytes),
          "backfill 4, 5 then live 6 with no gap and no duplicate"
        )
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  func testSubscribeReposCursorEqualsMaxYieldsNothingThenLive() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "atmax-seed-1", seed: 0x41
      )
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "atmax-seed-2", seed: 0x42
      )
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "atmax-seed-3", seed: 0x43
      )
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.cursor-equals-max")
      )
      try await app.test(.live) { client in
        let recorder = WSFrameRecorder()
        let wsTask = Task {
          try await self.runWSClient(
            client,
            path: "\(self.subscribePath)?cursor=3",
            recorder: recorder,
            closeAfterFrames: 1
          )
        }
        try await self.waitUntil { await fixture.hub.subscriberCount() == 1 }
        let earlyFrames = await recorder.snapshot()
        XCTAssertTrue(
          earlyFrames.isEmpty,
          "cursor == max must yield nothing until a live append"
        )
        try await self.appendCommit(
          to: fixture.firehose, hub: fixture.hub, sourceKey: "atmax-live-4", seed: 0x44
        )
        try await self.waitUntil { await recorder.snapshot().count == 1 }
        let closeFrame = try await self.awaitWithDeadline { try await wsTask.value }
        XCTAssertEqual(closeFrame?.closeCode, .normalClosure)
        let stored = try await fixture.firehose.events(after: 3, limit: 10)
        XCTAssertEqual(stored.map(\.seq), [4])
        let delivered = await recorder.snapshot().map { Data(buffer: $0.data) }
        XCTAssertEqual(delivered, stored.map(\.frameBytes))
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  func testSubscribeReposFutureCursorErrorFrameAndClose() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "future-seed-1", seed: 0x51
      )
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "future-seed-2", seed: 0x52
      )
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "future-seed-3", seed: 0x53
      )
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.future-cursor")
      )
      try await app.test(.live) { client in
        let recorder = WSFrameRecorder()
        let wsTask = Task {
          try await self.runWSClientPassive(
            client,
            path: "\(self.subscribePath)?cursor=13",
            recorder: recorder
          )
        }
        try await self.waitUntil { await recorder.snapshot().count == 1 }
        let frames = await recorder.snapshot()
        XCTAssertEqual(frames.count, 1, "no data frames may precede the error")
        try self.assertErrorFrame(frames[0], error: "FutureCursor")
        let closeFrame = try await self.awaitWithDeadline { try await wsTask.value }
        XCTAssertEqual(closeFrame?.closeCode, .normalClosure)
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  func testSubscribeReposPrunedCursorReportsOutdatedThenStreamsRetainedRows() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      try await appendCommit(to: fixture.firehose, hub: fixture.hub, sourceKey: "pruned-1", seed: 0x01, now: epoch)
      try await appendCommit(to: fixture.firehose, hub: fixture.hub, sourceKey: "pruned-2", seed: 0x02, now: epoch)
      let retained = try await appendCommit(to: fixture.firehose, hub: fixture.hub, sourceKey: "retained-3", seed: 0x03, now: epoch.addingTimeInterval(20))
      _ = try await fixture.firehose.prune(
        now: epoch.addingTimeInterval(20),
        policy: try PublicFirehoseRetentionPolicy(
          maximumAge: .seconds(1),
          maximumRows: 100,
          maximumBytes: 1_073_741_824
        )
      )

      let app = fixture.server.buildApplication(logger: logger)
      try await app.test(.live) { client in
        let recorder = WSFrameRecorder()
        let wsTask = Task {
          try await self.runWSClient(
            client,
            path: "\(self.subscribePath)?cursor=1",
            recorder: recorder,
            closeAfterFrames: 2
          )
        }
        try await self.waitUntil { await recorder.snapshot().count == 2 }
        _ = try await self.awaitWithDeadline { try await wsTask.value }
        let frames = await recorder.snapshot()
        try self.assertInfoFrame(frames[0], name: "OutdatedCursor")
        XCTAssertEqual(Data(buffer: frames[1].data), retained.frameBytes)
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  func testSubscribeReposCursorZeroUsesRetainedWindowWithoutOutdatedInfo() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      try await appendCommit(to: fixture.firehose, hub: fixture.hub, sourceKey: "full-old-1", seed: 0x11, now: epoch)
      try await appendCommit(to: fixture.firehose, hub: fixture.hub, sourceKey: "full-old-2", seed: 0x12, now: epoch)
      let retained = try await appendCommit(to: fixture.firehose, hub: fixture.hub, sourceKey: "full-retained-3", seed: 0x13, now: epoch.addingTimeInterval(20))
      _ = try await fixture.firehose.prune(
        now: epoch.addingTimeInterval(20),
        policy: try PublicFirehoseRetentionPolicy(
          maximumAge: .seconds(1),
          maximumRows: 100,
          maximumBytes: 1_073_741_824
        )
      )

      let app = fixture.server.buildApplication(logger: logger)
      try await app.test(.live) { client in
        let recorder = WSFrameRecorder()
        let wsTask = Task {
          try await self.runWSClient(
            client,
            path: "\(self.subscribePath)?cursor=0",
            recorder: recorder,
            closeAfterFrames: 1
          )
        }
        try await self.waitUntil { await recorder.snapshot().count == 1 }
        _ = try await self.awaitWithDeadline { try await wsTask.value }
        let frames = await recorder.snapshot()
        let frame = try XCTUnwrap(frames.first)
        let header = try self.decodeFrameHeader(frame)
        XCTAssertEqual(header.type, "#commit")
        XCTAssertEqual(Data(buffer: frame.data), retained.frameBytes)
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  /// Exercises the mid-stream recovery path in `publicFirehoseRunTailer`
  /// (the `.outdatedCursor` retry branch), as opposed to the connect-time
  /// `.outdatedCursor` branch in `publicFirehoseOnUpgrade` already covered
  /// above: a session that is already live and caught up must survive a
  /// retention advance that lands behind it, not close.
  func testSubscribeReposActiveSessionRecoversFromRetentionAdvanceMidStream() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      // Two events delivered before connecting so `cursor=0` catches the
      // session up to seq 2 with nothing left to backfill.
      try await appendCommit(to: fixture.firehose, hub: fixture.hub, sourceKey: "active-1", seed: 0xA1, now: epoch)
      try await appendCommit(to: fixture.firehose, hub: fixture.hub, sourceKey: "active-2", seed: 0xA2, now: epoch)

      let app = fixture.server.buildApplication(logger: logger)
      try await app.test(.live) { client in
        let recorder = WSFrameRecorder()
        let wsTask = Task {
          try await self.runWSClient(
            client,
            path: "\(self.subscribePath)?cursor=0",
            recorder: recorder,
            closeAfterFrames: 4
          )
        }
        // The session catches up to the two seeded events and goes idle,
        // live-tailing at seq 2 with nothing left to deliver.
        try await self.waitUntil { await recorder.snapshot().count == 2 }

        // Two more events land with an old timestamp, appended directly
        // (bypassing the hub signal `appendCommit` sends) so the
        // already-idle tailer does not discover them via its own bounded
        // poll before the prune below deletes them out from under this
        // live session. A third, later event survives the prune and
        // becomes the new retained boundary.
        _ = try await fixture.firehose.appendBatch(
          [self.commitItem(sourceKey: "active-3", seed: 0xA3)], now: self.epoch
        )
        _ = try await fixture.firehose.appendBatch(
          [self.commitItem(sourceKey: "active-4", seed: 0xA4)], now: self.epoch
        )
        _ = try await fixture.firehose.appendBatch(
          [self.commitItem(sourceKey: "active-5", seed: 0xA5)],
          now: self.epoch.addingTimeInterval(20)
        )
        let seeded = try await fixture.firehose.events(after: 2, limit: 10)
        let retained = try XCTUnwrap(seeded.last { $0.sourceKey == "active-5" })

        // The live session's cursor (2) is behind the two events about to
        // be pruned out from under it; only the later "active-5" survives.
        _ = try await fixture.firehose.prune(
          now: self.epoch.addingTimeInterval(20),
          policy: try PublicFirehoseRetentionPolicy(
            maximumAge: .seconds(1),
            maximumRows: 100,
            maximumBytes: 1_073_741_824
          )
        )
        // Mirrors `SwanPublicFirehoseRetentionService.run()`: re-read the
        // durable high-water mark and signal the hub directly, exactly as
        // the scheduled retention service does after a prune that advances
        // the retained boundary.
        let maxSeq = try await fixture.firehose.maxSequencedSeq()
        await fixture.hub.firehoseRetentionDidAdvance(maxSeq: maxSeq)

        try await self.waitUntil { await recorder.snapshot().count == 4 }
        let closeFrame = try await self.awaitWithDeadline { try await wsTask.value }
        // A client-initiated close after 4 frames, not a server-initiated
        // one: the session must survive the retention advance instead of
        // being torn down.
        XCTAssertEqual(closeFrame?.closeCode, .normalClosure)

        let frames = await recorder.snapshot()
        XCTAssertEqual(frames.count, 4)
        for frame in frames.prefix(2) {
          let header = try self.decodeFrameHeader(frame)
          XCTAssertEqual(header.type, "#commit")
        }
        try self.assertInfoFrame(frames[2], name: "OutdatedCursor")
        let resumed = try self.decodeFrameHeader(frames[3])
        XCTAssertEqual(resumed.type, "#commit", "streaming must resume from the retained window")
        XCTAssertEqual(Data(buffer: frames[3].data), retained.frameBytes)
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  func testSubscribeReposConsumerTooSlowErrorFrameAndClose() async throws {
    // Task 2's validated init rejects zero bounds, so the smallest positive
    // lag ceiling is 1; seeding two events makes the lag 2 at cursor 0.
    let fixture = try await makeFixture(
      limits: try PublicFirehoseStreamingLimits(maximumSequenceLag: 1)
    )
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "slow-seed-1", seed: 0x71
      )
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "slow-seed-2", seed: 0x72
      )
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.consumer-too-slow")
      )
      try await app.test(.live) { client in
        let recorder = WSFrameRecorder()
        let wsTask = Task {
          try await self.runWSClientPassive(
            client,
            path: "\(self.subscribePath)?cursor=0",
            recorder: recorder
          )
        }
        try await self.waitUntil { await recorder.snapshot().count == 1 }
        let frames = await recorder.snapshot()
        XCTAssertEqual(frames.count, 1, "no data frame may reach a dropped consumer")
        try self.assertErrorFrame(frames[0], error: "ConsumerTooSlow")
        let closeFrame = try await self.awaitWithDeadline { try await wsTask.value }
        XCTAssertEqual(closeFrame?.closeCode, .normalClosure)
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  func testSubscribeReposTwoConnectionsIndependentCursors() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      for index in 1 ... 4 {
        try await self.appendCommit(
          to: fixture.firehose,
          hub: fixture.hub,
          sourceKey: "independent-\(index)",
          seed: UInt8(0x80 + index)
        )
      }
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.two-connections")
      )
      try await app.test(.live) { client in
        let recorderA = WSFrameRecorder()
        let recorderB = WSFrameRecorder()
        let wsTaskA = Task {
          try await self.runWSClient(
            client,
            path: "\(self.subscribePath)?cursor=0",
            recorder: recorderA,
            closeAfterFrames: 5
          )
        }
        let wsTaskB = Task {
          try await self.runWSClient(
            client,
            path: "\(self.subscribePath)?cursor=2",
            recorder: recorderB,
            closeAfterFrames: 4
          )
        }
        try await self.waitUntil { await fixture.hub.subscriberCount() == 2 }
        try await self.appendCommit(
          to: fixture.firehose, hub: fixture.hub, sourceKey: "independent-5", seed: 0x85
        )
        try await self.waitUntil { await recorderA.snapshot().count == 5 }
        try await self.waitUntil { await recorderB.snapshot().count == 3 }
        let storedUpTo5 = try await fixture.firehose.events(after: 0, limit: 10)
        XCTAssertEqual(storedUpTo5.map(\.seq), [1, 2, 3, 4, 5])
        let deliveredA = await recorderA.snapshot().map { Data(buffer: $0.data) }
        XCTAssertEqual(deliveredA, storedUpTo5.map(\.frameBytes))
        let deliveredB = await recorderB.snapshot().map { Data(buffer: $0.data) }
        XCTAssertEqual(
          deliveredB,
          storedUpTo5.filter { $0.seq >= 3 }.map(\.frameBytes)
        )
        let closeFrameA = try await self.awaitWithDeadline { try await wsTaskA.value }
        XCTAssertEqual(closeFrameA?.closeCode, .normalClosure)
        // Closing A must not disturb B: B still receives the next live append.
        try await self.waitUntil { await fixture.hub.subscriberCount() == 1 }
        try await self.appendCommit(
          to: fixture.firehose, hub: fixture.hub, sourceKey: "independent-6", seed: 0x86
        )
        try await self.waitUntil { await recorderB.snapshot().count == 4 }
        let closeFrameB = try await self.awaitWithDeadline { try await wsTaskB.value }
        XCTAssertEqual(closeFrameB?.closeCode, .normalClosure)
        let storedUpTo6 = try await fixture.firehose.events(after: 0, limit: 10)
        let deliveredBAfter = await recorderB.snapshot().map { Data(buffer: $0.data) }
        XCTAssertEqual(
          deliveredBAfter,
          storedUpTo6.filter { $0.seq >= 3 }.map(\.frameBytes)
        )
        try await self.waitUntil { await fixture.hub.subscriberCount() == 0 }
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  func testSubscribeReposLostWakeupLosesNothingOverHTTP() async throws {
    // A tiny idle poll interval bounds the lost-wakeup recovery window.
    let fixture = try await makeFixture(
      limits: try PublicFirehoseStreamingLimits(idlePollInterval: 0.01)
    )
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "lost-seed", seed: 0x91
      )
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.lost-wakeup")
      )
      try await app.test(.live) { client in
        let recorder = WSFrameRecorder()
        let wsTask = Task {
          try await client.ws(
            "\(self.subscribePath)?cursor=0",
            configuration: .init(maxFrameSize: 5_000_000),
            logger: Logger(label: "PublicFirehoseStreamingHTTPTests.ws-client")
          ) { inbound, outbound, _ in
            // The client deliberately does not read while appending: the
            // server keeps writing into the socket, and the tailer recovers
            // any missed wakeup (coalesced to `.bufferingNewest(1)`) via its
            // bounded idle poll.
            try await self.appendCommit(
              to: fixture.firehose, hub: fixture.hub, sourceKey: "lost-2", seed: 0x92
            )
            try await self.appendCommit(
              to: fixture.firehose, hub: fixture.hub, sourceKey: "lost-3", seed: 0x93
            )
            try await self.appendCommit(
              to: fixture.firehose, hub: fixture.hub, sourceKey: "lost-4", seed: 0x94
            )
            var seen = 0
            for try await frame in inbound {
              await recorder.record(frame)
              seen += 1
              if seen == 4 {
                try await outbound.close(.normalClosure, reason: nil)
                break
              }
            }
          }
        }
        try await self.waitUntil { await recorder.snapshot().count == 4 }
        let closeFrame = try await self.awaitWithDeadline { try await wsTask.value }
        XCTAssertEqual(closeFrame?.closeCode, .normalClosure)
        let stored = try await fixture.firehose.events(after: 0, limit: 10)
        XCTAssertEqual(stored.map(\.seq), [1, 2, 3, 4])
        let delivered = await recorder.snapshot().map { Data(buffer: $0.data) }
        XCTAssertEqual(
          delivered,
          stored.map(\.frameBytes),
          "all 3 live appends must arrive in order despite paused reads"
        )
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  // MARK: - Liveness and graceful shutdown

  /// A client handler that never iterates `inbound` cannot answer the
  /// server's ping, so Hummingbird's auto-ping loop must close it with
  /// `.goingAway` / `"Ping timeout"`. The short override avoids a
  /// 30-second test; the production default remains exactly 30 seconds
  /// (`buildApplication(webSocketAutoPingInterval:)` defaults to
  /// `.seconds(30)`, which this test overrides to `.milliseconds(50)`).
  func testPublicFirehoseAutoPingClosesAClientThatDoesNotPong() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      let app = fixture.server.buildApplication(
        logger: logger,
        webSocketAutoPingInterval: .milliseconds(50)
      )

      try await app.test(.live) { client in
        let closeFrame = try await self.awaitWithDeadline(timeout: .seconds(2)) {
          try await client.ws(
            self.subscribePath,
            configuration: .init(maxFrameSize: 5_000_000),
            logger: self.logger
          ) { _, _, _ in
            try await Task.sleep(for: .milliseconds(250))
          }
        }
        XCTAssertEqual(closeFrame?.closeCode, .goingAway)
        XCTAssertEqual(closeFrame?.reason, "Ping timeout")
      }
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  /// Runs the real application as a member of an explicit `ServiceGroup`,
  /// captures its ephemeral port through `onServerRunning`, holds a passive
  /// WebSocket open, triggers `serviceGroup.triggerGracefulShutdown()`, and
  /// asserts the close frame arrives before the `ServiceGroup` exits.
  /// Hummingbird's `WebSocketHandler.handle` already wraps every upgraded
  /// handler in `withGracefulShutdownHandler`, whose graceful callback sends
  /// `.normalClosure` — this test proves that path is actually wired end to
  /// end through Swan's `ServiceGroup` composition, not a separate registry.
  ///
  /// `app.test(.live)` cannot be used here: it owns and tears down its own
  /// internal `ServiceGroup`, and this test needs to drive
  /// `triggerGracefulShutdown()` on a `ServiceGroup` it controls itself. The
  /// bare `TestClient` HummingbirdTesting hands out for that case does not
  /// itself conform to `TestClientProtocol` (only the framework's private
  /// `Client` wrappers do, e.g. `LiveTestFramework.Client`), so
  /// `RawTestClient` below reproduces that same wrapper locally, purely to
  /// reach `TestClientProtocol`'s `.ws(...)` helper.
  func testPublicFirehoseGracefulShutdownSendsNormalCloseFrame() async throws {
    let fixture = try await makeFixture(port: 0)
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      let portBox = PortBox()
      let application = fixture.server.buildApplication(
        logger: logger,
        onServerRunning: { channel in
          await portBox.set(channel.localAddress?.port)
        }
      )
      let serviceGroup = SwanHTTPServiceLifecycle.makeServiceGroup(
        services: [application],
        logger: logger
      )
      let serviceTask = Task { try await serviceGroup.run() }
      let port = try await portBox.wait()
      let client = RawTestClient(port: port)

      let wsTask = Task {
        try await client.ws(self.subscribePath) { inbound, _, _ in
          for try await _ in inbound {}
        }
      }
      try await waitUntil { await fixture.hub.subscriberCount() == 1 }
      await serviceGroup.triggerGracefulShutdown()

      let closeFrame = try await awaitWithDeadline { try await wsTask.value }
      XCTAssertEqual(closeFrame?.closeCode, .normalClosure)
      _ = try await serviceTask.value
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  // MARK: - Configuration

  func testWebSocketMaxFrameSizeAtLeastFrameLimit() {
    XCTAssertGreaterThanOrEqual(
      SwanHTTPServer.publicFirehoseWebSocketConfiguration().maxFrameSize,
      FirehoseFrameLimits.maximumFrameBytes,
      "the ws maxFrameSize must cover the largest stored firehose frame"
    )
  }
}
