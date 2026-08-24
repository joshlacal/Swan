import Foundation
import Hummingbird
import HummingbirdTesting
import HummingbirdWebSocket
import HummingbirdWSTesting
import Logging
import NIOCore
import Petrel
import SwanOAuth
import PetrelFirehose
import SwanSpacesWire
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
    port: Int = 3_000,
    maximumConnections: Int = 256,
    subscriberAdmission: PublicFirehoseSubscriberAdmission? = nil,
    useDefaultObservation: Bool = false,
    profileOverride: ProtocolProfile? = nil,
    observeSubscription: @escaping @Sendable (PublicFirehoseSubscriptionObservation) async -> Void = { _ in }
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
      let profile = try profileOverride ?? ProtocolProfile.load(
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
          logger: logger,
          // Nil selects the production observer — the throttled journal
          // writer — which is the thing under test for F33.
          observeSubscription: useDefaultObservation ? nil : observeSubscription
        )
      } else {
        streamingRuntime = nil
      }
      let server = SwanHTTPServer(
        profile: profile,
        configuration: .init(
          host: "127.0.0.1",
          port: port,
          maximumConnections: maximumConnections
        ),
        oauthRuntime: oauthRuntime,
        publicFirehoseStreaming: streamingRuntime,
        publicFirehoseSubscriberAdmission: subscriberAdmission
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

  private func commitItem(
    sourceKey: String,
    seed: UInt8,
    diffCARBytes: Int = 0
  ) -> FirehoseAppendItem {
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
    let diffCAR = Data(repeating: seed, count: diffCARBytes)
    return FirehoseAppendItem(
      sourceKey: sourceKey,
      batchID: nil,
      did: did,
      kind: .commit
    ) { seq in
      try FirehoseFrameEncoder.commitFrame(
        seq: seq,
        material: material,
        diffCAR: diffCAR
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
    diffCARBytes: Int = 0,
    now: Date = Date(timeIntervalSince1970: 1_785_844_800)
  ) async throws -> FirehoseStoredEvent {
    let sequences = try await firehose.appendBatch(
      [commitItem(sourceKey: sourceKey, seed: seed, diffCARBytes: diffCARBytes)],
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

  private actor SubscriptionObservationRecorder {
    private var observations: [PublicFirehoseSubscriptionObservation] = []
    private var waiters: [
      (count: Int, continuation: CheckedContinuation<Void, Never>)
    ] = []

    func record(_ observation: PublicFirehoseSubscriptionObservation) {
      observations.append(observation)
      var remaining: [
        (count: Int, continuation: CheckedContinuation<Void, Never>)
      ] = []
      for waiter in waiters {
        if observations.count >= waiter.count {
          waiter.continuation.resume()
        } else {
          remaining.append(waiter)
        }
      }
      waiters = remaining
    }

    func waitForCount(_ count: Int) async {
      if observations.count >= count { return }
      await withCheckedContinuation { continuation in
        waiters.append((count, continuation))
      }
    }

    func snapshot() -> [PublicFirehoseSubscriptionObservation] {
      observations
    }
  }

  private func assertSubscriptionObservations(
    _ observations: [PublicFirehoseSubscriptionObservation],
    cursorMode: PublicFirehoseSubscriptionObservation.CursorMode,
    cursorValue: Int64?,
    closeCategory: PublicFirehoseSubscriptionObservation.CloseCategory,
    closeReason: PublicFirehoseSubscriptionObservation.CloseReason,
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    XCTAssertEqual(observations.count, 2, file: file, line: line)
    guard observations.count == 2 else { return }
    let opened = observations[0]
    let closed = observations[1]
    XCTAssertEqual(opened.event, .opened, file: file, line: line)
    XCTAssertEqual(opened.cursorMode, cursorMode, file: file, line: line)
    XCTAssertEqual(opened.cursorValue, cursorValue, file: file, line: line)
    XCTAssertNil(opened.closeCategory, file: file, line: line)
    XCTAssertNil(opened.closeReason, file: file, line: line)
    XCTAssertEqual(closed.event, .closed, file: file, line: line)
    XCTAssertEqual(closed.connectionID, opened.connectionID, file: file, line: line)
    XCTAssertEqual(closed.closeCategory, closeCategory, file: file, line: line)
    XCTAssertEqual(closed.closeReason, closeReason, file: file, line: line)
    XCTAssertNil(closed.cursorMode, file: file, line: line)
    XCTAssertNil(closed.cursorValue, file: file, line: line)
    XCTAssertNotNil(UUID(uuidString: opened.connectionID), file: file, line: line)
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
    let observations = SubscriptionObservationRecorder()
    let fixture = try await makeFixture(observeSubscription: {
      await observations.record($0)
    })
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
        await observations.waitForCount(2)
        await self.assertSubscriptionObservations(
          observations.snapshot(),
          cursorMode: .live,
          cursorValue: nil,
          closeCategory: .completed,
          closeReason: .clientClosed
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
    let observations = SubscriptionObservationRecorder()
    let fixture = try await makeFixture(observeSubscription: {
      await observations.record($0)
    })
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
        await observations.waitForCount(2)
        await self.assertSubscriptionObservations(
          observations.snapshot(),
          cursorMode: .backfill,
          cursorValue: 3,
          closeCategory: .completed,
          closeReason: .clientClosed
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
    let observations = SubscriptionObservationRecorder()
    let fixture = try await makeFixture(observeSubscription: {
      await observations.record($0)
    })
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
        await observations.waitForCount(2)
        await self.assertSubscriptionObservations(
          observations.snapshot(),
          cursorMode: .backfill,
          cursorValue: 13,
          closeCategory: .failure,
          closeReason: .futureCursor
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
    let observations = SubscriptionObservationRecorder()
    let fixture = try await makeFixture(
      port: 0,
      observeSubscription: { await observations.record($0) }
    )
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
      await observations.waitForCount(2)
      await self.assertSubscriptionObservations(
        observations.snapshot(),
        cursorMode: .live,
        cursorValue: nil,
        closeCategory: .completed,
        closeReason: .clientClosed
      )
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  /// Cancelling the service task closes the handler's channel input through
  /// Hummingbird's cancellation hook. This is distinct from graceful
  /// shutdown, whose normal close handshake completes the inbound stream.
  func testPublicFirehoseServiceCancellationIsObservedAsCancellation() async throws {
    let observations = SubscriptionObservationRecorder()
    let fixture = try await makeFixture(
      port: 0,
      observeSubscription: { await observations.record($0) }
    )
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      let portBox = PortBox()
      let quietLogger = Logger(
        label: "PublicFirehoseStreamingHTTPTests.service-cancellation",
        factory: SwiftLogNoOpLogHandler.init
      )
      let application = fixture.server.buildApplication(
        logger: quietLogger,
        onServerRunning: { channel in
          await portBox.set(channel.localAddress?.port)
        }
      )
      let serviceGroup = SwanHTTPServiceLifecycle.makeServiceGroup(
        services: [application],
        logger: quietLogger
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
      serviceTask.cancel()

      _ = try? await awaitWithDeadline { try await wsTask.value }
      _ = try? await serviceTask.value
      await observations.waitForCount(2)
      await self.assertSubscriptionObservations(
        observations.snapshot(),
        cursorMode: .live,
        cursorValue: nil,
        closeCategory: .cancellation,
        closeReason: .serverShutdown
      )
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  // MARK: - Subscriber admission

  /// The sizing rule, stated as arithmetic rather than as a literal at the
  /// call site: anonymous subscribers may hold a quarter of the listener
  /// budget, so three quarters stay reachable by HTTP — login, OAuth, public
  /// reads, and the relay's own reconnect.
  func testFirehoseReservationLeavesThreeQuartersOfTheListenerBudget() async throws {
    XCTAssertEqual(
      PublicFirehoseSubscriberAdmission.reservedSubscriberSlots(listenerBudget: 256),
      64
    )
    XCTAssertEqual(
      PublicFirehoseSubscriberAdmission.reservedSubscriberSlots(listenerBudget: 1),
      1,
      "a tiny listener must still serve subscribeRepos at all"
    )
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let admission = fixture.server.publicFirehoseSubscriberAdmission
    XCTAssertEqual(admission.maximumConcurrentSubscribers, 64)
    XCTAssertEqual(
      256 - admission.maximumConcurrentSubscribers,
      192,
      "192 listener slots must remain unreachable by anonymous subscribers"
    )
    try await fixture.control.close()
    try await fixture.firehose.close()
  }

  /// The property the reservation exists for, proven end to end: with the
  /// firehose budget fully held, a further subscriber is refused *and* an
  /// unrelated HTTP route is still served on the same listener.
  ///
  /// A refusal on its own would prove nothing — the hazard is not that a 65th
  /// subscriber connects, it is that anonymous WebSockets which never close
  /// hold listener slots that `AvailableConnectionsHandler` refunds only from
  /// `channel.closeFuture`, so the accept socket stops being read.
  func testSaturatedFirehoseReservationRefusesSurplusAndLeavesHTTPServable() async throws {
    let fixture = try await makeFixture(
      maximumConnections: 8,
      subscriberAdmission: PublicFirehoseSubscriberAdmission(
        maximumConcurrentSubscribers: 2
      )
    )
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.admission")
      )
      try await app.test(.live) { client in
        let held = (0..<2).map { _ in
          Task {
            try await self.runWSClientPassive(
              client,
              path: self.subscribePath,
              recorder: WSFrameRecorder()
            )
          }
        }
        defer {
          for task in held { task.cancel() }
        }
        try await self.waitUntil { await fixture.hub.subscriberCount() == 2 }
        XCTAssertEqual(
          fixture.server.publicFirehoseSubscriberAdmission.snapshot,
          .init(activeSubscribers: 2, maximumConcurrentSubscribers: 2)
        )

        let surplus = WSFrameRecorder()
        let closeFrame = try await self.awaitWithDeadline {
          try await self.runWSClientPassive(
            client,
            path: self.subscribePath,
            recorder: surplus
          )
        }
        XCTAssertEqual(
          closeFrame?.closeCode,
          .unknown(1_013),
          "a capacity refusal is 1013 Try Again Later, not a lexicon #error name"
        )
        let surplusFrames = await surplus.snapshot()
        XCTAssertTrue(
          surplusFrames.isEmpty,
          "a refused subscriber must receive no firehose frame at all"
        )
        let subscribers = await fixture.hub.subscriberCount()
        XCTAssertEqual(
          subscribers,
          2,
          "a refused subscriber must never reach the wakeup hub"
        )

        // The whole point: the listener still accepts and answers HTTP while
        // every firehose slot is held.
        try await client.execute(uri: "/health", method: .get) { response in
          XCTAssertEqual(response.status, .ok)
          XCTAssertEqual(String(buffer: response.body), "OK")
        }

        for task in held { task.cancel() }
        for task in held { _ = try? await task.value }
        try await self.waitUntil {
          fixture.server.publicFirehoseSubscriberAdmission
            .snapshot.activeSubscribers == 0
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

  /// A disconnect must refund its slot, or the reservation degrades into a
  /// permanent lockout after the first `maximumConcurrentSubscribers`
  /// connections in the process's lifetime.
  func testDisconnectedSubscriberRefundsItsReservation() async throws {
    let fixture = try await makeFixture(
      subscriberAdmission: PublicFirehoseSubscriberAdmission(
        maximumConcurrentSubscribers: 1
      )
    )
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      let admission = fixture.server.publicFirehoseSubscriberAdmission
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.admission-refund")
      )
      try await app.test(.live) { client in
        for attempt in 0..<2 {
          try await self.appendCommit(
            to: fixture.firehose,
            hub: fixture.hub,
            sourceKey: "refund-\(attempt)",
            seed: UInt8(0x60 + attempt)
          )
          let recorder = WSFrameRecorder()
          _ = try await self.awaitWithDeadline {
            try await self.runWSClient(
              client,
              path: "\(self.subscribePath)?cursor=0",
              recorder: recorder,
              closeAfterFrames: 1
            )
          }
          let delivered = await recorder.snapshot()
          XCTAssertEqual(
            delivered.count,
            1,
            "attempt \(attempt) must be admitted"
          )
          try await self.waitUntil { admission.snapshot.activeSubscribers == 0 }
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

  // MARK: - Outbound write deadline

  /// `maximumWriteDuration` must be a deadline, not a post-mortem.
  ///
  /// The shape this replaces measured each write *after* it returned. Against
  /// the case worth bounding — a peer that stopped reading, so the socket
  /// buffer fills and the write suspends inside the page — that comparison is
  /// never reached at all. This test discriminates the two directly: it is the
  /// *elapsed* time, not the thrown error, that tells them apart. A write that
  /// takes 2 s under a 50 ms limit throws `writeTooSlow` either way; only the
  /// deadline throws it at 50 ms.
  func testSlowOutboundWriteIsDroppedAtTheDeadlineNotAfterTheWrite() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "slow-write", seed: 0x81
      )
      let limits = try PublicFirehoseStreamingLimits(
        maximumWriteDuration: .milliseconds(50),
        idlePollInterval: 0.01
      )
      let tailer = PublicFirehoseTailer(
        database: fixture.firehose,
        limits: limits,
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.slow-write")
      )
      let clock = ContinuousClock()
      let started = clock.now
      do {
        try await tailer.run(
          lastSent: 0,
          outbound: { _ in try await Task.sleep(for: .seconds(2)) },
          waitForWakeup: { nil }
        )
        XCTFail("a write that outruns the deadline must drop the consumer")
      } catch let error as PublicFirehoseTailerError {
        guard case .writeTooSlow(let duration) = error else {
          return XCTFail("expected writeTooSlow, got \(error)")
        }
        XCTAssertEqual(duration, .milliseconds(50))
      }
      let elapsed = clock.now - started
      XCTAssertLessThan(
        elapsed,
        .seconds(1),
        """
        the drop must happen at the deadline, not once the write finally \
        returns — took \(elapsed)
        """
      )
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  // MARK: - Permissioned route surface

  /// F13's route half. It lives in this file because lane ownership put
  /// `SwanHTTP.swift` here; the property is about the permissioned surface,
  /// not about the firehose.
  ///
  /// `--profile` is documented as the control that decides which permissioned
  /// methods this deployment speaks, but the registration loop iterated the
  /// generated registry unfiltered, so every method the registry knows got a
  /// 503 gate whether the profile declared it or not. The filter is a no-op
  /// against both checked-in profiles — this test is what makes it observable
  /// at all, by narrowing a real profile by one endpoint.
  func testPermissionedRoutesFollowTheSelectedProfile() async throws {
    let profileURL = packageRoot().appending(
      path: "Profiles/permissioned-data-0016-2026-07-03.json"
    )
    var object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: try Data(contentsOf: profileURL))
        as? [String: Any]
    )
    let endpoints = try XCTUnwrap(object["endpoints"] as? [String])
    let divergent = Set(
      ((object["intentionalDivergences"] as? [[String: Any]]) ?? [])
        .compactMap { $0["endpoint"] as? String }
    )
    // A query so the retained-versus-dropped comparison is GET on both sides.
    let queryNSIDs = Set(
      PermissionedData0016.methods
        .filter { $0.kind == .query }
        .map(\.nsid)
    )
    let candidates = endpoints.filter {
      queryNSIDs.contains($0) && !divergent.contains($0)
    }
    let dropped = try XCTUnwrap(candidates.first)
    let retained = try XCTUnwrap(candidates.dropFirst().first)
    object["endpoints"] = endpoints.filter { $0 != dropped }
    let narrowed = try ProtocolProfile(
      data: JSONSerialization.data(withJSONObject: object)
    )

    let fixture = try await makeFixture(profileOverride: narrowed)
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.profile-surface")
      )
      try await app.test(.router) { client in
        try await client.execute(uri: "/xrpc/\(retained)", method: .get) { response in
          XCTAssertEqual(
            response.status,
            .serviceUnavailable,
            "a declared method keeps its method-correct 503 gate"
          )
        }
        try await client.execute(uri: "/xrpc/\(dropped)", method: .get) { response in
          XCTAssertEqual(
            response.status,
            .notFound,
            "a method the profile does not declare must not be advertised as pending"
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

  // MARK: - Lifecycle journal throttling

  /// The defect, stated as a property of the key rather than of the log.
  ///
  /// Every session gets a fresh UUID, so a key that included it would make
  /// every record unique and the throttle a no-op — which is why connection
  /// churn could set the journal's growth rate. Two opens differing only in
  /// connection id must collapse to one key; a genuinely different record
  /// shape must not be delayed behind them.
  func testLifecycleDiagnosticKeyIgnoresConnectionIdentity() {
    publicFirehoseDiagnosticThrottle.resetForTesting()
    let first = PublicFirehoseSubscriptionObservation(
      event: .opened,
      connectionID: UUID().uuidString,
      cursorMode: .live,
      cursorValue: nil,
      closeCategory: nil,
      closeReason: nil
    )
    let second = PublicFirehoseSubscriptionObservation(
      event: .opened,
      connectionID: UUID().uuidString,
      cursorMode: .live,
      cursorValue: nil,
      closeCategory: nil,
      closeReason: nil
    )
    XCTAssertNotEqual(first.connectionID, second.connectionID)
    XCTAssertEqual(first.diagnosticKey, second.diagnosticKey)

    let backfill = PublicFirehoseSubscriptionObservation(
      event: .opened,
      connectionID: first.connectionID,
      cursorMode: .backfill,
      cursorValue: 7,
      closeCategory: nil,
      closeReason: nil
    )
    XCTAssertNotEqual(first.diagnosticKey, backfill.diagnosticKey)
    let closed = PublicFirehoseSubscriptionObservation(
      event: .closed,
      connectionID: first.connectionID,
      cursorMode: nil,
      cursorValue: nil,
      closeCategory: .failure,
      closeReason: .subscriberCapacity
    )
    XCTAssertEqual(closed.diagnosticKey, "failure|subscriber_capacity")

    let now = ContinuousClock.now
    XCTAssertEqual(
      publicFirehoseDiagnosticThrottle.admit(
        method: first.event.rawValue, reason: first.diagnosticKey, now: now
      ),
      0,
      "the first record of a shape is always journalled"
    )
    XCTAssertNil(
      publicFirehoseDiagnosticThrottle.admit(
        method: second.event.rawValue, reason: second.diagnosticKey, now: now
      ),
      "a second open differing only in connection id must be suppressed"
    )
    XCTAssertEqual(
      publicFirehoseDiagnosticThrottle.admit(
        method: backfill.event.rawValue, reason: backfill.diagnosticKey, now: now
      ),
      0,
      "a different record shape must never wait behind an ongoing window"
    )
    publicFirehoseDiagnosticThrottle.resetForTesting()
  }

  /// The same property through the real route: anonymous connect/disconnect
  /// churn must stop setting the journal's growth rate.
  func testConnectionChurnDoesNotSetTheJournalGrowthRate() async throws {
    publicFirehoseDiagnosticThrottle.resetForTesting()
    publicFirehoseDiagnosticJournalLines.withLock { $0 = 0 }
    defer { publicFirehoseDiagnosticThrottle.resetForTesting() }
    let fixture = try await makeFixture(useDefaultObservation: true)
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      try await self.appendCommit(
        to: fixture.firehose, hub: fixture.hub, sourceKey: "churn", seed: 0x71
      )
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.churn")
      )
      let cycles = 8
      try await app.test(.live) { client in
        for _ in 0..<cycles {
          let recorder = WSFrameRecorder()
          _ = try await self.awaitWithDeadline {
            try await self.runWSClient(
              client,
              path: "\(self.subscribePath)?cursor=0",
              recorder: recorder,
              closeAfterFrames: 1
            )
          }
        }
      }
      let lines = publicFirehoseDiagnosticJournalLines.withLock { $0 }
      XCTAssertLessThanOrEqual(
        lines,
        4,
        """
        \(cycles) churn cycles produced \(cycles * 2) lifecycle records; the \
        journal must carry at most one line per distinct record shape per \
        window, not one per connection
        """
      )
      XCTAssertGreaterThan(lines, 0, "the first record of each shape stays visible")
      try await fixture.control.close()
      try await fixture.firehose.close()
    } catch {
      try? await fixture.control.close()
      try? await fixture.firehose.close()
      throw error
    }
  }

  // MARK: - Configuration

  /// `maxFrameSize` reaches only the inbound `WebSocketFrameDecoder`
  /// (`NIOTypedWebSocketServerUpgrader` at
  /// `swift-nio/Sources/NIOWebSocket/NIOWebSocketServerUpgrader.swift:316-325`),
  /// so it is a bound on what an anonymous client may make the server buffer
  /// and parse — not a floor under what Swan may send. `subscribeRepos`
  /// defines no client-to-server data frame at all, so the budget is the
  /// smallest one that still leaves control frames (bounded at 125 bytes by
  /// RFC 6455) and any future short client message comfortable.
  func testWebSocketMaxFrameSizeBoundsInboundClientFrames() {
    let configuration = SwanHTTPServer.publicFirehoseWebSocketConfiguration()
    XCTAssertEqual(
      configuration.maxFrameSize,
      4_096,
      "the ws maxFrameSize is the inbound client-frame budget, not an outbound floor"
    )
    XCTAssertLessThan(
      configuration.maxFrameSize,
      FirehoseFrameLimits.maximumFrameBytes,
      """
      the inbound budget must not be sized against the outbound frame ceiling: \
      a client that may pin one stored-frame-sized decoder buffer per socket is \
      exactly the hazard this value exists to bound
      """
    )
  }

  /// The property the small `maxFrameSize` must not break, pinned against the
  /// wire rather than against the configuration value.
  ///
  /// `WebSocketOutboundWriter.write(.binary(_:))`
  /// (`swift-websocket/Sources/WSCore/WebSocketOutboundWriter.swift:30-47`)
  /// emits one `fin: true` frame and never consults `maxFrameSize`; only
  /// `writeBinaryMessage` (`:55-71`) fragments. Swan's tailer uses the former
  /// (`PublicFirehoseStreamingRoute.swift:416`). A future switch to
  /// `writeBinaryMessage` would silently start fragmenting every `#commit`
  /// above 4 KiB, which no `subscribeRepos` consumer expects — this test is
  /// what fails when that happens.
  func testOutboundCommitFramesAboveMaxFrameSizeArriveUnfragmented() async throws {
    let fixture = try await makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      let inboundBudget = SwanHTTPServer
        .publicFirehoseWebSocketConfiguration().maxFrameSize
      let stored = try await self.appendCommit(
        to: fixture.firehose,
        hub: fixture.hub,
        sourceKey: "oversize-commit",
        seed: 0x11,
        diffCARBytes: 64 * 1_024
      )
      XCTAssertGreaterThan(
        stored.frameBytes.count,
        inboundBudget,
        "the fixture frame must exceed the inbound budget or this proves nothing"
      )
      let app = fixture.server.buildApplication(
        logger: Logger(label: "PublicFirehoseStreamingHTTPTests.unfragmented")
      )
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
        XCTAssertEqual(frames.count, 1, "one stored frame must arrive as one frame")
        let frame = try XCTUnwrap(frames.first)
        XCTAssertEqual(frame.opcode, .binary)
        XCTAssertTrue(frame.fin, "a #commit frame must not be fragmented")
        XCTAssertEqual(Data(buffer: frame.data), stored.frameBytes)
        XCTAssertFalse(
          frames.contains { $0.opcode == .continuation },
          "no continuation frame may appear on the subscribeRepos wire"
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
}
