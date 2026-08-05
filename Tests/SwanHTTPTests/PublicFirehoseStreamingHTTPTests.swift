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
    includeRuntime: Bool = true
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
        configuration: .init(host: "127.0.0.1", port: 3_000),
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
  @discardableResult
  private func appendCommit(
    to firehose: SQLiteFirehoseDatabase,
    hub: PublicFirehoseWakeupHub,
    sourceKey: String,
    seed: UInt8
  ) async throws -> FirehoseStoredEvent {
    let sequences = try await firehose.appendBatch(
      [commitItem(sourceKey: sourceKey, seed: seed)],
      now: epoch
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

  // MARK: - Configuration

  func testWebSocketMaxFrameSizeAtLeastFrameLimit() {
    XCTAssertGreaterThanOrEqual(
      SwanHTTPServer.publicFirehoseWebSocketConfiguration().maxFrameSize,
      FirehoseFrameLimits.maximumFrameBytes,
      "the ws maxFrameSize must cover the largest stored firehose frame"
    )
  }
}
