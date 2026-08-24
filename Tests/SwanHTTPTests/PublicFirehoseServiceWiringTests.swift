import Crypto
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
import PetrelRepo
import SwanStorage
import XCTest
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanSQLite

final class PublicFirehoseServiceWiringTests: XCTestCase, @unchecked Sendable {
  private let did = "did:plc:abcdefghijklmnopqrstuvwx"
  private let genesisRevision = "3jzfcijpj2z2a"
  private let subscribePath = "/xrpc/com.atproto.sync.subscribeRepos"
  private let logger = Logger(label: "swan.public-firehose-wiring-tests")

  private struct FixedWiringAccountSource: PublicFirehoseAccountDatabaseSource {
    let accounts: [PublicFirehoseAccountDatabase]

    func publicFirehoseAccountDatabases() async throws -> [PublicFirehoseAccountDatabase] {
      accounts
    }
  }

  func testSequencerServiceSequencesARealPublicMutationAndExitsCleanly() async throws {
    let root = FileManager.default.temporaryDirectory
      .appending(path: "swan-firehose-wiring-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
      at: root,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(at: root) }

    let key = P256.Signing.PrivateKey()
    let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
    defer { Task { try? await database.close() } }
    let genesis = try PublicRepositoryGenesisCodec.create(
      did: did,
      revision: genesisRevision,
      signingKey: key
    )
    _ = try await database.installPublicRepositoryGenesis(
      genesis,
      signingPublicKey: key.publicKey,
      installedAt: Date(timeIntervalSince1970: 1_750_000_000)
    )
    let control = try await SQLiteControlDatabase(dataDirectory: root)
    defer { Task { try? await control.close() } }
    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await firehose.close() } }

    let sequencer = PublicFirehoseSequencer(
      accountSource: FixedWiringAccountSource(
        accounts: [PublicFirehoseAccountDatabase(did: did, database: database)]
      ),
      control: control,
      firehose: firehose,
      wakeup: nil
    )
    let service = SwanPublicFirehoseSequencerService(sequencer: sequencer)
    let serviceTask = Task {
      try await service.run()
    }
    defer { serviceTask.cancel() }

    let loadedInitial = try await database.loadPublicRepositoryState()
    let initial = try XCTUnwrap(loadedInitial)
    let request = try PublicRepositoryMutationRequest(
      id: "wiring-commit",
      canonicalDigest: Data(repeating: 0x77, count: 32),
      baseCommitCID: initial.commitCID
    )
    guard case let .reserved(reservation) = try await database.reservePublicRepositoryRevision(
      request,
      wallClockMicroseconds: 1_750_000_000_000_000
    ) else {
      return XCTFail("reservation unexpectedly replayed")
    }
    let path = try PublicRepositoryPath(
      collection: "app.bsky.feed.post",
      recordKey: "wiring"
    )
    let prepared = try await PublicRepositoryEngine.apply(
      repositoryDID: did,
      currentState: initial,
      blocks: database,
      revision: reservation.nextRevision,
      batch: try PublicRepositoryWriteBatch(
        writes: [.create(
          path: path,
          record: [
            "$type": .string("app.bsky.feed.post"),
            "text": .string("wiring"),
          ]
        )],
        expectedCommitCID: initial.commitCID
      ),
      signer: P256PublicRepositoryCommitSigner(privateKey: key)
    )
    let committed = try await database.applyPublicRepositoryMutation(
      reservation: reservation,
      prepared: prepared,
      firehose: .init(lifecycleGeneration: 0)
    )

    let deadline = Date().addingTimeInterval(5)
    var maxSeq: Int64 = 0
    while Date() < deadline {
      maxSeq = try await firehose.maxSequencedSeq()
      if maxSeq >= 1 { break }
      try await Task.sleep(nanoseconds: 50_000_000)
    }
    XCTAssertEqual(maxSeq, 1, "sequencer service must append within the five-second deadline")

    serviceTask.cancel()
    do {
      try await serviceTask.value
    } catch is CancellationError {
      XCTFail("service must exit cleanly on cancellation")
    }

    let events = try await firehose.events(after: 0, limit: 10)
    XCTAssertEqual(events.count, 1)
    let event = try XCTUnwrap(events.first)
    XCTAssertEqual(event.seq, 1)
    XCTAssertEqual(event.did, did)
    XCTAssertEqual(event.kind, .commit)
    XCTAssertEqual(
      event.sourceKey,
      PublicFirehoseSourceKey.commit(
        did: did,
        commitCID: committed.state.commitCID.string
      )
    )
    // DAG-CBOR text strings are raw UTF-8, so the encoded frame must contain
    // the committed revision verbatim. The commit CID encodes as a binary
    // tag-42 link (never a string) and is already proven by the source key
    // assertion above. The event time is captured inside the repository
    // transaction and is not reproducible by the test.
    XCTAssertNotNil(
      event.frameBytes.range(of: Data(committed.state.revision.utf8)),
      "frame must carry the committed revision"
    )
  }

  /// The Task 5 end-to-end chain over a live server built the way `serve`
  /// builds it (`makeServer` + the streaming runtime): a real repository
  /// mutation lands in the account outbox, the sequencer appends to
  /// `firehose.sqlite` and wakes the shared hub, and the hub's wakeup delivers
  /// the stored frame to a live `subscribeRepos` WebSocket connection.
  func testSequencerWakeupHubStreamsRealCommitOverLiveSubscribeRepos() async throws {
    let root = FileManager.default.temporaryDirectory
      .appending(path: "swan-firehose-wiring-ws-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
      at: root,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(at: root) }

    let key = P256.Signing.PrivateKey()
    let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
    defer { Task { try? await database.close() } }
    let genesis = try PublicRepositoryGenesisCodec.create(
      did: did,
      revision: genesisRevision,
      signingKey: key
    )
    _ = try await database.installPublicRepositoryGenesis(
      genesis,
      signingPublicKey: key.publicKey,
      installedAt: Date(timeIntervalSince1970: 1_750_000_000)
    )
    let control = try await SQLiteControlDatabase(dataDirectory: root)
    defer { Task { try? await control.close() } }
    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await firehose.close() } }

    // The one hub instance serves as the sequencer's wakeup sink *and* the
    // runtime's fan-out; the sequencer never sees the route.
    let hub = PublicFirehoseWakeupHub()
    let sequencer = PublicFirehoseSequencer(
      accountSource: FixedWiringAccountSource(
        accounts: [PublicFirehoseAccountDatabase(did: did, database: database)]
      ),
      control: control,
      firehose: firehose,
      wakeup: hub
    )
    let service = SwanPublicFirehoseSequencerService(sequencer: sequencer)
    let serviceTask = Task {
      try await service.run()
    }
    defer { serviceTask.cancel() }

    let profile = try ProtocolProfile.load(
      from: packageRoot().appending(
        path: "Profiles/permissioned-data-0016-2026-07-03.json"
      )
    )
    let oauthRuntime = try SwanOAuthRuntime(
      controlStore: control,
      serverKey: Data(repeating: 0x71, count: 32)
    )
    let server = SwanHTTPServer(
      profile: profile,
      configuration: .init(host: "127.0.0.1", port: 3_000),
      oauthRuntime: oauthRuntime,
      publicFirehoseStreaming: SwanPublicFirehoseStreamingRuntime(
        database: firehose,
        hub: hub,
        limits: .standard,
        logger: logger
      )
    )
    let app = server.buildApplication(logger: logger)
    do {
      try await app.test(.live) { client in
        let recorder = WSFrameRecorder()
        let wsTask = Task {
          try await self.runWSClient(
            client,
            path: self.subscribePath,
            recorder: recorder,
            closeAfterFrames: 1
          )
        }
        // A live (no-cursor) connection subscribing to the same hub instance
        // the sequencer wakes proves the wiring: the route's hub subscription
        // is the sequencer's wakeup sink.
        try await self.waitUntil { await hub.subscriberCount() == 1 }

        let loadedInitial = try await database.loadPublicRepositoryState()
        let initial = try XCTUnwrap(loadedInitial)
        let request = try PublicRepositoryMutationRequest(
          id: "wiring-live-commit",
          canonicalDigest: Data(repeating: 0x77, count: 32),
          baseCommitCID: initial.commitCID
        )
        guard case let .reserved(reservation) = try await database.reservePublicRepositoryRevision(
          request,
          wallClockMicroseconds: 1_750_000_000_000_000
        ) else {
          return XCTFail("reservation unexpectedly replayed")
        }
        let path = try PublicRepositoryPath(
          collection: "app.bsky.feed.post",
          recordKey: "wiring-live"
        )
        let prepared = try await PublicRepositoryEngine.apply(
          repositoryDID: did,
          currentState: initial,
          blocks: database,
          revision: reservation.nextRevision,
          batch: try PublicRepositoryWriteBatch(
            writes: [.create(
              path: path,
              record: [
                "$type": .string("app.bsky.feed.post"),
                "text": .string("wiring-live"),
              ]
            )],
            expectedCommitCID: initial.commitCID
          ),
          signer: P256PublicRepositoryCommitSigner(privateKey: key)
        )
        let committed = try await database.applyPublicRepositoryMutation(
          reservation: reservation,
          prepared: prepared,
          firehose: .init(lifecycleGeneration: 0)
        )

        // The sequencer's append must reach the connection through the hub's
        // wakeup (not through a re-poll of a pre-seeded log).
        try await self.waitUntil { await recorder.snapshot().count == 1 }
        let frames = await recorder.snapshot()
        XCTAssertEqual(frames.count, 1)
        let frame = try XCTUnwrap(frames.first)
        XCTAssertEqual(frame.opcode, .binary)
        let header = try self.decodeFrameHeader(frame)
        XCTAssertEqual(header.op, 1)
        XCTAssertEqual(header.type, "#commit")
        let stored = try await firehose.events(after: 0, limit: 10)
        XCTAssertEqual(stored.map(\.seq), [1])
        XCTAssertEqual(
          Data(buffer: frame.data),
          stored.first?.frameBytes,
          "the server must ship the stored frame byte-for-byte"
        )
        XCTAssertNotNil(
          Data(buffer: frame.data).range(of: Data(committed.state.revision.utf8)),
          "frame must carry the committed revision"
        )

        let closeFrame = try await self.awaitWithDeadline { try await wsTask.value }
        XCTAssertEqual(closeFrame?.closeCode, .normalClosure)
        try await self.waitUntil { await hub.subscriberCount() == 0 }
      }
      serviceTask.cancel()
      do {
        try await serviceTask.value
      } catch is CancellationError {
        XCTFail("service must exit cleanly on cancellation")
      }
    } catch {
      serviceTask.cancel()
      throw error
    }
  }

  func testRetentionServicePrunesImmediatelyAndSignalsSubscribers() async throws {
    let root = FileManager.default.temporaryDirectory
      .appending(path: "swan-firehose-retention-service-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
      at: root,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(at: root) }

    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await firehose.close() } }
    let hub = PublicFirehoseWakeupHub()
    let stream = await hub.subscribe()
    var iterator = stream.makeAsyncIterator()
    _ = try await firehose.appendBatch(
      [FirehoseAppendItem(
        sourceKey: "retention-service",
        batchID: nil,
        did: "did:plc:retentionservice000000000",
        kind: .identity
      ) { _ in Data([0x01]) }],
      now: Date(timeIntervalSince1970: 1_700_000_000)
    )

    let service = try SwanPublicFirehoseRetentionService(
      database: firehose,
      hub: hub,
      policy: try PublicFirehoseRetentionPolicy(
        maximumAge: .seconds(1),
        maximumRows: 100,
        maximumBytes: 5_000_000
      ),
      interval: .seconds(60),
      logger: Logger(label: "retention-service-test")
    )
    let task = Task { try await service.run() }
    defer { task.cancel() }

    let wakeup = await iterator.next()
    XCTAssertEqual(wakeup, 1)
    let retained = try await firehose.retainedFromSeq()
    XCTAssertEqual(
      retained,
      2,
      "the sole row (seq 1) was deleted, so the boundary is one past it, "
        + "not the deleted sequence itself"
    )
  }

  /// End-to-end production composition proof: the same five objects
  /// `SwanCommand.Serve` builds under `--enable-public-firehose` — one
  /// `SQLiteFirehoseDatabase`, one `PublicFirehoseWakeupHub`, one
  /// `SwanPublicFirehoseSequencerService`, one
  /// `SwanPublicFirehoseRetentionService`, and one
  /// `SwanPublicFirehoseStreamingRuntime` — constructed together and run as
  /// two concurrent services against one live `subscribeRepos` route.
  ///
  /// An event well outside the retention window and a fresh one inside it
  /// are seeded directly (the sequencer has no accounts registered here; its
  /// wiring into this exact composition is what is under test, not its
  /// mutation-draining behavior, which Task 1's and this file's other tests
  /// already cover). The running retention service — not a test-driven
  /// `prune` call — must age out the old row and advance the retained
  /// cursor, after which a connection with a cursor below that boundary must
  /// receive the `OutdatedCursor` info frame followed by the retained
  /// frame's exact stored bytes.
  func testProductionCompositionRunsSequencerRetentionAndStreamingOverSharedHubAndDatabase() async throws {
    let root = FileManager.default.temporaryDirectory
      .appending(path: "swan-firehose-composition-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
      at: root,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(at: root) }

    let control = try await SQLiteControlDatabase(dataDirectory: root)
    defer { Task { try? await control.close() } }
    let firehose = try await SQLiteFirehoseDatabase(dataDirectory: root)
    defer { Task { try? await firehose.close() } }

    // One hub instance backs the sequencer's wakeup sink, the retention
    // service's advance signal, and the streaming runtime's fan-out below —
    // the exact object graph `SwanCommand.Serve` wires together.
    let hub = PublicFirehoseWakeupHub()
    let sequencer = PublicFirehoseSequencer(
      accountSource: FixedWiringAccountSource(accounts: []),
      control: control,
      firehose: firehose,
      wakeup: hub
    )
    let sequencerService = SwanPublicFirehoseSequencerService(sequencer: sequencer)
    let sequencerTask = Task { try await sequencerService.run() }
    defer { sequencerTask.cancel() }

    let retentionService = try SwanPublicFirehoseRetentionService(
      database: firehose,
      hub: hub,
      policy: try PublicFirehoseRetentionPolicy(
        maximumAge: .seconds(3_600),
        maximumRows: 100,
        maximumBytes: 5_000_000
      ),
      interval: .milliseconds(50),
      logger: logger
    )
    let retentionTask = Task { try await retentionService.run() }
    defer { retentionTask.cancel() }

    let profile = try ProtocolProfile.load(
      from: packageRoot().appending(
        path: "Profiles/permissioned-data-0016-2026-07-03.json"
      )
    )
    let oauthRuntime = try SwanOAuthRuntime(
      controlStore: control,
      serverKey: Data(repeating: 0x71, count: 32)
    )
    let server = SwanHTTPServer(
      profile: profile,
      configuration: .init(host: "127.0.0.1", port: 3_000),
      oauthRuntime: oauthRuntime,
      publicFirehoseStreaming: SwanPublicFirehoseStreamingRuntime(
        database: firehose,
        hub: hub,
        limits: .standard,
        logger: logger
      )
    )
    let app = server.buildApplication(logger: logger)
    do {
      try await app.test(.live) { client in
        // Phase 1 — shared-hub identity: the database is still empty here,
        // so this live (no-cursor) connection has nothing to deliver and
        // cannot race a client-initiated close the way a connection with
        // ready data could. That gives a stable window to prove the hub
        // this route subscribed to is the exact instance the sequencer and
        // retention service above were constructed with. The connection is
        // torn down by cancellation (never fed a frame to close itself on)
        // once this phase's assertions are done.
        let liveRecorder = WSFrameRecorder()
        let liveTask = Task {
          try await self.runWSClient(
            client,
            path: self.subscribePath,
            recorder: liveRecorder
          )
        }
        defer { liveTask.cancel() }
        try await self.waitUntil { await hub.subscriberCount() == 1 }

        let subscriberCount = await hub.subscriberCount()
        XCTAssertEqual(subscriberCount, 1)
        let maxSeq = try await firehose.maxSequencedSeq()
        await hub.firehoseRetentionDidAdvance(maxSeq: maxSeq)

        // Phase 2 — retained-cursor recovery: an old event (well past the
        // one-hour retention window) and a newer one (effectively age zero)
        // seeded directly into the shared database. Only the running
        // retention service, polling every 50ms, prunes the former and
        // advances the retained cursor to the latter's sequence.
        _ = try await firehose.appendBatch(
          [FirehoseAppendItem(
            sourceKey: "composition-old",
            batchID: nil,
            did: "did:plc:compositionoldaaaaaaaaaaaa",
            kind: .identity
          ) { _ in Data([0x01]) }],
          now: Date(timeIntervalSince1970: 1_700_000_000)
        )
        _ = try await firehose.appendBatch(
          [FirehoseAppendItem(
            sourceKey: "composition-new",
            batchID: nil,
            did: "did:plc:compositionnewaaaaaaaaaaaa",
            kind: .identity
          ) { _ in Data([0x02]) }],
          now: Date()
        )
        try await self.waitUntil { (try? await firehose.retainedFromSeq()) == 2 }

        // Seq 1 is pruned and seq 2 is retained, so cursor=1 is below the
        // retained boundary (2): the connection must report `OutdatedCursor`
        // and then stream the one retained row.
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
        let closeFrame = try await self.awaitWithDeadline { try await wsTask.value }
        XCTAssertEqual(closeFrame?.closeCode, .normalClosure)

        let frames = await recorder.snapshot()
        XCTAssertEqual(frames.count, 2)
        try self.assertInfoFrame(frames[0], name: "OutdatedCursor")

        let stored = try await firehose.events(after: 0, limit: 10)
        XCTAssertEqual(Data(buffer: frames[1].data), stored.last?.frameBytes)
      }
      sequencerTask.cancel()
      retentionTask.cancel()
      do {
        try await sequencerTask.value
      } catch is CancellationError {
        XCTFail("sequencer service must exit cleanly on cancellation")
      }
      do {
        try await retentionTask.value
      } catch is CancellationError {
        XCTFail("retention service must exit cleanly on cancellation")
      }
    } catch {
      sequencerTask.cancel()
      retentionTask.cancel()
      throw error
    }
  }

  // MARK: - WebSocket client helpers (mirroring PublicFirehoseStreamingHTTPTests)

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

  /// Connects the WS test client, records every inbound frame, and closes
  /// after `closeAfterFrames` binary frames have arrived.
  private func runWSClient(
    _ client: any TestClientProtocol,
    path: String,
    recorder: WSFrameRecorder,
    closeAfterFrames: Int = .max
  ) async throws -> WebSocketCloseFrame? {
    try await client.ws(
      path,
      configuration: .init(maxFrameSize: 5_000_000),
      logger: Logger(label: "PublicFirehoseServiceWiringTests.ws-client")
    ) { inbound, outbound, _ in
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

  private func packageRoot() -> URL {
    URL(filePath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
  }
}
