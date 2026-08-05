import Crypto
import Foundation
import Petrel
import SwanPublicFirehose
import SwanPublicRepository
import SwanStorage
import XCTest
@testable import SwanHTTP
@testable import SwanSQLite

final class PublicFirehoseServiceWiringTests: XCTestCase {
  private let did = "did:plc:abcdefghijklmnopqrstuvwx"
  private let genesisRevision = "3jzfcijpj2z2a"

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
      prepared: prepared
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
}
