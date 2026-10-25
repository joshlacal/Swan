import Crypto
import Foundation
import Petrel
import SQLiteNIO
import SwanCore
import SwanSpaces
import SwanStorage
import XCTest

@testable import SwanSQLite

final class RepositoryCARPaginationTests: XCTestCase {
  func testRepositoryCARUsesOneIndexedCanonicalMetadataPassAndDropsItAfterSuccess() async throws {
    let fixture = try RepositoryCARPaginationFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    defer { Task { try? await database.close() } }
    try await fixture.seed(database)

    let barrier = RepositoryCARPaginationBarrier()
    await database.installTestingHooks(
      SQLiteTestingHooks(afterSnapshotStateRead: { await barrier.pause() })
    )
    let snapshotTask = Task {
      try await database.prepareRepositoryCARSnapshot(
        space: fixture.space,
        author: fixture.author
      )
    }
    await barrier.waitUntilPaused()
    defer { Task { await barrier.release() } }

    let tempTables = try await database.connection.query(
      """
      SELECT name
      FROM sqlite_temp_master
      WHERE type = 'table' AND name = 'swan_repository_car_index'
      """
    )
    XCTAssertEqual(
      tempTables.count,
      1,
      "the canonical path projection must be materialized exactly once per CAR snapshot"
    )

    if tempTables.count == 1 {
      let metadataCount = try await database.connection.query(
        "SELECT COUNT(*) AS record_count FROM temp.swan_repository_car_index"
      )
      XCTAssertEqual(metadataCount.first?.column("record_count")?.integer, fixture.records.count)

      let canonicalPlan = try await database.connection.query(
        """
        EXPLAIN QUERY PLAN
        SELECT records.collection, records.rkey, records.value,
               records.cid, records.revision
        FROM temp.swan_repository_car_index AS metadata
        JOIN permissioned_space_records AS records
          ON records.space_uri = ?
         AND records.author_did = ?
         AND records.collection = metadata.collection
         AND records.rkey = metadata.rkey
        WHERE (metadata.path_length, metadata.path_bytes) > (?, ?)
        ORDER BY metadata.path_length, metadata.path_bytes
        LIMIT 1
        """,
        [
          .text(fixture.space.rawValue),
          .text(fixture.author),
          .integer(0),
          Data().sqliteData!,
        ]
      )
      assertIndexedWithoutTemporarySort(canonicalPlan)

      let recordPlan = try await database.connection.query(
        """
        EXPLAIN QUERY PLAN
        SELECT records.collection, records.rkey, records.cid,
               records.revision, length(records.value) AS value_byte_count
        FROM temp.swan_repository_car_index AS metadata
        JOIN permissioned_space_records AS records
          ON records.space_uri = ? AND records.author_did = ?
         AND records.collection = metadata.collection
         AND records.rkey = metadata.rkey
         AND records.cid = metadata.cid
        WHERE (metadata.path_length, metadata.path_bytes) > (?, ?)
        ORDER BY metadata.path_length, metadata.path_bytes
        LIMIT 1
        """,
        [
          .text(fixture.space.rawValue),
          .text(fixture.author),
          .integer(0),
          Data().sqliteData!,
        ]
      )
      assertIndexedWithoutTemporarySort(recordPlan)
    }

    await barrier.release()
    let preparedResult = try await snapshotTask.value
    let prepared = try XCTUnwrap(preparedResult)
    defer { prepared.spool.cleanup() }
    let recovered = try await fixture.verify(prepared)
    XCTAssertEqual(
      recovered.records.map(\.uri),
      fixture.records.map(\.uri).sorted {
        ($0.collection, $0.rkey) < ($1.collection, $1.rkey)
      },
      "same-collection records must advance by the full (collection, rkey) keyset"
    )

    let remainingTempTables = try await database.connection.query(
      """
      SELECT name
      FROM sqlite_temp_master
      WHERE type = 'table' AND name = 'swan_repository_car_index'
      """
    )
    XCTAssertTrue(remainingTempTables.isEmpty)
  }

  func testRepositoryCARCancellationDropsCanonicalMetadataBeforeReleasingConnection() async throws {
    let fixture = try RepositoryCARPaginationFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    defer { Task { try? await database.close() } }
    try await fixture.seed(database)

    let barrier = RepositoryCARPaginationBarrier()
    await database.installTestingHooks(
      SQLiteTestingHooks(afterSnapshotStateRead: { await barrier.pause() })
    )
    let snapshotTask = Task {
      try await database.prepareRepositoryCARSnapshot(
        space: fixture.space,
        author: fixture.author
      )
    }
    await barrier.waitUntilPaused()
    defer { Task { await barrier.release() } }
    snapshotTask.cancel()
    await barrier.release()

    do {
      let unexpected = try await snapshotTask.value
      unexpected?.spool.cleanup()
      XCTFail("a cancelled CAR snapshot must not complete or retain a spool")
    } catch is CancellationError {
      // Expected.
    } catch {
      XCTFail("expected CancellationError, got \(error)")
    }

    let remainingTempTables = try await database.connection.query(
      """
      SELECT name
      FROM sqlite_temp_master
      WHERE type = 'table' AND name = 'swan_repository_car_index'
      """
    )
    XCTAssertTrue(remainingTempTables.isEmpty)
    // Cancellation must roll back before releasing the same connection. A
    // fresh transaction fails here if cleanup inherited the cancelled task.
    _ = try await database.connection.query("BEGIN")
    _ = try await database.connection.query("ROLLBACK")
  }

  func testRepositoryCARValidationFailureDropsCanonicalMetadata() async throws {
    let fixture = try RepositoryCARPaginationFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let database = try await fixture.open()
    defer { Task { try? await database.close() } }
    try await fixture.seed(database)

    _ = try await database.connection.query(
      """
      UPDATE permissioned_space_records
      SET cid = ?
      WHERE space_uri = ? AND author_did = ?
        AND collection = ? AND rkey = ?
      """,
      [
        .text(CID.fromDAGCBOR(Data([0xa1, 0x61, 0x7a, 0x01])).string),
        .text(fixture.space.rawValue),
        .text(fixture.author),
        .text(fixture.records[0].uri.collection),
        .text(fixture.records[0].uri.rkey),
      ]
    )

    do {
      let unexpected = try await database.prepareRepositoryCARSnapshot(
        space: fixture.space,
        author: fixture.author
      )
      unexpected?.spool.cleanup()
      XCTFail("a record CID/value mismatch must fail closed")
    } catch {
      guard let repositoryError = error as? SQLiteRepositoryError,
            case .corruptDatabase = repositoryError else {
        return XCTFail("expected corruptDatabase, got \(error)")
      }
    }

    let remainingTempTables = try await database.connection.query(
      """
      SELECT name
      FROM sqlite_temp_master
      WHERE type = 'table' AND name = 'swan_repository_car_index'
      """
    )
    XCTAssertTrue(remainingTempTables.isEmpty)
  }

  private func assertIndexedWithoutTemporarySort(
    _ plan: [SQLiteRow],
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    let details = plan.compactMap { $0.column("detail")?.string?.uppercased() }
    XCTAssertFalse(
      details.contains { $0.contains("USE TEMP B-TREE") },
      "query plan must not repeat a temporary ORDER BY sort: \(details)",
      file: file,
      line: line
    )
    XCTAssertTrue(
      details.contains { $0.contains("PRIMARY KEY") || $0.contains("INDEX") },
      "query plan must advance through an index: \(details)",
      file: file,
      line: line
    )
  }
}

private struct RepositoryCARPaginationFixture {
  struct Record {
    let uri: SpaceRecordURI
    let value: Data
  }

  let root: URL
  let author = "did:plc:alice"
  let space: SpaceURI
  let records: [Record]

  init() throws {
    let fixtureAuthor = "did:plc:alice"
    root = FileManager.default.temporaryDirectory
      .appending(path: "RepositoryCARPaginationTests-\(UUID().uuidString)")
    let fixtureSpace = try SpaceURI(
      authority: fixtureAuthor,
      spaceType: "app.bsky.bookmarks",
      skey: "self"
    )
    space = fixtureSpace
    records = try [
      ("app.bsky.feed.post", "zeta", Data([0xa1, 0x61, 0x61, 0x01])),
      ("app.bsky.feed.post", "alpha", Data([0xa1, 0x61, 0x62, 0x02])),
      ("app.bsky.actor.profile", "self", Data([0xa1, 0x61, 0x63, 0x03])),
      ("app.bsky.feed.post", "middle", Data([0xa1, 0x61, 0x64, 0x04])),
    ].map { collection, rkey, value in
      Record(
        uri: try SpaceRecordURI(
          space: fixtureSpace,
          author: fixtureAuthor,
          collection: collection,
          rkey: rkey
        ),
        value: value
      )
    }
  }

  func open() async throws -> SQLiteAccountDatabase {
    try await SQLiteAccountDatabase(dataDirectory: root, did: author)
  }

  func seed(_ database: SQLiteAccountDatabase) async throws {
    _ = try await database.apply(
      space: space,
      author: author,
      expectedRevision: 0,
      requestID: UUID(),
      wireRevision: try TID(tidString: "2222222222222"),
      writes: records.reversed().map {
        .put(uri: $0.uri, value: $0.value, cid: CID.fromDAGCBOR($0.value).string)
      }
    )
  }

  func verify(
    _ prepared: AuthorizedSpaceRepositoryCARSnapshot
  ) async throws -> VerifiedSpaceCARRecovery {
    let revision = try XCTUnwrap(prepared.state.wireRevision)
    let key = P256.Signing.PrivateKey()
    let envelope = try SpaceCommitCodec.sign(
      context: try SpaceCommitContext(
        space: space,
        author: author,
        rev: revision,
        ikm: Data(repeating: 0x29, count: 32)
      ),
      commitment: prepared.state.commitment,
      key: key
    )
    var car = try SpaceCARCodec.recoveryPrefix(
      commit: envelope,
      indexCID: prepared.spool.indexCID
    )
    try await prepared.spool.streamBody { car.append($0) }
    return try SpaceCARCodec.verifyRecovery(
      car,
      space: space,
      author: author,
      publicKey: key.publicKey
    )
  }
}

private actor RepositoryCARPaginationBarrier {
  private var pauseContinuation: CheckedContinuation<Void, Never>?
  private var startedContinuation: CheckedContinuation<Void, Never>?
  private var paused = false

  func pause() async {
    paused = true
    startedContinuation?.resume()
    startedContinuation = nil
    await withCheckedContinuation { pauseContinuation = $0 }
  }

  func waitUntilPaused() async {
    guard !paused else { return }
    await withCheckedContinuation { startedContinuation = $0 }
  }

  func release() {
    pauseContinuation?.resume()
    pauseContinuation = nil
  }
}
