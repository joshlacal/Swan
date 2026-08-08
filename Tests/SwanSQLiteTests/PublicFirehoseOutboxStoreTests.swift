import Foundation
import SQLiteNIO
import SwanCore
import SwanPublicFirehose
import XCTest
@testable import SwanSQLite

final class PublicFirehoseOutboxStoreTests: XCTestCase {
  private let did = "did:plc:abcdefghijklmnopqrstuvwx"
  private let epoch = Date(timeIntervalSince1970: 1_785_844_800)

  private static let payloadEncoder: JSONEncoder = {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return encoder
  }()

  private func makeDatabase() async throws -> (URL, SQLiteAccountDatabase) {
    let root = FileManager.default.temporaryDirectory
      .appending(path: "swan-firehose-outbox-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
      at: root,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
    return (root, database)
  }

  private func commitRow(
    sourceKey: String = "did:plc:abc|commit|bafy1",
    payload: Data? = nil,
    carBytes: Data = Data("car".utf8),
    generation: Int64 = 0
  ) async throws {
    let storedPayload = try payload ?? Self.payloadEncoder.encode(
      PublicFirehoseCommitMaterial(
        did: "did:plc:abc",
        rev: "3kabc",
        since: nil,
        commitCID: "bafycid",
        prevDataCID: nil,
        ops: [],
        time: "2026-08-04T12:00:00.000Z"
      )
    )
    _ = try await database.enqueuePublicFirehoseEvent(
      sourceKey: sourceKey,
      kind: .commit,
      lifecycleGeneration: generation,
      payload: storedPayload,
      carBytes: carBytes,
      now: epoch
    )
  }

  private var database: SQLiteAccountDatabase!
  private var root: URL!

  override func setUp() async throws {
    let (root, database) = try await makeDatabase()
    self.root = root
    self.database = database
  }

  override func tearDown() async throws {
    if let database {
      try? await database.close()
    }
    if let root {
      try? FileManager.default.removeItem(at: root)
    }
  }

  func testEnqueueLeaseComplete() async throws {
    try await commitRow()
    let lease = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch,
      leaseDuration: 30
    )
    let leased = try XCTUnwrap(lease)
    XCTAssertEqual(leased.row.sourceKey, "did:plc:abc|commit|bafy1")
    XCTAssertEqual(leased.row.kind, .commit)
    XCTAssertEqual(leased.row.lifecycleGeneration, 0)
    XCTAssertEqual(leased.row.attempts, 0)
    XCTAssertEqual(leased.expiresAt, epoch.addingTimeInterval(30))

    let completed = try await database.completePublicFirehoseOutboxLease(
      id: leased.row.id,
      token: leased.token
    )
    XCTAssertTrue(completed)
    let oldest = try await database.oldestPendingPublicFirehoseOutbox()
    XCTAssertNil(oldest)
  }

  func testExactSourceKeyReplayReturnsFalseAndLeavesOneRow() async throws {
    try await commitRow()
    let replayed = try await database.enqueuePublicFirehoseEvent(
      sourceKey: "did:plc:abc|commit|bafy1",
      kind: .commit,
      lifecycleGeneration: 0,
      payload: try Self.payloadEncoder.encode(
        PublicFirehoseCommitMaterial(
          did: "did:plc:abc", rev: "3kabc", since: nil,
          commitCID: "bafycid", prevDataCID: nil, ops: [],
          time: "2026-08-04T12:00:00.000Z"
        )
      ),
      carBytes: Data("car".utf8),
      now: epoch
    )
    XCTAssertFalse(replayed)
    let pending = try await database.pendingPublicFirehoseOutbox()
    XCTAssertEqual(pending.count, 1)
  }

  func testCompletedOutboxRowRemainsExactReplayAnchorButIsNotPendingOrLeaseable() async throws {
    try await commitRow()
    let optionalLease = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch,
      leaseDuration: 30
    )
    let lease = try XCTUnwrap(optionalLease)
    let completed = try await database.completePublicFirehoseOutboxLease(
      id: lease.row.id,
      token: lease.token
    )
    XCTAssertTrue(completed)

    let replayed = try await database.enqueuePublicFirehoseEvent(
      sourceKey: "did:plc:abc|commit|bafy1",
      kind: .commit,
      lifecycleGeneration: 0,
      payload: try Self.payloadEncoder.encode(
        PublicFirehoseCommitMaterial(
          did: "did:plc:abc", rev: "3kabc", since: nil,
          commitCID: "bafycid", prevDataCID: nil, ops: [],
          time: "2026-08-04T12:00:00.000Z"
        )
      ),
      carBytes: Data("car".utf8),
      now: epoch.addingTimeInterval(300)
    )

    XCTAssertFalse(replayed)
    let oldest = try await database.oldestPendingPublicFirehoseOutbox()
    XCTAssertNil(oldest)
    let pending = try await database.pendingPublicFirehoseOutbox()
    XCTAssertTrue(pending.isEmpty)
    let recoveredLease = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch.addingTimeInterval(301),
      leaseDuration: 30
    )
    XCTAssertNil(recoveredLease)
  }

  func testChangedMaterialAgainstCompletedOutboxAnchorRemainsConflict() async throws {
    try await commitRow()
    let optionalLease = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch,
      leaseDuration: 30
    )
    let lease = try XCTUnwrap(optionalLease)
    let completed = try await database.completePublicFirehoseOutboxLease(
      id: lease.row.id,
      token: lease.token
    )
    XCTAssertTrue(completed)

    do {
      _ = try await database.enqueuePublicFirehoseEvent(
        sourceKey: "did:plc:abc|commit|bafy1",
        kind: .commit,
        lifecycleGeneration: 0,
        payload: Data("changed".utf8),
        carBytes: Data("car".utf8),
        now: epoch.addingTimeInterval(300)
      )
      XCTFail("changed material against a completed source key must conflict")
    } catch let error as SQLiteRepositoryError {
      XCTAssertEqual(
        error,
        .conflictingPublicFirehoseSourceKey("did:plc:abc|commit|bafy1")
      )
    }
    let pending = try await database.pendingPublicFirehoseOutbox()
    XCTAssertTrue(pending.isEmpty)
  }

  func testCorruptMaterialInCompletedOutboxAnchorFailsAsCorruptDatabase() async throws {
    try await commitRow()
    let optionalLease = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch,
      leaseDuration: 30
    )
    let lease = try XCTUnwrap(optionalLease)
    let completed = try await database.completePublicFirehoseOutboxLease(
      id: lease.row.id,
      token: lease.token
    )
    XCTAssertTrue(completed)
    try await database.close()
    database = nil

    let raw = try await SQLiteConnection.open(
      storage: .file(path: SQLiteLayout.accountDatabase(in: root, did: did).path)
    )
    _ = try await raw.query(
      "UPDATE public_event_outbox SET payload = ? WHERE id = ?",
      [Data("not-json".utf8).sqliteData!, .integer(Int(lease.row.id))]
    )
    try await raw.close()

    database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
    do {
      _ = try await database.enqueuePublicFirehoseEvent(
        sourceKey: "did:plc:abc|commit|bafy1",
        kind: .commit,
        lifecycleGeneration: 0,
        payload: try Self.payloadEncoder.encode(
          PublicFirehoseCommitMaterial(
            did: "did:plc:abc", rev: "3kabc", since: nil,
            commitCID: "bafycid", prevDataCID: nil, ops: [],
            time: "2026-08-04T12:00:00.000Z"
          )
        ),
        carBytes: Data("car".utf8),
        now: epoch.addingTimeInterval(300)
      )
      XCTFail("corrupt retained material must fail as corrupt database")
    } catch let error as SQLiteRepositoryError {
      guard case .corruptDatabase = error else {
        return XCTFail("expected corruptDatabase, got \(error)")
      }
    }
  }

  func testSameSourceKeyWithChangedContentThrowsConflict() async throws {
    try await commitRow()
    for (kind, generation, payload, car) in [
      (PublicFirehoseEventKind.commit, Int64(1), Data("payload".utf8), Data("car".utf8)),
      (PublicFirehoseEventKind.commit, Int64(0), Data("other".utf8), Data("car".utf8)),
      (PublicFirehoseEventKind.commit, Int64(0), Data("payload".utf8), Data("other".utf8)),
      (PublicFirehoseEventKind.sync, Int64(0), Data("payload".utf8), Data("car".utf8)),
    ] {
      do {
        _ = try await database.enqueuePublicFirehoseEvent(
          sourceKey: "did:plc:abc|commit|bafy1",
          kind: kind,
          lifecycleGeneration: generation,
          payload: payload,
          carBytes: car,
          now: epoch
        )
        XCTFail("expected conflictingPublicFirehoseSourceKey")
      } catch let error as SQLiteRepositoryError {
        XCTAssertEqual(
          error,
          .conflictingPublicFirehoseSourceKey("did:plc:abc|commit|bafy1")
        )
      }
    }
    let pending = try await database.pendingPublicFirehoseOutbox()
    XCTAssertEqual(pending.count, 1)
  }

  func testActiveLeaseIsInvisibleUntilExpiry() async throws {
    try await commitRow()
    let firstLease = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch,
      leaseDuration: 60
    )
    let first = try XCTUnwrap(firstLease)
    let midLease = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch.addingTimeInterval(30),
      leaseDuration: 60
    )
    XCTAssertNil(midLease)
    let secondLease = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch.addingTimeInterval(61),
      leaseDuration: 60
    )
    let second = try XCTUnwrap(secondLease)
    XCTAssertEqual(second.row.id, first.row.id)
  }

  func testStaleTokenCannotCompleteOrFail() async throws {
    try await commitRow()
    let firstLease = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch,
      leaseDuration: 30
    )
    let first = try XCTUnwrap(firstLease)
    let secondLease = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch.addingTimeInterval(31),
      leaseDuration: 30
    )
    let second = try XCTUnwrap(secondLease)
    let staleComplete = try await database.completePublicFirehoseOutboxLease(
      id: first.row.id,
      token: first.token
    )
    XCTAssertFalse(staleComplete)
    let staleFail = try await database.failPublicFirehoseOutboxLease(
      id: first.row.id,
      token: first.token,
      retryAt: epoch.addingTimeInterval(32)
    )
    XCTAssertNil(staleFail)
    let currentComplete = try await database.completePublicFirehoseOutboxLease(
      id: second.row.id,
      token: second.token
    )
    XCTAssertTrue(currentComplete)
  }

  func testFailureIncrementsAttemptsAndReschedules() async throws {
    try await commitRow()
    let firstLease = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch,
      leaseDuration: 30
    )
    let first = try XCTUnwrap(firstLease)
    let attempts = try await database.failPublicFirehoseOutboxLease(
      id: first.row.id,
      token: first.token,
      retryAt: epoch.addingTimeInterval(120)
    )
    XCTAssertEqual(attempts, 1)
    let blocked = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch.addingTimeInterval(60),
      leaseDuration: 30
    )
    XCTAssertNil(blocked)
    let retriedLease = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch.addingTimeInterval(121),
      leaseDuration: 30
    )
    let retried = try XCTUnwrap(retriedLease)
    XCTAssertEqual(retried.row.attempts, 1)
  }

  func testStrictHeadOfLineOrdering() async throws {
    try await commitRow(sourceKey: "did:plc:abc|commit|k1", payload: Data("k1".utf8))
    try await commitRow(sourceKey: "did:plc:abc|commit|k2", payload: Data("k2".utf8))

    let k1Lease = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch,
      leaseDuration: 30
    )
    let k1 = try XCTUnwrap(k1Lease)
    XCTAssertEqual(k1.row.sourceKey, "did:plc:abc|commit|k1")
    _ = try await database.failPublicFirehoseOutboxLease(
      id: k1.row.id,
      token: k1.token,
      retryAt: epoch.addingTimeInterval(300)
    )

    let blockedHead = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch.addingTimeInterval(60),
      leaseDuration: 30
    )
    XCTAssertNil(blockedHead)

    let afterDeadlineLease = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch.addingTimeInterval(301),
      leaseDuration: 30
    )
    let afterDeadline = try XCTUnwrap(afterDeadlineLease)
    XCTAssertEqual(afterDeadline.row.sourceKey, "did:plc:abc|commit|k1")
    let completedAfterDeadline = try await database.completePublicFirehoseOutboxLease(
      id: afterDeadline.row.id,
      token: afterDeadline.token
    )
    XCTAssertTrue(completedAfterDeadline)

    let leasedK2 = try await database.leaseNextPublicFirehoseOutbox(
      now: epoch.addingTimeInterval(302),
      leaseDuration: 30
    )
    let k2 = try XCTUnwrap(leasedK2)
    XCTAssertEqual(k2.row.sourceKey, "did:plc:abc|commit|k2")
  }

  func testPendingRowsAreReturnedInAscendingIDOrder() async throws {
    for index in 1 ... 5 {
      try await commitRow(
        sourceKey: "did:plc:abc|commit|k\(index)",
        payload: Data("k\(index)".utf8)
      )
    }
    let pending = try await database.pendingPublicFirehoseOutbox()
    XCTAssertEqual(pending.map(\.sourceKey), [
      "did:plc:abc|commit|k1",
      "did:plc:abc|commit|k2",
      "did:plc:abc|commit|k3",
      "did:plc:abc|commit|k4",
      "did:plc:abc|commit|k5",
    ])
  }

  func testIdentityAndAccountKindsRejectedBeforeSQL() async throws {
    for kind in [PublicFirehoseEventKind.identity, .account] {
      do {
        _ = try await database.enqueuePublicFirehoseEvent(
          sourceKey: "did:plc:abc|identity|bafy1",
          kind: kind,
          lifecycleGeneration: 0,
          payload: Data("payload".utf8),
          carBytes: Data("car".utf8),
          now: epoch
        )
        XCTFail("expected malformed error for \(kind)")
      } catch let error as SwanError {
        guard case .malformed = error else {
          return XCTFail("expected malformed, got \(error)")
        }
      }
    }
    let pendingCount = try await database.pendingPublicFirehoseOutbox().count
    XCTAssertEqual(pendingCount, 0)
  }

  func testInvalidLeaseDurationsRejected() async throws {
    try await commitRow()
    for duration in [0.0, -5.0, 86_401.0, .infinity, .nan] {
      let error = await firehoseThrowsError(
        try await database.leaseNextPublicFirehoseOutbox(
          now: epoch,
          leaseDuration: duration
        )
      )
      guard let error, case let malformedError as SwanError = error, case .malformed = malformedError else {
        return XCTFail("expected malformed error for \(duration)")
      }
    }
  }

  func testInvalidPendingLimitsRejected() async throws {
    for limit in [0, -1, 1_001] {
      let error = await firehoseThrowsError(
        try await database.pendingPublicFirehoseOutbox(limit: limit)
      )
      guard let error, case let malformedError as SwanError = error, case .malformed = malformedError else {
        return XCTFail("expected malformed error for \(limit)")
      }
    }
  }

  func testMigrationLedgerRecordsVersionFourteenOnReopenAndPreservesPendingRow() async throws {
    try await commitRow()
    try await database.close()
    database = nil
    let reopened = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
    let rows = try await reopened.pendingPublicFirehoseOutbox()
    XCTAssertEqual(rows.count, 1)
    try await reopened.close()

    let raw = try await SQLiteConnection.open(
      storage: .file(path: SQLiteLayout.accountDatabase(in: root, did: did).path)
    )
    defer { Task { try? await raw.close() } }
    let ledger = try await raw.query(
      "SELECT version FROM permissioned_repository_migrations WHERE version = 14"
    )
    XCTAssertEqual(ledger.compactMap { $0.column("version")?.integer }, [14])
    let columns = try await raw.query("PRAGMA table_info(public_event_outbox)")
    XCTAssertTrue(columns.contains { $0.column("name")?.string == "completed" })
  }
}

private func firehoseThrowsError<T>(
  _ expression: @autoclosure () async throws -> T,
  file: StaticString = #filePath,
  line: UInt = #line
) async -> Error? {
  do {
    _ = try await expression()
    XCTFail("expected error", file: file, line: line)
    return nil
  } catch {
    return error
  }
}
