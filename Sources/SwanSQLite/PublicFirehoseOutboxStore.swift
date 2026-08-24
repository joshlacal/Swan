import Foundation
import Petrel
import SQLiteNIO
import SwanCore
import SwanPublicFirehose
import PetrelRepo

public struct PublicFirehoseOutboxRow: Sendable, Equatable {
  public let id: Int64
  public let sourceKey: String
  public let kind: PublicFirehoseEventKind
  public let lifecycleGeneration: Int64
  public let payload: Data
  public let carBytes: Data
  public let createdAt: Int64
  public let availableAt: Int64
  public let attempts: Int
}

public struct PublicFirehoseOutboxLease: Sendable, Equatable {
  public let row: PublicFirehoseOutboxRow
  public let token: UUID
  public let expiresAt: Date
}

extension SQLiteAccountDatabase {
  /// Inserts one public firehose source row. The caller already holds the
  /// connection gate and an open write transaction; this helper must not
  /// reacquire either. Exact source-key reuse with identical durable content
  /// returns `false`; reuse with any different content is a conflict.
  func enqueuePublicFirehoseEventInTransaction(
    sourceKey: String,
    kind: PublicFirehoseEventKind,
    lifecycleGeneration: Int64,
    payload: Data,
    carBytes: Data,
    createdAt: Int64
  ) async throws -> Bool {
    guard kind == .commit || kind == .sync else {
      throw SwanError.malformed(
        "the account-local outbox only accepts commit or sync events"
      )
    }
    guard !sourceKey.isEmpty, !payload.isEmpty, !carBytes.isEmpty else {
      throw SwanError.malformed(
        "public outbox rows require nonempty source key, payload, and CAR bytes"
      )
    }
    guard lifecycleGeneration >= 0, createdAt >= 0 else {
      throw SwanError.malformed(
        "public outbox generation and timestamps must be nonnegative"
      )
    }

    let existing = try await connection.query(
      """
      SELECT id, source_key, kind, lifecycle_generation, payload, car_bytes,
             attempts, created_at, available_at, lease_token, lease_expires_at
      FROM public_event_outbox
      WHERE source_key = ?
      """,
      [.text(sourceKey)]
    )
    if let row = existing.first {
      return try await matchExactFirehoseReplay(
        row,
        sourceKey: sourceKey,
        kind: kind,
        lifecycleGeneration: lifecycleGeneration,
        payload: payload,
        carBytes: carBytes
      )
    }

    _ = try await connection.query(
      """
      INSERT INTO public_event_outbox(
          source_key, kind, lifecycle_generation, payload, car_bytes,
          attempts, created_at, available_at, lease_token, lease_expires_at
      ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, NULL, NULL)
      """,
      [
        .text(sourceKey),
        .text(kind.rawValue),
        .integer(Int(lifecycleGeneration)),
        firehoseBlob(payload),
        firehoseBlob(carBytes),
        .integer(Int(createdAt)),
        .integer(Int(createdAt)),
      ]
    )
    return true
  }

  /// Standalone enqueue wrapping the in-transaction helper in one gate and
  /// one write transaction.
  public func enqueuePublicFirehoseEvent(
    sourceKey: String,
    kind: PublicFirehoseEventKind,
    lifecycleGeneration: Int64,
    payload: Data,
    carBytes: Data,
    now: Date
  ) async throws -> Bool {
    let createdAt = Int64(try firehoseTimestamp(now))
    return try await withConnectionGate {
      try await transaction {
        try await enqueuePublicFirehoseEventInTransaction(
          sourceKey: sourceKey,
          kind: kind,
          lifecycleGeneration: lifecycleGeneration,
          payload: payload,
          carBytes: carBytes,
          createdAt: createdAt
        )
      }
    }
  }

  /// Manual operator sync retries use the request UUID as an idempotency key.
  /// Once accepted, the stored row is authoritative even if a later retry has
  /// a different invocation clock or the repository head has advanced.
  func enqueueAuthoritativeManualSyncEvent(
    sourceKey: String,
    lifecycleGeneration: Int64,
    payload: Data,
    carBytes: Data,
    now: Date
  ) async throws -> Bool {
    let createdAt = Int64(try firehoseTimestamp(now))
    return try await withConnectionGate {
      try await transaction {
        let existing = try await connection.query(
          """
          SELECT id, source_key, kind, lifecycle_generation, payload, car_bytes,
                 attempts, created_at, available_at, lease_token, lease_expires_at
          FROM public_event_outbox WHERE source_key = ?
          """,
          [.text(sourceKey)]
        )
        if let row = existing.first {
          let stored = try decodeFirehoseOutboxRow(row)
          guard stored.sourceKey == sourceKey, stored.kind == .sync else {
            throw SQLiteRepositoryError.corruptDatabase(
              "manual sync idempotency key collides with another event"
            )
          }
          return false
        }
        return try await enqueuePublicFirehoseEventInTransaction(
          sourceKey: sourceKey,
          kind: .sync,
          lifecycleGeneration: lifecycleGeneration,
          payload: payload,
          carBytes: carBytes,
          createdAt: createdAt
        )
      }
    }
  }

  /// Non-leasing peek used only by the sequencer's causal merge. Returns the
  /// smallest `id` regardless of availability or lease state.
  public func oldestPendingPublicFirehoseOutbox() async throws -> PublicFirehoseOutboxRow? {
    try await withConnectionGate {
      let rows = try await connection.query(
        """
        SELECT id, source_key, kind, lifecycle_generation, payload, car_bytes,
               attempts, created_at, available_at, lease_token, lease_expires_at
        FROM public_event_outbox
        WHERE completed = 0
        ORDER BY id
        LIMIT 1
        """
      )
      return try rows.first.map(decodeFirehoseOutboxRow)
    }
  }

  /// Leases the strict FIFO head: the smallest outstanding `id`. Never orders
  /// by `available_at`, so a later repository revision can never overtake a
  /// failed earlier revision.
  public func leaseNextPublicFirehoseOutbox(
    now: Date = Date(),
    leaseDuration: TimeInterval
  ) async throws -> PublicFirehoseOutboxLease? {
    let nowTimestamp = try firehoseTimestamp(now)
    let leaseExpiry = try firehoseTimestamp(
      now.addingTimeInterval(
        try validFirehoseInterval(leaseDuration, name: "lease duration")
      )
    )
    return try await withConnectionGate {
      try await transaction {
        let rows = try await connection.query(
          """
          SELECT id, source_key, kind, lifecycle_generation, payload, car_bytes,
                 attempts, created_at, available_at, lease_token, lease_expires_at
          FROM public_event_outbox
          WHERE completed = 0
          ORDER BY id
          LIMIT 1
          """
        )
        guard let row = rows.first else { return nil }
        let head = try decodeFirehoseOutboxRow(row)
        let lease = try decodeFirehoseLeaseColumns(row)
        guard head.availableAt <= nowTimestamp else { return nil }
        if let leaseExpiry = lease.expiry {
          guard leaseExpiry <= nowTimestamp else { return nil }
        }
        let token = UUID()
        _ = try await connection.query(
          """
          UPDATE public_event_outbox
          SET lease_token = ?, lease_expires_at = ?
          WHERE id = ? AND completed = 0
          """,
          [
            .text(token.uuidString),
            .integer(leaseExpiry),
            .integer(Int(head.id)),
          ]
        )
        return PublicFirehoseOutboxLease(
          row: head,
          token: token,
          expiresAt: Date(timeIntervalSince1970: Double(leaseExpiry) / 1_000_000)
        )
      }
    }
  }

  /// Completes a source row only while the caller still owns its durable
  /// lease, retaining its public material indefinitely as an exact-replay and
  /// conflict-detection anchor.
  @discardableResult
  public func completePublicFirehoseOutboxLease(
    id: Int64,
    token: UUID
  ) async throws -> Bool {
    try await withConnectionGate {
      try await transaction {
        let rows = try await connection.query(
          """
          SELECT id, source_key, kind, lifecycle_generation, payload, car_bytes,
                 attempts, created_at, available_at, lease_token, lease_expires_at
          FROM public_event_outbox
          WHERE id = ? AND completed = 0
          """,
          [.integer(Int(id))]
        )
        guard let row = rows.first else { return false }
        _ = try decodeFirehoseOutboxRow(row)
        let lease = try decodeFirehoseLeaseColumns(row)
        guard lease.token == token.uuidString else { return false }
        _ = try await connection.query(
          """
          UPDATE public_event_outbox
          SET completed = 1, lease_token = NULL, lease_expires_at = NULL
          WHERE id = ? AND lease_token = ? AND completed = 0
          """,
          [.integer(Int(id)), .text(token.uuidString)]
        )
        return true
      }
    }
  }

  /// Records a failed source step only while the same lease is current, then
  /// clears that lease and makes the row eligible again at `retryAt`.
  /// Returning `nil` means a stale token or an already-completed row.
  @discardableResult
  public func failPublicFirehoseOutboxLease(
    id: Int64,
    token: UUID,
    retryAt: Date
  ) async throws -> Int? {
    let retryTimestamp = try firehoseTimestamp(retryAt)
    return try await withConnectionGate {
      try await transaction {
        let rows = try await connection.query(
          """
          SELECT id, source_key, kind, lifecycle_generation, payload, car_bytes,
                 attempts, created_at, available_at, lease_token, lease_expires_at
          FROM public_event_outbox
          WHERE id = ? AND completed = 0
          """,
          [.integer(Int(id))]
        )
        guard let row = rows.first else { return nil }
        let decoded = try decodeFirehoseOutboxRow(row)
        let lease = try decodeFirehoseLeaseColumns(row)
        guard lease.token == token.uuidString else { return nil }
        _ = try await connection.query(
          """
          UPDATE public_event_outbox
          SET attempts = attempts + 1, lease_token = NULL,
              lease_expires_at = NULL, available_at = ?
          WHERE id = ? AND lease_token = ? AND completed = 0
          """,
          [
            .integer(retryTimestamp),
            .integer(Int(id)),
            .text(token.uuidString),
          ]
        )
        return decoded.attempts + 1
      }
    }
  }

  /// All currently stored rows in ascending `id` order.
  public func pendingPublicFirehoseOutbox(
    limit: Int = 100
  ) async throws -> [PublicFirehoseOutboxRow] {
    guard limit > 0, limit <= 1_000 else {
      throw SwanError.malformed("public outbox pending limit must be between 1 and 1000")
    }
    return try await withConnectionGate {
      let rows = try await connection.query(
        """
        SELECT id, source_key, kind, lifecycle_generation, payload, car_bytes,
               attempts, created_at, available_at, lease_token, lease_expires_at
        FROM public_event_outbox
        WHERE completed = 0
        ORDER BY id
        LIMIT ?
        """,
        [.integer(limit)]
      )
      return try rows.map(decodeFirehoseOutboxRow)
    }
  }

  // MARK: - Exact replay

  private func matchExactFirehoseReplay(
    _ row: SQLiteRow,
    sourceKey: String,
    kind: PublicFirehoseEventKind,
    lifecycleGeneration: Int64,
    payload: Data,
    carBytes: Data
  ) async throws -> Bool {
    let storedKindText = try requiredFirehoseText(row, "kind")
    guard let storedKind = PublicFirehoseEventKind(rawValue: storedKindText) else {
      throw SQLiteRepositoryError.corruptDatabase(
        "invalid public firehose outbox kind"
      )
    }
    let storedGeneration = Int64(try requiredFirehoseInteger(row, "lifecycle_generation"))
    let storedPayload = try requiredFirehoseBlob(row, "payload")
    let storedCAR = try requiredFirehoseBlob(row, "car_bytes")
    guard storedGeneration >= 0 else {
      throw SQLiteRepositoryError.corruptDatabase(
        "invalid public firehose outbox generation"
      )
    }
    do {
      let commitCID: String
      switch storedKind {
      case .commit:
        let material = try JSONDecoder().decode(
          PublicFirehoseCommitMaterial.self,
          from: storedPayload
        )
        try validateStoredFirehoseTime(material.time)
        _ = try FirehoseFrameEncoder.commitFrame(
          seq: FirehoseFrameLimits.maximumSequence,
          material: material,
          diffCAR: storedCAR
        )
        commitCID = material.commitCID
      case .sync:
        let material = try JSONDecoder().decode(
          PublicFirehoseSyncMaterial.self,
          from: storedPayload
        )
        try validateStoredFirehoseTime(material.time)
        _ = try FirehoseFrameEncoder.syncFrame(
          seq: FirehoseFrameLimits.maximumSequence,
          material: material,
          commitCAR: storedCAR
        )
        commitCID = material.commitCID
      case .identity, .account:
        throw StoredFirehoseReplayValidationError.invalidMaterial
      }
      let expectedRoot = try CID.parse(commitCID)
      try PublicRepositoryCID.validate(expectedRoot)
      guard expectedRoot.string == commitCID else {
        throw StoredFirehoseReplayValidationError.invalidMaterial
      }
      let source = StoredFirehoseCARSource(storedCAR)
      let sink = StoredFirehoseCARSink()
      let parsed = try await PublicRepositoryCAR.parseIncrementally(
        from: source,
        to: sink
      )
      guard parsed.rootCID == expectedRoot,
            parsed.frameCount > 0,
            await sink.contains(expectedRoot) else {
        throw StoredFirehoseReplayValidationError.invalidCAR
      }
    } catch {
      throw SQLiteRepositoryError.corruptDatabase(
        "invalid public firehose outbox material"
      )
    }
    guard storedKind == kind,
          storedGeneration == lifecycleGeneration,
          storedPayload == payload,
          storedCAR == carBytes
    else {
      throw SQLiteRepositoryError.conflictingPublicFirehoseSourceKey(sourceKey)
    }
    return false
  }

  private func validateStoredFirehoseTime(_ value: String) throws {
    let bytes = Array(value.utf8)
    guard bytes.count == 24 else {
      throw StoredFirehoseReplayValidationError.invalidMaterial
    }
    for (index, byte) in bytes.enumerated() {
      let expected: UInt8?
      switch index {
      case 4, 7:
        expected = UInt8(ascii: "-")
      case 10:
        expected = UInt8(ascii: "T")
      case 13, 16:
        expected = UInt8(ascii: ":")
      case 19:
        expected = UInt8(ascii: ".")
      case 23:
        expected = UInt8(ascii: "Z")
      default:
        expected = nil
      }
      if let expected {
        guard byte == expected else {
          throw StoredFirehoseReplayValidationError.invalidMaterial
        }
      } else {
        guard byte >= UInt8(ascii: "0"), byte <= UInt8(ascii: "9") else {
          throw StoredFirehoseReplayValidationError.invalidMaterial
        }
      }
    }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    guard formatter.date(from: value) != nil else {
      throw StoredFirehoseReplayValidationError.invalidMaterial
    }
  }

  // MARK: - Row decoding

  private func decodeFirehoseOutboxRow(_ row: SQLiteRow) throws -> PublicFirehoseOutboxRow {
    let kindText = try requiredFirehoseText(row, "kind")
    guard let kind = PublicFirehoseEventKind(rawValue: kindText),
          kind == .commit || kind == .sync
    else {
      throw SQLiteRepositoryError.corruptDatabase(
        "invalid public firehose outbox kind"
      )
    }
    return PublicFirehoseOutboxRow(
      id: Int64(try requiredFirehoseInteger(row, "id")),
      sourceKey: try requiredFirehoseText(row, "source_key"),
      kind: kind,
      lifecycleGeneration: Int64(try requiredFirehoseInteger(row, "lifecycle_generation")),
      payload: try requiredFirehoseBlob(row, "payload"),
      carBytes: try requiredFirehoseBlob(row, "car_bytes"),
      createdAt: Int64(try requiredFirehoseInteger(row, "created_at")),
      availableAt: Int64(try requiredFirehoseInteger(row, "available_at")),
      attempts: try requiredFirehoseInteger(row, "attempts")
    )
  }

  private func decodeFirehoseLeaseColumns(
    _ row: SQLiteRow
  ) throws -> (token: String?, expiry: Int64?) {
    let token = row.column("lease_token")?.string
    let expiry = row.column("lease_expires_at")?.integer
    guard (token == nil) == (expiry == nil) else {
      throw SQLiteRepositoryError.corruptDatabase(
        "invalid public firehose outbox lease"
      )
    }
    guard expiry == nil || expiry! >= 0 else {
      throw SQLiteRepositoryError.corruptDatabase(
        "invalid public firehose outbox lease"
      )
    }
    return (token, expiry.map { Int64($0) })
  }

  // MARK: - File-private helpers

  private func requiredFirehoseText(_ row: SQLiteRow, _ column: String) throws -> String {
    guard let value = row.column(column)?.string else {
      throw SQLiteRepositoryError.corruptDatabase("invalid \(column)")
    }
    return value
  }

  private func requiredFirehoseInteger(_ row: SQLiteRow, _ column: String) throws -> Int {
    guard let value = row.column(column), case let .integer(integer) = value else {
      throw SQLiteRepositoryError.corruptDatabase("invalid \(column)")
    }
    return integer
  }

  private func requiredFirehoseBlob(_ row: SQLiteRow, _ column: String) throws -> Data {
    guard let value = row.column(column),
          let data = Data(sqliteData: value)
    else {
      throw SQLiteRepositoryError.corruptDatabase("invalid \(column)")
    }
    return data
  }

  private func firehoseBlob(_ data: Data) -> SQLiteData {
    data.sqliteData!
  }

  private func validFirehoseInterval(
    _ interval: TimeInterval,
    name: String
  ) throws -> TimeInterval {
    guard interval.isFinite, interval > 0, interval <= 86_400 else {
      throw SwanError.malformed("\(name) must be between zero and one day")
    }
    return interval
  }

  private func firehoseTimestamp(_ date: Date) throws -> Int {
    let microseconds = date.timeIntervalSince1970 * 1_000_000
    guard microseconds.isFinite,
          microseconds >= 0,
          microseconds <= Double(Int.max)
    else {
      throw SwanError.malformed("public firehose timestamp is out of range")
    }
    return Int(microseconds.rounded(.down))
  }
}

private enum StoredFirehoseReplayValidationError: Error {
  case invalidMaterial
  case invalidCAR
}

private actor StoredFirehoseCARSource: PublicRepositoryCARByteSource {
  private let bytes: Data
  private var offset = 0

  init(_ bytes: Data) {
    self.bytes = bytes
  }

  func read(maximumBytes: Int) -> Data? {
    guard offset < bytes.count else { return nil }
    let end = min(bytes.count, offset + maximumBytes)
    defer { offset = end }
    return Data(bytes[offset ..< end])
  }
}

private actor StoredFirehoseCARSink: PublicRepositoryCARFrameSink {
  private var receivedCIDs = Set<CID>()

  func receiveHeader(rootCID: CID, receivedByteCount: Int) {}

  func receiveBlock(
    _ block: PublicRepositoryBlock,
    receivedByteCount: Int,
    frameCount: Int
  ) {
    receivedCIDs.insert(block.cid)
  }

  func contains(_ cid: CID) -> Bool {
    receivedCIDs.contains(cid)
  }
}
