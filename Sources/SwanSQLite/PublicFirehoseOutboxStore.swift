import Foundation
import SQLiteNIO
import SwanCore
import SwanPublicFirehose

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
      return try matchExactFirehoseReplay(
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

  /// Non-leasing peek used only by the sequencer's causal merge. Returns the
  /// smallest `id` regardless of availability or lease state.
  public func oldestPendingPublicFirehoseOutbox() async throws -> PublicFirehoseOutboxRow? {
    try await withConnectionGate {
      let rows = try await connection.query(
        """
        SELECT id, source_key, kind, lifecycle_generation, payload, car_bytes,
               attempts, created_at, available_at, lease_token, lease_expires_at
        FROM public_event_outbox
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
          WHERE id = ?
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

  /// Deletes a source row only while the caller still owns its durable lease.
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
          WHERE id = ?
          """,
          [.integer(Int(id))]
        )
        guard let row = rows.first else { return false }
        _ = try decodeFirehoseOutboxRow(row)
        let lease = try decodeFirehoseLeaseColumns(row)
        guard lease.token == token.uuidString else { return false }
        _ = try await connection.query(
          """
          DELETE FROM public_event_outbox
          WHERE id = ? AND lease_token = ?
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
          WHERE id = ?
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
          WHERE id = ? AND lease_token = ?
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
  ) throws -> Bool {
    let storedKindText = try requiredFirehoseText(row, "kind")
    guard let storedKind = PublicFirehoseEventKind(rawValue: storedKindText) else {
      throw SQLiteRepositoryError.corruptDatabase(
        "invalid public firehose outbox kind"
      )
    }
    let storedGeneration = Int64(try requiredFirehoseInteger(row, "lifecycle_generation"))
    let storedPayload = try requiredFirehoseBlob(row, "payload")
    let storedCAR = try requiredFirehoseBlob(row, "car_bytes")
    guard storedKind == kind,
          storedGeneration == lifecycleGeneration,
          storedPayload == payload,
          storedCAR == carBytes
    else {
      throw SQLiteRepositoryError.conflictingPublicFirehoseSourceKey(sourceKey)
    }
    return false
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
