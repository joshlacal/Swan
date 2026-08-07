import Foundation
import SQLiteNIO
import SwanCore
import SwanPublicFirehose

public struct LifecycleEventItem: Sendable, Equatable {
  public let sourceKey: String
  public let kind: PublicFirehoseEventKind
  public let payload: Data
  public let carBytes: Data?

  public init(sourceKey: String, kind: PublicFirehoseEventKind, payload: Data, carBytes: Data?) {
    self.sourceKey = sourceKey
    self.kind = kind
    self.payload = payload
    self.carBytes = carBytes
  }
}

public struct LifecycleEventBatch: Sendable, Equatable {
  public let batchID: String
  public let did: String
  public let generation: Int64
  public let createdAt: Int64
  public let items: [LifecycleEventItem]

  public init(batchID: String, did: String, generation: Int64, createdAt: Int64, items: [LifecycleEventItem]) {
    self.batchID = batchID
    self.did = did
    self.generation = generation
    self.createdAt = createdAt
    self.items = items
  }
}

public enum LifecycleEventOutboxError: Error, Sendable, Equatable {
  case invalidItemCount(Int)
  case invalidItemShape(String)
  case invalidItemMaterial(String)
  case conflictingBatch(String)
  case corruptState(String)
}

/// Durable lifecycle batches with per-DID generations. No lease columns are
/// required because there is one sequencer and the global append is idempotent
/// by exact source key: crash recovery is append-then-complete, and a batch
/// left in these tables is safely replayed.
extension SQLiteControlDatabase {
  public func enqueueLifecycleEventBatch(
    did: String,
    operationID: String,
    items: [LifecycleEventItem],
    now: Date
  ) async throws -> LifecycleEventBatch {
    guard (1 ... 16).contains(items.count) else {
      throw LifecycleEventOutboxError.invalidItemCount(items.count)
    }
    for (index, item) in items.enumerated() {
      try validateLifecycleItem(item, ordinal: index)
    }
    return try await withConnectionGate {
      try await transaction {
        try await enqueueLifecycleEventBatchInTransaction(
          did: did,
          operationID: operationID,
          items: items,
          now: now
        )
      }
    }
  }

  /// The transactional half of `enqueueLifecycleEventBatch`. The caller must
  /// already hold the connection gate and an open control transaction (the
  /// public wrapper, or the lifecycle-write transaction of a status change
  /// which must commit or roll back atomically with the batch). Item count and
  /// shape are validated by the public wrapper before the gate.
  func enqueueLifecycleEventBatchInTransaction(
    did: String,
    operationID: String,
    items: [LifecycleEventItem],
    now: Date
  ) async throws -> LifecycleEventBatch {
    let createdAt = Int64(try lifecycleTimestamp(now))
    let batchID = PublicFirehoseSourceKey.lifecycleBatch(
      did: did,
      operationID: operationID
    )
    let existing = try await connection.query(
      """
      SELECT batch_id, did, generation, created_at
      FROM lifecycle_event_batches
      WHERE batch_id = ?
      """,
      [.text(batchID)]
    )
    if let row = existing.first {
      let stored = try decodeLifecycleBatchHeader(row)
      let storedItems = try await lifecycleItems(for: batchID)
      guard stored.did == did,
            storedItems == items else {
        throw LifecycleEventOutboxError.conflictingBatch(batchID)
      }
      return LifecycleEventBatch(
        batchID: batchID,
        did: stored.did,
        generation: stored.generation,
        createdAt: stored.createdAt,
        items: storedItems
      )
    }

    let generationRows = try await connection.query(
      """
      INSERT INTO account_lifecycle_generation(did, generation)
      VALUES (?, 1)
      ON CONFLICT(did) DO UPDATE SET generation = generation + 1
      RETURNING generation
      """,
      [.text(did)]
    )
    guard generationRows.count == 1,
          case let .integer(generation)? = generationRows.first?
            .column("generation"),
          generation >= 1 else {
      throw LifecycleEventOutboxError.corruptState(
        "lifecycle generation allocation returned an invalid value"
      )
    }
    let storedGeneration = Int64(generation)
    do {
      _ = try await connection.query(
        """
        INSERT INTO lifecycle_event_batches(
            batch_id, did, generation, created_at
        ) VALUES (?, ?, ?, ?)
        """,
        [
          .text(batchID),
          .text(did),
          .integer(Int(storedGeneration)),
          .integer(Int(createdAt)),
        ]
      )
    } catch {
      throw LifecycleEventOutboxError.conflictingBatch(batchID)
    }
    for (ordinal, item) in items.enumerated() {
      do {
        _ = try await connection.query(
          """
          INSERT INTO lifecycle_event_items(
              batch_id, batch_ordinal, source_key, kind, payload, car_bytes
          ) VALUES (?, ?, ?, ?, ?, ?)
          """,
          [
            .text(batchID),
            .integer(ordinal),
            .text(item.sourceKey),
            .text(item.kind.rawValue),
            item.payload.sqliteData!,
            item.carBytes?.sqliteData ?? SQLiteData.null,
          ]
        )
      } catch {
        throw LifecycleEventOutboxError.conflictingBatch(batchID)
      }
    }
    return LifecycleEventBatch(
      batchID: batchID,
      did: did,
      generation: storedGeneration,
      createdAt: createdAt,
      items: items
    )
  }

  public func currentLifecycleGeneration(did: String) async throws -> Int64 {
    try await withConnectionGate {
      let rows = try await connection.query(
        """
        SELECT generation
        FROM account_lifecycle_generation
        WHERE did = ?
        """,
        [.text(did)]
      )
      guard rows.count <= 1 else {
        throw LifecycleEventOutboxError.corruptState(
          "duplicate lifecycle generation rows"
        )
      }
      guard let row = rows.first else { return 0 }
      guard case let .integer(generation)? = row.column("generation"),
            generation >= 0 else {
        throw LifecycleEventOutboxError.corruptState(
          "invalid lifecycle generation"
        )
      }
      return Int64(generation)
    }
  }

  public func nextPendingLifecycleBatch(
    did: String?
  ) async throws -> LifecycleEventBatch? {
    try await withConnectionGate {
      let rows: [SQLiteRow]
      if let did {
        rows = try await connection.query(
          """
          SELECT batch_id, did, generation, created_at
          FROM lifecycle_event_batches
          WHERE did = ?
          ORDER BY generation, created_at, batch_id
          LIMIT 1
          """,
          [.text(did)]
        )
      } else {
        rows = try await connection.query(
          """
          SELECT batch_id, did, generation, created_at
          FROM lifecycle_event_batches
          ORDER BY did, generation, created_at, batch_id
          LIMIT 1
          """
        )
      }
      guard let row = rows.first else { return nil }
      let header = try decodeLifecycleBatchHeader(row)
      let items = try await lifecycleItems(for: header.batchID)
      return LifecycleEventBatch(
        batchID: header.batchID,
        did: header.did,
        generation: header.generation,
        createdAt: header.createdAt,
        items: items
      )
    }
  }

  public func pendingLifecycleDIDs() async throws -> [String] {
    try await withConnectionGate {
      let rows = try await connection.query(
        """
        SELECT DISTINCT did
        FROM lifecycle_event_batches
        ORDER BY did
        """
      )
      return try rows.map { row -> String in
        guard let did = row.column("did")?.string else {
          throw LifecycleEventOutboxError.corruptState(
            "invalid lifecycle batch did"
          )
        }
        return did
      }
    }
  }

  /// Deletes the batch; items are removed by cascade. The per-DID generation
  /// counter is intentionally preserved so generations are never reused.
  @discardableResult
  public func completeLifecycleBatch(batchID: String) async throws -> Bool {
    try await withConnectionGate {
      try await transaction {
        let deleted = try await connection.query(
          """
          DELETE FROM lifecycle_event_batches
          WHERE batch_id = ?
          RETURNING batch_id
          """,
          [.text(batchID)]
        )
        return deleted.count == 1
      }
    }
  }

  // MARK: - Item validation and preflight

  private func validateLifecycleItem(
    _ item: LifecycleEventItem,
    ordinal: Int
  ) throws {
    switch item.kind {
    case .commit:
      throw LifecycleEventOutboxError.invalidItemShape(
        "commit events never originate in the control database"
      )
    case .sync:
      guard let carBytes = item.carBytes, !carBytes.isEmpty else {
        throw LifecycleEventOutboxError.invalidItemShape(
          "lifecycle sync items require nonempty CAR bytes"
        )
      }
      let material: PublicFirehoseSyncMaterial
      do {
        material = try JSONDecoder().decode(
          PublicFirehoseSyncMaterial.self,
          from: item.payload
        )
      } catch {
        throw LifecycleEventOutboxError.invalidItemMaterial(
          "sync item \(ordinal) has a malformed payload"
        )
      }
      do {
        _ = try FirehoseFrameEncoder.syncFrame(
          seq: FirehoseFrameLimits.maximumSequence,
          material: material,
          commitCAR: carBytes
        )
      } catch {
        throw LifecycleEventOutboxError.invalidItemMaterial(
          "sync item \(ordinal) cannot preflight at the maximum sequence"
        )
      }
    case .identity:
      guard item.carBytes == nil else {
        throw LifecycleEventOutboxError.invalidItemShape(
          "identity items cannot carry CAR bytes"
        )
      }
      let material: PublicFirehoseIdentityMaterial
      do {
        material = try JSONDecoder().decode(
          PublicFirehoseIdentityMaterial.self,
          from: item.payload
        )
      } catch {
        throw LifecycleEventOutboxError.invalidItemMaterial(
          "identity item \(ordinal) has a malformed payload"
        )
      }
      do {
        _ = try FirehoseFrameEncoder.identityFrame(
          seq: FirehoseFrameLimits.maximumSequence,
          material: material
        )
      } catch {
        throw LifecycleEventOutboxError.invalidItemMaterial(
          "identity item \(ordinal) cannot preflight at the maximum sequence"
        )
      }
    case .account:
      guard item.carBytes == nil else {
        throw LifecycleEventOutboxError.invalidItemShape(
          "account items cannot carry CAR bytes"
        )
      }
      let material: PublicFirehoseAccountMaterial
      do {
        material = try JSONDecoder().decode(
          PublicFirehoseAccountMaterial.self,
          from: item.payload
        )
      } catch {
        throw LifecycleEventOutboxError.invalidItemMaterial(
          "account item \(ordinal) has a malformed payload"
        )
      }
      do {
        _ = try FirehoseFrameEncoder.accountFrame(
          seq: FirehoseFrameLimits.maximumSequence,
          material: material
        )
      } catch {
        throw LifecycleEventOutboxError.invalidItemMaterial(
          "account item \(ordinal) cannot preflight at the maximum sequence"
        )
      }
    }
  }

  // MARK: - Row decoding

  private func decodeLifecycleBatchHeader(
    _ row: SQLiteRow
  ) throws -> (batchID: String, did: String, generation: Int64, createdAt: Int64) {
    guard let batchID = row.column("batch_id")?.string,
          let did = row.column("did")?.string,
          case let .integer(generation)? = row.column("generation"),
          generation >= 1,
          case let .integer(createdAt)? = row.column("created_at"),
          createdAt >= 0 else {
      throw LifecycleEventOutboxError.corruptState(
        "invalid lifecycle batch row"
      )
    }
    return (batchID, did, Int64(generation), Int64(createdAt))
  }

  private func lifecycleItems(for batchID: String) async throws -> [LifecycleEventItem] {
    let rows = try await connection.query(
      """
      SELECT source_key, kind, payload, car_bytes
      FROM lifecycle_event_items
      WHERE batch_id = ?
      ORDER BY batch_ordinal
      """,
      [.text(batchID)]
    )
    return try rows.map { row in
      guard let sourceKey = row.column("source_key")?.string,
            let kindText = row.column("kind")?.string,
            let kind = PublicFirehoseEventKind(rawValue: kindText),
            let payloadValue = row.column("payload"),
            let payload = Data(sqliteData: payloadValue) else {
        throw LifecycleEventOutboxError.corruptState(
          "invalid lifecycle item row"
        )
      }
      let carBytes = row.column("car_bytes").flatMap(Data.init(sqliteData:))
      return LifecycleEventItem(
        sourceKey: sourceKey,
        kind: kind,
        payload: payload,
        carBytes: carBytes
      )
    }
  }

  private func lifecycleTimestamp(_ date: Date) throws -> Int {
    let microseconds = date.timeIntervalSince1970 * 1_000_000
    guard microseconds.isFinite,
          microseconds >= 0,
          microseconds <= Double(Int.max) else {
      throw SwanError.malformed("lifecycle timestamp is out of range")
    }
    return Int(microseconds.rounded(.down))
  }
}
