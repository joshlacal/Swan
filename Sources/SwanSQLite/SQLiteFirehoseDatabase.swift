import Foundation
import SQLiteNIO
import SwanCore
import PetrelFirehose

public struct FirehoseAppendItem: Sendable {
  public let sourceKey: String
  public let batchID: String?
  public let did: String
  public let kind: PublicFirehoseEventKind
  public let encodeFrame: @Sendable (Int64) throws -> Data

  public init(
    sourceKey: String,
    batchID: String?,
    did: String,
    kind: PublicFirehoseEventKind,
    encodeFrame: @escaping @Sendable (Int64) throws -> Data
  ) {
    self.sourceKey = sourceKey
    self.batchID = batchID
    self.did = did
    self.kind = kind
    self.encodeFrame = encodeFrame
  }
}

/// Marks the source key of a decoded `deleted` `#account` lifecycle item so
/// its append can atomically prune that DID's earlier retained history in
/// the same global transaction. The marker's source key must match exactly
/// one `.account` item in the batch it accompanies.
public struct FirehoseDeletionMarker: Sendable, Equatable {
  public let did: String
  public let sourceKey: String

  public init(did: String, sourceKey: String) {
    self.did = did
    self.sourceKey = sourceKey
  }
}

public struct FirehoseStoredEvent: Sendable, Equatable {
  public let seq: Int64
  public let sourceKey: String
  public let batchID: String?
  public let batchOrdinal: Int?
  public let did: String
  public let kind: PublicFirehoseEventKind
  public let sequencedAt: Int64
  public let frameBytes: Data
}

public enum SQLiteFirehoseDatabaseError: Error, Sendable, Equatable {
  case invalidRequest(String)
  case sequenceExhausted
  case conflictingSourceKey(String)
  case mixedBatchReplay(String)
  case corruptDatabase(String)
  case closed
}

/// The durable authority for the global public firehose log. Every append is
/// one `BEGIN IMMEDIATE` transaction: checked sequence allocation, frame
/// encoding, and row insertion commit or roll back together.
public actor SQLiteFirehoseDatabase {
  private static let migrationBusyRetryLimit = 12
  private static let migrationBusyInitialDelayNanoseconds: UInt64 = 5_000_000
  private static let migrationBusyMaximumDelayNanoseconds: UInt64 = 80_000_000
  private static let maximumCursorLimit = 1_000

  private let connection: SQLiteConnection
  private var dataDirectoryDescriptor: Int32
  private var databaseFileDescriptor: Int32
  private var isClosed = false

  public static func firehoseDatabase(in dataDirectory: URL) -> URL {
    SQLiteLayout.firehoseDatabase(in: dataDirectory)
  }

  public init(dataDirectory: URL) async throws {
    let rootDescriptor = try SQLiteProtectedPaths.openRoot(dataDirectory)
    let resolvedPath = SQLiteLayout.firehoseDatabase(in: dataDirectory)
      .standardizedFileURL.path
    let databasePath: String
    var heldDatabaseDescriptor: Int32 = -1
    do {
      databasePath = try SQLiteProtectedPaths.openDatabaseFile(
        parentDescriptor: rootDescriptor,
        name: "firehose.sqlite",
        resolvedPath: resolvedPath
      )
    } catch {
      SQLiteProtectedPaths.closeDirectory(rootDescriptor)
      throw error
    }
    let openedConnection: SQLiteConnection
    do {
      openedConnection = try await SQLiteConnection.open(
        storage: .file(path: databasePath)
      )
    } catch {
      SQLiteProtectedPaths.closeDirectory(heldDatabaseDescriptor)
      SQLiteProtectedPaths.closeDirectory(rootDescriptor)
      throw error
    }
    connection = openedConnection
    dataDirectoryDescriptor = rootDescriptor
    databaseFileDescriptor = heldDatabaseDescriptor
    do {
      try await migrateWithBusyRetry()
      try SQLiteProtectedPaths.hardenSQLiteFiles(
        parentDescriptor: rootDescriptor,
        databaseName: "firehose.sqlite"
      )
    } catch {
      try? await openedConnection.close()
      SQLiteProtectedPaths.closeDirectory(heldDatabaseDescriptor)
      SQLiteProtectedPaths.closeDirectory(rootDescriptor)
      throw error
    }
  }

  public func close() async throws {
    let descriptor = dataDirectoryDescriptor
    let databaseDescriptor = databaseFileDescriptor
    dataDirectoryDescriptor = -1
    databaseFileDescriptor = -1
    isClosed = true
    defer {
      SQLiteProtectedPaths.closeDirectory(databaseDescriptor)
      SQLiteProtectedPaths.closeDirectory(descriptor)
    }
    try await connection.close()
  }

  // MARK: - Append

  /// Allocates consecutive sequences, encodes frames at those sequences, and
  /// inserts all rows in one transaction. Exact source-key replay re-encodes
  /// at the stored sequence and returns the original sequences without new
  /// rows; any content difference is corruption.
  ///
  /// `deletingPriorEvents` marks decoded `deleted` `#account` items so their
  /// DID's earlier retained history is pruned in the same transaction as the
  /// append: the deletion commits or rolls back atomically with the public
  /// event that announces it. Each marker's source key must match exactly
  /// one `.account` item in `items`; the delete boundary is the first
  /// sequence allocated (or replayed) to *this* call, not the marker's own
  /// item's sequence, so it never touches any row `items` is inserting or
  /// replaying right now — including a same-DID sibling item earlier in this
  /// same batch. It applies on exact replay too, so a crash between the
  /// first commit and lifecycle completion cannot leave prior rows behind.
  public func appendBatch(
    _ items: [FirehoseAppendItem],
    now: Date,
    deletingPriorEvents: [FirehoseDeletionMarker] = []
  ) async throws -> [Int64] {
    try checkOpen()
    guard !items.isEmpty else {
      throw SQLiteFirehoseDatabaseError.invalidRequest("empty append batch")
    }
    let batchIDs = Set(items.compactMap(\.batchID))
    if let batchID = batchIDs.first, batchIDs.count > 1 {
      throw SQLiteFirehoseDatabaseError.invalidRequest(
        "all items in one batch must share the same batch ID"
      )
    }
    if let batchID = batchIDs.first {
      for item in items where item.batchID != batchID {
        throw SQLiteFirehoseDatabaseError.invalidRequest(
          "nil batch ID is allowed only for a single account event"
        )
      }
    } else if items.count > 1 {
      throw SQLiteFirehoseDatabaseError.invalidRequest(
        "nil batch ID is allowed only for a single account event"
      )
    }
    var seen = Set<String>()
    var itemsBySourceKey: [String: FirehoseAppendItem] = [:]
    itemsBySourceKey.reserveCapacity(items.count)
    for item in items {
      guard !item.sourceKey.isEmpty, !item.did.isEmpty else {
        throw SQLiteFirehoseDatabaseError.invalidRequest(
          "append items require nonempty source keys and DIDs"
        )
      }
      guard seen.insert(item.sourceKey).inserted else {
        throw SQLiteFirehoseDatabaseError.invalidRequest(
          "duplicate source key in one append request"
        )
      }
      itemsBySourceKey[item.sourceKey] = item
    }
    var seenMarkerKeys = Set<String>()
    for marker in deletingPriorEvents {
      guard !marker.did.isEmpty, !marker.sourceKey.isEmpty else {
        throw SQLiteFirehoseDatabaseError.invalidRequest(
          "deletion markers require nonempty DIDs and source keys"
        )
      }
      guard seenMarkerKeys.insert(marker.sourceKey).inserted else {
        throw SQLiteFirehoseDatabaseError.invalidRequest(
          "duplicate deletion marker source key"
        )
      }
      guard let matched = itemsBySourceKey[marker.sourceKey] else {
        throw SQLiteFirehoseDatabaseError.invalidRequest(
          "deletion marker source key does not match any item in this batch"
        )
      }
      guard matched.kind == .account, matched.did == marker.did else {
        throw SQLiteFirehoseDatabaseError.invalidRequest(
          "deletion marker must match exactly one account item for the same DID"
        )
      }
    }
    let sequencedAt = Int64(try firehoseTimestamp(now))

    return try await withConnectionGate {
      try await transaction {
        let placeholders = Array(repeating: "?", count: items.count).joined(separator: ", ")
        let existing = try await connection.query(
          """
          SELECT seq, source_key, batch_id, batch_ordinal, did, kind,
                 sequenced_at, frame_bytes
          FROM firehose_events
          WHERE source_key IN (\(placeholders))
          """,
          items.map { .text($0.sourceKey) }
        )
        if !existing.isEmpty {
          let seqs = try await replayExisting(
            items: items,
            existing: existing,
            batchID: batchIDs.first
          )
          try await deletePriorEvents(
            deletingPriorEvents,
            seqBySourceKey: Dictionary(
              uniqueKeysWithValues: zip(items.map(\.sourceKey), seqs)
            )
          )
          return seqs
        }

        let metaRows = try await connection.query(
          "SELECT next_seq FROM firehose_meta WHERE singleton = 1"
        )
        guard metaRows.count == 1,
              let metaRow = metaRows.first,
              case let .integer(rawNext)? = metaRow.column("next_seq"),
              rawNext >= 1 else {
          throw SQLiteFirehoseDatabaseError.corruptDatabase(
            "firehose_meta is missing or invalid"
          )
        }
        let start = Int64(rawNext)
        let count = items.count
        let (last, overflow) = start.addingReportingOverflow(Int64(count) - 1)
        guard !overflow,
              start <= FirehoseFrameLimits.maximumSequence,
              last <= FirehoseFrameLimits.maximumSequence else {
          throw SQLiteFirehoseDatabaseError.sequenceExhausted
        }
        let newNext = last + 1

        var frames: [Data] = []
        frames.reserveCapacity(count)
        for (index, item) in items.enumerated() {
          let seq = start + Int64(index)
          do {
            let frame = try item.encodeFrame(seq)
            guard frame.count <= FirehoseFrameLimits.maximumFrameBytes else {
              throw SQLiteFirehoseDatabaseError.invalidRequest(
                "frame exceeds the maximum encoded size"
              )
            }
            frames.append(frame)
          } catch let error as SQLiteFirehoseDatabaseError {
            throw error
          } catch {
            throw SQLiteFirehoseDatabaseError.corruptDatabase(
              "frame encoding failed before insertion"
            )
          }
        }

        let updated = try await connection.query(
          """
          UPDATE firehose_meta
          SET next_seq = ?
          WHERE singleton = 1 AND next_seq = ?
          RETURNING singleton
          """,
          [.integer(Int(newNext)), .integer(rawNext)]
        )
        guard updated.count == 1 else {
          throw SQLiteFirehoseDatabaseError.corruptDatabase(
            "firehose_meta sequence allocation lost a race"
          )
        }

        for (index, item) in items.enumerated() {
          let seq = start + Int64(index)
          let frame = frames[index]
          _ = try await connection.query(
            """
            INSERT INTO firehose_events(
                seq, source_key, batch_id, batch_ordinal, did, kind,
                sequenced_at, frame_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
              .integer(Int(seq)),
              .text(item.sourceKey),
              item.batchID.map { .text($0) } ?? SQLiteData.null,
              item.batchID.map { _ in .integer(index) } ?? SQLiteData.null,
              .text(item.did),
              .text(item.kind.rawValue),
              .integer(Int(sequencedAt)),
              frame.sqliteData!,
            ]
          )
        }
        let seqs = (0 ..< count).map { start + Int64($0) }
        try await deletePriorEvents(
          deletingPriorEvents,
          seqBySourceKey: Dictionary(
            uniqueKeysWithValues: zip(items.map(\.sourceKey), seqs)
          )
        )
        return seqs
      }
    }
  }

  /// Deletes each marker's DID's rows with `seq` strictly less than the
  /// first sequence allocated (or, on exact replay, re-derived) to *this*
  /// `appendBatch` call — never the marker's own item's sequence. Using the
  /// marker's own sequence would also delete any same-DID sibling rows
  /// inserted earlier in this same call (for example an `#identity` item
  /// paired with the deleted `#account` item in one lifecycle batch); using
  /// the batch's start boundary instead means only rows sequenced in a
  /// strictly earlier call are eligible, so every row this call is inserting
  /// or replaying survives. `seqBySourceKey` always covers every item in the
  /// call, so its minimum is exactly that start boundary on both the
  /// new-insert path (where it equals the first allocated sequence) and the
  /// exact-replay path (where it equals the first item's original stored
  /// sequence, re-derived fresh from this call's replayed results). This
  /// permits sequence gaps in the remaining log and never advances
  /// `retained_from_seq`: this is a per-DID deletion, not a global retention
  /// boundary.
  private func deletePriorEvents(
    _ markers: [FirehoseDeletionMarker],
    seqBySourceKey: [String: Int64]
  ) async throws {
    guard !markers.isEmpty else { return }
    guard let batchStartSeq = seqBySourceKey.values.min() else {
      throw SQLiteFirehoseDatabaseError.corruptDatabase(
        "deletion markers require at least one allocated sequence"
      )
    }
    for marker in markers {
      guard seqBySourceKey[marker.sourceKey] != nil else {
        throw SQLiteFirehoseDatabaseError.corruptDatabase(
          "deletion marker sequence was not allocated"
        )
      }
      _ = try await connection.query(
        "DELETE FROM firehose_events WHERE did = ? AND seq < ?",
        [.text(marker.did), .integer(Int(batchStartSeq))]
      )
    }
  }

  private func replayExisting(
    items: [FirehoseAppendItem],
    existing: [SQLiteRow],
    batchID: String?
  ) async throws -> [Int64] {
    guard existing.count == items.count else {
      throw SQLiteFirehoseDatabaseError.mixedBatchReplay(
        "a batch must be all new or all existing"
      )
    }
    let byKey = try decodeStoredEvents(existing)
    var result: [Int64] = []
    for (index, item) in items.enumerated() {
      guard let stored = byKey[item.sourceKey] else {
        throw SQLiteFirehoseDatabaseError.mixedBatchReplay(
          "a batch must be all new or all existing"
        )
      }
      if let batchID {
        guard stored.batchID == batchID else {
          throw SQLiteFirehoseDatabaseError.conflictingSourceKey(item.sourceKey)
        }
        guard stored.batchOrdinal == index else {
          throw SQLiteFirehoseDatabaseError.mixedBatchReplay(
            "stored batch ordinals must equal request indices"
          )
        }
        if index > 0 {
          guard stored.seq == result[index - 1] + 1 else {
            throw SQLiteFirehoseDatabaseError.mixedBatchReplay(
              "stored sequences must be consecutive in request order"
            )
          }
        }
      } else {
        guard stored.batchID == nil, stored.batchOrdinal == nil else {
          throw SQLiteFirehoseDatabaseError.conflictingSourceKey(item.sourceKey)
        }
      }
      guard stored.did == item.did,
            stored.kind == item.kind else {
        throw SQLiteFirehoseDatabaseError.conflictingSourceKey(item.sourceKey)
      }
      let reencoded: Data
      do {
        reencoded = try item.encodeFrame(stored.seq)
      } catch {
        throw SQLiteFirehoseDatabaseError.conflictingSourceKey(item.sourceKey)
      }
      guard reencoded == stored.frameBytes else {
        throw SQLiteFirehoseDatabaseError.conflictingSourceKey(item.sourceKey)
      }
      result.append(stored.seq)
    }
    return result
  }

  // MARK: - Reads

  /// Returns the sequence high-water mark from `firehose_meta.next_seq - 1`
  /// rather than `MAX(seq)`, so the already-issued cursor survives retention
  /// deletes (including an entirely empty log) and per-DID deletion gaps.
  public func maxSequencedSeq() async throws -> Int64 {
    try checkOpen()
    return try await withConnectionGate {
      let rows = try await connection.query(
        "SELECT next_seq FROM firehose_meta WHERE singleton = 1"
      )
      guard rows.count == 1,
            let row = rows.first,
            case let .integer(nextSeq)? = row.column("next_seq"),
            nextSeq >= 1 else {
        throw SQLiteFirehoseDatabaseError.corruptDatabase(
          "firehose_meta is missing or invalid"
        )
      }
      let maxSeq = Int64(nextSeq) - 1
      guard maxSeq >= 0, maxSeq <= FirehoseFrameLimits.maximumSequence else {
        throw SQLiteFirehoseDatabaseError.corruptDatabase(
          "firehose max sequence is invalid"
        )
      }
      return maxSeq
    }
  }

  /// Returns the oldest sequence still retained in the firehose log, or `nil`
  /// while retention pruning has never advanced. Phase 2 never advances
  /// retention, so this reads `firehose_meta.retained_from_seq` and returns
  /// `nil` on a fresh database.
  public func retainedFromSeq() async throws -> Int64? {
    try checkOpen()
    return try await withConnectionGate {
      let rows = try await connection.query(
        "SELECT retained_from_seq FROM firehose_meta WHERE singleton = 1"
      )
      guard rows.count == 1, let row = rows.first else {
        throw SQLiteFirehoseDatabaseError.corruptDatabase(
          "firehose_meta is missing or invalid"
        )
      }
      guard let value = row.column("retained_from_seq") else {
        throw SQLiteFirehoseDatabaseError.corruptDatabase(
          "firehose_meta is missing its retention column"
        )
      }
      switch value {
      case .null:
        return nil
      case let .integer(retained) where retained >= 1:
        return Int64(retained)
      default:
        throw SQLiteFirehoseDatabaseError.corruptDatabase(
          "firehose_meta retained_from_seq is invalid"
        )
      }
    }
  }

  public func events(
    after seq: Int64,
    limit: Int,
    maximumBytes: Int = 4 * FirehoseFrameLimits.maximumFrameBytes
  ) async throws -> [FirehoseStoredEvent] {
    try checkOpen()
    guard seq >= 0, seq <= FirehoseFrameLimits.maximumSequence else {
      throw SQLiteFirehoseDatabaseError.invalidRequest(
        "firehose cursor must be between 0 and the maximum sequence"
      )
    }
    guard limit > 0, limit <= Self.maximumCursorLimit else {
      throw SQLiteFirehoseDatabaseError.invalidRequest(
        "firehose event limit must be between 1 and \(Self.maximumCursorLimit)"
      )
    }
    guard maximumBytes > 0 else {
      throw SQLiteFirehoseDatabaseError.invalidRequest(
        "firehose maximum bytes must be positive"
      )
    }
    return try await withConnectionGate {
      let lengthRows = try await connection.query(
        """
        SELECT seq, length(frame_bytes) AS frame_len
        FROM firehose_events
        WHERE seq > ?
        ORDER BY seq
        LIMIT ?
        """,
        [.integer(Int(seq)), .integer(limit)]
      )
      guard !lengthRows.isEmpty else { return [] }

      var selectedSeqs: [Int] = []
      var accumulatedBytes = 0
      for row in lengthRows {
        guard let s = row.column("seq")?.integer,
              let len = row.column("frame_len")?.integer else {
          throw SQLiteFirehoseDatabaseError.corruptDatabase("invalid seq or frame_len")
        }
        if selectedSeqs.isEmpty {
          selectedSeqs.append(s)
          accumulatedBytes += len
        } else if accumulatedBytes + len <= maximumBytes {
          selectedSeqs.append(s)
          accumulatedBytes += len
        } else {
          break
        }
      }

      guard let minSeq = selectedSeqs.first, let maxSeq = selectedSeqs.last else {
        return []
      }

      let rows = try await connection.query(
        """
        SELECT seq, source_key, batch_id, batch_ordinal, did, kind,
               sequenced_at, frame_bytes
        FROM firehose_events
        WHERE seq >= ? AND seq <= ?
        ORDER BY seq
        """,
        [.integer(minSeq), .integer(maxSeq)]
      )
      return try decodeStoredEvents(rows).values.sorted { $0.seq < $1.seq }
    }
  }

  /// Counts stored (deliverable) rows strictly above `seq`, stopping at
  /// `limit`. Per-DID deletion pruning leaves sequence-number gaps, so
  /// `maxSequencedSeq() - cursor` overstates a consumer's real backlog; this
  /// bounded count is the gap-aware measure the slow-consumer policy uses.
  public func deliverableEventCount(after seq: Int64, limit: Int64) async throws -> Int64 {
    try checkOpen()
    guard seq >= 0, seq <= FirehoseFrameLimits.maximumSequence else {
      throw SQLiteFirehoseDatabaseError.invalidRequest(
        "firehose cursor must be between 0 and the maximum sequence"
      )
    }
    guard limit >= 1 else {
      throw SQLiteFirehoseDatabaseError.invalidRequest(
        "firehose deliverable count limit must be at least 1"
      )
    }
    return try await withConnectionGate {
      let rows = try await connection.query(
        """
        SELECT COUNT(*) AS deliverable FROM (
          SELECT 1 FROM firehose_events WHERE seq > ? LIMIT ?
        )
        """,
        [.integer(Int(seq)), .integer(Int(limit))]
      )
      guard rows.count == 1,
            let row = rows.first,
            let deliverable = row.column("deliverable")?.integer,
            deliverable >= 0 else {
        throw SQLiteFirehoseDatabaseError.corruptDatabase(
          "firehose deliverable event count is invalid"
        )
      }
      return Int64(deliverable)
    }
  }

  /// Raises `next_seq` only; never lowers it. Accepts the exhausted sentinel.
  public func reseedSequence(toAtLeast nextSeq: Int64) async throws {
    try checkOpen()
    guard nextSeq >= 1, nextSeq <= FirehoseFrameLimits.maximumSequence + 1 else {
      throw SQLiteFirehoseDatabaseError.invalidRequest(
        "firehose reseed target is out of range"
      )
    }
    try await withConnectionGate {
      try await transaction {
        let updated = try await connection.query(
          """
          UPDATE firehose_meta
          SET next_seq = ?
          WHERE singleton = 1 AND next_seq < ?
          RETURNING singleton
          """,
          [.integer(Int(nextSeq)), .integer(Int(nextSeq))]
        )
        guard updated.count <= 1 else {
          throw SQLiteFirehoseDatabaseError.corruptDatabase(
            "firehose_meta reseed affected multiple rows"
          )
        }
      }
    }
  }

  // MARK: - Row decoding

  private func decodeStoredEvents(
    _ rows: [SQLiteRow]
  ) throws -> [String: FirehoseStoredEvent] {
    var result: [String: FirehoseStoredEvent] = [:]
    for row in rows {
      guard let sourceKey = row.column("source_key")?.string,
            let did = row.column("did")?.string,
            let kindText = row.column("kind")?.string,
            let kind = PublicFirehoseEventKind(rawValue: kindText),
            case let .integer(seq)? = row.column("seq"),
            seq >= 1,
            case let .integer(sequencedAt)? = row.column("sequenced_at"),
            sequencedAt >= 0,
            let frameValue = row.column("frame_bytes"),
            let frame = Data(sqliteData: frameValue) else {
        throw SQLiteFirehoseDatabaseError.corruptDatabase(
          "invalid firehose event row"
        )
      }
      let batchID = row.column("batch_id")?.string
      let batchOrdinal = row.column("batch_ordinal")?.integer
      guard (batchID == nil) == (batchOrdinal == nil),
            batchOrdinal == nil || batchOrdinal! >= 0 else {
        throw SQLiteFirehoseDatabaseError.corruptDatabase(
          "invalid firehose batch columns"
        )
      }
      result[sourceKey] = FirehoseStoredEvent(
        seq: Int64(seq),
        sourceKey: sourceKey,
        batchID: batchID,
        batchOrdinal: batchOrdinal,
        did: did,
        kind: kind,
        sequencedAt: Int64(sequencedAt),
        frameBytes: frame
      )
    }
    return result
  }

  // MARK: - Lifecycle

  private func checkOpen() throws {
    guard !isClosed else {
      throw SQLiteFirehoseDatabaseError.closed
    }
  }

  private func firehoseTimestamp(_ date: Date) throws -> Int {
    let microseconds = date.timeIntervalSince1970 * 1_000_000
    guard microseconds.isFinite,
          microseconds >= 0,
          microseconds <= Double(Int.max) else {
      throw SwanError.malformed("firehose timestamp is out of range")
    }
    return Int(microseconds.rounded(.down))
  }

  private func migrateWithBusyRetry() async throws {
    var delay = Self.migrationBusyInitialDelayNanoseconds
    for attempt in 0 ..< Self.migrationBusyRetryLimit {
      do {
        try await migrateWithoutGate()
        return
      } catch {
        guard isRetryableMigrationLock(error),
              attempt + 1 < Self.migrationBusyRetryLimit else {
          throw error
        }
        try await Task.sleep(nanoseconds: delay)
        delay = min(delay * 2, Self.migrationBusyMaximumDelayNanoseconds)
      }
    }
    preconditionFailure("migration retry loop must either return or throw")
  }

  private func migrateWithoutGate() async throws {
    for statement in SQLiteLayout.controlConnectionPragmas {
      _ = try await connection.query(statement)
    }
    try await transaction {
      for statement in schemaStatements {
        _ = try await connection.query(statement)
      }
    }
  }

  private func isRetryableMigrationLock(_ error: Error) -> Bool {
    guard let sqliteError = error as? SQLiteError else { return false }
    switch sqliteError.reason {
    case .busy, .busyInRecovery, .busyInSnapshot, .busyTimeout,
         .locked, .lockedBySharedCache:
      return true
    default:
      return false
    }
  }

  private var schemaStatements: [String] {
    [
      """
      CREATE TABLE IF NOT EXISTS firehose_meta (
          singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
          next_seq INTEGER NOT NULL
              CHECK(next_seq >= 1 AND next_seq <= 9007199254740992),
          retained_from_seq INTEGER
              CHECK(
                  retained_from_seq IS NULL
                  OR (
                      retained_from_seq >= 1
                      AND retained_from_seq <= 9007199254740991
                  )
              )
      );
      """,
      """
      INSERT INTO firehose_meta(singleton, next_seq, retained_from_seq)
      SELECT 1, 1, NULL
      WHERE NOT EXISTS (SELECT 1 FROM firehose_meta WHERE singleton = 1);
      """,
      """
      CREATE TABLE IF NOT EXISTS firehose_events (
          seq INTEGER PRIMARY KEY
              CHECK(seq >= 1 AND seq <= 9007199254740991),
          source_key TEXT NOT NULL UNIQUE,
          batch_id TEXT,
          batch_ordinal INTEGER,
          did TEXT NOT NULL CHECK(length(did) > 0),
          kind TEXT NOT NULL CHECK(kind IN ('commit', 'sync', 'identity', 'account')),
          sequenced_at INTEGER NOT NULL CHECK(sequenced_at >= 0),
          frame_bytes BLOB NOT NULL
              CHECK(length(frame_bytes) > 0 AND length(frame_bytes) <= 5000000),
          CHECK(
              (batch_id IS NULL AND batch_ordinal IS NULL)
              OR (batch_id IS NOT NULL AND batch_ordinal IS NOT NULL AND batch_ordinal >= 0)
          ),
          UNIQUE(batch_id, batch_ordinal)
      );
      """,
      """
      CREATE INDEX IF NOT EXISTS firehose_events_did_seq
      ON firehose_events(did, seq);
      """,
      """
      CREATE INDEX IF NOT EXISTS firehose_events_batch
      ON firehose_events(batch_id, batch_ordinal)
      WHERE batch_id IS NOT NULL;
      """,
      """
      CREATE INDEX IF NOT EXISTS firehose_events_sequenced_at_seq
      ON firehose_events(sequenced_at, seq);
      """,
    ]
  }

  private func withConnectionGate<T: Sendable>(
    _ body: () async throws -> T
  ) async throws -> T {
    await connectionGate.acquire()
    do {
      try Task.checkCancellation()
      let result = try await body()
      await connectionGate.release()
      return result
    } catch {
      await connectionGate.release()
      throw error
    }
  }

  private func transaction<T: Sendable>(
    _ body: () async throws -> T
  ) async throws -> T {
    _ = try await connection.query("BEGIN IMMEDIATE")
    do {
      let result = try await body()
      _ = try await connection.query("COMMIT")
      return result
    } catch {
      _ = try? await connection.query("ROLLBACK")
      throw error
    }
  }

  private let connectionGate = SQLiteFirehoseConnectionGate()
}

private actor SQLiteFirehoseConnectionGate {
  private var isLocked = false
  private var waiting: [CheckedContinuation<Void, Never>] = []

  func acquire() async {
    if !isLocked {
      isLocked = true
      return
    }
    await withCheckedContinuation { continuation in
      waiting.append(continuation)
    }
  }

  func release() async {
    if let next = waiting.first {
      waiting.removeFirst()
      next.resume()
    } else {
      isLocked = false
    }
  }
}

extension SQLiteFirehoseDatabase {
  /// Enforces all three policy bounds in one transaction. The age pass pages
  /// through every row whose `sequenced_at` is below the cutoff first,
  /// deleting at most 1000 rows per statement, then the budget loop
  /// repeatedly removes the minimal prefix of the oldest bounded page
  /// (at most 1000 rows) that satisfies the row or byte budget, re-checking the
  /// totals until both are within bounds. The retained boundary is the
  /// `MIN(seq)` of the surviving rows, or one past the greatest deleted
  /// sequence when the log ends empty (that sequence was itself deleted, so
  /// the boundary must not claim it as retained). `retained_from_seq` is
  /// written only when this prune deleted at least one row and the new
  /// boundary exceeds the previous value; the never-set state is treated as
  /// unbounded and a no-op prune leaves it untouched.
  public func prune(
    now: Date,
    policy: PublicFirehoseRetentionPolicy
  ) async throws -> PublicFirehosePruneResult {
    try checkOpen()
    let nowMicroseconds = try PublicFirehoseTime.microseconds(now)
    // `nowMicros - maximumAgeMicroseconds` cannot overflow: both values are
    // non-negative and the age is bounded by Int64. A negative cutoff simply
    // matches nothing because `sequenced_at` is non-negative.
    let cutoff = nowMicroseconds - policy.maximumAgeMicroseconds

    return try await withConnectionGate {
      try await transaction {
        var deletedRows: Int64 = 0
        var deletedBytes: Int64 = 0
        var maximumDeletedSequence: Int64 = 0

        // Accumulates a page of `RETURNING seq, length(frame_bytes) AS bytes`
        // rows into the running totals above. Shared by the age pass and the
        // budget loop so both bounded-delete sites stay in lockstep.
        func accumulate(_ rows: [SQLiteRow]) {
          for row in rows {
            deletedRows += 1
            deletedBytes += Int64(row.column("bytes")?.integer ?? 0)
            if let seq = row.column("seq")?.integer {
              maximumDeletedSequence = max(maximumDeletedSequence, Int64(seq))
            }
          }
        }

        // Age pass: page through rows older than the cutoff in bounded
        // (<=1000-row) statements, same shape as the budget loop below, so a
        // large first-ever prune never buffers the whole expired set (up to
        // ~1M rows) in memory inside this single transaction.
        while true {
          let agePage = try await connection.query(
            """
            SELECT seq
            FROM firehose_events
            WHERE sequenced_at < ?
            ORDER BY seq
            LIMIT 1000
            """,
            [.integer(Int(cutoff))]
          )
          if agePage.isEmpty { break }
          var pageSequences: [Int64] = []
          pageSequences.reserveCapacity(agePage.count)
          for row in agePage {
            guard let seq = row.column("seq")?.integer else {
              throw SQLiteFirehoseDatabaseError.corruptDatabase(
                "firehose retention age page has an invalid sequence"
              )
            }
            pageSequences.append(Int64(seq))
          }
          let agePlaceholders = Array(repeating: "?", count: pageSequences.count)
            .joined(separator: ", ")
          let ageDeleted = try await connection.query(
            """
            DELETE FROM firehose_events
            WHERE seq IN (\(agePlaceholders))
            RETURNING seq, length(frame_bytes) AS bytes
            """,
            pageSequences.map { .integer(Int($0)) }
          )
          accumulate(ageDeleted)
        }

        while true {
          let totals = try await connection.query(
            """
            SELECT COUNT(*) AS row_count,
                   COALESCE(SUM(length(frame_bytes)), 0) AS byte_count
            FROM firehose_events
            """
          )
          guard totals.count == 1,
                let total = totals.first,
                let rowCount = total.column("row_count")?.integer,
                let byteCount = total.column("byte_count")?.integer,
                rowCount >= 0, byteCount >= 0 else {
            throw SQLiteFirehoseDatabaseError.corruptDatabase(
              "firehose retention totals are invalid"
            )
          }
          let currentRows = Int64(rowCount)
          let currentBytes = Int64(byteCount)
          if currentRows <= policy.maximumRows
              && currentBytes <= policy.maximumBytes {
            break
          }
          // Read the oldest bounded page together with stored frame sizes and
          // delete only the minimal prefix that satisfies either budget. The
          // loop then re-checks totals, so row and byte bounds are both
          // converged on with the fewest deletions.
          let oldest = try await connection.query(
            """
            SELECT seq, length(frame_bytes) AS bytes
            FROM firehose_events
            ORDER BY seq
            LIMIT 1000
            """
          )
          var selectedSequences: [Int64] = []
          var selectedBytes: Int64 = 0
          for row in oldest {
            guard let seq = row.column("seq")?.integer else {
              throw SQLiteFirehoseDatabaseError.corruptDatabase(
                "firehose retention page has an invalid sequence"
              )
            }
            selectedSequences.append(Int64(seq))
            selectedBytes += Int64(row.column("bytes")?.integer ?? 0)
            // Both budgets must be satisfied by the prospective deletion
            // before stopping. With `||` a single already-satisfied budget
            // (the common case: only one of the two is actually violated)
            // broke out after selecting just one row, so each outer-loop
            // pass re-ran the full-table totals query and deleted exactly
            // one row — K excess rows cost K full-table scans instead of
            // ceil(K / 1000). `&&` lets the prefix grow to the full
            // (<=1000-row) page whenever the other budget is already fine.
            if currentRows - Int64(selectedSequences.count) <= policy.maximumRows
                && currentBytes - selectedBytes <= policy.maximumBytes {
              break
            }
          }
          guard !selectedSequences.isEmpty else { break }
          let placeholders = Array(repeating: "?", count: selectedSequences.count)
            .joined(separator: ", ")
          let deleted = try await connection.query(
            """
            DELETE FROM firehose_events
            WHERE seq IN (\(placeholders))
            RETURNING seq, length(frame_bytes) AS bytes
            """,
            selectedSequences.map { .integer(Int($0)) }
          )
          accumulate(deleted)
        }

        let remaining = try await connection.query(
          "SELECT MIN(seq) AS min_seq FROM firehose_events"
        )
        let newBoundary: Int64?
        if let minSeq = remaining.first?.column("min_seq")?.integer, minSeq >= 1 {
          newBoundary = Int64(minSeq)
        } else if deletedRows > 0 {
          // The log is now empty: `maximumDeletedSequence` itself was
          // deleted, so it is one *past* the retained window, not the
          // oldest retained row (there is no oldest retained row). Using
          // the bare deleted sequence understated the boundary by one,
          // which let a mid-stream cursor at `maximumDeletedSequence - 1`
          // pass the tailer's `cursor < retainedFromSeq - 1` check even
          // though the very next sequence it needed was pruned, and could
          // make a later prune whose own maximum deleted sequence equals
          // this already-recorded boundary look like a no-op advance (the
          // monotonicity guard below would reject `newBoundary >
          // previous`), silently dropping `didAdvanceRetention` despite
          // rows actually being deleted.
          newBoundary = maximumDeletedSequence + 1
        } else {
          newBoundary = nil
        }

        var didAdvanceRetention = false
        if deletedRows > 0, let newBoundary {
          let meta = try await connection.query(
            "SELECT retained_from_seq FROM firehose_meta WHERE singleton = 1"
          )
          guard meta.count == 1 else {
            throw SQLiteFirehoseDatabaseError.corruptDatabase(
              "firehose_meta is missing or invalid"
            )
          }
          let shouldAdvance: Bool
          if let previous = meta.first?.column("retained_from_seq")?.integer {
            shouldAdvance = newBoundary > Int64(previous)
          } else {
            shouldAdvance = true
          }
          if shouldAdvance {
            _ = try await connection.query(
              """
              UPDATE firehose_meta
              SET retained_from_seq = ?
              WHERE singleton = 1
              """,
              [.integer(Int(newBoundary))]
            )
            didAdvanceRetention = true
          }
        }

        return PublicFirehosePruneResult(
          deletedRows: deletedRows,
          deletedBytes: deletedBytes,
          retainedFromSeq: didAdvanceRetention ? newBoundary : nil,
          didAdvanceRetention: didAdvanceRetention
        )
      }
    }
  }
}
