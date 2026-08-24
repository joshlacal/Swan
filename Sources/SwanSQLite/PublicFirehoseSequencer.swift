import Foundation
import SwanCore
import PetrelFirehose

public struct PublicFirehoseAccountDatabase: Sendable {
  public let did: String
  public let database: SQLiteAccountDatabase

  public init(did: String, database: SQLiteAccountDatabase) {
    self.did = did
    self.database = database
  }
}

public protocol PublicFirehoseAccountDatabaseSource: Sendable {
  func publicFirehoseAccountDatabases() async throws -> [PublicFirehoseAccountDatabase]
}

public protocol PublicFirehoseWakeupSink: Sendable {
  func firehoseDidAppend(maxSeq: Int64) async
}

public struct PublicFirehoseSequencerConfiguration: Sendable, Equatable {
  public let leaseDuration: TimeInterval
  public let idlePollInterval: TimeInterval
  public let initialFailureBackoff: TimeInterval
  public let maximumFailureBackoff: TimeInterval

  public static let standard = try! PublicFirehoseSequencerConfiguration()

  public init(
    leaseDuration: TimeInterval = 30,
    idlePollInterval: TimeInterval = 0.25,
    initialFailureBackoff: TimeInterval = 1,
    maximumFailureBackoff: TimeInterval = 60
  ) throws {
    guard leaseDuration.isFinite, leaseDuration > 0, leaseDuration <= 86_400 else {
      throw SwanError.malformed("lease duration must be between zero and one day")
    }
    guard idlePollInterval.isFinite, idlePollInterval > 0, idlePollInterval <= 86_400 else {
      throw SwanError.malformed("idle poll interval must be between zero and one day")
    }
    guard initialFailureBackoff.isFinite, initialFailureBackoff > 0,
          initialFailureBackoff <= 86_400 else {
      throw SwanError.malformed("initial failure backoff must be between zero and one day")
    }
    guard maximumFailureBackoff.isFinite, maximumFailureBackoff > 0,
          maximumFailureBackoff <= 86_400 else {
      throw SwanError.malformed("maximum failure backoff must be between zero and one day")
    }
    guard initialFailureBackoff <= maximumFailureBackoff else {
      throw SwanError.malformed("initial failure backoff must not exceed the maximum")
    }
    self.leaseDuration = leaseDuration
    self.idlePollInterval = idlePollInterval
    self.initialFailureBackoff = initialFailureBackoff
    self.maximumFailureBackoff = maximumFailureBackoff
  }
}

public enum PublicFirehoseSequencerResult: Sendable, Equatable {
  case idle
  case sequencedLifecycleBatch(batchID: String, seqs: [Int64])
  case sequencedAccountEvent(sourceKey: String, seq: Int64)
  case leaseLost(sourceKey: String, seq: Int64)
}

public enum PublicFirehoseSequencerError: Error, Sendable, Equatable {
  case corruptSource(String)
}

/// The single durable leader merging account-local outbox rows with
/// control-plane lifecycle batches into one causally ordered global log.
///
/// Ordering model per DID:
///
/// ```text
/// lifecycle batch g  <  account events stamped g  <  lifecycle batch g + 1
/// ```
///
/// Crash safety is append-then-complete:
///
/// ```text
/// source lease/batch remains durable
///         ↓
/// global append commits
///         ↓
/// source completion commits
/// ```
///
/// A crash after the global append but before source completion leaves the
/// source present; retry re-encodes at the stored sequence and returns the
/// original sequences, then marks the source complete while retaining its
/// exact replay anchor. No duplicate sequence, no lost event.
/// Test-only crash boundary context, invoked after the global append commits
/// and before the source outbox row or lifecycle batch is completed. A
/// throwing hook must leave the source untouched.
struct PublicFirehoseSequencerCrashContext: Sendable {
  let accountLease: (id: Int64, token: UUID)?
  let batchID: String?
}

public actor PublicFirehoseSequencer {
  private let accountSource: any PublicFirehoseAccountDatabaseSource
  private let control: SQLiteControlDatabase
  private let firehose: SQLiteFirehoseDatabase
  private let wakeup: (any PublicFirehoseWakeupSink)?
  private let configuration: PublicFirehoseSequencerConfiguration
  private var roundRobinCursor = 0

  var testCrashHook: (@Sendable (PublicFirehoseSequencerCrashContext) async throws -> Void)?

  /// Internal test hook setter: actor stored properties cannot be mutated
  /// from outside the actor.
  func setTestCrashHook(_ hook: (@Sendable (PublicFirehoseSequencerCrashContext) async throws -> Void)?) {
    testCrashHook = hook
  }

  public init(
    accountSource: any PublicFirehoseAccountDatabaseSource,
    control: SQLiteControlDatabase,
    firehose: SQLiteFirehoseDatabase,
    wakeup: (any PublicFirehoseWakeupSink)? = nil,
    configuration: PublicFirehoseSequencerConfiguration = .standard
  ) {
    self.accountSource = accountSource
    self.control = control
    self.firehose = firehose
    self.wakeup = wakeup
    self.configuration = configuration
  }

  public func sequenceNext(
    now: Date = Date()
  ) async throws -> PublicFirehoseSequencerResult {
    let accounts = try await accountSource.publicFirehoseAccountDatabases()
    let lifecycleDIDs = try await control.pendingLifecycleDIDs()
    let accountsByDID = Dictionary(
      uniqueKeysWithValues: accounts.map { ($0.did, $0) }
    )
    let dids = Array(Set(accountsByDID.keys + lifecycleDIDs)).sorted()

    guard !dids.isEmpty else { return .idle }
    let rotated = rotate(dids)
    for did in rotated {
      let accountHead = try await accountsByDID[did]?.database
        .oldestPendingPublicFirehoseOutbox()
      let lifecycleBatch = try await control.nextPendingLifecycleBatch(did: did)

      let accountGeneration = accountHead?.lifecycleGeneration
      let lifecycleGeneration = lifecycleBatch?.generation

      let chooseAccount: Bool
      switch (accountGeneration, lifecycleGeneration) {
      case (nil, nil):
        continue
      case (nil, .some):
        chooseAccount = false
      case (.some, nil):
        chooseAccount = true
      case let (.some(account), .some(lifecycle)):
        chooseAccount = account < lifecycle
      }

      if chooseAccount {
        guard let database = accountsByDID[did]?.database else { continue }
        let lease = try await database.leaseNextPublicFirehoseOutbox(
          now: now,
          leaseDuration: configuration.leaseDuration
        )
        // A delayed or actively leased head blocks this DID's later events
        // and next lifecycle generation, but never another DID.
        guard let lease else { continue }
        let sourceKey = lease.row.sourceKey
        do {
          let seqs = try await firehose.appendBatch(
            [try accountAppendItem(lease.row, did: database.accountDID)],
            now: now
          )
          guard let seq = seqs.first else {
            throw PublicFirehoseSequencerError.corruptSource(
              "account append returned no sequence"
            )
          }
          try await testCrashHook?(
            PublicFirehoseSequencerCrashContext(
              accountLease: (lease.row.id, lease.token),
              batchID: nil
            )
          )
          let completed = try await database.completePublicFirehoseOutboxLease(
            id: lease.row.id,
            token: lease.token
          )
          if completed {
            await wakeup?.firehoseDidAppend(maxSeq: seq)
            return .sequencedAccountEvent(sourceKey: sourceKey, seq: seq)
          }
          return .leaseLost(sourceKey: sourceKey, seq: seq)
        } catch is CancellationError {
          throw CancellationError()
        } catch {
          guard isTransient(error) else { throw error }
          let retryAt = now.addingTimeInterval(
            retryDelay(afterFailureAttempt: lease.row.attempts + 1)
          )
          _ = try await database.failPublicFirehoseOutboxLease(
            id: lease.row.id,
            token: lease.token,
            retryAt: retryAt
          )
          throw error
        }
      } else {
        guard let batch = lifecycleBatch else {
          throw PublicFirehoseSequencerError.corruptSource(
            "lifecycle generation was chosen but no batch exists"
          )
        }
        let items = try batch.items.map { item in
          FirehoseAppendItem(
            sourceKey: item.sourceKey,
            batchID: batch.batchID,
            did: batch.did,
            kind: item.kind
          ) { seq in
            try Self.encodeLifecycleFrame(item: item, seq: seq)
          }
        }
        // A decoded `deleted` `#account` item marks its own DID's earlier
        // retained history for deletion in the same global transaction as
        // this append, so the public deletion event and the prior-row prune
        // commit or roll back together.
        let deletionMarkers = try batch.items.compactMap { item -> FirehoseDeletionMarker? in
          guard item.kind == .account else { return nil }
          let material = try JSONDecoder().decode(
            PublicFirehoseAccountMaterial.self,
            from: item.payload
          )
          guard !material.active, material.status == .deleted else { return nil }
          return FirehoseDeletionMarker(did: batch.did, sourceKey: item.sourceKey)
        }
        let seqs = try await firehose.appendBatch(
          items,
          now: now,
          deletingPriorEvents: deletionMarkers
        )
        try await testCrashHook?(
          PublicFirehoseSequencerCrashContext(
            accountLease: nil,
            batchID: batch.batchID
          )
        )
        _ = try await control.completeLifecycleBatch(batchID: batch.batchID)
        if let maxSeq = seqs.last {
          await wakeup?.firehoseDidAppend(maxSeq: maxSeq)
        }
        return .sequencedLifecycleBatch(batchID: batch.batchID, seqs: seqs)
      }
    }
    return .idle
  }

  /// Drains every causally ready source once. One lifecycle batch counts as
  /// one step even when it appends multiple events.
  public func drainAll(
    now: Date = Date()
  ) async throws -> Int {
    var steps = 0
    while true {
      let result = try await sequenceNext(now: now)
      switch result {
      case .idle:
        return steps
      case .sequencedAccountEvent, .sequencedLifecycleBatch, .leaseLost:
        steps += 1
      }
    }
  }

  /// Bounded-polling service-loop entry point. Exits promptly on task
  /// cancellation; the durable lease provides the crash-recovery boundary.
  public func runUntilCancelled() async {
    while !Task.isCancelled {
      do {
        let result = try await sequenceNext()
        if case .idle = result {
          try await Task.sleep(nanoseconds: nanoseconds(configuration.idlePollInterval))
        }
      } catch is CancellationError {
        return
      } catch {
        try? await Task.sleep(nanoseconds: nanoseconds(configuration.idlePollInterval))
      }
    }
  }

  // MARK: - Source material

  private func accountAppendItem(
    _ row: PublicFirehoseOutboxRow,
    did: String
  ) throws -> FirehoseAppendItem {
    switch row.kind {
    case .commit:
      let material = try JSONDecoder().decode(
        PublicFirehoseCommitMaterial.self,
        from: row.payload
      )
      let car = row.carBytes
      return FirehoseAppendItem(
        sourceKey: row.sourceKey,
        batchID: nil,
        did: did,
        kind: row.kind
      ) { seq in
        try FirehoseFrameEncoder.commitFrame(
          seq: seq,
          material: material,
          diffCAR: car
        )
      }
    case .sync:
      let material = try JSONDecoder().decode(
        PublicFirehoseSyncMaterial.self,
        from: row.payload
      )
      let car = row.carBytes
      return FirehoseAppendItem(
        sourceKey: row.sourceKey,
        batchID: nil,
        did: did,
        kind: row.kind
      ) { seq in
        try FirehoseFrameEncoder.syncFrame(
          seq: seq,
          material: material,
          commitCAR: car
        )
      }
    case .identity, .account:
      throw PublicFirehoseSequencerError.corruptSource(
        "account outbox rows can only be commit or sync"
      )
    }
  }

  private static func encodeLifecycleFrame(
    item: LifecycleEventItem,
    seq: Int64
  ) throws -> Data {
    switch item.kind {
    case .sync:
      guard let carBytes = item.carBytes else {
        throw PublicFirehoseSequencerError.corruptSource(
          "lifecycle sync item lost its CAR"
        )
      }
      let material = try JSONDecoder().decode(
        PublicFirehoseSyncMaterial.self,
        from: item.payload
      )
      return try FirehoseFrameEncoder.syncFrame(
        seq: seq,
        material: material,
        commitCAR: carBytes
      )
    case .identity:
      let material = try JSONDecoder().decode(
        PublicFirehoseIdentityMaterial.self,
        from: item.payload
      )
      return try FirehoseFrameEncoder.identityFrame(seq: seq, material: material)
    case .account:
      let material = try JSONDecoder().decode(
        PublicFirehoseAccountMaterial.self,
        from: item.payload
      )
      return try FirehoseFrameEncoder.accountFrame(seq: seq, material: material)
    case .commit:
      throw PublicFirehoseSequencerError.corruptSource(
        "commit events never originate in the control database"
      )
    }
  }

  // MARK: - Scheduling helpers

  private func rotate(_ dids: [String]) -> [String] {
    guard !dids.isEmpty else { return [] }
    let cursor = roundRobinCursor % dids.count
    let rotated = Array(dids[cursor...] + dids[..<cursor])
    roundRobinCursor = (cursor + 1) % dids.count
    return rotated
  }

  private func retryDelay(afterFailureAttempt attempts: Int) -> TimeInterval {
    let exponent = Double(max(0, attempts - 1))
    let delay = configuration.initialFailureBackoff * pow(2, exponent)
    return min(delay, configuration.maximumFailureBackoff)
  }

  private func isTransient(_ error: Error) -> Bool {
    switch error {
    case is SQLiteFirehoseDatabaseError,
         is LifecycleEventOutboxError,
         is PublicFirehoseSequencerError,
         is SQLiteRepositoryError,
         is FirehoseFrameEncoderError,
         is Swift.DecodingError,
         is CancellationError:
      return false
    default:
      return true
    }
  }

  private func nanoseconds(_ interval: TimeInterval) -> UInt64 {
    UInt64((interval * 1_000_000_000).rounded(.up))
  }
}
