import Foundation
import Logging
import ServiceLifecycle
import SwanCore
import SwanSQLite

/// Runs bounded public firehose retention as a service-group member.
///
/// The worker prunes once immediately on start (so a freshly enabled policy
/// takes effect without waiting a full interval), then sleeps for `interval`
/// between passes. A transient database error is logged and the worker keeps
/// running, retrying on the next scheduled interval; cancellation from the
/// service group is the normal shutdown path and returns without throwing.
/// A prune that advances the retained boundary re-reads the durable high-water
/// mark and signals the shared wakeup hub so idle tailers wake even when no
/// new sequence was appended.
public struct SwanPublicFirehoseRetentionService: Service {
  private let database: SQLiteFirehoseDatabase
  private let hub: PublicFirehoseWakeupHub
  private let policy: PublicFirehoseRetentionPolicy
  private let interval: Duration
  private let logger: Logger

  public init(
    database: SQLiteFirehoseDatabase,
    hub: PublicFirehoseWakeupHub,
    policy: PublicFirehoseRetentionPolicy,
    interval: Duration = .seconds(60),
    logger: Logger
  ) throws {
    guard interval > .zero else {
      throw SwanError.malformed("firehose retention interval must be positive")
    }
    self.database = database
    self.hub = hub
    self.policy = policy
    self.interval = interval
    self.logger = logger
  }

  public func run() async throws {
    while !Task.isCancelled {
      do {
        let result = try await database.prune(now: Date(), policy: policy)
        if result.didAdvanceRetention {
          let maxSeq = try await database.maxSequencedSeq()
          await hub.firehoseRetentionDidAdvance(maxSeq: maxSeq)
        }
      } catch is CancellationError {
        return
      } catch {
        logger.error("public firehose retention pass failed", metadata: [
          "error": "\(error)",
        ])
      }

      do {
        try await Task.sleep(for: interval)
      } catch is CancellationError {
        return
      }
    }
  }
}
