import Foundation
import Logging
import SwanCore
import SwanSQLite

/// Injectable per-connection streaming bounds for `subscribeRepos`.
///
/// All values must be positive; `pageSize` must not exceed the database's
/// maximum event page (`SQLiteFirehoseDatabase.maximumCursorLimit`).
public struct PublicFirehoseStreamingLimits: Sendable, Equatable {
  public let pageSize: Int
  public let maximumSequenceLag: Int64
  public let maximumBackfillCatchUp: Duration
  public let maximumWriteDuration: Duration
  public let idlePollInterval: TimeInterval

  public static let standard = try! PublicFirehoseStreamingLimits()

  public init(
    pageSize: Int = 1_000,
    maximumSequenceLag: Int64 = 50_000,
    maximumBackfillCatchUp: Duration = .seconds(120),
    maximumWriteDuration: Duration = .seconds(30),
    idlePollInterval: TimeInterval = 0.25
  ) throws {
    guard pageSize > 0, pageSize <= 1_000 else {
      throw SwanError.malformed(
        "firehose page size must be between 1 and 1_000"
      )
    }
    guard maximumSequenceLag > 0 else {
      throw SwanError.malformed("firehose maximum sequence lag must be positive")
    }
    guard maximumBackfillCatchUp > .zero else {
      throw SwanError.malformed("firehose maximum backfill catch-up must be positive")
    }
    guard maximumWriteDuration > .zero else {
      throw SwanError.malformed("firehose maximum write duration must be positive")
    }
    guard idlePollInterval.isFinite, idlePollInterval > 0 else {
      throw SwanError.malformed("firehose idle poll interval must be positive")
    }
    self.pageSize = pageSize
    self.maximumSequenceLag = maximumSequenceLag
    self.maximumBackfillCatchUp = maximumBackfillCatchUp
    self.maximumWriteDuration = maximumWriteDuration
    self.idlePollInterval = idlePollInterval
  }
}

/// Resolves a connecting cursor against the current log position per the
/// design-doc cursor matrix (nil → live; 0 → full window; cursor > max →
/// `FutureCursor`; cursor below retention → `OutdatedCursor`; else backfill).
///
/// Pure and fully unit-testable. Callers must have already validated the
/// cursor as a non-negative decimal at or below
/// `FirehoseFrameLimits.maximumSequence`.
public enum PublicFirehoseCursorPolicy: Sendable {
  public enum Outcome: Sendable, Equatable {
    /// No cursor: stream live from the current position.
    case live
    /// `cursor == 0`: stream the entire retained window from the oldest event
    /// with no `OutdatedCursor`, then live.
    case fullWindow
    /// Cursor within retention: backfill from the given sequence. Delivery is
    /// strictly after it (`seq > cursor`), so backfill and live are the same
    /// code path and the boundary has no gap or duplicate.
    case backfill(from: Int64)
    /// Cursor above the current maximum sequence: reject with a `FutureCursor`
    /// error frame.
    case futureCursor
    /// Cursor below the oldest retained event: send an `OutdatedCursor` info
    /// frame and stream from the oldest retained event. Dormant while
    /// retention is unbounded (`retainedFromSeq` is `nil`).
    case outdatedCursor
  }

  public static func resolve(
    cursor: Int64?,
    maxSequencedSeq: Int64,
    retainedFromSeq: Int64?
  ) -> Outcome {
    guard let cursor else { return .live }
    guard cursor != 0 else { return .fullWindow }
    if cursor > maxSequencedSeq { return .futureCursor }
    if let retainedFromSeq, cursor < retainedFromSeq { return .outdatedCursor }
    if let retainedFromSeq, cursor == retainedFromSeq {
      return .backfill(from: retainedFromSeq)
    }
    return .backfill(from: cursor)
  }
}

/// Pure slow-consumer bounds: sequence lag, accumulated backfill wall-clock,
/// and per-write duration. Any exceeded bound drops the consumer.
public enum PublicFirehoseSlowConsumerPolicy: Sendable {
  public static func shouldDrop(
    seqLag: Int64,
    backfillElapsed: Duration,
    writeDuration: Duration?,
    limits: PublicFirehoseStreamingLimits
  ) -> Bool {
    if seqLag > limits.maximumSequenceLag { return true }
    if backfillElapsed > limits.maximumBackfillCatchUp { return true }
    if let writeDuration, writeDuration > limits.maximumWriteDuration {
      return true
    }
    return false
  }
}

/// Errors thrown by the per-connection tailer. The caller maps
/// ``consumerTooSlow(seqLag:backfillElapsed:)`` and
/// ``writeTooSlow(duration:)`` to a `ConsumerTooSlow` error frame followed by
/// a close, and maps ``outdatedCursor(retainedFromSeq:)`` to an `#info`
/// `OutdatedCursor` frame followed by resuming from the new retained
/// boundary rather than closing the connection.
public enum PublicFirehoseTailerError: Error, Sendable, Equatable {
  case consumerTooSlow(seqLag: Int64, backfillElapsed: Duration)
  case writeTooSlow(duration: Duration)
  /// The delivered cursor has fallen behind the retained window (a prune
  /// advanced `retained_from_seq` past what this connection has consumed).
  /// Carries the new retained boundary so the caller can resume there.
  case outdatedCursor(retainedFromSeq: Int64)
}

/// The per-connection log-as-queue delivery loop. Reads complete stored
/// frames from the durable firehose log and ships them verbatim; backfill and
/// live delivery are the same code path, so the boundary has no gap or
/// duplicate. Slow consumers are dropped, and a cursor that falls behind the
/// retained window is reported, by throwing a ``PublicFirehoseTailerError``
/// that the caller maps to a `ConsumerTooSlow` close or an `OutdatedCursor`
/// resume, respectively.
///
/// No HTTP or WebSocket type is referenced here; the loop is driven purely by
/// the database, an outbound writer closure, and a wakeup closure.
public struct PublicFirehoseTailer: Sendable {
  public let database: SQLiteFirehoseDatabase
  public let limits: PublicFirehoseStreamingLimits
  public let logger: Logger

  public init(
    database: SQLiteFirehoseDatabase,
    limits: PublicFirehoseStreamingLimits,
    logger: Logger
  ) {
    self.database = database
    self.limits = limits
    self.logger = logger
  }

  /// Runs the delivery loop from `lastSent` until task cancellation.
  ///
  /// - Parameters:
  ///   - lastSent: the last sequence already delivered to this consumer;
  ///     events are delivered strictly after it (`seq > lastSent`).
  ///   - outbound: writes one stored frame verbatim, in sequence order; must
  ///     be invoked exactly once per delivered event. Every call is run under
  ///     ``PublicFirehoseStreamingLimits/maximumWriteDuration`` as a real
  ///     deadline, so a write that never returns cannot pin the loop.
  ///   - waitForWakeup: blocks until a new append or retention advance is
  ///     signaled, or returns `nil` when nothing is new so the loop falls
  ///     back to its bounded idle poll. Any non-`nil` signal — including a
  ///     stale append at or below the delivered cursor, or a retention
  ///     signal whose sequence high-water mark is unchanged — immediately
  ///     continues the loop rather than sleeping, so the retention check
  ///     below always gets a fresh pass after any wakeup. Callers feeding a
  ///     hub subscription must ensure this closure does not block past task
  ///     cancellation; the loop itself exits promptly on cancellation.
  ///
  /// Returns normally on task cancellation (it never rethrows
  /// `CancellationError`). Throws ``PublicFirehoseTailerError`` on a slow
  /// consumer or an outdated cursor, and propagates database or outbound
  /// errors.
  public func run(
    lastSent: Int64,
    outbound: @escaping @Sendable (Data) async throws -> Void,
    waitForWakeup: @escaping @Sendable () async -> Int64?
  ) async throws {
    let watchdog = PublicFirehoseWriteWatchdog(
      timeout: limits.maximumWriteDuration,
      logger: logger
    )
    let writerTask = Task {
      try await self.runDeliveryLoop(
        lastSent: lastSent,
        outbound: outbound,
        waitForWakeup: waitForWakeup,
        watchdog: watchdog
      )
    }
    watchdog.registerWriterTask(writerTask)
    let watchdogTask = Task {
      await watchdog.runWatchdogLoop()
    }

    return try await withTaskCancellationHandler {
      defer {
        writerTask.cancel()
        watchdogTask.cancel()
        watchdog.terminate()
      }
      do {
        try await writerTask.value
      } catch is CancellationError {
        if let timeoutDuration = watchdog.checkTimedOutDuration() {
          throw PublicFirehoseTailerError.writeTooSlow(duration: timeoutDuration)
        }
        return
      } catch {
        if let timeoutDuration = watchdog.checkTimedOutDuration() {
          throw PublicFirehoseTailerError.writeTooSlow(duration: timeoutDuration)
        }
        throw error
      }
    } onCancel: {
      writerTask.cancel()
      watchdogTask.cancel()
      watchdog.terminate()
    }
  }

  private func runDeliveryLoop(
    lastSent: Int64,
    outbound: @escaping @Sendable (Data) async throws -> Void,
    waitForWakeup: () async -> Int64?,
    watchdog: PublicFirehoseWriteWatchdog
  ) async throws {
    var cursor = lastSent
    var backfillElapsed = Duration.zero
    while !Task.isCancelled {
      // Checked before every read so a retention advance is caught even
      // when it does not change what `events(after:)` would return (e.g.
      // the consumer is already caught up but the retained window moved
      // past its delivered cursor).
      if let retainedFromSeq = try await database.retainedFromSeq(),
         cursor < retainedFromSeq - 1 {
        throw PublicFirehoseTailerError.outdatedCursor(
          retainedFromSeq: retainedFromSeq
        )
      }
      let rows = try await database.events(after: cursor, limit: limits.pageSize)
      if rows.isEmpty {
        let wakeupSeq = await waitForWakeup()
        if wakeupSeq != nil {
          continue
        }
        try await Task.sleep(for: .seconds(limits.idlePollInterval))
        continue
      }
      let maxSeq = try await database.maxSequencedSeq()
      // Raw difference is an upper bound on deliverable rows (deletion
      // gaps only shrink the real count), so the bounded count runs only
      // when a drop is already plausible.
      var seqLag = maxSeq - cursor
      if seqLag > limits.maximumSequenceLag {
        seqLag = try await database.deliverableEventCount(
          after: cursor,
          limit: limits.maximumSequenceLag + 1
        )
      }
      if PublicFirehoseSlowConsumerPolicy.shouldDrop(
        seqLag: seqLag,
        backfillElapsed: backfillElapsed,
        writeDuration: nil,
        limits: limits
      ) {
        logger.warning("dropping slow public firehose consumer")
        throw PublicFirehoseTailerError.consumerTooSlow(
          seqLag: seqLag,
          backfillElapsed: backfillElapsed
        )
      }
      let pageClock = ContinuousClock()
      let pageStarted = pageClock.now
      for row in rows {
        watchdog.beginWrite()
        do {
          try await outbound(row.frameBytes)
          watchdog.endWrite()
        } catch {
          watchdog.endWrite()
          throw error
        }
        cursor = row.seq
      }
      let pageElapsed = pageClock.now - pageStarted
      if seqLag > 0 {
        backfillElapsed += pageElapsed
      } else {
        backfillElapsed = .zero
      }
    }
    logger.debug("public firehose tailer exited")
  }
}

/// Per-subscriber watchdog enforcing write deadlines without per-frame task allocations.
///
/// Rather than creating a `withThrowingTaskGroup` and two child tasks per frame,
/// a single long-lived watchdog task is spawned per subscriber `run` invocation.
/// When a frame write begins, the watchdog is informed of the deadline. If the write
/// completes before the deadline, the watchdog is returned to idle. If the write
/// exceeds the deadline, the watchdog marks the timeout, logs the drop, and cancels
/// the writer task.
private final class PublicFirehoseWriteWatchdog: @unchecked Sendable {
  private let lock = NSLock()
  private let timeout: Duration
  private let logger: Logger
  private var isWriting: Bool = false
  private var currentDeadline: ContinuousClock.Instant?
  private var isTerminated: Bool = false
  private var timedOutDuration: Duration?
  private var writerTask: Task<Void, any Error>?
  private var idleContinuation: CheckedContinuation<Void, Never>?

  init(timeout: Duration, logger: Logger) {
    self.timeout = timeout
    self.logger = logger
  }

  func registerWriterTask(_ task: Task<Void, any Error>) {
    lock.withLock {
      self.writerTask = task
    }
  }

  func beginWrite() {
    let continuation: CheckedContinuation<Void, Never>? = lock.withLock {
      self.isWriting = true
      self.currentDeadline = ContinuousClock.now + timeout
      let cont = self.idleContinuation
      self.idleContinuation = nil
      return cont
    }
    continuation?.resume()
  }

  func endWrite() {
    lock.withLock {
      self.isWriting = false
      self.currentDeadline = nil
    }
  }

  func terminate() {
    let continuation: CheckedContinuation<Void, Never>? = lock.withLock {
      self.isTerminated = true
      let cont = self.idleContinuation
      self.idleContinuation = nil
      return cont
    }
    continuation?.resume()
  }

  func checkTimedOutDuration() -> Duration? {
    lock.withLock {
      self.timedOutDuration
    }
  }

  func runWatchdogLoop() async {
    let clock = ContinuousClock()
    while !Task.isCancelled {
      enum Action {
        case waitForBegin
        case sleep(until: ContinuousClock.Instant)
        case terminate
      }

      let action: Action = lock.withLock {
        if self.isTerminated {
          return .terminate
        }
        guard self.isWriting, let deadline = self.currentDeadline else {
          return .waitForBegin
        }
        return .sleep(until: deadline)
      }

      switch action {
      case .terminate:
        return

      case .waitForBegin:
        await withCheckedContinuation { continuation in
          var shouldResumeImmediately = false
          lock.withLock {
            if self.isTerminated || self.isWriting {
              shouldResumeImmediately = true
            } else {
              assert(self.idleContinuation == nil)
              self.idleContinuation = continuation
            }
          }
          if shouldResumeImmediately {
            continuation.resume()
          }
        }

      case .sleep(let deadline):
        let now = clock.now
        if now < deadline {
          do {
            try await Task.sleep(until: deadline, clock: clock)
          } catch {
            return
          }
        }

        let targetToCancel: Task<Void, any Error>? = lock.withLock {
          if self.isTerminated {
            return nil
          }
          if self.isWriting, let activeDeadline = self.currentDeadline, clock.now >= activeDeadline {
            self.timedOutDuration = self.timeout
            return self.writerTask
          }
          return nil
        }
        if let targetToCancel {
          logger.warning("dropping slow public firehose write")
          targetToCancel.cancel()
          return
        }
      }
    }
  }
}
