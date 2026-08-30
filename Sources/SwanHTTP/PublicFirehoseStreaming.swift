import Foundation
import Logging
import Synchronization
import SwanCore
import SwanSQLite
import PetrelFirehose

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

/// Process-wide page admission bounding concurrent firehose event page materialization.
public final class PublicFirehosePageAdmission: Sendable {
  public static let shared = PublicFirehosePageAdmission()

  private let activeLeases = Mutex<Int>(0)
  public let maximumConcurrentPages: Int

  public init(maximumConcurrentPages: Int = 4) {
    self.maximumConcurrentPages = maximumConcurrentPages
  }

  public func reserve() -> PublicFirehosePageLease? {
    let reserved = activeLeases.withLock { count -> Bool in
      guard count < maximumConcurrentPages else { return false }
      count += 1
      return true
    }
    guard reserved else { return nil }
    return PublicFirehosePageLease(admission: self)
  }

  fileprivate func release() {
    activeLeases.withLock { count in
      guard count > 0 else { return }
      count -= 1
    }
  }

  public var currentActiveLeases: Int {
    activeLeases.withLock { $0 }
  }
}

public final class PublicFirehosePageLease: Sendable {
  private let admission: PublicFirehosePageAdmission
  private let released = Mutex(false)

  fileprivate init(admission: PublicFirehosePageAdmission) {
    self.admission = admission
  }

  deinit {
    release()
  }

  public func release() {
    let shouldRelease = released.withLock { isReleased -> Bool in
      guard !isReleased else { return false }
      isReleased = true
      return true
    }
    if shouldRelease {
      admission.release()
    }
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
  case admissionStarved
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
  public let pageAdmission: PublicFirehosePageAdmission

  public init(
    database: SQLiteFirehoseDatabase,
    limits: PublicFirehoseStreamingLimits,
    logger: Logger,
    pageAdmission: PublicFirehosePageAdmission = .shared
  ) {
    self.database = database
    self.limits = limits
    self.logger = logger
    self.pageAdmission = pageAdmission
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
        if let timeoutDuration = watchdog.checkTimedOutDuration() {
          throw PublicFirehoseTailerError.writeTooSlow(duration: timeoutDuration)
        }
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
    var starvedStarted: ContinuousClock.Instant?
    var pendingAdmissionSeqLag: Int64?
    let clock = ContinuousClock()
    while !Task.isCancelled {
      // Checked before every read so a retention advance is caught even
      // when it does not change what `events(after:, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)` would return (e.g.
      // the consumer is already caught up but the retained window moved
      // past its delivered cursor).
      if let retainedFromSeq = try await database.retainedFromSeq(),
         cursor < retainedFromSeq - 1 {
        throw PublicFirehoseTailerError.outdatedCursor(
          retainedFromSeq: retainedFromSeq
        )
      }

      // Snapshot lag before admission so an already-lagging cursor is rejected
      // without waiting for or reserving a page. Lag created while waiting for
      // this server-side gate is not attributed to the consumer.
      let seqLag: Int64
      if let pendingAdmissionSeqLag {
        seqLag = pendingAdmissionSeqLag
      } else {
        let maxSeq = try await database.maxSequencedSeq()
        var snapshotLag: Int64 = 0
        if maxSeq > cursor {
          snapshotLag = maxSeq - cursor
          if snapshotLag > limits.maximumSequenceLag {
            snapshotLag = try await database.deliverableEventCount(
              after: cursor,
              limit: limits.maximumSequenceLag + 1
            )
          }
        }
        pendingAdmissionSeqLag = snapshotLag
        seqLag = snapshotLag
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

      if let starvedStarted,
         clock.now - starvedStarted > limits.maximumBackfillCatchUp {
        logger.warning("dropping public firehose subscriber due to page admission saturation")
        throw PublicFirehoseTailerError.admissionStarved
      }
      guard let pageLease = pageAdmission.reserve() else {
        if starvedStarted == nil {
          starvedStarted = clock.now
        }
        try await Task.sleep(for: .seconds(limits.idlePollInterval))
        continue
      }
      pendingAdmissionSeqLag = nil
      starvedStarted = nil

      let rows: [FirehoseStoredEvent]
      do {
        rows = try await database.events(
          after: cursor,
          limit: limits.pageSize,
          maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes
        )
      } catch {
        pageLease.release()
        throw error
      }
      if rows.isEmpty {
        pageLease.release()
        let wakeupSeq = await waitForWakeup()
        if wakeupSeq != nil {
          continue
        }
        try await Task.sleep(for: .seconds(limits.idlePollInterval))
        continue
      }
      let pageStarted = clock.now
      let maximumPageHold = limits.maximumBackfillCatchUp / 2
      for row in rows {
        let currentHold = clock.now - pageStarted
        if currentHold > maximumPageHold
          || (seqLag > 0 && backfillElapsed + currentHold > limits.maximumBackfillCatchUp) {
          pageLease.release()
          logger.warning("dropping slow public firehose consumer exceeding backfill catch-up budget")
          throw PublicFirehoseTailerError.consumerTooSlow(
            seqLag: seqLag,
            backfillElapsed: backfillElapsed + currentHold
          )
        }
        try watchdog.beginWrite()
        do {
          try await outbound(row.frameBytes)
          try watchdog.endWrite()
        } catch {
          try? watchdog.endWrite()
          pageLease.release()
          throw error
        }
        cursor = row.seq
      }
      pageLease.release()
      let pageElapsed = clock.now - pageStarted
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
/// exceeds the deadline, the watchdog atomically transitions to timedOut, logs the
/// drop, and cancels the writer task. `endWrite` and timeout arbitrate one atomic
/// terminal decision under a single lock.
private final class PublicFirehoseWriteWatchdog: @unchecked Sendable {
  private let lock = NSLock()
  private let timeout: Duration
  private let logger: Logger

  private enum State {
    case idle
    case writing(deadline: ContinuousClock.Instant)
    case timedOut(duration: Duration)
    case terminated
  }

  private var state: State = .idle
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

  func beginWrite() throws {
    let continuation: CheckedContinuation<Void, Never>? = try lock.withLock {
      switch self.state {
      case .terminated:
        throw CancellationError()
      case .timedOut(let duration):
        throw PublicFirehoseTailerError.writeTooSlow(duration: duration)
      case .idle, .writing:
        self.state = .writing(deadline: ContinuousClock.now + timeout)
        let cont = self.idleContinuation
        self.idleContinuation = nil
        return cont
      }
    }
    continuation?.resume()
  }

  func endWrite() throws {
    try lock.withLock {
      switch self.state {
      case .timedOut(let duration):
        throw PublicFirehoseTailerError.writeTooSlow(duration: duration)
      case .terminated:
        throw CancellationError()
      case .writing, .idle:
        self.state = .idle
      }
    }
  }

  func terminate() {
    let continuation: CheckedContinuation<Void, Never>? = lock.withLock {
      self.state = .terminated
      let cont = self.idleContinuation
      self.idleContinuation = nil
      return cont
    }
    continuation?.resume()
  }

  func checkTimedOutDuration() -> Duration? {
    lock.withLock {
      if case .timedOut(let duration) = self.state {
        return duration
      }
      return nil
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
        switch self.state {
        case .terminated, .timedOut:
          return .terminate
        case .idle:
          return .waitForBegin
        case .writing(let deadline):
          return .sleep(until: deadline)
        }
      }

      switch action {
      case .terminate:
        return

      case .waitForBegin:
        await withCheckedContinuation { continuation in
          var shouldResumeImmediately = false
          lock.withLock {
            switch self.state {
            case .terminated, .timedOut, .writing:
              shouldResumeImmediately = true
            case .idle:
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
          switch self.state {
          case .writing(let activeDeadline):
            if clock.now >= activeDeadline {
              self.state = .timedOut(duration: self.timeout)
              return self.writerTask
            }
            return nil
          case .idle, .terminated, .timedOut:
            return nil
          }
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
