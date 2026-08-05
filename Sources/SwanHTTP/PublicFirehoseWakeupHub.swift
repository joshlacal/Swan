import Foundation
import SwanSQLite

/// In-process coalesced wakeup fan-out for public firehose appends.
///
/// The sequencer's per-append ``firehoseDidAppend(maxSeq:)`` is fanned out to
/// every subscriber as a buffered stream with `.bufferingNewest(1)` semantics:
/// a subscriber that is not currently reading observes only the most recent
/// bump, so a burst of appends coalesces into one delivered value. A missed
/// wakeup is harmless — per-connection tailer loops recover by polling — so
/// this hub carries wakeup signals only and never event bytes.
///
/// This is the only fan-out primitive in `Sources/`; the sequencer invokes it
/// exactly as it does today (`await wakeup?.firehoseDidAppend(maxSeq: seq)`).
public actor PublicFirehoseWakeupHub: PublicFirehoseWakeupSink {
  private var latestMaxSeq: Int64 = 0
  private var subscribers: [UUID: AsyncStream<Int64>.Continuation] = [:]

  public init() {}

  /// Records the append and resumes every subscriber with the bumped maximum
  /// sequence. Equal or lower bumps (exact source-key replays) are coalesced
  /// away: no new rows exist beyond the previous maximum, so no subscriber
  /// needs waking.
  public func firehoseDidAppend(maxSeq: Int64) async {
    guard maxSeq > latestMaxSeq else { return }
    latestMaxSeq = maxSeq
    for continuation in subscribers.values {
      continuation.yield(maxSeq)
    }
  }

  /// Returns a per-subscriber stream of append bumps. Each subscriber owns
  /// its continuation; cancellation or deallocation removes it from the hub.
  public func subscribe() -> AsyncStream<Int64> {
    let (stream, continuation) = AsyncStream<Int64>.makeStream(
      bufferingPolicy: .bufferingNewest(1)
    )
    let id = UUID()
    subscribers[id] = continuation
    continuation.onTermination = { [weak self] _ in
      Task { await self?.removeSubscriber(id) }
    }
    return stream
  }

  private func removeSubscriber(_ id: UUID) {
    subscribers[id] = nil
  }
}
