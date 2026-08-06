import Foundation
import Hummingbird
import HummingbirdWebSocket
import Logging
import NIOConcurrencyHelpers
import NIOCore
import Petrel
import SwanPublicFirehose
import SwanSQLite

/// The durable runtime backing the public `com.atproto.sync.subscribeRepos`
/// WebSocket endpoint. Constructed once at startup and shared by every
/// connection; per-connection state lives entirely inside the upgrade handler.
public struct SwanPublicFirehoseStreamingRuntime: Sendable {
  public let database: SQLiteFirehoseDatabase
  public let hub: PublicFirehoseWakeupHub
  public let limits: PublicFirehoseStreamingLimits
  public let logger: Logger

  public init(
    database: SQLiteFirehoseDatabase,
    hub: PublicFirehoseWakeupHub,
    limits: PublicFirehoseStreamingLimits,
    logger: Logger
  ) {
    self.database = database
    self.hub = hub
    self.limits = limits
    self.logger = logger
  }
}

/// Registers the `subscribeRepos` WebSocket route on the public router.
///
/// Upgrade requests are gated on the `Upgrade: websocket` header and a strict
/// single-`cursor` query (D7): any malformed cursor rejects the upgrade.
/// Non-upgrade GETs to the exact path receive 405 from the route itself.
public func registerPublicFirehoseStreamingEndpoint(
  on router: Router<SwanHTTPRequestContext>,
  runtime: SwanPublicFirehoseStreamingRuntime
) {
  router.ws(
    "/xrpc/com.atproto.sync.subscribeRepos",
    shouldUpgrade: { request, _ in
      switch publicFirehoseUpgradeDecision(request) {
      case .upgrade:
        return .upgrade([:])
      case .reject:
        return .dontUpgrade
      }
    },
    onUpgrade: { inbound, outbound, context in
      await publicFirehoseOnUpgrade(
        inbound: inbound,
        outbound: outbound,
        context: context,
        runtime: runtime
      )
    }
  )
}

// MARK: - Upgrade decision

private enum PublicFirehoseUpgradeDecision {
  case upgrade(cursor: Int64?)
  case reject
}

/// Strict cursor policy per D7, mirroring the house strict-query style:
/// no fragments, query bounded at 8 KiB, at most one `cursor` key, value
/// strictly decimal (digits only, non-empty) and at or below the firehose
/// sequence ceiling. Anything else rejects the upgrade.
private func publicFirehoseUpgradeDecision(
  _ request: Request
) -> PublicFirehoseUpgradeDecision {
  guard request.headers[.upgrade] == "websocket" else {
    return .reject
  }
  guard !request.uri.string.contains("#") else {
    return .reject
  }
  guard let query = request.uri.query else {
    // No query: no cursor, stream live.
    return .upgrade(cursor: nil)
  }
  guard query.utf8.count <= 8 * 1_024 else {
    return .reject
  }
  if query.isEmpty {
    return .upgrade(cursor: nil)
  }
  var cursorSeen = false
  var cursor: Int64?
  for segment in query.split(separator: "&", omittingEmptySubsequences: false) {
    let pair = segment.split(
      separator: "=", maxSplits: 1, omittingEmptySubsequences: false
    )
    guard pair.count == 2, pair[0] == "cursor", !cursorSeen,
          let parsed = strictFirehoseCursor(pair[1]) else {
      return .reject
    }
    cursor = parsed
    cursorSeen = true
  }
  return .upgrade(cursor: cursor)
}

private func strictFirehoseCursor(_ value: Substring) -> Int64? {
  guard !value.isEmpty,
        value.utf8.allSatisfy({ $0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9") })
  else {
    return nil
  }
  var result: Int64 = 0
  for byte in value.utf8 {
    let digit = Int64(byte - UInt8(ascii: "0"))
    let (multiplied, multiplicationOverflow) =
      result.multipliedReportingOverflow(by: 10)
    let (added, additionOverflow) = multiplied.addingReportingOverflow(digit)
    if multiplicationOverflow || additionOverflow
      || added > FirehoseFrameLimits.maximumSequence {
      return nil
    }
    result = added
  }
  return result
}

// MARK: - Upgrade handler

/// Per-connection streaming session. Resolves the cursor policy, then runs
/// two sibling tasks — an inbound drain that consumes client close/ping
/// frames and the tailer loop fed by the hub — and cancels the sibling when
/// either ends. The subscription is finished before exit because a suspended
/// `AsyncStream.next()` is not resumed by cancellation alone.
private func publicFirehoseOnUpgrade(
  inbound: WebSocketInboundStream,
  outbound: WebSocketOutboundWriter,
  context: WebSocketRouterContext<SwanHTTPRequestContext>,
  runtime: SwanPublicFirehoseStreamingRuntime
) async {
  let logger = context.logger
  // `shouldUpgrade` already validated the request; re-parsing the same
  // request here is deterministic and avoids carrying per-request state in
  // the shared runtime.
  let cursor: Int64?
  switch publicFirehoseUpgradeDecision(context.request) {
  case .upgrade(let parsed): cursor = parsed
  case .reject: cursor = nil
  }

  let lastSent: Int64
  do {
    let maxSequencedSeq = try await runtime.database.maxSequencedSeq()
    let retainedFromSeq = try await runtime.database.retainedFromSeq()
    switch PublicFirehoseCursorPolicy.resolve(
      cursor: cursor,
      maxSequencedSeq: maxSequencedSeq,
      retainedFromSeq: retainedFromSeq
    ) {
    case .futureCursor:
      try? await outbound.write(
        .binary(ByteBuffer(data: try FirehoseFrameEncoder.errorFrame(error: "FutureCursor", message: nil)))
      )
      try? await outbound.close(.normalClosure, reason: "FutureCursor")
      return
    case .outdatedCursor:
      try? await outbound.write(
        .binary(ByteBuffer(data: try FirehoseFrameEncoder.infoFrame(name: "OutdatedCursor", message: nil)))
      )
      // Stream from the oldest retained event. `retainedFromSeq` is always
      // non-nil here (the policy only reports `.outdatedCursor` against one);
      // the defensive fallback keeps the cursor at the window start.
      lastSent = (retainedFromSeq ?? 1) - 1
    case .live:
      lastSent = maxSequencedSeq
    case .fullWindow:
      // Start just before the oldest retained row (not literal 0) so the
      // slow-consumer sequence-lag check is computed against what is
      // actually deliverable, not against sequences retention already
      // deleted. This preserves the design rule that `cursor=0` streams the
      // retained window without an `OutdatedCursor` info frame.
      lastSent = max(0, (retainedFromSeq ?? 1) - 1)
    case .backfill(from: let from):
      lastSent = from
    }
  } catch {
    logger.error("public firehose cursor resolution failed", metadata: [
      "error": "\(error)"
    ])
    try? await outbound.close(.unexpectedServerError, reason: nil)
    return
  }

  let (wakeupStream, finishWakeup) = await runtime.hub.subscribeWithFinish()
  // One long-lived task per connection forwards hub bumps into an atomic
  // mailbox. `waitForWakeup` reads the mailbox without ever blocking, so a
  // bump that arrived before the subscriber registered (or a lost signal)
  // always falls back to the tailer's bounded idle poll; a suspended
  // `AsyncStream.next()` inside this task is resumed by `finishWakeup()`
  // before the group scope exits.
  let wakeupMailbox = NIOLockedValueBox<Int64?>(nil)
  Task {
    for await seq in wakeupStream {
      wakeupMailbox.withLockedValue { $0 = seq }
    }
  }
  let tailer = PublicFirehoseTailer(
    database: runtime.database,
    limits: runtime.limits,
    logger: logger
  )
  await withTaskGroup(of: Void.self) { group in
    group.addTask {
      // Draining the inbound stream keeps the library processing control
      // frames (close/ping) for the lifetime of the connection. This task
      // ends when the client closes or the channel tears down.
      do {
        for try await _ in inbound {}
      } catch {
        logger.debug("public firehose inbound drain ended with error", metadata: [
          "error": "\(error)"
        ])
      }
    }
    group.addTask {
      await publicFirehoseRunTailer(
        tailer: tailer,
        initialLastSent: lastSent,
        outbound: outbound,
        wakeupMailbox: wakeupMailbox,
        logger: logger
      )
    }
    // Wait for whichever child ends first, then cancel the sibling and
    // finish the hub subscription so the wakeup forwarder's suspended
    // `AsyncStream.next()` resumes instead of leaking the subscriber.
    _ = await group.next()
    group.cancelAll()
    finishWakeup()
  }
  logger.debug("public firehose subscription ended")
}

/// Runs the tailer loop for a connection, restarting it in place after a
/// retention advance so the session survives instead of closing.
///
/// `PublicFirehoseTailerError.outdatedCursor` writes an `#info`
/// `OutdatedCursor` frame and re-enters `tailer.run` from the new retained
/// boundary — the cursor is mutable across iterations for exactly this
/// resume. `consumerTooSlow`/`writeTooSlow` map to a `ConsumerTooSlow` error
/// frame followed by a close, ending the loop. Any other failure (closed
/// channel, database error) ends the loop without a control frame; the
/// sibling task group teardown handles the channel.
private func publicFirehoseRunTailer(
  tailer: PublicFirehoseTailer,
  initialLastSent: Int64,
  outbound: WebSocketOutboundWriter,
  wakeupMailbox: NIOLockedValueBox<Int64?>,
  logger: Logger
) async {
  let outboundWrite: (Data) async throws -> Void = { frameBytes in
    try await outbound.write(.binary(ByteBuffer(data: frameBytes)))
  }
  let wakeupRead: () async -> Int64? = {
    // Never blocks: consumes the newest pending bump or reports none, so the
    // tailer falls back to its own bounded idle poll (the recovery path for
    // a missed or pre-subscription wakeup, and for a lost retention signal).
    wakeupMailbox.withLockedValue { value in
      let pending = value
      value = nil
      return pending
    }
  }

  var lastSent = initialLastSent
  while !Task.isCancelled {
    do {
      try await tailer.run(
        lastSent: lastSent,
        outbound: outboundWrite,
        waitForWakeup: wakeupRead
      )
      return
    } catch let error as PublicFirehoseTailerError {
      switch error {
      case let .outdatedCursor(retainedFromSeq):
        try? await outbound.write(
          .binary(ByteBuffer(data: try FirehoseFrameEncoder.infoFrame(
            name: "OutdatedCursor",
            message: nil
          )))
        )
        lastSent = max(0, retainedFromSeq - 1)
      case .consumerTooSlow, .writeTooSlow:
        logger.warning("dropping slow public firehose consumer", metadata: [
          "tailerError": "\(error)"
        ])
        try? await outbound.write(
          .binary(ByteBuffer(data: try FirehoseFrameEncoder.errorFrame(
            error: "ConsumerTooSlow",
            message: nil
          )))
        )
        try? await outbound.close(.normalClosure, reason: "ConsumerTooSlow")
        return
      }
    } catch {
      logger.debug("public firehose tailer ended with error", metadata: [
        "error": "\(error)"
      ])
      return
    }
  }
}
