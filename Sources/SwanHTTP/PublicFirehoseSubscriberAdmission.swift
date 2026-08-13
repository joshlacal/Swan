import Foundation
import Synchronization

/// Route-level admission for anonymous `com.atproto.sync.subscribeRepos`
/// subscribers.
///
/// This is a **reservation, not a ceiling**, and the distinction is the whole
/// point. Hummingbird's `AvailableConnectionsHandler` charges a listener slot
/// in `channelRead` and refunds it only from `channel.closeFuture`
/// (`hummingbird/Sources/HummingbirdCore/Server/AvailableConnectionsHandler.swift:96-113`);
/// once the budget is full it stops calling `context.read()` on the accept
/// socket entirely (`:116-121`). An upgraded WebSocket never closes on its
/// own, so anonymous subscribers holding the *whole* listener budget do not
/// merely crowd the firehose — they stop `accept()` for login, OAuth, public
/// reads and the relay's own reconnect. Capping subscribers below the listener
/// budget is what keeps the remainder reachable; refusing the surplus
/// subscriber is only how that cap is expressed.
///
/// Modelled on `PublicRepositoryJSONReadAdmission`
/// (`Sources/SwanStorage/PublicRepositoryReadDirectory.swift:554-621`) and on
/// the reasoning recorded for the handle-resolution reservation in
/// `docs/superpowers/records/2026-08-12-swan-production-readiness/task-7-report.md:410-440`:
/// a dedicated instance, never `.processShared`, so a saturated firehose and a
/// saturated read budget cannot deny each other.
///
/// There is deliberately no per-peer dimension. Every socket on the deployed
/// box arrives from a Cloudflare address, so a per-peer bucket keyed on the
/// transport peer would bound one identity that all traffic shares; the global
/// reservation is the control that actually holds.
public final class PublicFirehoseSubscriberAdmission: Sendable {
  public struct Snapshot: Sendable, Equatable {
    public let activeSubscribers: Int
    public let maximumConcurrentSubscribers: Int

    public init(activeSubscribers: Int, maximumConcurrentSubscribers: Int) {
      self.activeSubscribers = activeSubscribers
      self.maximumConcurrentSubscribers = maximumConcurrentSubscribers
    }
  }

  /// The share of the listener connection budget anonymous subscribers may
  /// hold. A quarter leaves three quarters — 192 of the default 256 slots —
  /// permanently reachable by HTTP, which includes the relay's reconnect.
  public static let listenerBudgetShareDenominator = 4

  /// Never zero: a one-slot listener still serves the firehose, it just
  /// serves nothing else while that subscriber is connected.
  public static func reservedSubscriberSlots(listenerBudget: Int) -> Int {
    max(1, listenerBudget / listenerBudgetShareDenominator)
  }

  public let maximumConcurrentSubscribers: Int
  private let leases = Mutex(Set<UUID>())

  public init(maximumConcurrentSubscribers: Int) {
    precondition(
      maximumConcurrentSubscribers > 0,
      "a zero firehose reservation would make subscribeRepos permanently unavailable"
    )
    self.maximumConcurrentSubscribers = maximumConcurrentSubscribers
  }

  /// Sizes the reservation as a share of the listener's connection budget.
  public convenience init(listenerBudget: Int) {
    self.init(
      maximumConcurrentSubscribers: Self.reservedSubscriberSlots(
        listenerBudget: listenerBudget
      )
    )
  }

  /// Charges one subscriber slot, or reports that the reservation is full.
  ///
  /// The caller must hold the returned lease for the whole lifetime of the
  /// upgraded connection and release it exactly once on exit; the listener
  /// slot it stands for is not refunded until the channel closes.
  public func reserve() -> PublicFirehoseSubscriberLease? {
    leases.withLock { leases in
      guard leases.count < maximumConcurrentSubscribers else { return nil }
      let id = UUID()
      leases.insert(id)
      return PublicFirehoseSubscriberLease(admission: self, id: id)
    }
  }

  public var snapshot: Snapshot {
    leases.withLock { leases in
      Snapshot(
        activeSubscribers: leases.count,
        maximumConcurrentSubscribers: maximumConcurrentSubscribers
      )
    }
  }

  fileprivate func release(_ id: UUID) {
    leases.withLock { _ = $0.remove(id) }
  }
}

/// One charged subscriber slot. Releasing twice is a no-op, and a lease that
/// is dropped without an explicit release still refunds — a connection handler
/// that returns on an unexpected path must not leak the reservation.
public final class PublicFirehoseSubscriberLease: Sendable {
  private let admission: PublicFirehoseSubscriberAdmission
  private let id: UUID
  private let released = Mutex(false)

  fileprivate init(admission: PublicFirehoseSubscriberAdmission, id: UUID) {
    self.admission = admission
    self.id = id
  }

  deinit { release() }

  public func release() {
    let shouldRelease = released.withLock { released -> Bool in
      guard !released else { return false }
      released = true
      return true
    }
    if shouldRelease {
      admission.release(id)
    }
  }
}
