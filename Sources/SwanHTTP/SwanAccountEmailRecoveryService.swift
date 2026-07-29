import Foundation
import ServiceLifecycle
import SwanAccounts
import SwanStorage

/// Drains the durable account-email outbox for the live `swan serve` process.
///
/// The recovery service owns SQLite admission/retry state while the delivery
/// actor owns the bounded SMTP event-loop group.  Both are assembled only
/// after the control database and public account directory have opened, and
/// the delivery actor is shut down when the lifecycle task is cancelled.
public struct SwanAccountEmailRecoveryService: Service {
    private let recovery: AccountEmailRecoveryService
    private let delivery: MailpitSMTPDelivery
    private let workerID: String
    private let idlePollInterval: Duration

    public init(
        recovery: AccountEmailRecoveryService,
        delivery: MailpitSMTPDelivery,
        workerID: String = "swan-email-worker",
        idlePollInterval: Duration = .seconds(1)
    ) throws {
        guard !workerID.isEmpty,
              workerID.utf8.count <= 128,
              workerID.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw AccountControlStoreError.invalidInput
        }
        self.recovery = recovery
        self.delivery = delivery
        self.workerID = workerID
        self.idlePollInterval = idlePollInterval
    }

    public func run() async throws {
        do {
            while !Task.isCancelled {
                try Task.checkCancellation()
                let result: AccountEmailDeliveryRunResult
                do {
                    result = try await recovery.deliverNext(workerID: workerID)
                    try Task.checkCancellation()
                } catch is CancellationError {
                    break
                } catch {
                    // A transient SQLite or SMTP failure is represented by the
                    // durable lease/retry path.  Keep the worker alive so a
                    // restart is not required for the next scheduled attempt.
                    try? await Task.sleep(for: idlePollInterval)
                    continue
                }

                switch result {
                case .idle:
                    try await Task.sleep(for: idlePollInterval)
                case let .retryScheduled(_, nextAttemptAt):
                    let delay = max(0, nextAttemptAt.timeIntervalSinceNow)
                    if delay > 0 {
                        try await Task.sleep(for: .milliseconds(
                            Int64(min(delay, 86_400) * 1_000)
                        ))
                    }
                case .delivered, .expired:
                    // Drain another immediately available row without adding
                    // latency to a burst, while still checking cancellation at
                    // the top of the loop.
                    continue
                }
            }
        } catch is CancellationError {
            // ServiceGroup cancellation is the normal shutdown path.
        }

        // Do not leave the NIO event-loop group behind when the lifecycle
        // group tears down. `shutdown` is idempotent for signal races.
        try? await delivery.shutdown()
    }
}
