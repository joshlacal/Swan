import Foundation
import ServiceLifecycle
import SwanAccounts
import SwanSQLite
import SwanStorage

/// Drains the durable signup-email outbox for the live `swan serve` process.
///
/// The service owns SQLite admission/retry state through
/// `SignupEmailOutboxWorker` while the delivery actor owns the bounded SMTP
/// event-loop group. It is assembled only when authenticated SMTP (non-lab
/// mode) is configured; the Mailpit laboratory path has no signup email
/// worker because the lab SMTP client is not an `AuthenticatedSMTPDelivery`.
public struct SwanSignupEmailOutboxService: Service {
    private let worker: SignupEmailOutboxWorker<SQLiteControlDatabase>
    private let delivery: AuthenticatedSMTPDelivery
    private let idlePollInterval: Duration

    public init(
        worker: SignupEmailOutboxWorker<SQLiteControlDatabase>,
        delivery: AuthenticatedSMTPDelivery,
        idlePollInterval: Duration = .seconds(1)
    ) {
        self.worker = worker
        self.delivery = delivery
        self.idlePollInterval = idlePollInterval
    }

    public func run() async throws {
        do {
            while !Task.isCancelled {
                try Task.checkCancellation()
                do {
                    let delivered = try await worker.runOnce()
                    try Task.checkCancellation()
                    if delivered {
                        // Drain another immediately available row without
                        // adding latency to a burst, while still checking
                        // cancellation at the top of the loop.
                        continue
                    }
                } catch is CancellationError {
                    break
                } catch {
                    // A transient SQLite or SMTP failure is represented by the
                    // durable lease/retry path. Keep the worker alive so a
                    // restart is not required for the next scheduled attempt.
                    try? await Task.sleep(for: idlePollInterval)
                    continue
                }
                try await Task.sleep(for: idlePollInterval)
            }
        } catch is CancellationError {
            // ServiceGroup cancellation is the normal shutdown path.
        }
    }
}
