import Foundation
import ServiceLifecycle
import SwanAccounts

/// Bounded background did:web revalidation, started and stopped with the
/// application lifecycle. The scheduler is an actor with its own bounded
/// page loop; this wrapper owns the interval and cancellation so the
/// revalidation task is never a forever `Task` detached from the ServiceGroup.
public struct SwanDidWebRevalidationService: Service {
    private let scheduler: SwanDidWebRevalidationScheduler
    private let interval: Duration

    public init(
        scheduler: SwanDidWebRevalidationScheduler,
        interval: Duration = .seconds(3_600)
    ) {
        self.scheduler = scheduler
        self.interval = interval
    }

    public func run() async throws {
        do {
            while !Task.isCancelled {
                try Task.checkCancellation()
                do {
                    _ = try await scheduler.runOnce()
                } catch is CancellationError {
                    break
                } catch {
                    // A transient resolver or storage failure is bounded by
                    // the scheduler's own page loop; keep the service alive
                    // for the next scheduled attempt.
                    try? await Task.sleep(for: interval)
                    continue
                }
                try Task.checkCancellation()
                try await Task.sleep(for: interval)
            }
        } catch is CancellationError {
            // ServiceGroup cancellation is the normal shutdown path.
        }
    }
}
