import Logging
import ServiceLifecycle
import UnixSignals

/// The lifecycle contract shared by the public and management applications.
/// Keeping the signal policy in the HTTP module makes it directly testable and
/// prevents a command adapter from accidentally dropping graceful shutdown
/// while composing multiple Hummingbird `Service`s.
public enum SwanHTTPServiceLifecycle {
    public static let gracefulShutdownSignals: [UnixSignal] = [.sigterm, .sigint]

    public static func makeServiceGroup(
        services: [any Service],
        logger: Logger
    ) -> ServiceGroup {
        ServiceGroup(configuration: .init(
            services: services,
            gracefulShutdownSignals: gracefulShutdownSignals,
            logger: logger
        ))
    }
}
