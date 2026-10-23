import ServiceLifecycle
import SwanSQLite

/// Starts both durable notification queues for every account database that
/// was preopened during server startup. The service has no HTTP routes and no
/// database-opening capability; callers construct it only after supplying
/// explicit, SSRF-hardened transports. A process crash between a commit and a
/// send leaves the SQLite lease row for this service to reclaim on restart.
public struct SwanNotificationRecoveryService: Service {
    public typealias OutboxTransportFactory = @Sendable (SQLiteAccountDatabase) -> any PermissionedSpaceOutboxTransport
    public typealias FanoutTransportFactory = @Sendable (SQLiteAccountDatabase) -> any PermissionedSpaceNotificationFanoutTransport

    private let databases: [SQLiteAccountDatabase]
    private let makeOutboxTransport: OutboxTransportFactory
    private let makeFanoutTransport: FanoutTransportFactory
    private let configuration: PermissionedSpaceOutboxDeliveryConfiguration

    public init(
        databases: [SQLiteAccountDatabase],
        makeOutboxTransport: @escaping OutboxTransportFactory,
        makeFanoutTransport: @escaping FanoutTransportFactory,
        configuration: PermissionedSpaceOutboxDeliveryConfiguration = .standard
    ) {
        self.databases = databases
        self.makeOutboxTransport = makeOutboxTransport
        self.makeFanoutTransport = makeFanoutTransport
        self.configuration = configuration
    }

    /// Convenience startup constructor for the exact inventory used by the
    /// authenticated HTTP directory. It rechecks active/path state but never
    /// reopens a SQLite file.
    public static func fromPreopenedDirectory(
        _ directory: SQLitePreMigratedAccountDirectory,
        makeOutboxTransport: @escaping OutboxTransportFactory,
        makeFanoutTransport: @escaping FanoutTransportFactory,
        configuration: PermissionedSpaceOutboxDeliveryConfiguration = .standard
    ) async throws -> SwanNotificationRecoveryService {
        try await .init(
            databases: directory.notificationRecoveryDatabases(),
            makeOutboxTransport: makeOutboxTransport,
            makeFanoutTransport: makeFanoutTransport,
            configuration: configuration
        )
    }

    public func run() async throws {
        await cancelWhenGracefulShutdown {
            await withTaskGroup(of: Void.self) { group in
                for database in databases {
                    let outbox = PermissionedSpaceOutboxDeliveryWorker(
                        database: database,
                        transport: makeOutboxTransport(database),
                        configuration: configuration
                    )
                    let fanout = PermissionedSpaceNotificationFanoutDeliveryWorker(
                        database: database,
                        transport: makeFanoutTransport(database),
                        configuration: configuration
                    )
                    group.addTask { await outbox.runUntilCancelled() }
                    group.addTask { await fanout.runUntilCancelled() }
                }
                await group.waitForAll()
            }
        }
    }
}
