import ServiceLifecycle
import SwanSQLite

/// Starts both durable notification queues for every account database that
/// was preopened during server startup. The service has no HTTP routes and no
/// database-opening capability; callers construct it only after supplying
/// explicit, SSRF-hardened transports. A process crash between a commit and a
/// send leaves the SQLite lease row for this service to reclaim on restart.
public struct SwanNotificationRecoveryService: Service {
    public typealias OutboxTransportFactory = @Sendable (SQLiteAccountDatabase) -> any PermissionedSpaceOutboxTransport
    public typealias SyncTransportFactory = @Sendable (SQLiteAccountDatabase) -> any PermissionedSpaceSyncNotificationTransport
    public typealias RevocationTransportFactory = @Sendable (SQLiteAccountDatabase) -> any PermissionedSpaceCredentialRevocationTransport

    private let databases: [SQLiteAccountDatabase]
    private let makeOutboxTransport: OutboxTransportFactory
    private let makeSyncTransport: SyncTransportFactory
    private let makeRevocationTransport: RevocationTransportFactory?
    private let configuration: PermissionedSpaceOutboxDeliveryConfiguration
    private let allowLocalhostDevelopment: Bool

    public init(
        databases: [SQLiteAccountDatabase],
        makeOutboxTransport: @escaping OutboxTransportFactory,
        makeSyncTransport: @escaping SyncTransportFactory,
        makeRevocationTransport: RevocationTransportFactory? = nil,
        configuration: PermissionedSpaceOutboxDeliveryConfiguration = .standard,
        allowLocalhostDevelopment: Bool = false
    ) {
        self.databases = databases
        self.makeOutboxTransport = makeOutboxTransport
        self.makeSyncTransport = makeSyncTransport
        self.makeRevocationTransport = makeRevocationTransport
        self.configuration = configuration
        self.allowLocalhostDevelopment = allowLocalhostDevelopment
    }

    /// Convenience startup constructor for the exact inventory used by the
    /// authenticated HTTP directory. It rechecks active/path state but never
    /// reopens a SQLite file.
    public static func fromPreopenedDirectory(
        _ directory: SQLitePreMigratedAccountDirectory,
        makeOutboxTransport: @escaping OutboxTransportFactory,
        makeSyncTransport: @escaping SyncTransportFactory,
        makeRevocationTransport: RevocationTransportFactory? = nil,
        configuration: PermissionedSpaceOutboxDeliveryConfiguration = .standard,
        allowLocalhostDevelopment: Bool = false
    ) async throws -> SwanNotificationRecoveryService {
        try await .init(
            databases: directory.notificationRecoveryDatabases(),
            makeOutboxTransport: makeOutboxTransport,
            makeSyncTransport: makeSyncTransport,
            makeRevocationTransport: makeRevocationTransport,
            configuration: configuration,
            allowLocalhostDevelopment: allowLocalhostDevelopment
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
                    let syncTransport = makeSyncTransport(database)
                    group.addTask { await outbox.runUntilCancelled() }
                    for _ in 0 ..< 4 {
                        let sync = PermissionedSpaceSyncNotificationDeliveryWorker(
                            database: database,
                            transport: syncTransport,
                            configuration: configuration,
                            allowLocalhostDevelopment: allowLocalhostDevelopment
                        )
                        group.addTask { await sync.runUntilCancelled() }
                    }
                    if let makeRevocationTransport {
                        let revocationTransport = makeRevocationTransport(database)
                        let revocation = PermissionedSpaceCredentialRevocationDeliveryWorker(
                            database: database,
                            transport: revocationTransport,
                            configuration: configuration
                        )
                        group.addTask { await revocation.runUntilCancelled() }
                    }
                }
                await group.waitForAll()
            }
        }
    }
}
