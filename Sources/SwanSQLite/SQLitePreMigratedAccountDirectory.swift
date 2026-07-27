import Foundation
import SwanCore
import SwanSpaces
import SwanStorage

/// A startup-owned directory of account databases that were opened and
/// migrated before the service accepted traffic. It intentionally has no
/// fallback construction path: a request can select only a database that was
/// successfully preopened for an active account at bootstrap.
public actor SQLitePreMigratedAccountDirectory:
    AuthorizedSimpleSpaceDirectory,
    AuthorizedSpaceRepositoryDirectory
{
    private let controlStore: any AccountControlStore
    private let dataDirectory: URL
    private var databases: [String: SQLiteAccountDatabase]
    private var isClosed = false

    private init(
        dataDirectory: URL,
        controlStore: any AccountControlStore,
        databases: [String: SQLiteAccountDatabase]
    ) {
        self.dataDirectory = dataDirectory
        self.controlStore = controlStore
        self.databases = databases
    }

    /// Opens and migrates every currently active account database. A missing,
    /// non-regular, symlinked, corrupt, or unopenable account database makes
    /// startup unavailable; it is never created as a recovery side effect.
    public static func bootstrap(
        dataDirectory: URL,
        controlStore: any AccountControlStore,
        oplogRetention: Int = 10_000
    ) async throws -> SQLitePreMigratedAccountDirectory {
        guard oplogRetention > 0 else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }

        var opened: [String: SQLiteAccountDatabase] = [:]
        do {
            let dids = try await controlStore.activeAccountDIDs()
            try validateStartupDIDs(dids)
            for did in dids {
                let databaseURL = SQLiteLayout.accountDatabase(in: dataDirectory, did: did)
                try requireExistingRegularDatabase(databaseURL)
                opened[did] = try await SQLiteAccountDatabase(
                    dataDirectory: dataDirectory,
                    did: did,
                    oplogRetention: oplogRetention
                )
            }
            return SQLitePreMigratedAccountDirectory(
                dataDirectory: dataDirectory,
                controlStore: controlStore,
                databases: opened
            )
        } catch {
            await closeSilently(Array(opened.values))
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
    }

    /// There is no request-time database construction. Reactivated accounts
    /// whose databases were not in the startup inventory fail closed instead
    /// of causing a new SQLite file or migration to be created.
    public func space(
        _ space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws -> AuthenticatedSimpleSpaceDescription? {
        guard !isClosed else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard case let .accountOAuth(subject, scopes) = authorization,
              subject == space.authority,
              scopes.contains("atproto") else {
            throw SwanError.unauthorized("authority account OAuth with atproto scope is required")
        }

        guard try await isActiveAccount(space.authority) else { return nil }
        guard !isClosed else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        do {
            // An already-open SQLite handle may continue serving an unlinked
            // file on POSIX. Refuse that stale state rather than treating a
            // vanished/replaced path as permission to recreate it.
            try Self.requireExistingRegularDatabase(
                SQLiteLayout.accountDatabase(in: dataDirectory, did: space.authority)
            )
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard let database = databases[space.authority] else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }

        let state: DurableSimpleSpaceState?
        do {
            // `simpleSpace` performs the existing managing-authority scope
            // checks and fully validates all authority state before a safe
            // response projection is made below.
            state = try await database.simpleSpace(space, authorization: authorization)
        } catch let error as SwanError {
            if case .unauthorized = error {
                throw error
            }
            throw SwanError.unavailable("authenticated space directory is unavailable")
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }

        guard try await isActiveAccount(space.authority) else { return nil }
        // Actors are reentrant while the durable calls above await. A
        // concurrent service shutdown therefore wins over a stale lookup
        // that began before `close()` set its terminal state.
        guard !isClosed else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard let state, !state.space.isDeleted else { return nil }
        return AuthenticatedSimpleSpaceDescription(
            space: state.space.uri,
            configuration: state.space.configuration
        )
    }

    /// Reads one record only from a database which was opened during startup.
    /// The actor never treats a requested DID as a construction request: a
    /// missing preopened database, a replaced path, or shutdown is always
    /// unavailable rather than a chance to migrate or open SQLite on demand.
    public func record(
        _ uri: SpaceRecordURI,
        authorization: AuthorizationContext
    ) async throws -> SpaceRecord? {
        let database = try await preopenedRepositoryDatabase(
            for: uri.author,
            authorization: authorization
        )
        guard let database else { return nil }

        do {
            let repository = try DurableSpaceRepository(
                database: database,
                space: uri.space,
                author: uri.author
            )
            let result = try await repository.record(uri, authorization: authorization)
            guard try await isActiveAccount(uri.author) else { return nil }
            guard !isClosed else {
                throw SwanError.unavailable("authenticated space directory is unavailable")
            }
            return result
        } catch let error as SwanError {
            throw error
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
    }

    /// Reads a bounded page only from an already-open repository database.
    /// Ordering and tolerant cursor semantics live in
    /// ``DurableSpaceRepository/listRecords(collection:limit:cursor:reverse:authorization:)``
    /// so SQLite cannot bypass the domain's collection-scoped authorization.
    public func records(
        space: SpaceURI,
        author: String,
        collection: String?,
        limit: Int,
        cursor: String?,
        reverse: Bool,
        authorization: AuthorizationContext
    ) async throws -> [SpaceRecord] {
        let database = try await preopenedRepositoryDatabase(
            for: author,
            authorization: authorization
        )
        guard let database else { return [] }

        do {
            let repository = try DurableSpaceRepository(
                database: database,
                space: space,
                author: author
            )
            let result = try await repository.listRecords(
                collection: collection,
                limit: limit,
                cursor: cursor,
                reverse: reverse,
                authorization: authorization
            )
            guard try await isActiveAccount(author) else { return [] }
            guard !isClosed else {
                throw SwanError.unavailable("authenticated space directory is unavailable")
            }
            return result
        } catch let error as SwanError {
            throw error
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
    }

    /// Explicitly releases every startup-opened connection. The method is
    /// idempotent, and lookup after closing is unavailable rather than able to
    /// reopen a database on demand.
    public func close() async throws {
        guard !isClosed else { return }
        isClosed = true
        let opened = Array(databases.values)
        databases.removeAll()

        var failed = false
        for database in opened {
            do {
                try await database.close()
            } catch {
                failed = true
            }
        }
        if failed {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
    }

    private func isActiveAccount(_ did: String) async throws -> Bool {
        do {
            guard let account = try await controlStore.account(did: did) else {
                return false
            }
            return account.status.authorizesAccount
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
    }

    /// Selects an existing startup-opened database for the OAuth subject's
    /// own repository. This is intentionally shared by the two record-read
    /// projections so one path cannot regress into request-time opening or
    /// forget the stale-path defense.
    private func preopenedRepositoryDatabase(
        for did: String,
        authorization: AuthorizationContext
    ) async throws -> SQLiteAccountDatabase? {
        guard !isClosed else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard case let .accountOAuth(subject, _) = authorization,
              subject == did else {
            throw SwanError.unauthorized("account OAuth may read only its own repository")
        }
        guard try await isActiveAccount(did) else { return nil }
        guard !isClosed else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        do {
            try Self.requireExistingRegularDatabase(
                SQLiteLayout.accountDatabase(in: dataDirectory, did: did)
            )
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard let database = databases[did] else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        return database
    }

    private static func validateStartupDIDs(_ dids: [String]) throws {
        var previous: String?
        for did in dids {
            guard AccountControlIdentifiers.isDID(did),
                  previous.map({ $0 < did }) ?? true else {
                throw SwanError.unavailable("authenticated space directory is unavailable")
            }
            previous = did
        }
    }

    private static func requireExistingRegularDatabase(_ url: URL) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let type = attributes[.type] as? FileAttributeType,
              type == .typeRegular,
              !isSymbolicLink(url) else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
    }

    private static func isSymbolicLink(_ url: URL) -> Bool {
        let values = try? url.resourceValues(forKeys: [.isSymbolicLinkKey])
        return values?.isSymbolicLink == true
    }

    private static func closeSilently(
        _ databases: [SQLiteAccountDatabase]
    ) async {
        for database in databases {
            try? await database.close()
        }
    }
}
