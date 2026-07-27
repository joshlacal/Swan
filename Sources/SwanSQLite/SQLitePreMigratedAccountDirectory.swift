import Foundation
import SwanCore
import SwanSpaces
import SwanStorage

/// A startup-owned directory of account databases that were opened and
/// migrated before the service accepted traffic. It intentionally has no
/// fallback construction path: a request can select only a database that was
/// successfully preopened for an active account at bootstrap.
public actor SQLitePreMigratedAccountDirectory: AuthorizedSimpleSpaceDirectory {
    private let controlStore: any AccountControlStore
    private var databases: [String: SQLiteAccountDatabase]
    private var isClosed = false

    private init(
        controlStore: any AccountControlStore,
        databases: [String: SQLiteAccountDatabase]
    ) {
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
