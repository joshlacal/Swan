import Foundation
import Petrel
import SwanCore
import SwanSpaces
import SwanStorage

/// A startup-owned directory of account databases that were opened and
/// migrated before the service accepted traffic. It intentionally has no
/// fallback construction path: a request can select only a database that was
/// successfully preopened for an active account at bootstrap.
public actor SQLitePreMigratedAccountDirectory:
    AuthorizedSimpleSpaceDirectory,
    AuthorizedPreopenedAccountDirectory,
    AuthorizedSimpleSpaceLifecycleDirectory,
    AuthorizedSimpleSpaceCredentialDirectory,
    AuthorizedSpaceRepositoryDirectory,
    AuthorizedSpaceBlobDirectory,
    AuthorizedSpaceNotificationDirectory
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

    /// Returns the currently active, startup-preopened account databases for
    /// the notification recovery service. This is intentionally a lifecycle
    /// API, not an HTTP lookup: it neither accepts a request-selected DID nor
    /// opens, creates, or migrates a database after startup.
    public func notificationRecoveryDatabases() async throws -> [SQLiteAccountDatabase] {
        guard !isClosed else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        var active: [SQLiteAccountDatabase] = []
        for did in databases.keys.sorted() {
            guard try await isActiveAccount(did) else { continue }
            do {
                try Self.requireExistingRegularDatabase(
                    SQLiteLayout.accountDatabase(in: dataDirectory, did: did)
                )
            } catch {
                throw SwanError.unavailable("authenticated space directory is unavailable")
            }
            guard !isClosed, let database = databases[did] else {
                throw SwanError.unavailable("authenticated space directory is unavailable")
            }
            active.append(database)
        }
        return active
    }

    // MARK: Authenticated simple-space lifecycle

    /// Every lifecycle operation selects only the authority's preopened
    /// database and delegates the exact operation to
    /// `DurableSimpleSpaceAuthority`. The facade keeps scope matching in the
    /// domain/storage layer, rather than treating a successful DPoP proof as
    /// a generic management boolean.
    public func createSimpleSpace(
        _ space: SpaceURI,
        configuration: SimpleSpaceConfiguration,
        authorization: AuthorizationContext
    ) async throws {
        let authority = try await lifecycleAuthority(
            for: space,
            authorization: authorization
        )
        _ = try await authority.create(
            space: space,
            owner: space.authority,
            configuration: configuration,
            authorization: authorization
        )
        try await requireLifecycleAuthorityStillAvailable(space.authority)
    }

    public func updateSimpleSpace(
        _ space: SpaceURI,
        patch: SimpleSpaceConfigurationPatch,
        authorization: AuthorizationContext
    ) async throws {
        let authority = try await lifecycleAuthority(
            for: space,
            authorization: authorization
        )
        _ = try await authority.update(
            space: space,
            patch: patch,
            authorization: authorization
        )
        try await requireLifecycleAuthorityStillAvailable(space.authority)
    }

    public func deleteSimpleSpace(
        _ space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws {
        let authority = try await lifecycleAuthority(
            for: space,
            authorization: authorization
        )
        _ = try await authority.delete(space: space, authorization: authorization)
        try await requireLifecycleAuthorityStillAvailable(space.authority)
    }

    public func addSimpleSpaceMember(
        _ member: String,
        to space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws {
        let authority = try await lifecycleAuthority(
            for: space,
            authorization: authorization
        )
        _ = try await authority.addMember(
            space: space,
            member: member,
            authorization: authorization
        )
        try await requireLifecycleAuthorityStillAvailable(space.authority)
    }

    public func removeSimpleSpaceMember(
        _ member: String,
        from space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws {
        let authority = try await lifecycleAuthority(
            for: space,
            authorization: authorization
        )
        _ = try await authority.removeMember(
            space: space,
            member: member,
            authorization: authorization
        )
        try await requireLifecycleAuthorityStillAvailable(space.authority)
    }

    public func simpleSpaceMembers(
        _ space: SpaceURI,
        limit: Int,
        cursor: String?,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSimpleSpaceMemberPage {
        guard (1 ... 1_000).contains(limit) else {
            throw SwanError.malformed("invalid member page limit")
        }
        let authority = try await lifecycleAuthority(
            for: space,
            authorization: authorization
        )
        guard let state = try await authority.space(space, authorization: authorization),
              !state.space.isDeleted else {
            throw AuthorizedSimpleSpaceLifecycleError.notFound
        }
        let members = state.space.members.sorted()
        let selected: [String]
        if let cursor {
            selected = Array(members.lazy.filter { $0 > cursor }.prefix(limit))
        } else {
            selected = Array(members.prefix(limit))
        }
        try await requireLifecycleAuthorityStillAvailable(space.authority)
        return AuthorizedSimpleSpaceMemberPage(
            members: selected,
            cursor: selected.last
        )
    }

    // MARK: Authority credential policy

    /// Runs the authority's durable user/app policy only against the
    /// authority database that was opened during startup. This method cannot
    /// obtain an account key or create a credential; those capabilities live
    /// in SwanOAuth and are intentionally sequenced *after* this read-only
    /// policy transaction commits.
    public func authorizeSimpleSpaceCredentialRead(
        space: SpaceURI,
        user: String,
        clientID: String?,
        authorization: AuthorizationContext
    ) async throws {
        let database = try await preopenedCredentialAuthorityDatabase(for: space)
        do {
            try await database.authorizeSimpleSpaceRead(
                space: space,
                user: user,
                clientID: clientID,
                authorization: authorization
            )
            try await requireCredentialAuthorityStillAvailable(space.authority)
        } catch let error as SwanError {
            throw error
        } catch let error as AuthorizedSimpleSpaceLifecycleError {
            throw error
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
    }

    // MARK: Authority writer discovery and notifications

    public func listSpaceWriters(
        space: SpaceURI,
        limit: Int,
        cursor: String?,
        authorization: AuthorizationContext
    ) async throws -> [AuthorizedSpaceWriter] {
        let database = try await preopenedCredentialAuthorityDatabase(for: space)
        do {
            let writers = try await database.spaceWriters(
                space: space,
                limit: limit,
                cursor: cursor,
                authorization: authorization
            )
            try await requireCredentialAuthorityStillAvailable(space.authority)
            return writers
        } catch let error as SwanError {
            throw error
        } catch let error as AuthorizedSimpleSpaceLifecycleError {
            throw error
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
    }

    public func registerSpaceNotification(
        _ registration: AuthorizedSpaceNotificationRegistration,
        authorization: AuthorizationContext
    ) async throws {
        let database = try await preopenedCredentialAuthorityDatabase(
            for: registration.space
        )
        do {
            try await database.registerSpaceNotification(
                registration,
                authorization: authorization
            )
            try await requireCredentialAuthorityStillAvailable(
                registration.space.authority
            )
        } catch let error as SwanError {
            throw error
        } catch let error as AuthorizedSimpleSpaceLifecycleError {
            throw error
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
    }

    public func receiveSpaceWriteNotification(
        _ notification: AuthorizedSpaceWriteNotification
    ) async throws {
        let database = try await preopenedCredentialAuthorityDatabase(
            for: notification.space
        )
        do {
            try await database.receiveSpaceWriteNotification(notification)
            try await requireCredentialAuthorityStillAvailable(
                notification.space.authority
            )
        } catch let error as SwanError {
            throw error
        } catch let error as AuthorizedSimpleSpaceLifecycleError {
            throw error
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
    }

    public func receiveSpaceDeletionNotification(
        space: SpaceURI,
        issuer: String,
        audience: String,
        eventID: String
    ) async throws {
        let database = try await preopenedServiceRecipientDatabase(for: audience)
        do {
            try await database.receiveSpaceDeletionNotification(
                space: space,
                issuer: issuer,
                audience: audience,
                eventID: eventID
            )
            try await requireLifecycleAuthorityStillAvailable(audience)
        } catch let error as SwanError {
            throw error
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
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

    /// Reads only the durable state facts required to create a fresh signed
    /// commit.  The selected database was opened at startup; neither this
    /// projection nor its signer has a request-time SQLite construction path.
    public func repositoryCommitState(
        space: SpaceURI,
        author: String,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceRepositoryCommitState {
        let database = try await preopenedRepositoryDatabase(
            for: author,
            authorization: authorization
        )
        guard let database else {
            throw SwanError.unauthorized("account repository is unavailable")
        }
        do {
            let repository = try DurableSpaceRepository(
                database: database,
                space: space,
                author: author
            )
            let state = try await repository.currentCommitState(
                authorization: authorization
            )
            guard state.space == space, state.author == author,
                  try await isActiveAccount(author) else {
                throw SwanError.unauthorized("account repository is unavailable")
            }
            guard !isClosed else {
                throw SwanError.unavailable("authenticated space directory is unavailable")
            }
            return state
        } catch let error as SwanError {
            throw error
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
    }

    /// Reads one strictly bounded, ordered permissioned oplog page through a
    /// startup-preopened account database.  A recovery gap remains a distinct
    /// domain result; no snapshot or historic record value becomes available
    /// through this incremental-read adapter.
    public func repositoryOplog(
        space: SpaceURI,
        author: String,
        since: String?,
        limit: Int,
        includeValues: Bool,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceRepositoryOplogRead {
        let database = try await preopenedRepositoryDatabase(
            for: author,
            authorization: authorization
        )
        guard let database else {
            throw SwanError.unauthorized("account repository is unavailable")
        }
        do {
            let cursor = try since.map { try TID(tidString: $0) }
            let repository = try DurableSpaceRepository(
                database: database,
                space: space,
                author: author
            )
            let result = try await repository.incrementalOplog(
                since: cursor,
                limit: limit,
                includeValues: includeValues,
                authorization: authorization
            )
            if case let .incremental(state, entries) = result {
                guard state.space == space, state.author == author,
                      entries.allSatisfy({
                          $0.collection.utf8.count > 0 && $0.rkey.utf8.count > 0
                      }),
                      try await isActiveAccount(author) else {
                    throw SwanError.unauthorized("account repository is unavailable")
                }
            } else {
                guard try await isActiveAccount(author) else {
                    throw SwanError.unauthorized("account repository is unavailable")
                }
            }
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

    /// Creates the bounded-memory full-recovery spool only through a database
    /// that was opened at startup. The durable repository applies aggregate
    /// read policy before it can read any record, and this facade rechecks
    /// account lifecycle/path validity before returning the opaque spool.
    public func repositoryCARSnapshot(
        space: SpaceURI,
        author: String,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceRepositoryCARSnapshot? {
        let database = try await preopenedRepositoryDatabase(
            for: author,
            authorization: authorization
        )
        guard let database else {
            throw SwanError.unauthorized("account repository is unavailable")
        }
        do {
            let repository = try DurableSpaceRepository(
                database: database,
                space: space,
                author: author
            )
            let snapshot = try await repository.prepareCARSnapshot(
                authorization: authorization
            )
            guard try await isActiveAccount(author) else {
                snapshot?.spool.cleanup()
                throw SwanError.unauthorized("account repository is unavailable")
            }
            guard !isClosed else {
                snapshot?.spool.cleanup()
                throw SwanError.unavailable("authenticated space directory is unavailable")
            }
            return snapshot
        } catch let error as SwanError {
            throw error
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
    }

    /// Returns a descriptor-backed private blob only from the startup-opened
    /// account inventory.  The repository facade applies aggregate read
    /// authorization before SQLite can inspect namespace metadata, and this
    /// coordinator rechecks lifecycle/closure before the opaque body reaches
    /// HTTP.  It deliberately has no database-open or public-blob fallback.
    public func spaceBlob(
        space: SpaceURI,
        author: String,
        cid: String,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceBlob? {
        let database = try await preopenedRepositoryDatabase(
            for: author,
            authorization: authorization
        )
        guard let database else {
            throw SwanError.unauthorized("account repository is unavailable")
        }
        do {
            let repository = try DurableSpaceRepository(
                database: database,
                space: space,
                author: author
            )
            let blob = try await repository.permissionedBlob(
                cid: cid,
                authorization: authorization
            )
            guard try await isActiveAccount(author) else {
                throw SwanError.unauthorized("account repository is unavailable")
            }
            guard !isClosed else {
                throw SwanError.unavailable("authenticated space directory is unavailable")
            }
            return blob
        } catch let error as SwanError {
            throw error
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
    }

    /// Writes only through a database that was opened and migrated before the
    /// listener accepted traffic. The actor rechecks lifecycle, terminal
    /// shutdown, and the resolved database path around the durable operation;
    /// it deliberately has no construction or migration fallback.
    public func apply(
        space: SpaceURI,
        author: String,
        writes: [AuthorizedSpaceRepositoryWrite],
        requestID: UUID,
        wireRevision: String,
        authorization: AuthorizationContext
    ) async throws -> [AuthorizedSpaceRepositoryWriteResult] {
        let database = try await preopenedRepositoryDatabase(
            for: author,
            authorization: authorization
        )
        guard let database else {
            throw SwanError.unauthorized("account repository is unavailable")
        }
        do {
            let repository = try DurableSpaceRepository(
                database: database,
                space: space,
                author: author
            )
            let result = try await repository.applyAuthorizedWrites(
                writes,
                requestID: requestID,
                wireRevision: try TID(tidString: wireRevision),
                authorization: authorization
            )
            guard try await isActiveAccount(author) else {
                throw SwanError.unauthorized("account repository is unavailable")
            }
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

    /// Checks only the active/startup-preopened account inventory.  This is
    /// intentionally not a repository or simple-space lookup: a user PDS can
    /// mint a delegation for an authority it does not control, and the remote
    /// authority alone decides membership and policy during exchange.
    public func requireActivePreopenedAccount(_ did: String) async throws {
        guard !isClosed else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard try await isActiveAccount(did) else {
            throw SwanError.unauthorized("account is unavailable")
        }
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
        guard databases[did] != nil else {
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

    /// Selects an existing startup-opened database for an OAuth subject's own
    /// repository or for a verified space credential. This is intentionally
    /// shared by the two record-read projections so one path cannot regress
    /// into request-time opening or forget the stale-path defense. The domain
    /// repository still receives the exact context and enforces the requested
    /// space before it returns any record material.
    private func preopenedRepositoryDatabase(
        for did: String,
        authorization: AuthorizationContext
    ) async throws -> SQLiteAccountDatabase? {
        guard !isClosed else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        switch authorization {
        case let .accountOAuth(subject, _) where subject == did:
            break
        case .spaceCredential:
            break
        default:
            throw SwanError.unauthorized("authorization may not read this repository")
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

    /// Returns a lifecycle-only authority facade over an account database that
    /// was opened before the listener accepted traffic. The facade has no
    /// credential secret, so it cannot accidentally become a credential
    /// minting capability while serving lifecycle requests.
    private func lifecycleAuthority(
        for space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws -> DurableSimpleSpaceAuthority {
        let database = try await preopenedAuthorityDatabase(
            for: space,
            authorization: authorization
        )
        return DurableSimpleSpaceAuthority(lifecycleDatabase: database)
    }

    /// Authority lifecycle operations may select only the exact active
    /// authority account. This repeats the stale path, lifecycle, and closure
    /// checks around every request and deliberately has no SQLite open or
    /// migration fallback.
    private func preopenedAuthorityDatabase(
        for space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws -> SQLiteAccountDatabase {
        guard !isClosed else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard case let .accountOAuth(subject, _) = authorization,
              subject == space.authority else {
            throw SwanError.unauthorized("authority account OAuth is required")
        }
        guard try await isActiveAccount(space.authority) else {
            throw SwanError.unauthorized("authority account is unavailable")
        }
        guard !isClosed else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        do {
            try Self.requireExistingRegularDatabase(
                SQLiteLayout.accountDatabase(in: dataDirectory, did: space.authority)
            )
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard let database = databases[space.authority] else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        return database
    }

    /// Selects the authority account independently of the requesting user.
    /// Unlike lifecycle endpoints, credential issuance is normally requested
    /// by a reader account, so requiring that reader to equal the authority
    /// would both reject valid membership checks and tempt handlers to bypass
    /// this preopened-directory boundary. The durable SQLite method performs
    /// the separate requester-equals-user check before policy evaluation.
    private func preopenedCredentialAuthorityDatabase(
        for space: SpaceURI
    ) async throws -> SQLiteAccountDatabase {
        guard !isClosed else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard try await isActiveAccount(space.authority) else {
            throw SwanError.unauthorized("authority account is unavailable")
        }
        do {
            try Self.requireExistingRegularDatabase(
                SQLiteLayout.accountDatabase(in: dataDirectory, did: space.authority)
            )
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard !isClosed, let database = databases[space.authority] else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        return database
    }

    /// Service notifications select their recipient from the signed `aud`
    /// claim only after the service-JWT verifier has bound it to this route.
    /// This retains the same active/preopened/path checks as every other
    /// account database projection and never constructs remote-space state.
    private func preopenedServiceRecipientDatabase(
        for did: String
    ) async throws -> SQLiteAccountDatabase {
        guard !isClosed,
              try await isActiveAccount(did) else {
            throw SwanError.unauthorized("service notification recipient is unavailable")
        }
        do {
            try Self.requireExistingRegularDatabase(
                SQLiteLayout.accountDatabase(in: dataDirectory, did: did)
            )
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard !isClosed, let database = databases[did] else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        return database
    }

    private func requireLifecycleAuthorityStillAvailable(_ did: String) async throws {
        guard try await isActiveAccount(did), !isClosed else {
            throw SwanError.unauthorized("authority account is unavailable")
        }
        do {
            try Self.requireExistingRegularDatabase(
                SQLiteLayout.accountDatabase(in: dataDirectory, did: did)
            )
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
    }

    private func requireCredentialAuthorityStillAvailable(_ did: String) async throws {
        guard try await isActiveAccount(did), !isClosed else {
            throw SwanError.unauthorized("authority account is unavailable")
        }
        do {
            try Self.requireExistingRegularDatabase(
                SQLiteLayout.accountDatabase(in: dataDirectory, did: did)
            )
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
