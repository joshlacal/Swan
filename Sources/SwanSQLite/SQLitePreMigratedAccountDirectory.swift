import Foundation
import Petrel
import SwanCore
import SwanPublicRepository
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
    AuthorizedSpaceNotificationDirectory,
    AuthorizedHostedSpaceDirectory,
    PublicRepositoryReadDirectory
{
    private let controlStore: any AccountControlStore
    private let publicIdentityVerifier: (any PublicPLCGenesisVerifying)?
    private let publicCARSpoolAdmission: PublicRepositorySpoolAdmission
    private let dataDirectory: URL
    private var databases: [String: SQLiteAccountDatabase]
    private var isClosed = false

    private init(
        dataDirectory: URL,
        controlStore: any AccountControlStore,
        databases: [String: SQLiteAccountDatabase],
        publicIdentityVerifier: (any PublicPLCGenesisVerifying)?,
        publicCARSpoolAdmission: PublicRepositorySpoolAdmission
    ) {
        self.dataDirectory = dataDirectory
        self.controlStore = controlStore
        self.publicIdentityVerifier = publicIdentityVerifier
        self.publicCARSpoolAdmission = publicCARSpoolAdmission
        self.databases = databases
    }

    /// Opens and migrates every currently active account database. A missing,
    /// non-regular, symlinked, corrupt, or unopenable account database makes
    /// startup unavailable; it is never created as a recovery side effect.
    public static func bootstrap(
        dataDirectory: URL,
        controlStore: any AccountControlStore,
        oplogRetention: Int = 10_000,
        publicIdentityVerifier: (any PublicPLCGenesisVerifying)? = nil,
        publicCARSpoolAdmission: PublicRepositorySpoolAdmission? = nil
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
            let admission = try publicCARSpoolAdmission
                ?? PublicRepositorySpoolAdmission()
            return SQLitePreMigratedAccountDirectory(
                dataDirectory: dataDirectory,
                controlStore: controlStore,
                databases: opened,
                publicIdentityVerifier: publicIdentityVerifier,
                publicCARSpoolAdmission: admission
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

    /// Admits one database only after the loopback management activation flow
    /// has opened/migrated it and durably installed an active control row.
    /// Public HTTP paths have no access to this API and retain their strict
    /// preopened-only selection behavior.
    public func admitActivatedAccount(
        _ admission: SQLiteActivatedAccountAdmission
    ) async throws {
        let did = admission.did
        let database = admission.database
        guard !isClosed,
              AccountControlIdentifiers.isDID(did) else {
            try? await database.close()
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        let isActive: Bool
        do {
            isActive = try await isActiveAccount(did)
        } catch {
            try? await database.close()
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard isActive, !isClosed else {
            try? await database.close()
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        do {
            try Self.requireExistingRegularDatabase(
                SQLiteLayout.accountDatabase(in: dataDirectory, did: did)
            )
        } catch {
            try? await database.close()
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard !isClosed else {
            try? await database.close()
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        if databases[did] != nil {
            do {
                try await database.close()
            } catch {
                throw SwanError.unavailable("authenticated space directory is unavailable")
            }
            return
        }
        databases[did] = database
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
        } catch let error as SimpleSpaceCredentialPolicyError {
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
        // The direct writer->authority message is the only notifyWrite shape
        // that this host may apply. Authority->recipient fanout is a delivery
        // hint for a remote synchronizer, not remote operation application;
        // it deliberately succeeds as a no-op here, matching the pinned PDS
        // behavior for a host that does not own the space authority.
        guard notification.audience == notification.space.authority,
              notification.issuer == notification.repository else {
            return
        }
        guard let database = try await preopenedActiveDatabaseIfHosted(
            notification.space.authority
        ) else {
            return
        }
        do {
            try await database.receiveSpaceWriteNotification(notification)
            guard try await isActiveAccount(notification.space.authority), !isClosed else {
                throw SwanError.unavailable("authenticated space directory is unavailable")
            }
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
        // A notification addressed to a PDS that does not host this account
        // is a successful best-effort no-op. Do not create/migrate an account
        // database from an incoming audience claim.
        guard let database = try await preopenedActiveDatabaseIfHosted(audience) else {
            return
        }
        do {
            try await database.receiveSpaceDeletionNotification(
                space: space,
                issuer: issuer,
                audience: audience,
                eventID: eventID
            )
            guard try await isActiveAccount(audience), !isClosed else {
                throw SwanError.unavailable("authenticated space directory is unavailable")
            }
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

    // MARK: Public repository reads

    public func publicRepositoryStatus(
        selector: String
    ) async throws -> PublicRepositoryReadStatus? {
        let account = try await resolvePublicAccount(selector)
        guard let account else { return nil }
        guard !isClosed else {
            throw PublicRepositoryReadError.unavailable
        }
        if account.status != .active {
            return try PublicRepositoryReadStatus(
                did: account.did, status: account.status, revision: nil
            )
        }
        let database = try preopenedPublicRepositoryDatabase(account.did)
        guard let publicIdentityVerifier else {
            throw PublicRepositoryReadError.unavailable
        }
        let description: PublicRepositoryReadDescription
        do {
            description = try await database.readPublicRepositoryDescription(
                account: account,
                identityVerifier: publicIdentityVerifier
            )
            try await verifyPublicIdentityIntent(description)
        } catch {
            throw PublicRepositoryReadError.unavailable
        }
        try await recheckPublicAccount(account)
        return try PublicRepositoryReadStatus(
            did: account.did,
            status: account.status,
            revision: description.state.revision
        )
    }

    public func describePublicRepository(
        selector: String
    ) async throws -> PublicRepositoryReadDescription? {
        guard let account = try await resolvePublicAccount(selector),
              account.status == .active else { return nil }
        let database = try preopenedPublicRepositoryDatabase(account.did)
        guard let publicIdentityVerifier else {
            throw PublicRepositoryReadError.unavailable
        }
        let result: PublicRepositoryReadDescription
        do {
            result = try await database.readPublicRepositoryDescription(
                account: account,
                identityVerifier: publicIdentityVerifier
            )
            try await verifyPublicIdentityIntent(result)
        } catch {
            throw PublicRepositoryReadError.unavailable
        }
        try await recheckPublicAccount(account)
        return result
    }

    private func verifyPublicIdentityIntent(
        _ description: PublicRepositoryReadDescription
    ) async throws {
        guard let intentStore = controlStore
                as? any PLCAccountPreparationIntentStore,
              let intent = try await intentStore.plcAccountPreparationIntent(
                requestID: description.identity.preparationRequestID
              ),
              intent.did == description.did,
              intent.canonicalHandle == description.identity.canonicalHandle,
              intent.pdsOrigin == description.identity.pdsOrigin,
              intent.operationCID == description.identity.genesisOperationCID,
              intent.stage == .submitted else {
            throw PublicRepositoryReadError.unavailable
        }
    }

    public func publicRepositoryRecord(
        selector: String,
        path: PublicRepositoryPath,
        expectedCID: CID?
    ) async throws -> PublicRepositoryReadRecord? {
        guard let account = try await resolvePublicAccount(selector),
              account.status == .active else { return nil }
        let database = try preopenedPublicRepositoryDatabase(account.did)
        let result = try await database.readPublicRepositoryRecord(
            path: path, expectedCID: expectedCID
        )
        try await recheckPublicAccount(account)
        return result
    }

    public func listPublicRepositoryRecords(
        selector: String,
        collection: String,
        limit: Int,
        cursor: String?,
        reverse: Bool
    ) async throws -> PublicRepositoryReadPage {
        guard let account = try await resolvePublicAccount(selector),
              account.status == .active else {
            throw PublicRepositoryReadError.invalidSelector
        }
        let database = try preopenedPublicRepositoryDatabase(account.did)
        let result = try await database.readPublicRepositoryRecords(
            collection: collection,
            limit: limit,
            cursor: cursor,
            reverse: reverse
        )
        try await recheckPublicAccount(account)
        return result
    }

    public func publicRepositoryCAR(
        selector: String
    ) async throws -> PublicRepositoryReadCAR? {
        guard let account = try await resolvePublicAccount(selector),
              account.status == .active else { return nil }
        guard let lease = publicCARSpoolAdmission.reserve(
            accountDID: account.did,
            maximumBytes: PublicRepositoryLimits.standard.maximumCARBytes
        ) else {
            throw PublicRepositoryReadError.unavailable
        }
        let database = try preopenedPublicRepositoryDatabase(account.did)
        let result: PublicRepositoryReadCAR
        do {
            result = try await database.preparePublicRepositoryCAR(lease: lease)
        } catch {
            lease.release()
            throw PublicRepositoryReadError.unavailable
        }
        do {
            try await recheckPublicAccount(account)
            return result
        } catch {
            result.spool.cleanup()
            throw error
        }
    }

    private func resolvePublicAccount(
        _ selector: String
    ) async throws -> AccountControlAccount? {
        guard !isClosed else { throw PublicRepositoryReadError.unavailable }
        let account: AccountControlAccount?
        do {
            if selector.hasPrefix("did:") {
                guard AccountControlIdentifiers.isDID(selector) else {
                    throw PublicRepositoryReadError.invalidSelector
                }
                account = try await controlStore.account(did: selector)
            } else {
                guard AccountControlIdentifiers.isCanonicalHandle(selector) else {
                    throw PublicRepositoryReadError.invalidSelector
                }
                account = try await controlStore.account(
                    canonicalHandle: selector
                )
            }
        } catch let error as PublicRepositoryReadError {
            throw error
        } catch {
            throw PublicRepositoryReadError.unavailable
        }
        guard !isClosed else { throw PublicRepositoryReadError.unavailable }
        return account
    }

    private func preopenedPublicRepositoryDatabase(
        _ did: String
    ) throws -> SQLiteAccountDatabase {
        guard !isClosed else { throw PublicRepositoryReadError.unavailable }
        do {
            try Self.requireExistingRegularDatabase(
                SQLiteLayout.accountDatabase(in: dataDirectory, did: did)
            )
        } catch {
            throw PublicRepositoryReadError.unavailable
        }
        guard let database = databases[did] else {
            throw PublicRepositoryReadError.unavailable
        }
        return database
    }

    private func recheckPublicAccount(
        _ expected: AccountControlAccount
    ) async throws {
        guard !isClosed, databases[expected.did] != nil else {
            throw PublicRepositoryReadError.unavailable
        }
        let current: AccountControlAccount?
        do {
            current = try await controlStore.account(did: expected.did)
        } catch {
            throw PublicRepositoryReadError.unavailable
        }
        guard let current,
              current.did == expected.did,
              current.canonicalHandle == expected.canonicalHandle,
              current.status == .active else {
            throw PublicRepositoryReadError.unavailable
        }
        guard !isClosed, databases[expected.did] != nil else {
            throw PublicRepositoryReadError.unavailable
        }
        do {
            try Self.requireExistingRegularDatabase(
                SQLiteLayout.accountDatabase(
                    in: dataDirectory, did: expected.did
                )
            )
        } catch {
            throw PublicRepositoryReadError.unavailable
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

    /// Lists only canonical local hosted-space identities for the authenticated
    /// subject. The directory repeats the active/startup-preopened/path checks
    /// used by request-time repository projections, so a stale account path
    /// can never become authority to reopen or migrate SQLite.
    public func hostedSpaces(
        _ query: AuthorizedHostedSpaceListQuery,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedHostedSpacePage {
        guard (1 ... 100).contains(query.limit),
              case let .accountOAuth(subject, _) = authorization,
              subject == query.subject else {
            throw SwanError.unauthorized("account OAuth is required for hosted-space listing")
        }
        guard let database = try await preopenedRepositoryDatabase(
            for: query.subject,
            authorization: authorization
        ) else {
            throw SwanError.unauthorized("account repository is unavailable")
        }
        do {
            let spaces = try await database.hostedSpaceURIs(
                spaceType: query.spaceType,
                authority: query.authority,
                cursor: query.cursor,
                limit: query.limit
            )
            guard try await isActiveAccount(query.subject) else {
                throw SwanError.unauthorized("account repository is unavailable")
            }
            guard !isClosed else {
                throw SwanError.unavailable("authenticated space directory is unavailable")
            }
            let projected = spaces.map {
                AuthorizedHostedSpace(
                    space: $0,
                    isOwner: $0.authority == query.subject
                )
            }
            return AuthorizedHostedSpacePage(
                spaces: projected,
                cursor: projected.last?.space
            )
        } catch let error as SwanError {
            throw error
        } catch {
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

    /// Returns an existing active account database for a best-effort service
    /// delivery target. Unlike request authorization helpers, absence is not
    /// an error: the signed audience may name an account hosted by another
    /// PDS. This method never opens, creates, or migrates a database.
    private func preopenedActiveDatabaseIfHosted(
        _ did: String
    ) async throws -> SQLiteAccountDatabase? {
        guard !isClosed else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard try await isActiveAccount(did) else { return nil }
        do {
            try Self.requireExistingRegularDatabase(
                SQLiteLayout.accountDatabase(in: dataDirectory, did: did)
            )
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard !isClosed else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        return databases[did]
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
