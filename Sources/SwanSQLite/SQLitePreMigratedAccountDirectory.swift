import Foundation
import Petrel
import SwanCore
import PetrelRepo
import SwanSpaces
import SwanStorage

/// Server-side diagnostics for the unauthenticated public read path. Stable
/// identifiers only — never payloads, credentials, or repository content.
private let publicReadDiagnosticLog = SwanLog(label: "swan.public-read")

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
    PublicRepositoryReadDirectory,
    PublicFirehoseAccountDatabaseSource
{
    private let controlStore: any AccountControlStore
    private let publicIdentityVerifier: (any PublicPLCGenesisVerifying)?
    /// Shared process-wide/per-account disk admission for every public
    /// descriptor-backed transfer, including CAR reads and public blob
    /// uploads.  The value is immutable after bootstrap so HTTP capabilities
    /// cannot accidentally construct a second, uncoordinated budget.
    public nonisolated let publicRepositorySpoolAdmission: PublicRepositorySpoolAdmission
    private let dataDirectory: URL
    private var databases: [String: SQLiteAccountDatabase]
    private var publicReadGenerations:
        [String: SQLiteVerifiedPublicRepositoryGeneration]
    /// How many times this DID's cached public-read generation has been
    /// invalidated: once per publish, once per eviction, and once per durable
    /// repository commit. Monotonic per DID and never reset.
    ///
    /// A generation carries only a `UUID`, so two generations cannot be
    /// ordered against each other and "is what I computed still the newest
    /// snapshot anybody has seen?" has no answer from the generation alone.
    /// This counter is that answer. Every admission samples it before it looks
    /// at the database and re-reads it in the same actor turn that publishes;
    /// a value that moved in between means some other publisher, evictor, or
    /// commit invalidated the snapshot this admission was computed against, and
    /// the admission discards its result rather than installing it. See
    /// ``refreshPublicReadGeneration(account:database:)``.
    ///
    /// Per DID rather than directory-wide on purpose: a publish for one
    /// account must not cost every other account's in-flight admission its
    /// publish. Keyed by DIDs that are already active and startup-preopened,
    /// so it is bounded by hosted accounts rather than by anonymous input —
    /// the same bound ``publicReadReadmissionFailures`` argues for itself.
    private var publicReadGenerationPublishSequence: [String: UInt64] = [:]
    /// One single-holder gate per `(account, space)` repository, live only
    /// while a batch holds or waits for it. Concurrent permissioned batches
    /// for one repository serialize here, so each stages against the revision
    /// its predecessor committed and the revision CAS has nothing to reject —
    /// the ordering `testConcurrentHTTPWritesAllCommitInATotalOrderUnderThe
    /// AuthorizationFence` pins, and the ordering the pinned reference PDS
    /// gets from its per-actor write lock.
    ///
    /// This used to fall out of holding the process-wide control-plane write
    /// transaction across the whole batch, which bought the ordering at the
    /// price of blocking OAuth and account-lifecycle traffic behind every
    /// repository write. The ordering is an account-local property and now
    /// costs the control plane nothing.
    ///
    /// Lock order is repository lease → control gate → account connection
    /// gate. Nothing acquires a repository lease while holding the control
    /// gate, so the added edge closes no cycle; keep it that way.
    private var repositoryWriteGates: [String: RepositoryWriteGateEntry] = [:]
    private var permanentlyRevokedDIDs: Set<String> = []
    private var drainingDatabases: [String: SQLiteAccountDatabase] = [:]
    /// At most one in-flight public-read re-admission per DID. A foreign
    /// commit invalidates one account's generation pin for every concurrent
    /// reader at the same instant, so without this every one of them would
    /// run its own full admission against the single SQLite connection they
    /// all share. See ``readmitPublicReadGeneration(account:database:replacing:)``.
    private var publicReadReadmissions:
        [String: Task<SQLiteVerifiedPublicRepositoryGeneration, any Error>] = [:]
    /// Why, and until when, re-admission of one DID is not worth re-running.
    /// See ``recordPublicReadReadmissionFailure(did:error:)``.
    private struct PublicReadReadmissionFailure {
        let reason: PublicReadUnavailableReason
        let expiresAt: ContinuousClock.Instant
        /// Reads this entry refused without re-running the admission. Counted
        /// rather than journalled per request; see
        /// ``retirePublicReadReadmissionFailure(did:)``.
        var suppressedReads = 0
    }

    private var publicReadReadmissionFailures:
        [String: PublicReadReadmissionFailure] = [:]
    /// Test seam: how many public-read admission lines this directory has
    /// written to the service journal. Incremented at the two sites that emit
    /// one and nowhere else, so a test can assert that journal volume tracks
    /// distinct admission failures rather than inbound request rate. Never
    /// consulted by production code.
    private var publicReadAdmissionJournalLines = 0
    private var isClosed = false

    /// How long a failed re-admission suppresses the next one for that DID.
    ///
    /// Flat, and deliberately short. The window exists to stop an
    /// unadmittable account from paying a full admission — a record-index
    /// walk of up to 100k entries, an MST projection verify, and PLC
    /// verification — on every anonymous public read. It must never become a
    /// second way for an account to stay dark: a growing or long backoff would
    /// reintroduce the 2026-08-12 outage in a slower form, so the worst-case
    /// added recovery delay is a constant a quarter-second rather than
    /// something that compounds with the number of failures.
    ///
    /// A quarter-second caps wasted admissions at four per second per DID no
    /// matter how much anonymous traffic arrives — the same order as a healthy
    /// account's own control-row churn — while staying far below any client's
    /// or relay's retry interval. Recovery that has an event to hang off does
    /// not wait even that long: every publisher of a generation clears the
    /// entry outright.
    private static let publicReadReadmissionBackoff = Duration.milliseconds(250)

    /// Defence in depth on the negative cache's key space. Only DIDs that are
    /// already active and startup-preopened can reach it — an unknown DID is
    /// refused by `activePublicReadContext` long before — so this is bounded
    /// by hosted accounts, not by anonymous input. The cap makes that true by
    /// construction rather than by argument.
    private static let maximumPublicReadReadmissionFailures = 4_096

    /// Returns only a startup-preopened public mutation store. HTTP adapters
    /// must still bind the selector to the OAuth subject and lifecycle status;
    /// this method never opens a database on demand.
    public func preopenedPublicMutationStore(did: String) async -> (any PublicRepositoryMutationStore)? {
        guard !isClosed else { return nil }
        return databases[did]
    }

    /// Runtime mutation surface. Every commit made through this store runs a
    /// post-commit republication step before the response is returned, so the
    /// read directory is never left pinned to the pre-mutation state.
    ///
    /// That step publishes rather than blocks. It is **not** a precondition of
    /// the response: the commit is already durable by the time it runs, so
    /// when the new state cannot be re-admitted the store evicts the cached
    /// generation instead of failing a write that succeeded, and the next
    /// public read admits from cold. A successful commit is therefore returned
    /// to HTTP either with the new generation published or with no generation
    /// cached — never with the old one still answering reads. See
    /// ``refreshPublicReadGenerationAfterMutation(did:database:)``.
    public func generationRefreshingPublicMutationStore(
        did: String,
        firehoseFence: PublicFirehoseCommitFence? = nil
    ) async -> (any PublicRepositoryMutationStore)? {
        guard !isClosed, let database = databases[did] else { return nil }
        return SQLiteGenerationRefreshingPublicMutationStore(
            did: did,
            database: database,
            directory: self,
            firehoseFence: firehoseFence
        )
    }

    private init(
        dataDirectory: URL,
        controlStore: any AccountControlStore,
        databases: [String: SQLiteAccountDatabase],
        publicReadGenerations:
            [String: SQLiteVerifiedPublicRepositoryGeneration],
        publicIdentityVerifier: (any PublicPLCGenesisVerifying)?,
        publicCARSpoolAdmission: PublicRepositorySpoolAdmission
    ) {
        self.dataDirectory = dataDirectory
        self.controlStore = controlStore
        self.publicIdentityVerifier = publicIdentityVerifier
        self.publicRepositorySpoolAdmission = publicCARSpoolAdmission
        self.databases = databases
        self.publicReadGenerations = publicReadGenerations
    }

    /// Opens and migrates every currently active account database. A missing,
    /// non-regular, symlinked, corrupt, or unopenable account database makes
    /// startup unavailable; it is never created as a recovery side effect.
    ///
    /// `publicIdentityVerifier: nil` is an explicit internal/test mode that
    /// disables public repository admission. Production passes a verifier and
    /// therefore requires every active account to carry both authenticated PLC
    /// genesis facts and a valid empty or non-empty public repository.
    public static func bootstrap(
        dataDirectory: URL,
        controlStore: any AccountControlStore,
        oplogRetention: Int = 10_000,
        publicIdentityVerifier: (any PublicPLCGenesisVerifying)?,
        publicCARSpoolAdmission: PublicRepositorySpoolAdmission? = nil
    ) async throws -> SQLitePreMigratedAccountDirectory {
        guard oplogRetention > 0 else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }

        var opened: [String: SQLiteAccountDatabase] = [:]
        var admittedPublicReads:
            [String: SQLiteVerifiedPublicRepositoryGeneration] = [:]
        do {
            let dids = try await controlStore.activeAccountDIDs()
            try validateStartupDIDs(dids)
            for did in dids {
                let databaseURL = SQLiteLayout.accountDatabase(in: dataDirectory, did: did)
                try requireExistingRegularDatabase(databaseURL)
                let database = try await SQLiteAccountDatabase(
                    dataDirectory: dataDirectory,
                    did: did,
                    oplogRetention: oplogRetention
                )
                do {
                    guard let account = try await controlStore.account(did: did),
                          account.did == did,
                          account.status.authorizesAccount else {
                        throw SwanError.unavailable(
                            "authenticated space directory is unavailable"
                        )
                    }
                    let publicGeneration =
                        try await validatePublicRepositoryAdmission(
                        database: database,
                        account: account,
                        identityVerifier: publicIdentityVerifier,
                        controlStore: controlStore
                    )
                    guard let current = try await controlStore.account(did: did),
                          current == account,
                          current.status.authorizesAccount else {
                        throw SwanError.unavailable(
                            "authenticated space directory is unavailable"
                        )
                    }
                    try requireExistingRegularDatabase(databaseURL)
                    opened[did] = database
                    admittedPublicReads[did] = publicGeneration
                } catch {
                    try? await database.close()
                    throw error
                }
            }
            let admission = try publicCARSpoolAdmission
                ?? PublicRepositorySpoolAdmission()
            return SQLitePreMigratedAccountDirectory(
                dataDirectory: dataDirectory,
                controlStore: controlStore,
                databases: opened,
                publicReadGenerations: admittedPublicReads,
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
        // The live `simplespace.getSpace` contract: the authority's own OAuth
        // session (read_self scope, with the ambient `atproto` bypass), or a
        // space credential bound to exactly this space. The durable policy in
        // `simpleSpace` re-evaluates the same predicate inside the read
        // transaction; this early check keeps a foreign principal from
        // observing account-lifecycle timing below.
        try SpaceAuthorizationPolicy.requireSpaceDescriptionRead(
            space: space,
            authorization: authorization
        )

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

    /// Fresh snapshot of every currently managed account database, sorted by
    /// DID. Unlike `notificationRecoveryDatabases`, there is no active-status
    /// filter: public commits written before deactivation must still drain.
    /// This method never opens, creates, or migrates a database.
    public func publicFirehoseAccountDatabases()
        async throws -> [PublicFirehoseAccountDatabase]
    {
        guard !isClosed else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        return databases.keys.sorted().map { did in
            PublicFirehoseAccountDatabase(
                did: did,
                database: databases[did]!
            )
        }
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
              !permanentlyRevokedDIDs.contains(did),
              AccountControlIdentifiers.isDID(did),
              database.accountDID == did,
              database.dataDirectory.standardizedFileURL
                == dataDirectory.standardizedFileURL else {
            try? await database.close()
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        if let installed = databases[did] {
            // The activation transfer is intentionally opaque and single-use,
            // but a retry can still replay the same value after a lost
            // response. Never close the actor already owned by this directory.
            if installed === database {
                return
            }
            try? await database.close()
            guard !isClosed,
                  !permanentlyRevokedDIDs.contains(did),
                  databases[did] === installed else {
                throw SwanError.unavailable(
                    "authenticated space directory is unavailable"
                )
            }
            return
        }
        let account: AccountControlAccount
        do {
            guard let current = try await controlStore.account(did: did),
                  current.did == did,
                  current.status.authorizesAccount else {
                throw SwanError.unavailable(
                    "authenticated space directory is unavailable"
                )
            }
            account = current
        } catch {
            try? await database.close()
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard !isClosed else {
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
        let publicGeneration: SQLiteVerifiedPublicRepositoryGeneration?
        do {
            publicGeneration =
                try await Self.validatePublicRepositoryAdmission(
                database: database,
                account: account,
                identityVerifier: publicIdentityVerifier,
                controlStore: controlStore
                )
        } catch {
            try? await database.close()
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        let current: AccountControlAccount
        do {
            guard let rechecked = try await controlStore.account(did: did),
                  rechecked == account,
                  rechecked.status.authorizesAccount else {
                throw SwanError.unavailable(
                    "authenticated space directory is unavailable"
                )
            }
            current = rechecked
        } catch {
            try? await database.close()
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        guard current.status.authorizesAccount, !isClosed else {
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
        // Every validation above suspends this actor. Permanent deletion or a
        // competing activation may therefore have won while this admission was
        // awaiting durable state. Recheck terminal revocation and occupancy in
        // one non-suspending actor turn before publishing the transferred
        // database and its read generation.
        guard !permanentlyRevokedDIDs.contains(did) else {
            try? await database.close()
            throw SwanError.unavailable(
                "authenticated space directory is unavailable"
            )
        }
        if let installed = databases[did] {
            if installed === database {
                return
            }
            try? await database.close()
            guard !isClosed,
                  !permanentlyRevokedDIDs.contains(did),
                  databases[did] === installed else {
                throw SwanError.unavailable(
                    "authenticated space directory is unavailable"
                )
            }
            return
        }
        databases[did] = database
        // Both arms move the publish sequence: installing a transferred
        // database replaces this DID's read answer just as a refresh does, and
        // an admission still in flight against the pre-transfer database must
        // not be allowed to publish over it.
        if let publicGeneration {
            publishPublicReadGeneration(publicGeneration, did: did)
        } else {
            evictPublicReadGeneration(did: did)
        }
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

    public func putSimpleSpaceMember(
        _ member: String,
        read: Bool,
        write: Bool,
        in space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws {
        let authority = try await lifecycleAuthority(
            for: space,
            authorization: authorization
        )
        _ = try await authority.putMember(
            space: space,
            member: member,
            read: read,
            write: write,
            authorization: authorization
        )
        try await requireLifecycleAuthorityStillAvailable(space.authority)
    }

    public func addSimpleSpaceMember(
        _ member: String,
        to space: SpaceURI,
        authorization: AuthorizationContext
    ) async throws {
        try await putSimpleSpaceMember(
            member,
            read: true,
            write: true,
            in: space,
            authorization: authorization
        )
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
        let page = try await authority.memberPage(
            space: space,
            limit: limit,
            cursor: cursor,
            authorization: authorization
        )
        try await requireLifecycleAuthorityStillAvailable(space.authority)
        return page
    }

    // MARK: Authority credential policy

    /// Runs the authority's durable user/app policy only against the
    /// authority database that was opened during startup. This method cannot
    /// obtain an account key or create a credential; those capabilities live
    /// in SwanOAuth and are intentionally sequenced *after* this read-only
    /// policy transaction commits.
    public func authorizeSimpleSpaceCredentialRead(
        space: SpaceURI,
        user: String?,
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

    public func unregisterSpaceNotification(
        space: SpaceURI,
        ownerServiceDID: String,
        deliveryServiceDID: String?,
        authorization: AuthorizationContext
    ) async throws {
        let database = try await preopenedCredentialAuthorityDatabase(for: space)
        do {
            try await database.unregisterSpaceNotification(
                space: space,
                ownerServiceDID: ownerServiceDID,
                deliveryServiceDID: deliveryServiceDID,
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

    public func unregisterSpaceNotification(
        space: SpaceURI,
        serviceDID: String,
        authorization: AuthorizationContext
    ) async throws {
        let baseDID = serviceIssuerDID(serviceDID) ?? serviceDID
        try await unregisterSpaceNotification(
            space: space,
            ownerServiceDID: baseDID,
            deliveryServiceDID: serviceDID,
            authorization: authorization
        )
    }

    public func registerSpaceNotification(
        _ registration: AuthorizedSpaceNotificationRegistration,
        serviceDID: String,
        authorization: AuthorizationContext
    ) async throws {
        let database = try await preopenedCredentialAuthorityDatabase(
            for: registration.space
        )
        do {
            try await database.registerSpaceNotification(
                registration,
                serviceDID: serviceDID,
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
        // it deliberately succeeds as a no-op here.
        guard notification.audience == notification.space.authority,
              notification.issuer == notification.repository else {
            return
        }
        // A space whose authority this host does not serve is unknown here:
        // `SpaceNotFound`, as the reference's `assertSpaceHost` answers. The
        // sender's outbox treats that 4xx as permanent and stops retrying.
        guard let database = try await preopenedActiveDatabaseIfHosted(
            notification.space.authority
        ) else {
            throw AuthorizedSimpleSpaceLifecycleError.notFound
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
        } catch let error as AuthorizedSpaceWriteNotificationError {
            throw error
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
    }

    public func receiveSpaceDeletionNotification(
        space: SpaceURI,
        issuer: String,
        audience: String,
        eventID: String,
        requestBodyDigest: String
    ) async throws {
        guard let database = try await preopenedActiveDatabaseIfHosted(audience) else {
            return
        }
        do {
            try await database.receiveSpaceDeletionNotification(
                space: space,
                issuer: issuer,
                audience: audience,
                eventID: eventID,
                requestBodyDigest: requestBodyDigest
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
    public func repositoryBlobCIDs(
        space: SpaceURI,
        author: String,
        since: String?,
        limit: Int,
        cursor: String?,
        authorization: AuthorizationContext
    ) async throws -> [String] {
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
            let result = try await repository.listBlobCIDs(
                since: since,
                cursor: cursor,
                limit: limit,
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

    public func repositoryWriteWireRevision(
        space: SpaceURI,
        author: String,
        writes: [AuthorizedSpaceRepositoryWrite],
        authorization: AuthorizationContext
    ) async throws -> String? {
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
            let revision = try await repository.currentWireRevisionForWrite(
                writes,
                authorization: authorization
            )
            guard try await isActiveAccount(author) else {
                throw SwanError.unauthorized("account repository is unavailable")
            }
            guard !isClosed else {
                throw SwanError.unavailable("authenticated space directory is unavailable")
            }
            return revision
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
        maximumAggregateValueBytes: Int,
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
                maximumAggregateValueBytes: maximumAggregateValueBytes,
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
    public func repositorySTARSnapshot(
        space: SpaceURI,
        author: String,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceRepositorySTARSnapshot? {
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
            let snapshot = try await repository.prepareSTARSnapshot(
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

    /// Returns the declared length of the blob ``spaceBlob`` would open, from
    /// the same startup-opened inventory and behind the same authorization and
    /// lifecycle rechecks.  The transfer budget is reserved from this, so a
    /// response holds only the bytes it will stream.
    ///
    /// The two calls are separate reads of an immutable, content-addressed
    /// row, so the caller must still refuse a body whose declared length is
    /// not the one reserved for.
    public func spaceBlobMetadata(
        space: SpaceURI,
        author: String,
        cid: String,
        authorization: AuthorizationContext
    ) async throws -> AuthorizedSpaceBlobMetadata? {
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
            let metadata = try await repository.permissionedBlobMetadata(
                cid: cid,
                authorization: authorization
            )
            guard try await isActiveAccount(author) else {
                throw SwanError.unauthorized("account repository is unavailable")
            }
            guard !isClosed else {
                throw SwanError.unavailable("authenticated space directory is unavailable")
            }
            return metadata
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
    /// listener accepted traffic. The actor rechecks terminal shutdown and the
    /// resolved database path around the durable operation, and commits the
    /// batch under the control-plane authorization fence; it deliberately has
    /// no construction or migration fallback.
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
            // Parsed outside the fence so a malformed wire revision never
            // opens a control-plane write transaction.
            let revision = try TID(tidString: wireRevision)
            // The lifecycle recheck that used to follow this call could only
            // reject a batch it had already made durable: a deactivation
            // landing between the account-database COMMIT and the recheck
            // produced a permanent permissioned record *and* an `unauthorized`
            // response, with nothing able to roll the write back.
            //
            // The lease covers the durable transaction and nothing else.
            // Staging — the revision and record-metadata reads, every
            // authorization check, and CID computation over as much as 1 MiB
            // across as many as 4,096 operations — makes nothing durable, so
            // running it under the control-plane write gate would head-of-line
            // block OAuth and account-lifecycle traffic for the whole
            // preflight at request rate, buying no linearization: a
            // deactivation that lands during staging is still observed by the
            // fence, and one that lands after the commit is still ordered
            // after it.
            //
            // The in-process ordering that the control lease used to provide
            // as a side effect is provided directly, by the repository's own
            // write lease: concurrent batches for one repository still
            // serialize, each still stages against its predecessor's
            // committed revision, and the revision CAS still has nothing to
            // reject — without the control plane paying for it.
            let result = try await withRepositoryWriteLease(
                space: space,
                author: author
            ) {
                let staged = try await repository.stageAuthorizedWrites(
                    writes,
                    requestID: requestID,
                    wireRevision: revision,
                    authorization: authorization
                )
                // Nothing reachable from the closure re-enters the control
                // store: `DurableSpaceRepository` holds only the account
                // database, `SQLiteAccountDatabase` holds only its own
                // connection and performs no network I/O, and
                // `commitStagedWrites` reads nothing beyond the staged batch.
                // The lock order this takes — control gate, then
                // account-database gate — is the one
                // `PublicFirehoseCommitFence` already takes on the public
                // mutation path, so it introduces no new inversion.
                return try await requireAuthorizationFence()
                    .withActiveAccountAuthorization(did: author) {
                        try await repository.commitStagedWrites(staged)
                    }
            }
            guard !isClosed else {
                throw SwanError.unavailable("authenticated space directory is unavailable")
            }
            return result
        } catch let error as SwanError {
            throw error
        } catch let error as AccountControlStoreError {
            // The fence's two "this account may not write" answers carry the
            // same client-visible body the post-commit recheck used to emit,
            // now reached before anything is durable.
            switch error {
            case .invalidTransition, .notFound:
                throw SwanError.unauthorized("account repository is unavailable")
            default:
                throw SwanError.unavailable("authenticated space directory is unavailable")
            }
        } catch {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
    }

    /// Runs one permissioned batch as the sole writer of its repository.
    ///
    /// The gate is checked out and back in around the whole body, so an entry
    /// cannot be dropped between a waiter's lookup and its acquisition — that
    /// race would hand two batches a lease on the same repository and lose
    /// exactly the ordering this exists to provide.
    private func withRepositoryWriteLease<T: Sendable>(
        space: SpaceURI,
        author: String,
        _ body: () async throws -> T
    ) async throws -> T {
        let key = "\(author)\u{1F}\(space.rawValue)"
        let gate = checkOutRepositoryWriteGate(key)
        defer { checkInRepositoryWriteGate(key) }
        try await gate.acquire()
        do {
            let result = try await body()
            await gate.release()
            return result
        } catch {
            await gate.release()
            throw error
        }
    }

    private func checkOutRepositoryWriteGate(
        _ key: String
    ) -> RepositoryWriteGate {
        if var entry = repositoryWriteGates[key] {
            entry.users += 1
            repositoryWriteGates[key] = entry
            return entry.gate
        }
        let gate = RepositoryWriteGate()
        repositoryWriteGates[key] = RepositoryWriteGateEntry(gate: gate, users: 1)
        return gate
    }

    private func checkInRepositoryWriteGate(_ key: String) {
        guard var entry = repositoryWriteGates[key] else { return }
        entry.users -= 1
        if entry.users <= 0 {
            repositoryWriteGates.removeValue(forKey: key)
        } else {
            repositoryWriteGates[key] = entry
        }
    }

    /// The control-plane publication fence used to linearize a permissioned
    /// batch against account lifecycle. `withActiveAccountAuthorization` is a
    /// concrete `SQLiteControlDatabase` capability rather than an
    /// `AccountControlStore` requirement, and a directory that cannot reach it
    /// has no way to make the batch and the lifecycle check atomic — so this
    /// fails closed instead of silently returning to the post-commit recheck.
    private func requireAuthorizationFence() throws -> SQLiteControlDatabase {
        guard let fence = controlStore as? SQLiteControlDatabase else {
            throw SwanError.unavailable("authenticated space directory is unavailable")
        }
        return fence
    }

    /// Removes one DID from every live selection path before awaiting its
    /// database and escaped-blob-body drain. Revocation is terminal for this
    /// directory instance, so a concurrent activation cannot reinsert the
    /// actor after deletion begins.
    public func revokeAndDrainAccount(did: String) async throws {
        guard !isClosed,
              AccountControlIdentifiers.isDID(did) else {
            throw SwanError.unavailable(
                "account deletion quiescence is unavailable"
            )
        }
        permanentlyRevokedDIDs.insert(did)
        evictPublicReadGeneration(did: did)
        // Drop the shared re-admission handle rather than cancelling it: the
        // task's own post-await guards already refuse to publish a generation
        // once this DID leaves `databases`, and cancelling a live SQLite query
        // buys nothing but a second failure mode.
        publicReadReadmissions.removeValue(forKey: did)
        publicReadReadmissionFailures.removeValue(forKey: did)
        let database: SQLiteAccountDatabase
        if let draining = drainingDatabases[did] {
            database = draining
        } else if let installed = databases.removeValue(forKey: did) {
            drainingDatabases[did] = installed
            database = installed
        } else {
            return
        }
        do {
            try await database.closeForPermanentDeletion()
        } catch {
            throw SwanError.unavailable(
                "account deletion quiescence is unavailable"
            )
        }
        if drainingDatabases[did] === database {
            drainingDatabases.removeValue(forKey: did)
        }
    }

    /// Explicitly releases every startup-opened connection. The method is
    /// idempotent, and lookup after closing is unavailable rather than able to
    /// reopen a database on demand.
    public func close() async throws {
        guard !isClosed else { return }
        isClosed = true
        let opened = Array(databases.values) + Array(drainingDatabases.values)
        databases.removeAll()
        drainingDatabases.removeAll()
        for did in publicReadGenerations.keys {
            advancePublicReadPublishSequence(did: did)
        }
        publicReadGenerations.removeAll()
        publicReadReadmissions.removeAll()
        publicReadReadmissionFailures.removeAll()

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

    /// Internal failure/interleaving injection on one preopened account
    /// database. It exposes no connection or account data.
    func installAccountTestingHooks(
        _ hooks: SQLiteTestingHooks,
        did: String
    ) async throws {
        guard !isClosed,
              let database = databases[did] ?? drainingDatabases[did] else {
            throw SwanError.unavailable(
                "account deletion quiescence is unavailable"
            )
        }
        await database.installTestingHooks(hooks)
    }

    /// Internal failure injection for the permanent-deletion drain retry
    /// regression. It exposes no connection or account data.
    func installPermanentDeletionTestingHooks(
        _ hooks: SQLiteTestingHooks,
        did: String
    ) async throws {
        try await installAccountTestingHooks(hooks, did: did)
    }

    // MARK: Public repository reads

    public func publicRepositoryStatus(
        selector: String
    ) async throws -> PublicRepositoryReadStatus? {
        let account = try await resolvePublicAccount(selector)
        guard let account else { return nil }
        guard !isClosed else {
            throw PublicRepositoryReadError.unavailable(reason: .directoryClosed)
        }
        if account.status != .active {
            return try PublicRepositoryReadStatus(
                did: account.did, status: account.status, revision: nil
            )
        }
        return try await withPublicReadGeneration(account) {
            database, generation in
            do {
                _ = try await database.readPublicRepositoryDescription(
                    generation: generation
                )
            } catch let error as PublicRepositoryReadError {
                throw error
            } catch {
                throw PublicRepositoryReadError.unavailable(
                    reason: .storageFailure
                )
            }
            try await recheckPublicAccount(account, generation: generation)
            return try PublicRepositoryReadStatus(
                did: account.did,
                status: account.status,
                revision: generation.description.state.revision
            )
        }
    }

    /// The blob-read projection behind `com.atproto.sync.getBlob`.
    ///
    /// Deliberately does not call ``withPublicReadGeneration``. Every other
    /// method on this directory has to admit and pin a repository generation
    /// before it can answer; a blob has no MST revision to pin, so requiring
    /// one would place avatar and image serving behind the exact admission
    /// gate that stopped returning on 2026-08-12 and would buy nothing.
    ///
    /// An account with no startup-preopened database is reported exactly as an
    /// unhosted one. This route must never scan the data directory or open a
    /// database on demand for an anonymous caller, and the preopened check
    /// precedes the lifecycle check so a non-preopened account cannot be
    /// distinguished from one this server has never hosted.
    public func publicRepositoryBlobOutcome(
        did: String
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadBlobTarget> {
        guard AccountControlIdentifiers.isDID(did) else {
            throw PublicRepositoryReadError.invalidSelector
        }
        guard let account = try await resolvePublicAccount(did) else {
            return .notFound
        }
        guard !isClosed else {
            throw PublicRepositoryReadError.unavailable(reason: .directoryClosed)
        }
        guard let database = databases[account.did] else { return .notFound }
        guard account.status == .active else {
            return .lifecycle(
                try PublicRepositoryReadStatus(
                    did: account.did,
                    status: account.status,
                    revision: nil
                )
            )
        }
        return .active(
            try PublicRepositoryReadBlobTarget(
                did: account.did,
                status: account.status,
                store: SQLitePublicRepositoryReadBlobStore(database: database)
            )
        )
    }

    public func describePublicRepository(
        selector: String
    ) async throws -> PublicRepositoryReadDescription? {
        switch try await publicRepositoryDescriptionOutcome(
            selector: selector
        ) {
        case .notFound, .lifecycle:
            return nil
        case let .active(description):
            return description
        }
    }

    public func publicRepositoryDescriptionOutcome(
        selector: String
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadDescription> {
        guard let account = try await resolvePublicAccount(selector) else {
            return .notFound
        }
        guard account.status == .active else {
            return .lifecycle(try PublicRepositoryReadStatus(
                did: account.did,
                status: account.status,
                revision: nil
            ))
        }
        return try await withPublicReadGeneration(account) {
            database, generation in
            let description: PublicRepositoryReadDescription
            do {
                description = try await database
                    .readPublicRepositoryDescription(generation: generation)
            } catch let error as PublicRepositoryReadError {
                throw error
            } catch {
                throw PublicRepositoryReadError.unavailable(
                    reason: .storageFailure
                )
            }
            try await recheckPublicAccount(account, generation: generation)
            return .active(description)
        }
    }

    private func verifyPublicIdentityIntent(
        _ description: PublicRepositoryReadDescription
    ) async throws {
        try await Self.verifyPublicIdentityIntent(
            description,
            controlStore: controlStore
        )
    }

    private static func verifyPublicIdentityIntent(
        _ description: PublicRepositoryReadDescription,
        controlStore: any AccountControlStore
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
            throw PublicRepositoryReadError.unavailable(reason: .intentVerificationFailed)
        }
    }

    public func publicRepositoryRecord(
        selector: String,
        path: PublicRepositoryPath,
        expectedCID: CID?
    ) async throws -> PublicRepositoryReadRecord? {
        switch try await publicRepositoryRecordOutcome(
            selector: selector,
            path: path,
            expectedCID: expectedCID
        ) {
        case .notFound, .lifecycle:
            return nil
        case let .active(result):
            return result.record
        }
    }

    public func publicRepositoryRecordOutcome(
        selector: String,
        path: PublicRepositoryPath,
        expectedCID: CID?
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadRecordResult> {
        guard let account = try await resolvePublicAccount(selector) else {
            return .notFound
        }
        guard account.status == .active else {
            return .lifecycle(try PublicRepositoryReadStatus(
                did: account.did,
                status: account.status,
                revision: nil
            ))
        }
        return try await withPublicReadGeneration(account) {
            database, generation in
            let read: SQLitePublicRepositoryRecordRead
            do {
                read = try await database.readPublicRepositoryRecord(
                    path: path,
                    expectedCID: expectedCID,
                    generation: generation
                )
            } catch let error as PublicRepositoryReadError {
                throw error
            } catch {
                throw PublicRepositoryReadError.unavailable(
                    reason: .storageFailure
                )
            }
            try await recheckPublicAccount(account, generation: generation)
            return .active(try PublicRepositoryReadRecordResult(
                did: account.did,
                state: read.state,
                record: read.record
            ))
        }
    }

    public func listPublicRepositoryRecords(
        selector: String,
        collection: String,
        limit: Int,
        cursor: String?,
        reverse: Bool
    ) async throws -> PublicRepositoryReadPage {
        switch try await publicRepositoryRecordsOutcome(
            selector: selector,
            collection: collection,
            limit: limit,
            cursor: cursor,
            reverse: reverse
        ) {
        case .notFound, .lifecycle:
            throw PublicRepositoryReadError.invalidSelector
        case let .active(result):
            return result.page
        }
    }

    public func publicRepositoryRecordsOutcome(
        selector: String,
        collection: String,
        limit: Int,
        cursor: String?,
        reverse: Bool
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadPageResult> {
        guard let account = try await resolvePublicAccount(selector) else {
            return .notFound
        }
        guard account.status == .active else {
            return .lifecycle(try PublicRepositoryReadStatus(
                did: account.did,
                status: account.status,
                revision: nil
            ))
        }
        return try await withPublicReadGeneration(account) {
            database, generation in
            let read: SQLitePublicRepositoryPageRead
            do {
                read = try await database.readPublicRepositoryRecords(
                    collection: collection,
                    limit: limit,
                    cursor: cursor,
                    reverse: reverse,
                    generation: generation
                )
            } catch let error as PublicRepositoryReadError {
                throw error
            } catch {
                throw PublicRepositoryReadError.unavailable(
                    reason: .storageFailure
                )
            }
            try await recheckPublicAccount(account, generation: generation)
            return .active(try PublicRepositoryReadPageResult(
                did: account.did,
                state: read.state,
                page: read.page
            ))
        }
    }

    public func publicRepositoryCAR(
        selector: String
    ) async throws -> PublicRepositoryReadCAR? {
        switch try await publicRepositoryCAROutcome(selector: selector) {
        case .notFound, .lifecycle:
            return nil
        case let .active(car):
            return car
        }
    }

    public func publicRepositoryCAROutcome(
        selector: String
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadCAR> {
        guard let account = try await resolvePublicAccount(selector) else {
            return .notFound
        }
        guard account.status == .active else {
            return .lifecycle(try PublicRepositoryReadStatus(
                did: account.did,
                status: account.status,
                revision: nil
            ))
        }
        return try await withPublicReadGeneration(account) {
            database, generation in
            // The lease is reserved inside the attempt so a re-admitted retry
            // starts from a released budget rather than double-charging the
            // account against the shared spool admission.
            guard let lease = publicRepositorySpoolAdmission.reserve(
                accountDID: account.did,
                maximumBytes: PublicRepositoryLimits.standard.maximumCARBytes
            ) else {
                throw PublicRepositoryReadError.unavailable(
                    reason: .admissionBudgetExhausted
                )
            }
            let result: PublicRepositoryReadCAR
            do {
                result = try await database.preparePublicRepositoryCAR(
                    lease: lease,
                    generation: generation
                )
            } catch let error as PublicRepositoryReadError {
                lease.release()
                throw error
            } catch {
                lease.release()
                throw PublicRepositoryReadError.unavailable(
                    reason: .storageFailure
                )
            }
            do {
                try await recheckPublicAccount(account, generation: generation)
                return .active(result)
            } catch {
                result.spool.cleanup()
                throw error
            }
        }
    }

    /// Republishes an account's public read generation after a mutation, and
    /// evicts rather than refuses when that cannot be done.
    ///
    /// This runs strictly *after* `applyPublicRepositoryMutation` has
    /// committed. By then the write is durable and nothing here can unmake it,
    /// so propagating a refresh failure was wrong twice over. It reported
    /// failure for a request whose write had already succeeded — a client that
    /// retries on that answer writes the record twice — and it left the
    /// pre-mutation generation cached, pinned to a `public_repository_state`
    /// the commit has already moved past. Every following read matched that
    /// pin, refused with ``PublicReadUnavailableReason/repositoryStateMismatch``,
    /// and stayed refused: the 2026-08-12 outage's shape reached through a
    /// different door, and one that re-admission cannot rescue because only
    /// ``PublicReadUnavailableReason/generationPinStale`` earns a retry.
    ///
    /// The repair is local and negative. The entry is dropped from
    /// ``publicReadGenerations`` — the *positive* cache, the one that answers
    /// reads — so the next read finds nothing cached and admits from cold
    /// exactly as the first read after bootstrap does. The mutation itself is
    /// unaffected and returns success.
    ///
    /// Deliberately **not** written here: a `publicReadReadmissionFailures`
    /// entry. That negative cache is consulted by
    /// ``admitPublicReadGenerationForRequest(account:database:)``, which is
    /// the path the post-eviction cold read takes, and while an entry is live
    /// that path refuses without admitting. Writing one here would therefore
    /// suppress the very cold admission this eviction depends on, converting a
    /// self-healing cache miss into a guaranteed backoff window of `503`s for
    /// an account whose write just succeeded.
    ///
    /// Nor would the reason recorded be true. Entries in that cache name a
    /// *read* refusal — the answer a read would have got by re-running the
    /// admission — and are cleared only by a publisher. An entry written from
    /// here names a write-path publication failure that no read ever asked
    /// about, and no cold-path failure would clear it: the only clearing site
    /// is `refreshPublicReadGeneration`'s publish. It would go on to suppress
    /// a legitimate later re-admission with a reason that was never a read's.
    ///
    /// Both halves are pinned by tests:
    /// `testFailedPostMutationRefreshEvictsRatherThanCachingStale` asserts no
    /// entry is written, and `testColdCacheReadsAreBoundedByTheBackoff`
    /// asserts that an entry, once a *read* writes one, does suppress the cold
    /// path — which is what makes writing one from here harmful rather than
    /// merely untidy.
    fileprivate func refreshPublicReadGenerationAfterMutation(
        did: String,
        database: SQLiteAccountDatabase
    ) async {
        // The commit this refresh follows is already durable, so every
        // generation admitted against a snapshot taken before this line is
        // stale — including one whose admission is suspended mid-flight right
        // now, on some reader's re-admission. Recording the invalidation here,
        // before the first suspension of this method, is what makes such an
        // admission lose its publish rather than refill the cache this method
        // is about to correct or evict. Without it the eviction below is
        // undone the instant the suspended admission resumes, and the account
        // is pinned to a pre-commit `public_repository_state` — a permanent
        // `.repositoryStateMismatch`, the 2026-08-12 outage's shape again.
        advancePublicReadPublishSequence(did: did)
        do {
            let resolved: AccountControlAccount?
            do {
                resolved = try await controlStore.account(did: did)
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                throw namedPostMutationRefreshFailure(
                    .controlStoreFailure, did: did
                )
            }
            guard let account = resolved else {
                throw namedPostMutationRefreshFailure(
                    .controlRowChanged, did: did
                )
            }
            _ = try await refreshPublicReadGeneration(
                account: account,
                database: database
            )
        } catch is CancellationError {
            // Ordered before the generic catch, as on the admission path. A
            // cancelled refresh is not evidence that this account cannot be
            // admitted, so the generation is still retired — it is stale
            // either way — but nothing is journalled as a refusal.
            evictPublicReadGeneration(did: did)
        } catch {
            evictPublicReadGeneration(did: did)
            logPublicReadAdmissionFailure(
                .unavailable(reason: .postMutationRefreshFailed),
                did: did
            )
        }
    }

    /// Journals a refusal raised by this file's own pre-refresh guards and
    /// returns it to be thrown.
    ///
    /// ``refreshPublicReadGeneration(account:database:)`` journals every
    /// refusal it names itself, so the guards that run before it are the only
    /// ones that would otherwise refuse silently. Every post-mutation refresh
    /// failure therefore leaves exactly one line naming the cause, followed by
    /// one naming the eviction.
    private func namedPostMutationRefreshFailure(
        _ reason: PublicReadUnavailableReason,
        did: String
    ) -> PublicRepositoryReadError {
        let error = PublicRepositoryReadError.unavailable(reason: reason)
        logPublicReadAdmissionFailure(error, did: did)
        return error
    }

    /// Test seam: the identity of the generation currently cached for one DID,
    /// or `nil` when nothing is cached.
    ///
    /// Eviction and replacement are indistinguishable from the read path —
    /// both end in a cold admission — yet the difference is exactly what
    /// ``refreshPublicReadGenerationAfterMutation(did:database:)`` has to get
    /// right. Read-only, and never consulted by production code.
    func cachedPublicReadGenerationID(did: String) -> UUID? {
        publicReadGenerations[did]?.id
    }

    /// Test seam: whether a re-admission backoff entry is live for one DID.
    /// A failed post-mutation refresh must evict the positive generation
    /// without writing one of these. Never consulted by production code.
    func hasLivePublicReadReadmissionBackoff(did: String) -> Bool {
        guard let failure = publicReadReadmissionFailures[did] else {
            return false
        }
        return failure.expiresAt > ContinuousClock.now
    }

    private func resolvePublicAccount(
        _ selector: String
    ) async throws -> AccountControlAccount? {
        guard !isClosed else { throw PublicRepositoryReadError.unavailable(reason: .directoryClosed) }
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
            throw PublicRepositoryReadError.unavailable(reason: .controlStoreFailure)
        }
        guard !isClosed else { throw PublicRepositoryReadError.unavailable(reason: .directoryClosed) }
        return account
    }

    private func preopenedPublicRepositoryDatabase(
        _ did: String
    ) throws -> SQLiteAccountDatabase {
        guard !isClosed else { throw PublicRepositoryReadError.unavailable(reason: .directoryClosed) }
        do {
            try Self.requireExistingRegularDatabase(
                SQLiteLayout.accountDatabase(in: dataDirectory, did: did)
            )
        } catch {
            throw PublicRepositoryReadError.unavailable(reason: .accountNotPreopened)
        }
        guard let database = databases[did] else {
            throw PublicRepositoryReadError.unavailable(reason: .accountNotPreopened)
        }
        return database
    }

    private func activePublicReadContext(
        _ account: AccountControlAccount
    ) async throws -> (
        database: SQLiteAccountDatabase,
        generation: SQLiteVerifiedPublicRepositoryGeneration
    ) {
        guard account.status == .active else {
            throw PublicRepositoryReadError.unavailable(reason: .accountNotActive)
        }
        let database = try preopenedPublicRepositoryDatabase(account.did)
        if let generation = publicReadGenerations[account.did],
           generation.controlAccount == account {
            return (database, generation)
        }
        // Cold cache. Reached when the control row moved out from under the
        // cached generation, and — since Task 3 — when a failed post-mutation
        // refresh evicted it. That second case is a *steady* state for an
        // account whose refresh keeps failing for a persistent reason, so this
        // path carries the same request-time bounds as re-admission rather
        // than calling `refreshPublicReadGeneration` bare.
        let generation = try await admitPublicReadGenerationForRequest(
            account: account,
            database: database
        )
        return (
            database,
            generation
        )
    }

    /// Runs one generation-validated public read, re-admitting at most once.
    ///
    /// This is the fix for the 2026-08-12 outage. A published generation pins
    /// `PRAGMA data_version`. That pragma is monotonic, advances on **any**
    /// commit from **any other** connection to the account database — even a
    /// commit that touches no repository state at all — and never returns to
    /// its prior value. Swan holds more than one descriptor per account
    /// database in the live process, so such a commit is routine. Nothing on
    /// the read path ever replaced a generation whose pin had drifted, so the
    /// first foreign commit made every public read for that account return
    /// `503` permanently; the live incident cleared only because an unrelated
    /// record write happened to run the post-commit refresh three hours later.
    ///
    /// A reason earns a second attempt exactly when it is change detection —
    /// ``PublicReadUnavailableReason/isChangeDetection``, which is
    /// `.generationPinStale` and `.generationPublishSuperseded` and nothing
    /// else. The second cannot reach the retry from here — an admission that
    /// refuses to publish throws out of `readmitPublicReadGeneration` below,
    /// which is already the second attempt's own admission and not an
    /// `attempt` — so the bound is unchanged. Every other refusal — identity,
    /// projection, control row, corruption — propagates from the first attempt
    /// untouched, so re-admission can never launder a real failure into a
    /// success or into a different reason. The same property gates
    /// ``recordPublicReadReadmissionFailure(did:error:)``, so the reason this
    /// retries is by construction the reason that is never cached as a refusal.
    ///
    /// The second attempt runs against a generation produced by the same
    /// ``refreshPublicReadGeneration(account:database:)`` that admits a cold
    /// account: PLC identity, preparation intent, commit authentication,
    /// projection, database path, and the exact active control row are all
    /// re-checked on both sides. Re-admission therefore accepts exactly the
    /// set a cold start accepts, and the retried read re-validates every pin
    /// against the new generation before a byte is served.
    ///
    /// The bound is structural, not incidental: `attempt` appears exactly
    /// twice on a straight line, with no loop and no recursion. Whatever the
    /// second attempt throws is what the caller sees.
    /// `T` is constrained to `Sendable` because `attempt` is a nonisolated
    /// closure invoked from this actor: the Linux Swift 6.1 toolchain rejects
    /// sending an unconstrained result across that boundary, while the macOS
    /// toolchain accepts it. The deployment target is Linux, so the stricter
    /// reading governs.
    private func withPublicReadGeneration<T: Sendable>(
        _ account: AccountControlAccount,
        _ attempt: (
            SQLiteAccountDatabase,
            SQLiteVerifiedPublicRepositoryGeneration
        ) async throws -> T
    ) async throws -> T {
        let (database, admitted) = try await activePublicReadContext(account)
        let stale: SQLiteVerifiedPublicRepositoryGeneration
        do {
            return try await attempt(database, admitted)
        } catch let error as PublicRepositoryReadError
            where error.unavailableReason?.isChangeDetection == true
        {
            stale = admitted
        }
        let readmitted = try await readmitPublicReadGeneration(
            account: account,
            database: database,
            replacing: stale
        )
        return try await attempt(database, readmitted)
    }

    /// Re-admits one account's public read generation after its pin drifted.
    ///
    /// Only the short-circuit lives here; the bounded admission itself is
    /// ``admitPublicReadGenerationForRequest(account:database:)``, shared with
    /// the cold-cache read.
    private func readmitPublicReadGeneration(
        account: AccountControlAccount,
        database: SQLiteAccountDatabase,
        replacing stale: SQLiteVerifiedPublicRepositoryGeneration
    ) async throws -> SQLiteVerifiedPublicRepositoryGeneration {
        if let current = publicReadGenerations[account.did],
           current.id != stale.id,
           current.controlAccount == account {
            // Someone already re-admitted this account while this request was
            // reading. That generation went through the full admission, so
            // spending another one here would buy nothing. Checked before the
            // negative cache: a published generation is proof of recovery and
            // must win over a window that has not expired yet.
            return current
        }
        return try await admitPublicReadGenerationForRequest(
            account: account,
            database: database
        )
    }

    /// The one request-time admission path, collapsing concurrent admissions
    /// for the same DID onto a single one and bounding how often a DID that
    /// cannot be admitted is allowed to re-pay for finding that out.
    ///
    /// A foreign commit invalidates the pin for every in-flight reader of that
    /// account at once, so the naive shape is a stampede: N concurrent public
    /// reads each running a full admission — record-index walk, block
    /// materialization, commit authentication — against the one SQLite
    /// connection that serializes them anyway. Single-flighting is both
    /// cheaper and no weaker than admitting per request: the shared result is
    /// a fully verified generation, the joining request still checks that it
    /// was admitted against its own resolved control row, and the retried read
    /// re-validates every pin. A joiner that resolved a different control row
    /// is refused rather than served.
    ///
    /// Both callers arrive from an anonymous public read, so both get those
    /// bounds. The cold-cache caller is not the cheaper case it looks like:
    /// since Task 3's post-mutation eviction, "database open, no generation
    /// cached" is a state an account can sit in indefinitely when its refresh
    /// keeps failing for a persistent reason — `accountNotActive`,
    /// `identityFactsMalformed`, `accountNotPreopened`. Routed around the
    /// negative cache, every anonymous read for such a DID would pay a full
    /// record-index walk, MST projection verify and PLC `verifyGenesis`,
    /// forever. That is precisely the unbounded per-read cost
    /// ``recordPublicReadReadmissionFailure(did:error:)`` exists to cap, on
    /// endpoints the whole network can reach once Swan is announced to a
    /// relay.
    private func admitPublicReadGenerationForRequest(
        account: AccountControlAccount,
        database: SQLiteAccountDatabase
    ) async throws -> SQLiteVerifiedPublicRepositoryGeneration {
        if let failure = publicReadReadmissionFailures[account.did] {
            if failure.expiresAt > ContinuousClock.now {
                // Suppress the work, never the refusal. The caller sees the
                // same reason it would have seen from a re-run admission, and
                // the client sees the same 503 body; the record-index walk is
                // what does not happen.
                //
                // The line is *not* re-emitted here. The failure that opened
                // this window was already journalled in full by the admission
                // that failed, with this same reason and DID, so a second
                // line per suppressed request carries no new information and
                // scales with inbound request rate rather than with distinct
                // failures. One dark account plus a relay retrying `getRepo`
                // is then a disk-fill path on the production box. The reads
                // are counted instead and reported once, when the window
                // retires.
                publicReadReadmissionFailures[account.did]?
                    .suppressedReads += 1
                throw PublicRepositoryReadError.unavailable(
                    reason: failure.reason
                )
            }
            retirePublicReadReadmissionFailure(did: account.did)
        }
        let admission: Task<SQLiteVerifiedPublicRepositoryGeneration, any Error>
        if let inFlight = publicReadReadmissions[account.did] {
            admission = inFlight
        } else {
            // The store below runs before this closure's first suspension —
            // actor-isolated code continues synchronously past `Task { }` —
            // so a second caller in the same turn always sees the handle.
            let started = Task { [self] in
                defer { publicReadReadmissions.removeValue(forKey: account.did) }
                return try await refreshPublicReadGeneration(
                    account: account,
                    database: database
                )
            }
            publicReadReadmissions[account.did] = started
            admission = started
        }
        let generation: SQLiteVerifiedPublicRepositoryGeneration
        do {
            generation = try await admission.value
        } catch let error as PublicRepositoryReadError {
            recordPublicReadReadmissionFailure(did: account.did, error: error)
            throw error
        }
        guard generation.controlAccount == account else {
            // The shared admission verified a control row this request did not
            // resolve. Fail closed instead of serving another row's account.
            throw PublicRepositoryReadError.unavailable(
                reason: .controlRowChanged
            )
        }
        return generation
    }

    /// Remembers, briefly, that admitting this DID did not work.
    ///
    /// A failed admission never publishes a generation, so the next read finds
    /// the cache in exactly the state that sent this one down the admission
    /// path — the same stale generation, or nothing at all after a
    /// post-mutation eviction — and re-enters it. Without this, one
    /// unadmittable account turns each anonymous public read into a full
    /// record-index walk plus PLC verification — a fast 503 becomes a slow
    /// one, on endpoints the whole network can reach once Swan is announced
    /// to a relay.
    ///
    /// The entry suppresses *work* only. It is never consulted to serve
    /// anything: while it is live the read still refuses, with the same reason
    /// and the same body it would have produced by re-running the admission.
    /// Cancellation is deliberately not recorded — a caller hanging up is not
    /// evidence about the account.
    ///
    /// Neither is change detection. `PRAGMA data_version` moving says only that
    /// some connection committed something, so an admission that refuses with
    /// ``PublicReadUnavailableReason/isChangeDetection`` is reporting a race,
    /// not an account that cannot be admitted. Recording it would invert the
    /// reason's meaning at the worst possible moment: the entry is consulted by
    /// ``admitPublicReadGenerationForRequest(account:database:)``, which is the
    /// admission ``withPublicReadGeneration(_:_:)`` runs *because* the pin went
    /// stale — so a stale pin would suppress its own recovery and leave the
    /// account dark for the whole window. That is the 2026-08-12 outage again,
    /// reached through the path built to end it, merely time-boxed to 250 ms.
    /// The exclusion costs at most one redone admission per read in a race that
    /// resolves itself.
    ///
    /// Everything else is recorded, including the admission failures that carry
    /// no ``PublicReadUnavailableReason`` of their own. `resourceLimitExceeded`
    /// is raised by admission's own projection preflight *after* it paginates
    /// the entire `public_repository_record_index`, and it is the most
    /// permanent refusal there is — it repeats identically until an operator
    /// changes the data. Skipping it because it arrived unnamed left precisely
    /// the account this cache exists for unbounded, so classification runs
    /// through ``PublicRepositoryReadError/admissionFailureReason``, which
    /// names it. Only request-shape errors are still passed over, and those no
    /// admission can raise.
    private func recordPublicReadReadmissionFailure(
        did: String,
        error: PublicRepositoryReadError
    ) {
        guard let reason = error.admissionFailureReason,
              !reason.isChangeDetection else { return }
        let now = ContinuousClock.now
        if publicReadReadmissionFailures[did] == nil,
           publicReadReadmissionFailures.count
           >= Self.maximumPublicReadReadmissionFailures {
            publicReadReadmissionFailures = publicReadReadmissionFailures
                .filter { $0.value.expiresAt > now }
            guard publicReadReadmissionFailures.count
                < Self.maximumPublicReadReadmissionFailures else {
                // Every slot holds a live window. Decline to record rather
                // than grow: the only consequence is that this DID redoes the
                // admission next read, which is exactly the behaviour that
                // shipped before this cache existed.
                return
            }
        }
        publicReadReadmissionFailures[did] = PublicReadReadmissionFailure(
            reason: reason,
            expiresAt: now.advanced(by: Self.publicReadReadmissionBackoff)
        )
    }

    // MARK: Publish sequencing

    /// The value an in-flight admission must still see when it publishes.
    private func publicReadPublishSequence(did: String) -> UInt64 {
        publicReadGenerationPublishSequence[did] ?? 0
    }

    /// Installs a verified generation as the answer to this DID's reads and
    /// records the installation, so an admission still in flight against an
    /// older snapshot loses its own publish rather than overwriting this one.
    private func publishPublicReadGeneration(
        _ generation: SQLiteVerifiedPublicRepositoryGeneration,
        did: String
    ) {
        publicReadGenerations[did] = generation
        advancePublicReadPublishSequence(did: did)
    }

    /// Drops this DID's cached generation and records the drop.
    ///
    /// Recording it is the load-bearing half. An eviction that did not move
    /// the sequence could be silently undone by an admission that started
    /// before it and resumed after it — which is how a committed write's
    /// correct eviction gets refilled with the pre-commit generation.
    private func evictPublicReadGeneration(did: String) {
        publicReadGenerations.removeValue(forKey: did)
        advancePublicReadPublishSequence(did: did)
    }

    /// Wrapping is deliberate and harmless. A `UInt64` counting cache
    /// invalidations cannot realistically reach its bound, and the guard that
    /// reads it compares for equality rather than for order, so even a wrap
    /// would have to land back on exactly the sampled value to matter.
    private func advancePublicReadPublishSequence(did: String) {
        publicReadGenerationPublishSequence[did] =
            publicReadPublishSequence(did: did) &+ 1
    }

    /// Test seam: awaited by ``refreshPublicReadGeneration(account:database:)``
    /// immediately after the admission and before the intent verification, so
    /// a test can hold one publisher at the exact point the live interleaving
    /// holds it — after the database snapshot, before the publish.
    ///
    /// `nil` in every production configuration; there is no way to set it from
    /// outside this module. It stands in for the control-store round trip in
    /// `verifyPublicIdentityIntent`, which is where a publisher really does
    /// suspend, and exists because that suspension cannot otherwise be placed
    /// deterministically: the fixtures drive a real `SQLiteControlDatabase`.
    private var publicReadPublishBarrier: (@Sendable () async -> Void)?

    /// Test seam: installs (or clears) ``publicReadPublishBarrier``.
    /// Never called by production code.
    func setPublicReadPublishBarrier(
        _ barrier: (@Sendable () async -> Void)?
    ) {
        publicReadPublishBarrier = barrier
    }

    /// Re-admits the existing account database when the control row changed
    /// after bootstrap (for example, deactivation followed by reactivation).
    /// This is deliberately request-time refresh only: it never opens,
    /// creates, or migrates a database, and it publishes a generation only
    /// after PLC identity, preparation intent, path, and the exact active
    /// control row have been checked on both sides of the admission.
    private func refreshPublicReadGeneration(
        account: AccountControlAccount,
        database: SQLiteAccountDatabase
    ) async throws -> SQLiteVerifiedPublicRepositoryGeneration {
        // Sampled before this method looks at the database, so the snapshot
        // the admission below reads is never older than this value. The
        // symmetric re-read sits in the publishing turn at the bottom.
        let admittedAtSequence = publicReadPublishSequence(did: account.did)
        do {
            // This is the guard on the exact path that failed live for three
            // hours. Four unrelated conditions shared one name until
            // 2026-08-12; a recurrence must point the next investigation at
            // the right subsystem, so each condition reports itself — and all
            // four sit inside the `do` so the catch below journals them.
            guard !isClosed else {
                throw PublicRepositoryReadError.unavailable(
                    reason: .directoryClosed
                )
            }
            guard account.status == .active else {
                throw PublicRepositoryReadError.unavailable(
                    reason: .accountNotActive
                )
            }
            guard databases[account.did] === database else {
                throw PublicRepositoryReadError.unavailable(
                    reason: .accountNotPreopened
                )
            }
            guard let identityVerifier = publicIdentityVerifier else {
                throw PublicRepositoryReadError.unavailable(
                    reason: .publicIdentityVerifierUnconfigured
                )
            }
            try Self.requireExistingRegularDatabase(
                SQLiteLayout.accountDatabase(in: dataDirectory, did: account.did)
            )
            guard let current = try await controlStore.account(did: account.did),
                  current == account else {
                throw PublicRepositoryReadError.unavailable(
                    reason: .controlRowChanged
                )
            }
            guard current.status == .active else {
                throw PublicRepositoryReadError.unavailable(
                    reason: .accountNotActive
                )
            }
            let generation = try await database.admitPublicRepositoryGeneration(
                account: account,
                identityVerifier: identityVerifier
            )
            await publicReadPublishBarrier?()
            try await Self.verifyPublicIdentityIntent(
                generation.description,
                controlStore: controlStore
            )
            guard !isClosed else {
                throw PublicRepositoryReadError.unavailable(
                    reason: .directoryClosed
                )
            }
            guard databases[account.did] === database else {
                throw PublicRepositoryReadError.unavailable(
                    reason: .accountNotPreopened
                )
            }
            guard let current = try await controlStore.account(did: account.did),
                  current == account else {
                throw PublicRepositoryReadError.unavailable(
                    reason: .controlRowChanged
                )
            }
            guard current.status == .active else {
                throw PublicRepositoryReadError.unavailable(
                    reason: .accountNotActive
                )
            }
            try Self.requireExistingRegularDatabase(
                SQLiteLayout.accountDatabase(in: dataDirectory, did: account.did)
            )
            // The last guard, and the only one that is about *other*
            // publishers rather than about this account.
            //
            // Every guard above re-checks something this admission read: the
            // directory, the database identity, the control row, the status,
            // the file. None of them looks at `public_repository_state`, and
            // none of them can — a repository commit moves that row without
            // touching anything they inspect, and (committed on this same
            // connection) without moving `PRAGMA data_version` either. So an
            // admission suspended across a commit passes all of them and then
            // publishes a generation pinned to the pre-commit head. Once that
            // generation is cached, `activePublicReadContext` hits it — it
            // compares only the control row, which a repository write does not
            // touch — and every read then fails `state == description.state`
            // with `.repositoryStateMismatch`. That reason is not change
            // detection, so it is not retried, not evicted and not
            // negative-cached: the account's public repository returns `503`
            // until the next successful write or a process restart.
            //
            // The sequence closes that door. It moved iff some other
            // publisher, evictor, or durable commit invalidated this DID's
            // cache after this admission sampled it, which is exactly the
            // condition under which what follows would be a stale publish.
            //
            // Refusing here cannot wedge anything, because refusing writes
            // nothing. The cache is left holding either a generation some
            // other publisher installed — which passed this same guard, so it
            // is at least as fresh — or nothing at all, in which case the next
            // read admits from cold. Never stale-and-pinned. The refusal is
            // reported as change detection so it is not mistaken for a verdict
            // on the account: it is never negative-cached, and the caller's own
            // read fails once while the next one recovers with no operator
            // involvement. The post-mutation refresh, which is the one caller
            // that must not merely decline, converts this throw into the
            // eviction it already performs for every other refresh failure.
            //
            // There is no suspension between the check and the publish: the
            // last `await` is the control-store round trip above, and
            // everything from there down runs in one actor turn. A `state`
            // re-read here would not have that property — it would itself be
            // an `await`, reopening a narrower version of the same window.
            guard publicReadPublishSequence(did: account.did)
                == admittedAtSequence else {
                throw PublicRepositoryReadError.unavailable(
                    reason: .generationPublishSuperseded
                )
            }
            publishPublicReadGeneration(generation, did: account.did)
            // The single line that publishes a generation is also the single
            // line that retires the negative cache entry, so every publisher
            // clears it — a cold-cache refresh, a successful re-admission, and
            // `refreshPublicReadGenerationAfterMutation` alike. Recovery that
            // has an event to hang off never waits out the window.
            retirePublicReadReadmissionFailure(did: account.did)
            return generation
        } catch is CancellationError {
            // A caller hanging up is not an admission refusal. Rethrow it
            // untouched rather than journalling a service failure that did not
            // happen.
            throw CancellationError()
        } catch let error as PublicRepositoryReadError {
            logPublicReadAdmissionFailure(error, did: account.did)
            throw error
        } catch let error as PublicRepositoryMutationStoreError
            where error == .corruptRepository
        {
            // Admission's own block reads report corruption through the
            // mutation-store error. Name it rather than folding it into the
            // generic bucket; the client-visible 503 is unchanged.
            let named = PublicRepositoryReadError.unavailable(
                reason: .blockMaterializationFailed
            )
            logPublicReadAdmissionFailure(named, did: account.did)
            throw named
        } catch {
            let named = PublicRepositoryReadError.unavailable(
                reason: .storageFailure
            )
            logPublicReadAdmissionFailure(named, did: account.did)
            throw named
        }
    }

    /// The one line that turns a silent 503 into a diagnosable one.
    ///
    /// Server-side only: the DID and the failed guard's name are written to the
    /// service journal and never to a response body. The 2026-08-12 outage ran
    /// for three hours with zero `journalctl` lines because this did not exist.
    ///
    /// Classification goes through
    /// ``PublicRepositoryReadError/admissionFailureReason``, not
    /// ``PublicRepositoryReadError/unavailableReason``: an admission can refuse
    /// with `resourceLimitExceeded`, which carries no reason of its own, and
    /// reading the bare reason here reproduced the silent-503 the outage was
    /// about for exactly that failure.
    private func logPublicReadAdmissionFailure(
        _ error: PublicRepositoryReadError,
        did: String
    ) {
        guard let reason = error.admissionFailureReason else { return }
        publicReadAdmissionJournalLines += 1
        publicReadDiagnosticLog.warning(
            "public read admission refused",
            fields: ["did": did, "reason": reason.rawValue]
        )
    }

    /// Drops one negative-cache entry and reports, once, how many reads it
    /// refused without re-running the admission.
    ///
    /// The window bounds *work*; this bounds the journal for the same reason
    /// and by the same shape. A persistently unadmittable account is read by
    /// the whole network once Swan is announced to a relay, so a line per
    /// suppressed request makes journal volume a function of inbound request
    /// rate with no ceiling — a disk-fill path, and one an anonymous caller
    /// controls. What an operator needs is already carried by the full line
    /// the failed admission wrote when it opened the window; the only thing
    /// missing from it is how much traffic ran into that window, which is one
    /// integer. So each window costs at most two lines: the named failure that
    /// opened it, and this rollup. Volume tracks distinct admission failures,
    /// which is what a diagnosis is made of.
    ///
    /// Retirement is lazy — the next read past the expiry runs it, and that
    /// read then pays a real admission whose own outcome is journalled — and
    /// it also runs from the publish site, so a recovered account reports its
    /// suppressed reads immediately rather than at some later read.
    ///
    /// The teardown paths (`revokeAndDrainAccount`, `close`) deliberately drop
    /// entries without a rollup. An account being revoked or a directory
    /// closing is not a diagnosis moment, and every read those entries
    /// suppressed was already refused with the reason the opening line names.
    private func retirePublicReadReadmissionFailure(did: String) {
        guard let failure = publicReadReadmissionFailures
            .removeValue(forKey: did),
            failure.suppressedReads > 0 else { return }
        publicReadAdmissionJournalLines += 1
        publicReadDiagnosticLog.warning(
            "public read admission refusals suppressed",
            fields: [
                "did": did,
                "reason": failure.reason.rawValue,
                "suppressedReads": String(failure.suppressedReads),
            ]
        )
    }

    /// Test seam: journal lines this directory has emitted for public-read
    /// admission failures. Never consulted by production code.
    func publicReadAdmissionJournalLineCount() -> Int {
        publicReadAdmissionJournalLines
    }

    private func recheckPublicAccount(
        _ expected: AccountControlAccount,
        generation: SQLiteVerifiedPublicRepositoryGeneration
    ) async throws {
        guard !isClosed,
              databases[expected.did] != nil,
              publicReadGenerations[expected.did]?.id == generation.id else {
            throw PublicRepositoryReadError.unavailable(reason: .accountNotPreopened)
        }
        let current: AccountControlAccount?
        do {
            current = try await controlStore.account(did: expected.did)
        } catch {
            throw PublicRepositoryReadError.unavailable(reason: .controlStoreFailure)
        }
        guard let current, current == expected else {
            throw PublicRepositoryReadError.unavailable(reason: .controlRowChanged)
        }
        guard current.status == .active else {
            throw PublicRepositoryReadError.unavailable(reason: .accountNotActive)
        }
        guard !isClosed,
              databases[expected.did] != nil,
              publicReadGenerations[expected.did]?.id == generation.id else {
            throw PublicRepositoryReadError.unavailable(reason: .accountNotPreopened)
        }
        do {
            try Self.requireExistingRegularDatabase(
                SQLiteLayout.accountDatabase(
                    in: dataDirectory, did: expected.did
                )
            )
        } catch {
            throw PublicRepositoryReadError.unavailable(reason: .accountNotPreopened)
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

    private static func validatePublicRepositoryAdmission(
        database: SQLiteAccountDatabase,
        account: AccountControlAccount,
        identityVerifier: (any PublicPLCGenesisVerifying)?,
        controlStore: any AccountControlStore
    ) async throws -> SQLiteVerifiedPublicRepositoryGeneration? {
        let state = try await database.loadPublicRepositoryState()
        guard let identityVerifier else {
            // Explicit public-read-disabled mode must not normalize partially
            // provisioned public truth into an inaccessible nil generation.
            guard state == nil, account.publicGenesisCommitCID == nil else {
                throw PublicRepositoryReadError.unavailable(reason: .repositoryStateMismatch)
            }
            return nil
        }
        guard state != nil, account.publicGenesisCommitCID != nil else {
            throw PublicRepositoryReadError.unavailable(reason: .repositoryStateMissing)
        }
        let generation = try await database.admitPublicRepositoryGeneration(
            account: account,
            identityVerifier: identityVerifier
        )
        try await verifyPublicIdentityIntent(
            generation.description,
            controlStore: controlStore
        )
        return generation
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

/// Applies a public repository mutation while holding the control-plane
/// authorization transaction so no lifecycle transition can interleave with
/// the generation snapshot. An account that no longer authorizes is refused.
///
/// This used to fall back to a *non-emitting* mutation instead: the write
/// committed durably and no firehose event was published, which forks Swan's
/// repository from every relay's view of it silently and permanently. The
/// pinned reference PDS has no such concept — every write route calls
/// `findAccount(repo, { checkDeactivated: true, checkTakedown: true })` and
/// answers `AuthRequiredError('Account is deactivated', 'AccountDeactivated')`
/// before touching the repository
/// (`.interop-cache/atproto-3f6c96d5…/packages/pds/src/api/com/atproto/repo/`
/// `createRecord.ts:52-56`, and the same in `putRecord`, `deleteRecord` and
/// `applyWrites`).
///
/// Nothing pre-activation depends on the fallback: the genesis commit is
/// written by `PLCAccountPreparationService` against its own store, and this
/// fence is constructed only on the serve path
/// (`SwanCommand.swift:627`), whose route already requires `status == .active`
/// before it reaches here (`SwanPublicRepositoryMutationXRPC.swift:373`). What
/// the fallback actually covered was the race — a deactivation landing between
/// that check and this fence — and for that case a refusal is the honest
/// answer.
public struct PublicFirehoseCommitFence: Sendable {
    private let control: SQLiteControlDatabase

    public init(control: SQLiteControlDatabase) {
        self.control = control
    }

    public func apply(
        did: String,
        signingGeneration: UInt64,
        mutate: @escaping @Sendable (PublicFirehoseCommitContext?) async throws
            -> CommittedPublicRepositoryMutation
    ) async throws -> CommittedPublicRepositoryMutation {
        try await control.withActiveAccountFirehoseAuthorization(
            did: did,
            signingGeneration: signingGeneration
        ) {
            generation in
            try await mutate(.init(lifecycleGeneration: generation))
        }
    }
}

private actor SQLiteGenerationRefreshingPublicMutationStore:
    PublicRepositoryMutationStore,
    StreamingBlobStore
{
    let did: String
    let database: SQLiteAccountDatabase
    let directory: SQLitePreMigratedAccountDirectory
    let firehoseFence: PublicFirehoseCommitFence?

    init(
        did: String,
        database: SQLiteAccountDatabase,
        directory: SQLitePreMigratedAccountDirectory,
        firehoseFence: PublicFirehoseCommitFence?
    ) {
        self.did = did
        self.database = database
        self.directory = directory
        self.firehoseFence = firehoseFence
    }

    func loadPublicRepositoryState() async throws -> PublicRepositoryState? {
        try await database.loadPublicRepositoryState()
    }

    func verifyPublicRepositoryProjection() async throws {
        try await database.verifyPublicRepositoryProjection()
    }

    func block(for cid: CID) async throws -> Data? {
        try await database.block(for: cid)
    }

    func publicRepositoryRecordCID(
        for path: PublicRepositoryPath
    ) async throws -> CID? {
        try await database.publicRepositoryRecordCID(for: path)
    }

    func reservePublicRepositoryRevision(
        _ request: PublicRepositoryMutationRequest,
        wallClockMicroseconds: UInt64
    ) async throws -> PublicRepositoryMutationReservationOutcome {
        try await database.reservePublicRepositoryRevision(
            request,
            wallClockMicroseconds: wallClockMicroseconds
        )
    }

    func applyPublicRepositoryMutation(
        reservation: PublicRepositoryMutationReservation,
        prepared: PreparedPublicRepositoryMutation
    ) async throws -> CommittedPublicRepositoryMutation {
        let committed: CommittedPublicRepositoryMutation
        if let firehoseFence {
            committed = try await firehoseFence.apply(
                did: did,
                signingGeneration: prepared.signingGeneration
            ) { context in
                try await self.database.applyPublicRepositoryMutation(
                    reservation: reservation,
                    prepared: prepared,
                    firehose: context
                )
            }
        } else {
            committed = try await database.applyPublicRepositoryMutation(
                reservation: reservation,
                prepared: prepared
            )
        }
        // Scope note: only the refresh is allowed to fail quietly. Everything
        // above — the fence and the durable commit itself — has already
        // propagated its own errors from this method, so a write that did not
        // happen can never be reported as one that did.
        await directory.refreshPublicReadGenerationAfterMutation(
            did: did,
            database: database
        )
        return committed
    }

    func abandonPublicRepositoryReservation(
        _ reservation: PublicRepositoryMutationReservation
    ) async throws {
        try await database.abandonPublicRepositoryReservation(reservation)
    }

    // Public repository mutation targets are deliberately exposed through the
    // narrow mutation-store protocol above.  The HTTP upload/getBlob paths
    // need the separate streaming capability as well, but must retain the
    // generation-refreshing wrapper so a successful mutation still runs the
    // post-commit republication step — publish the new generation, or evict
    // the one the commit just invalidated — before the response is returned.
    // Delegate the blob surface here rather than handing the raw account
    // database to the request path, which would skip that step entirely and
    // leave the pre-mutation generation cached and answering reads.
    func put(
        _ data: Data,
        namespace: BlobNamespace
    ) async throws -> BlobReference {
        try await database.put(data, namespace: namespace)
    }

    func data(for reference: BlobReference) async throws -> Data {
        try await database.data(for: reference)
    }

    func publicData(cid: String) async throws -> Data? {
        try await database.publicData(cid: cid)
    }

    func remove(_ reference: BlobReference) async throws {
        try await database.remove(reference)
    }

    func putStreaming(
        namespace: BlobNamespace,
        mimeType: String?,
        maximumBytes: Int,
        source: @escaping @Sendable (
            @escaping (Data) async throws -> Void
        ) async throws -> Void
    ) async throws -> BlobReference {
        try await database.putStreaming(
            namespace: namespace,
            mimeType: mimeType,
            maximumBytes: maximumBytes,
            source: source
        )
    }

    func publicBlob(cid: String) async throws -> PublicBlob? {
        try await database.publicBlob(cid: cid)
    }

    func publicBlobExists(cid: String) async throws -> Bool {
        try await database.publicBlobExists(cid: cid)
    }

    func publicBlobMetadata(cid: String) async throws -> PublicBlobMetadata? {
        try await database.publicBlobMetadata(cid: cid)
    }

    func uploadedBlobMetadata(cid: String) async throws -> PublicBlobMetadata? {
        try await database.uploadedBlobMetadata(cid: cid)
    }
}

/// Public blob serving is narrower than retained namespace storage: a CID
/// must still be referenced by a public record when metadata or bytes open.
/// The database checks the record projection and namespace in one snapshot.
private struct SQLitePublicRepositoryReadBlobStore: PublicRepositoryReadBlobStore {
    let database: SQLiteAccountDatabase

    func publicBlob(cid: String) async throws -> PublicBlob? {
        try await database.publicRepositoryBlob(cid: cid)
    }

    func publicBlobMetadata(cid: String) async throws -> PublicBlobMetadata? {
        try await database.publicRepositoryBlobMetadata(cid: cid)
    }
}

/// A live repository write gate plus the number of batches that hold or are
/// waiting on it. The count is what makes the map self-pruning without a race:
/// an entry survives exactly as long as some batch is using it.
struct RepositoryWriteGateEntry {
    let gate: RepositoryWriteGate
    var users: Int
}

/// Single-holder FIFO admission for one repository's permissioned writes.
///
/// Deliberately separate from `ControlSQLiteConnectionGate` rather than a
/// reuse of it: that gate guards one process-wide connection and refuses with
/// the control plane's own exhaustion message, while this one is per
/// repository and refuses with the repository's.
actor RepositoryWriteGate {
    private struct Waiter {
        let id: UUID
        let continuation: CheckedContinuation<Void, Error>
    }

    private let maximumQueuedWaiters: Int
    private var isHeld = false
    private var waiters: [Waiter] = []

    init(maximumQueuedWaiters: Int = 128) {
        precondition(maximumQueuedWaiters > 0)
        self.maximumQueuedWaiters = maximumQueuedWaiters
    }

    func acquire() async throws {
        try Task.checkCancellation()
        if !isHeld {
            isHeld = true
            return
        }
        guard waiters.count < maximumQueuedWaiters else {
            throw SwanError.unavailable(
                "permissioned repository write capacity is exhausted"
            )
        }
        let id = UUID()
        try await withTaskCancellationHandler(
            operation: { try await self.enqueueWaiter(id: id) },
            onCancel: { Task { await self.cancelWaiter(id: id) } }
        )
        // A cancellation that lands after the hand-off would otherwise leak
        // the lease and wedge this repository for the process's lifetime.
        do {
            try Task.checkCancellation()
        } catch {
            release()
            throw error
        }
    }

    func release() {
        if waiters.isEmpty {
            isHeld = false
        } else {
            waiters.removeFirst().continuation.resume()
        }
    }

    private func cancelWaiter(id: UUID) {
        guard let index = waiters.firstIndex(where: { $0.id == id }) else {
            return
        }
        waiters.remove(at: index).continuation.resume(
            throwing: CancellationError()
        )
    }

    private func enqueueWaiter(id: UUID) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            if Task.isCancelled {
                continuation.resume(throwing: CancellationError())
                return
            }
            waiters.append(Waiter(id: id, continuation: continuation))
        }
    }

    func admissionSnapshotForTesting() -> (isHeld: Bool, queuedWaiters: Int) {
        (isHeld, waiters.count)
    }
}
