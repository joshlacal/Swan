import Foundation
import Hummingbird
import HummingbirdCore
import HummingbirdWebSocket
import HTTPTypes
import Logging
import NIOCore
import ServiceLifecycle
import SwanAccounts
import SwanCore
import SwanOAuth
import SwanPublicWire
import SwanSpaces
import SwanSpacesWire
import SwanStorage

/// Public-listener context retaining the accepted channel's direct socket
/// peer. Forwarded headers are deliberately not decoded into this type.
public struct SwanHTTPRequestContext:
    RequestContext,
    RemoteAddressRequestContext,
    @unchecked Sendable
{
    public var coreContext: CoreRequestContextStorage
    public let remoteAddress: SocketAddress?
    private let requestChannel: any Channel
    private let bodyTerminationState: SwanJSONWriteBodyTerminationState
    /// WebSocket handler slot set by a matched `router.ws` route. Never
    /// touched by plain HTTP routes; the upgrade channel reads it only after
    /// the route returned `.ok`.
    public let webSocket: WebSocketHandlerReference<SwanHTTPRequestContext>

    public init(source: ApplicationRequestContextSource) {
        coreContext = .init(source: source)
        remoteAddress = source.channel.remoteAddress
        requestChannel = source.channel
        bodyTerminationState = SwanJSONWriteBodyTerminationState()
        webSocket = .init()
    }

    /// Stops an admitted inbound body at an absolute deadline. Production
    /// HTTP/1 channels finish only Hummingbird's application stream, then keep
    /// reading and discarding the remainder while the response is written.
    /// The fallback is retained for direct test channels without that gate.
    var jsonWriteBodyTermination: SwanJSONWriteBodyTerminationHandle {
        SwanJSONWriteBodyTerminationHandle({
            bodyTerminationState.markTerminated()
            requestChannel.pipeline.context(handlerType: SwanJSONWriteBodyDrainHandler.self)
                .whenComplete { result in
                    switch result {
                    case .success:
                        requestChannel.pipeline.fireUserInboundEventTriggered(
                            SwanJSONWriteBodyDrainEvent()
                        )
                    case .failure:
                        requestChannel.close(mode: .input, promise: nil)
                    }
                }
        }, state: { bodyTerminationState.value })
    }
}

/// The `@unchecked Sendable` annotation above is scoped to the retained
/// `requestChannel`, which is only touched through NIO's thread-safe pipeline
/// API from the accepted channel's own event loop. `coreContext` and
/// `webSocket` are Sendable value types; `bodyTerminationState` is an
/// `NIOLockedValueBox`-backed Sendable. Without this conformance the ws route
/// could not store the context in its `WebSocketHandlerReference` slot.
extension SwanHTTPRequestContext: WebSocketRequestContext {}

// Keep the existing internal route-registration signatures compact while
// migrating the complete public router to the peer-retaining context.
typealias BasicRequestContext = SwanHTTPRequestContext

/// An explicit publication boundary for OAuth discovery. The only public
/// construction is `.unavailable`; a future complete HTTP assembly inside
/// `SwanHTTP` must supply validated metadata before discovery can return 200.
/// This prevents a caller from accidentally advertising incomplete PAR,
/// authorization, token, or revocation routes.
public struct OAuthPublicationGate: Sendable {
    private let publication: OAuthMetadataPublication?

    public static let unavailable = OAuthPublicationGate(publication: nil)

    init(completePublication: OAuthMetadataPublication) {
        publication = completePublication
    }

    private init(publication: OAuthMetadataPublication?) {
        self.publication = publication
    }

    func protectedResourceMetadata() -> OAuthProtectedResourceMetadata? {
        publication?.protectedResource
    }

    func authorizationServerMetadata() -> OAuthAuthorizationServerMetadata? {
        publication?.authorizationServer
    }
}

public struct SwanHTTPConfiguration: Sendable, Equatable {
    public let host: String
    public let port: Int
    public let publicURL: URL
    /// Maximum simultaneously accepted TCP connections for the Hummingbird
    /// listener. This is independent of body-stream admission: a slow reader
    /// must consume both a connection slot and a bounded transfer lease.
    public let maximumConnections: Int
    /// Idle HTTP/1 channels are closed after this interval. Response-stream
    /// admission remains the primary bound for slow blob/CAR consumers.
    public let idleTimeoutSeconds: Int
    /// What `com.atproto.server.describeServer` reports for
    /// `inviteCodeRequired`. Swan has no invite-code issuance, redemption, or
    /// enforcement anywhere in the process, so the only truthful value today
    /// is `false` and that is the default. The value is configuration rather
    /// than a literal so that if enforcement is ever added, the advertisement
    /// is switched on by the same assembly that switches on the enforcement
    /// instead of by editing a route body.
    public let inviteCodeRequired: Bool
    /// The public XRPC method contract this process registers, selected by
    /// profile id rather than named as a literal at the registration site. The
    /// default preserves the historical hardcoded surface; `swan serve` derives
    /// it from `--public-profile` and refuses to boot when that profile has no
    /// registered surface.
    public let publicRouteSurface: SwanPublicRouteSurface

    public init(
        host: String = "127.0.0.1",
        port: Int = 3000,
        publicURL: URL = URL(string: "http://127.0.0.1:3000")!,
        maximumConnections: Int = 256,
        idleTimeoutSeconds: Int = 60,
        inviteCodeRequired: Bool = false,
        publicRouteSurface: SwanPublicRouteSurface = .default
    ) {
        precondition(maximumConnections > 0)
        precondition(idleTimeoutSeconds > 0)
        self.host = host
        self.port = port
        self.publicURL = publicURL
        self.maximumConnections = maximumConnections
        self.idleTimeoutSeconds = idleTimeoutSeconds
        self.inviteCodeRequired = inviteCodeRequired
        self.publicRouteSurface = publicRouteSurface
    }
}

/// An explicit development-only opt-in for Swan's first live OAuth endpoint.
///
/// The value can be constructed only from an HTTPS issuer that passes the
/// same URL policy as the eventual authorization-server metadata. It does not
/// publish discovery metadata or make authorization, token, or revocation
/// routes available.
public struct SwanLocalhostPARConfiguration: Sendable, Equatable {
    public let issuer: URL

    public init(issuer: URL) throws {
        self.issuer = try OAuthAuthorizationServerMetadata(issuer: issuer).issuer
    }
}

/// An explicit local-laboratory OAuth authorization surface. It is restricted
/// to the AT Protocol localhost development-client exception: no remote client
/// metadata, confidential-client authentication, or discovery publication is
/// implied by constructing it. Password verification remains in
/// ``DurableAccountDirectory``; this configuration contains no password or
/// account-key material.
public struct SwanLocalhostOAuthConfiguration: Sendable {
    public let issuer: URL
    public let accounts: DurableAccountDirectory

    public init(issuer: URL, accounts: DurableAccountDirectory) throws {
        self.issuer = try OAuthAuthorizationServerMetadata(issuer: issuer).issuer
        self.accounts = accounts
    }
}

/// The complete, explicitly assembled authorization-server surface. This is
/// intentionally not a bag of optional route dependencies: it requires the
/// durable account authenticator, remote client-metadata loader, hardened
/// fetch policy, and the exact publication pair before Hummingbird can build
/// any authorization-server route.
public struct SwanOAuthAuthorizationServerConfiguration: Sendable {
    public let issuer: URL
    public let publication: OAuthMetadataPublication
    public let accounts: DurableAccountDirectory
    public let clientMetadataLoader: OAuthClientMetadataLoader
    public let remoteFetchPolicy: OAuthRemoteFetchPolicy

    public init(
        issuer: URL,
        protectedResource: URL,
        accounts: DurableAccountDirectory,
        clientMetadataLoader: OAuthClientMetadataLoader,
        scopesSupported: [String] = ["atproto"]
    ) throws {
        let metadata = try OAuthAuthorizationServerMetadata(
            issuer: issuer,
            scopesSupported: scopesSupported
        )
        self.issuer = metadata.issuer
        publication = try OAuthMetadataPublication(
            resource: protectedResource,
            issuer: metadata.issuer,
            scopesSupported: scopesSupported
        )
        self.accounts = accounts
        self.clientMetadataLoader = clientMetadataLoader
        // This immutable policy is retained as construction evidence only;
        // the loader remains the sole remote-fetch capability.
        remoteFetchPolicy = clientMetadataLoader.fetchPolicy
    }
}

/// The explicit, offline-only dependencies that enable the permissioned
/// delegation exchange and Bearer credential read paths. The server combines
/// these with the exact startup-preopened directory supplied to its
/// initializer, so an issuer cannot accidentally evaluate policy through an
/// arbitrary request-selected database. Every resolver is local or pinned;
/// none receives network authority from an HTTP request.
public struct SwanSpaceCredentialHTTPConfiguration: Sendable {
    let authoritySigningKeys: any SpaceCredentialSigningKeyResolver
    let delegationPublicKeys: any SpaceDelegationPublicKeyResolver
    let credentialPublicKeys: any SpaceCredentialPublicKeyResolver
    let clientAttestationPolicy: any SpaceCredentialClientAttestationPolicy

    public init(
        authoritySigningKeys: any SpaceCredentialSigningKeyResolver,
        delegationPublicKeys: any SpaceDelegationPublicKeyResolver,
        credentialPublicKeys: any SpaceCredentialPublicKeyResolver,
        clientAttestationPolicy: any SpaceCredentialClientAttestationPolicy = UnavailableSpaceCredentialClientAttestationPolicy()
    ) {
        self.authoritySigningKeys = authoritySigningKeys
        self.delegationPublicKeys = delegationPublicKeys
        self.credentialPublicKeys = credentialPublicKeys
        self.clientAttestationPolicy = clientAttestationPolicy
    }
}

/// Narrow credential-verification input for a capability that must accept a
/// space credential without thereby enabling credential reads everywhere.
/// In particular, a local interop server uses this only for repository sync;
/// record and blob routes remain OAuth-only unless the broader legacy
/// ``SwanSpaceCredentialHTTPConfiguration`` is explicitly supplied.
public struct SwanSpaceCredentialVerificationHTTPConfiguration: Sendable {
    let credentialPublicKeys: any SpaceCredentialPublicKeyResolver

    public init(credentialPublicKeys: any SpaceCredentialPublicKeyResolver) {
        self.credentialPublicKeys = credentialPublicKeys
    }
}

/// The explicit key-backed dependency required for a user PDS to mint a
/// proposal-0016 delegation.  This is intentionally separate from authority
/// credential exchange configuration: a user PDS does not consult authority
/// policy or membership before it signs the user's short-lived assertion.
public struct SwanSpaceDelegationHTTPConfiguration: Sendable {
    let tokenIssuer: any SpaceDelegationTokenIssuer

    public init(tokenIssuer: any SpaceDelegationTokenIssuer) {
        self.tokenIssuer = tokenIssuer
    }
}

/// The explicit account-key backed dependency for authenticated incremental
/// permissioned repository reads.  It deliberately exposes only fresh
/// proposal-0016 commit construction, not raw account signing or a database
/// connection.  Space-credential verification remains separately configured
/// through ``SwanSpaceCredentialHTTPConfiguration``.
public struct SwanSpaceRepositorySyncHTTPConfiguration: Sendable {
    let commitSigner: any SpaceRepositoryCommitSigner

    public init(commitSigner: any SpaceRepositoryCommitSigner) {
        self.commitSigner = commitSigner
    }
}

/// Explicitly enables only the local/pinned service-JWT verification needed
/// by the writer notification endpoints. Incoming service CLAIMS still never
/// turn an XRPC request into a network lookup; the one resolver here is used
/// solely by `registerNotify` (Erratum 03) to resolve the credentialed
/// caller's OWN `service` identifier through its DID document — a lookup the
/// caller explicitly requested by naming it.
public struct SwanSpaceNotificationHTTPConfiguration: Sendable {
    public let serviceAuthentication: any SpaceServiceAuthenticationVerifier
    let recipientBindings: SwanSpaceNotificationRecipientBindings
    let notificationJSONDecodeObserver: (@Sendable () async -> Void)?
    let serviceEndpointResolver: SwanServiceEndpointResolver?

    public init(
        serviceAuthentication: any SpaceServiceAuthenticationVerifier,
        recipientBindings: SwanSpaceNotificationRecipientBindings = .empty,
        serviceEndpointResolver: SwanServiceEndpointResolver? = nil
    ) {
        self.serviceAuthentication = serviceAuthentication
        self.recipientBindings = recipientBindings
        notificationJSONDecodeObserver = nil
        self.serviceEndpointResolver = serviceEndpointResolver
    }

    init(
        serviceAuthentication: any SpaceServiceAuthenticationVerifier,
        recipientBindings: SwanSpaceNotificationRecipientBindings = .empty,
        serviceEndpointResolver: SwanServiceEndpointResolver? = nil,
        notificationJSONDecodeObserver: @escaping @Sendable () async -> Void
    ) {
        self.serviceAuthentication = serviceAuthentication
        self.recipientBindings = recipientBindings
        self.notificationJSONDecodeObserver = notificationJSONDecodeObserver
        self.serviceEndpointResolver = serviceEndpointResolver
    }
}

/// Explicitly enables Swan's generic managing-app response for
/// `com.atproto.simplespace.checkUserAccess`.  It deliberately contains no
/// account directory, authority policy, or repository capability: a generic
/// PDS can verify who called it, but cannot make an application-policy grant.
public struct SwanSimpleSpaceCheckUserAccessHTTPConfiguration: Sendable {
    public let serviceAuthentication: any SpaceServiceAuthenticationVerifier
    let managingServiceAudience: String

    public init(
        serviceAuthentication: any SpaceServiceAuthenticationVerifier,
        managingServiceAudience: String
    ) throws {
        guard !managingServiceAudience.isEmpty,
              managingServiceAudience.utf8.count <= 2_048,
              managingServiceAudience.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw SwanError.malformed("managing service audience is invalid")
        }
        self.serviceAuthentication = serviceAuthentication
        self.managingServiceAudience = managingServiceAudience
    }
}

public struct SwanHTTPServer: Sendable {
    public let profile: ProtocolProfile
    public let configuration: SwanHTTPConfiguration
    public let repositories: any AccountRepositoryStore
    /// The durable OAuth control-plane runtime. The server deliberately has no
    /// `OAuthTokenVault` fallback: an incomplete or missing durable runtime is
    /// a startup failure, not a switch back to process-local bearer state.
    public let oauthRuntime: SwanOAuthRuntime
    /// Discovery is unavailable unless a later complete OAuth HTTP assembly
    /// explicitly supplies a ready gate. Durable OAuth primitives alone are
    /// not sufficient authorization-server behavior.
    public let oauthPublicationGate: OAuthPublicationGate
    /// The sole live OAuth alpha route. This never enables discovery or any
    /// other authorization-server endpoint.
    public let localhostPARConfiguration: SwanLocalhostPARConfiguration?
    /// The opt-in local browser authorization bridge. It is intentionally
    /// separate from PAR-only mode so a caller cannot make password pages
    /// appear merely by enabling the lower-risk PAR endpoint.
    public let localhostOAuthConfiguration: SwanLocalhostOAuthConfiguration?
    /// The complete remote/public and confidential authorization server. It
    /// cannot coexist with the narrower localhost bridge because both own the
    /// same PAR, browser, token, and revocation paths.
    public let authorizationServerConfiguration: SwanOAuthAuthorizationServerConfiguration?
    /// Resolves the password-login admission identity from the accepted socket
    /// peer and, only for explicitly trusted peers, Swan's single internal
    /// proxy header. The default ignores every forwarding header.
    public let loginClientIdentityPolicy: SwanLoginClientIdentityPolicy
    /// The one authenticated authority `getSpace` query. It is unavailable by
    /// default and only constructed from this server's runtime and canonical
    /// public URL after account databases have been preopened at startup.
    public let authenticatedGetSpace: SwanAuthenticatedGetSpaceCapability?
    /// The first authenticated permissioned record readers. They remain
    /// unavailable unless the supplied startup-preopened directory also
    /// implements the deliberately narrower repository projection.
    public let authenticatedSpaceRecords: SwanAuthenticatedSpaceRecordsCapability?
    /// Authenticated local-PDS space inventory. This remains distinct from
    /// record access and accepts only sender-constrained account OAuth.
    public let authenticatedSpaceList: SwanAuthenticatedSpaceListCapability?
    /// Authority-owned SimpleSpace lifecycle and membership endpoints. They
    /// remain closed unless the same startup-preopened directory explicitly
    /// exposes the narrower lifecycle projection.
    public let authenticatedSimpleSpaceLifecycle: SwanAuthenticatedSimpleSpaceLifecycleCapability?
    /// The authority-only delegation exchange. It remains unavailable unless
    /// a caller supplied local/pinned key resolvers and the same startup
    /// directory exposes the narrow durable credential-policy projection.
    public let authenticatedSpaceCredentialExchange: SwanSpaceCredentialExchangeCapability?
    /// User-PDS delegation minting remains unavailable unless an explicit
    /// AccountKeyStore-backed issuer and a startup-preopened account directory
    /// are both supplied alongside durable DPoP OAuth authorization.
    public let authenticatedSpaceDelegationMinting: SwanSpaceDelegationMintingCapability?
    /// Read-only current-commit and incremental-oplog endpoints.  They remain
    /// closed until a startup-preopened repository directory and narrow
    /// account-key commit signer are both explicitly configured.
    public let authenticatedSpaceRepositorySync: SwanAuthenticatedSpaceRepositorySyncCapability?
    /// Private, descriptor-streamed permissioned blob reads.  This remains
    /// closed unless the startup directory exposes the dedicated blob
    /// projection; it is intentionally independent of public blob routes.
    public let authenticatedSpaceBlobs: SwanAuthenticatedSpaceBlobCapability?
    /// Credential-only writer discovery/registration and service-authenticated
    /// notification receivers. It is closed unless both an exact preopened
    /// notification directory and local/pinned service verifier are supplied.
    public let authenticatedSpaceNotifications: SwanAuthenticatedSpaceNotificationsCapability?
    /// The standalone managing-app service-auth endpoint. Unlike authority
    /// routes, this has no storage dependency and always returns the pinned
    /// generic PDS denial after authenticating its service caller.
    public let simpleSpaceCheckUserAccess: SwanSimpleSpaceCheckUserAccessCapability?
    /// Public-only read capability selected from the startup-preopened account
    /// inventory. It contains no authorization or permissioned-data fallback.
    public let publicRepositoryReadDirectory: (any PublicRepositoryReadDirectory)?
    /// Unauthenticated `com.atproto.identity.resolveHandle`. It is formed
    /// whenever an account control store is configured, and its route is
    /// installed only alongside ``publicRepositoryReadDirectory`` — a server
    /// exposing no public reads must not expose an anonymous handle->DID
    /// oracle. It depends on none of that directory's *health*: handle
    /// resolution reads one control row and keeps working when repository
    /// generation admission does not.
    public let publicHandleResolution: SwanPublicHandleResolutionCapability?
    /// Explicitly opt-in public mutation capability. Public reads never imply
    /// this capability, and it is only formed alongside the server-bound
    /// OAuth resource authorizer.
    public let publicRepositoryMutations: SwanPublicRepositoryMutationCapability?
    /// Durable account-email confirmation and password-recovery routes. This
    /// capability is nil unless the caller has assembled the proof codec,
    /// control-store adapter, rate limiter, and SMTP worker at startup.
    public let accountEmailXRPC: SwanAccountEmailXRPCServer?
    public let legacySessionXRPC: SwanLegacySessionXRPCServer?
    /// Optional account portal bundle. Its registration owns `/account/api/**`
    /// and `/account/**` and is installed before every XRPC or proxy fallback.
    public let accountPortalHTTP: SwanAccountPortalHTTP?
    /// Optional account lifecycle XRPC adapter. When present, its
    /// `com.atproto.server.createAccount` route is registered before the
    /// unknown-public guards; the lifecycle methods (activate/status/
    /// deactivate/delete/invite/listInvites) are operator/management-session
    /// authorized and are not registered as live public routes in this task.
    public let accountLifecycleXRPC: SwanAccountLifecycleXRPCAdapter?
    /// Optional did:web identity surface. When present, its public one-time
    /// claim endpoint and management-session-authenticated reserve/claim/
    /// rotate/remove/reverify/admission routes are registered before the
    /// unknown-public guards and the `/xrpc/**` proxy fallback.
    public let didWebIdentityHTTP: SwanDidWebIdentityHTTP?
    /// Local `app.bsky.actor.getPreferences` / `app.bsky.actor.putPreferences`
    /// routes. These can never be proxied to an AppView — the AppView does
    /// not store preferences, the PDS does — so this capability is nil unless
    /// the caller has assembled a resource authorizer and a durable
    /// preferences store at startup.
    public let actorPreferencesXRPC: SwanActorPreferencesXRPCServer?
    /// The `/xrpc/**` AppView proxy fallback. It is registered last and is the
    /// lowest-priority route in the trie, so it can only ever answer a request
    /// that no local Swan route claimed. Nil keeps Swan's pre-proxy behavior:
    /// an unknown XRPC method is simply not found here.
    public let xrpcPipethrough: SwanXRPCPipethroughServer?
    /// Shared process-wide/per-account admission for descriptor-backed blob
    /// responses. The CLI passes the preopened directory's instance so
    /// public CAR, upload, and blob budgets remain coordinated.
    public let blobStreamAdmission: PublicRepositorySpoolAdmission
    /// Shared process-wide/per-account admission for allocation-heavy JSON
    /// responses. Public and permissioned read routes must use the same
    /// instance; otherwise a caller-provided test/production budget can be
    /// silently replaced by the global default during router construction.
    public let jsonReadAdmission: PublicRepositoryJSONReadAdmission
    /// Shared aggregate bound for buffered public and permissioned JSON
    /// command bodies.
    public let jsonWriteAdmission: PublicRepositoryJSONWriteAdmission
    /// The anonymous `com.atproto.sync.getBlob` route's own inbound-body
    /// admission. Deliberately not ``jsonWriteAdmission``: an anonymous read
    /// must not be able to hold the leases the authenticated JSON commands
    /// reserve from.
    public let publicBlobRequestBodyAdmission: PublicRepositoryJSONWriteAdmission
    /// Shared finite total elapsed-time policy for admitted JSON command
    /// bodies. This is distinct from the listener's resettable idle timeout.
    public let jsonWriteBodyPolicy: SwanJSONWriteBodyPolicy
    /// The durable public firehose streaming runtime backing
    /// `com.atproto.sync.subscribeRepos`. Nil keeps the legacy wildcard-404
    /// behavior for the endpoint; non-nil registers the WebSocket route.
    public let publicFirehoseStreaming: SwanPublicFirehoseStreamingRuntime?
    /// How much of this listener's connection budget anonymous
    /// `subscribeRepos` subscribers may hold at once. Sized here, from
    /// ``SwanHTTPConfiguration/maximumConnections``, because the reservation
    /// only means anything relative to the budget it reserves *from* — an
    /// upgraded WebSocket holds its listener slot until the channel closes.
    public let publicFirehoseSubscriberAdmission: PublicFirehoseSubscriberAdmission

    public init(
        profile: ProtocolProfile,
        configuration: SwanHTTPConfiguration = .init(),
        repositories: any AccountRepositoryStore = InMemoryAccountRepositoryStore(),
        oauthRuntime: SwanOAuthRuntime,
        oauthPublicationGate: OAuthPublicationGate = .unavailable,
        localhostPARConfiguration: SwanLocalhostPARConfiguration? = nil,
        localhostOAuthConfiguration: SwanLocalhostOAuthConfiguration? = nil,
        authorizationServerConfiguration: SwanOAuthAuthorizationServerConfiguration? = nil,
        authenticatedGetSpaceDirectory: (any AuthorizedSimpleSpaceDirectory)? = nil,
        accountControlStore: (any AccountControlStore)? = nil,
        spaceCredentialConfiguration: SwanSpaceCredentialHTTPConfiguration? = nil,
        spaceCredentialExchangeConfiguration: SwanSpaceCredentialHTTPConfiguration? = nil,
        spaceDelegationConfiguration: SwanSpaceDelegationHTTPConfiguration? = nil,
        spaceRepositorySyncConfiguration: SwanSpaceRepositorySyncHTTPConfiguration? = nil,
        spaceRepositoryCredentialConfiguration: SwanSpaceCredentialVerificationHTTPConfiguration? = nil,
        spaceNotificationConfiguration: SwanSpaceNotificationHTTPConfiguration? = nil,
        simpleSpaceCheckUserAccessConfiguration: SwanSimpleSpaceCheckUserAccessHTTPConfiguration? = nil,
        publicRepositoryReadDirectory: (any PublicRepositoryReadDirectory)? = nil,
        publicRepositoryMutationDirectory: (any PublicRepositoryMutationDirectory)? = nil,
        publicRepositoryMutationSignerProvider: (any PublicRepositoryMutationSignerProvider)? = nil,
        publicBlobSpoolAdmission: PublicRepositorySpoolAdmission? = nil,
        blobStreamAdmission: PublicRepositorySpoolAdmission? = nil,
        accountEmailXRPC: SwanAccountEmailXRPCServer? = nil,
        legacySessionXRPC: SwanLegacySessionXRPCServer? = nil,
        accountPortalHTTP: SwanAccountPortalHTTP? = nil,
        accountLifecycleXRPC: SwanAccountLifecycleXRPCAdapter? = nil,
        didWebIdentityHTTP: SwanDidWebIdentityHTTP? = nil,
        // Kept as a source-compatible, inert parameter for callers compiled
        // against the account-program merge. Legacy XRPC is owned solely by
        // `SwanLegacySessionXRPCServer`; this adapter is never registered.
        legacyAuthXRPC: SwanLegacyAuthXRPCAdapter? = nil,
        actorPreferencesXRPC: SwanActorPreferencesXRPCServer? = nil,
        xrpcPipethrough: SwanXRPCPipethroughServer? = nil,
        loginClientIdentityPolicy: SwanLoginClientIdentityPolicy = .direct,
        jsonReadAdmission: PublicRepositoryJSONReadAdmission? = nil,
        jsonWriteAdmission: PublicRepositoryJSONWriteAdmission? = nil,
        publicBlobRequestBodyAdmission: PublicRepositoryJSONWriteAdmission? = nil,
        jsonWriteBodyPolicy: SwanJSONWriteBodyPolicy? = nil,
        publicFirehoseStreaming: SwanPublicFirehoseStreamingRuntime? = nil,
        publicFirehoseSubscriberAdmission: PublicFirehoseSubscriberAdmission? = nil
    ) {
        self.profile = profile
        self.configuration = configuration
        self.repositories = repositories
        self.oauthRuntime = oauthRuntime
        self.loginClientIdentityPolicy = loginClientIdentityPolicy
        self.publicRepositoryReadDirectory = publicRepositoryReadDirectory
        publicHandleResolution = accountControlStore.map {
            SwanPublicHandleResolutionCapability(controlStore: $0)
        }
        self.accountEmailXRPC = accountEmailXRPC
        self.legacySessionXRPC = legacySessionXRPC
        self.accountPortalHTTP = accountPortalHTTP
        self.accountLifecycleXRPC = accountLifecycleXRPC
        self.didWebIdentityHTTP = didWebIdentityHTTP
        _ = legacyAuthXRPC
        self.actorPreferencesXRPC = actorPreferencesXRPC
        self.xrpcPipethrough = xrpcPipethrough
        self.publicFirehoseStreaming = publicFirehoseStreaming
        self.publicFirehoseSubscriberAdmission = publicFirehoseSubscriberAdmission
            ?? PublicFirehoseSubscriberAdmission(
                listenerBudget: configuration.maximumConnections
            )
        let resolvedJSONReadAdmission = jsonReadAdmission
            ?? PublicRepositoryJSONReadAdmission.processShared
        self.jsonReadAdmission = resolvedJSONReadAdmission
        let resolvedJSONWriteAdmission = jsonWriteAdmission
            ?? PublicRepositoryJSONWriteAdmission.processShared
        self.jsonWriteAdmission = resolvedJSONWriteAdmission
        let resolvedPublicBlobRequestBodyAdmission = publicBlobRequestBodyAdmission
            ?? PublicRepositoryJSONWriteAdmission.publicBlobReadProcessShared
        self.publicBlobRequestBodyAdmission = resolvedPublicBlobRequestBodyAdmission
        let resolvedJSONWriteBodyPolicy = jsonWriteBodyPolicy
            ?? SwanJSONWriteBodyPolicy.productionDefault
        self.jsonWriteBodyPolicy = resolvedJSONWriteBodyPolicy
        self.blobStreamAdmission = blobStreamAdmission
            ?? publicBlobSpoolAdmission
            ?? PublicRepositorySpoolAdmission.shared
        if let simpleSpaceCheckUserAccessConfiguration {
            simpleSpaceCheckUserAccess = SwanSimpleSpaceCheckUserAccessCapability(
                serviceAuthentication: simpleSpaceCheckUserAccessConfiguration.serviceAuthentication,
                managingServiceAudience: simpleSpaceCheckUserAccessConfiguration.managingServiceAudience
            )
        } else {
            simpleSpaceCheckUserAccess = nil
        }
        // A caller may not smuggle metadata publication through a partial
        // assembly. Only the complete remote authorization-server config can
        // publish discovery; all other inputs remain closed by default.
        if let authorizationServerConfiguration,
           authorizationServerConfiguration.issuer.absoluteString == configuration.publicURL.absoluteString,
           authorizationServerConfiguration.publication.protectedResource.resource.absoluteString == configuration.publicURL.absoluteString {
            self.authorizationServerConfiguration = authorizationServerConfiguration
            self.oauthPublicationGate = OAuthPublicationGate(
                completePublication: authorizationServerConfiguration.publication
            )
        } else {
            self.authorizationServerConfiguration = nil
            self.oauthPublicationGate = .unavailable
        }
        // A mismatched issuer would produce a DPoP target different from the
        // process's public identity. There is no best-effort normalization:
        // retain the default 404 closure instead.
        let matchesPublicIdentity: (URL) -> Bool = {
            $0.absoluteString == configuration.publicURL.absoluteString
        }
        if self.authorizationServerConfiguration != nil {
            self.localhostOAuthConfiguration = nil
            self.localhostPARConfiguration = nil
        } else if let localhostOAuthConfiguration,
           matchesPublicIdentity(localhostOAuthConfiguration.issuer) {
            self.localhostOAuthConfiguration = localhostOAuthConfiguration
            // The complete local bridge includes PAR. Do not permit a second
            // caller-selected PAR configuration to make route selection
            // ambiguous.
            self.localhostPARConfiguration = nil
        } else {
            self.localhostOAuthConfiguration = nil
            if let localhostPARConfiguration,
               matchesPublicIdentity(localhostPARConfiguration.issuer) {
                self.localhostPARConfiguration = localhostPARConfiguration
            } else {
                self.localhostPARConfiguration = nil
            }
        }
        // Never accept a caller-supplied authorizer here: it might bind DPoP
        // to another public URL or runtime. Failure to form the exact local
        // binding is a safe closed route, not a best-effort fallback.
        if let authenticatedGetSpaceDirectory,
           let accountControlStore,
           Self.permitsResourceAuthorization(on: configuration),
           let authorizer = try? SwanOAuthResourceAuthorizer(
               publicURL: configuration.publicURL,
               runtime: oauthRuntime,
               accountControlStore: accountControlStore,
               // `nil` unless the deployment enabled legacy sessions, which
               // leaves this authorizer DPoP-only exactly as before.
               legacySessions: legacySessionXRPC?.sessions
           ) {
            // Formed once, ahead of every capability that verifies compact
            // space credentials — including the description endpoint, whose
            // live contract admits a member hosted elsewhere by credential.
            let getSpaceCredentialVerifier: (any SpaceCredentialAuthorizationVerifier)?
            if let spaceCredentialConfiguration {
                getSpaceCredentialVerifier = DurableSpaceCredentialVerifier(
                    publicKeys: spaceCredentialConfiguration.credentialPublicKeys
                )
            } else {
                getSpaceCredentialVerifier = nil
            }
            authenticatedGetSpace = SwanAuthenticatedGetSpaceCapability(
                authorizer: authorizer,
                directory: authenticatedGetSpaceDirectory,
                credentialAuthorizer: getSpaceCredentialVerifier
            )
            if let mutationDirectory = publicRepositoryMutationDirectory,
               let signerProvider = publicRepositoryMutationSignerProvider {
                publicRepositoryMutations = SwanPublicRepositoryMutationCapability(
                    authorizer: authorizer,
                    directory: mutationDirectory,
                    signerProvider: signerProvider,
                    publicBlobSpoolAdmission: publicBlobSpoolAdmission,
                    jsonWriteAdmission: resolvedJSONWriteAdmission,
                    jsonWriteBodyPolicy: resolvedJSONWriteBodyPolicy
                )
            } else {
                publicRepositoryMutations = nil
            }
            if let repositoryDirectory = authenticatedGetSpaceDirectory
                as? any AuthorizedSpaceRepositoryDirectory {
                let credentialVerifier = getSpaceCredentialVerifier
                authenticatedSpaceRecords = SwanAuthenticatedSpaceRecordsCapability(
                    authorizer: authorizer,
                    directory: repositoryDirectory,
                    credentialAuthorizer: credentialVerifier,
                    jsonReadAdmission: resolvedJSONReadAdmission,
                    jsonWriteAdmission: resolvedJSONWriteAdmission,
                    jsonWriteBodyPolicy: resolvedJSONWriteBodyPolicy
                )
            } else {
                authenticatedSpaceRecords = nil
            }
            if let hostedSpaceDirectory = authenticatedGetSpaceDirectory
                as? any AuthorizedHostedSpaceDirectory {
                authenticatedSpaceList = SwanAuthenticatedSpaceListCapability(
                    authorizer: authorizer,
                    directory: hostedSpaceDirectory
                )
            } else {
                authenticatedSpaceList = nil
            }
            if let lifecycleDirectory = authenticatedGetSpaceDirectory
                as? any AuthorizedSimpleSpaceLifecycleDirectory {
                authenticatedSimpleSpaceLifecycle = SwanAuthenticatedSimpleSpaceLifecycleCapability(
                    authorizer: authorizer,
                    directory: lifecycleDirectory,
                    jsonWriteAdmission: resolvedJSONWriteAdmission,
                    jsonWriteBodyPolicy: resolvedJSONWriteBodyPolicy
                )
            } else {
                authenticatedSimpleSpaceLifecycle = nil
            }
            // The exchange can be enabled independently of broad credential
            // reads.  Retain the pre-existing global configuration as the
            // fallback for callers that deliberately opted into every legacy
            // credential-bearing capability.
            let exchangeCredentialConfiguration =
                spaceCredentialExchangeConfiguration ?? spaceCredentialConfiguration
            if let credentialDirectory = authenticatedGetSpaceDirectory
                as? any AuthorizedSimpleSpaceCredentialDirectory,
               let exchangeCredentialConfiguration {
                authenticatedSpaceCredentialExchange = SwanSpaceCredentialExchangeCapability(
                    delegationAuthorizer: DurableSpaceDelegationVerifier(
                        publicKeys: exchangeCredentialConfiguration.delegationPublicKeys
                    ),
                    delegationReplayStore: oauthRuntime.spaceDelegationReplayStore,
                    credentialIssuer: DurableSpaceCredentialAuthority(
                        policyDirectory: credentialDirectory,
                        signingKeys: exchangeCredentialConfiguration.authoritySigningKeys,
                        clientAttestationPolicy: exchangeCredentialConfiguration.clientAttestationPolicy
                    )
                )
            } else {
                authenticatedSpaceCredentialExchange = nil
            }
            if let preopenedAccountDirectory = authenticatedGetSpaceDirectory
                as? any AuthorizedPreopenedAccountDirectory,
               let spaceDelegationConfiguration {
                authenticatedSpaceDelegationMinting = SwanSpaceDelegationMintingCapability(
                    authorizer: authorizer,
                    accounts: preopenedAccountDirectory,
                    tokenIssuer: spaceDelegationConfiguration.tokenIssuer
                )
            } else {
                authenticatedSpaceDelegationMinting = nil
            }
            if let repositoryDirectory = authenticatedGetSpaceDirectory
                as? any AuthorizedSpaceRepositoryDirectory,
               let spaceRepositorySyncConfiguration {
                let credentialVerifier: (any SpaceCredentialAuthorizationVerifier)?
                if let spaceRepositoryCredentialConfiguration {
                    credentialVerifier = DurableSpaceCredentialVerifier(
                        publicKeys: spaceRepositoryCredentialConfiguration.credentialPublicKeys
                    )
                } else if let spaceCredentialConfiguration {
                    credentialVerifier = DurableSpaceCredentialVerifier(
                        publicKeys: spaceCredentialConfiguration.credentialPublicKeys
                    )
                } else {
                    credentialVerifier = nil
                }
                authenticatedSpaceRepositorySync = SwanAuthenticatedSpaceRepositorySyncCapability(
                    authorizer: authorizer,
                    directory: repositoryDirectory,
                    credentialAuthorizer: credentialVerifier,
                    commitSigner: spaceRepositorySyncConfiguration.commitSigner,
                    jsonReadAdmission: resolvedJSONReadAdmission
                )
            } else {
                authenticatedSpaceRepositorySync = nil
            }
            if let blobDirectory = authenticatedGetSpaceDirectory
                as? any AuthorizedSpaceBlobDirectory {
                let credentialVerifier: (any SpaceCredentialAuthorizationVerifier)?
                if let spaceCredentialConfiguration {
                    credentialVerifier = DurableSpaceCredentialVerifier(
                        publicKeys: spaceCredentialConfiguration.credentialPublicKeys
                    )
                } else {
                    credentialVerifier = nil
                }
                authenticatedSpaceBlobs = SwanAuthenticatedSpaceBlobCapability(
                    authorizer: authorizer,
                    directory: blobDirectory,
                    credentialAuthorizer: credentialVerifier,
                    streamAdmission: self.blobStreamAdmission
                )
            } else {
                authenticatedSpaceBlobs = nil
            }
            if let notificationDirectory = authenticatedGetSpaceDirectory
                as? any AuthorizedSpaceNotificationDirectory,
               let spaceCredentialConfiguration,
               let spaceNotificationConfiguration {
                authenticatedSpaceNotifications = SwanAuthenticatedSpaceNotificationsCapability(
                    directory: notificationDirectory,
                    credentialAuthorizer: DurableSpaceCredentialVerifier(
                        publicKeys: spaceCredentialConfiguration.credentialPublicKeys
                    ),
                    serviceAuthentication: spaceNotificationConfiguration.serviceAuthentication,
                    recipientBindings: spaceNotificationConfiguration.recipientBindings,
                    notificationJSONDecodeObserver:
                        spaceNotificationConfiguration.notificationJSONDecodeObserver,
                    serviceEndpointResolver:
                        spaceNotificationConfiguration.serviceEndpointResolver
                )
            } else {
                authenticatedSpaceNotifications = nil
            }
        } else {
            authenticatedGetSpace = nil
            publicRepositoryMutations = nil
            authenticatedSpaceRecords = nil
            authenticatedSpaceList = nil
            authenticatedSimpleSpaceLifecycle = nil
            authenticatedSpaceCredentialExchange = nil
            authenticatedSpaceDelegationMinting = nil
            authenticatedSpaceRepositorySync = nil
            authenticatedSpaceBlobs = nil
            authenticatedSpaceNotifications = nil
        }
    }

    /// HTTPS resource identities may be reverse-proxied in the normal way.
    /// A cleartext identity is only a local lab escape hatch, so require the
    /// actual listener to be a literal loopback address on the same port.
    /// This prevents `http://127.0.0.1` from being advertised while Hummingbird
    /// is really accepting DPoP credentials on `0.0.0.0`.
    private static func permitsResourceAuthorization(
        on configuration: SwanHTTPConfiguration
    ) -> Bool {
        guard configuration.publicURL.scheme?.lowercased() == "http" else {
            return true
        }
        guard (configuration.publicURL.port ?? 80) == configuration.port else {
            return false
        }
        return switch configuration.host.lowercased() {
        case "127.0.0.1", "::1": true
        default: false
        }
    }

    /// All routes are registered before Application construction. Hummingbird
    /// ignores routes appended after app initialization, so this is the only
    /// supported server assembly boundary.
    public func buildRouter() -> Router<SwanHTTPRequestContext> {
        let router = Router(context: SwanHTTPRequestContext.self)
        // MUST precede every route registration below. Hummingbird bakes the
        // middleware stack into each responder as the route is added
        // (`Router.swift:90`), so a middleware registered later silently binds
        // to nothing. Registering it first also covers the not-found responder
        // (`Router.swift:70`), which is the exact path a preflight takes when
        // a path matches but the method has no responder.
        router.add(middleware: SwanCORSMiddleware<SwanHTTPRequestContext>())
        let requestBodyAdmission = SwanRequestBodyAdmissionConfiguration(
            admission: jsonWriteAdmission,
            policy: jsonWriteBodyPolicy
        )
        router.get("/health") { _, _ in "OK" }

        // The portal registers its explicit API routes and API catch-all
        // before the SPA fallback. Installing the entire bundle here, before
        // OAuth/XRPC/proxy routes, preserves that precedence at the sole
        // supported router assembly boundary.
        accountPortalHTTP?.register(on: router)

        // The did:web identity surface registers its public one-time claim
        // endpoint and management-session-authenticated account API routes
        // before the unknown-public guards and the `/xrpc/**` proxy fallback.
        // The claim endpoint is public by design (the external domain operator
        // must fetch the claim bytes without a Swan credential); the account
        // API routes enforce the same cookie/CSRF/origin policy as the portal.
        if let didWebIdentityHTTP {
            registerSwanDidWebIdentityRoutes(
                on: router,
                didWeb: didWebIdentityHTTP,
                publicOrigin: configuration.publicURL,
                requestBodyAdmission: requestBodyAdmission
            )
        }

        let publicURL = configuration.publicURL
        let profile = profile
        let oauthPublicationGate = oauthPublicationGate
        // One derivation, read by both the DID document and describeServer.
        // A resolver reads `describeServer.did`, fetches the document that DID
        // names, and compares the two; formatting the identity twice is how
        // those two answers silently drift apart.
        let serviceIdentity = SwanServiceIdentity(publicURL: publicURL)
        let inviteCodeRequired = configuration.inviteCodeRequired
        // `did:web:<authority>` resolves to
        // `https://<authority>/.well-known/did.json`, so this route is the
        // other half of the DID Swan publishes everywhere else. The body is
        // public, static, non-secret identity data.
        router.get("/.well-known/did.json") { _, _ -> Response in
            oauthMetadataJSONResponse(SwanServiceDIDDocument(identity: serviceIdentity))
        }
        router.on("/.well-known/did.json", method: .options) { _, _ -> Response in
            oauthMetadataCORSPreflightResponse()
        }
        router.get("/.well-known/oauth-protected-resource") { _, _ -> Response in
            guard let metadata = oauthPublicationGate.protectedResourceMetadata() else {
                return oauthUnavailable()
            }
            return oauthMetadataJSONResponse(metadata)
        }
        router.on("/.well-known/oauth-protected-resource", method: .options) { _, _ -> Response in
            guard oauthPublicationGate.protectedResourceMetadata() != nil else {
                return oauthUnavailable()
            }
            return oauthMetadataCORSPreflightResponse()
        }
        router.get("/.well-known/oauth-authorization-server") { _, _ -> Response in
            guard let metadata = oauthPublicationGate.authorizationServerMetadata() else {
                return oauthUnavailable()
            }
            return oauthMetadataJSONResponse(metadata)
        }
        router.on("/.well-known/oauth-authorization-server", method: .options) { _, _ -> Response in
            guard oauthPublicationGate.authorizationServerMetadata() != nil else {
                return oauthUnavailable()
            }
            return oauthMetadataCORSPreflightResponse()
        }

        if let authorizationServerConfiguration {
            registerOAuthAuthorizationServerEndpoints(
                on: router,
                configuration: authorizationServerConfiguration,
                runtime: oauthRuntime,
                loginClientIdentityPolicy: loginClientIdentityPolicy,
                requestBodyAdmission: requestBodyAdmission
            )
            registerOAuthAuthorizationServerPAREndpoint(
                on: router,
                configuration: authorizationServerConfiguration,
                runtime: oauthRuntime,
                loginClientIdentityPolicy: loginClientIdentityPolicy,
                requestBodyAdmission: requestBodyAdmission
            )
        } else if let localhostOAuthConfiguration {
            registerLocalhostOAuthEndpoints(
                on: router,
                configuration: localhostOAuthConfiguration,
                runtime: oauthRuntime,
                loginClientIdentityPolicy: loginClientIdentityPolicy,
                requestBodyAdmission: requestBodyAdmission
            )
        } else {
            router.get("/oauth/authorize") { _, _ -> Response in
                oauthUnavailable()
            }
        }

        // This narrow development bridge stores a durable PAR only. It does
        // not publish discovery and cannot lead to login, consent, codes, or
        // tokens until a complete OAuth HTTP assembly is separately enabled.
        if authorizationServerConfiguration != nil {
            // Registered above as one inseparable authorization-server bundle.
        } else if let localhostOAuthConfiguration {
            registerLocalhostPAREndpoint(
                on: router,
                issuer: localhostOAuthConfiguration.issuer,
                runtime: oauthRuntime,
                requestBodyAdmission: requestBodyAdmission
            )
        } else if let localhostPARConfiguration {
            registerLocalhostPAREndpoint(
                on: router,
                configuration: localhostPARConfiguration,
                runtime: oauthRuntime,
                requestBodyAdmission: requestBodyAdmission
            )
        }

        router.get("/xrpc/com.atproto.server.describeServer") { _, _ -> Response in
            jsonResponse(ServerDescription(
                did: serviceIdentity.did,
                availableUserDomains: [],
                inviteCodeRequired: inviteCodeRequired,
                swanProfile: profile.id
            ))
        }

        // `community.lexicon.service.describe` — the community proposal that
        // lets a caller ask which XRPC methods a service serves instead of
        // trying each one and reading the failures. Clients gate on it:
        // bulleted.app refuses to enable its spaces support when this answer
        // is missing, because a 404 here is indistinguishable from a server
        // with no spaces plane. The answer is derived from the same two
        // inputs that install routes below — the selected permissioned
        // profile and the public route surface — so it cannot drift from the
        // router the way a hand-kept list would. Profile methods whose
        // capability is absent still appear: they are routed (as
        // method-correct unavailability gates), and this deployment speaks
        // them.
        var describedMethodSet = Set(
            PermissionedData0016.methods
                .filter { profile.endpoints.contains($0.nsid) }
                .map(\.nsid)
        )
        .union(configuration.publicRouteSurface.servedMethodNSIDs)
        .union([
            "com.atproto.server.describeServer",
            // This method itself: a description that omitted it would be the
            // one claim a caller could disprove from the response in hand.
            "community.lexicon.service.describe",
        ])
        // The `getRepoState` alias is listed exactly when its route is live —
        // the sync capability exists and the profile declares the canonical
        // name (see `registerAuthenticatedGetLatestCommitEndpoint`). Listing
        // one routed name but not the other would 404 the very probe this
        // endpoint exists to answer.
        if authenticatedSpaceRepositorySync != nil,
           describedMethodSet.contains(ComAtprotoSpaceGetLatestCommit.typeIdentifier) {
            describedMethodSet.insert(spaceGetRepoStateAliasNSID)
        }
        let describedMethodNSIDs = describedMethodSet.sorted()
        router.get("/xrpc/community.lexicon.service.describe") { _, _ -> Response in
            jsonResponse(CommunityServiceDescription(
                roles: ["pds"],
                methods: describedMethodNSIDs.map(CommunityServiceMethodReference.init(value:))
            ))
        }

        // `com.atproto.server.createAccount` is Swan's own PDS method and is
        // registered before the unknown-public guards and the `/xrpc/**`
        // proxy fallback. The adapter fails closed (503) when the signup
        // runtime is not assembled; a registered route is never a bare 404.
        if let accountLifecycleXRPC {
            let adapter = accountLifecycleXRPC
            router.post("/xrpc/com.atproto.server.createAccount") { request, context async -> Response in
                let now = Date()
                do {
                    let input: SwanCreateAccountXRPCInput = try await decodeCreateAccountBody(
                        request,
                        context: context,
                        requestBodyAdmission: requestBodyAdmission
                    )
                    let result = try await adapter.createAccount(
                        input,
                        peerAddress: context.remoteAddress,
                        now: now
                    )
                    return jsonResponseWithStatus(.ok, body: CreateAccountResponse(
                        did: result.account.did,
                        handle: result.account.canonicalHandle,
                        accessJwt: "",
                        refreshJwt: ""
                    ))
                } catch {
                    return lifecycleErrorResponse(for: error)
                }
            }
        }

        // Do not route permissioned traffic to the in-memory repository store
        // while durable OAuth and account control have no HTTP entry points.
        // The checked-in wire registry is the sole source for this coverage:
        // every profile method gets an explicit, method-correct closed handler
        // until its authenticated implementation is ready.
        var installedSimpleSpaceLifecycle = false
        // The generated registry is the full proposal-0016 method set; the
        // selected profile is what this deployment claims to speak. Iterating
        // the registry unfiltered installed a gate for every method the
        // registry knows, whether or not the profile declared it, so
        // `--profile` did not decide the permissioned surface it names. Today
        // this filter removes nothing (both checked-in permissioned profiles
        // carry the same 25 NSIDs) — it is what makes a narrower profile
        // answer 404 rather than 503 when one is written.
        for descriptor in PermissionedData0016.methods
            .filter({ profile.endpoints.contains($0.nsid) }) {
            if descriptor.nsid == ComAtprotoSimplespaceGetSpace.typeIdentifier,
               let authenticatedGetSpace {
                registerAuthenticatedGetSpaceEndpoint(on: router, capability: authenticatedGetSpace)
            } else if descriptor.nsid == ComAtprotoSpaceGetDelegationToken.typeIdentifier,
                      let authenticatedSpaceDelegationMinting {
                registerAuthenticatedGetSpaceDelegationTokenEndpoint(
                    on: router,
                    capability: authenticatedSpaceDelegationMinting
                )
            } else if descriptor.nsid == ComAtprotoSpaceGetSpaceCredential.typeIdentifier,
                      let authenticatedSpaceCredentialExchange {
                registerAuthenticatedGetSpaceCredentialEndpoint(
                    on: router,
                    capability: authenticatedSpaceCredentialExchange,
                    requestBodyAdmission: requestBodyAdmission
                )
            } else if descriptor.nsid == ComAtprotoSpaceGetRecord.typeIdentifier,
                      let authenticatedSpaceRecords {
                registerAuthenticatedGetRecordEndpoint(on: router, capability: authenticatedSpaceRecords)
            } else if descriptor.nsid == ComAtprotoSpaceListRecords.typeIdentifier,
                      let authenticatedSpaceRecords {
                registerAuthenticatedListRecordsEndpoint(on: router, capability: authenticatedSpaceRecords)
            } else if descriptor.nsid == ComAtprotoSpaceListBlobs.typeIdentifier,
                      let authenticatedSpaceRecords {
                registerAuthenticatedListBlobsEndpoint(on: router, capability: authenticatedSpaceRecords)
            } else if descriptor.nsid == ComAtprotoSpaceListSpaces.typeIdentifier,
                      let authenticatedSpaceList {
                registerAuthenticatedListSpacesEndpoint(on: router, capability: authenticatedSpaceList)
            } else if descriptor.nsid == ComAtprotoSpaceCreateRecord.typeIdentifier,
                      let authenticatedSpaceRecords {
                registerAuthenticatedCreateRecordEndpoint(on: router, capability: authenticatedSpaceRecords)
            } else if descriptor.nsid == ComAtprotoSpacePutRecord.typeIdentifier,
                      let authenticatedSpaceRecords {
                registerAuthenticatedPutRecordEndpoint(on: router, capability: authenticatedSpaceRecords)
            } else if descriptor.nsid == ComAtprotoSpaceDeleteRecord.typeIdentifier,
                      let authenticatedSpaceRecords {
                registerAuthenticatedDeleteRecordEndpoint(on: router, capability: authenticatedSpaceRecords)
            } else if descriptor.nsid == ComAtprotoSpaceApplyWrites.typeIdentifier,
                      let authenticatedSpaceRecords {
                registerAuthenticatedApplyWritesEndpoint(on: router, capability: authenticatedSpaceRecords)
            } else if descriptor.nsid == ComAtprotoSpaceGetLatestCommit.typeIdentifier,
                      let authenticatedSpaceRepositorySync {
                registerAuthenticatedGetLatestCommitEndpoint(
                    on: router,
                    capability: authenticatedSpaceRepositorySync
                )
            } else if descriptor.nsid == ComAtprotoSpaceListRepoOps.typeIdentifier,
                      let authenticatedSpaceRepositorySync {
                registerAuthenticatedListRepoOpsEndpoint(
                    on: router,
                    capability: authenticatedSpaceRepositorySync
                )
            } else if descriptor.nsid == ComAtprotoSpaceGetRepo.typeIdentifier,
                      let authenticatedSpaceRepositorySync {
                registerAuthenticatedGetRepoEndpoint(
                    on: router,
                    capability: authenticatedSpaceRepositorySync
                )
            } else if descriptor.nsid == ComAtprotoSpaceGetBlob.typeIdentifier,
                      let authenticatedSpaceBlobs {
                registerAuthenticatedGetSpaceBlobEndpoint(
                    on: router,
                    capability: authenticatedSpaceBlobs
                )
            } else if descriptor.nsid == ComAtprotoSpaceListRepos.typeIdentifier,
                      let authenticatedSpaceNotifications {
                registerAuthenticatedListSpaceReposEndpoint(
                    on: router,
                    capability: authenticatedSpaceNotifications
                )
            } else if descriptor.nsid == ComAtprotoSpaceRegisterNotify.typeIdentifier,
                      let authenticatedSpaceNotifications {
                registerAuthenticatedRegisterSpaceNotifyEndpoint(
                    on: router,
                    capability: authenticatedSpaceNotifications,
                    requestBodyAdmission: requestBodyAdmission
                )
            } else if descriptor.nsid == ComAtprotoSpaceUnregisterNotify.typeIdentifier,
                      let authenticatedSpaceNotifications {
                registerAuthenticatedUnregisterSpaceNotifyEndpoint(
                    on: router,
                    capability: authenticatedSpaceNotifications,
                    requestBodyAdmission: requestBodyAdmission
                )
            } else if descriptor.nsid == ComAtprotoSpaceNotifyWrite.typeIdentifier,
                      let authenticatedSpaceNotifications {
                registerAuthenticatedNotifySpaceWriteEndpoint(
                    on: router,
                    capability: authenticatedSpaceNotifications,
                    requestBodyAdmission: requestBodyAdmission
                )
            } else if descriptor.nsid == ComAtprotoSpaceNotifySpaceDeleted.typeIdentifier,
                      let authenticatedSpaceNotifications {
                registerAuthenticatedNotifySpaceDeletedEndpoint(
                    on: router,
                    capability: authenticatedSpaceNotifications,
                    requestBodyAdmission: requestBodyAdmission
                )
            } else if descriptor.nsid == ComAtprotoSimplespaceCheckUserAccess.typeIdentifier,
                      let simpleSpaceCheckUserAccess {
                registerSimpleSpaceCheckUserAccessEndpoint(
                    on: router,
                    capability: simpleSpaceCheckUserAccess
                )
            } else if let authenticatedSimpleSpaceLifecycle,
                      Self.isSimpleSpaceLifecycleMethod(descriptor.nsid) {
                if !installedSimpleSpaceLifecycle {
                    registerAuthenticatedSimpleSpaceLifecycleEndpoints(
                        on: router,
                        capability: authenticatedSimpleSpaceLifecycle
                    )
                    installedSimpleSpaceLifecycle = true
                }
            } else {
                registerUnavailablePermissionedEndpoint(descriptor, on: router)
            }
        }

        // Reject future/unknown permissioned methods explicitly instead of
        // allowing a later generic XRPC route to become an accidental public
        // fallback. Exact profile routes above have higher router precedence,
        // so a wrong method on a known endpoint remains unavailable (404),
        // rather than being mistaken for its method-correct 503 gate.
        registerUnknownPermissionedEndpointGuards(on: router)

        // Public repository/sync stays a finite, separately generated surface.
        // P1 deliberately installs only method-correct unavailable gates; no
        // public route receives permissioned repositories or credential
        // readers, and streaming endpoints never invoke Data-shaped generated
        // handlers.
        // resolveHandle is registered from inside this call, so it exists only
        // on a server that already exposes public reads — it must not be a
        // handle->DID oracle an operator never opted into. It still depends on
        // none of the directory's health: it reads one control row and answers
        // even when no repository generation can be admitted at all.
        // The complete allow-list of public NSIDs this process may install a
        // live handler for. Every public registration below filters against
        // it, so `--public-profile` removes routes as well as adding gates.
        let servedPublicMethods = configuration.publicRouteSurface
            .servedMethodNSIDs
        if let publicRepositoryReadDirectory {
            registerPublicRepositoryReadEndpoints(
                on: router,
                directory: publicRepositoryReadDirectory,
                servedMethods: servedPublicMethods,
                publicURL: configuration.publicURL,
                jsonReadAdmission: jsonReadAdmission,
                handleResolution: publicHandleResolution,
                blobStreamAdmission: blobStreamAdmission,
                blobRequestBodyAdmission: publicBlobRequestBodyAdmission,
                blobRequestBodyPolicy: .noRequestBodyDefault
            )
        }
        if let publicRepositoryMutations {
            registerPublicRepositoryMutationEndpoints(
                on: router,
                capability: publicRepositoryMutations,
                servedMethods: servedPublicMethods
            )
        }
        // The exact ws route beats the `com.atproto.sync.*` wildcard guard
        // below (exact paths have higher precedence). When the runtime is
        // absent the wildcard 404 remains the endpoint's only shape.
        // Gated at the call site rather than inside the registration function:
        // `subscribeRepos` is a single route, and the streaming file is the one
        // public-surface file written in the 2-space style, so keeping the
        // condition here avoids mixing indentation inside it. A profile that
        // does not declare the subscription installs no WebSocket upgrade even
        // when the runtime exists — the `com.atproto.sync.*` guard answers 404,
        // exactly as it does when the runtime is absent.
        if let publicFirehoseStreaming,
           servedPublicMethods.contains(publicSubscribeReposNSID) {
            registerPublicFirehoseStreamingEndpoint(
                on: router,
                runtime: publicFirehoseStreaming,
                admission: publicFirehoseSubscriberAdmission
            )
        }
        // The one iteration that decides which public methods exist at all.
        // It reads the selected surface rather than naming a registry as a
        // literal, so `--public-profile` is the control it claims to be.
        for descriptor in configuration.publicRouteSurface.methods {
            if accountEmailXRPC != nil,
               Self.isInstalledAccountEmailMethod(descriptor.nsid) {
                continue
            }
            if publicRepositoryReadDirectory != nil,
               isInstalledPublicReadMethod(
                   descriptor.nsid,
                   handleResolutionInstalled: publicHandleResolution != nil
               ) {
                continue
            }
            if publicRepositoryMutations != nil,
               Self.isInstalledPublicMutationMethod(descriptor.nsid) {
                continue
            }
            // `com.atproto.sync.getBlob` had its own clause here, keyed on the
            // *mutation* capability. It is a read; it is covered by
            // `isInstalledPublicReadMethod` above now, so turning public
            // writes off no longer replaces image serving with a 503.
            registerUnavailablePublicEndpoint(descriptor, on: router)
        }
        accountEmailXRPC?.register(
            on: router,
            requestBodyAdmission: requestBodyAdmission,
            servedMethods: servedPublicMethods
        )
        // Registered BEFORE `registerUnknownPublicEndpointGuards` for
        // readability only — exact paths outrank a `<prefix>.*` guard in
        // Hummingbird's trie regardless of order, which is what lets these seven
        // methods coexist with the flat 404 over `com.atproto.server.*` without
        // weakening it.
        legacySessionXRPC?.register(
            on: router,
            requestBodyAdmission: requestBodyAdmission
        )
        actorPreferencesXRPC?.register(
            on: router,
            requestBodyAdmission: requestBodyAdmission
        )
        registerUnknownPublicEndpointGuards(on: router)
        // Registered last, and lowest priority in the trie. Every exact route
        // and every `<prefix>.*` guard above resolves ahead of it, so this can
        // never forward a Swan-owned lexicon to a third party.
        xrpcPipethrough?.register(
            on: router,
            requestBodyAdmission: requestBodyAdmission
        )

        return router
    }

    private static func isSimpleSpaceLifecycleMethod(_ nsid: String) -> Bool {
        switch nsid {
        case ComAtprotoSimplespaceCreateSpace.typeIdentifier,
             ComAtprotoSimplespaceUpdateSpace.typeIdentifier,
             ComAtprotoSimplespaceDeleteSpace.typeIdentifier,
             ComAtprotoSimplespaceAddMember.typeIdentifier,
             ComAtprotoSimplespaceRemoveMember.typeIdentifier,
             ComAtprotoSimplespaceListMembers.typeIdentifier:
            true
        default:
            false
        }
    }

    private static func isInstalledPublicMutationMethod(_ nsid: String) -> Bool {
        nsid == SwanPublicWire.ComAtprotoRepoApplyWrites.typeIdentifier ||
            nsid == SwanPublicWire.ComAtprotoRepoCreateRecord.typeIdentifier ||
            nsid == SwanPublicWire.ComAtprotoRepoPutRecord.typeIdentifier ||
            nsid == SwanPublicWire.ComAtprotoRepoUploadBlob.typeIdentifier ||
            nsid == SwanPublicWire.ComAtprotoRepoDeleteRecord.typeIdentifier
    }

    private static func isInstalledAccountEmailMethod(_ nsid: String) -> Bool {
        switch nsid {
        case SwanPublicWire.ComAtprotoServerRequestEmailConfirmation.typeIdentifier,
             SwanPublicWire.ComAtprotoServerConfirmEmail.typeIdentifier,
             SwanPublicWire.ComAtprotoServerRequestEmailUpdate.typeIdentifier,
             SwanPublicWire.ComAtprotoServerUpdateEmail.typeIdentifier,
             SwanPublicWire.ComAtprotoServerRequestPasswordReset.typeIdentifier,
             SwanPublicWire.ComAtprotoServerResetPassword.typeIdentifier:
            true
        default:
            false
        }
    }

    public func buildApplication(
        logger: Logger,
        onServerRunning: @escaping @Sendable (any Channel) async -> Void = { _ in },
        webSocketAutoPingInterval: Duration = .seconds(30)
    ) -> some ApplicationProtocol {
        let applicationConfiguration = ApplicationConfiguration(
            address: .hostname(configuration.host, port: configuration.port),
            serverName: "swan",
            availableConnectionsDelegate: MaximumAvailableConnections(
                configuration.maximumConnections,
                logger: logger
            )
        )
        let router = buildRouter()
        return Application(
            router: router,
            server: .http1WebSocketUpgrade(
                webSocketRouter: router,
                configuration: .init(
                    http1: .init(
                        additionalChannelHandlers: [SwanJSONWriteBodyDrainHandler(
                            timeout: jsonWriteBodyPolicy.totalBodyTimeout + .milliseconds(50)
                        )],
                        idleTimeout: .seconds(Int64(configuration.idleTimeoutSeconds))
                    ),
                    ws: Self.publicFirehoseWebSocketConfiguration(autoPingInterval: webSocketAutoPingInterval)
                )
            ),
            configuration: applicationConfiguration,
            onServerRunning: onServerRunning,
            logger: logger
        )
    }

    /// The WebSocket sub-configuration used by the public listener.
    ///
    /// `maxFrameSize` is **inbound only**. It reaches exactly one place: the
    /// `WebSocketFrameDecoder` that `NIOTypedWebSocketServerUpgrader` installs
    /// on the upgraded channel
    /// (`swift-nio/Sources/NIOWebSocket/NIOWebSocketServerUpgrader.swift:316-325`).
    /// Swan's outbound path is `outbound.write(.binary(_:))`
    /// (`PublicFirehoseStreamingRoute.swift:416`), which emits one `fin: true`
    /// frame of whatever size it is handed and never reads this value
    /// (`swift-websocket/Sources/WSCore/WebSocketOutboundWriter.swift:30-47`;
    /// only `writeBinaryMessage` at `:55-71` fragments, and nothing here calls
    /// it). Sizing this against `FirehoseFrameLimits.maximumFrameBytes` was
    /// therefore never what kept `#commit` frames on the wire — it only let
    /// every anonymous socket pin a 5 MB decoder accumulation buffer, one byte
    /// per second, for a protocol that defines no client-to-server data frame.
    /// 4 KiB is the inbound budget: control frames are capped at 125 bytes by
    /// RFC 6455 and cannot be affected.
    ///
    /// Auto-ping runs every `autoPingInterval` (30 seconds in production) so a
    /// peer that never answers a ping is closed by Hummingbird's own liveness
    /// loop; close negotiation is bounded so a dead peer cannot pin a channel.
    static func publicFirehoseWebSocketConfiguration(
        autoPingInterval: Duration = .seconds(30)
    ) -> WebSocketServerConfiguration {
        WebSocketServerConfiguration(
            maxFrameSize: 4_096,
            autoPing: .enabled(timePeriod: autoPingInterval),
            closeTimeout: .seconds(15),
            validateUTF8: true
        )
    }
}

private struct ServerDescription: Encodable {
    let did: String
    let availableUserDomains: [String]
    let inviteCodeRequired: Bool
    let swanProfile: String

    enum CodingKeys: String, CodingKey {
        case did
        case availableUserDomains
        case inviteCodeRequired
        case swanProfile
    }
}

/// Output of `community.lexicon.service.describe`.
private struct CommunityServiceDescription: Encodable {
    let roles: [String]
    let methods: [CommunityServiceMethodReference]
}

/// One entry in `methods`. The proposal allows an NSID, an AT-URI, or a
/// strongRef; every method Swan serves is standardised and resolvable by
/// NSID, so that is the only form emitted — an AT-URI or strongRef would pin
/// a schema record this server does not publish. The `$type` discriminator is
/// required or a client cannot tell which of the three forms it received.
private struct CommunityServiceMethodReference: Encodable {
    let value: String

    enum CodingKeys: String, CodingKey {
        case type = "$type"
        case value
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode("community.lexicon.service.describe#nsid", forKey: .type)
        try container.encode(value, forKey: .value)
    }
}

/// The one derivation of Swan's own service identity from its configured
/// public URL.
///
/// This is the server's identity as a service, not any account's identity: no
/// account signing key, rotation key, or handle participates. Both
/// `/.well-known/did.json` and `com.atproto.server.describeServer` read this
/// value so that a resolver following the DID from one to the other cannot
/// observe two identities for a single deployment.
public struct SwanServiceIdentity: Sendable, Equatable {
    /// `did:web:<host>` — with `%3A<port>` appended when the public URL names
    /// a port other than its scheme's default. Dropping a non-default port
    /// would publish an identity that resolves to a *different* origin than
    /// the one actually serving, which is a silent misdirection rather than a
    /// visible failure.
    public let did: String
    /// The scheme/host/port origin, with no path, query, or trailing slash.
    /// This is what the `AtprotoPersonalDataServer` service entry advertises.
    public let serviceEndpoint: String

    public init(publicURL: URL) {
        let scheme = publicURL.scheme?.lowercased() ?? "https"
        let host = (publicURL.host ?? "localhost").lowercased()
        let defaultPort = scheme == "http" ? 80 : 443
        if let port = publicURL.port, port != defaultPort {
            did = "did:web:\(host)%3A\(port)"
            serviceEndpoint = "\(scheme)://\(host):\(port)"
        } else {
            did = "did:web:\(host)"
            serviceEndpoint = "\(scheme)://\(host)"
        }
    }
}

/// The DID document served at `/.well-known/did.json`.
///
/// It carries no `verificationMethod`: Swan holds no service-level signing key
/// whose public half it could publish here, and emitting an empty or invented
/// one would let a verifier believe a key was checked. Account signing keys
/// belong to account DID documents, which this route never serves.
private struct SwanServiceDIDDocument: Encodable {
    let context = ["https://www.w3.org/ns/did/v1"]
    let id: String
    let service: [SwanServiceDIDServiceEntry]

    init(identity: SwanServiceIdentity) {
        id = identity.did
        service = [SwanServiceDIDServiceEntry(
            id: "#atproto_pds",
            type: "AtprotoPersonalDataServer",
            serviceEndpoint: identity.serviceEndpoint
        )]
    }

    enum CodingKeys: String, CodingKey {
        case context = "@context"
        case id
        case service
    }
}

private struct SwanServiceDIDServiceEntry: Encodable {
    let id: String
    let type: String
    let serviceEndpoint: String
}

private func jsonResponse(_ body: some Encodable) -> Response {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = (try? encoder.encode(body)) ?? Data("{}".utf8)
    return Response(status: .ok, headers: [.contentType: "application/json", .cacheControl: "no-store"], body: .init(byteBuffer: ByteBuffer(data: data)))
}

/// AT Protocol requires CORS on discovery and browser-capable PAR/token
/// requests. These responses are never credentialed: the wildcard policy is
/// safe because DPoP, PKCE, and the request body still authenticate the
/// caller, and no `Access-Control-Allow-Credentials` header is emitted.
func oauthMetadataCORSHeaders(_ headers: inout HTTPFields) {
    headers[HTTPField.Name("Access-Control-Allow-Origin")!] = "*"
    headers[HTTPField.Name("Access-Control-Allow-Methods")!] = "GET, OPTIONS"
    headers[HTTPField.Name("Access-Control-Allow-Headers")!] = "Content-Type, DPoP"
}

func oauthAPICORSHeaders(_ headers: inout HTTPFields) {
    headers[HTTPField.Name("Access-Control-Allow-Origin")!] = "*"
    headers[HTTPField.Name("Access-Control-Allow-Methods")!] = "POST, OPTIONS"
    headers[HTTPField.Name("Access-Control-Allow-Headers")!] = "Content-Type, DPoP"
    headers[HTTPField.Name("Access-Control-Expose-Headers")!] = "DPoP-Nonce, WWW-Authenticate"
}

func oauthMetadataCORSPreflightResponse() -> Response {
    var headers: HTTPFields = [.cacheControl: "no-store"]
    oauthMetadataCORSHeaders(&headers)
    return Response(status: .noContent, headers: headers)
}

func oauthAPICORSPreflightResponse() -> Response {
    var headers: HTTPFields = [.cacheControl: "no-store"]
    oauthAPICORSHeaders(&headers)
    return Response(status: .noContent, headers: headers)
}

private func oauthMetadataJSONResponse(_ body: some Encodable) -> Response {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = (try? encoder.encode(body)) ?? Data("{}".utf8)
    var headers: HTTPFields = [.contentType: "application/json", .cacheControl: "no-store"]
    oauthMetadataCORSHeaders(&headers)
    return Response(status: .ok, headers: headers, body: .init(byteBuffer: ByteBuffer(data: data)))
}

private func oauthUnavailable() -> Response {
    // Do not publish OAuth discovery metadata until PAR, authorization,
    // token, revocation, consent, and proof validation are all registered.
    jsonResponseWithStatus(.serviceUnavailable, body: ["error": "oauth_flow_pending"])
}

private func registerUnavailablePermissionedEndpoint(
    _ descriptor: XRPCMethodDescriptor,
    on router: Router<BasicRequestContext>
) {
    let path = RouterPath("/xrpc/\(descriptor.nsid)")
    let allMethods: [HTTPRequest.Method] = [
        .get, .head, .post, .put, .patch, .delete, .options, .connect, .trace,
    ]
    let availableMethod: HTTPRequest.Method
    switch descriptor.kind {
    case .query, .subscription:
        router.get(path) { _, _ -> Response in
            permissionedDataUnavailable()
        }
        availableMethod = .get
    case .procedure:
        router.post(path) { _, _ -> Response in
            permissionedDataUnavailable()
        }
        availableMethod = .post
    }
    // A disabled profile endpoint stays method-correct.  Hummingbird's bare
    // router 404 has no cache policy or structured body, which would make a
    // closed delegation route observably different from its enabled shape.
    // Install explicit no-store guards for every wrong method before the
    // broader unknown-namespace guards below.
    for method in allMethods where method != availableMethod {
        router.on(path, method: method) { _, _ -> Response in
            permissionedEndpointUnavailable()
        }
    }
}

private func registerUnknownPermissionedEndpointGuards(
    on router: Router<BasicRequestContext>
) {
    let methods: [HTTPRequest.Method] = [
        .get, .head, .post, .put, .patch, .delete, .options, .connect, .trace,
    ]
    let paths: [RouterPath] = [
        "/xrpc/com.atproto.space.*",
        "/xrpc/com.atproto.simplespace.*",
    ]

    for path in paths {
        for method in methods {
            router.on(path, method: method) { _, _ -> Response in
                permissionedEndpointUnavailable()
            }
        }
    }
}

private func permissionedEndpointUnavailable() -> Response {
    jsonResponseWithStatus(.notFound, body: ["error": "permissioned_endpoint_unavailable"])
}

private func permissionedDataUnavailable() -> Response {
    jsonResponseWithStatus(.serviceUnavailable, body: ["error": "permissioned_data_pending"])
}

func jsonResponseWithStatus(_ status: HTTPResponse.Status, body: some Encodable) -> Response {
    let encoder = JSONEncoder()
    let data = (try? encoder.encode(body)) ?? Data("{}".utf8)
    return Response(status: status, headers: [.contentType: "application/json", .cacheControl: "no-store"], body: .init(byteBuffer: ByteBuffer(data: data)))
}

/// Wire response for `com.atproto.server.createAccount`. The durable signup
/// path returns the account and a management session digest; the reference
/// response shape carries empty JWTs because the OAuth session issuance is a
/// later task.
private struct CreateAccountResponse: Encodable {
    let did: String
    let handle: String
    let accessJwt: String
    let refreshJwt: String
}

/// Maps signup/lifecycle failures to the spec §3.3 status codes: 401
/// authentication_required, 403 request_not_allowed, 422 field-safe codes,
/// 409 duplicate, 429 rate limit, 503 service_unavailable. There is no
/// fallback to weaker authentication.
private func lifecycleErrorResponse(for error: any Error) -> Response {
    let status: HTTPResponse.Status
    let code: String
    switch error {
    case is TurnstileVerificationError:
        status = .forbidden
        code = "turnstile_verification_failed"
    case SignupServiceError.closed:
        status = .forbidden
        code = "request_not_allowed"
    case SignupServiceError.inviteRequired:
        status = .forbidden
        code = "invite_required"
    case SignupServiceError.emailProofRequired:
        status = .forbidden
        code = "email_proof_required"
    case SignupServiceError.turnstileRequired:
        status = .forbidden
        code = "turnstile_required"
    case SignupServiceError.invalidIdentity:
        status = HTTPResponse.Status(code: 422)
        code = "invalid_identity"
    case SignupServiceError.duplicateRequest:
        status = .conflict
        code = "duplicate_request"
    case SignupServiceError.rateLimited:
        status = .tooManyRequests
        code = "rate_limited"
    case AccountControlStoreError.duplicateDID:
        status = .conflict
        code = "duplicate_did"
    case AccountControlStoreError.duplicateHandle:
        status = .conflict
        code = "duplicate_handle"
    case AccountControlStoreError.invalidInput:
        status = HTTPResponse.Status(code: 422)
        code = "invalid_input"
    case SwanError.invalidIdentifier:
        status = HTTPResponse.Status(code: 422)
        code = "invalid_request"
    case SwanError.unauthorized:
        status = .unauthorized
        code = "authentication_required"
    case SwanError.expired:
        status = HTTPResponse.Status(code: 422)
        code = "expired"
    case is CancellationError:
        status = .serviceUnavailable
        code = "service_unavailable"
    default:
        status = .serviceUnavailable
        code = "service_unavailable"
    }
    return jsonResponseWithStatus(status, body: ["error": code])
}

/// Decodes the `com.atproto.server.createAccount` body under the same strict
/// JSON admission as the account-email XRPC surface: exact key set, no null
/// values, bounded bytes. A malformed body surfaces as a 422 invalid_request
/// through `lifecycleErrorResponse`.
private func decodeCreateAccountBody(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws -> SwanCreateAccountXRPCInput {
    let buffer: SwanAdmittedRequestBody
    do {
        buffer = try await collectAdmittedRequestBody(
            request,
            mediaType: .json,
            admission: requestBodyAdmission.admission,
            policy: requestBodyAdmission.policy,
            maximumBytes: 8 * 1024,
            termination: context.jsonWriteBodyTermination
        )
    } catch {
        throw SwanError.invalidIdentifier("createAccount body")
    }
    defer { withExtendedLifetime(buffer) {} }
    guard buffer.readableBytes > 0,
          let bytes = buffer.getBytes(
              at: buffer.readerIndex,
              length: buffer.readableBytes
          ) else {
        throw SwanError.invalidIdentifier("createAccount body")
    }
    let data = Data(bytes)
    do {
        try StrictJSON.validate(data)
        guard let object = try JSONSerialization.jsonObject(
            with: data,
            options: []
        ) as? [String: Any] else {
            throw SwanError.invalidIdentifier("createAccount body")
        }
        let keys = Set(object.keys)
        let required: Set<String> = ["handle", "password"]
        let optional: Set<String> = [
            "email", "inviteCode", "verificationCode", "did",
            "recoveryKey", "plcOp", "verificationPhone", "turnstileToken",
        ]
        guard required.isSubset(of: keys),
              keys.isSubset(of: required.union(optional)),
              !object.values.contains(where: { $0 is NSNull }) else {
            throw SwanError.invalidIdentifier("createAccount body")
        }
        return try JSONDecoder().decode(SwanCreateAccountXRPCInput.self, from: data)
    } catch let error as SwanError {
        throw error
    } catch {
        throw SwanError.invalidIdentifier("createAccount body")
    }
}
