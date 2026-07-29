import Foundation
import Hummingbird
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
    RemoteAddressRequestContext
{
    public var coreContext: CoreRequestContextStorage
    public let remoteAddress: SocketAddress?

    public init(source: ApplicationRequestContextSource) {
        coreContext = .init(source: source)
        remoteAddress = source.channel.remoteAddress
    }
}

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

    public init(host: String = "127.0.0.1", port: Int = 3000, publicURL: URL = URL(string: "http://127.0.0.1:3000")!) {
        self.host = host
        self.port = port
        self.publicURL = publicURL
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
/// by the writer notification endpoints. It contains no remote DID resolver;
/// service claims can never turn an XRPC request into a network lookup.
public struct SwanSpaceNotificationHTTPConfiguration: Sendable {
    public let serviceAuthentication: any SpaceServiceAuthenticationVerifier
    let recipientBindings: SwanSpaceNotificationRecipientBindings

    public init(
        serviceAuthentication: any SpaceServiceAuthenticationVerifier,
        recipientBindings: SwanSpaceNotificationRecipientBindings = .empty
    ) {
        self.serviceAuthentication = serviceAuthentication
        self.recipientBindings = recipientBindings
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
    /// Explicitly opt-in public mutation capability. Public reads never imply
    /// this capability, and it is only formed alongside the server-bound
    /// OAuth resource authorizer.
    public let publicRepositoryMutations: SwanPublicRepositoryMutationCapability?
    /// Durable account-email confirmation and password-recovery routes. This
    /// capability is nil unless the caller has assembled the proof codec,
    /// control-store adapter, rate limiter, and SMTP worker at startup.
    public let accountEmailXRPC: SwanAccountEmailXRPCServer?

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
        accountEmailXRPC: SwanAccountEmailXRPCServer? = nil,
        loginClientIdentityPolicy: SwanLoginClientIdentityPolicy = .direct
    ) {
        self.profile = profile
        self.configuration = configuration
        self.repositories = repositories
        self.oauthRuntime = oauthRuntime
        self.loginClientIdentityPolicy = loginClientIdentityPolicy
        self.publicRepositoryReadDirectory = publicRepositoryReadDirectory
        self.accountEmailXRPC = accountEmailXRPC
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
               accountControlStore: accountControlStore
           ) {
            authenticatedGetSpace = SwanAuthenticatedGetSpaceCapability(
                authorizer: authorizer,
                directory: authenticatedGetSpaceDirectory
            )
            if let mutationDirectory = publicRepositoryMutationDirectory,
               let signerProvider = publicRepositoryMutationSignerProvider {
                publicRepositoryMutations = SwanPublicRepositoryMutationCapability(
                    authorizer: authorizer,
                    directory: mutationDirectory,
                    signerProvider: signerProvider
                )
            } else {
                publicRepositoryMutations = nil
            }
            if let repositoryDirectory = authenticatedGetSpaceDirectory
                as? any AuthorizedSpaceRepositoryDirectory {
                let credentialVerifier: (any SpaceCredentialAuthorizationVerifier)?
                if let spaceCredentialConfiguration {
                    credentialVerifier = DurableSpaceCredentialVerifier(
                        publicKeys: spaceCredentialConfiguration.credentialPublicKeys
                    )
                } else {
                    credentialVerifier = nil
                }
                authenticatedSpaceRecords = SwanAuthenticatedSpaceRecordsCapability(
                    authorizer: authorizer,
                    directory: repositoryDirectory,
                    credentialAuthorizer: credentialVerifier
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
                    directory: lifecycleDirectory
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
                    commitSigner: spaceRepositorySyncConfiguration.commitSigner
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
                    credentialAuthorizer: credentialVerifier
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
                    recipientBindings: spaceNotificationConfiguration.recipientBindings
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
        router.get("/health") { _, _ in "OK" }

        let publicURL = configuration.publicURL
        let profile = profile
        let oauthPublicationGate = oauthPublicationGate
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
                loginClientIdentityPolicy: loginClientIdentityPolicy
            )
            registerOAuthAuthorizationServerPAREndpoint(
                on: router,
                configuration: authorizationServerConfiguration,
                runtime: oauthRuntime
            )
        } else if let localhostOAuthConfiguration {
            registerLocalhostOAuthEndpoints(
                on: router,
                configuration: localhostOAuthConfiguration,
                runtime: oauthRuntime,
                loginClientIdentityPolicy: loginClientIdentityPolicy
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
                runtime: oauthRuntime
            )
        } else if let localhostPARConfiguration {
            registerLocalhostPAREndpoint(
                on: router,
                configuration: localhostPARConfiguration,
                runtime: oauthRuntime
            )
        }

        router.get("/xrpc/com.atproto.server.describeServer") { _, _ -> Response in
            jsonResponse(ServerDescription(
                did: "did:web:\(publicURL.host ?? "localhost")",
                availableUserDomains: [],
                inviteCodeRequired: true,
                swanProfile: profile.id
            ))
        }

        // Do not route permissioned traffic to the in-memory repository store
        // while durable OAuth and account control have no HTTP entry points.
        // The checked-in wire registry is the sole source for this coverage:
        // every profile method gets an explicit, method-correct closed handler
        // until its authenticated implementation is ready.
        var installedSimpleSpaceLifecycle = false
        for descriptor in PermissionedData0016.methods {
            if descriptor.nsid == ComAtprotoSpaceGetSpace.typeIdentifier,
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
                    capability: authenticatedSpaceCredentialExchange
                )
            } else if descriptor.nsid == ComAtprotoSpaceGetRecord.typeIdentifier,
                      let authenticatedSpaceRecords {
                registerAuthenticatedGetRecordEndpoint(on: router, capability: authenticatedSpaceRecords)
            } else if descriptor.nsid == ComAtprotoSpaceListRecords.typeIdentifier,
                      let authenticatedSpaceRecords {
                registerAuthenticatedListRecordsEndpoint(on: router, capability: authenticatedSpaceRecords)
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
                    capability: authenticatedSpaceNotifications
                )
            } else if descriptor.nsid == ComAtprotoSpaceNotifyWrite.typeIdentifier,
                      let authenticatedSpaceNotifications {
                registerAuthenticatedNotifySpaceWriteEndpoint(
                    on: router,
                    capability: authenticatedSpaceNotifications
                )
            } else if descriptor.nsid == ComAtprotoSpaceNotifySpaceDeleted.typeIdentifier,
                      let authenticatedSpaceNotifications {
                registerAuthenticatedNotifySpaceDeletedEndpoint(
                    on: router,
                    capability: authenticatedSpaceNotifications
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
        if let publicRepositoryReadDirectory {
            registerPublicRepositoryReadEndpoints(
                on: router,
                directory: publicRepositoryReadDirectory,
                publicURL: configuration.publicURL
            )
        }
        if let publicRepositoryMutations {
            registerPublicRepositoryMutationEndpoints(
                on: router,
                capability: publicRepositoryMutations
            )
        }
        for descriptor in PublicDataTesting20260727.methods {
            if accountEmailXRPC != nil,
               Self.isInstalledAccountEmailMethod(descriptor.nsid) {
                continue
            }
            if publicRepositoryReadDirectory != nil,
               isInstalledPublicReadMethod(descriptor.nsid) {
                continue
            }
            if publicRepositoryMutations != nil,
               Self.isInstalledPublicMutationMethod(descriptor.nsid) {
                continue
            }
            if publicRepositoryMutations != nil,
               descriptor.nsid == "com.atproto.sync.getBlob" {
                continue
            }
            registerUnavailablePublicEndpoint(descriptor, on: router)
        }
        accountEmailXRPC?.register(on: router)
        registerUnknownPublicEndpointGuards(on: router)

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

    public func buildApplication(logger: Logger) -> some ApplicationProtocol {
        Application(
            router: buildRouter(),
            configuration: .init(address: .hostname(configuration.host, port: configuration.port), serverName: "swan"),
            logger: logger
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
