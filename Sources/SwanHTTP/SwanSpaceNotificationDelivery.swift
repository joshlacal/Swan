import Foundation
import Petrel
import SwanCore
import SwanOAuth
import SwanSQLite
import SwanSpaces
import SwanStorage

/// One operator-configured service destination. The endpoint is selected from
/// a static allowlist, never directly from a registered URL or an incoming
/// service JWT. `audience` is the exact configured remote service identity
/// used for the service JWT; it is not assumed to be a DID. The pinned
/// TypeScript PDS records the registered endpoint itself as this identity.
public struct SwanSpaceNotificationDestination: Sendable, Equatable {
    public let endpoint: URL
    public let audience: String

    public init(endpoint: URL, audience: String) throws {
        guard let components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false),
              components.scheme != nil,
              components.host != nil,
              components.user == nil,
              components.password == nil,
              components.fragment == nil,
              validConfiguredServiceIdentity(audience) else {
            throw SwanError.malformed("notification destination is invalid")
        }
        self.endpoint = endpoint
        self.audience = audience
    }
}

/// Maps an authority DID to the one configured endpoint that accepts its
/// `notifyWrite` request. An outbox event with no mapping fails and retries;
/// it never falls back to a request-controlled URL.
public protocol SwanSpaceAuthorityNotificationDestinationResolving: Sendable {
    func destination(forAuthority authority: String) async throws -> SwanSpaceNotificationDestination?
}

/// Maps an *exact registered endpoint string* to an operator-configured
/// endpoint and service audience. A registration only acts as a key into this
/// map; it cannot select an audience or make a new network destination live.
public protocol SwanRegisteredSpaceNotificationDestinationResolving: Sendable {
    func destination(
        forRegisteredEndpoint endpoint: String
    ) async throws -> SwanSpaceNotificationDestination?
}

/// Immutable lab configuration for writer-to-authority notifications. The
/// pinned TypeScript handler accepts only this writer-signed shape. Registered
/// write fanout is retained as local discovery state but is not represented as
/// a claimed cross-host delivery protocol until upstream defines a receiver
/// that accepts an authority signing for another writer.
public struct StaticSwanSpaceNotificationDestinations:
    SwanSpaceAuthorityNotificationDestinationResolving,
    SwanRegisteredSpaceNotificationDestinationResolving
{
    private let authorities: [String: SwanSpaceNotificationDestination]
    private let registrations: [String: SwanSpaceNotificationDestination]

    public init(
        authorityDestinations: [String: SwanSpaceNotificationDestination] = [:],
        registrationDestinations: [String: SwanSpaceNotificationDestination] = [:]
    ) throws {
        for authority in authorityDestinations.keys {
            guard (try? DID(didString: authority)) != nil else {
                throw SwanError.malformed("notification authority mapping is invalid")
            }
        }
        for endpoint in registrationDestinations.keys {
            guard validConfiguredNotificationEndpoint(endpoint) else {
                throw SwanError.malformed("notification registration mapping is invalid")
            }
        }
        authorities = authorityDestinations
        registrations = registrationDestinations
    }

    public func destination(
        forAuthority authority: String
    ) async throws -> SwanSpaceNotificationDestination? {
        authorities[authority]
    }

    public func destination(
        forRegisteredEndpoint endpoint: String
    ) async throws -> SwanSpaceNotificationDestination? {
        registrations[endpoint]
    }
}

/// `--enable-spaces-open-interop` (decision B(c)): an operator-configured
/// destination wins; otherwise the authority's DID document decides —
/// `#atproto_space_host` (type `AtprotoSpaceHost`), else `#atproto_pds`.
/// A present-but-malformed entry is an error, so the outbox row retries
/// rather than silently routing elsewhere.
public struct SwanOpenFederationAuthorityNotificationDestinations:
    SwanSpaceAuthorityNotificationDestinationResolving
{
    private let configured: any SwanSpaceAuthorityNotificationDestinationResolving
    private let resolver: SwanDIDDocumentSpaceResolver

    public init(
        configured: any SwanSpaceAuthorityNotificationDestinationResolving,
        resolver: SwanDIDDocumentSpaceResolver
    ) {
        self.configured = configured
        self.resolver = resolver
    }

    public func destination(
        forAuthority authority: String
    ) async throws -> SwanSpaceNotificationDestination? {
        if let destination = try await configured.destination(forAuthority: authority) {
            return destination
        }
        guard let resolved = try await resolver.notifyDestination(forAuthority: authority) else {
            return nil
        }
        return try SwanSpaceNotificationDestination(
            endpoint: resolved.endpoint,
            audience: resolved.audience
        )
    }
}

/// Looks up the latest durable repository state only after the outbox lease
/// has committed. It returns commitment metadata, not records, CAR bytes,
/// CIDs, credentials, or a database connection. A coalesced older event may
/// therefore announce a newer current commit, which is safe because the
/// receiver keeps the highest TID and converges on the current writer state.
public struct SQLiteSpaceWriteAnnouncementSource: Sendable {
    private let database: SQLiteAccountDatabase

    public init(database: SQLiteAccountDatabase) {
        self.database = database
    }

    public func currentAnnouncement(
        for notification: PermissionedSpaceOutboxNotification
    ) async throws -> AuthorizedSpaceWriter {
        guard let state = try await database.repositoryState(
            space: notification.space,
            author: notification.author
        ), state.commitment.count == 32 else {
            throw SwanError.unavailable("notification repository state is unavailable")
        }
        return AuthorizedSpaceWriter(
            space: notification.space,
            repository: notification.author,
            wireRevision: state.wireRevision.toString(),
            commitment: state.commitment
        )
    }
}

/// Sends an atomically-created local commit outbox event to the configured
/// space authority. Its only body fields are the proposal's writer hint:
/// space, repo, wire TID, and 32-byte LtHash commitment.
public struct HTTPPermissionedSpaceOutboxTransport: PermissionedSpaceOutboxTransport {
    private let destinations: any SwanSpaceAuthorityNotificationDestinationResolving
    private let announcements: SQLiteSpaceWriteAnnouncementSource
    private let serviceAuthentication: any SpaceServiceAuthenticationIssuer
    private let poster: OAuthBoundedJSONPoster

    public init(
        destinations: any SwanSpaceAuthorityNotificationDestinationResolving,
        announcements: SQLiteSpaceWriteAnnouncementSource,
        serviceAuthentication: any SpaceServiceAuthenticationIssuer,
        poster: OAuthBoundedJSONPoster
    ) {
        self.destinations = destinations
        self.announcements = announcements
        self.serviceAuthentication = serviceAuthentication
        self.poster = poster
    }

    public func deliver(_ notification: PermissionedSpaceOutboxNotification) async throws {
        guard let destination = try await destinations.destination(
            forAuthority: notification.space.authority
        ) else {
            throw SwanError.unavailable("space authority notification destination is unavailable")
        }
        let announcement = try await announcements.currentAnnouncement(for: notification)
        let body = try notificationJSON(
            space: announcement.space,
            repository: announcement.repository,
            wireRevision: announcement.wireRevision,
            commitment: announcement.commitment
        )
        let endpoint = try notificationEndpoint(
            destination.endpoint,
            method: ComAtprotoSpaceNotifyWrite.typeIdentifier
        )
        let reqDigest = SpaceNotificationRequestDigest.write(
            space: announcement.space,
            repository: announcement.repository,
            wireRevision: announcement.wireRevision,
            commitment: announcement.commitment
        )
        let token = try await serviceAuthentication.issue(
            issuer: notification.author,
            audience: destination.audience,
            method: ComAtprotoSpaceNotifyWrite.typeIdentifier,
            eventID: notification.id.uuidString,
            requestBodyDigest: reqDigest,
            now: Date()
        )
        do {
            try await poster.postJSON(
                to: endpoint,
                headers: notificationHeaders(token),
                body: body
            )
        } catch is OAuthOutboundPostPermanentlyRejected {
            // A verified peer answered 4xx: the receiver refused this
            // delivery and a retry cannot change its mind. Acknowledge
            // rather than grinding the queue on a permanent failure.
            return
        }
    }
}

/// Delivers authority-created fanout rows after confirming their
/// registration remains current: deletions, and (Erratum 03 / atproto#5574)
/// writes forwarded to service-named subscribers as authority-signed
/// `notifyWrite` calls carrying the space host's `spaceRev` and
/// `prevSpaceRev`. Forwarding is reasonable-effort; subscribers recover
/// missed updates through `listRepos`. The configured resolver maps an opaque
/// registered string to an allowlisted endpoint and exact audience, so a
/// malicious registration can never steer service traffic or JWT claims.
public struct HTTPPermissionedSpaceNotificationFanoutTransport:
    PermissionedSpaceNotificationFanoutTransport
{
    private let database: SQLiteAccountDatabase
    private let destinations: any SwanRegisteredSpaceNotificationDestinationResolving
    private let serviceAuthentication: any SpaceServiceAuthenticationIssuer
    private let poster: OAuthBoundedJSONPoster

    public init(
        database: SQLiteAccountDatabase,
        destinations: any SwanRegisteredSpaceNotificationDestinationResolving,
        serviceAuthentication: any SpaceServiceAuthenticationIssuer,
        poster: OAuthBoundedJSONPoster
    ) {
        self.database = database
        self.destinations = destinations
        self.serviceAuthentication = serviceAuthentication
        self.poster = poster
    }

    public func deliver(_ notification: PersistedSpaceNotificationFanout) async throws {
        // A replacement, expiry, or future explicit removal wins over a row
        // that was already queued. Treat the stale delivery as a successful
        // no-op; the lease worker will acknowledge it without network I/O.
        let service: String?
        if notification.kind == .deleted {
            guard let registration = try await database.currentSpaceDeletionDeliveryRegistration(
                for: notification
            ) else { return }
            service = registration.serviceIdentity
        } else {
            guard try await database.isSpaceNotificationRegistrationActive(
                space: notification.space,
                endpoint: notification.endpoint,
                repository: notification.repository,
                now: Date()
            ) else { return }
            service = try await database.spaceNotificationRegistrationService(
                space: notification.space,
                endpoint: notification.endpoint,
                repository: notification.repository,
                now: Date()
            )
        }
        // Erratum 03: a SERVICE-NAMED registration is its own destination —
        // the endpoint carries DID-document provenance from registration-time
        // resolution, and the identifier is the verifiable JWT audience. The
        // poster still applies the full egress policy per request, so a
        // resolved endpoint gets the same SSRF refusals as a configured one.
        // Endpoint-only legacy rows keep requiring the operator map: with no
        // service identity there is no audience a receiver could verify, and
        // their raw URLs never became network destinations before.
        let destination: SwanSpaceNotificationDestination
        if let service {
            guard let registered = URL(string: notification.endpoint) else {
                throw SwanError.malformed("registered notification endpoint is invalid")
            }
            destination = try SwanSpaceNotificationDestination(
                endpoint: registered,
                audience: service
            )
        } else if notification.kind == .deleted,
                  let configured = try await destinations.destination(
                      forRegisteredEndpoint: notification.endpoint
                  ) {
            destination = configured
        } else if notification.kind == .write {
            // A write row for a registration that lost (or never had) its
            // service identity: nothing verifiable to deliver. Pre-Erratum-03
            // rows are also retired through here.
            return
        } else {
            throw SwanError.unavailable("registered notification destination is unavailable")
        }
        let method: String
        let body: Data
        let reqDigest: String
        switch notification.kind {
        case .write:
            guard let repository = notification.repository,
                  let wireRevision = notification.wireRevision,
                  let commitment = notification.commitment else {
                throw SwanError.malformed("write fanout row is incomplete")
            }
            // A forward must carry the space revision the space host
            // assigned. Rows queued before space revisions existed have none
            // and are retired unsent; the subscriber catches up via listRepos.
            guard let spaceRevision = notification.spaceRevision else { return }
            method = ComAtprotoSpaceNotifyWrite.typeIdentifier
            body = try notificationJSON(
                space: notification.space,
                repository: repository,
                wireRevision: wireRevision,
                commitment: commitment,
                spaceRevision: spaceRevision,
                previousSpaceRevision: notification.previousSpaceRevision
            )
            reqDigest = SpaceNotificationRequestDigest.forwardedWrite(
                space: notification.space,
                repository: repository,
                wireRevision: wireRevision,
                commitment: commitment,
                spaceRevision: spaceRevision,
                previousSpaceRevision: notification.previousSpaceRevision
            )
        case .deleted:
            method = ComAtprotoSpaceNotifySpaceDeleted.typeIdentifier
            body = try deletionJSON(space: notification.space)
            reqDigest = SpaceNotificationRequestDigest.deletion(space: notification.space)
        }
        let endpoint = try notificationEndpoint(destination.endpoint, method: method)
        let token = try await serviceAuthentication.issue(
            issuer: notification.space.authority,
            audience: destination.audience,
            method: method,
            eventID: notification.id.uuidString,
            requestBodyDigest: reqDigest,
            now: Date()
        )
        do {
            try await poster.postJSON(
                to: endpoint,
                headers: notificationHeaders(token),
                body: body
            )
        } catch is OAuthOutboundPostPermanentlyRejected {
            // A verified peer answered 4xx (bulleted.app has no deletion
            // receiver at all, for instance): permanent, acknowledge.
            return
        }
    }
}

/// The TypeScript XRPC client treats a DID-document PDS/service endpoint as
/// an origin and constructs an absolute `/xrpc/<nsid>` request path.  Keep
/// that behavior at the transport boundary so an operator pin cannot turn
/// the notification worker into a request to an arbitrary configured path.
/// Query and fragment components are intentionally discarded, matching the
/// absolute-path construction used by the reference client.
private func notificationEndpoint(_ endpoint: URL, method: String) throws -> URL {
    guard let components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false),
          components.scheme != nil,
          components.host != nil,
          components.user == nil,
          components.password == nil,
          components.fragment == nil,
          method.utf8.count <= 256,
          !method.isEmpty,
          method.utf8.allSatisfy({ byte in
              (byte >= 0x41 && byte <= 0x5A)
                  || (byte >= 0x61 && byte <= 0x7A)
                  || (byte >= 0x30 && byte <= 0x39)
                  || byte == 0x2E
        }) else {
        throw SwanError.malformed("notification endpoint is invalid")
    }
    var request = components
    request.path = "/xrpc/\(method)"
    request.query = nil
    request.fragment = nil
    guard let url = request.url else {
        throw SwanError.malformed("notification endpoint is invalid")
    }
    return url
}

/// The repo-host hop is `{space, repo, repoRev, hash}`; a space-host
/// forward adds `spaceRev` and, except on the space's first update,
/// `prevSpaceRev`.
private func notificationJSON(
    space: SpaceURI,
    repository: String,
    wireRevision: String,
    commitment: Data,
    spaceRevision: String? = nil,
    previousSpaceRevision: String? = nil
) throws -> Data {
    guard commitment.count == 32,
          let revision = try? TID(tidString: wireRevision) else {
        throw SwanError.malformed("writer notification is invalid")
    }
    let spaceRev = try spaceRevision.map { try TID(tidString: $0) }
    let prevSpaceRev = try previousSpaceRevision.map { try TID(tidString: $0) }
    guard spaceRev != nil || prevSpaceRev == nil else {
        throw SwanError.malformed("writer notification is invalid")
    }
    let input = try ComAtprotoSpaceNotifyWrite.Input(
        space: SpaceRef(uriString: space.rawValue),
        repo: DID(didString: repository),
        repoRev: revision,
        hash: Bytes(data: commitment),
        spaceRev: spaceRev,
        prevSpaceRev: prevSpaceRev
    )
    return try SwanJSONEncoders.sortedNoEscaping.encode(input)
}

private func deletionJSON(space: SpaceURI) throws -> Data {
    let input = try ComAtprotoSpaceNotifySpaceDeleted.Input(
        space: SpaceRef(uriString: space.rawValue)
    )
    return try SwanJSONEncoders.sortedNoEscaping.encode(input)
}

private func notificationHeaders(_ token: String) -> [String: String] {
    [
        "authorization": "Bearer \(token)",
        "content-type": "application/json",
        "accept": "application/json",
    ]
}

private func validConfiguredNotificationEndpoint(_ raw: String) -> Bool {
    guard raw.utf8.count <= 4_096,
          raw.unicodeScalars.allSatisfy({ $0.value > 0x1f && $0.value != 0x7f }),
          let components = URLComponents(string: raw),
          components.scheme != nil,
          components.host != nil,
          components.user == nil,
          components.password == nil,
          components.fragment == nil else {
        return false
    }
    return true
}

private func validConfiguredServiceIdentity(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 4_096 && value.utf8.allSatisfy {
        $0 >= 0x21 && $0 <= 0x7e
    }
}
