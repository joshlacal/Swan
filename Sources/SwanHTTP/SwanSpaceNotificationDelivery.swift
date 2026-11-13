import Foundation
import Petrel
import SwanCore
import SwanOAuth
import SwanSQLite
import SwanSpaces
import SwanStorage


public protocol SwanSpaceRegistrationConfirming: Sendable {
    func confirmRegistration(
        space: SpaceURI,
        endpoint: URL,
        token: String,
        challenge: String
    ) async throws
}

/// Confirms a request-selected endpoint through the same DNS pinning,
/// public-address checks, redirect refusal, and bounded response rules as
/// Swan's other untrusted outbound fetches.
public struct HTTPSwanSpaceRegistrationConfirmer: SwanSpaceRegistrationConfirming {
    private let policy: OAuthRemoteFetchPolicy
    private let resolver: any OAuthHostnameResolving
    private let transport: NIOPeerPinnedOAuthPostTransport

    public init(
        policy: OAuthRemoteFetchPolicy,
        transport: NIOPeerPinnedOAuthPostTransport,
        resolver: any OAuthHostnameResolving = SystemOAuthHostnameResolver()
    ) {
        self.policy = policy
        self.transport = transport
        self.resolver = resolver
    }

    public func confirmRegistration(
        space: SpaceURI,
        endpoint: URL,
        token: String,
        challenge: String
    ) async throws {
        guard token.utf16.count <= 512, !token.isEmpty,
              challenge.utf8.count <= 128, !challenge.isEmpty,
              let base = URLComponents(url: endpoint, resolvingAgainstBaseURL: false),
              base.path.isEmpty || base.path == "/",
              base.query == nil,
              base.fragment == nil else {
            throw SwanError.malformed("notification registration is invalid")
        }
        let url = try notificationEndpoint(
            endpoint,
            method: ComAtprotoSpaceConfirmRegistration.typeIdentifier
        )
        let body = try JSONEncoder().encode(
            ComAtprotoSpaceConfirmRegistration.Input(
                space: try SpaceRef(uriString: space.rawValue),
                token: token,
                challenge: challenge
            )
        )
        let host = try policy.validateURL(url)
        let before = Set(
            try await resolveRegistrationHostname(
                resolver, host: host, timeout: policy.timeout
            )
        )
        try policy.validateResolved(Array(before), host: host)
        let response = try await transport.post(
            url: url,
            approvedPeers: before,
            headers: [
                "Accept": "application/json",
                "Content-Type": "application/json",
            ],
            body: body,
            timeout: policy.timeout,
            maximumResponseBodyBytes: 4_096
        )
        let after = Set(
            try await resolveRegistrationHostname(
                resolver, host: host, timeout: policy.timeout
            )
        )
        try policy.validateResolved(Array(after), host: host)
        guard response.status == 200,
              response.redirectCount == 0,
              response.responseURL == url,
              let peer = response.connectedPeerAddress,
              before.contains(peer),
              after.contains(peer),
              response.body.count <= 4_096 else {
            throw SwanError.unavailable("registration confirmation failed")
        }
        try StrictJSON.validate(response.body)
        guard let object = try JSONSerialization.jsonObject(with: response.body)
                as? [String: Any],
              Set(object.keys) == ["challenge"],
              object["challenge"] as? String == challenge else {
            throw SwanError.unavailable("registration confirmation failed")
        }
    }
}

private final class RegistrationDNSResolutionDeadline: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<[OAuthIPAddress], Error>?
    private var result: Result<[OAuthIPAddress], Error>?

    func install(_ continuation: CheckedContinuation<[OAuthIPAddress], Error>) {
        lock.lock()
        if let result {
            lock.unlock()
            resume(continuation, with: result)
        } else {
            self.continuation = continuation
            lock.unlock()
        }
    }

    func complete(_ result: Result<[OAuthIPAddress], Error>) {
        lock.lock()
        guard self.result == nil else {
            lock.unlock()
            return
        }
        self.result = result
        let continuation = continuation
        self.continuation = nil
        lock.unlock()
        if let continuation {
            resume(continuation, with: result)
        }
    }

    private func resume(
        _ continuation: CheckedContinuation<[OAuthIPAddress], Error>,
        with result: Result<[OAuthIPAddress], Error>
    ) {
        switch result {
        case let .success(addresses):
            continuation.resume(returning: addresses)
        case let .failure(error):
            continuation.resume(throwing: error)
        }
    }
}

private func resolveRegistrationHostname(
    _ resolver: any OAuthHostnameResolving,
    host: String,
    timeout: TimeInterval
) async throws -> [OAuthIPAddress] {
    let completion = RegistrationDNSResolutionDeadline()
    let resolutionTask = Task { @Sendable in
        do {
            completion.complete(.success(try await resolver.resolve(host: host)))
        } catch {
            completion.complete(.failure(error))
        }
    }
    let timeoutNanoseconds = UInt64((timeout * 1_000_000_000).rounded(.up))
    let timeoutTask = Task { @Sendable in
        do {
            try await Task.sleep(nanoseconds: timeoutNanoseconds)
        } catch {
            return
        }
        completion.complete(
            .failure(SwanError.unavailable("registration DNS resolution timed out"))
        )
        resolutionTask.cancel()
    }
    defer {
        resolutionTask.cancel()
        timeoutTask.cancel()
    }
    return try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { continuation in
            completion.install(continuation)
        }
    } onCancel: {
        completion.complete(.failure(CancellationError()))
        resolutionTask.cancel()
        timeoutTask.cancel()
    }
}

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
/// `notifyRepoUpdate` request. An outbox event with no mapping fails and
/// retries; it never falls back to a request-controlled URL.
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
/// `#atproto_pds` (type `AtprotoSpaceHost`), else `#atproto_pds`.
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
            method: ComAtprotoSpaceNotifyRepoUpdate.typeIdentifier
        )
        let reqDigest = SpaceNotificationRequestDigest.write(
            space: announcement.space,
            repository: announcement.repository,
            wireRevision: announcement.wireRevision,
            commitment: announcement.commitment
        )
        // Every attempt gets a fresh random jti, as upstream createServiceJwt
        // mints one per call. A receiver with a single-use jti store consumes
        // it on the first attempt and would refuse the retry with a 4xx, which
        // is acknowledged below as permanent. Receivers dedupe a repeat by the
        // writer's revision, not by jti: Swan's authority and the reference
        // ignore a notifyRepoUpdate whose `repoRev` is not newer.
        let token = try await serviceAuthentication.issue(
            issuer: notification.author,
            audience: destination.audience,
            method: ComAtprotoSpaceNotifyRepoUpdate.typeIdentifier,
            eventID: UUID().uuidString.lowercased(),
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

/// Sends continuous sync updates to the exact endpoint selected by the
/// registration. The opaque token is the only authorization material; these
/// calls intentionally carry no service-authentication header.
public struct HTTPPermissionedSpaceSyncNotificationTransport:
    PermissionedSpaceSyncNotificationTransport
{
    private let poster: OAuthBoundedJSONPoster

    public init(poster: OAuthBoundedJSONPoster) {
        self.poster = poster
    }

    public func deliver(
        _ notification: PersistedSpaceSyncNotification
    ) async -> PermissionedSpaceSyncNotificationDisposition {
        let endpoint: URL
        let body: Data
        do {
            guard let base = URL(string: notification.endpoint) else {
                return .rejected
            }
            endpoint = try notificationEndpoint(
                base,
                method: ComAtprotoSpaceNotifySpaceUpdate.typeIdentifier
            )
            body = try spaceSyncNotificationJSON(notification)
        } catch {
            return .rejected
        }
        do {
            try await poster.postJSON(
                to: endpoint,
                headers: ["content-type": "application/json"],
                body: body
            )
            return .delivered
        } catch is OAuthOutboundPostPermanentlyRejected {
            return .rejected
        } catch {
            return .retryableFailure
        }
    }
}


private func spaceSyncNotificationJSON(
    _ notification: PersistedSpaceSyncNotification
) throws -> Data {
    let update: ComAtprotoSpaceNotifySpaceUpdate.InputUpdateUnion
    switch notification.kind {
    case .repoWrite:
        guard let repo = notification.repository,
              let repoRev = notification.wireRevision,
              let data = notification.commitment,
              data.count == 32,
              let spaceRev = notification.spaceRevision else {
            throw SwanError.malformed("repository update notification is incomplete")
        }
        update = try .init(ComAtprotoSpaceDefs.RepoWrite(
            repo: DID(didString: repo),
            repoRev: TID(tidString: repoRev),
            data: Bytes(data: data),
            spaceRev: TID(tidString: spaceRev),
            prevSpaceRev: notification.previousSpaceRevision.map(TID.init(tidString:))
        ))
    case .repoRemoved:
        guard let repo = notification.repository,
              let spaceRev = notification.spaceRevision else {
            throw SwanError.malformed("repository removal notification is incomplete")
        }
        update = try .init(ComAtprotoSpaceDefs.RepoRemoved(
            repo: DID(didString: repo),
            spaceRev: TID(tidString: spaceRev),
            prevSpaceRev: notification.previousSpaceRevision.map(TID.init(tidString:))
        ))
    case .spaceDeleted:
        update = .init(ComAtprotoSpaceNotifySpaceUpdate.SpaceDeleted())
    case .registrationExpired:
        guard let spaceRev = notification.spaceRevision else {
            throw SwanError.malformed("registration expiry notification is incomplete")
        }
        update = try .init(ComAtprotoSpaceNotifySpaceUpdate.RegistrationExpired(
            spaceRev: TID(tidString: spaceRev)
        ))
    }
    return try SwanJSONEncoders.sortedNoEscaping.encode(
        ComAtprotoSpaceNotifySpaceUpdate.Input(
            space: try SpaceRef(uriString: notification.space.rawValue),
            token: notification.token,
            update: update
        )
    )
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

/// The repo-host hop is `{space, repo, repoRev, data}`.
private func notificationJSON(
    space: SpaceURI,
    repository: String,
    wireRevision: String,
    commitment: Data
) throws -> Data {
    guard commitment.count == 32 else {
        throw SwanError.malformed("writer notification is invalid")
    }
    let input = try ComAtprotoSpaceNotifyRepoUpdate.Input(
        space: SpaceRef(uriString: space.rawValue),
        repo: DID(didString: repository),
        repoRev: TID(tidString: wireRevision),
        data: Bytes(data: commitment)
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
