import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import Petrel
import PetrelCrypto
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage

/// The narrow capability for the proposal-0016 writer-discovery and
/// notification endpoints. It has no repository-value access and is formed
/// only after the server has selected a startup-preopened account directory.
public struct SwanAuthenticatedSpaceNotificationsCapability: Sendable {
    let authorizer: SwanOAuthResourceAuthorizer
    let directory: any AuthorizedSpaceNotificationDirectory
    let credentialAuthorizer: any SpaceCredentialAuthorizationVerifier
    let serviceAuthentication: any SpaceServiceAuthenticationVerifier
    let notificationJSONDecodeObserver: (@Sendable () async -> Void)?
    /// `--enable-spaces-open-interop`; `nil` keeps the hardened receive rules.
    let openInterop: SwanSpacesOpenInteropNotificationPolicy?

    init(
        authorizer: SwanOAuthResourceAuthorizer,
        directory: any AuthorizedSpaceNotificationDirectory,
        credentialAuthorizer: any SpaceCredentialAuthorizationVerifier,
        serviceAuthentication: any SpaceServiceAuthenticationVerifier,
        notificationJSONDecodeObserver: (@Sendable () async -> Void)? = nil,
        openInterop: SwanSpacesOpenInteropNotificationPolicy? = nil
    ) {
        self.openInterop = openInterop
        self.authorizer = authorizer
        self.directory = directory
        self.credentialAuthorizer = credentialAuthorizer
        self.serviceAuthentication = serviceAuthentication
        self.notificationJSONDecodeObserver = notificationJSONDecodeObserver
    }
}

/// The notification-route half of ``SwanSpacesOpenInteropConfiguration``:
/// unbound service-JWT admission for the remaining repo-host methods.
struct SwanSpacesOpenInteropNotificationPolicy: Sendable {
    let configuration: SwanSpacesOpenInteropConfiguration
    let replayStore: DurableSpaceServiceJWTReplayStore

    init(
        configuration: SwanSpacesOpenInteropConfiguration,
        replayStore: DurableSpaceServiceJWTReplayStore
    ) {
        self.configuration = configuration
        self.replayStore = replayStore
    }

    /// The audiences a notification to `authority` may name: the bare DID
    /// (what the reference sends to `#atproto_pds`) or the space-host
    /// service identifier.
    static func acceptedAudiences(for authority: String) -> Set<String> {
        [authority, "\(authority)#atproto_pds"]
    }

    /// Admits a verified service JWT that carries no `req`: it must carry an
    /// `iat`, live at most 60 s, and its `jti` must be unused (durably).
    func admitUnbound(_ service: VerifiedSpaceServiceAuthentication, now: Date = Date()) async throws {
        guard let issuedAt = service.issuedAt,
              service.expiresAt > issuedAt,
              service.expiresAt.timeIntervalSince(issuedAt)
                <= SwanSpacesOpenInteropConfiguration.maximumUnboundServiceLifetime else {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        let fresh: Bool
        do {
            fresh = try await replayStore.claim(
                issuer: service.issuer,
                method: service.method,
                jti: service.eventID,
                // Hold the reservation past the verifier's 60 s expiry skew.
                expiresAt: max(service.expiresAt, now).addingTimeInterval(60),
                now: now
            )
        } catch let error as SwanError {
            if case .unavailable = error {
                throw AuthenticatedSpaceNotificationFailure.unavailable
            }
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        guard fresh else {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
    }
}


private enum AuthenticatedSpaceNotificationFailure: Error {
    case invalidRequest
    case spaceNotFound
    case denied
    case credentialPresentation(SpaceCredentialPresentationFailure)
    case unavailable
    case repoDeactivated
    case repoTakendown
    case upstreamFailure
    /// notifyRepoUpdate's `repoRev` is more than five minutes ahead (`FutureRev`).
    case futureRevision
}

private enum SwanSpaceNotificationHTTP {
    /// Writer metadata and compact service tokens are control-plane inputs.
    /// Keeping this much smaller than a record write also prevents the route
    /// from turning into a generic buffered upload surface.
    static let maximumJSONBytes = 16 * 1_024
    static let maximumQueryBytes = 4 * 1_024
    static let maximumListLimit = 1_000
}

private struct ListSpaceWritersParameters {
    let space: SpaceRef
    let limit: Int?
    let cursor: String?
}

private struct ListSpaceWriterWireEntry: Encodable {
    let type: String
    let repo: DID
    let repoRev: TID?
    let data: Bytes?
    let spaceRev: TID

    enum CodingKeys: String, CodingKey {
        case type = "$type"
        case repo
        case repoRev
        case data
        case spaceRev
    }
}

private struct ListSpaceWritersWireOutput: Encodable {
    let repos: [ListSpaceWriterWireEntry]
    let cursor: String?
}

private struct AuthenticatedListSpaceWritersHandler {
    let capability: SwanAuthenticatedSpaceNotificationsCapability

    func handle(
        parameters: ListSpaceWritersParameters,
        context request: Request
    ) async throws -> ListSpaceWritersWireOutput {
        let space = try notificationSpace(parameters.space)
        let authorization = try await credentialAuthorization(
            capability,
            request: request,
            space: space
        )
        let writers: [AuthorizedSpaceWriter]
        do {
            writers = try await capability.directory.listSpaceWriters(
                space: space,
                limit: parameters.limit ?? 100,
                cursor: parameters.cursor,
                authorization: authorization
            )
        } catch {
            throw notificationStorageFailure(error)
        }
        do {
            let repos: [ListSpaceWriterWireEntry] = try writers.map {
                guard let spaceRevision = $0.spaceRevision else {
                    throw AuthenticatedSpaceNotificationFailure.unavailable
                }
                return try ListSpaceWriterWireEntry(
                    type: $0.isRemoved
                        ? "com.atproto.space.defs#repoRemoved"
                        : "com.atproto.space.defs#repoWrite",
                    repo: DID(didString: $0.repository),
                    repoRev: $0.isRemoved ? nil : TID(tidString: $0.wireRevision),
                    data: $0.isRemoved ? nil : Bytes(data: $0.commitment),
                    spaceRev: TID(tidString: spaceRevision)
                )
            }
            return .init(repos: repos, cursor: repos.last?.spaceRev.toString())
        } catch {
            throw AuthenticatedSpaceNotificationFailure.unavailable
        }
    }
}


private struct NotifyRepoUpdateWireInput: Decodable {
    let space: SpaceRef
    let repo: DID
    let repoRev: TID
    let data: Bytes
}

private struct AuthenticatedNotifyRepoUpdateHandler {
    let capability: SwanAuthenticatedSpaceNotificationsCapability

    func handle(
        parameters _: Void,
        input: NotifyRepoUpdateWireInput,
        context request: Request
    ) async throws {
        let space = try notificationSpace(input.space)
        guard input.data.data.count == 32 else {
            throw AuthenticatedSpaceNotificationFailure.invalidRequest
        }
        let expectedDigest = SpaceNotificationRequestDigest.write(
            space: space,
            repository: input.repo.didString(),
            wireRevision: input.repoRev.toString(),
            commitment: input.data.data
        )
        let verifiedDigest: String
        let service: VerifiedSpaceServiceAuthentication
        if let openInterop = capability.openInterop {
            // `req` is checked below rather than by the verifier, because an
            // unbound upstream token has none to compare.
            service = try await serviceAuthentication(
                capability,
                request: request,
                expectedAudience: nil,
                expectedMethod: SwanSpaceNotificationNSID.notifyRepoUpdate,
                expectedRequestBodyDigest: nil
            )
            guard service.issuer == input.repo.didString(),
                  SwanSpacesOpenInteropNotificationPolicy
                    .acceptedAudiences(for: space.authority)
                    .contains(service.audience) else {
                throw AuthenticatedSpaceNotificationFailure.denied
            }
            if let bound = service.requestBodyDigest {
                guard bound == expectedDigest else {
                    throw AuthenticatedSpaceNotificationFailure.denied
                }
            } else {
                try await openInterop.admitUnbound(service)
            }
            verifiedDigest = expectedDigest
        } else {
            // A repo host addresses `<authority>#atproto_pds` (the
            // reference sender always does, even when it falls back to the
            // authority's PDS endpoint); the bare authority DID is accepted
            // too. Only the audience form is relaxed here: `req` stays
            // mandatory in the hardened posture.
            service = try await serviceAuthentication(
                capability,
                request: request,
                expectedAudience: nil,
                expectedMethod: SwanSpaceNotificationNSID.notifyRepoUpdate,
                expectedRequestBodyDigest: expectedDigest
            )
            guard service.issuer == input.repo.didString(),
                  SwanSpacesOpenInteropNotificationPolicy
                    .acceptedAudiences(for: space.authority)
                    .contains(service.audience),
                  let bound = service.requestBodyDigest,
                  bound == expectedDigest else {
                throw AuthenticatedSpaceNotificationFailure.denied
            }
            verifiedDigest = bound
        }
        do {
            try await capability.directory.receiveSpaceWriteNotification(
                .init(
                    eventID: service.eventID,
                    space: space,
                    repository: input.repo.didString(),
                    wireRevision: input.repoRev.toString(),
                    commitment: input.data.data,
                    issuer: service.issuer,
                    // Both accepted audience forms name this authority.
                    audience: space.authority,
                    requestBodyDigest: verifiedDigest
                )
            )
        } catch {
            throw notificationStorageFailure(error)
        }
    }
}


/// The repo-host receiver for `com.atproto.space.notifyCredentialsRevoked`:
/// service auth whose `iss` is the space authority, whose `aud` is the bare
/// DID of an account this host stores, and whose `lxm` is this method. Like
/// the other notification receivers, it requires a `req` claim binding the
/// body by default and admits unbound upstream-shaped tokens only under
/// `--enable-spaces-open-interop` (with a 60 s lifetime and a durable
/// single-use `jti`). Revocations are persisted idempotently by `(space, jti)`
/// and honoured for ``DurableSpaceCredentialRevocations/retention``.
private struct NotifyCredentialsRevokedWireInput: Decodable {
    let space: SpaceRef
    let credentials: [String]
}

private struct AuthenticatedNotifyCredentialsRevokedHandler {

    let capability: SwanAuthenticatedSpaceNotificationsCapability

    func handle(
        parameters _: Void,
        input: NotifyCredentialsRevokedWireInput,
        context request: Request
    ) async throws {
        let space = try notificationSpace(input.space)
        let expectedDigest = SpaceNotificationRequestDigest.credentialRevocation(
            space: space,
            credentials: input.credentials
        )
        let service = try await serviceAuthentication(
            capability,
            request: request,
            expectedAudience: nil,
            expectedMethod: SwanSpaceNotificationNSID.notifyCredentialsRevoked,
            expectedRequestBodyDigest: capability.openInterop == nil ? expectedDigest : nil
        )
        guard service.issuer == space.authority else {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        if let bound = service.requestBodyDigest {
            guard bound == expectedDigest else {
                throw AuthenticatedSpaceNotificationFailure.denied
            }
        } else if let openInterop = capability.openInterop {
            try await openInterop.admitUnbound(service)
        } else {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        // The audience is a repo account's bare DID, never a service
        // identifier or this host's own DID.
        let audience = service.audience
        guard (try? DID(didString: audience)) != nil, !audience.contains("#") else {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        let hosted: Bool
        do {
            hosted = try await capability.authorizer.hostsAccount(did: audience)
        } catch {
            throw AuthenticatedSpaceNotificationFailure.unavailable
        }
        guard hosted else {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        do {
            try await capability.authorizer.recordSpaceCredentialRevocations(
                space: space,
                credentialIDs: input.credentials
            )
        } catch {
            throw notificationStorageFailure(error)
        }
    }
}

func registerAuthenticatedNotifyCredentialsRevokedEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceNotificationsCapability,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) {
    let handler = AuthenticatedNotifyCredentialsRevokedHandler(capability: capability)
    let path: RouterPath = "/xrpc/\(SwanSpaceNotificationNSID.notifyCredentialsRevoked)"
    router.post(path) { request, context async -> Response in
        do {
            let input = try await decodeNotifyCredentialsRevokedInput(
                request, context: context, requestBodyAdmission: requestBodyAdmission,
                decodeObserver: capability.notificationJSONDecodeObserver)
            try await handler.handle(parameters: (), input: input, context: request)
            return Response(status: .ok, headers: [.cacheControl: "no-store"])
        } catch let failure as AuthenticatedSpaceNotificationFailure {
            return authenticatedSpaceNotificationResponse(for: failure)
        } catch let failure as SwanRequestBodyCollectionFailure {
            return authenticatedSpaceNotificationResponse(
                for: failure == .unavailable ? .unavailable : .invalidRequest
            )
        } catch {
            return authenticatedSpaceNotificationError(.badRequest, code: "InvalidRequest")
        }
    }
    registerAuthenticatedNotificationWrongMethods(on: router, path: path, allowed: .post)
}

func registerAuthenticatedListSpaceWritersEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceNotificationsCapability
) {
    let handler = AuthenticatedListSpaceWritersHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.listWriters"
    router.get(path) { request, _ async -> Response in
        do {
            let parameters = try parseListSpaceWritersParameters(request)
            let output = try await handler.handle(parameters: parameters, context: request)
            return authenticatedGetSpaceJSON(.ok, output)
        } catch let failure as AuthenticatedSpaceNotificationFailure {
            return authenticatedSpaceNotificationResponse(for: failure)
        } catch {
            return authenticatedSpaceNotificationError(.badRequest, code: "InvalidRequest")
        }
    }
    registerAuthenticatedNotificationWrongMethods(on: router, path: path, allowed: .get)
}

func registerAuthenticatedNotifyRepoUpdateEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceNotificationsCapability,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) {
    let handler = AuthenticatedNotifyRepoUpdateHandler(capability: capability)
    let path: RouterPath = "/xrpc/\(SwanSpaceNotificationNSID.notifyRepoUpdate)"
    router.post(path) { request, context async -> Response in
        do {
            let input = try await decodeNotifyRepoUpdateInput(
                request, context: context, requestBodyAdmission: requestBodyAdmission,
                decodeObserver: capability.notificationJSONDecodeObserver)
            try await handler.handle(parameters: (), input: input, context: request)
            return Response(status: .ok, headers: [.cacheControl: "no-store"])
        } catch let failure as AuthenticatedSpaceNotificationFailure {
            return authenticatedSpaceNotificationResponse(for: failure)
        } catch let failure as SwanRequestBodyCollectionFailure {
            return authenticatedSpaceNotificationResponse(
                for: failure == .unavailable ? .unavailable : .invalidRequest
            )
        } catch {
            return authenticatedSpaceNotificationError(.badRequest, code: "InvalidRequest")
        }
    }
    registerAuthenticatedNotificationWrongMethods(on: router, path: path, allowed: .post)
}


private func parseListSpaceWritersParameters(
    _ request: Request
) throws -> ListSpaceWritersParameters {
    guard !request.uri.string.contains("#"),
          let rawQuery = request.uri.query,
          !rawQuery.isEmpty,
          rawQuery.utf8.count <= SwanSpaceNotificationHTTP.maximumQueryBytes else {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
    var values: [String: String] = [:]
    for pair in rawQuery.split(separator: "&", omittingEmptySubsequences: false) {
        let components = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        guard components.count == 2,
              !components[0].isEmpty,
              values[String(components[0])] == nil else {
            throw AuthenticatedSpaceNotificationFailure.invalidRequest
        }
        values[String(components[0])] = try strictQueryDecode(components[1])
    }
    guard Set(values.keys).isSubset(of: ["space", "limit", "cursor"]),
          let rawSpace = values["space"],
          !rawSpace.isEmpty else {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
    let limit: Int?
    if let rawLimit = values["limit"] {
        guard !rawLimit.isEmpty,
              rawLimit.allSatisfy({ $0.isNumber }),
              let parsed = Int(rawLimit),
              (1 ... SwanSpaceNotificationHTTP.maximumListLimit).contains(parsed) else {
            throw AuthenticatedSpaceNotificationFailure.invalidRequest
        }
        limit = parsed
    } else {
        limit = nil
    }
    // The cursor is an opaque exclusive space-revision checkpoint: plain
    // string, deliberately not TID-validated (atproto#5574). Empty means
    // absent, as in the reference. The 4 KiB query bound above caps it.
    let cursor = values["cursor"].flatMap { $0.isEmpty ? nil : $0 }
    do {
        let space = try SpaceRef(uriString: rawSpace)
        _ = try SpaceURI(space.uriString())
        return .init(space: space, limit: limit, cursor: cursor)
    } catch {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
}


private func decodeNotifyRepoUpdateInput(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration,
    decodeObserver: (@Sendable () async -> Void)?
) async throws -> NotifyRepoUpdateWireInput {
    let admitted = try await notificationJSONBody(
        request, context: context, requestBodyAdmission: requestBodyAdmission)
    defer { withExtendedLifetime(admitted.body) {} }
    let data = admitted.data
    await decodeObserver?()
    try notificationJSONObject(
        data,
        allowedKeys: ["space", "repo", "repoRev", "data"],
        requiredKeys: ["space", "repo", "repoRev", "data"]
    )
    do {
        let input = try JSONDecoder().decode(NotifyRepoUpdateWireInput.self, from: data)
        _ = try notificationSpace(input.space)
        _ = try DID(didString: input.repo.didString())
        guard input.data.data.count == 32 else {
            throw AuthenticatedSpaceNotificationFailure.invalidRequest
        }
        return input
    } catch let failure as AuthenticatedSpaceNotificationFailure {
        throw failure
    } catch {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
}


/// `{space, credentials}` with 1...100 nonempty JWT IDs, as the lexicon
/// requires. Anything else, including a JWT-shaped or control-bearing ID, is
/// `InvalidRequest` before authentication work begins.
private func decodeNotifyCredentialsRevokedInput(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration,
    decodeObserver: (@Sendable () async -> Void)?
) async throws -> NotifyCredentialsRevokedWireInput {
    let admitted = try await notificationJSONBody(
        request, context: context, requestBodyAdmission: requestBodyAdmission)
    defer { withExtendedLifetime(admitted.body) {} }
    let data = admitted.data
    await decodeObserver?()
    try notificationJSONObject(
        data,
        allowedKeys: ["space", "credentials"],
        requiredKeys: ["space", "credentials"]
    )
    do {
        let input = try JSONDecoder().decode(
            NotifyCredentialsRevokedWireInput.self,
            from: data
        )
        _ = try notificationSpace(input.space)
        guard (1 ... DurableSpaceCredentialRevocations.maximumCredentialsPerNotification)
                .contains(input.credentials.count),
              input.credentials.allSatisfy({
                  !$0.isEmpty
                      && $0.utf8.count <= PermissionedDataJWT.maximumOpaqueJTIBytes
                      && $0.utf8.allSatisfy { $0 >= 0x20 && $0 != 0x7f }
              }) else {
            throw AuthenticatedSpaceNotificationFailure.invalidRequest
        }
        return input
    } catch {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
}

private func notificationJSONBody(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws -> SwanAdmittedNotificationJSON {
    let body = try await collectAdmittedRequestBody(
        request,
        mediaType: .json,
        admission: requestBodyAdmission.admission,
        policy: requestBodyAdmission.policy,
        maximumBytes: SwanSpaceNotificationHTTP.maximumJSONBytes,
        termination: context.jsonWriteBodyTermination
    )
    guard body.readableBytes > 0,
          let bytes = body.getBytes(at: body.readerIndex, length: body.readableBytes) else {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
    return SwanAdmittedNotificationJSON(body: body, data: Data(bytes))
}

private struct SwanAdmittedNotificationJSON {
    // Retaining this wrapper keeps aggregate admission held through the
    // caller's strict object validation and generated-model decode.
    let body: SwanAdmittedRequestBody
    let data: Data
}

private func notificationJSONObject(
    _ data: Data,
    allowedKeys: Set<String>,
    requiredKeys: Set<String>
) throws {
    do {
        try StrictPermissionedWriteJSON.validate(data)
    } catch {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
    guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(root.keys).isSubset(of: allowedKeys),
          requiredKeys.isSubset(of: root.keys) else {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
}

private func notificationSpace(_ value: SpaceRef) throws -> SpaceURI {
    do {
        return try SpaceURI(value.uriString())
    } catch {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
}

/// listWriters is a space-host operation, so the credential's signed
/// audience must be the space authority's bare DID.
private func credentialAuthorization(
    _ capability: SwanAuthenticatedSpaceNotificationsCapability,
    request: Request,
    space: SpaceURI
) async throws -> AuthorizationContext {
    let token: String
    do {
        guard let bearer = try spaceCredentialSchemeToken(from: request.headers) else {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        token = bearer
        let authorization = try await capability.authorizer.authorizeSpaceCredential(
            token,
            verifier: capability.credentialAuthorizer,
            request: request,
            expectedSpace: space,
            expectedAudience: space.authority,
            now: Date()
        )
        guard case let .spaceCredential(grant) = authorization,
              grant.space == space else {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        return authorization
    } catch let failure as AuthenticatedSpaceNotificationFailure {
        throw failure
    } catch let failure as SpaceCredentialPresentationFailure {
        throw AuthenticatedSpaceNotificationFailure.credentialPresentation(failure)
    } catch let error as SwanError {
        if case .unavailable = error {
            throw AuthenticatedSpaceNotificationFailure.unavailable
        }
        throw AuthenticatedSpaceNotificationFailure.denied
    } catch {
        throw AuthenticatedSpaceNotificationFailure.denied
    }
}

private func serviceAuthentication(
    _ capability: SwanAuthenticatedSpaceNotificationsCapability,
    request: Request,
    expectedAudience: String?,
    expectedMethod: String,
    expectedRequestBodyDigest: String? = nil
) async throws -> VerifiedSpaceServiceAuthentication {
    let compact: String
    do {
        compact = try exactSpaceServiceBearerToken(from: request.headers)
        return try await capability.serviceAuthentication.authenticate(
            compact,
            expectedAudience: expectedAudience,
            expectedMethod: expectedMethod,
            expectedRequestBodyDigest: expectedRequestBodyDigest,
            now: Date()
        )
    } catch let failure as AuthenticatedSpaceNotificationFailure {
        throw failure
    } catch let error as SwanError {
        if case .unavailable = error {
            throw AuthenticatedSpaceNotificationFailure.unavailable
        }
        throw AuthenticatedSpaceNotificationFailure.denied
    } catch {
        throw AuthenticatedSpaceNotificationFailure.denied
    }
}


/// Parses the only authorization presentation accepted by service-auth XRPC
/// endpoints. OAuth DPoP and generic Bearer credentials never fall through:
/// callers must supply exactly one bounded compact service JWT.
func exactSpaceServiceBearerToken(from headers: HTTPFields) throws -> String {
    let authMatches = headers.filter {
        $0.name == .authorization || $0.name.rawName.caseInsensitiveCompare("authorization") == .orderedSame
    }
    let atprotoMatches = headers.filter {
        $0.name.rawName.caseInsensitiveCompare("atproto-service-auth") == .orderedSame
    }
    let totalCount = authMatches.count + atprotoMatches.count
    guard totalCount == 1,
          let raw = authMatches.first?.value ?? atprotoMatches.first?.value else {
        throw SwanError.unauthorized("service authentication is invalid")
    }
    let prefix = "Bearer "
    let token: String
    if raw.count >= prefix.count,
       raw.prefix(prefix.count).caseInsensitiveCompare(prefix) == .orderedSame {
        token = String(raw.dropFirst(prefix.count))
    } else {
        token = raw
    }
    guard !token.isEmpty,
          token.utf8.count <= SpaceServiceJWT.maximumCompactBytes,
          token.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
        throw SwanError.unauthorized("service authentication is invalid")
    }
    return token
}

private func validRegisteredNotificationEndpoint(_ raw: String) -> Bool {
    guard raw.utf8.count <= 4_096,
          raw.unicodeScalars.allSatisfy({ $0.value > 0x1f && $0.value != 0x7f }),
          let components = URLComponents(string: raw),
          let scheme = components.scheme?.lowercased(),
          ["https", "http"].contains(scheme),
          components.host != nil,
          components.user == nil,
          components.password == nil,
          components.fragment == nil else {
        return false
    }
    return true
}

private func notificationStorageFailure(_ error: Error) -> AuthenticatedSpaceNotificationFailure {
    if error is AuthorizedSimpleSpaceLifecycleError {
        return .spaceNotFound
    }
    if let error = error as? AuthorizedSpaceAuthorityStatusError {
        return switch error {
        case .deactivated: .repoDeactivated
        case .takendown: .repoTakendown
        }
    }
    if error is any AuthorizedSpaceUpstreamFailure {
        return .upstreamFailure
    }
    if let error = error as? AuthorizedSpaceWriteNotificationError {
        return switch error {
        case .futureRevision: .futureRevision
        }
    }
    guard let error = error as? SwanError else {
        return .unavailable
    }
    return switch error {
    case .invalidIdentifier, .invalidProfile, .malformed, .expired:
        .invalidRequest
    case .unauthorized:
        .denied
    case .conflict:
        // An equal revision with a different commitment is intentionally
        // indistinguishable from a rejected notification to the sender.
        .denied
    case .unavailable:
        .unavailable
    }
}

private func authenticatedSpaceNotificationResponse(
    for failure: AuthenticatedSpaceNotificationFailure
) -> Response {
    switch failure {
    case .invalidRequest:
        authenticatedSpaceNotificationError(.badRequest, code: "InvalidRequest")
    case .spaceNotFound:
        authenticatedSpaceNotificationError(.notFound, code: "SpaceNotFound")
    case .denied:
        authenticatedSpaceNotificationError(.unauthorized, code: "Unauthorized")
    case let .credentialPresentation(failure):
        authenticatedSpaceNotificationError(failure.httpStatus, code: failure.xrpcErrorCode)
    case .unavailable:
        authenticatedSpaceNotificationError(.serviceUnavailable, code: "temporarily_unavailable")
    case .upstreamFailure:
        authenticatedSpaceNotificationError(.badGateway, code: "UpstreamFailure")
    case .futureRevision:
        authenticatedSpaceNotificationError(.badRequest, code: "FutureRev")
    case .repoDeactivated:
        authenticatedSpaceNotificationError(.badRequest, code: "RepoDeactivated")
    case .repoTakendown:
        authenticatedSpaceNotificationError(.badRequest, code: "RepoTakendown")
    }
}

private func authenticatedSpaceNotificationError(
    _ status: HTTPResponse.Status,
    code: String
) -> Response {
    authenticatedGetSpaceJSON(status, ["error": code])
}

private func registerAuthenticatedNotificationWrongMethods(
    on router: Router<BasicRequestContext>,
    path: RouterPath,
    allowed: HTTPRequest.Method
) {
    for method: HTTPRequest.Method in [.get, .head, .post, .put, .patch, .delete, .options, .connect, .trace] {
        // The method-correct handler has already been registered. Hummingbird
        // gives it precedence, while every other method gets the same opaque
        // no-store closure.
        guard method != allowed else { continue }
        router.on(path, method: method) { _, _ -> Response in
            authenticatedSpaceNotificationError(
                .notFound,
                code: "permissioned_endpoint_unavailable"
            )
        }
    }
}
